/**
 * NODUS Relay Server v2
 * Объединяет функционал старого relay + blind relay для сообщений
 */

const express = require('express');
const cors = require('cors');
const http = require('http');
const WebSocket = require('ws');
const nacl = require('tweetnacl');

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// Proxy endpoint для браузера
app.post('/api/proxy', async (req, res) => {
  try {
    const { url, method = 'GET', headers = {} } = req.body;
    
    if (!url) {
      return res.json({ ok: false, error: 'URL required' });
    }

    console.log(`[Proxy] Fetching ${url}`);
    
    // Добавляем заголовки для анонимности
    const proxyHeaders = {
      'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
      'Accept-Language': 'en-US,en;q=0.5',
      'Accept-Encoding': 'gzip, deflate, br',
      'Connection': 'keep-alive',
      'Upgrade-Insecure-Requests': '1',
      ...headers
    };

    const response = await fetch(url, {
      method,
      headers: proxyHeaders,
      timeout: 15000
    });

    if (!response.ok) {
      return res.json({ ok: false, error: `HTTP ${response.status}` });
    }

    const content = await response.text();
    
    res.json({
      ok: true,
      content,
      headers: Object.fromEntries(response.headers.entries()),
      status: response.status
    });

  } catch (error) {
    console.error('[Proxy] Error:', error);
    res.json({ ok: false, error: error.message });
  }
});

// Health check для браузера
app.get('/api/health', (req, res) => {
  res.json({ ok: true, status: 'healthy', timestamp: Date.now() });
});

const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// ============ STORAGE ============
const wsConnections = new Map();      // peerId -> ws
const activePeers = {};               // peerId -> { info, lastSeen }
const profiles = {};                  // fingerprint -> profile
const messageQueue = [];              // legacy message queue
const callEvents = {};                // peerId -> [events]
const signalingQueue = {};            // peerId -> [signals]
const groups = {};                    // groupId -> group
const groupMessages = {};             // groupId -> [messages]
const channels = {};                  // channelId -> channel
const channelPosts = {};              // channelId -> [posts]
const userChats = {};                 // fingerprint -> encrypted chats

// Blind relay storage
const mailboxes = new Map();          // mailboxId -> { messages: [], lastAccess }
const registeredKeys = new Map();     // mailboxId -> publicKey
const challenges = new Map();         // mailboxId -> { challenge, expires }

// ============ UTILS ============
function logMessage(msg) {
  console.log(new Date().toISOString().slice(11, 19) + ' ' + msg);
}

function b64ToBytes(b64) {
  return Uint8Array.from(Buffer.from(b64, 'base64'));
}

function bytesToB64(bytes) {
  return Buffer.from(bytes).toString('base64');
}

function generateChallenge() {
  return bytesToB64(nacl.randomBytes(32));
}

function verifySignature(message, signature, publicKey) {
  try {
    const msgBytes = typeof message === 'string' 
      ? new Uint8Array([...message].map(c => c.charCodeAt(0)))
      : message;
    return nacl.sign.detached.verify(msgBytes, b64ToBytes(signature), b64ToBytes(publicKey));
  } catch {
    return false;
  }
}

// ============ CLEANUP ============
setInterval(() => {
  const now = Date.now();
  // Cleanup old peers
  Object.keys(activePeers).forEach(id => {
    if (now - activePeers[id].lastSeen > 300000) delete activePeers[id];
  });
  // Cleanup call events
  Object.keys(callEvents).forEach(id => {
    callEvents[id] = callEvents[id].filter(e => now - e.ts < 120000);
    if (callEvents[id].length === 0) delete callEvents[id];
  });
  // Cleanup mailboxes
  for (const [id, mb] of mailboxes) {
    mb.messages = mb.messages.filter(m => now - m.timestamp < 7 * 24 * 60 * 60 * 1000);
    if (mb.messages.length === 0 && now - mb.lastAccess > 86400000) mailboxes.delete(id);
  }
}, 60000);

// ============ WEBSOCKET ============
wss.on('connection', (ws) => {
  let peerId = null;
  
  ws.on('message', (data) => {
    try {
      const msg = JSON.parse(data);
      if (msg.action === 'subscribe' && msg.peerId) {
        peerId = msg.peerId;
        wsConnections.set(peerId, ws);
        logMessage(`[WS] ${peerId.slice(0,8)} connected`);
        
        // Send pending messages
        const pending = messageQueue.filter(m => m.toPeerId === peerId);
        messageQueue.length = 0;
        messageQueue.push(...messageQueue.filter(m => m.toPeerId !== peerId));
        pending.forEach(m => ws.send(JSON.stringify({ type: 'message', ...m })));
      }
    } catch {}
  });
  
  ws.on('close', () => {
    if (peerId) {
      wsConnections.delete(peerId);
      logMessage(`[WS] ${peerId.slice(0,8)} disconnected`);
    }
  });
  
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });
});

setInterval(() => {
  wss.clients.forEach(ws => {
    if (!ws.isAlive) return ws.terminate();
    ws.isAlive = false;
    ws.ping();
  });
}, 30000);

function sendToWs(peerId, data) {
  const ws = wsConnections.get(peerId);
  if (ws?.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(data));
    return true;
  }
  return false;
}

// ============ BLIND RELAY API ============
app.post('/api/challenge', (req, res) => {
  const { mailboxId } = req.body;
  if (!mailboxId || mailboxId.length < 16) return res.json({ ok: false, error: 'Invalid mailboxId' });
  
  const challenge = generateChallenge();
  challenges.set(mailboxId, { challenge, expires: Date.now() + 60000 });
  res.json({ ok: true, challenge });
});

app.post('/api/register', (req, res) => {
  const { mailboxId, publicKey, signature, challenge } = req.body;
  if (!mailboxId || !publicKey || !signature || !challenge) return res.json({ ok: false, error: 'Missing fields' });
  
  const stored = challenges.get(mailboxId);
  if (!stored || stored.challenge !== challenge || Date.now() > stored.expires) {
    return res.json({ ok: false, error: 'Invalid challenge' });
  }
  challenges.delete(mailboxId);
  
  if (!verifySignature(challenge, signature, publicKey)) {
    return res.json({ ok: false, error: 'Invalid signature' });
  }
  
  registeredKeys.set(mailboxId, publicKey);
  if (!mailboxes.has(mailboxId)) mailboxes.set(mailboxId, { messages: [], lastAccess: Date.now() });
  
  logMessage(`[Register] Mailbox: ${mailboxId} (full)`);
  res.json({ ok: true });
});

app.post('/api/send', (req, res) => {
  const { mailboxId, blob } = req.body;
  if (!mailboxId || !blob) return res.json({ ok: false, error: 'Missing fields' });
  if (blob.length > 1024 * 1024) return res.json({ ok: false, error: 'Too large' });
  
  if (!mailboxes.has(mailboxId)) mailboxes.set(mailboxId, { messages: [], lastAccess: Date.now() });
  const mb = mailboxes.get(mailboxId);
  
  if (mb.messages.length >= 1000) mb.messages.shift();
  const messageId = bytesToB64(nacl.randomBytes(16));
  mb.messages.push({ id: messageId, blob, timestamp: Date.now() });
  
  logMessage(`[Send] To: ${mailboxId.slice(0,8)}... (${mb.messages.length} msgs)`);
  res.json({ ok: true, messageId });
});

app.post('/api/poll', (req, res) => {
  const { mailboxId, timestamp, signature } = req.body;
  if (!mailboxId || !timestamp || !signature) return res.json({ ok: false, error: 'Missing fields' });
  
  const ts = parseInt(timestamp);
  if (isNaN(ts) || Math.abs(Date.now() - ts) > 60000) return res.json({ ok: false, error: 'Invalid timestamp' });
  
  const publicKey = registeredKeys.get(mailboxId);
  if (!publicKey) return res.json({ ok: false, error: 'Not registered' });
  
  if (!verifySignature(`poll:${mailboxId}:${timestamp}`, signature, publicKey)) {
    return res.json({ ok: false, error: 'Invalid signature' });
  }
  
  const mb = mailboxes.get(mailboxId);
  if (!mb) return res.json({ ok: true, messages: [] });
  
  mb.lastAccess = Date.now();
  const messages = mb.messages.map(m => ({ id: m.id, blob: m.blob, ts: m.timestamp }));
  
  if (messages.length > 0) {
    logMessage(`[Poll] ${mailboxId.slice(0,8)}... has ${messages.length} msgs`);
  }
  res.json({ ok: true, messages });
});

app.post('/api/ack', (req, res) => {
  const { mailboxId, messageIds, timestamp, signature } = req.body;
  logMessage(`[Ack] Mailbox: ${mailboxId} ids: ${messageIds?.join(',')}`);
  if (!mailboxId || !messageIds || !timestamp || !signature) return res.json({ ok: false, error: 'Missing fields' });
  
  const publicKey = registeredKeys.get(mailboxId);
  if (publicKey && !verifySignature(`ack:${mailboxId}:${timestamp}:${messageIds.join(',')}`, signature, publicKey)) {
    return res.json({ ok: false, error: 'Invalid signature' });
  }
  
  const mb = mailboxes.get(mailboxId);
  if (mb) {
    const before = mb.messages.length;
    mb.messages = mb.messages.filter(m => !messageIds.includes(m.id));
    logMessage(`[Ack] Deleted ${before - mb.messages.length} msgs from ${mailboxId.slice(0,8)}`);
  }
  
  res.json({ ok: true });
});

// ============ LEGACY RELAY API ============
app.post('/relay', (req, res) => {
  const { action } = req.body;
  
  switch (action) {
    case 'register': {
      const { peerId, info } = req.body;
      logMessage(`[Register] peerId=${peerId?.slice(0,8)} info=${JSON.stringify(info)}`);
      if (!peerId) return res.json({ success: false, error: 'peerId required' });
      
      activePeers[peerId] = { info: info || {}, lastSeen: Date.now() };
      
      // Always save to profiles (merge with existing)
      profiles[peerId] = {
        ...profiles[peerId],
        fingerprint: peerId,
        username: info?.username || profiles[peerId]?.username,
        alias: info?.alias || profiles[peerId]?.alias,
        publicKey: info?.publicKey || profiles[peerId]?.publicKey,
        bio: info?.bio || profiles[peerId]?.bio,
        updatedAt: Date.now()
      };
      
      logMessage(`[Register] ${profiles[peerId]?.username || peerId.slice(0, 8)} (total: ${Object.keys(activePeers).length})`);
      res.json({ success: true, peerId });
      break;
    }
    
    case 'heartbeat': {
      const { peerId } = req.body;
      if (peerId && activePeers[peerId]) activePeers[peerId].lastSeen = Date.now();
      res.json({ success: true });
      break;
    }
    
    case 'sendMessage': {
      const { fromPeerId, toPeerId, message } = req.body;
      if (!fromPeerId || !toPeerId || !message) return res.json({ success: false, error: 'missing params' });
      
      const sent = sendToWs(toPeerId, { type: 'message', fromPeerId, message, timestamp: Date.now() });
      if (!sent) messageQueue.push({ fromPeerId, toPeerId, message, timestamp: Date.now() });
      
      logMessage(`[Send] ${fromPeerId.slice(0,8)} -> ${toPeerId.slice(0,8)} (${sent ? 'WS' : 'queued'})`);
      res.json({ success: true, delivered: sent });
      break;
    }
    
    case 'getMessages': {
      const { peerId } = req.body;
      if (!peerId) return res.json({ success: false, error: 'peerId required' });
      
      const msgs = messageQueue.filter(m => m.toPeerId === peerId);
      messageQueue.length = 0;
      messageQueue.push(...messageQueue.filter(m => m.toPeerId !== peerId));
      
      res.json({ success: true, messages: msgs, count: msgs.length });
      break;
    }
    
    case 'searchUser': {
      const query = (req.body.query || req.body.username || '').toLowerCase();
      if (!query) return res.json({ success: true, users: [], results: [] });
      
      const results = [];
      const seen = new Set();
      
      // Search online peers
      Object.entries(activePeers).forEach(([id, peer]) => {
        const u = (peer.info?.username || '').toLowerCase();
        const a = (peer.info?.alias || '').toLowerCase();
        if (u.includes(query) || a.includes(query) || id.toLowerCase().includes(query)) {
          seen.add(id);
          results.push({
            peerId: id, fingerprint: id,
            username: peer.info?.username, alias: peer.info?.alias,
            avatar: peer.info?.avatar, bio: peer.info?.bio,
            publicKey: peer.info?.publicKey, isOnline: true
          });
        }
      });
      
      // Search saved profiles
      Object.entries(profiles).forEach(([id, p]) => {
        if (seen.has(id)) return;
        const u = (p.username || '').toLowerCase();
        const a = (p.alias || '').toLowerCase();
        if (u.includes(query) || a.includes(query) || id.toLowerCase().includes(query)) {
          results.push({
            peerId: id, fingerprint: id,
            username: p.username, alias: p.alias,
            avatar: p.avatar, bio: p.bio,
            publicKey: p.publicKey, isOnline: false
          });
        }
      });
      
      logMessage(`[Search] "${query}" -> ${results.length} results`);
      res.json({ success: true, users: results, results });
      break;
    }
    
    case 'saveProfile': {
      const { fingerprint, username, alias, avatar, bio, publicKey, encryptedProfile } = req.body;
      if (!fingerprint) return res.json({ ok: false });
      
      profiles[fingerprint] = {
        ...profiles[fingerprint],
        fingerprint, username, alias, avatar, bio, publicKey, encryptedProfile,
        updatedAt: Date.now()
      };
      
      logMessage(`[Profile] Saved: ${username || fingerprint.slice(0, 8)}`);
      res.json({ ok: true, success: true });
      break;
    }
    
    case 'getProfile': {
      const { fingerprint, peerId } = req.body;
      const id = fingerprint || peerId;
      const p = profiles[id];
      if (p) {
        res.json({ ok: true, ...p });
      } else {
        res.json({ ok: false, error: 'not found' });
      }
      break;
    }
    
    case 'presenceGet': {
      const peerIds = req.body.peerIds || [];
      const now = Date.now();
      const presence = {};
      peerIds.forEach(id => {
        const peer = activePeers[id];
        presence[id] = peer 
          ? { online: now - peer.lastSeen < 60000, lastSeen: Math.floor(peer.lastSeen / 1000) }
          : { online: false, lastSeen: 0 };
      });
      res.json({ ok: true, presence });
      break;
    }
    
    case 'callSend': {
      const { to, from, callId, event, kind, payload } = req.body;
      if (!to || !from || !callId || !event) return res.json({ error: 'missing params' });
      
      if (!callEvents[to]) callEvents[to] = [];
      callEvents[to].push({ from, callId, event, kind: kind || 'voice', payload, ts: Date.now() });
      if (callEvents[to].length > 50) callEvents[to] = callEvents[to].slice(-50);
      
      logMessage(`[Call] ${event} ${from.slice(0,8)} -> ${to.slice(0,8)}`);
      res.json({ ok: true });
      break;
    }
    
    case 'callPoll': {
      const { peerId } = req.body;
      if (!peerId) return res.json({ error: 'peerId required' });
      
      const events = callEvents[peerId] || [];
      delete callEvents[peerId];
      res.json(events);
      break;
    }
    
    // Groups
    case 'groupCreate': {
      const { name, username, ownerId, avatar, description, groupKey } = req.body;
      if (!name || !ownerId) return res.json({ ok: false, error: 'name and ownerId required' });
      
      const uname = username?.toLowerCase().replace(/[^a-z0-9_]/g, '');
      if (uname && Object.values(groups).find(g => g.username === uname)) {
        return res.json({ ok: false, error: 'username taken' });
      }
      
      const groupId = 'g_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8);
      groups[groupId] = { id: groupId, name, username: uname, avatar, description, ownerId, members: [ownerId], groupKey, createdAt: Date.now() };
      groupMessages[groupId] = [];
      
      logMessage(`[Group] Created: ${name}`);
      res.json({ ok: true, groupId, group: groups[groupId] });
      break;
    }
    
    case 'groupJoin': {
      const { groupId, memberId } = req.body;
      if (!groupId || !memberId || !groups[groupId]) return res.json({ ok: false });
      
      if (!groups[groupId].members.includes(memberId)) groups[groupId].members.push(memberId);
      res.json({ ok: true, group: groups[groupId], groupKey: groups[groupId].groupKey });
      break;
    }
    
    case 'groupInfo': {
      const { groupId } = req.body;
      if (groupId && groups[groupId]) {
        res.json({ ok: true, group: groups[groupId] });
      } else {
        res.json({ ok: false });
      }
      break;
    }
    
    case 'groupSend': {
      const { groupId, from, content, type, id, timestamp } = req.body;
      if (!groupId || !from || !groups[groupId]) return res.json({ ok: false });
      
      if (!groupMessages[groupId]) groupMessages[groupId] = [];
      const msgId = id || 'gm_' + Date.now();
      groupMessages[groupId].push({ id: msgId, from, content, type: type || 'text', timestamp: timestamp || Date.now() });
      if (groupMessages[groupId].length > 500) groupMessages[groupId] = groupMessages[groupId].slice(-500);
      
      res.json({ ok: true, messageId: msgId });
      break;
    }
    
    case 'groupPoll': {
      const { groupId, since } = req.body;
      if (!groupId || !groups[groupId]) return res.json({ ok: false });
      
      const msgs = (groupMessages[groupId] || []).filter(m => m.timestamp > (since || 0));
      res.json({ ok: true, messages: msgs });
      break;
    }
    
    case 'groupSearch': {
      const q = (req.body.query || '').toLowerCase();
      const results = Object.values(groups)
        .filter(g => g.username?.includes(q) || g.name.toLowerCase().includes(q))
        .map(g => ({ id: g.id, name: g.name, username: g.username, memberCount: g.members.length }));
      res.json({ ok: true, results });
      break;
    }
    
    default:
      res.json({ ok: true, success: true });
  }
});

// Health check
app.get('/health', (req, res) => {
  res.json({
    ok: true,
    peers: Object.keys(activePeers).length,
    profiles: Object.keys(profiles).length,
    mailboxes: mailboxes.size,
    groups: Object.keys(groups).length,
    uptime: process.uptime()
  });
});

// TURN credentials (временные, истекают через 24 часа)
const TURN_SECRET = process.env.TURN_SECRET || 'nodus-turn-secret-key-2024';
app.get('/api/turn', (req, res) => {
  const ttl = 86400; // 24 часа
  const timestamp = Math.floor(Date.now() / 1000) + ttl;
  const username = `${timestamp}:nodus`;
  
  // HMAC-SHA1 для coturn
  const crypto = require('crypto');
  const hmac = crypto.createHmac('sha1', TURN_SECRET);
  hmac.update(username);
  const credential = hmac.digest('base64');
  
  res.json({
    ok: true,
    iceServers: [
      { urls: 'stun:stun.l.google.com:19302' },
      { urls: 'stun:194.87.103.193:3478' },
      { 
        urls: 'turn:194.87.103.193:3478',
        username,
        credential
      },
      { 
        urls: 'turn:194.87.103.193:3478?transport=tcp',
        username,
        credential
      }
    ],
    ttl
  });
});

// ============ START ============
const PORT = process.env.PORT || 8082;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 NODUS Relay v2 running on port ${PORT}`);
  console.log(`   - Legacy API: /relay`);
  console.log(`   - Blind API: /api/*`);
  console.log(`   - WebSocket: ws://localhost:${PORT}`);
});

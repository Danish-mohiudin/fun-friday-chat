// server.js
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const path = require('path');
const http = require('http');
const WebSocket = require('ws');

const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);

const USERS_FILE = path.join(DATA_DIR, 'users.json');
const MESSAGES_FILE = path.join(DATA_DIR, 'messages.json');

function readJSON(filePath) {
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8') || '[]');
  } catch (e) {
    return [];
  }
}
function writeJSON(filePath, data) {
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
}

// initialize files if missing
if (!fs.existsSync(USERS_FILE)) writeJSON(USERS_FILE, []);
if (!fs.existsSync(MESSAGES_FILE)) writeJSON(MESSAGES_FILE, []);

const JWT_SECRET = process.env.JWT_SECRET || 'replace_this_with_a_strong_secret';
const TOKEN_EXPIRES_IN = '7d';

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Simple auth middleware
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization || '';
  if (!auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Missing token' });
  const token = auth.slice(7);
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

/* ---------- Auth routes ---------- */
app.post('/api/register', (req, res) => {
  const { username, password, email } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });

  const users = readJSON(USERS_FILE);
  if (users.find(u => u.username === username)) return res.status(409).json({ error: 'username already exists' });

  const hashed = bcrypt.hashSync(password, 10);
  const user = { id: uuidv4(), username, password: hashed, email: email || '', created_at: new Date().toISOString() };
  users.push(user);
  writeJSON(USERS_FILE, users);

  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: TOKEN_EXPIRES_IN });
  const safeUser = { id: user.id, username: user.username, email: user.email, created_at: user.created_at };
  res.json({ token, user: safeUser });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });

  const users = readJSON(USERS_FILE);
  const user = users.find(u => u.username === username);
  if (!user) return res.status(401).json({ error: 'invalid credentials' });

  if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: 'invalid credentials' });

  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: TOKEN_EXPIRES_IN });
  const safeUser = { id: user.id, username: user.username, email: user.email, created_at: user.created_at };
  res.json({ token, user: safeUser });
});

/* ---------- Messages & stats ---------- */
app.get('/api/messages', authMiddleware, (req, res) => {
  const messages = readJSON(MESSAGES_FILE);
  // return last 200
  res.json(messages.slice(-200));
});

// Create message: server will store and broadcast via ws
app.post('/api/messages', authMiddleware, (req, res) => {
  const { content, isAnonymous } = req.body || {};
  if (!content || typeof content !== 'string') return res.status(400).json({ error: 'content required' });

  const messages = readJSON(MESSAGES_FILE);
  const message = {
    id: uuidv4(),
    content,
    user_id: isAnonymous ? null : req.user.id,
    sender_name: isAnonymous ? 'Anonymous' : req.user.username,
    created_at: new Date().toISOString(),
    delivered: false
  };
  messages.push(message);
  writeJSON(MESSAGES_FILE, messages);

  // Broadcast to all websocket clients that a new message arrived
  broadcastWS({ type: 'new_message', message });

  // Simulate delivery confirmation (mark delivered true and notify sender)
  setTimeout(() => {
    const msgs = readJSON(MESSAGES_FILE);
    const m = msgs.find(x => x.id === message.id);
    if (m) {
      m.delivered = true;
      writeJSON(MESSAGES_FILE, msgs);
      broadcastWS({ type: 'message_delivered', id: message.id });
    }
  }, 700); // 700ms later -> delivered

  res.json({ message });
});

// stats: simple online users count
app.get('/api/stats', (req, res) => {
  const online = wss ? [...wss.clients].filter(c => c.isAlive && c.user).length : 0;
  res.json({ online_users: online });
});

/* ---------- Serve frontend static (optional) ---------- */
app.use('/', express.static(path.join(__dirname, 'public')));

/* ---------- Start server + WebSocket ---------- */
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

function safeSend(ws, obj) {
  try {
    ws.send(JSON.stringify(obj));
  } catch (e) { /* ignore */ }
}

// broadcast to all connected clients
function broadcastWS(obj) {
  const raw = JSON.stringify(obj);
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(raw);
    }
  });
}

// WebSocket connection: optionally pass token as query param ?token=...
wss.on('connection', (ws, req) => {
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });

  // parse token from query param
  const url = req.url || '';
  const query = new URL('http://localhost' + url).searchParams;
  const token = query.get('token');
  if (token) {
    try {
      const payload = jwt.verify(token, JWT_SECRET);
      ws.user = payload;
    } catch (err) {
      // ignore - ws.user undefined for anonymous connections
    }
  }

  // respond to messages from client if needed
  ws.on('message', (raw) => {
    try {
      const data = JSON.parse(raw);
      // optionally handle pings, typing events etc.
      if (data.type === 'ping') safeSend(ws, { type: 'pong' });
    } catch (e) { /* ignore */ }
  });

  ws.on('close', () => { /* closed */ });
});

// heartbeat to remove dead connections
setInterval(() => {
  wss.clients.forEach(ws => {
    if (!ws.isAlive) return ws.terminate();
    ws.isAlive = false;
    ws.ping(() => {});
  });
}, 30000);

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`Static files served from /public (if present).`);
});

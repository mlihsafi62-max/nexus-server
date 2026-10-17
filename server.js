// server.js — Node.js, Express, Socket.io, PostgreSQL
require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const crypto = require('crypto'); 

const app = express();
app.use(cors());
app.use(express.json());

// 🟢 التعديل 1: زيادة مسار رئيسي (Root Route) باش نحيو مشكل Cannot GET /
app.get('/', (req, res) => {
  res.send('Marhba! Server Nexus khdam mzyan! 🚀 (API is running)');
});

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

// 🟢 التعديل 2: زيادة إعدادات للـ Pool باش يتحمل الضغط ديال السيرفرات (Hosting)
const db = new Pool({ 
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 10, // الحد الأقصى ديال الاتصالات
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

// ---------- Auth ----------
app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'missing fields' });
    const hash = await bcrypt.hash(password, 12);
    const result = await db.query(
      'INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id, username',
      [username, hash]
    );
    const user = result.rows[0];
    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'username taken' });
    console.error(e); // 🟢 التعديل 3: طباعة الخطأ فالتيرمينال باش تعرف شنو كاين
    res.status(500).json({ error: 'server error' });
  }
});

app.post('/login', async (req, res) => {
  try { // 🟢 التعديل 4: درنا try/catch باش السيرفر ما يطيحش إلا كان مشكل فالداتابيز
    const { username, password } = req.body;
    const result = await db.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password_hash)))
      return res.status(401).json({ error: 'invalid credentials' });
    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { id: user.id, username: user.username } });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server error' });
  }
});

// ---------- Chat Rooms ----------
app.post('/rooms/create', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  try {
    const { id: userId } = jwt.verify(token, process.env.JWT_SECRET);
    const pass = crypto.randomBytes(3).toString('hex').toUpperCase(); 
    const conv = await db.query('INSERT INTO conversations (is_group) VALUES (TRUE) RETURNING id');
    const roomId = conv.rows[0].id;
    
    await db.query('INSERT INTO conversation_members (conversation_id, user_id) VALUES ($1, $2)', [roomId, userId]);
    await db.query('UPDATE conversations SET room_pass = $1 WHERE id = $2', [pass, roomId]);
    
    res.json({ roomId, roomPass: pass });
  } catch (e) { res.status(401).json({ error: 'unauthorized' }); }
});

app.post('/rooms/join', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  const { roomId, roomPass } = req.body;
  try {
    const { id: userId } = jwt.verify(token, process.env.JWT_SECRET);
    const room = await db.query('SELECT * FROM conversations WHERE id = $1 AND room_pass = $2', [roomId, roomPass]);
    if (!room.rows[0]) return res.status(401).json({ error: 'معطيات غالطة' });

    await db.query('INSERT INTO conversation_members (conversation_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING', [roomId, userId]);
    res.json({ success: true, roomId });
  } catch (e) { res.status(401).json({ error: 'unauthorized' }); }
});

app.get('/messages/:convId', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  try {
    jwt.verify(token, process.env.JWT_SECRET);
    const result = await db.query('SELECT * FROM messages WHERE conversation_id=$1 ORDER BY created_at ASC LIMIT 200', [req.params.convId]);
    res.json(result.rows);
  } catch { res.status(401).json({ error: 'unauthorized' }); }
});

// ---------- Socket.io ----------
io.use((socket, next) => {
  try {
    const payload = jwt.verify(socket.handshake.auth.token, process.env.JWT_SECRET);
    socket.userId = payload.id;
    next();
  } catch { next(new Error('unauthorized')); }
});

io.on('connection', (socket) => {
  socket.join(`user:${socket.userId}`);
  
  socket.on('message:send', async ({ conversationId, body }) => {
    if (!body?.trim()) return;
    try { // 🟢 التعديل 5: درنا try/catch هنا حيت Socket.io كيقدر يطيح السيرفر إلا وقع خطأ
      const member = await db.query('SELECT 1 FROM conversation_members WHERE conversation_id=$1 AND user_id=$2', [conversationId, socket.userId]);
      if (!member.rows[0]) return;
      
      const msg = await db.query('INSERT INTO messages (conversation_id, sender_id, body) VALUES ($1,$2,$3) RETURNING *', [conversationId, socket.userId, body]);
      const members = await db.query('SELECT user_id FROM conversation_members WHERE conversation_id=$1', [conversationId]);
      
      members.rows.forEach(m => io.to(`user:${m.user_id}`).emit('message:new', msg.rows[0]));
    } catch (e) {
      console.error('Socket error:', e);
    }
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`🚀 server on :${PORT}`));
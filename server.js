const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));

const JWT_SECRET = process.env.JWT_SECRET || 'eventflow_secret_2026';

// ── DATABASE ──────────────────────────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
});

// Tạo bảng nếu chưa có
const initDB = async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name VARCHAR(255) NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      password VARCHAR(255) NOT NULL,
      avatar TEXT,
      bio TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS events (
      id SERIAL PRIMARY KEY,
      owner_id INTEGER REFERENCES users(id),
      owner_name VARCHAR(255),
      title VARCHAR(255) NOT NULL,
      datetime TIMESTAMP NOT NULL,
      location TEXT,
      description TEXT,
      category VARCHAR(100) DEFAULT 'Khác',
      max_attendees INTEGER,
      image TEXT,
      members INTEGER[] DEFAULT '{}',
      invites JSONB DEFAULT '[]',
      requests JSONB DEFAULT '[]',
      checked_in INTEGER[] DEFAULT '{}',
      comments JSONB DEFAULT '[]',
      created_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS otps (
      email VARCHAR(255) PRIMARY KEY,
      otp VARCHAR(6) NOT NULL,
      expires BIGINT NOT NULL
    );
  `);
  console.log('✅ Database initialized');
};

initDB().catch(console.error);

// ── MIDDLEWARE ────────────────────────────────────────────────────────────────
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Không có token' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ message: 'Token không hợp lệ' }); }
}

// ── AUTH ──────────────────────────────────────────────────────────────────────

// Gửi OTP
app.post('/api/auth/send-otp', async (req, res) => {
  const { email, type } = req.body;
  try {
    const userExists = await pool.query('SELECT id FROM users WHERE email=$1', [email]);
    if (type === 'register' && userExists.rows.length > 0)
      return res.status(400).json({ message: 'Email đã được sử dụng' });
    if (type === 'forgot' && userExists.rows.length === 0)
      return res.status(400).json({ message: 'Email không tồn tại' });

    const otp = String(Math.floor(100000 + Math.random() * 900000));
    const expires = Date.now() + 5 * 60 * 1000;
    await pool.query('INSERT INTO otps(email,otp,expires) VALUES($1,$2,$3) ON CONFLICT(email) DO UPDATE SET otp=$2,expires=$3', [email, otp, expires]);

    console.log(`[OTP] ${email} → ${otp}`);

    // Gửi email thật nếu có cấu hình
    if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
      try {
        await nodemailer.createTransport({
          service: 'gmail',
          auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
        }).sendMail({
          from: `"EventFlow" <${process.env.EMAIL_USER}>`,
          to: email,
          subject: '[EventFlow] Mã xác minh OTP',
          html: `<div style="font-family:sans-serif;padding:2rem;max-width:400px">
            <h2 style="color:#FF6B35">📅 EventFlow</h2>
            <p>Mã OTP xác minh của bạn:</p>
            <div style="font-size:2.5rem;font-weight:800;letter-spacing:0.3em;color:#FF6B35;text-align:center;padding:1rem;background:#fff3f0;border-radius:0.5rem">${otp}</div>
            <p style="color:#888;font-size:0.85rem">Mã có hiệu lực trong 5 phút.</p>
          </div>`,
        });
        return res.json({ message: 'OTP đã gửi tới email', demo: false });
      } catch (e) { console.error('Email error:', e.message); }
    }
    res.json({ message: 'OTP đã gửi (demo)', otp, demo: true });
  } catch (e) { console.error(e); res.status(500).json({ message: 'Lỗi server' }); }
});

// Đăng ký
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password, otp } = req.body;
  try {
    const otpRow = await pool.query('SELECT * FROM otps WHERE email=$1', [email]);
    if (!otpRow.rows.length || otpRow.rows[0].otp !== otp || Date.now() > Number(otpRow.rows[0].expires))
      return res.status(400).json({ message: 'OTP không đúng hoặc hết hạn' });

    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query('INSERT INTO users(name,email,password) VALUES($1,$2,$3) RETURNING id,name,email', [name, email, hash]);
    await pool.query('DELETE FROM otps WHERE email=$1', [email]);

    const user = result.rows[0];
    const token = jwt.sign({ id: user.id, name: user.name, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user });
  } catch (e) { console.error(e); res.status(500).json({ message: 'Lỗi server' }); }
});

// Đăng nhập
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
    if (!result.rows.length) return res.status(400).json({ message: 'Email không tồn tại' });
    const user = result.rows[0];
    if (!await bcrypt.compare(password, user.password)) return res.status(400).json({ message: 'Mật khẩu không đúng' });
    const token = jwt.sign({ id: user.id, name: user.name, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, avatar: user.avatar, bio: user.bio } });
  } catch (e) { console.error(e); res.status(500).json({ message: 'Lỗi server' }); }
});

// Đặt lại mật khẩu
app.post('/api/auth/reset-password', async (req, res) => {
  const { email, otp, newPassword } = req.body;
  try {
    const otpRow = await pool.query('SELECT * FROM otps WHERE email=$1', [email]);
    if (!otpRow.rows.length || otpRow.rows[0].otp !== otp || Date.now() > Number(otpRow.rows[0].expires))
      return res.status(400).json({ message: 'OTP không đúng hoặc hết hạn' });
    const hash = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET password=$1 WHERE email=$2', [hash, email]);
    await pool.query('DELETE FROM otps WHERE email=$1', [email]);
    res.json({ message: 'Đặt lại mật khẩu thành công' });
  } catch (e) { console.error(e); res.status(500).json({ message: 'Lỗi server' }); }
});

// Cập nhật profile
app.put('/api/auth/profile', auth, async (req, res) => {
  const { name, bio, avatar } = req.body;
  try {
    const result = await pool.query(
      'UPDATE users SET name=COALESCE($1,name), bio=COALESCE($2,bio), avatar=COALESCE($3,avatar) WHERE id=$4 RETURNING id,name,email,avatar,bio',
      [name, bio, avatar, req.user.id]
    );
    res.json(result.rows[0]);
  } catch (e) { console.error(e); res.status(500).json({ message: 'Lỗi server' }); }
});

// Lấy danh sách users
app.get('/api/auth/users', auth, async (req, res) => {
  try {
    const result = await pool.query('SELECT id,name,email,avatar,bio FROM users ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (e) { res.status(500).json({ message: 'Lỗi server' }); }
});

// ── EVENTS ────────────────────────────────────────────────────────────────────

// Lấy tất cả events
app.get('/api/events', auth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM events ORDER BY created_at DESC');
    res.json(result.rows.map(formatEvent));
  } catch (e) { res.status(500).json({ message: 'Lỗi server' }); }
});

// Tạo event
app.post('/api/events', auth, async (req, res) => {
  const { title, datetime, location, description, category, maxAttendees, image } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO events(owner_id,owner_name,title,datetime,location,description,category,max_attendees,image,members) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *',
      [req.user.id, req.user.name, title, datetime, location, description, category||'Khác', maxAttendees||null, image||null, [req.user.id]]
    );
    res.json(formatEvent(result.rows[0]));
  } catch (e) { console.error(e); res.status(500).json({ message: 'Lỗi server' }); }
});

// Cập nhật event
app.put('/api/events/:id', auth, async (req, res) => {
  const { title, datetime, location, description, category, maxAttendees, image } = req.body;
  try {
    const ev = await pool.query('SELECT * FROM events WHERE id=$1', [req.params.id]);
    if (!ev.rows.length) return res.status(404).json({ message: 'Không tìm thấy' });
    if (ev.rows[0].owner_id !== req.user.id) return res.status(403).json({ message: 'Không có quyền' });
    const result = await pool.query(
      'UPDATE events SET title=COALESCE($1,title),datetime=COALESCE($2,datetime),location=COALESCE($3,location),description=COALESCE($4,description),category=COALESCE($5,category),max_attendees=COALESCE($6,max_attendees),image=COALESCE($7,image) WHERE id=$8 RETURNING *',
      [title, datetime, location, description, category, maxAttendees||null, image, req.params.id]
    );
    res.json(formatEvent(result.rows[0]));
  } catch (e) { console.error(e); res.status(500).json({ message: 'Lỗi server' }); }
});

// Xóa event
app.delete('/api/events/:id', auth, async (req, res) => {
  try {
    const ev = await pool.query('SELECT * FROM events WHERE id=$1', [req.params.id]);
    if (!ev.rows.length) return res.status(404).json({ message: 'Không tìm thấy' });
    if (ev.rows[0].owner_id !== req.user.id) return res.status(403).json({ message: 'Không có quyền' });
    await pool.query('DELETE FROM events WHERE id=$1', [req.params.id]);
    res.json({ message: 'Đã xóa' });
  } catch (e) { res.status(500).json({ message: 'Lỗi server' }); }
});

// Gửi lời mời
app.post('/api/events/:id/invite', auth, async (req, res) => {
  const { toUserId } = req.body;
  try {
    const ev = await pool.query('SELECT * FROM events WHERE id=$1', [req.params.id]);
    if (!ev.rows.length) return res.status(404).json({ message: 'Không tìm thấy' });
    const e = ev.rows[0];
    if (e.owner_id !== req.user.id) return res.status(403).json({ message: 'Không có quyền' });
    if (e.members.includes(toUserId)) return res.status(400).json({ message: 'Đã là thành viên' });
    const invites = e.invites || [];
    if (invites.find(i => i.toUserId === toUserId && i.status === 'pending'))
      return res.status(400).json({ message: 'Đã mời rồi' });
    invites.push({ toUserId, status: 'pending' });
    const result = await pool.query('UPDATE events SET invites=$1 WHERE id=$2 RETURNING *', [JSON.stringify(invites), req.params.id]);
    res.json(formatEvent(result.rows[0]));
  } catch (e) { console.error(e); res.status(500).json({ message: 'Lỗi server' }); }
});

// Phản hồi lời mời
app.post('/api/events/:id/invite/respond', auth, async (req, res) => {
  const { action } = req.body;
  try {
    const ev = await pool.query('SELECT * FROM events WHERE id=$1', [req.params.id]);
    if (!ev.rows.length) return res.status(404).json({ message: 'Không tìm thấy' });
    const e = ev.rows[0];
    const invites = e.invites || [];
    const inv = invites.find(i => i.toUserId === req.user.id && i.status === 'pending');
    if (!inv) return res.status(400).json({ message: 'Không có lời mời' });
    inv.status = action === 'accept' ? 'accepted' : 'declined';
    let members = e.members || [];
    if (action === 'accept' && !members.includes(req.user.id)) members.push(req.user.id);
    const result = await pool.query('UPDATE events SET invites=$1,members=$2 WHERE id=$3 RETURNING *', [JSON.stringify(invites), members, req.params.id]);
    res.json(formatEvent(result.rows[0]));
  } catch (e) { console.error(e); res.status(500).json({ message: 'Lỗi server' }); }
});

// Gửi yêu cầu tham gia
app.post('/api/events/:id/request', auth, async (req, res) => {
  try {
    const ev = await pool.query('SELECT * FROM events WHERE id=$1', [req.params.id]);
    if (!ev.rows.length) return res.status(404).json({ message: 'Không tìm thấy' });
    const e = ev.rows[0];
    if (e.members.includes(req.user.id)) return res.status(400).json({ message: 'Đã là thành viên' });
    const requests = e.requests || [];
    if (requests.find(r => r.fromUserId === req.user.id)) return res.status(400).json({ message: 'Đã gửi yêu cầu' });
    requests.push({ fromUserId: req.user.id, fromName: req.user.name, status: 'pending' });
    const result = await pool.query('UPDATE events SET requests=$1 WHERE id=$2 RETURNING *', [JSON.stringify(requests), req.params.id]);
    res.json(formatEvent(result.rows[0]));
  } catch (e) { console.error(e); res.status(500).json({ message: 'Lỗi server' }); }
});

// Duyệt yêu cầu
app.post('/api/events/:id/request/respond', auth, async (req, res) => {
  const { fromUserId, action } = req.body;
  try {
    const ev = await pool.query('SELECT * FROM events WHERE id=$1', [req.params.id]);
    if (!ev.rows.length) return res.status(404).json({ message: 'Không tìm thấy' });
    const e = ev.rows[0];
    if (e.owner_id !== req.user.id) return res.status(403).json({ message: 'Không có quyền' });
    const requests = e.requests || [];
    const r = requests.find(r => r.fromUserId === fromUserId && r.status === 'pending');
    if (!r) return res.status(400).json({ message: 'Không có yêu cầu' });
    r.status = action === 'accept' ? 'accepted' : 'declined';
    let members = e.members || [];
    if (action === 'accept' && !members.includes(fromUserId)) members.push(fromUserId);
    const result = await pool.query('UPDATE events SET requests=$1,members=$2 WHERE id=$3 RETURNING *', [JSON.stringify(requests), members, req.params.id]);
    res.json(formatEvent(result.rows[0]));
  } catch (e) { console.error(e); res.status(500).json({ message: 'Lỗi server' }); }
});

// Check-in
app.post('/api/events/:id/checkin', auth, async (req, res) => {
  try {
    const ev = await pool.query('SELECT * FROM events WHERE id=$1', [req.params.id]);
    if (!ev.rows.length) return res.status(404).json({ message: 'Không tìm thấy' });
    const e = ev.rows[0];
    if (!e.members.includes(req.user.id) && e.owner_id !== req.user.id) return res.status(403).json({ message: 'Chưa là thành viên' });
    if (e.checked_in.includes(req.user.id)) return res.status(400).json({ message: 'Đã check-in rồi' });
    const checkedIn = [...e.checked_in, req.user.id];
    const result = await pool.query('UPDATE events SET checked_in=$1 WHERE id=$2 RETURNING *', [checkedIn, req.params.id]);
    res.json(formatEvent(result.rows[0]));
  } catch (e) { console.error(e); res.status(500).json({ message: 'Lỗi server' }); }
});

// Bình luận
app.post('/api/events/:id/comment', auth, async (req, res) => {
  try {
    const ev = await pool.query('SELECT * FROM events WHERE id=$1', [req.params.id]);
    if (!ev.rows.length) return res.status(404).json({ message: 'Không tìm thấy' });
    const e = ev.rows[0];
    if (!e.members.includes(req.user.id) && e.owner_id !== req.user.id) return res.status(403).json({ message: 'Chưa là thành viên' });
    const comments = e.comments || [];
    comments.push({ userId: req.user.id, text: req.body.text, ts: Date.now() });
    const result = await pool.query('UPDATE events SET comments=$1 WHERE id=$2 RETURNING *', [JSON.stringify(comments), req.params.id]);
    res.json(formatEvent(result.rows[0]));
  } catch (e) { console.error(e); res.status(500).json({ message: 'Lỗi server' }); }
});

// ── FORMAT EVENT ──────────────────────────────────────────────────────────────
function formatEvent(e) {
  return {
    id: e.id,
    ownerId: e.owner_id,
    ownerName: e.owner_name,
    title: e.title,
    datetime: e.datetime,
    location: e.location,
    description: e.description,
    category: e.category,
    maxAttendees: e.max_attendees,
    image: e.image,
    members: e.members || [],
    invites: e.invites || [],
    requests: e.requests || [],
    checkedIn: e.checked_in || [],
    comments: e.comments || [],
  };
}

app.get('/', (req, res) => res.json({ message: '✅ EventFlow API + PostgreSQL đang chạy!' }));

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server: http://localhost:${PORT}`));

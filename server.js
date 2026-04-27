const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));

const JWT_SECRET = process.env.JWT_SECRET || 'eventflow_secret_2026';

// ── STORAGE ───────────────────────────────────────────────────────────────────
let users = [];
let events = [];
const otpStore = {};

// ── MIDDLEWARE ────────────────────────────────────────────────────────────────
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Không có token' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ message: 'Token không hợp lệ' }); }
}

// ── AUTH ──────────────────────────────────────────────────────────────────────
app.post('/api/auth/send-otp', async (req, res) => {
  const { email, type } = req.body;
  if (type === 'register' && users.find(u => u.email === email))
    return res.status(400).json({ message: 'Email đã được sử dụng' });
  if (type === 'forgot' && !users.find(u => u.email === email))
    return res.status(400).json({ message: 'Email không tồn tại' });

  const otp = String(Math.floor(100000 + Math.random() * 900000));
  otpStore[email] = { otp, expires: Date.now() + 5 * 60 * 1000 };
  console.log(`[OTP] ${email} → ${otp}`);

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
          <h2 style="color:#FF6B35">📅 EventFlow - Mã OTP</h2>
          <p>Mã xác minh của bạn:</p>
          <div style="font-size:2.5rem;font-weight:800;letter-spacing:0.3em;color:#FF6B35;text-align:center;padding:1rem;background:#fff3f0;border-radius:0.5rem">${otp}</div>
          <p style="color:#888;font-size:0.85rem">Mã có hiệu lực trong 5 phút. Không chia sẻ mã này với ai.</p>
        </div>`,
      });
      return res.json({ message: 'OTP đã gửi tới email', demo: false });
    } catch (e) { console.error('Email lỗi:', e.message); }
  }
  res.json({ message: 'OTP đã gửi (demo)', otp, demo: true });
});

app.post('/api/auth/register', async (req, res) => {
  const { name, email, password, otp } = req.body;
  const s = otpStore[email];
  if (!s || s.otp !== otp || Date.now() > s.expires)
    return res.status(400).json({ message: 'OTP không đúng hoặc hết hạn' });
  if (users.find(u => u.email === email))
    return res.status(400).json({ message: 'Email đã được sử dụng' });
  const user = { id: Date.now(), name, email, password: await bcrypt.hash(password, 10) };
  users.push(user);
  delete otpStore[email];
  const token = jwt.sign({ id: user.id, name: user.name, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: user.id, name: user.name, email: user.email } });
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email);
  if (!user) return res.status(400).json({ message: 'Email không tồn tại' });
  if (!await bcrypt.compare(password, user.password))
    return res.status(400).json({ message: 'Mật khẩu không đúng' });
  const token = jwt.sign({ id: user.id, name: user.name, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: user.id, name: user.name, email: user.email } });
});

app.post('/api/auth/reset-password', async (req, res) => {
  const { email, otp, newPassword } = req.body;
  const s = otpStore[email];
  if (!s || s.otp !== otp || Date.now() > s.expires)
    return res.status(400).json({ message: 'OTP không đúng hoặc hết hạn' });
  const user = users.find(u => u.email === email);
  if (!user) return res.status(400).json({ message: 'Email không tồn tại' });
  user.password = await bcrypt.hash(newPassword, 10);
  delete otpStore[email];
  res.json({ message: 'Đặt lại mật khẩu thành công' });
});

app.get('/api/auth/users', auth, (req, res) => {
  res.json(users.map(u => ({ id: u.id, name: u.name, email: u.email })));
});

// ── EVENTS ────────────────────────────────────────────────────────────────────
app.get('/api/events', auth, (req, res) => res.json(events));

app.post('/api/events', auth, (req, res) => {
  const ev = {
    id: Date.now(), ownerId: req.user.id, ownerName: req.user.name,
    ...req.body, members: [req.user.id], invites: [], requests: [], checkedIn: [],
  };
  events.push(ev);
  res.json(ev);
});

app.put('/api/events/:id', auth, (req, res) => {
  const ev = events.find(e => e.id == req.params.id);
  if (!ev) return res.status(404).json({ message: 'Không tìm thấy' });
  if (ev.ownerId !== req.user.id) return res.status(403).json({ message: 'Không có quyền' });
  Object.assign(ev, req.body);
  res.json(ev);
});

app.delete('/api/events/:id', auth, (req, res) => {
  const idx = events.findIndex(e => e.id == req.params.id);
  if (idx === -1) return res.status(404).json({ message: 'Không tìm thấy' });
  if (events[idx].ownerId !== req.user.id) return res.status(403).json({ message: 'Không có quyền' });
  events.splice(idx, 1);
  res.json({ message: 'Đã xóa' });
});

app.post('/api/events/:id/invite', auth, (req, res) => {
  const ev = events.find(e => e.id == req.params.id);
  if (!ev) return res.status(404).json({ message: 'Không tìm thấy' });
  if (ev.ownerId !== req.user.id) return res.status(403).json({ message: 'Không có quyền' });
  const { toUserId } = req.body;
  if (ev.members.includes(toUserId)) return res.status(400).json({ message: 'Đã là thành viên' });
  if (ev.invites.find(i => i.toUserId === toUserId && i.status === 'pending'))
    return res.status(400).json({ message: 'Đã mời rồi' });
  ev.invites.push({ toUserId, status: 'pending' });
  res.json(ev);
});

app.post('/api/events/:id/invite/respond', auth, (req, res) => {
  const ev = events.find(e => e.id == req.params.id);
  if (!ev) return res.status(404).json({ message: 'Không tìm thấy' });
  const invite = ev.invites.find(i => i.toUserId === req.user.id && i.status === 'pending');
  if (!invite) return res.status(400).json({ message: 'Không có lời mời' });
  invite.status = req.body.action === 'accept' ? 'accepted' : 'declined';
  if (req.body.action === 'accept') ev.members.push(req.user.id);
  res.json(ev);
});

app.post('/api/events/:id/request', auth, (req, res) => {
  const ev = events.find(e => e.id == req.params.id);
  if (!ev) return res.status(404).json({ message: 'Không tìm thấy' });
  if (ev.members.includes(req.user.id)) return res.status(400).json({ message: 'Đã là thành viên' });
  if (ev.requests.find(r => r.fromUserId === req.user.id))
    return res.status(400).json({ message: 'Đã gửi yêu cầu rồi' });
  ev.requests.push({ fromUserId: req.user.id, fromName: req.user.name, status: 'pending' });
  res.json(ev);
});

app.post('/api/events/:id/request/respond', auth, (req, res) => {
  const ev = events.find(e => e.id == req.params.id);
  if (!ev) return res.status(404).json({ message: 'Không tìm thấy' });
  if (ev.ownerId !== req.user.id) return res.status(403).json({ message: 'Không có quyền' });
  const { fromUserId, action } = req.body;
  const r = ev.requests.find(r => r.fromUserId === fromUserId && r.status === 'pending');
  if (!r) return res.status(400).json({ message: 'Không có yêu cầu' });
  r.status = action === 'accept' ? 'accepted' : 'declined';
  if (action === 'accept') ev.members.push(fromUserId);
  res.json(ev);
});

app.post('/api/events/:id/checkin', auth, (req, res) => {
  const ev = events.find(e => e.id == req.params.id);
  if (!ev) return res.status(404).json({ message: 'Không tìm thấy' });
  if (!ev.members.includes(req.user.id)) return res.status(403).json({ message: 'Chưa là thành viên' });
  if (ev.checkedIn.includes(req.user.id)) return res.status(400).json({ message: 'Đã check-in rồi' });
  ev.checkedIn.push(req.user.id);
  res.json(ev);
});

app.get('/', (req, res) => res.json({ message: '✅ EventFlow API đang chạy!', users: users.length, events: events.length }));

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server: http://localhost:${PORT}`));

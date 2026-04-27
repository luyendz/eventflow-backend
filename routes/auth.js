const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');

// In-memory storage (thay bằng DB sau)
const users = [];
const otpStore = {}; // { email: { otp, expires } }

// Tạo transporter email
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Gửi OTP
router.post('/send-otp', async (req, res) => {
  const { email, type } = req.body; // type: register | forgot

  if (type === 'register' && users.find(u => u.email === email)) {
    return res.status(400).json({ message: 'Email đã được sử dụng' });
  }
  if (type === 'forgot' && !users.find(u => u.email === email)) {
    return res.status(400).json({ message: 'Email không tồn tại' });
  }

  const otp = String(Math.floor(100000 + Math.random() * 900000));
  otpStore[email] = { otp, expires: Date.now() + 5 * 60 * 1000 };

  // Gửi email thật nếu có cấu hình
  if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
    try {
      await transporter.sendMail({
        from: `"EventFlow" <${process.env.EMAIL_USER}>`,
        to: email,
        subject: '[EventFlow] Mã xác minh OTP',
        html: `
          <div style="font-family:sans-serif;max-width:500px;margin:0 auto;padding:2rem;background:#0E0E1C;color:#fff;border-radius:1rem">
            <h2 style="color:#FF6B35">📅 EventFlow</h2>
            <p>Mã OTP xác minh của bạn:</p>
            <div style="font-size:2.5rem;font-weight:800;letter-spacing:0.3em;color:#FF6B35;text-align:center;padding:1rem;background:rgba(255,107,53,0.1);border-radius:0.5rem">${otp}</div>
            <p style="color:#888;font-size:0.85rem">Mã có hiệu lực trong 5 phút. Không chia sẻ mã này với ai.</p>
          </div>
        `,
      });
      res.json({ message: 'OTP đã gửi tới email', demo: false });
    } catch (err) {
      // Fallback: trả OTP về để demo
      res.json({ message: 'OTP đã gửi (demo)', otp, demo: true });
    }
  } else {
    // Chưa cấu hình email → trả về để demo
    res.json({ message: 'OTP đã gửi (demo)', otp, demo: true });
  }
});

// Đăng ký
router.post('/register', async (req, res) => {
  const { name, email, password, otp } = req.body;

  const stored = otpStore[email];
  if (!stored || stored.otp !== otp || Date.now() > stored.expires) {
    return res.status(400).json({ message: 'OTP không đúng hoặc đã hết hạn' });
  }

  if (users.find(u => u.email === email)) {
    return res.status(400).json({ message: 'Email đã được sử dụng' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const user = { id: Date.now(), name, email, password: hashedPassword };
  users.push(user);
  delete otpStore[email];

  const token = jwt.sign(
    { id: user.id, name: user.name, email: user.email },
    process.env.JWT_SECRET || 'eventflow_secret',
    { expiresIn: '7d' }
  );

  res.json({ token, user: { id: user.id, name: user.name, email: user.email } });
});

// Đăng nhập
router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email);
  if (!user) return res.status(400).json({ message: 'Email không tồn tại' });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(400).json({ message: 'Mật khẩu không đúng' });

  const token = jwt.sign(
    { id: user.id, name: user.name, email: user.email },
    process.env.JWT_SECRET || 'eventflow_secret',
    { expiresIn: '7d' }
  );

  res.json({ token, user: { id: user.id, name: user.name, email: user.email } });
});

// Đặt lại mật khẩu
router.post('/reset-password', async (req, res) => {
  const { email, otp, newPassword } = req.body;

  const stored = otpStore[email];
  if (!stored || stored.otp !== otp || Date.now() > stored.expires) {
    return res.status(400).json({ message: 'OTP không đúng hoặc đã hết hạn' });
  }

  const user = users.find(u => u.email === email);
  if (!user) return res.status(400).json({ message: 'Email không tồn tại' });

  user.password = await bcrypt.hash(newPassword, 10);
  delete otpStore[email];

  res.json({ message: 'Đặt lại mật khẩu thành công' });
});

// Lấy danh sách users (để mời)
router.get('/users', (req, res) => {
  res.json(users.map(u => ({ id: u.id, name: u.name, email: u.email })));
});

module.exports = router;

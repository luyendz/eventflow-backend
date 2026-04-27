const express = require('express');
const router = express.Router();
const authMiddleware = require('../middleware/auth');

// In-memory storage
let events = [];

// Lấy tất cả events
router.get('/', authMiddleware, (req, res) => {
  res.json(events);
});

// Tạo event mới
router.post('/', authMiddleware, (req, res) => {
  const { title, datetime, location, description, image } = req.body;
  const event = {
    id: Date.now(),
    ownerId: req.user.id,
    ownerName: req.user.name,
    title, datetime, location, description, image: image || null,
    members: [req.user.id],
    invites: [],
    requests: [],
    checkedIn: [],
    createdAt: new Date().toISOString(),
  };
  events.push(event);
  res.json(event);
});

// Cập nhật event
router.put('/:id', authMiddleware, (req, res) => {
  const event = events.find(e => e.id == req.params.id);
  if (!event) return res.status(404).json({ message: 'Không tìm thấy sự kiện' });
  if (event.ownerId !== req.user.id) return res.status(403).json({ message: 'Không có quyền' });
  Object.assign(event, req.body);
  res.json(event);
});

// Xóa event
router.delete('/:id', authMiddleware, (req, res) => {
  const idx = events.findIndex(e => e.id == req.params.id);
  if (idx === -1) return res.status(404).json({ message: 'Không tìm thấy' });
  if (events[idx].ownerId !== req.user.id) return res.status(403).json({ message: 'Không có quyền' });
  events.splice(idx, 1);
  res.json({ message: 'Đã xóa' });
});

// Gửi lời mời
router.post('/:id/invite', authMiddleware, (req, res) => {
  const event = events.find(e => e.id == req.params.id);
  if (!event) return res.status(404).json({ message: 'Không tìm thấy' });
  if (event.ownerId !== req.user.id) return res.status(403).json({ message: 'Không có quyền' });

  const { toUserId } = req.body;
  if (event.members.includes(toUserId)) return res.status(400).json({ message: 'Người dùng đã là thành viên' });
  if (event.invites.find(i => i.toUserId === toUserId && i.status === 'pending')) {
    return res.status(400).json({ message: 'Đã gửi lời mời rồi' });
  }

  event.invites.push({ toUserId, status: 'pending' });
  res.json(event);
});

// Phản hồi lời mời (accept/decline)
router.post('/:id/invite/respond', authMiddleware, (req, res) => {
  const event = events.find(e => e.id == req.params.id);
  if (!event) return res.status(404).json({ message: 'Không tìm thấy' });

  const { action } = req.body; // accept | decline
  const invite = event.invites.find(i => i.toUserId === req.user.id && i.status === 'pending');
  if (!invite) return res.status(400).json({ message: 'Không có lời mời' });

  invite.status = action === 'accept' ? 'accepted' : 'declined';
  if (action === 'accept' && !event.members.includes(req.user.id)) {
    event.members.push(req.user.id);
  }
  res.json(event);
});

// Gửi yêu cầu tham gia
router.post('/:id/request', authMiddleware, (req, res) => {
  const event = events.find(e => e.id == req.params.id);
  if (!event) return res.status(404).json({ message: 'Không tìm thấy' });
  if (event.members.includes(req.user.id)) return res.status(400).json({ message: 'Đã là thành viên' });
  if (event.requests.find(r => r.fromUserId === req.user.id)) {
    return res.status(400).json({ message: 'Đã gửi yêu cầu rồi' });
  }

  event.requests.push({ fromUserId: req.user.id, fromName: req.user.name, status: 'pending' });
  res.json(event);
});

// Duyệt yêu cầu tham gia
router.post('/:id/request/respond', authMiddleware, (req, res) => {
  const event = events.find(e => e.id == req.params.id);
  if (!event) return res.status(404).json({ message: 'Không tìm thấy' });
  if (event.ownerId !== req.user.id) return res.status(403).json({ message: 'Không có quyền' });

  const { fromUserId, action } = req.body;
  const request = event.requests.find(r => r.fromUserId === fromUserId && r.status === 'pending');
  if (!request) return res.status(400).json({ message: 'Không có yêu cầu' });

  request.status = action === 'accept' ? 'accepted' : 'declined';
  if (action === 'accept' && !event.members.includes(fromUserId)) {
    event.members.push(fromUserId);
  }
  res.json(event);
});

// Check-in
router.post('/:id/checkin', authMiddleware, (req, res) => {
  const event = events.find(e => e.id == req.params.id);
  if (!event) return res.status(404).json({ message: 'Không tìm thấy' });
  if (!event.members.includes(req.user.id)) return res.status(403).json({ message: 'Bạn chưa là thành viên' });
  if (event.checkedIn.includes(req.user.id)) return res.status(400).json({ message: 'Đã check-in rồi' });

  event.checkedIn.push(req.user.id);
  res.json(event);
});

module.exports = router;
 
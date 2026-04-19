const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.options('*', cors());
app.use(express.json());

// ─── MODELS ───────────────────────────────────────────────

const HotelSchema = new mongoose.Schema({
  name: String,
  location: String,
  email: { type: String, unique: true },
  password: String,
  hotelCode: { type: String, unique: true },
}, { timestamps: true });

const Hotel = mongoose.model('Hotel', HotelSchema);

const SharedIDSchema = new mongoose.Schema({
  hotelId: { type: mongoose.Schema.Types.ObjectId, ref: 'Hotel' },
  sidNumber: String,
  guestName: String,
  guestPhone: String,
  guestDOB: String,
  guestGender: String,
  guestAddress: String,
  roomNumber: String,
  comments: String,
  status: { type: String, default: 'pending' },
  sharedAt: { type: Date, default: Date.now },
}, { timestamps: true });

const SharedID = mongoose.model('SharedID', SharedIDSchema);

// ─── MIDDLEWARE ───────────────────────────────────────────

const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ success: false, error: 'No token' });
  try {
    req.hotel = jwt.verify(token, process.env.JWT_SECRET || 'shortid_secret');
    next();
  } catch {
    res.status(401).json({ success: false, error: 'Invalid token' });
  }
};

// ─── HEALTH ───────────────────────────────────────────────

app.get('/', (req, res) => res.json({ message: "ShortID API is running 🚀" }));
app.get('/health', (req, res) => res.json({ status: "OK", message: "ShortID API is running" }));

// ─── HOTEL ROUTES ─────────────────────────────────────────

app.post('/api/hotel/register', async (req, res) => {
  try {
    const { name, location, email, password } = req.body;
    const existing = await Hotel.findOne({ email });
    if (existing) return res.json({ success: false, error: 'Email already registered' });
    const hashed = await bcrypt.hash(password, 10);
    const hotelCode = 'HTL-' + Math.random().toString(36).substring(2, 8).toUpperCase();
    const hotel = await Hotel.create({ name, location, email, password: hashed, hotelCode });
    const token = jwt.sign({ id: hotel._id }, process.env.JWT_SECRET || 'shortid_secret', { expiresIn: '7d' });
    res.json({ success: true, token, hotel: { _id: hotel._id, name: hotel.name, location: hotel.location, email: hotel.email, hotelCode: hotel.hotelCode } });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.post('/api/hotel/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const hotel = await Hotel.findOne({ email });
    if (!hotel) return res.json({ success: false, error: 'Hotel not found' });
    const match = await bcrypt.compare(password, hotel.password);
    if (!match) return res.json({ success: false, error: 'Wrong password' });
    const token = jwt.sign({ id: hotel._id }, process.env.JWT_SECRET || 'shortid_secret', { expiresIn: '7d' });
    res.json({ success: true, token, hotel: { _id: hotel._id, name: hotel.name, location: hotel.location, email: hotel.email, hotelCode: hotel.hotelCode } });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.get('/api/hotel/profile', authMiddleware, async (req, res) => {
  try {
    const hotel = await Hotel.findById(req.hotel.id).select('-password');
    if (!hotel) return res.json({ success: false, error: 'Hotel not found' });
    res.json({ success: true, hotel });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ─── SHARE ROUTES ─────────────────────────────────────────

app.post('/api/share', async (req, res) => {
  try {
    const { hotelCode, sidNumber, guestName, guestPhone, guestDOB, guestGender, guestAddress } = req.body;
    const hotel = await Hotel.findOne({ hotelCode });
    if (!hotel) return res.json({ success: false, error: 'Hotel not found' });
    const shared = await SharedID.create({ hotelId: hotel._id, sidNumber, guestName, guestPhone, guestDOB, guestGender, guestAddress });
    res.json({ success: true, shared });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.get('/api/share/hotel/:hotelId', authMiddleware, async (req, res) => {
  try {
    const sharedIDs = await SharedID.find({ hotelId: req.params.hotelId }).sort({ sharedAt: -1 });
    res.json({ success: true, sharedIDs });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.put('/api/share/approve/:id', authMiddleware, async (req, res) => {
  try {
    const shared = await SharedID.findByIdAndUpdate(req.params.id, { status: 'approved' }, { new: true });
    res.json({ success: true, shared });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.put('/api/share/update-guest/:id', authMiddleware, async (req, res) => {
  try {
    const { roomNumber, comments } = req.body;
    const shared = await SharedID.findByIdAndUpdate(req.params.id, { roomNumber, comments }, { new: true });
    res.json({ success: true, shared });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ─── START ────────────────────────────────────────────────

mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log("✅ Connected to MongoDB"))
  .catch(err => console.error("❌ MongoDB error:", err.message));

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT} - v2`);
});

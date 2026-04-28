const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors({ origin: '*', methods: ['GET','POST','PUT','DELETE','OPTIONS'], allowedHeaders: ['Content-Type','Authorization'] }));
app.options('*', cors());
app.use(express.json());

// ─── AES-256 ENCRYPTION ───────────────────────────────────
// Key must be exactly 32 bytes. We derive it from AES_SECRET env var.
const AES_KEY = crypto.scryptSync(
  process.env.AES_SECRET || 'shortid_default_secret_change_me',
  'shortid_salt',
  32
);
const IV_LENGTH = 16; // AES block size

function encrypt(text) {
  if (!text) return text;
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-cbc', AES_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(String(text), 'utf8'), cipher.final()]);
  // Store as iv:encryptedData (both hex encoded)
  return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text) {
  if (!text || !text.includes(':')) return text; // not encrypted or empty
  try {
    const [ivHex, encryptedHex] = text.split(':');
    const iv = Buffer.from(ivHex, 'hex');
    const encrypted = Buffer.from(encryptedHex, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', AES_KEY, iv);
    const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
    return decrypted.toString('utf8');
  } catch {
    return text; // return as-is if decryption fails (e.g. old unencrypted data)
  }
}

// Encrypt all PII fields of a guest/user object before saving
function encryptGuest(data) {
  return {
    ...data,
    guestName:    encrypt(data.guestName),
    guestPhone:   encrypt(data.guestPhone),
    guestDOB:     encrypt(data.guestDOB),
    guestGender:  encrypt(data.guestGender),
    guestAddress: encrypt(data.guestAddress),
  };
}

// Decrypt all PII fields after reading from DB
function decryptGuest(doc) {
  if (!doc) return doc;
  const d = typeof doc.toObject === 'function' ? doc.toObject() : { ...doc };
  return {
    ...d,
    guestName:    decrypt(d.guestName),
    guestPhone:   decrypt(d.guestPhone),
    guestDOB:     decrypt(d.guestDOB),
    guestGender:  decrypt(d.guestGender),
    guestAddress: decrypt(d.guestAddress),
  };
}

function encryptUser(data) {
  return {
    ...data,
    name:    encrypt(data.name),
    dob:     encrypt(data.dob),
    gender:  encrypt(data.gender),
    address: encrypt(data.address),
  };
}

function decryptUser(doc) {
  if (!doc) return doc;
  const d = typeof doc.toObject === 'function' ? doc.toObject() : { ...doc };
  return {
    ...d,
    name:    decrypt(d.name),
    dob:     decrypt(d.dob),
    gender:  decrypt(d.gender),
    address: decrypt(d.address),
  };
}

// ─── MODELS ───────────────────────────────────────────────

const AdminSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
}, { timestamps: true });
const Admin = mongoose.model('Admin', AdminSchema);

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
  hotelName: String,
  hotelLocation: String,
  sidNumber: String,        // NOT encrypted — needed for lookups
  guestName: String,        // encrypted
  guestPhone: String,       // encrypted
  guestDOB: String,         // encrypted
  guestGender: String,      // encrypted
  guestAddress: String,     // encrypted
  roomNumber: String,       // NOT encrypted — operational
  comments: String,         // NOT encrypted — hotel notes
  status: { type: String, default: 'pending' },
  sharedAt: { type: Date, default: Date.now },
}, { timestamps: true });
const SharedID = mongoose.model('SharedID', SharedIDSchema);

const UserSchema = new mongoose.Schema({
  phone: { type: String, unique: true }, // NOT encrypted — needed for lookup
  sid: { type: String, unique: true },   // NOT encrypted — needed for lookup
  name: String,     // encrypted
  dob: String,      // encrypted
  gender: String,   // encrypted
  address: String,  // encrypted
}, { timestamps: true });
const User = mongoose.model('User', UserSchema);

// ─── MIDDLEWARE ───────────────────────────────────────────

const authHotel = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ success: false, error: 'No token' });
  try { req.hotel = jwt.verify(token, process.env.JWT_SECRET || 'shortid_secret'); next(); }
  catch { res.status(401).json({ success: false, error: 'Invalid token' }); }
};

const authAdmin = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ success: false, error: 'No token' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'shortid_secret');
    if (!decoded.isAdmin) return res.status(403).json({ success: false, error: 'Not an admin' });
    req.admin = decoded;
    next();
  } catch { res.status(401).json({ success: false, error: 'Invalid token' }); }
};

// ─── HEALTH ───────────────────────────────────────────────

app.get('/', (req, res) => res.json({ message: "ShortID API is running 🚀", encryption: "AES-256-CBC" }));
app.get('/health', (req, res) => res.json({ status: "OK" }));

// ─── ADMIN AUTH ───────────────────────────────────────────

app.post('/api/admin/setup', async (req, res) => {
  try {
    const count = await Admin.countDocuments();
    if (count > 0) return res.json({ success: false, error: 'Admin already exists. Use login.' });
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.json({ success: false, error: 'All fields required' });
    const hashed = await bcrypt.hash(password, 10);
    const admin = await Admin.create({ name, email, password: hashed });
    const token = jwt.sign({ id: admin._id, isAdmin: true }, process.env.JWT_SECRET || 'shortid_secret', { expiresIn: '7d' });
    res.json({ success: true, token, admin: { _id: admin._id, name: admin.name, email: admin.email } });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.post('/api/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const admin = await Admin.findOne({ email });
    if (!admin) return res.json({ success: false, error: 'Admin not found' });
    const match = await bcrypt.compare(password, admin.password);
    if (!match) return res.json({ success: false, error: 'Wrong password' });
    const token = jwt.sign({ id: admin._id, isAdmin: true }, process.env.JWT_SECRET || 'shortid_secret', { expiresIn: '7d' });
    res.json({ success: true, token, admin: { _id: admin._id, name: admin.name, email: admin.email } });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// ─── ADMIN ROUTES ─────────────────────────────────────────

app.get('/api/admin/stats', authAdmin, async (req, res) => {
  try {
    const [totalHotels, totalGuests, pendingGuests, approvedGuests, totalUsers] = await Promise.all([
      Hotel.countDocuments(),
      SharedID.countDocuments(),
      SharedID.countDocuments({ status: 'pending' }),
      SharedID.countDocuments({ status: 'approved' }),
      User.countDocuments(),
    ]);
    res.json({ success: true, stats: { totalHotels, totalGuests, pendingGuests, approvedGuests, totalUsers } });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.get('/api/admin/hotels', authAdmin, async (req, res) => {
  try {
    const hotels = await Hotel.find().select('-password').sort({ createdAt: -1 });
    const hotelsWithCount = await Promise.all(hotels.map(async h => {
      const guestCount = await SharedID.countDocuments({ hotelId: h._id });
      return { ...h.toObject(), guestCount };
    }));
    res.json({ success: true, hotels: hotelsWithCount });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.get('/api/admin/hotels/:hotelId/guests', authAdmin, async (req, res) => {
  try {
    const guests = await SharedID.find({ hotelId: req.params.hotelId }).sort({ sharedAt: -1 });
    res.json({ success: true, guests: guests.map(decryptGuest) });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.get('/api/admin/guests', authAdmin, async (req, res) => {
  try {
    const guests = await SharedID.find().sort({ sharedAt: -1 }).limit(200);
    res.json({ success: true, guests: guests.map(decryptGuest) });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.get('/api/admin/users', authAdmin, async (req, res) => {
  try {
    const users = await User.find().sort({ createdAt: -1 });
    res.json({ success: true, users: users.map(decryptUser) });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.post('/api/admin/hotels', authAdmin, async (req, res) => {
  try {
    const { name, location, email, password } = req.body;
    if (!name || !location || !email || !password) return res.json({ success: false, error: 'All fields required' });
    const existing = await Hotel.findOne({ email });
    if (existing) return res.json({ success: false, error: 'Email already registered' });
    const hashed = await bcrypt.hash(password, 10);
    const hotelCode = 'HTL-' + Math.random().toString(36).substring(2, 8).toUpperCase();
    const hotel = await Hotel.create({ name, location, email, password: hashed, hotelCode });
    res.json({ success: true, hotel: { _id: hotel._id, name: hotel.name, location: hotel.location, email: hotel.email, hotelCode: hotel.hotelCode } });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.delete('/api/admin/hotels/:hotelId', authAdmin, async (req, res) => {
  try {
    await Hotel.findByIdAndDelete(req.params.hotelId);
    await SharedID.deleteMany({ hotelId: req.params.hotelId });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.delete('/api/admin/guests/:guestId', authAdmin, async (req, res) => {
  try {
    await SharedID.findByIdAndDelete(req.params.guestId);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// ─── HOTEL AUTH ───────────────────────────────────────────

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
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
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
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.get('/api/hotel/profile', authHotel, async (req, res) => {
  try {
    const hotel = await Hotel.findById(req.hotel.id).select('-password');
    if (!hotel) return res.json({ success: false, error: 'Hotel not found' });
    res.json({ success: true, hotel });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// ─── SHARE ROUTES ─────────────────────────────────────────

app.post('/api/share', async (req, res) => {
  try {
    const { hotelCode, sidNumber, guestName, guestPhone, guestDOB, guestGender, guestAddress } = req.body;
    const hotel = await Hotel.findOne({ hotelCode });
    if (!hotel) return res.json({ success: false, error: 'Hotel not found. Check the QR code.' });
    // Encrypt PII before saving
    const shared = await SharedID.create(encryptGuest({
      hotelId: hotel._id, hotelName: hotel.name, hotelLocation: hotel.location,
      sidNumber, guestName, guestPhone, guestDOB, guestGender, guestAddress
    }));
    res.json({ success: true, shared: decryptGuest(shared) });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.get('/api/share/hotel/:hotelId', authHotel, async (req, res) => {
  try {
    const sharedIDs = await SharedID.find({ hotelId: req.params.hotelId }).sort({ sharedAt: -1 });
    res.json({ success: true, sharedIDs: sharedIDs.map(decryptGuest) });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.get('/api/share/guest/:phone', async (req, res) => {
  try {
    // Phone is stored encrypted so we encrypt the search param to match
    const encryptedPhone = encrypt(req.params.phone);
    // We can't query encrypted fields directly — fetch all and filter in memory
    // For scale this would need a HMAC index, but fine for now
    const allShares = await SharedID.find().sort({ sharedAt: -1 });
    const shares = allShares.filter(s => decrypt(s.guestPhone) === req.params.phone);
    res.json({ success: true, shares: shares.map(decryptGuest) });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.put('/api/share/approve/:id', authHotel, async (req, res) => {
  try {
    const shared = await SharedID.findByIdAndUpdate(req.params.id, { status: 'approved' }, { new: true });
    res.json({ success: true, shared: decryptGuest(shared) });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.put('/api/share/update-guest/:id', authHotel, async (req, res) => {
  try {
    const { roomNumber, comments } = req.body;
    const shared = await SharedID.findByIdAndUpdate(req.params.id, { roomNumber, comments }, { new: true });
    res.json({ success: true, shared: decryptGuest(shared) });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// ─── USER ROUTES ──────────────────────────────────────────

app.get('/api/user/:phone', async (req, res) => {
  try {
    const user = await User.findOne({ phone: req.params.phone });
    if (user) {
      res.json({ success: true, exists: true, user: decryptUser(user) });
    } else {
      res.json({ success: true, exists: false });
    }
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.post('/api/user/register', async (req, res) => {
  try {
    const { phone, sid, name, dob, gender, address } = req.body;
    if (!phone || !sid || !name) return res.json({ success: false, error: 'Missing required fields' });
    const user = await User.findOneAndUpdate(
      { phone },
      { phone, sid, ...encryptUser({ name, dob, gender, address }) },
      { upsert: true, new: true }
    );
    res.json({ success: true, user: decryptUser(user) });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.put('/api/user/:phone', async (req, res) => {
  try {
    const { name, dob, gender, address } = req.body;
    const user = await User.findOneAndUpdate(
      { phone: req.params.phone },
      encryptUser({ name, dob, gender, address }),
      { new: true }
    );
    if (!user) return res.json({ success: false, error: 'User not found' });
    res.json({ success: true, user: decryptUser(user) });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// ─── START ────────────────────────────────────────────────

mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log("✅ Connected to MongoDB"))
  .catch(err => console.error("❌ MongoDB error:", err.message));

app.listen(PORT, '0.0.0.0', () => console.log(`Server running on port ${PORT} - v6 (AES-256 encrypted)`));

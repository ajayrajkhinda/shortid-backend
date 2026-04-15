const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
dotenv.config();

const app = express();

// Let Render control the port
const PORT = process.env.PORT || 10000;

// Middleware
app.use(express.json());

// Root route
app.get('/', (req, res) => {
  res.json({ message: "ShortID API is running 🚀" });
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: "OK", message: "ShortID API is running" });
});

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log("✅ Connected to MongoDB"))
  .catch(err => console.error("❌ MongoDB error:", err.message));

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});


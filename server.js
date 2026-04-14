const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');

dotenv.config();
const app = express();

// Always use Railway's injected PORT, fallback to 8080 locally
const PORT = process.env.PORT || 8080;

// Middleware
app.use(express.json());

// Health check endpoint (always available)
app.get('/health', (req, res) => {
  res.json({ status: "OK", message: "ShortID API is running" });
});

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => {
  console.log("✅ Connected to MongoDB successfully");
})
.catch(err => {
  console.error("❌ MongoDB connection error:", err.message);
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});



const express = require('express');
const dotenv = require('dotenv');

dotenv.config();
const app = express();

// Always use Railway's injected PORT, fallback to 8080 locally
const PORT = process.env.PORT || 8080;

// Middleware
app.use(express.json());

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: "OK", message: "ShortID API is running" });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});


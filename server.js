const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
dotenv.config();

const app = express();
const PORT = process.env.PORT || 8080;

app.use(express.json());

// Root route
app.get('/', (req, res) => {
  res.json({ message: "ShortID API is running 🚀" });
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: "OK", message: "ShortID API is running" });
});

// Your other routes here
// const shortidRoutes = require('./routes/shortid');
// app.use('/api', shortidRoutes);

mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log("✅ Connected to MongoDB"))
  .catch(err => console.error("❌ MongoDB error:", err.message));

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));


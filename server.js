require('dotenv').config();
const express = require('express');
const app = express();
const PORT = process.env.PORT || 7000;
const connectDB = require('./configs/db');
connectDB();

const cookieParser = require('cookie-parser');
app.use(cookieParser());

// Middleware to parse JSON requests

app.use(express.json());

app.get('/', (req, res) => {
    res.send('JWT Authentication Server is running');
});

const authRoutes = require('./routes/auth');
app.use('/api/auth', authRoutes);

const profileRoutes = require('./routes/profile');
app.use('/api/profile', profileRoutes);

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
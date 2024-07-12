const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const mysql = require('mysql2/promise');
require('dotenv').config()
const cookieParser = require('cookie-parser');

const app = express();
const port = process.env.PORT || 5001;
const JWT_SECRET = 'test_key';

app.use(express.json())
app.use(cookieParser())
app.use(cors({
    origin: 'http://localhost:5173',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
}));

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

pool.getConnection((err, connection) => {
    if (err) {
        console.error('Error connecting to mysql database', err);
        return;
    }
    console.log('Connected to mysql database!');
    connection.release();
});

function authenticateToken(req, res, next) {
    const token = req.cookies.token;

    if (!token) {
        return res.status(401).json({ message: "Unauthorized: No token provided" });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            console.error("JWT verification error: ", err);
            return res.status(403).json({ message: "Forbidden Invalid Token" });
        }
        req.user = user;
        next();
    });
}

app.get('/api/me', authenticateToken, async (req, res) => {
    try {
        const userData = req.user;
        console.log("User data: ", userData);
        const [rows] = await pool.execute(
            'SELECT * FROM users WHERE username = ?',
            [userData.username]
        );
        const user = rows[0];
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.json(user);
    } catch (error) {
        res.status(500).json({ message: 'Failed to fetch user data' });
    }
});

app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);

    pool.execute(
        'INSERT INTO users (username, password) VALUES (?, ?)',
        [username, hashedPassword]
    ).then(([result]) => {
        console.log(result);
        res.status(201).json({ message: 'User registered' });
    }).catch((error) => {
        console.error(error)
        res.status(500).json({ message: "Registration Failed" });
    })
});

app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        const [rows] = await pool.execute(
            'SELECT * FROM users WHERE username = ?',
            [username]
        );
        const user = rows[0];
        if (!user) {
            return res.status(401).json({ message: 'Invalid Credentials' });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Invalid Credentials' });
        }

        const token = jwt.sign({ username: user.username, id: user.id }, JWT_SECRET);

        res.cookie('token', token, {
            httpOnly: true,
            //secure: true, enable on https
            sameSite: 'lax',
            maxAge: 3600000,
            path: '/',
        });

        res.json({ message: "Logged in Successfully" });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Login Failed From Server" });
    }
});

app.post('/api/logout', async (req, res) => {
    res.clearCookie('token', {
        httpOnly: true,
        sameSite: 'lax', 
        path: '/'
    });

    res.json({ message: 'Logged out successfully' });
});

app.post('/api/add-exercise', authenticateToken, async (req, res) => {
    try {
        const { exercise, time } = req.body;
        const userId = req.user.id;
        
        const [result] = await pool.execute(
            'INSERT INTO exercises (user_id, exercise, time) VALUES (?, ?, ?)',
            [userId, exercise, time]
        );

        res.status(201).json({ message: 'Exercise added successfully', id: result.insertId});
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Failed to add exercise'});
    }
});

app.get('/api/exercises', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;

        const [rows] = await pool.execute(
            'SELECT * FROM exercises WHERE user_id = ?',
            [userId]
        );

        res.json(rows);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Failed to fetch exercises' });
    }
})

app.listen((port), () => {
    console.log(`Server is running on port: ${port}`);
});
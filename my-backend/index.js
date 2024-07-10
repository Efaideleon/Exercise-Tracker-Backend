const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const mysql = require('mysql2/promise');
require('dotenv').config()

const app = express();
const port = process.env.PORT || 5001;
const JWT_SECRET = 'test_key';

app.use(express.json())
app.use(cors())

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

        const token = jwt.sign({ username: user.username }, JWT_SECRET);
        res.json({ token });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Login Failed From Server" });
    }
});

app.listen((port), () => {
    console.log(`Server is running on port: ${port}`);
})
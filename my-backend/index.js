const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const port = process.env.PORT || 5001;
const JWT_SECRET = 'test_key';

app.use(express.json())
app.use(cors())

const users = []

app.post('/api/register', async (req, res) => {
    try {
        const { username, password } = req.body;

        const hashedPassword = await bcrypt.hash(password, 10);
        users.push({ username, hashedPassword });

        res.status(200).json({ message: "User registed!" });

    } catch (error) {
        console.error(error)
        res.status(500).json({ message: "Registration Failed" });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        const user = users.find((user) => user.username == username)

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
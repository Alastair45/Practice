// Dependencies Used
const mysql = require('mysql2/promise');
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();

// Middleware (type in urlencoded section of the body)
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Database Connection
const pool = mysql.createPool({
    host: process.env.DBHost || 'localhost',
    user: process.env.DBUsername,
    password: process.env.DBPassword,
    database: process.env.DBName || 'myblogposts_db'
});
// Rate Limiter (100 transactions, resets every 2 minutes)
app.use(rateLimit({
    windowMs: 2 * 60 * 1000,
    max: 100
}));


// Authentication Middleware (Using JWT)
const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    
    if (!token) return res.status(401).json({ error: 'Error: Auth Token Not Found' });
    if (!process.env.JWTSecret) return res.status(500).json({ error: 'Error: Unconfigured JWT Secret' });

    jwt.verify(token, process.env.JWTSecret, (err, user) => {
        if (err) return res.status(403).json({ error: 'Error: Token Invalid o Expired' });
        req.user = user;
        next();
    });
};

// POST Method Login
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    
    if (!process.env.JWTSecret) return res.status(500).json({ error: 'Error: Unconfigured JWT Secret' });
    if (!username || !password) return res.status(400).json({ error: 'Error: Missing fields must be filled (username, password)' });

    if (username === process.env.AdminUsername && password === process.env.AdminPassword) {
        const token = jwt.sign({ username }, process.env.JWTSecret, { expiresIn: '1h' });
        res.json({ 
            message: 'Success: You logged in the system!',
            token 
        });
    } else {
        res.status(401).json({ error: 'Unsuccessful: Invalid Login Credentials' });
    }
});

// GET Method (All Posts)
app.get('/posts', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT id, title, content, author FROM posts');
        res.json({
            message: 'Success: All posts have been retrieved!',
            data: rows
        });
    } catch (error) {
        res.status(500).json({ error: 'Unsuccessful: Something went wrong! Please try again later.' });
    }
});

// GET Method (Posts by ID)
app.get('/posts/:id', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT id, title, content, author FROM posts WHERE id = ?', [req.params.id]);
        if (rows.length === 0) return res.status(404).json({ error: 'Unsuccessful: Post cannot be found!' });
        res.json({
            message: 'Success: A post has been retrieved!',
            data: rows[0]
        });
    } catch (error) {
        res.status(500).json({ error: 'Unsuccessful: Something went wrong! Please try again later.' });
    }
});

// POST Method (Add a Post)
app.post('/posts', authenticateToken, async (req, res) => {
    const { title, content, author } = req.body;  
    if (!title || !content || !author) {
        return res.status(400).json({ error: 'Error: Missing fields must be filled (title, content, author)' });
    }
    try {
        const [result] = await pool.query(
            'INSERT INTO posts (title, content, author) VALUES (?, ?, ?)',
            [title, content, author]
        );
        res.status(201).json({
            message: 'Success: A post has been created!',
            data: { id: result.insertId, title, content, author }
        });
    } catch (error) {
        res.status(500).json({ error: 'Unsuccessful: Something went wrong! Please try again later.' });
    }
});

// PUT Method (Update a Post by ID)
app.put('/posts/:id', authenticateToken, async (req, res) => {
    const { title, content, author } = req.body;
    if (!title || !content || !author) {
        return res.status(400).json({ error: 'Error: Missing fields must be filled (title, content, author)' });
    }
    try {
        const [result] = await pool.query(
            'UPDATE posts SET title = ?, content = ?, author = ? WHERE id = ?',
            [title, content, author, req.params.id]
        );
        if (result.affectedRows === 0) return res.status(404).json({ error: 'Unsuccessful: Post cannot be found!' });
        res.json({
            message: 'Success: A post has been updated!',
            data: { id: req.params.id, title, content, author }
        });
    } catch (error) {
        res.status(500).json({ error: 'Unsuccessful: Something went wrong! Please try again later.' });
    }
});

// DELETE Method (Delete a Post by ID)
app.delete('/posts/:id', authenticateToken, async (req, res) => {
    try {
        const [result] = await pool.query('DELETE FROM posts WHERE id = ?', [req.params.id]);
        if (result.affectedRows === 0) return res.status(404).json({ error: 'Unsuccessful: Post cannot be found!' });
        res.json({
            message: 'Success: A post has been deleted!',
            data: { id: req.params.id }
        });
    } catch (error) {
        res.status(500).json({ error: 'Unsuccessful: Something went wrong! Please try again later.' });
    }
});

// Hosting Using Localhost Port
const Port = process.env.Port || 3000;
app.listen(Port, () => console.log(`Server running on http//:localhost${Port}`)); 
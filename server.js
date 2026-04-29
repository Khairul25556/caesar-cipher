// server.js - Fixed: tables created before server starts
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const session = require('express-session');
const path = require('path');

const app = express();
const PORT = 3010;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({
    secret: 'caesar_cipher_secret_key_2024',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 3600000 }
}));

// Database connection
const db = new sqlite3.Database('./chat.db');

// Function to initialize database and then start server
function initDatabaseAndStartServer() {
    db.serialize(() => {
        // Create users table
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )`);

        // Create messages table
        db.run(`CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            cipher_text TEXT NOT NULL,
            encryption_key INTEGER NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (sender_id) REFERENCES users(id),
            FOREIGN KEY (receiver_id) REFERENCES users(id)
        )`);

        // Create settings table
        db.run(`CREATE TABLE IF NOT EXISTS settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            rule_name TEXT NOT NULL,
            key_value INTEGER NOT NULL CHECK (key_value BETWEEN 1 AND 25)
        )`, (err) => {
            if (err) {
                console.error('Error creating settings table:', err);
            } else {
                // Insert default settings if not exists
                db.get(`SELECT * FROM settings WHERE id = 1`, (err, row) => {
                    if (!row) {
                        db.run(`INSERT INTO settings (id, rule_name, key_value) VALUES (1, 'Caesar_k3', 3)`);
                    }
                });
            }
        });

        // Create admin user if not exists
        db.get(`SELECT * FROM users WHERE username = 'admin'`, (err, row) => {
            if (!row) {
                bcrypt.hash('admin@123', 10, (err, hash) => {
                    if (!err) {
                        db.run(`INSERT INTO users (username, password_hash) VALUES ('admin', ?)`, [hash]);
                    }
                });
            }
        });

        // Start server only after all table operations are queued
        app.listen(PORT, () => {
            console.log(`Secure Chat System running on http://localhost:${PORT}`);
            console.log(`Admin login: admin / admin@123`);
            console.log('Database initialized and server ready.');
        });
    });
}

// Start the initialization process
initDatabaseAndStartServer();

// ==================== CAESAR CIPHER UTILITIES ====================
function caesarEncrypt(text, shift) {
    if (!text) return '';
    shift = ((shift % 26) + 26) % 26;
    return text.split('').map(char => {
        if (char >= 'a' && char <= 'z') {
            return String.fromCharCode(((char.charCodeAt(0) - 97 + shift) % 26) + 97);
        } else if (char >= 'A' && char <= 'Z') {
            return String.fromCharCode(((char.charCodeAt(0) - 65 + shift) % 26) + 65);
        }
        return char;
    }).join('');
}

function caesarDecrypt(cipherText, shift) {
    return caesarEncrypt(cipherText, 26 - (shift % 26));
}

function getCurrentKey(callback) {
    db.get(`SELECT key_value FROM settings WHERE id = 1`, (err, row) => {
        if (err || !row) callback(3);
        else callback(row.key_value);
    });
}

// ==================== AUTHENTICATION MIDDLEWARE ====================
function requireAuth(req, res, next) {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Authentication required' });
    }
    next();
}

function requireAdmin(req, res, next) {
    if (!req.session.userId || req.session.username !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    next();
}

// ==================== API ROUTES ====================
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password required' });
    }
    
    try {
        const hash = await bcrypt.hash(password, 10);
        db.run(`INSERT INTO users (username, password_hash) VALUES (?, ?)`, [username, hash], function(err) {
            if (err) {
                if (err.message.includes('UNIQUE')) {
                    return res.status(400).json({ error: 'Username already exists' });
                }
                return res.status(500).json({ error: 'Registration failed' });
            }
            res.json({ success: true, message: 'Registration successful' });
        });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
        if (err || !user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        const valid = await bcrypt.compare(password, user.password_hash);
        if (!valid) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        req.session.userId = user.id;
        req.session.username = user.username;
        req.session.isAdmin = (user.username === 'admin');
        res.json({ success: true, username: user.username, isAdmin: user.username === 'admin' });
    });
});

app.post('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

app.get('/api/me', (req, res) => {
    if (req.session.userId) {
        res.json({ 
            loggedIn: true, 
            username: req.session.username, 
            isAdmin: req.session.isAdmin,
            userId: req.session.userId 
        });
    } else {
        res.json({ loggedIn: false });
    }
});

app.get('/api/users', requireAuth, (req, res) => {
    db.all(`SELECT id, username FROM users WHERE id != ?`, [req.session.userId], (err, users) => {
        if (err) {
            res.status(500).json({ error: 'Failed to fetch users' });
        } else {
            res.json(users);
        }
    });
});

app.get('/api/messages/:userId', requireAuth, (req, res) => {
    const otherUserId = req.params.userId;
    const currentUserId = req.session.userId;
    
    db.all(`
        SELECT m.id, m.cipher_text, m.encryption_key, m.timestamp, 
               u.username as sender_name, m.sender_id
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE (m.sender_id = ? AND m.receiver_id = ?) 
           OR (m.sender_id = ? AND m.receiver_id = ?)
        ORDER BY m.timestamp ASC
    `, [currentUserId, otherUserId, otherUserId, currentUserId], (err, messages) => {
        if (err) {
            res.status(500).json({ error: 'Failed to fetch messages' });
        } else {
            res.json(messages);
        }
    });
});

app.post('/api/send-message', requireAuth, (req, res) => {
    const { receiverId, plaintext } = req.body;
    if (!receiverId || !plaintext) {
        return res.status(400).json({ error: 'Receiver and message required' });
    }
    
    getCurrentKey((currentKey) => {
        const cipherText = caesarEncrypt(plaintext, currentKey);
        db.run(`
            INSERT INTO messages (sender_id, receiver_id, cipher_text, encryption_key)
            VALUES (?, ?, ?, ?)
        `, [req.session.userId, receiverId, cipherText, currentKey], function(err) {
            if (err) {
                res.status(500).json({ error: 'Failed to send message' });
            } else {
                res.json({ 
                    success: true, 
                    messageId: this.lastID,
                    cipherText: cipherText,
                    keyUsed: currentKey
                });
            }
        });
    });
});

app.post('/api/decrypt-message', requireAuth, (req, res) => {
    const { messageId } = req.body;
    const currentUserId = req.session.userId;
    
    db.get(`
        SELECT m.cipher_text, m.encryption_key, m.sender_id, m.receiver_id
        FROM messages m
        WHERE m.id = ?
    `, [messageId], (err, message) => {
        if (err || !message) {
            return res.status(404).json({ error: 'Message not found' });
        }
        if (message.sender_id !== currentUserId && message.receiver_id !== currentUserId) {
            return res.status(403).json({ error: 'Access denied' });
        }
        
        const plaintext = caesarDecrypt(message.cipher_text, message.encryption_key);
        res.json({ plaintext: plaintext });
    });
});

app.get('/api/settings', (req, res) => {
    db.get(`SELECT rule_name, key_value FROM settings WHERE id = 1`, (err, settings) => {
        if (err || !settings) {
            res.json({ rule_name: 'Caesar_k3', key_value: 3 });
        } else {
            res.json(settings);
        }
    });
});

app.put('/api/settings', requireAdmin, (req, res) => {
    const { rule_name, key_value } = req.body;
    const key = parseInt(key_value);
    
    if (isNaN(key) || key < 1 || key > 25) {
        return res.status(400).json({ error: 'Key must be between 1 and 25' });
    }
    if (!rule_name || rule_name.trim() === '') {
        return res.status(400).json({ error: 'Rule name required' });
    }
    
    db.run(`UPDATE settings SET rule_name = ?, key_value = ? WHERE id = 1`, 
        [rule_name, key], function(err) {
        if (err) {
            res.status(500).json({ error: 'Failed to update settings' });
        } else {
            res.json({ success: true, rule_name, key_value: key });
        }
    });
});

// ==================== PAGE ROUTES ====================
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/chat', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'chat.html'));
});

app.get('/processes', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'processes.html'));
});

app.get('/bruteforce', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'bruteforce.html'));
});

app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});
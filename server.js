require('dotenv').config();
const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
const os = require('os');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

function broadcastToAdmins(eventData) {
    const payload = JSON.stringify({ ...eventData, timestamp: new Date().toISOString() });
    wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN && client.isAdmin) {
            client.send(payload);
        }
    });
}

wss.on('connection', (ws) => {
    ws.on('message', (message) => {
        try {
            const data = JSON.parse(message);
            if (data.type === 'AUTH' && data.adminKey === ADMIN_MASTER_KEY) {
                ws.isAdmin = true;
                ws.send(JSON.stringify({ type: 'SYSTEM', message: 'WebSocket Authenticated. Live Firehose Active.' }));
            }
        } catch (e) {}
    });
});

app.use(cors());
app.use(express.json({ limit: '50mb' }));
// Force no-caching for key HTML files and sw.js, cache static assets aggressively
app.use(express.static(__dirname, {
    setHeaders: (res, path) => {
        if (path.endsWith('index.html') || path.endsWith('sw.js') || path.endsWith('landing.html') || path.endsWith('login.html') || path.endsWith('admin.html') || path.endsWith('manifest.json')) {
            res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
            res.setHeader('Pragma', 'no-cache');
            res.setHeader('Expires', '0');
        } else if (/\.(jpg|jpeg|png|gif|svg|webp|avif|ico|css|js|woff|woff2|ttf|eot)$/i.test(path)) {
            res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
        }
    }
}));

const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret_key';
const ADMIN_MASTER_KEY = 'adminaryan';

// Initialize SQLite Database
const db = new sqlite3.Database(path.join(__dirname, 'fluxo.sqlite'), (err) => {
    if (err) {
        console.error('Database connection error:', err);
    } else {
        console.log('Connected to SQLite database.');
        
        // Users Table
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            password TEXT,
            status TEXT DEFAULT 'active',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);
        
        // Messages Table
        db.run(`CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            role TEXT,
            content TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )`);

        // Settings Table
        db.run(`CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )`, () => {
            // Seed API Key from .env if not exists
            if (process.env.GROQ_API_KEY) {
                db.run(`INSERT OR IGNORE INTO settings (key, value) VALUES ('groq_api_key', ?)`, [process.env.GROQ_API_KEY]);
            }
        });

        // Broadcasts Table
        db.run(`CREATE TABLE IF NOT EXISTS broadcasts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message TEXT,
            is_active BOOLEAN DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);
        
        // Add 'status' column to existing databases if it doesn't exist
        db.run(`ALTER TABLE users ADD COLUMN status TEXT DEFAULT 'active'`, (err) => {
            // Ignore error if column already exists
        });
    }
});

// Middleware to authenticate JWT token
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Access Denied. Please log in.' });

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ error: 'Invalid Token.' });
        
        // Check if banned
        db.get(`SELECT status FROM users WHERE id = ?`, [decoded.id], (err, row) => {
            if (err || !row) return res.status(403).json({ error: 'User not found.' });
            if (row.status === 'banned') return res.status(403).json({ error: 'ACCOUNT BANNED. Contact Administrator.' });
            req.user = decoded;
            next();
        });
    });
}

// ----------------------------------------------------
// AUTH ROUTES
// ----------------------------------------------------
app.post('/api/register', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required.' });

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.run(`INSERT INTO users (email, password) VALUES (?, ?)`, [email, hashedPassword], function(err) {
            if (err) {
                if (err.message.includes('UNIQUE constraint failed')) {
                    return res.status(400).json({ error: 'Email already in use.' });
                }
                return res.status(500).json({ error: 'Database error.' });
            }
            const token = jwt.sign({ id: this.lastID, email }, JWT_SECRET);
            const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
            console.log(`\n[SECURITY AUDIT] New Account Created: ${email} | IP: ${ip} | Time: ${new Date().toLocaleString()}`);
            broadcastToAdmins({ type: 'USER_REGISTER', email, ip });
            res.json({ token, message: 'Registration successful.' });
        });
    } catch (err) {
        res.status(500).json({ error: 'Server error.' });
    }
});

app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, user) => {
        try {
            if (err) return res.status(500).json({ error: 'Database error.' });
            if (!user) return res.status(400).json({ error: 'Invalid email or password.' });
            if (user.status === 'banned') return res.status(403).json({ error: 'ACCOUNT BANNED.' });

            const validPassword = await bcrypt.compare(password, user.password);
            if (!validPassword) return res.status(400).json({ error: 'Invalid email or password.' });

            const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET);
            const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
            console.log(`\n[SECURITY AUDIT] User Logged In: ${user.email} | IP: ${ip} | Time: ${new Date().toLocaleString()}`);
            broadcastToAdmins({ type: 'USER_LOGIN', email: user.email, ip });
            res.json({ token, message: 'Login successful.' });
        } catch (e) {
            console.error('Login error:', e);
            if (!res.headersSent) res.status(500).json({ error: 'Server error during login.' });
        }
    });
});

// ----------------------------------------------------
// PUBLIC/CHAT ROUTES
// ----------------------------------------------------
app.get('/api/broadcast', (req, res) => {
    db.get(`SELECT message FROM broadcasts WHERE is_active = 1 ORDER BY id DESC LIMIT 1`, [], (err, row) => {
        res.json({ broadcast: row ? row.message : null });
    });
});

app.get('/api/history', authenticateToken, (req, res) => {
    db.all(`SELECT role, content, created_at FROM messages WHERE user_id = ? ORDER BY id ASC`, [req.user.id], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Database error.' });
        res.json({ history: rows });
    });
});

app.get('/api/auth/status', authenticateToken, (req, res) => {
    res.json({ success: true, user: req.user });
});

app.post('/api/chat', authenticateToken, async (req, res) => {
    try {
        const { messages, model, stream } = req.body;
        const userMessage = messages[messages.length - 1];

        db.get(`SELECT value FROM settings WHERE key = 'groq_api_key'`, async (err, row) => {
            try {
                if (err || !row || !row.value) return res.status(500).json({ error: { message: 'Groq API Key not configured in Admin Settings.' } });
                
                const apiKey = row.value;

            const groqResponse = await fetch('https://api.groq.com/openai/v1/chat/completions', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${apiKey}`
                },
                body: JSON.stringify({
                    model: model || "llama-3.3-70b-versatile",
                    messages: messages,
                    stream: stream || false
                })
            });

            if (!groqResponse.ok) {
                const errData = await groqResponse.json();
                return res.status(groqResponse.status).json(errData);
            }

            if (stream) {
                res.setHeader('Content-Type', 'text/event-stream');
                res.setHeader('Cache-Control', 'no-cache');
                res.setHeader('Connection', 'keep-alive');

                const reader = groqResponse.body.getReader();
                const decoder = new TextDecoder('utf-8');
                let fullAiResponse = '';

                while (true) {
                    const { done, value } = await reader.read();
                    if (done) break;
                    
                    res.write(value);
                    
                    const chunkStr = decoder.decode(value, { stream: true });
                    const lines = chunkStr.split('\n');
                    for (const line of lines) {
                        if (line.startsWith('data: ') && line !== 'data: [DONE]') {
                            try {
                                const parsed = JSON.parse(line.replace('data: ', ''));
                                if (parsed.choices && parsed.choices[0].delta && parsed.choices[0].delta.content) {
                                    fullAiResponse += parsed.choices[0].delta.content;
                                }
                            } catch (e) {}
                        }
                    }
                }
                res.end();

                let userContentText = typeof userMessage.content === 'string' ? userMessage.content : JSON.stringify(userMessage.content);
                db.run(`INSERT INTO messages (user_id, role, content) VALUES (?, 'user', ?)`, [req.user.id, userContentText]);
                db.run(`INSERT INTO messages (user_id, role, content) VALUES (?, 'assistant', ?)`, [req.user.id, fullAiResponse]);

            } else {
                const data = await groqResponse.json();
                res.json(data);
                
                let userContentText = typeof userMessage.content === 'string' ? userMessage.content : JSON.stringify(userMessage.content);
                db.run(`INSERT INTO messages (user_id, role, content) VALUES (?, 'user', ?)`, [req.user.id, userContentText]);
                if(data.choices && data.choices[0].message) {
                    db.run(`INSERT INTO messages (user_id, role, content) VALUES (?, 'assistant', ?)`, [req.user.id, data.choices[0].message.content]);
                }
            }
            broadcastToAdmins({ type: 'CHAT_INTERACTION', userId: req.user.id, email: req.user.email, prompt: userMessage.content });
            } catch (innerError) {
                console.error('Inner Proxy Error:', innerError);
                if (!res.headersSent) {
                    res.status(500).json({ error: { message: 'Internal Server Error' } });
                }
            }
        });
    } catch (error) {
        console.error('Proxy Error:', error);
        res.status(500).json({ error: { message: 'Internal Server Error' } });
    }
});

// ----------------------------------------------------
// ADMIN COMMAND CENTER ROUTES
// ----------------------------------------------------
function verifyAdmin(req, res, next) {
    if (req.body.adminKey !== ADMIN_MASTER_KEY) {
        return res.status(403).json({ error: 'Invalid Master Key' });
    }
    next();
}

app.post('/api/admin/analytics', verifyAdmin, (req, res) => {
    db.get(`SELECT count(*) as total_users FROM users`, (err, usersRow) => {
        db.get(`SELECT count(*) as total_messages FROM messages`, (err, msgsRow) => {
            const memoryUsage = process.memoryUsage().heapUsed / 1024 / 1024;
            res.json({
                totalUsers: usersRow.total_users,
                totalMessages: msgsRow.total_messages,
                ramUsageMB: memoryUsage.toFixed(2)
            });
        });
    });
});

app.post('/api/admin/users', verifyAdmin, (req, res) => {
    db.all(`SELECT id, email, status, created_at FROM users ORDER BY id DESC`, [], (err, rows) => {
        res.json({ users: rows });
    });
});

app.post('/api/admin/users/status', verifyAdmin, (req, res) => {
    const { userId, status } = req.body;
    console.log(`[ADMIN] Changing user ${userId} status to ${status}`);
    db.run(`UPDATE users SET status = ? WHERE id = ?`, [status, userId], (err) => {
        if (err) {
            console.error('[ADMIN] Database error updating status:', err);
            return res.status(500).json({ error: 'Failed to update user' });
        }
        console.log(`[ADMIN] Successfully updated user ${userId} to ${status}`);
        res.json({ success: true });
    });
});

app.post('/api/admin/audit', verifyAdmin, (req, res) => {
    const { userId } = req.body;
    db.all(`SELECT role, content, created_at FROM messages WHERE user_id = ? ORDER BY id DESC LIMIT 50`, [userId], (err, rows) => {
        res.json({ logs: rows });
    });
});

app.post('/api/admin/broadcast', verifyAdmin, (req, res) => {
    const { message } = req.body;
    if (!message) {
        db.run(`UPDATE broadcasts SET is_active = 0`);
        return res.json({ success: true, cleared: true });
    }
    db.run(`UPDATE broadcasts SET is_active = 0`, () => {
        db.run(`INSERT INTO broadcasts (message, is_active) VALUES (?, 1)`, [message], () => {
            res.json({ success: true });
        });
    });
});

app.post('/api/admin/settings', verifyAdmin, (req, res) => {
    db.all(`SELECT key, value FROM settings`, (err, rows) => {
        res.json({ settings: rows });
    });
});

app.post('/api/admin/settings/update', verifyAdmin, (req, res) => {
    const { key, value } = req.body;
    db.run(`INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)`, [key, value], (err) => {
        res.json({ success: true });
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
    console.log(`[Fluxo SaaS] Secure Auth/DB backend running on http://localhost:${PORT}`);
});

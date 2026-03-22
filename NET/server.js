const express = require('express');
const app = express();
const http = require('http').createServer(app);
const io = require('socket.io')(http);
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const path = require('path');
const crypto = require('crypto');
const multer = require('multer');
const fs = require('fs');

const PORT = process.env.PORT || 1337;

const uploadDir = './uploads';
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
}

app.use(express.json());
app.use(express.static(__dirname));
app.use('/uploads', express.static('uploads'));

// 1. В базу добавлена колонка token
const db = new sqlite3.Database('./database.db');
db.serialize(() => {
    db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email TEXT UNIQUE, password TEXT, name TEXT, code TEXT UNIQUE, avatar TEXT DEFAULT '', description TEXT DEFAULT '', token TEXT)");
    db.run("CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY, sender_id INTEGER, receiver_id INTEGER, text TEXT, type TEXT DEFAULT 'text', timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)");
    db.run("CREATE TABLE IF NOT EXISTS contacts (id INTEGER PRIMARY KEY, user_id INTEGER, contact_id INTEGER)");
});

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'uploads/'),
    filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage: storage });

app.post('/upload', upload.single('photo'), (req, res) => {
    if (req.file) {
        res.json({ url: `/uploads/${req.file.filename}` });
    } else {
        res.status(400).json({ error: "Ошибка при загрузке фото" });
    }
});

app.post('/register', async (req, res) => {
    const { email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const code = crypto.randomBytes(3).toString('hex').toUpperCase();
    const token = crypto.randomBytes(16).toString('hex'); // Генерируем токен

    db.run("INSERT INTO users (email, password, code, token) VALUES (?, ?, ?, ?)", [email, hashedPassword, code, token], function (err) {
        if (err) return res.status(400).json({ error: "Этот Email уже занят" });
        res.json({ id: this.lastID, code: code, token: token });
    });
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    db.get("SELECT * FROM users WHERE email = ?", [email], async (err, user) => {
        if (!user) return res.status(400).json({ error: "Пользователь не найден" });
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.status(400).json({ error: "Неверный пароль" });

        const token = crypto.randomBytes(16).toString('hex'); // Обновляем токен
        db.run("UPDATE users SET token = ? WHERE id = ?", [token, user.id], () => {
            res.json({ id: user.id, name: user.name, code: user.code, avatar: user.avatar, description: user.description, token: token });
        });
    });
});

// Проверка сессии теперь ИСКЛЮЧИТЕЛЬНО по токену
app.get('/validate-session', (req, res) => {
    db.get("SELECT id, name, code, avatar, description FROM users WHERE token = ?", [req.query.token], (err, user) => {
        if (user) res.json({ valid: true, user });
        else res.json({ valid: false });
    });
});

app.post('/update-profile-init', (req, res) => {
    db.run("UPDATE users SET name = ?, avatar = ? WHERE id = ?", [req.body.name, req.body.avatar, req.body.id], () => res.json({ success: true }));
});

app.get('/profile/:id', (req, res) => {
    db.get("SELECT id, name, avatar, description FROM users WHERE id = ?", [req.params.id], (err, user) => {
        if (user) res.json(user);
        else res.status(404).json({ error: "Пользователь не найден" });
    });
});

app.post('/edit-profile', (req, res) => {
    const { id, description, avatar } = req.body;
    db.run("UPDATE users SET description = ?, avatar = ? WHERE id = ?", [description, avatar, id], () => res.json({ success: true }));
});

app.post('/add-contact', (req, res) => {
    const { userId, code } = req.body;
    db.get("SELECT id FROM users WHERE code = ?", [code], (err, friend) => {
        if (!friend) return res.status(400).json({ error: "Код не найден" });
        if (friend.id === userId) return res.status(400).json({ error: "Нельзя добавить себя" });

        db.get("SELECT * FROM contacts WHERE user_id = ? AND contact_id = ?", [userId, friend.id], (err, existing) => {
            if (existing) return res.status(400).json({ error: "Пользователь уже в контактах" });

            db.run("INSERT INTO contacts (user_id, contact_id) VALUES (?, ?), (?, ?)", [userId, friend.id, friend.id, userId], () => {
                io.to(String(friend.id)).emit('contact added');
                res.json({ success: true });
            });
        });
    });
});

app.get('/contacts', (req, res) => {
    db.all(`SELECT users.id, users.name, users.avatar FROM users JOIN contacts ON users.id = contacts.contact_id WHERE contacts.user_id = ?`, [req.query.userId], (err, rows) => {
        res.json(rows || []);
    });
});

app.get('/messages', (req, res) => {
    const { u1, u2 } = req.query;
    db.all(`SELECT * FROM messages WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?) ORDER BY timestamp ASC`, [u1, u2, u2, u1], (err, rows) => {
        res.json(rows || []);
    });
});

io.on('connection', (socket) => {
    socket.on('join', (userId) => {
        socket.join(String(userId));
    });

    socket.on('chat message', (data) => {
        if (!data.userId || !data.toId) return;
        const msgType = data.type === 'image' ? 'image' : 'text';

        db.run("INSERT INTO messages (sender_id, receiver_id, text, type) VALUES (?, ?, ?, ?)", [data.userId, data.toId, data.text, msgType], function (err) {
            if (err) {
                console.error("Ошибка сохранения сообщения:", err);
            } else {
                io.to(String(data.userId)).to(String(data.toId)).emit('chat message', data);
            }
        });
    });
});

http.listen(PORT, () => console.log('NET Server online on port ' + PORT));
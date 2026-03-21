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

// Настройка порта для Render (или 1337 для локального теста)
const PORT = process.env.PORT || 1337;

// Создаем папку для картинок автоматически, если её нет
const uploadDir = './uploads';
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
}

app.use(express.json());
app.use(express.static(__dirname));
app.use('/uploads', express.static('uploads')); // Открываем доступ к фото

// Подключаем базу (ОБЯЗАТЕЛЬНО УДАЛИ СТАРЫЙ database.db ПЕРЕД ЗАПУСКОМ)
const db = new sqlite3.Database('./database.db');

db.serialize(() => {
    db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email TEXT UNIQUE, password TEXT, name TEXT, code TEXT UNIQUE)");
    // Вот она, новая таблица сообщений с колонкой type!
    db.run("CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY, sender_id INTEGER, receiver_id INTEGER, text TEXT, type TEXT DEFAULT 'text', timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)");
    db.run("CREATE TABLE IF NOT EXISTS contacts (id INTEGER PRIMARY KEY, user_id INTEGER, contact_id INTEGER)");
});

// Настройка загрузки фото
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'uploads/'),
    filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage: storage });

// Маршрут приема фото
app.post('/upload', upload.single('photo'), (req, res) => {
    if (req.file) {
        res.json({ url: `/uploads/${req.file.filename}` });
    } else {
        res.status(400).json({ error: "Ошибка при загрузке фото" });
    }
});

// --- СТАНДАРТНЫЕ МАРШРУТЫ ---
app.post('/register', async (req, res) => {
    const { email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const code = crypto.randomBytes(3).toString('hex').toUpperCase();

    db.run("INSERT INTO users (email, password, code) VALUES (?, ?, ?)", [email, hashedPassword, code], function (err) {
        if (err) return res.status(400).json({ error: "Этот Email уже занят" });
        res.json({ id: this.lastID, code: code });
    });
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    db.get("SELECT * FROM users WHERE email = ?", [email], async (err, user) => {
        if (!user) return res.status(400).json({ error: "Пользователь не найден" });
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.status(400).json({ error: "Неверный пароль" });
        res.json({ id: user.id, name: user.name, code: user.code });
    });
});

// Проверка: существует ли еще пользователь в базе
app.get('/validate-session', (req, res) => {
    db.get("SELECT id FROM users WHERE id = ?", [req.query.id], (err, user) => {
        if (user) res.json({ valid: true });
        else res.json({ valid: false });
    });
});

app.post('/update-name', (req, res) => {
    db.run("UPDATE users SET name = ? WHERE id = ?", [req.body.name, req.body.id], () => res.json({ success: true }));
});

app.post('/add-contact', (req, res) => {
    const { userId, code } = req.body;
    db.get("SELECT id FROM users WHERE code = ?", [code], (err, friend) => {
        if (!friend) return res.status(400).json({ error: "Код не найден" });
        if (friend.id === userId) return res.status(400).json({ error: "Нельзя добавить себя" });

        db.get("SELECT * FROM contacts WHERE user_id = ? AND contact_id = ?", [userId, friend.id], (err, existing) => {
            if (existing) return res.status(400).json({ error: "Пользователь уже в контактах" });

            db.run("INSERT INTO contacts (user_id, contact_id) VALUES (?, ?), (?, ?)", [userId, friend.id, friend.id, userId], () => {
                // --- НОВОЕ: Мгновенно сообщаем другу, что его кто-то добавил ---
                io.to(String(friend.id)).emit('contact added');

                res.json({ success: true });
            });
        });
    });
});

app.get('/contacts', (req, res) => {
    db.all(`SELECT users.id, users.name FROM users JOIN contacts ON users.id = contacts.contact_id WHERE contacts.user_id = ?`, [req.query.userId], (err, rows) => {
        res.json(rows || []);
    });
});

app.get('/messages', (req, res) => {
    const { u1, u2 } = req.query;
    db.all(`SELECT * FROM messages WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?) ORDER BY timestamp ASC`, [u1, u2, u2, u1], (err, rows) => {
        res.json(rows || []);
    });
});

// --- SOCKET.IO ---
io.on('connection', (socket) => {
    // 1. Когда пользователь входит, сажаем его в персональную комнату по его ID
    socket.on('join', (userId) => {
        socket.join(String(userId));
    });

    socket.on('chat message', (data) => {
        if (!data.userId || !data.toId) return;

        // Защита: проверяем тип сообщения
        const msgType = data.type === 'image' ? 'image' : 'text';

        // Сохраняем в базу, и только ПОСЛЕ успешного сохранения рассылаем клиентам
        db.run("INSERT INTO messages (sender_id, receiver_id, text, type) VALUES (?, ?, ?, ?)", [data.userId, data.toId, data.text, msgType], function (err) {
            if (err) {
                console.error("Ошибка сохранения сообщения:", err);
            } else {
                // 2. ИСПРАВЛЕНИЕ: Отправляем сообщение ТОЛЬКО в комнаты отправителя и получателя
                io.to(String(data.userId)).to(String(data.toId)).emit('chat message', data);
            }
        });
    });
});

http.listen(PORT, () => console.log('NET Server online on port ' + PORT));
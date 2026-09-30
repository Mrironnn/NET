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

// 1. В базу добавлена колонка token и reply_text
const db = new sqlite3.Database('./database.db');
db.serialize(() => {
    db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email TEXT UNIQUE, password TEXT, name TEXT, code TEXT UNIQUE, avatar TEXT DEFAULT '', description TEXT DEFAULT '', token TEXT)");
    db.run("CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY, sender_id INTEGER, receiver_id INTEGER, text TEXT, type TEXT DEFAULT 'text', timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)");
    db.run("CREATE TABLE IF NOT EXISTS contacts (id INTEGER PRIMARY KEY, user_id INTEGER, contact_id INTEGER)");
    db.run("CREATE TABLE IF NOT EXISTS friend_requests (id INTEGER PRIMARY KEY, from_id INTEGER, to_id INTEGER, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)");

    // Безопасное добавление колонок для ответов и статуса прочтения
    db.all("PRAGMA table_info(messages)", (err, rows) => {
        const cols = rows.map(r => r.name);
        if (!cols.includes('reply_text')) db.run("ALTER TABLE messages ADD COLUMN reply_text TEXT DEFAULT NULL");
        if (!cols.includes('is_read')) db.run("ALTER TABLE messages ADD COLUMN is_read INTEGER DEFAULT 0");
        if (!cols.includes('reactions')) db.run("ALTER TABLE messages ADD COLUMN reactions TEXT DEFAULT '{}'");
    });
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
        res.status(400).json({ error: "upload_failed" });
    }
});

app.post('/register', async (req, res) => {
    const { email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const code = crypto.randomBytes(3).toString('hex').toUpperCase();
    const token = crypto.randomBytes(16).toString('hex');
    db.run("INSERT INTO users (email, password, code, token) VALUES (?, ?, ?, ?)", [email, hashedPassword, code, token], function (err) {
        if (err) return res.status(400).json({ error: "email_taken" });
        res.json({ id: this.lastID, code: code, token: token });
    });
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    db.get("SELECT * FROM users WHERE email = ?", [email], async (err, user) => {
        if (!user) return res.status(400).json({ error: "user_not_found" });
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.status(400).json({ error: "wrong_password" });
        const token = crypto.randomBytes(16).toString('hex');
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
        else res.status(404).json({ error: "user_not_found" });
    });
});

app.post('/edit-profile', (req, res) => {
    const { id, description, avatar } = req.body;
    db.run("UPDATE users SET description = ?, avatar = ? WHERE id = ?", [description, avatar, id], () => res.json({ success: true }));
});

// Отправка запроса в друзья
app.post('/add_contact', async (req, res) => {
    const token = req.headers.authorization;
    const { code } = req.body;
    if (!token || !code) return res.status(400).json({ error: 'data_missing' });
    db.get("SELECT id, name FROM users WHERE token = ?", [token], (err, user) => {
        if (!user) return res.status(401).json({ error: 'unauthorized' });
        db.get("SELECT id, name FROM users WHERE code = ?", [code], (err, contact) => {
            if (!contact) return res.status(404).json({ error: 'not_found' });
            if (user.id === contact.id) return res.status(400).json({ error: 'self' });
            // Проверяем, не друзья ли мы уже
            db.get("SELECT id FROM contacts WHERE user_id = ? AND contact_id = ?", [user.id, contact.id], (err, row) => {
                if (row) return res.status(400).json({ error: 'already_friends' });
                // Проверяем, не отправлял ли ОН нам запрос до этого (если да - авто-принятие)
                db.get("SELECT id FROM friend_requests WHERE from_id = ? AND to_id = ?", [contact.id, user.id], (err, reverseReq) => {
                    if (reverseReq) {
                        db.run("INSERT INTO contacts (user_id, contact_id) VALUES (?, ?), (?, ?)", [user.id, contact.id, contact.id, user.id], () => {
                            db.run("DELETE FROM friend_requests WHERE id = ?", [reverseReq.id], () => {
                                io.to(String(user.id)).emit('contact added');
                                io.to(String(contact.id)).emit('contact added');
                                return res.json({ success: true });
                            });
                        });
                        return;
                    }
                    // Проверяем, не отправляли ли МЫ уже запрос
                    db.get("SELECT id FROM friend_requests WHERE from_id = ? AND to_id = ?", [user.id, contact.id], (err, myReq) => {
                        if (myReq) return res.status(400).json({ error: 'already_sent' });
                        // Создаем запрос
                        db.run("INSERT INTO friend_requests (from_id, to_id) VALUES (?, ?)", [user.id, contact.id], function (err) {
                            if (err) return res.status(500).json({ error: 'db_error' });
                            // Уведомляем получателя
                            io.to(String(contact.id)).emit('friend_request', { fromName: user.name });
                            res.json({ success: true });
                        });
                    });
                });
            });
        });
    });
});

// Получение списка входящих запросов
app.get('/friend_requests', (req, res) => {
    const token = req.headers.authorization;
    if (!token) return res.status(401).json({ error: 'Unauthorized' });

    db.get("SELECT id FROM users WHERE token = ?", [token], (err, user) => {
        if (!user) return res.status(401).json({ error: 'Unauthorized' });

        db.all(`
            SELECT fr.id as req_id, u.id as sender_id, u.name, u.avatar 
            FROM friend_requests fr 
            JOIN users u ON fr.from_id = u.id 
            WHERE fr.to_id = ?
        `, [user.id], (err, rows) => {
            res.json(rows || []);
        });
    });
});

// Получение общих друзей
app.get('/mutual_friends', (req, res) => {
    const token = req.headers.authorization;
    const otherId = req.query.other_id;
    if (!token || !otherId) return res.status(400).json({ error: 'data_missing' });

    db.get("SELECT id FROM users WHERE token = ?", [token], (err, user) => {
        if (!user) return res.status(401).json({ error: 'unauthorized' });

        // SQL: Ищем тех, кто есть и в твоих контактах, и в контактах другого человека
        db.all(`
            SELECT u.id, u.name, u.avatar 
            FROM users u 
            JOIN contacts c1 ON u.id = c1.contact_id 
            JOIN contacts c2 ON u.id = c2.contact_id 
            WHERE c1.user_id = ? AND c2.user_id = ?
        `, [user.id, otherId], (err, rows) => {
            res.json(rows || []);
        });
    });
});

// Принять или отклонить запрос
app.post('/handle_request', (req, res) => {
    const token = req.headers.authorization;
    const { req_id, action } = req.body; // action = 'accept' или 'reject'
    if (!token || !req_id) return res.status(400).json({ error: 'Data missing' });

    db.get("SELECT id FROM users WHERE token = ?", [token], (err, user) => {
        if (!user) return res.status(401).json({ error: 'Unauthorized' });

        db.get("SELECT * FROM friend_requests WHERE id = ? AND to_id = ?", [req_id, user.id], (err, request) => {
            if (!request) return res.status(404).json({ error: 'Запрос не найден' });

            if (action === 'reject') {
                db.run("DELETE FROM friend_requests WHERE id = ?", [req_id], () => {
                    res.json({ success: true });
                });
            } else if (action === 'accept') {
                db.run("INSERT INTO contacts (user_id, contact_id) VALUES (?, ?), (?, ?)", [request.from_id, request.to_id, request.to_id, request.from_id], () => {
                    db.run("DELETE FROM friend_requests WHERE id = ?", [req_id], () => {
                        io.to(String(request.from_id)).emit('contact added');
                        io.to(String(request.to_id)).emit('contact added');
                        res.json({ success: true });
                    });
                });
            }
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

const onlineUsers = new Map(); // Хранилище онлайна

io.on('connection', (socket) => {
    socket.on('join', (userId) => {
        const uIdStr = String(userId);
        socket.userId = uIdStr;
        socket.join(uIdStr);

        // Считаем вкладки пользователя
        let count = onlineUsers.get(uIdStr) || 0;
        onlineUsers.set(uIdStr, count + 1);

        // Если это первая открытая вкладка - говорим всем, что он онлайн
        if (count === 0) {
            io.emit('user_status', { userId: uIdStr, status: 'online' });
        }
        // Отправляем список онлайна самому пользователю
        socket.emit('initial_online_list', Array.from(onlineUsers.keys()));
    });

    socket.on('chat message', (data) => {
        if (!data.userId || !data.toId) return;
        const msgType = data.type === 'image' ? 'image' : 'text';
        const replyText = data.replyText || null;

        db.run("INSERT INTO messages (sender_id, receiver_id, text, type, reply_text, is_read, reactions) VALUES (?, ?, ?, ?, ?, 0, '{}')",
            [data.userId, data.toId, data.text, msgType, replyText], function (err) {
                if (!err) {
                    io.to(String(data.userId)).to(String(data.toId)).emit('chat message', {
                        id: this.lastID,
                        userId: data.userId,
                        toId: data.toId,
                        text: data.text,
                        type: msgType,
                        reply_text: replyText,
                        is_read: 0,
                        reactions: '{}',
                        timestamp: new Date().toISOString()
                    });
                }
            });
    });

    // Обработка клика по реакции
    socket.on('add_reaction', ({ msgId, emoji, userId }) => {
        db.get("SELECT sender_id, receiver_id, reactions FROM messages WHERE id = ?", [msgId], (err, row) => {
            if (row) {
                let reacts = {};
                try { reacts = JSON.parse(row.reactions || '{}'); } catch (e) { }

                // Если юзер уже ставил этот смайл - удаляем (эффект отжатия кнопки)
                if (reacts[userId] === emoji) delete reacts[userId];
                else reacts[userId] = emoji;

                db.run("UPDATE messages SET reactions = ? WHERE id = ?", [JSON.stringify(reacts), msgId], () => {
                    io.to(String(row.sender_id)).to(String(row.receiver_id)).emit('reaction_updated', { msgId, reacts });
                });
            }
        });
    });

    // Пометка сообщения как прочитанного
    socket.on('mark_read', (msgId) => {
        db.run("UPDATE messages SET is_read = 1 WHERE id = ?", [msgId]);
    });

    // Получение количества непрочитанных
    socket.on('get_unread_status', (userId) => {
        db.all("SELECT sender_id, COUNT(*) as count FROM messages WHERE receiver_id = ? AND is_read = 0 GROUP BY sender_id", [userId], (err, rows) => {
            if (!err) {
                const unreadData = {};
                rows.forEach(r => unreadData[r.sender_id] = r.count);
                socket.emit('unread_status_data', unreadData);
            }
        });
    });
    // Логика отключения (закрыл сайт)
    socket.on('disconnect', () => {
        if (socket.userId) {
            let count = onlineUsers.get(socket.userId) || 0;
            if (count > 1) {
                onlineUsers.set(socket.userId, count - 1);
            } else {
                onlineUsers.delete(socket.userId);
                io.emit('user_status', { userId: socket.userId, status: 'offline' });
            }
        }
    });
});

http.listen(PORT, () => console.log('NET Server online on port ' + PORT));
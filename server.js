require('dotenv').config();
const express = require('express');
const session = require('express-session');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = process.env.SESSION_SECRET || 'nizam-altaqweem-secret-key-2024';

// ══════════════════════════════════════
//  إعداد قاعدة البيانات SQLite
//  في Railway: يُحفَظ في /data (Volume)
//  محلياً: يُحفَظ في مجلد المشروع
// ══════════════════════════════════════
const dataDir = process.env.DATA_DIR || __dirname;
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}
const dbFile = path.join(dataDir, 'data.db');
console.log('📁 قاعدة البيانات:', dbFile);
const sqlite = new Database(dbFile);

sqlite.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    app_data    TEXT DEFAULT '{}',
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login  DATETIME
  );

  CREATE TABLE IF NOT EXISTS logs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER,
    action     TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// ══════════════════════════════════════
//  Middleware
// ══════════════════════════════════════
app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ extended: true, limit: '20mb' }));
app.set('trust proxy', 1);
app.use(session({
  secret: SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 7 * 24 * 60 * 60 * 1000  // 7 أيام
  }
}));

// ══════════════════════════════════════
//  حماية - التحقق من تسجيل الدخول
// ══════════════════════════════════════
const requireAuth = (req, res, next) => {
  if (req.session && req.session.userId) return next();
  if (req.path.startsWith('/api/')) {
    return res.status(401).json({ error: 'يرجى تسجيل الدخول أولاً' });
  }
  res.redirect('/login.html');
};

// ══════════════════════════════════════
//  الملفات الثابتة
// ══════════════════════════════════════
// login.html متاح بدون تسجيل دخول
app.get('/login.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// باقي الملفات تحتاج تسجيل دخول
app.use(requireAuth, express.static(path.join(__dirname, 'public')));

// الصفحة الرئيسية
app.get('/', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ══════════════════════════════════════
//  API - الإعداد الأول
// ══════════════════════════════════════
app.get('/api/setup-status', (req, res) => {
  const result = sqlite.prepare('SELECT COUNT(*) as count FROM users').get();
  res.json({ setupDone: result.count > 0 });
});

app.post('/api/setup', (req, res) => {
  const { username, password, teacherName } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'اسم المستخدم وكلمة المرور مطلوبان' });
  }

  const existing = sqlite.prepare('SELECT COUNT(*) as count FROM users').get();
  if (existing.count > 0) {
    return res.status(400).json({ error: 'الحساب موجود بالفعل. يرجى تسجيل الدخول.' });
  }

  try {
    const hash = bcrypt.hashSync(password, 12);
    const defaultData = JSON.stringify({
      teacher: {
        name: teacherName || username,
        fullname: teacherName || username,
        subject: '', school: '', year: '2024 / 2025',
        phone: '', email: '', principal: '', schoolPhone: '',
        visitorSup: '', eduSup: ''
      },
      grades: [], evaluationAxes: [], observationCategories: [],
      templates: { obs: [], grades: [], behavioral: [], evaluation: [] },
      bot: {}
    });

    const result = sqlite.prepare(
      'INSERT INTO users (username, password_hash, app_data) VALUES (?, ?, ?)'
    ).run(username, hash, defaultData);

    req.session.userId = result.lastInsertRowid;
    req.session.username = username;

    res.json({ success: true });
  } catch (err) {
    if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      res.status(400).json({ error: 'اسم المستخدم مستخدم بالفعل' });
    } else {
      res.status(500).json({ error: 'خطأ في الإعداد: ' + err.message });
    }
  }
});

// ══════════════════════════════════════
//  API - تسجيل الدخول والخروج
// ══════════════════════════════════════
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'أدخل اسم المستخدم وكلمة المرور' });
  }

  const user = sqlite.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
  }

  req.session.userId = user.id;
  req.session.username = user.username;

  // تسجيل وقت الدخول
  sqlite.prepare('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?').run(user.id);
  sqlite.prepare('INSERT INTO logs (user_id, action) VALUES (?, ?)').run(user.id, 'login');

  res.json({ success: true });
});

app.post('/api/logout', (req, res) => {
  if (req.session.userId) {
    sqlite.prepare('INSERT INTO logs (user_id, action) VALUES (?, ?)').run(req.session.userId, 'logout');
  }
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

app.get('/api/session', (req, res) => {
  if (req.session && req.session.userId) {
    res.json({ loggedIn: true, username: req.session.username });
  } else {
    res.status(401).json({ loggedIn: false });
  }
});

// ══════════════════════════════════════
//  API - البيانات الرئيسية
// ══════════════════════════════════════
app.get('/api/data', requireAuth, (req, res) => {
  const user = sqlite.prepare('SELECT app_data FROM users WHERE id = ?').get(req.session.userId);
  try {
    res.json(JSON.parse(user.app_data || '{}'));
  } catch {
    res.json({});
  }
});

app.post('/api/data', requireAuth, (req, res) => {
  try {
    const data = JSON.stringify(req.body);
    sqlite.prepare('UPDATE users SET app_data = ? WHERE id = ?').run(data, req.session.userId);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'فشل الحفظ: ' + err.message });
  }
});

// ══════════════════════════════════════
//  API - تغيير كلمة المرور
// ══════════════════════════════════════
app.post('/api/change-password', requireAuth, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!newPassword || newPassword.length < 6) {
    return res.status(400).json({ error: 'كلمة المرور الجديدة قصيرة (6 أحرف على الأقل)' });
  }

  const user = sqlite.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);
  if (!bcrypt.compareSync(currentPassword, user.password_hash)) {
    return res.status(401).json({ error: 'كلمة المرور الحالية غير صحيحة' });
  }

  const hash = bcrypt.hashSync(newPassword, 12);
  sqlite.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, req.session.userId);
  sqlite.prepare('INSERT INTO logs (user_id, action) VALUES (?, ?)').run(req.session.userId, 'change_password');

  res.json({ success: true });
});

// ══════════════════════════════════════
//  بدء تشغيل السيرفر
// ══════════════════════════════════════
app.listen(PORT, () => {
  console.log('');
  console.log('╔══════════════════════════════════════════╗');
  console.log('║     نظام التقويم الذكي — يعمل الآن       ║');
  console.log('╠══════════════════════════════════════════╣');
  console.log(`║  الرابط: http://localhost:${PORT}              ║`);
  console.log('║  لإيقاف السيرفر: Ctrl + C                ║');
  console.log('╚══════════════════════════════════════════╝');
  console.log('');

  // تحقق من وجود حسابات
  const users = sqlite.prepare('SELECT COUNT(*) as count FROM users').get();
  if (users.count === 0) {
    console.log('⚠️  لا يوجد حساب — سيتم توجيهك لإعداد الحساب الأول عند فتح المتصفح');
  } else {
    console.log(`✅ ${users.count} حساب مسجّل`);
  }
});

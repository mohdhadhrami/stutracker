// Stutracker v2.2 — Multi-Tenant SaaS with personal profile, password recovery
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_PATH = process.env.DB_PATH || '/data/data.db';
const SESSION_SECRET = process.env.SESSION_SECRET || 'stutracker-secret-change-me';

// Ensure /data exists
require('fs').mkdirSync(path.dirname(DB_PATH), { recursive: true });

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// ========== Schema ==========
db.exec(`
CREATE TABLE IF NOT EXISTS super_admins (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  name TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS schools (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  school_code TEXT UNIQUE NOT NULL,
  name_ar TEXT NOT NULL,
  name_en TEXT,
  admin_username TEXT NOT NULL,
  admin_password_hash TEXT NOT NULL,
  admin_name TEXT,
  admin_email TEXT,
  twilio_sid TEXT,
  twilio_token TEXT,
  twilio_from TEXT,
  content_sid TEXT,
  openai_key TEXT,
  openai_model TEXT DEFAULT 'gpt-4o-mini',
  ai_system_prompt TEXT,
  status TEXT DEFAULT 'active',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS teachers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  school_id INTEGER NOT NULL,
  username TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  full_name TEXT,
  subject TEXT,
  grade_level TEXT,
  phone TEXT,
  email TEXT,
  academic_year TEXT,
  academic_term TEXT,
  security_question TEXT,
  security_answer_hash TEXT,
  app_data TEXT DEFAULT '{}',
  last_login DATETIME,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(school_id, username),
  FOREIGN KEY(school_id) REFERENCES schools(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS bot_conversations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  school_id INTEGER NOT NULL,
  teacher_id INTEGER,
  from_phone TEXT,
  to_phone TEXT,
  message TEXT,
  reply TEXT,
  direction TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(school_id) REFERENCES schools(id) ON DELETE CASCADE
);
`);

// ========== Lightweight migrations (idempotent) ==========
function ensureColumn(table, col, defn) {
  const cols = db.prepare(`PRAGMA table_info(${table})`).all().map(r => r.name);
  if (!cols.includes(col)) {
    try { db.exec(`ALTER TABLE ${table} ADD COLUMN ${col} ${defn}`); }
    catch (e) { console.error(`migration ${table}.${col}:`, e.message); }
  }
}
ensureColumn('teachers', 'academic_year', 'TEXT');
ensureColumn('teachers', 'academic_term', 'TEXT');
ensureColumn('teachers', 'security_question', 'TEXT');
ensureColumn('teachers', 'security_answer_hash', 'TEXT');

// ========== Seed super admin ==========
const superCount = db.prepare('SELECT COUNT(*) AS c FROM super_admins').get().c;
if (!superCount) {
  const hash = bcrypt.hashSync('admin123', 10);
  db.prepare('INSERT INTO super_admins (email, password_hash, name) VALUES (?, ?, ?)').run(
    'admin@stutracker.com', hash, 'System Administrator'
  );
  console.log('✓ Default super admin created: admin@stutracker.com / admin123');
}

// ========== Middleware ==========
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true, limit: '5mb' }));
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 30 * 24 * 60 * 60 * 1000, httpOnly: true, sameSite: 'lax' }
}));

function requireSuper(req, res, next) {
  if (!req.session.super_admin_id) return res.status(401).json({ error: 'Unauthorized' });
  next();
}
function requireSchool(req, res, next) {
  if (!req.session.school_id) return res.status(401).json({ error: 'Unauthorized' });
  next();
}
function requireTeacher(req, res, next) {
  if (!req.session.teacher_id) return res.status(401).json({ error: 'Unauthorized' });
  next();
}

// ========================================
// Super Admin APIs
// ========================================
app.post('/api/super/login', (req, res) => {
  const { email, password } = req.body;
  const admin = db.prepare('SELECT * FROM super_admins WHERE email = ?').get(email);
  if (!admin || !bcrypt.compareSync(password, admin.password_hash)) {
    return res.status(401).json({ error: 'بيانات الدخول غير صحيحة' });
  }
  req.session.super_admin_id = admin.id;
  res.json({ success: true, admin: { id: admin.id, email: admin.email, name: admin.name } });
});

app.post('/api/super/logout', (req, res) => { req.session.destroy(() => res.json({ success: true })); });

app.get('/api/super/session', (req, res) => {
  if (!req.session.super_admin_id) return res.json({ authenticated: false });
  const admin = db.prepare('SELECT id, email, name FROM super_admins WHERE id = ?').get(req.session.super_admin_id);
  res.json({ authenticated: !!admin, admin });
});

app.get('/api/super/schools', requireSuper, (req, res) => {
  const schools = db.prepare(`
    SELECT s.id, s.school_code, s.name_ar, s.name_en, s.admin_username, s.admin_name, s.admin_email,
           s.twilio_from, s.openai_model, s.status, s.created_at,
           (SELECT COUNT(*) FROM teachers WHERE school_id = s.id) AS teacher_count,
           CASE WHEN s.twilio_sid IS NOT NULL AND s.twilio_sid != '' THEN 1 ELSE 0 END AS has_twilio,
           CASE WHEN s.openai_key IS NOT NULL AND s.openai_key != '' THEN 1 ELSE 0 END AS has_openai
    FROM schools s ORDER BY s.created_at DESC
  `).all();
  res.json({ schools });
});

app.post('/api/super/schools', requireSuper, (req, res) => {
  try {
    const b = req.body;
    if (!b.school_code || !b.name_ar || !b.admin_username || !b.admin_password) {
      return res.status(400).json({ error: 'الحقول المطلوبة ناقصة' });
    }
    const hash = bcrypt.hashSync(b.admin_password, 10);
    const r = db.prepare(`
      INSERT INTO schools (school_code, name_ar, name_en, admin_username, admin_password_hash,
        admin_name, admin_email, twilio_sid, twilio_token, twilio_from, content_sid,
        openai_key, openai_model, ai_system_prompt, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      b.school_code, b.name_ar, b.name_en || '', b.admin_username, hash,
      b.admin_name || '', b.admin_email || '',
      b.twilio_sid || '', b.twilio_token || '', b.twilio_from || '', b.content_sid || '',
      b.openai_key || '', b.openai_model || 'gpt-4o-mini', b.ai_system_prompt || '',
      b.status || 'active'
    );
    res.json({ success: true, id: r.lastInsertRowid });
  } catch (e) {
    res.status(400).json({ error: e.message.includes('UNIQUE') ? 'رمز المدرسة مستخدم مسبقاً' : e.message });
  }
});

app.put('/api/super/schools/:id', requireSuper, (req, res) => {
  try {
    const b = req.body;
    const fields = []; const values = [];
    ['school_code','name_ar','name_en','admin_username','admin_name','admin_email',
     'twilio_sid','twilio_token','twilio_from','content_sid',
     'openai_key','openai_model','ai_system_prompt','status'].forEach(f => {
      if (b[f] !== undefined) { fields.push(`${f} = ?`); values.push(b[f]); }
    });
    if (b.admin_password) {
      fields.push('admin_password_hash = ?');
      values.push(bcrypt.hashSync(b.admin_password, 10));
    }
    if (!fields.length) return res.json({ success: true });
    values.push(req.params.id);
    db.prepare(`UPDATE schools SET ${fields.join(', ')} WHERE id = ?`).run(...values);
    res.json({ success: true });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.delete('/api/super/schools/:id', requireSuper, (req, res) => {
  db.prepare('DELETE FROM schools WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// ========================================
// School Admin APIs
// ========================================
app.post('/api/school/login', (req, res) => {
  const { school_code, username, password } = req.body;
  const school = db.prepare('SELECT * FROM schools WHERE school_code = ? AND status = ?').get(school_code, 'active');
  if (!school || school.admin_username !== username || !bcrypt.compareSync(password, school.admin_password_hash)) {
    return res.status(401).json({ error: 'بيانات الدخول غير صحيحة' });
  }
  req.session.school_id = school.id;
  res.json({
    success: true,
    school: { id: school.id, code: school.school_code, name_ar: school.name_ar, admin_username: school.admin_username }
  });
});

app.post('/api/school/logout', (req, res) => { req.session.destroy(() => res.json({ success: true })); });

app.get('/api/school/session', (req, res) => {
  if (!req.session.school_id) return res.json({ authenticated: false });
  const school = db.prepare('SELECT id, school_code, name_ar, name_en, admin_username, admin_name, admin_email FROM schools WHERE id = ?').get(req.session.school_id);
  res.json({ authenticated: !!school, school });
});

app.get('/api/school/settings', requireSchool, (req, res) => {
  const school = db.prepare('SELECT * FROM schools WHERE id = ?').get(req.session.school_id);
  if (school) delete school.admin_password_hash;
  res.json({ school });
});

app.put('/api/school/settings', requireSchool, (req, res) => {
  try {
    const b = req.body;
    const fields = []; const values = [];
    ['name_ar','name_en','admin_name','admin_email',
     'twilio_sid','twilio_token','twilio_from','content_sid',
     'openai_key','openai_model','ai_system_prompt'].forEach(f => {
      if (b[f] !== undefined) { fields.push(`${f} = ?`); values.push(b[f]); }
    });
    if (b.admin_password) {
      fields.push('admin_password_hash = ?');
      values.push(bcrypt.hashSync(b.admin_password, 10));
    }
    if (!fields.length) return res.json({ success: true });
    values.push(req.session.school_id);
    db.prepare(`UPDATE schools SET ${fields.join(', ')} WHERE id = ?`).run(...values);
    res.json({ success: true });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.get('/api/school/teachers', requireSchool, (req, res) => {
  const teachers = db.prepare(`
    SELECT id, username, full_name, subject, grade_level, phone, email,
           academic_year, academic_term, security_question, last_login, created_at
    FROM teachers WHERE school_id = ? ORDER BY created_at DESC
  `).all(req.session.school_id);
  res.json({ teachers });
});

app.post('/api/school/teachers', requireSchool, (req, res) => {
  try {
    const b = req.body;
    if (!b.username || !b.password) return res.status(400).json({ error: 'اسم المستخدم وكلمة المرور مطلوبان' });
    const hash = bcrypt.hashSync(b.password, 10);
    const r = db.prepare(`
      INSERT INTO teachers (school_id, username, password_hash, full_name, subject, grade_level, phone, email, academic_year, academic_term)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      req.session.school_id, b.username, hash,
      b.full_name || '', b.subject || '', b.grade_level || '',
      b.phone || '', b.email || '', b.academic_year || '', b.academic_term || ''
    );
    res.json({ success: true, id: r.lastInsertRowid });
  } catch (e) {
    res.status(400).json({ error: e.message.includes('UNIQUE') ? 'اسم المستخدم مستخدم مسبقاً' : e.message });
  }
});

app.put('/api/school/teachers/:id', requireSchool, (req, res) => {
  try {
    const b = req.body;
    const fields = []; const values = [];
    ['username','full_name','subject','grade_level','phone','email','academic_year','academic_term'].forEach(f => {
      if (b[f] !== undefined) { fields.push(`${f} = ?`); values.push(b[f]); }
    });
    if (b.password) {
      fields.push('password_hash = ?');
      values.push(bcrypt.hashSync(b.password, 10));
    }
    if (!fields.length) return res.json({ success: true });
    values.push(req.params.id, req.session.school_id);
    db.prepare(`UPDATE teachers SET ${fields.join(', ')} WHERE id = ? AND school_id = ?`).run(...values);
    res.json({ success: true });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// Reset teacher's password (school admin action)
app.post('/api/school/teachers/:id/reset-password', requireSchool, (req, res) => {
  try {
    const { new_password } = req.body;
    if (!new_password || new_password.length < 4) {
      return res.status(400).json({ error: 'كلمة المرور الجديدة قصيرة جداً' });
    }
    const t = db.prepare('SELECT id FROM teachers WHERE id = ? AND school_id = ?').get(req.params.id, req.session.school_id);
    if (!t) return res.status(404).json({ error: 'المعلم غير موجود' });
    const hash = bcrypt.hashSync(new_password, 10);
    db.prepare('UPDATE teachers SET password_hash = ? WHERE id = ?').run(hash, req.params.id);
    res.json({ success: true });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.delete('/api/school/teachers/:id', requireSchool, (req, res) => {
  db.prepare('DELETE FROM teachers WHERE id = ? AND school_id = ?').run(req.params.id, req.session.school_id);
  res.json({ success: true });
});

// ========================================
// Teacher APIs
// ========================================
app.post('/api/teacher/login', (req, res) => {
  const { school_code, username, password } = req.body;
  const school = db.prepare('SELECT * FROM schools WHERE school_code = ? AND status = ?').get(school_code, 'active');
  if (!school) return res.status(401).json({ error: 'رمز المدرسة غير صحيح أو المدرسة غير مفعلة' });
  const teacher = db.prepare('SELECT * FROM teachers WHERE school_id = ? AND username = ?').get(school.id, username);
  if (!teacher || !bcrypt.compareSync(password, teacher.password_hash)) {
    return res.status(401).json({ error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
  }
  req.session.school_id = school.id;
  req.session.teacher_id = teacher.id;
  db.prepare('UPDATE teachers SET last_login = CURRENT_TIMESTAMP WHERE id = ?').run(teacher.id);
  res.json({
    success: true,
    teacher: {
      id: teacher.id, username: teacher.username, full_name: teacher.full_name,
      subject: teacher.subject, grade_level: teacher.grade_level,
      academic_year: teacher.academic_year, academic_term: teacher.academic_term,
      school: { id: school.id, name: school.name_ar, code: school.school_code }
    }
  });
});

app.post('/api/teacher/logout', (req, res) => { req.session.destroy(() => res.json({ success: true })); });

app.get('/api/teacher/session', (req, res) => {
  if (!req.session.teacher_id) return res.json({ authenticated: false });
  const t = db.prepare('SELECT * FROM teachers WHERE id = ?').get(req.session.teacher_id);
  if (!t) return res.json({ authenticated: false });
  const school = db.prepare('SELECT id, name_ar, school_code FROM schools WHERE id = ?').get(t.school_id);
  res.json({
    authenticated: true,
    teacher: {
      id: t.id, username: t.username, full_name: t.full_name,
      subject: t.subject, grade_level: t.grade_level, phone: t.phone, email: t.email,
      academic_year: t.academic_year, academic_term: t.academic_term,
      security_question: t.security_question
    },
    school: { id: school.id, name_ar: school.name_ar, school_code: school.school_code }
  });
});

app.get('/api/teacher/data', requireTeacher, (req, res) => {
  const t = db.prepare('SELECT app_data FROM teachers WHERE id = ?').get(req.session.teacher_id);
  let data = {};
  try { data = JSON.parse(t.app_data || '{}'); } catch (e) { data = {}; }
  res.json({ data });
});

app.post('/api/teacher/data', requireTeacher, (req, res) => {
  try {
    const payload = JSON.stringify(req.body || {});
    db.prepare('UPDATE teachers SET app_data = ? WHERE id = ?').run(payload, req.session.teacher_id);
    res.json({ success: true });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// Update teacher's personal profile (subject, academic year, etc.)
app.put('/api/teacher/profile', requireTeacher, (req, res) => {
  try {
    const b = req.body;
    const fields = []; const values = [];
    ['full_name','subject','grade_level','phone','email','academic_year','academic_term'].forEach(f => {
      if (b[f] !== undefined) { fields.push(`${f} = ?`); values.push(b[f]); }
    });
    if (!fields.length) return res.json({ success: true });
    values.push(req.session.teacher_id);
    db.prepare(`UPDATE teachers SET ${fields.join(', ')} WHERE id = ?`).run(...values);
    res.json({ success: true });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.post('/api/teacher/change-password', requireTeacher, (req, res) => {
  const { current_password, new_password } = req.body;
  if (!current_password || !new_password) return res.status(400).json({ error: 'الحقول مطلوبة' });
  if (new_password.length < 4) return res.status(400).json({ error: 'كلمة المرور الجديدة قصيرة جداً' });
  const t = db.prepare('SELECT password_hash FROM teachers WHERE id = ?').get(req.session.teacher_id);
  if (!bcrypt.compareSync(current_password, t.password_hash)) {
    return res.status(401).json({ error: 'كلمة المرور الحالية غير صحيحة' });
  }
  const hash = bcrypt.hashSync(new_password, 10);
  db.prepare('UPDATE teachers SET password_hash = ? WHERE id = ?').run(hash, req.session.teacher_id);
  res.json({ success: true });
});

// Set security question & answer (for password recovery)
app.post('/api/teacher/security-question', requireTeacher, (req, res) => {
  const { question, answer } = req.body;
  if (!question || !answer) return res.status(400).json({ error: 'السؤال والإجابة مطلوبان' });
  const answerHash = bcrypt.hashSync(String(answer).trim().toLowerCase(), 10);
  db.prepare('UPDATE teachers SET security_question = ?, security_answer_hash = ? WHERE id = ?')
    .run(question, answerHash, req.session.teacher_id);
  res.json({ success: true });
});

// ========================================
// Password recovery flow (public)
// ========================================
// Step 1: lookup security question by school_code + username
app.post('/api/recovery/lookup', (req, res) => {
  const { school_code, username } = req.body;
  if (!school_code || !username) return res.status(400).json({ error: 'الحقول مطلوبة' });
  const school = db.prepare('SELECT id, name_ar FROM schools WHERE school_code = ?').get(school_code);
  if (!school) return res.status(404).json({ error: 'المدرسة غير موجودة' });
  const t = db.prepare('SELECT id, security_question FROM teachers WHERE school_id = ? AND username = ?').get(school.id, username);
  if (!t) return res.status(404).json({ error: 'اسم المستخدم غير موجود في هذه المدرسة' });
  if (!t.security_question) {
    return res.status(400).json({
      error: 'لم يتم تعيين سؤال أمان لهذا الحساب. يرجى التواصل مع مدير المدرسة لإعادة تعيين كلمة المرور.'
    });
  }
  res.json({ success: true, school_name: school.name_ar, question: t.security_question });
});

// Step 2: verify answer + set new password
app.post('/api/recovery/reset', (req, res) => {
  const { school_code, username, answer, new_password } = req.body;
  if (!school_code || !username || !answer || !new_password) {
    return res.status(400).json({ error: 'جميع الحقول مطلوبة' });
  }
  if (new_password.length < 4) return res.status(400).json({ error: 'كلمة المرور الجديدة قصيرة جداً' });
  const school = db.prepare('SELECT id FROM schools WHERE school_code = ?').get(school_code);
  if (!school) return res.status(404).json({ error: 'المدرسة غير موجودة' });
  const t = db.prepare('SELECT id, security_answer_hash FROM teachers WHERE school_id = ? AND username = ?').get(school.id, username);
  if (!t || !t.security_answer_hash) return res.status(404).json({ error: 'لا يمكن استرجاع كلمة المرور لهذا الحساب' });
  if (!bcrypt.compareSync(String(answer).trim().toLowerCase(), t.security_answer_hash)) {
    return res.status(401).json({ error: 'الإجابة غير صحيحة' });
  }
  const hash = bcrypt.hashSync(new_password, 10);
  db.prepare('UPDATE teachers SET password_hash = ? WHERE id = ?').run(hash, t.id);
  res.json({ success: true });
});

// ========================================
// Twilio / WhatsApp bot
// ========================================
app.post('/api/bot/send', requireTeacher, async (req, res) => {
  try {
    const { to, message } = req.body;
    if (!to || !message) return res.status(400).json({ error: 'الرقم والرسالة مطلوبان' });
    const school = db.prepare('SELECT twilio_sid, twilio_token, twilio_from FROM schools WHERE id = ?').get(req.session.school_id);
    if (!school || !school.twilio_sid || !school.twilio_token || !school.twilio_from) {
      return res.status(400).json({ error: 'إعدادات Twilio غير مكتملة. يرجى التواصل مع مدير المدرسة.' });
    }
    const formatNumber = n => { n = String(n).trim(); if (!n.startsWith('whatsapp:')) n = 'whatsapp:' + (n.startsWith('+') ? n : '+' + n); return n; };
    const from = formatNumber(school.twilio_from);
    const toFmt = formatNumber(to);
    const auth = Buffer.from(`${school.twilio_sid}:${school.twilio_token}`).toString('base64');
    const body = new URLSearchParams({ From: from, To: toFmt, Body: message });
    const r = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${school.twilio_sid}/Messages.json`, {
      method: 'POST',
      headers: { 'Authorization': `Basic ${auth}`, 'Content-Type': 'application/x-www-form-urlencoded' },
      body
    });
    const data = await r.json();
    if (!r.ok) return res.status(400).json({ error: data.message || 'فشل الإرسال' });
    db.prepare('INSERT INTO bot_conversations (school_id, teacher_id, to_phone, message, direction) VALUES (?, ?, ?, ?, ?)')
      .run(req.session.school_id, req.session.teacher_id, to, message, 'out');
    res.json({ success: true, sid: data.sid });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/webhook/twilio', express.urlencoded({ extended: false }), async (req, res) => {
  try {
    const from = req.body.From || '';
    const to = req.body.To || '';
    const message = req.body.Body || '';
    const school = db.prepare('SELECT * FROM schools WHERE twilio_from = ? OR twilio_from = ? OR twilio_from = ?')
      .get(to, to.replace('whatsapp:', ''), to.replace('whatsapp:+', ''));
    if (!school) { res.type('text/xml').send('<Response></Response>'); return; }
    db.prepare('INSERT INTO bot_conversations (school_id, from_phone, to_phone, message, direction) VALUES (?, ?, ?, ?, ?)')
      .run(school.id, from, to, message, 'in');
    res.type('text/xml').send('<Response></Response>');
  } catch (e) { console.error(e); res.type('text/xml').send('<Response></Response>'); }
});

// ========================================
// Static routes
// ========================================
app.use(express.static(path.join(__dirname, 'public')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('/school-admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'school-admin.html')));
app.get('/recovery', (req, res) => res.sendFile(path.join(__dirname, 'public', 'recovery.html')));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, () => {
  console.log('╔═══════════════════════════════════════╗');
  console.log('║  Stutracker v2.2 — Multi-Tenant      ║');
  console.log(`║  Running on port ${PORT}                 ║`);
  console.log('║  /admin         → Super Admin         ║');
  console.log('║  /school-admin  → School Admin        ║');
  console.log('║  /              → Teacher Login       ║');
  console.log('║  /recovery      → Password Recovery   ║');
  console.log('╚═══════════════════════════════════════╝');
});

// Stutracker v2 — Multi-Tenant (Super Admin → Schools → Teachers)
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const DB_PATH = process.env.DB_PATH || '/data/data.db';

// ═══════════════════════════════════════════════════════════════
// Database setup
// ═══════════════════════════════════════════════════════════════
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

db.exec(`
CREATE TABLE IF NOT EXISTS super_admins (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  name TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS schools (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  school_code TEXT UNIQUE NOT NULL,
  name_ar TEXT NOT NULL,
  name_en TEXT,
  admin_username TEXT NOT NULL,
  admin_password_hash TEXT NOT NULL,
  admin_email TEXT,
  admin_name TEXT,
  twilio_sid TEXT DEFAULT '',
  twilio_token TEXT DEFAULT '',
  twilio_from TEXT DEFAULT '',
  content_sid TEXT DEFAULT '',
  openai_key TEXT DEFAULT '',
  openai_model TEXT DEFAULT 'gpt-4o-mini',
  ai_system_prompt TEXT DEFAULT '',
  status TEXT DEFAULT 'active',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
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
  app_data TEXT DEFAULT '{}',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  last_login TEXT,
  UNIQUE(school_id, username),
  FOREIGN KEY (school_id) REFERENCES schools(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS bot_conversations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  school_id INTEGER,
  teacher_id INTEGER,
  from_phone TEXT,
  to_phone TEXT,
  message TEXT,
  reply TEXT,
  direction TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_type TEXT,
  user_id INTEGER,
  school_id INTEGER,
  action TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_teachers_school ON teachers(school_id);
CREATE INDEX IF NOT EXISTS idx_bot_conv_school ON bot_conversations(school_id);
CREATE INDEX IF NOT EXISTS idx_schools_twilio_from ON schools(twilio_from);
`);

// Seed default super admin if not exists
const superRow = db.prepare('SELECT COUNT(*) as c FROM super_admins').get();
if (superRow.c === 0) {
  const defaultPass = bcrypt.hashSync('admin123', 10);
  db.prepare('INSERT INTO super_admins (email, password_hash, name) VALUES (?, ?, ?)')
    .run('admin@stutracker.com', defaultPass, 'System Administrator');
  console.log('✓ Default super admin created: admin@stutracker.com / admin123');
}

// ═══════════════════════════════════════════════════════════════
// Middleware
// ═══════════════════════════════════════════════════════════════
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'stutracker-v2-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 30 * 24 * 60 * 60 * 1000 } // 30 days
}));
app.use(express.static(path.join(__dirname, 'public')));

// Auth guards
const requireSuperAdmin = (req, res, next) => {
  if (!req.session.superAdminId) return res.status(401).json({ error: 'غير مصرح' });
  next();
};
const requireSchoolAdmin = (req, res, next) => {
  if (!req.session.schoolAdminId) return res.status(401).json({ error: 'غير مصرح' });
  next();
};
const requireTeacher = (req, res, next) => {
  if (!req.session.teacherId) return res.status(401).json({ error: 'غير مصرح' });
  next();
};

// ═══════════════════════════════════════════════════════════════
// AUTH — Super Admin
// ═══════════════════════════════════════════════════════════════
app.post('/api/super/login', (req, res) => {
  const { email, password } = req.body;
  const admin = db.prepare('SELECT * FROM super_admins WHERE email = ?').get(email);
  if (!admin || !bcrypt.compareSync(password, admin.password_hash)) {
    return res.status(401).json({ error: 'البريد أو كلمة المرور غير صحيحة' });
  }
  req.session.superAdminId = admin.id;
  req.session.superAdminName = admin.name;
  res.json({ success: true, name: admin.name });
});

app.post('/api/super/logout', (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

app.get('/api/super/session', (req, res) => {
  if (req.session.superAdminId) {
    res.json({ authenticated: true, name: req.session.superAdminName });
  } else {
    res.json({ authenticated: false });
  }
});

// ═══════════════════════════════════════════════════════════════
// SUPER ADMIN — Schools CRUD
// ═══════════════════════════════════════════════════════════════
app.get('/api/super/schools', requireSuperAdmin, (req, res) => {
  const schools = db.prepare(`
    SELECT s.*,
    (SELECT COUNT(*) FROM teachers WHERE school_id = s.id) as teacher_count
    FROM schools s ORDER BY s.created_at DESC
  `).all();
  // Don't expose password hashes
  schools.forEach(s => { delete s.admin_password_hash; });
  res.json({ schools });
});

app.post('/api/super/schools', requireSuperAdmin, (req, res) => {
  const {
    school_code, name_ar, name_en,
    admin_username, admin_password, admin_email, admin_name,
    twilio_sid, twilio_token, twilio_from, content_sid,
    openai_key, openai_model, ai_system_prompt
  } = req.body;

  if (!school_code || !name_ar || !admin_username || !admin_password) {
    return res.status(400).json({ error: 'الحقول المطلوبة ناقصة' });
  }

  if (!/^[A-Za-z0-9_-]{3,32}$/.test(school_code)) {
    return res.status(400).json({ error: 'رمز المدرسة يجب أن يكون 3-32 حرفاً (أحرف/أرقام/_/-)' });
  }

  try {
    const hash = bcrypt.hashSync(admin_password, 10);
    const result = db.prepare(`
      INSERT INTO schools (
        school_code, name_ar, name_en,
        admin_username, admin_password_hash, admin_email, admin_name,
        twilio_sid, twilio_token, twilio_from, content_sid,
        openai_key, openai_model, ai_system_prompt
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      school_code, name_ar, name_en || '',
      admin_username, hash, admin_email || '', admin_name || '',
      twilio_sid || '', twilio_token || '', twilio_from || '', content_sid || '',
      openai_key || '', openai_model || 'gpt-4o-mini', ai_system_prompt || ''
    );
    res.json({ success: true, id: result.lastInsertRowid });
  } catch (err) {
    if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.status(400).json({ error: 'رمز المدرسة مستخدم مسبقاً' });
    }
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/super/schools/:id', requireSuperAdmin, (req, res) => {
  const id = parseInt(req.params.id);
  const f = req.body;
  const fields = [];
  const values = [];
  const allowed = ['name_ar','name_en','admin_username','admin_email','admin_name',
    'twilio_sid','twilio_token','twilio_from','content_sid',
    'openai_key','openai_model','ai_system_prompt','status'];
  allowed.forEach(k => {
    if (f[k] !== undefined) { fields.push(`${k} = ?`); values.push(f[k]); }
  });
  if (f.admin_password) {
    fields.push('admin_password_hash = ?');
    values.push(bcrypt.hashSync(f.admin_password, 10));
  }
  if (!fields.length) return res.json({ success: true, noop: true });
  values.push(id);
  db.prepare(`UPDATE schools SET ${fields.join(', ')} WHERE id = ?`).run(...values);
  res.json({ success: true });
});

app.delete('/api/super/schools/:id', requireSuperAdmin, (req, res) => {
  const id = parseInt(req.params.id);
  db.prepare('DELETE FROM schools WHERE id = ?').run(id);
  res.json({ success: true });
});

// ═══════════════════════════════════════════════════════════════
// AUTH — School Admin
// ═══════════════════════════════════════════════════════════════
app.post('/api/school/login', (req, res) => {
  const { school_code, username, password } = req.body;
  const school = db.prepare('SELECT * FROM schools WHERE school_code = ? AND status = ?')
    .get(school_code, 'active');
  if (!school || school.admin_username !== username ||
      !bcrypt.compareSync(password, school.admin_password_hash)) {
    return res.status(401).json({ error: 'بيانات الدخول غير صحيحة' });
  }
  req.session.schoolAdminId = school.id;
  req.session.schoolCode = school.school_code;
  req.session.schoolName = school.name_ar;
  res.json({ success: true, school: { id: school.id, code: school.school_code, name: school.name_ar } });
});

app.post('/api/school/logout', (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

app.get('/api/school/session', (req, res) => {
  if (req.session.schoolAdminId) {
    const school = db.prepare('SELECT id, school_code, name_ar, name_en, twilio_sid, twilio_from, content_sid, openai_model, ai_system_prompt FROM schools WHERE id = ?')
      .get(req.session.schoolAdminId);
    res.json({ authenticated: true, school });
  } else {
    res.json({ authenticated: false });
  }
});

// School admin updates own settings (API keys etc.)
app.put('/api/school/settings', requireSchoolAdmin, (req, res) => {
  const f = req.body;
  const fields = [];
  const values = [];
  const allowed = ['twilio_sid','twilio_token','twilio_from','content_sid',
    'openai_key','openai_model','ai_system_prompt'];
  allowed.forEach(k => {
    if (f[k] !== undefined) { fields.push(`${k} = ?`); values.push(f[k]); }
  });
  if (!fields.length) return res.json({ success: true, noop: true });
  values.push(req.session.schoolAdminId);
  db.prepare(`UPDATE schools SET ${fields.join(', ')} WHERE id = ?`).run(...values);
  res.json({ success: true });
});

// ═══════════════════════════════════════════════════════════════
// SCHOOL ADMIN — Teachers CRUD
// ═══════════════════════════════════════════════════════════════
app.get('/api/school/teachers', requireSchoolAdmin, (req, res) => {
  const teachers = db.prepare(`
    SELECT id, username, full_name, subject, grade_level, phone, email, created_at, last_login
    FROM teachers WHERE school_id = ? ORDER BY created_at DESC
  `).all(req.session.schoolAdminId);
  res.json({ teachers });
});

app.post('/api/school/teachers', requireSchoolAdmin, (req, res) => {
  const { username, password, full_name, subject, grade_level, phone, email } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'اسم المستخدم وكلمة المرور مطلوبان' });

  try {
    const hash = bcrypt.hashSync(password, 10);
    const result = db.prepare(`
      INSERT INTO teachers (school_id, username, password_hash, full_name, subject, grade_level, phone, email)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(req.session.schoolAdminId, username, hash,
      full_name || '', subject || '', grade_level || '', phone || '', email || '');
    res.json({ success: true, id: result.lastInsertRowid });
  } catch (err) {
    if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.status(400).json({ error: 'اسم المستخدم مستخدم في هذه المدرسة' });
    }
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/school/teachers/:id', requireSchoolAdmin, (req, res) => {
  const id = parseInt(req.params.id);
  const teacher = db.prepare('SELECT school_id FROM teachers WHERE id = ?').get(id);
  if (!teacher || teacher.school_id !== req.session.schoolAdminId) {
    return res.status(404).json({ error: 'المعلم غير موجود' });
  }
  const f = req.body;
  const fields = [];
  const values = [];
  ['username','full_name','subject','grade_level','phone','email'].forEach(k => {
    if (f[k] !== undefined) { fields.push(`${k} = ?`); values.push(f[k]); }
  });
  if (f.password) {
    fields.push('password_hash = ?');
    values.push(bcrypt.hashSync(f.password, 10));
  }
  if (!fields.length) return res.json({ success: true, noop: true });
  values.push(id);
  try {
    db.prepare(`UPDATE teachers SET ${fields.join(', ')} WHERE id = ?`).run(...values);
    res.json({ success: true });
  } catch (err) {
    if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.status(400).json({ error: 'اسم المستخدم مستخدم' });
    }
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/school/teachers/:id', requireSchoolAdmin, (req, res) => {
  const id = parseInt(req.params.id);
  const teacher = db.prepare('SELECT school_id FROM teachers WHERE id = ?').get(id);
  if (!teacher || teacher.school_id !== req.session.schoolAdminId) {
    return res.status(404).json({ error: 'المعلم غير موجود' });
  }
  db.prepare('DELETE FROM teachers WHERE id = ?').run(id);
  res.json({ success: true });
});

// ═══════════════════════════════════════════════════════════════
// AUTH — Teacher
// ═══════════════════════════════════════════════════════════════
app.post('/api/teacher/login', (req, res) => {
  const { school_code, username, password } = req.body;
  const school = db.prepare('SELECT id, name_ar FROM schools WHERE school_code = ? AND status = ?')
    .get(school_code, 'active');
  if (!school) return res.status(401).json({ error: 'رمز المدرسة غير صحيح' });

  const teacher = db.prepare('SELECT * FROM teachers WHERE school_id = ? AND username = ?')
    .get(school.id, username);
  if (!teacher || !bcrypt.compareSync(password, teacher.password_hash)) {
    return res.status(401).json({ error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
  }

  req.session.teacherId = teacher.id;
  req.session.teacherSchoolId = school.id;
  req.session.teacherSchoolName = school.name_ar;
  req.session.teacherName = teacher.full_name || teacher.username;

  db.prepare('UPDATE teachers SET last_login = CURRENT_TIMESTAMP WHERE id = ?').run(teacher.id);

  res.json({
    success: true,
    teacher: {
      id: teacher.id,
      username: teacher.username,
      full_name: teacher.full_name,
      subject: teacher.subject,
      grade_level: teacher.grade_level,
      school: { id: school.id, name: school.name_ar }
    }
  });
});

app.post('/api/teacher/logout', (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

app.get('/api/teacher/session', (req, res) => {
  if (!req.session.teacherId) return res.json({ authenticated: false });
  const teacher = db.prepare('SELECT id, username, full_name, subject, grade_level, school_id FROM teachers WHERE id = ?')
    .get(req.session.teacherId);
  if (!teacher) return res.json({ authenticated: false });
  const school = db.prepare('SELECT id, school_code, name_ar FROM schools WHERE id = ?').get(teacher.school_id);
  res.json({ authenticated: true, teacher, school });
});

// Teacher's own data (grades, students, templates, etc.)
app.get('/api/teacher/data', requireTeacher, (req, res) => {
  const row = db.prepare('SELECT app_data FROM teachers WHERE id = ?').get(req.session.teacherId);
  res.json({ data: JSON.parse(row?.app_data || '{}') });
});

app.post('/api/teacher/data', requireTeacher, (req, res) => {
  const data = JSON.stringify(req.body || {});
  db.prepare('UPDATE teachers SET app_data = ? WHERE id = ?')
    .run(data, req.session.teacherId);
  res.json({ success: true });
});

// Teacher change password
app.post('/api/teacher/change-password', requireTeacher, (req, res) => {
  const { old_password, new_password } = req.body;
  const t = db.prepare('SELECT password_hash FROM teachers WHERE id = ?').get(req.session.teacherId);
  if (!bcrypt.compareSync(old_password, t.password_hash)) {
    return res.status(401).json({ error: 'كلمة المرور الحالية غير صحيحة' });
  }
  const hash = bcrypt.hashSync(new_password, 10);
  db.prepare('UPDATE teachers SET password_hash = ? WHERE id = ?').run(hash, req.session.teacherId);
  res.json({ success: true });
});

// ═══════════════════════════════════════════════════════════════
// WhatsApp Bot — per-school routing
// ═══════════════════════════════════════════════════════════════

// Send WhatsApp (teacher sends, uses their school's Twilio)
app.post('/api/bot/send', requireTeacher, async (req, res) => {
  const { to, message } = req.body;
  const school = db.prepare('SELECT * FROM schools WHERE id = ?').get(req.session.teacherSchoolId);
  if (!school.twilio_sid || !school.twilio_token || !school.twilio_from) {
    return res.status(400).json({ error: 'إعدادات Twilio للمدرسة غير مكتملة' });
  }

  const toNumber = String(to || '').replace(/[^\d+]/g, '');
  if (!toNumber) return res.status(400).json({ error: 'رقم المستلم غير صحيح' });

  try {
    const fromWa = `whatsapp:${school.twilio_from}`;
    const toWa = `whatsapp:${toNumber.startsWith('+') ? toNumber : '+' + toNumber}`;
    const url = `https://api.twilio.com/2010-04-01/Accounts/${school.twilio_sid}/Messages.json`;
    const auth = Buffer.from(`${school.twilio_sid}:${school.twilio_token}`).toString('base64');
    const params = new URLSearchParams();
    params.append('From', fromWa);
    params.append('To', toWa);
    if (school.content_sid) {
      params.append('ContentSid', school.content_sid);
      params.append('ContentVariables', JSON.stringify({'1': message}));
    } else {
      params.append('Body', message);
    }

    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${auth}`,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: params.toString()
    });
    const result = await response.json();
    if (!response.ok) {
      return res.status(400).json({ error: result.message || 'فشل الإرسال', code: result.code });
    }

    db.prepare(`INSERT INTO bot_conversations (school_id, teacher_id, from_phone, to_phone, message, direction)
      VALUES (?, ?, ?, ?, ?, ?)`)
      .run(school.id, req.session.teacherId, school.twilio_from, toNumber, message, 'outgoing');

    res.json({ success: true, sid: result.sid });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Webhook — receives incoming WhatsApp messages (routed by recipient number)
app.post('/api/webhook/twilio', async (req, res) => {
  try {
    const from = String(req.body.From || '').replace('whatsapp:', '');
    const to = String(req.body.To || '').replace('whatsapp:', '');
    const message = String(req.body.Body || '').trim();

    // Find school by receiving number (whose twilio_from matches)
    const school = db.prepare('SELECT * FROM schools WHERE twilio_from = ? AND status = ?')
      .get(to, 'active');

    res.set('Content-Type', 'text/xml');
    if (!school) {
      console.log(`[Webhook] No school found for ${to}`);
      return res.send('<Response/>');
    }

    console.log(`[Webhook] ${from} → ${to} (${school.school_code}): "${message}"`);

    // Store incoming
    db.prepare(`INSERT INTO bot_conversations (school_id, from_phone, to_phone, message, direction)
      VALUES (?, ?, ?, ?, ?)`)
      .run(school.id, from, to, message, 'incoming');

    // Generate AI reply
    let reply = await generateAIReply(school, from, message);
    if (!reply) reply = 'شكراً لتواصلك مع ' + school.name_ar;

    // Send reply
    const fromWa = `whatsapp:${school.twilio_from}`;
    const toWa = `whatsapp:${from.startsWith('+') ? from : '+' + from}`;
    const url = `https://api.twilio.com/2010-04-01/Accounts/${school.twilio_sid}/Messages.json`;
    const auth = Buffer.from(`${school.twilio_sid}:${school.twilio_token}`).toString('base64');
    const params = new URLSearchParams();
    params.append('From', fromWa);
    params.append('To', toWa);
    if (school.content_sid) {
      params.append('ContentSid', school.content_sid);
      params.append('ContentVariables', JSON.stringify({'1': reply}));
    } else {
      params.append('Body', reply);
    }

    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Authorization': `Basic ${auth}`, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params.toString()
    });
    const result = await response.json();
    console.log(`[Webhook] Reply status: ${response.status}, code: ${result.code || 'ok'}`);

    db.prepare(`INSERT INTO bot_conversations (school_id, from_phone, to_phone, message, reply, direction)
      VALUES (?, ?, ?, ?, ?, ?)`)
      .run(school.id, school.twilio_from, from, reply, reply, 'outgoing');

    res.send('<Response/>');
  } catch (err) {
    console.error('Webhook error:', err);
    res.status(500).send('<Response/>');
  }
});

async function generateAIReply(school, fromPhone, message) {
  if (!school.openai_key) return null;

  const systemPrompt = school.ai_system_prompt ||
    `أنت مساعد ذكي لمدرسة ${school.name_ar}. أجب بإيجاز واحترام باللغة العربية.`;

  try {
    const response = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${school.openai_key}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        model: school.openai_model || 'gpt-4o-mini',
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: message }
        ],
        max_tokens: 500
      })
    });
    const data = await response.json();
    if (data.choices?.[0]?.message?.content) {
      return data.choices[0].message.content.trim();
    }
    console.error('OpenAI error:', data);
    return null;
  } catch (err) {
    console.error('AI call failed:', err);
    return null;
  }
}

// Teacher: view own conversations
app.get('/api/bot/conversations', requireTeacher, (req, res) => {
  const rows = db.prepare(`
    SELECT * FROM bot_conversations
    WHERE school_id = ?
    ORDER BY created_at DESC LIMIT 100
  `).all(req.session.teacherSchoolId);
  res.json({ conversations: rows });
});

// ═══════════════════════════════════════════════════════════════
// Static routes
// ═══════════════════════════════════════════════════════════════
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('/school-admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'school-admin.html')));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ═══════════════════════════════════════════════════════════════
// Start server
// ═══════════════════════════════════════════════════════════════
app.listen(PORT, () => {
  console.log('╔═══════════════════════════════════════╗');
  console.log('║  Stutracker v2 — Multi-Tenant        ║');
  console.log('║  Running on port ' + PORT.toString().padEnd(21) + '║');
  console.log('║  /admin → Super Admin                 ║');
  console.log('║  /school-admin → School Admin         ║');
  console.log('║  / → Teacher Login                    ║');
  console.log('╚═══════════════════════════════════════╝');
});

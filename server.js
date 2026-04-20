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

-- School staff (admins, deputies, supervisors with roles)
CREATE TABLE IF NOT EXISTS school_staff (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  school_id INTEGER NOT NULL,
  username TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  full_name TEXT,
  email TEXT,
  phone TEXT,
  role TEXT NOT NULL DEFAULT 'supervisor',
  permissions TEXT DEFAULT '[]',
  status TEXT DEFAULT 'active',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(school_id, username),
  FOREIGN KEY(school_id) REFERENCES schools(id) ON DELETE CASCADE
);

-- Central grades (managed by school admin, shared with teachers)
CREATE TABLE IF NOT EXISTS school_grades (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  school_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  display_order INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(school_id) REFERENCES schools(id) ON DELETE CASCADE
);

-- Central sections for each grade
CREATE TABLE IF NOT EXISTS school_sections (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  grade_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  display_order INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(grade_id) REFERENCES school_grades(id) ON DELETE CASCADE
);

-- Central students (imported by school admin)
CREATE TABLE IF NOT EXISTS school_students (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  school_id INTEGER NOT NULL,
  grade_id INTEGER NOT NULL,
  section_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  student_id TEXT,
  parent_phone TEXT,
  nationality TEXT,
  gender TEXT,
  date_of_birth TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(school_id) REFERENCES schools(id) ON DELETE CASCADE,
  FOREIGN KEY(grade_id) REFERENCES school_grades(id) ON DELETE CASCADE,
  FOREIGN KEY(section_id) REFERENCES school_sections(id) ON DELETE CASCADE
);

-- School schedule periods (e.g. Summer, Winter, Ramadan)
CREATE TABLE IF NOT EXISTS school_schedules (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  school_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  periods TEXT DEFAULT '[]',
  is_active INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(school_id) REFERENCES schools(id) ON DELETE CASCADE
);

-- School-level attendance (separate from teacher-level)
CREATE TABLE IF NOT EXISTS school_attendance (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  school_id INTEGER NOT NULL,
  student_id INTEGER NOT NULL,
  date TEXT NOT NULL,
  period_index INTEGER DEFAULT 0,
  status TEXT NOT NULL,
  recorded_by_type TEXT,
  recorded_by_id INTEGER,
  notes TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(school_id, student_id, date, period_index),
  FOREIGN KEY(school_id) REFERENCES schools(id) ON DELETE CASCADE,
  FOREIGN KEY(student_id) REFERENCES school_students(id) ON DELETE CASCADE
);

-- School-level notes
CREATE TABLE IF NOT EXISTS school_notes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  school_id INTEGER NOT NULL,
  student_id INTEGER NOT NULL,
  type TEXT NOT NULL,
  text TEXT NOT NULL,
  date TEXT,
  time TEXT,
  recorded_by_type TEXT,
  recorded_by_id INTEGER,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(school_id) REFERENCES schools(id) ON DELETE CASCADE,
  FOREIGN KEY(student_id) REFERENCES school_students(id) ON DELETE CASCADE
);

-- Teacher-student links (which school-students belong to each teacher)
CREATE TABLE IF NOT EXISTS teacher_students (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  teacher_id INTEGER NOT NULL,
  school_student_id INTEGER NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(teacher_id, school_student_id),
  FOREIGN KEY(teacher_id) REFERENCES teachers(id) ON DELETE CASCADE,
  FOREIGN KEY(school_student_id) REFERENCES school_students(id) ON DELETE CASCADE
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
// AI Assistant settings per teacher
ensureColumn('teachers', 'ai_enabled', 'INTEGER DEFAULT 0');
ensureColumn('teachers', 'ai_system_prompt', 'TEXT');
// School-level permissions for teachers (same pattern as staff)
ensureColumn('teachers', 'permissions', 'TEXT DEFAULT "[]"');
ensureColumn('teachers', 'status', 'TEXT DEFAULT "active"');

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
           academic_year, academic_term, security_question, last_login, created_at, permissions, status
    FROM teachers WHERE school_id = ? ORDER BY created_at DESC
  `).all(req.session.school_id);
  teachers.forEach(t => { try { t.permissions = JSON.parse(t.permissions || '[]'); } catch(e) { t.permissions = []; } });
  res.json({ teachers });
});

app.post('/api/school/teachers', requireSchool, (req, res) => {
  try {
    const b = req.body;
    if (!b.username || !b.password) return res.status(400).json({ error: 'اسم المستخدم وكلمة المرور مطلوبان' });
    const hash = bcrypt.hashSync(b.password, 10);
    const permsStr = JSON.stringify(Array.isArray(b.permissions) ? b.permissions : []);
    const r = db.prepare(`
      INSERT INTO teachers (school_id, username, password_hash, full_name, subject, grade_level, phone, email, academic_year, academic_term, permissions)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      req.session.school_id, b.username, hash,
      b.full_name || '', b.subject || '', b.grade_level || '',
      b.phone || '', b.email || '', b.academic_year || '', b.academic_term || '', permsStr
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
    ['username','full_name','subject','grade_level','phone','email','academic_year','academic_term','status'].forEach(f => {
      if (b[f] !== undefined) { fields.push(`${f} = ?`); values.push(b[f]); }
    });
    if (b.permissions !== undefined) {
      fields.push('permissions = ?');
      values.push(JSON.stringify(Array.isArray(b.permissions) ? b.permissions : []));
    }
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
// School Staff (Admins with roles)
// ========================================
app.get('/api/school/staff', requireSchool, (req, res) => {
  try {
    const rows = db.prepare(`SELECT id, username, full_name, email, phone, role, permissions, status, created_at
                             FROM school_staff WHERE school_id = ? ORDER BY created_at DESC`).all(req.session.school_id);
    rows.forEach(r => { try { r.permissions = JSON.parse(r.permissions || '[]'); } catch(e) { r.permissions = []; } });
    res.json({ staff: rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/school/staff', requireSchool, (req, res) => {
  try {
    const { username, password, full_name, email, phone, role, permissions } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'اسم المستخدم وكلمة المرور مطلوبان' });
    const hash = bcrypt.hashSync(password, 10);
    const permsStr = JSON.stringify(Array.isArray(permissions) ? permissions : []);
    const info = db.prepare(`INSERT INTO school_staff (school_id, username, password_hash, full_name, email, phone, role, permissions)
                             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`).run(
      req.session.school_id, username, hash, full_name || '', email || '', phone || '', role || 'supervisor', permsStr
    );
    res.json({ success: true, id: info.lastInsertRowid });
  } catch (e) {
    if (String(e.message).includes('UNIQUE')) return res.status(400).json({ error: 'اسم المستخدم موجود بالفعل' });
    res.status(500).json({ error: e.message });
  }
});

app.put('/api/school/staff/:id', requireSchool, (req, res) => {
  try {
    const { full_name, email, phone, role, permissions, status } = req.body;
    const permsStr = JSON.stringify(Array.isArray(permissions) ? permissions : []);
    db.prepare(`UPDATE school_staff SET full_name=?, email=?, phone=?, role=?, permissions=?, status=?
                WHERE id = ? AND school_id = ?`).run(
      full_name || '', email || '', phone || '', role || 'supervisor', permsStr, status || 'active',
      req.params.id, req.session.school_id
    );
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/school/staff/:id/reset-password', requireSchool, (req, res) => {
  try {
    const { password } = req.body;
    if (!password || password.length < 6) return res.status(400).json({ error: 'كلمة المرور يجب أن تكون 6 أحرف على الأقل' });
    const hash = bcrypt.hashSync(password, 10);
    db.prepare('UPDATE school_staff SET password_hash = ? WHERE id = ? AND school_id = ?').run(hash, req.params.id, req.session.school_id);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/school/staff/:id', requireSchool, (req, res) => {
  db.prepare('DELETE FROM school_staff WHERE id = ? AND school_id = ?').run(req.params.id, req.session.school_id);
  res.json({ success: true });
});

// ========================================
// Grades & Sections (School-level, shared)
// ========================================
app.get('/api/school/grades', requireSchool, (req, res) => {
  try {
    const grades = db.prepare(`SELECT * FROM school_grades WHERE school_id = ? ORDER BY display_order, id`)
      .all(req.session.school_id);
    grades.forEach(g => {
      g.sections = db.prepare(`SELECT * FROM school_sections WHERE grade_id = ? ORDER BY display_order, id`).all(g.id);
      g.student_count = db.prepare(`SELECT COUNT(*) AS c FROM school_students WHERE grade_id = ?`).get(g.id).c;
    });
    res.json({ grades });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/school/grades', requireSchool, (req, res) => {
  try {
    const { name, display_order } = req.body;
    if (!name) return res.status(400).json({ error: 'الاسم مطلوب' });
    const info = db.prepare(`INSERT INTO school_grades (school_id, name, display_order) VALUES (?, ?, ?)`)
      .run(req.session.school_id, name, display_order || 0);
    res.json({ success: true, id: info.lastInsertRowid });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/school/grades/:id', requireSchool, (req, res) => {
  try {
    const { name, display_order } = req.body;
    db.prepare(`UPDATE school_grades SET name = ?, display_order = ? WHERE id = ? AND school_id = ?`)
      .run(name, display_order || 0, req.params.id, req.session.school_id);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/school/grades/:id', requireSchool, (req, res) => {
  try {
    const gradeId = req.params.id;
    const schoolId = req.session.school_id;
    // Verify ownership
    const grade = db.prepare('SELECT id FROM school_grades WHERE id = ? AND school_id = ?').get(gradeId, schoolId);
    if (!grade) return res.status(404).json({ error: 'الصف غير موجود' });
    // Manual cascade in transaction to guarantee order
    const txn = db.transaction(() => {
      // Delete school_attendance records for students in this grade
      db.prepare(`DELETE FROM school_attendance WHERE student_id IN 
                  (SELECT id FROM school_students WHERE grade_id = ?)`).run(gradeId);
      // Delete school_notes records for students in this grade
      db.prepare(`DELETE FROM school_notes WHERE student_id IN 
                  (SELECT id FROM school_students WHERE grade_id = ?)`).run(gradeId);
      // Delete teacher_students links
      db.prepare(`DELETE FROM teacher_students WHERE school_student_id IN 
                  (SELECT id FROM school_students WHERE grade_id = ?)`).run(gradeId);
      // Delete students
      db.prepare('DELETE FROM school_students WHERE grade_id = ?').run(gradeId);
      // Delete sections
      db.prepare('DELETE FROM school_sections WHERE grade_id = ?').run(gradeId);
      // Delete grade
      db.prepare('DELETE FROM school_grades WHERE id = ? AND school_id = ?').run(gradeId, schoolId);
    });
    txn();
    res.json({ success: true });
  } catch (e) { 
    console.error('Delete grade error:', e);
    res.status(500).json({ error: e.message }); 
  }
});

app.post('/api/school/grades/:id/sections', requireSchool, (req, res) => {
  try {
    const { name, display_order } = req.body;
    const grade = db.prepare(`SELECT id FROM school_grades WHERE id = ? AND school_id = ?`)
      .get(req.params.id, req.session.school_id);
    if (!grade) return res.status(404).json({ error: 'الصف غير موجود' });
    const info = db.prepare(`INSERT INTO school_sections (grade_id, name, display_order) VALUES (?, ?, ?)`)
      .run(grade.id, name, display_order || 0);
    res.json({ success: true, id: info.lastInsertRowid });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/school/sections/:id', requireSchool, (req, res) => {
  try {
    const secId = req.params.id;
    const row = db.prepare(`SELECT ss.id FROM school_sections ss 
                            JOIN school_grades sg ON ss.grade_id = sg.id 
                            WHERE ss.id = ? AND sg.school_id = ?`).get(secId, req.session.school_id);
    if (!row) return res.status(404).json({ error: 'الشعبة غير موجودة' });
    const txn = db.transaction(() => {
      db.prepare(`DELETE FROM school_attendance WHERE student_id IN 
                  (SELECT id FROM school_students WHERE section_id = ?)`).run(secId);
      db.prepare(`DELETE FROM school_notes WHERE student_id IN 
                  (SELECT id FROM school_students WHERE section_id = ?)`).run(secId);
      db.prepare(`DELETE FROM teacher_students WHERE school_student_id IN 
                  (SELECT id FROM school_students WHERE section_id = ?)`).run(secId);
      db.prepare('DELETE FROM school_students WHERE section_id = ?').run(secId);
      db.prepare('DELETE FROM school_sections WHERE id = ?').run(secId);
    });
    txn();
    res.json({ success: true });
  } catch (e) { 
    console.error('Delete section error:', e);
    res.status(500).json({ error: e.message }); 
  }
});

// Bulk import grades+sections+students from Excel (client sends parsed JSON)
app.post('/api/school/grades/import', requireSchool, (req, res) => {
  try {
    const { grade_name, sections } = req.body;
    if (!grade_name) return res.status(400).json({ error: 'اسم الصف مطلوب' });
    if (!Array.isArray(sections) || !sections.length) return res.status(400).json({ error: 'يجب توفير شعبة واحدة على الأقل' });
    // Find or create grade
    let grade = db.prepare(`SELECT id FROM school_grades WHERE school_id = ? AND name = ?`)
      .get(req.session.school_id, grade_name);
    if (!grade) {
      const info = db.prepare(`INSERT INTO school_grades (school_id, name) VALUES (?, ?)`)
        .run(req.session.school_id, grade_name);
      grade = { id: info.lastInsertRowid };
    }
    let totalStudents = 0, totalSections = 0;
    const txn = db.transaction(() => {
      for (const sec of sections) {
        if (!sec.name || !Array.isArray(sec.students)) continue;
        let section = db.prepare(`SELECT id FROM school_sections WHERE grade_id = ? AND name = ?`)
          .get(grade.id, sec.name);
        if (!section) {
          const info = db.prepare(`INSERT INTO school_sections (grade_id, name) VALUES (?, ?)`)
            .run(grade.id, sec.name);
          section = { id: info.lastInsertRowid };
          totalSections++;
        }
        const insertStmt = db.prepare(`INSERT INTO school_students 
          (school_id, grade_id, section_id, name, student_id, parent_phone, nationality, gender, date_of_birth)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`);
        for (const st of sec.students) {
          if (!st.name) continue;
          insertStmt.run(req.session.school_id, grade.id, section.id, st.name,
            st.student_id || '', st.parent_phone || '', st.nationality || '',
            st.gender || '', st.date_of_birth || '');
          totalStudents++;
        }
      }
    });
    txn();
    res.json({ success: true, grade_id: grade.id, total_students: totalStudents, total_sections: totalSections });
  } catch (e) { console.error(e); res.status(500).json({ error: e.message }); }
});

// ========================================
// School Students (CRUD + list)
// ========================================
app.get('/api/school/students', requireSchool, (req, res) => {
  try {
    const students = db.prepare(`
      SELECT ss.*, sg.name AS grade_name, sec.name AS section_name
      FROM school_students ss
      JOIN school_grades sg ON ss.grade_id = sg.id
      JOIN school_sections sec ON ss.section_id = sec.id
      WHERE ss.school_id = ?
      ORDER BY sg.display_order, sec.display_order, ss.name
    `).all(req.session.school_id);
    res.json({ students });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/school/students', requireSchool, (req, res) => {
  try {
    const { grade_id, section_id, name, student_id, parent_phone, nationality, gender, date_of_birth } = req.body;
    if (!name || !grade_id || !section_id) return res.status(400).json({ error: 'الاسم والصف والشعبة مطلوبة' });
    const info = db.prepare(`INSERT INTO school_students 
      (school_id, grade_id, section_id, name, student_id, parent_phone, nationality, gender, date_of_birth)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
      req.session.school_id, grade_id, section_id, name,
      student_id || '', parent_phone || '', nationality || '', gender || '', date_of_birth || ''
    );
    res.json({ success: true, id: info.lastInsertRowid });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/school/students/:id', requireSchool, (req, res) => {
  try {
    const { grade_id, section_id, name, student_id, parent_phone, nationality, gender, date_of_birth } = req.body;
    db.prepare(`UPDATE school_students SET grade_id=?, section_id=?, name=?, student_id=?, parent_phone=?, 
                nationality=?, gender=?, date_of_birth=? WHERE id = ? AND school_id = ?`).run(
      grade_id, section_id, name, student_id || '', parent_phone || '', nationality || '',
      gender || '', date_of_birth || '', req.params.id, req.session.school_id
    );
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/school/students/:id', requireSchool, (req, res) => {
  try {
    const stuId = req.params.id;
    const txn = db.transaction(() => {
      db.prepare('DELETE FROM school_attendance WHERE student_id = ?').run(stuId);
      db.prepare('DELETE FROM school_notes WHERE student_id = ?').run(stuId);
      db.prepare('DELETE FROM teacher_students WHERE school_student_id = ?').run(stuId);
      db.prepare('DELETE FROM school_students WHERE id = ? AND school_id = ?').run(stuId, req.session.school_id);
    });
    txn();
    res.json({ success: true });
  } catch (e) {
    console.error('Delete student error:', e);
    res.status(500).json({ error: e.message });
  }
});

// ========================================
// School Schedules (periods)
// ========================================
app.get('/api/school/schedules', requireSchool, (req, res) => {
  try {
    const rows = db.prepare(`SELECT * FROM school_schedules WHERE school_id = ? ORDER BY is_active DESC, name`)
      .all(req.session.school_id);
    rows.forEach(r => { try { r.periods = JSON.parse(r.periods || '[]'); } catch(e) { r.periods = []; } });
    res.json({ schedules: rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/school/schedules', requireSchool, (req, res) => {
  try {
    const { name, periods, is_active } = req.body;
    if (!name) return res.status(400).json({ error: 'الاسم مطلوب' });
    if (is_active) db.prepare(`UPDATE school_schedules SET is_active = 0 WHERE school_id = ?`).run(req.session.school_id);
    const info = db.prepare(`INSERT INTO school_schedules (school_id, name, periods, is_active) VALUES (?, ?, ?, ?)`)
      .run(req.session.school_id, name, JSON.stringify(periods || []), is_active ? 1 : 0);
    res.json({ success: true, id: info.lastInsertRowid });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/school/schedules/:id', requireSchool, (req, res) => {
  try {
    const { name, periods, is_active } = req.body;
    if (is_active) db.prepare(`UPDATE school_schedules SET is_active = 0 WHERE school_id = ?`).run(req.session.school_id);
    db.prepare(`UPDATE school_schedules SET name=?, periods=?, is_active=? WHERE id = ? AND school_id = ?`)
      .run(name, JSON.stringify(periods || []), is_active ? 1 : 0, req.params.id, req.session.school_id);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/school/schedules/:id', requireSchool, (req, res) => {
  db.prepare(`DELETE FROM school_schedules WHERE id = ? AND school_id = ?`).run(req.params.id, req.session.school_id);
  res.json({ success: true });
});

// ========================================
// School Attendance
// ========================================

// GET attendance records for a specific date, optionally filtered by section/grade/period
app.get('/api/school/attendance', requireSchool, (req, res) => {
  try {
    const sid = req.session.school_id;
    const tid = (req.session.teacher_id && _teacherHasLinks(req.session.teacher_id)) ? req.session.teacher_id : null;
    const date = req.query.date || new Date().toISOString().slice(0, 10);
    const sectionId = req.query.section_id ? Number(req.query.section_id) : null;
    const gradeId   = req.query.grade_id   ? Number(req.query.grade_id)   : null;
    const periodIdx = (req.query.period_index !== undefined && req.query.period_index !== '')
      ? Number(req.query.period_index) : null;

    // DEDUP: one row per unique real student (by name + student_id)
    // Each real student has multiple rows in school_students (one per subject/section).
    // We collapse them here and use MIN(ss.id) as the canonical record for attendance.
    let stuSql = `SELECT MIN(ss.id) AS id, ss.name,
                         ss.student_id AS student_code,
                         MIN(ss.parent_phone) AS parent_phone,
                         MIN(ss.grade_id) AS grade_id,
                         MIN(ss.section_id) AS section_id,
                         MIN(sg.name) AS grade_name,
                         GROUP_CONCAT(DISTINCT sec.name) AS section_name
                  FROM school_students ss
                  JOIN school_grades sg ON ss.grade_id = sg.id
                  JOIN school_sections sec ON ss.section_id = sec.id`;
    if (tid) stuSql += ` JOIN teacher_students ts ON ts.school_student_id = ss.id AND ts.teacher_id = ?`;
    stuSql += ` WHERE ss.school_id = ?`;
    const stuParams = tid ? [tid, sid] : [sid];
    if (sectionId) { stuSql += ` AND ss.section_id = ?`; stuParams.push(sectionId); }
    if (gradeId)   { stuSql += ` AND ss.grade_id = ?`;   stuParams.push(gradeId); }
    stuSql += ` GROUP BY ss.name, COALESCE(ss.student_id, '')
                 ORDER BY MIN(sg.display_order), ss.name`;
    const students = db.prepare(stuSql).all(...stuParams);

    // Build a set of canonical IDs for record lookup (the same MIN(ss.id) values)
    const canonicalIds = new Set(students.map(s => s.id));

    let recSql = `SELECT sa.* FROM school_attendance sa
                  JOIN school_students ss ON sa.student_id = ss.id`;
    if (tid) recSql += ` JOIN teacher_students ts ON ts.school_student_id = ss.id AND ts.teacher_id = ?`;
    recSql += ` WHERE sa.school_id = ? AND sa.date = ?`;
    const recParams = tid ? [tid, sid, date] : [sid, date];
    if (sectionId) { recSql += ` AND ss.section_id = ?`; recParams.push(sectionId); }
    if (gradeId)   { recSql += ` AND ss.grade_id = ?`;   recParams.push(gradeId); }
    if (periodIdx !== null) { recSql += ` AND sa.period_index = ?`; recParams.push(periodIdx); }
    const allRecords = db.prepare(recSql).all(...recParams);
    // Only surface records tied to canonical student rows (prevents duplicates
    // if attendance was somehow saved on a non-canonical row in the past)
    const records = allRecords.filter(r => canonicalIds.has(r.student_id));

    const activeSchedule = db.prepare(`SELECT id, name, periods FROM school_schedules WHERE school_id = ? AND is_active = 1 LIMIT 1`)
      .get(sid);
    if (activeSchedule) {
      try { activeSchedule.periods = JSON.parse(activeSchedule.periods || '[]'); } catch(e) { activeSchedule.periods = []; }
    }

    res.json({ date, students, records, active_schedule: activeSchedule || null });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

function _attendanceRecorder(req) {
  if (req.session.teacher_id) return { type: 'teacher', id: req.session.teacher_id };
  if (req.session.staff_id)   return { type: 'staff',   id: req.session.staff_id };
  return { type: 'school', id: req.session.school_id };
}

function _teacherOwnsStudent(teacherId, studentId) {
  return !!db.prepare(`SELECT 1 FROM teacher_students WHERE teacher_id = ? AND school_student_id = ?`)
    .get(teacherId, studentId);
}

// Return true if this teacher has ANY linked students. If false, we show all school students.
function _teacherHasLinks(teacherId) {
  return !!db.prepare(`SELECT 1 FROM teacher_students WHERE teacher_id = ? LIMIT 1`).get(teacherId);
}

app.post('/api/school/attendance', requireSchool, (req, res) => {
  try {
    const { student_id, date, period_index, status, notes } = req.body;
    if (!student_id || !date || !status) return res.status(400).json({ error: '   ' });
    const validStatuses = ['present', 'absent', 'late', 'excused'];
    if (!validStatuses.includes(status)) return res.status(400).json({ error: '   ' });
    const stu = db.prepare(`SELECT id FROM school_students WHERE id = ? AND school_id = ?`)
      .get(student_id, req.session.school_id);
    if (!stu) return res.status(404).json({ error: '     ' });
    if (req.session.teacher_id && !_teacherOwnsStudent(req.session.teacher_id, student_id)) {
      return res.status(403).json({ error: '     ' });
    }
    const pIdx = Number(period_index) || 0;
    const rec = _attendanceRecorder(req);
    db.prepare(`INSERT INTO school_attendance
      (school_id, student_id, date, period_index, status, recorded_by_type, recorded_by_id, notes)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(school_id, student_id, date, period_index) DO UPDATE SET
        status = excluded.status, recorded_by_type = excluded.recorded_by_type,
        recorded_by_id = excluded.recorded_by_id, notes = excluded.notes
    `).run(req.session.school_id, student_id, date, pIdx, status, rec.type, rec.id, notes || '');
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/school/attendance/bulk', requireSchool, (req, res) => {
  try {
    const { date, period_index, records } = req.body;
    if (!date || !Array.isArray(records)) return res.status(400).json({ error: '   ' });
    const sid = req.session.school_id;
    const tid = (req.session.teacher_id && _teacherHasLinks(req.session.teacher_id)) ? req.session.teacher_id : null;
    const pIdx = Number(period_index) || 0;
    const rec = _attendanceRecorder(req);
    const validStatuses = ['present', 'absent', 'late', 'excused'];
    const upsert = db.prepare(`INSERT INTO school_attendance
      (school_id, student_id, date, period_index, status, recorded_by_type, recorded_by_id, notes)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(school_id, student_id, date, period_index) DO UPDATE SET
        status = excluded.status, recorded_by_type = excluded.recorded_by_type,
        recorded_by_id = excluded.recorded_by_id, notes = excluded.notes
    `);
    const clear = db.prepare(`DELETE FROM school_attendance WHERE school_id=? AND student_id=? AND date=? AND period_index=?`);
    const ownsStu = db.prepare(`SELECT 1 FROM school_students WHERE id=? AND school_id=?`);
    const teacherOwnsStu = db.prepare(`SELECT 1 FROM teacher_students WHERE teacher_id=? AND school_student_id=?`);
    const txn = db.transaction((arr) => {
      let saved = 0, cleared = 0, skipped = 0;
      for (const r of arr) {
        if (!r.student_id) { skipped++; continue; }
        if (!ownsStu.get(r.student_id, sid)) { skipped++; continue; }
        if (tid && !teacherOwnsStu.get(tid, r.student_id)) { skipped++; continue; }
        if (!r.status || r.status === 'clear') {
          clear.run(sid, r.student_id, date, pIdx); cleared++; continue;
        }
        if (!validStatuses.includes(r.status)) { skipped++; continue; }
        upsert.run(sid, r.student_id, date, pIdx, r.status, rec.type, rec.id, r.notes || '');
        saved++;
      }
      return { saved, cleared, skipped };
    });
    const result = txn(records);
    res.json({ success: true, ...result });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/school/attendance/:id', requireSchool, (req, res) => {
  try {
    if (req.session.teacher_id) {
      const row = db.prepare(`SELECT student_id FROM school_attendance WHERE id=? AND school_id=?`)
        .get(req.params.id, req.session.school_id);
      if (!row || !_teacherOwnsStudent(req.session.teacher_id, row.student_id)) {
        return res.status(403).json({ error: ' ' });
      }
    }
    db.prepare(`DELETE FROM school_attendance WHERE id = ? AND school_id = ?`)
      .run(req.params.id, req.session.school_id);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/school/attendance/report', requireSchool, (req, res) => {
  try {
    const sid = req.session.school_id;
    const tid = (req.session.teacher_id && _teacherHasLinks(req.session.teacher_id)) ? req.session.teacher_id : null;
    const from = req.query.from || new Date().toISOString().slice(0, 10);
    const to   = req.query.to   || from;
    const studentId = req.query.student_id ? Number(req.query.student_id) : null;
    const sectionId = req.query.section_id ? Number(req.query.section_id) : null;
    const gradeId   = req.query.grade_id   ? Number(req.query.grade_id)   : null;
    const periodIdx = (req.query.period_index !== undefined && req.query.period_index !== '')
      ? Number(req.query.period_index) : null;
    let sql = `SELECT sa.*, ss.name AS student_name, ss.student_id AS student_code,
                      sg.name AS grade_name, sec.name AS section_name
               FROM school_attendance sa
               JOIN school_students ss ON sa.student_id = ss.id
               JOIN school_grades sg ON ss.grade_id = sg.id
               JOIN school_sections sec ON ss.section_id = sec.id`;
    if (tid) sql += ` JOIN teacher_students ts ON ts.school_student_id = ss.id AND ts.teacher_id = ?`;
    sql += ` WHERE sa.school_id = ? AND sa.date BETWEEN ? AND ?`;
    const params = tid ? [tid, sid, from, to] : [sid, from, to];
    if (studentId) { sql += ` AND sa.student_id = ?`;  params.push(studentId); }
    if (sectionId) { sql += ` AND ss.section_id = ?`;  params.push(sectionId); }
    if (gradeId)   { sql += ` AND ss.grade_id = ?`;    params.push(gradeId); }
    if (periodIdx !== null) { sql += ` AND sa.period_index = ?`; params.push(periodIdx); }
    sql += ` ORDER BY sa.date DESC, sa.period_index, sg.display_order, sec.display_order, ss.name`;
    const rows = db.prepare(sql).all(...params);
    const counts = { present: 0, absent: 0, late: 0, excused: 0 };
    rows.forEach(r => { if (counts[r.status] !== undefined) counts[r.status]++; });
    res.json({ from, to, records: rows, counts, total: rows.length });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ========================================
// School Dashboard Stats
// ========================================
app.get('/api/school/stats', requireSchool, (req, res) => {
  try {
    const sid = req.session.school_id;
    const today = new Date().toISOString().slice(0, 10);
    const stats = {
      teachers_count: db.prepare(`SELECT COUNT(*) AS c FROM teachers WHERE school_id = ? AND status = 'active'`).get(sid).c,
      staff_count: db.prepare(`SELECT COUNT(*) AS c FROM school_staff WHERE school_id = ? AND status = 'active'`).get(sid).c,
      students_count: db.prepare(`SELECT COUNT(*) AS c FROM school_students WHERE school_id = ?`).get(sid).c,
      grades_count: db.prepare(`SELECT COUNT(*) AS c FROM school_grades WHERE school_id = ?`).get(sid).c,
      sections_count: db.prepare(`SELECT COUNT(*) AS c FROM school_sections ss JOIN school_grades sg ON ss.grade_id = sg.id WHERE sg.school_id = ?`).get(sid).c,
      attendance_today: db.prepare(`SELECT status, COUNT(*) AS c FROM school_attendance WHERE school_id = ? AND date = ? GROUP BY status`).all(sid, today),
      notes_week_positive: db.prepare(`SELECT COUNT(*) AS c FROM school_notes WHERE school_id = ? AND type = 'positive' AND date >= date('now', '-7 days')`).get(sid).c,
      notes_week_negative: db.prepare(`SELECT COUNT(*) AS c FROM school_notes WHERE school_id = ? AND type = 'negative' AND date >= date('now', '-7 days')`).get(sid).c
    };
    res.json({ stats, today });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ========================================
// Teacher APIs
// ========================================

// ==================== SCHOOL ADMIN: Access all teachers' notes & reports ====================

// Get aggregated data from ALL teachers in the school (for notes/reports views)
app.get('/api/school/all-teacher-data', requireSchool, (req, res) => {
  try {
    const teachers = db.prepare(`
      SELECT id, full_name, username, subject, grade_level, app_data 
      FROM teachers 
      WHERE school_id = ?
      ORDER BY full_name
    `).all(req.session.school_id);
    
    const result = teachers.map(t => {
      let data = {};
      try { data = JSON.parse(t.app_data || '{}'); } catch(e) {}
      return {
        teacher_id: t.id,
        teacher_name: t.full_name,
        teacher_username: t.username,
        subject: t.subject || '',
        grade_level: t.grade_level || '',
        data: data
      };
    });
    
    res.json({ teachers: result });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Get list of teachers (for filter dropdown)
app.get('/api/school/teachers-list', requireSchool, (req, res) => {
  try {
    const teachers = db.prepare(`
      SELECT id, full_name, username, subject 
      FROM teachers 
      WHERE school_id = ?
      ORDER BY full_name
    `).all(req.session.school_id);
    res.json({ teachers });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});


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

// Get school's grades, sections, and students for teacher to import
app.get('/api/teacher/school-data', requireTeacher, (req, res) => {
  try {
    const t = db.prepare('SELECT school_id FROM teachers WHERE id = ?').get(req.session.teacher_id);
    if (!t || !t.school_id) return res.json({ grades: [] });
    const schoolId = t.school_id;
    const grades = db.prepare('SELECT id, name, display_order FROM school_grades WHERE school_id = ? ORDER BY display_order, id').all(schoolId);
    grades.forEach(g => {
      g.sections = db.prepare('SELECT id, name, display_order FROM school_sections WHERE grade_id = ? ORDER BY display_order, id').all(g.id);
      g.sections.forEach(s => {
        s.students = db.prepare('SELECT id, name, student_id, parent_phone, nationality, gender FROM school_students WHERE section_id = ? ORDER BY name').all(s.id);
      });
      // Also include students in this grade without a section
      g.orphan_students = db.prepare('SELECT id, name, student_id, parent_phone, nationality, gender FROM school_students WHERE grade_id = ? AND (section_id IS NULL OR section_id = 0) ORDER BY name').all(g.id);
    });
    res.json({ grades });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
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

// ========================================
// AI Assistant (for teacher dashboard)
// ========================================
app.get('/api/teacher/ai-settings', requireTeacher, (req, res) => {
  try {
    const t = db.prepare('SELECT ai_enabled, ai_system_prompt FROM teachers WHERE id = ?').get(req.session.teacher_id);
    const school = db.prepare('SELECT openai_key, openai_model FROM schools WHERE id = ?').get(req.session.school_id);
    res.json({
      ai_enabled: !!(t?.ai_enabled),
      ai_system_prompt: t?.ai_system_prompt || '',
      school_has_openai: !!(school?.openai_key),
      school_openai_model: school?.openai_model || 'gpt-4o-mini'
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/teacher/ai-settings', requireTeacher, (req, res) => {
  try {
    const { ai_enabled, ai_system_prompt } = req.body;
    db.prepare('UPDATE teachers SET ai_enabled = ?, ai_system_prompt = ? WHERE id = ?')
      .run(ai_enabled ? 1 : 0, ai_system_prompt || '', req.session.teacher_id);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Get conversation history for teacher's students
app.get('/api/teacher/ai-conversations', requireTeacher, (req, res) => {
  try {
    const rows = db.prepare(`
      SELECT id, from_phone, message, reply, direction, created_at 
      FROM bot_conversations 
      WHERE school_id = ? AND teacher_id = ? 
      ORDER BY created_at DESC 
      LIMIT 100
    `).all(req.session.school_id, req.session.teacher_id);
    res.json({ conversations: rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Test the AI directly from teacher dashboard
app.post('/api/teacher/ai-test', requireTeacher, async (req, res) => {
  try {
    const { phone, message } = req.body;
    if (!phone || !message) return res.status(400).json({ error: 'phone and message are required' });
    const teacher = db.prepare('SELECT * FROM teachers WHERE id = ?').get(req.session.teacher_id);
    const school = db.prepare('SELECT openai_key, openai_model FROM schools WHERE id = ?').get(req.session.school_id);
    if (!school?.openai_key) return res.status(400).json({ error: 'لم يُضف مفتاح OpenAI في بيانات المدرسة' });
    const result = await processAiQuery({ phone, message, teacher, school });
    res.json(result);
  } catch (e) { console.error(e); res.status(500).json({ error: e.message }); }
});

// ========================================
// AI Processing helper
// ========================================
function findStudentByPhone(teacherId, phone) {
  // Normalize phone (remove whatsapp: prefix, spaces, keep + and digits)
  const clean = String(phone || '').replace(/whatsapp:/g, '').replace(/[^\d+]/g, '');
  const teacher = db.prepare('SELECT app_data FROM teachers WHERE id = ?').get(teacherId);
  if (!teacher?.app_data) return null;
  let data;
  try { data = JSON.parse(teacher.app_data); } catch (e) { return null; }
  const students = data.students || [];
  // Try exact match or suffix match (handle + prefix, country code variations)
  for (const s of students) {
    if (!s.parent_phone) continue;
    const stClean = String(s.parent_phone).replace(/[^\d+]/g, '');
    if (stClean === clean) return { student: s, teacherData: data };
    // Suffix match: last 9 digits (typical Oman/Gulf mobile length)
    const last9Clean = clean.replace(/\D/g, '').slice(-9);
    const last9St = stClean.replace(/\D/g, '').slice(-9);
    if (last9Clean && last9St && last9Clean === last9St) return { student: s, teacherData: data };
  }
  return null;
}

function buildStudentContext(student, teacherData, teacherInfo) {
  // Build a compact JSON-like context string for the AI about this student
  const grade = (teacherData.grades || []).find(g => g.id === student.grade_id);
  const section = grade?.sections?.find(s => s.id === student.section_id);
  const assessments = grade?.assessments || [];
  // Grades summary
  let totalScore = 0, maxScore = 0, scoreDetails = [];
  assessments.forEach(a => {
    const v = student.scores?.[a.id];
    maxScore += parseFloat(a.max) || 0;
    if (v != null) {
      totalScore += Number(v);
      scoreDetails.push(`${a.name}: ${v}/${a.max}${a.category === 'final' ? ' (نهائي)' : ' (مستمر)'}`);
    } else {
      scoreDetails.push(`${a.name}: لم تُدخل بعد (من ${a.max})`);
    }
  });
  // Attendance summary
  let present = 0, absent = 0, late = 0, excused = 0, attDates = [];
  Object.entries(teacherData.attendance || {}).forEach(([date, day]) => {
    const st = day[student.id];
    if (!st) return;
    if (st === 'present') present++;
    else if (st === 'absent') { absent++; attDates.push(`${date} (غائب)`); }
    else if (st === 'late') { late++; attDates.push(`${date} (متأخر)`); }
    else if (st === 'excused') { excused++; attDates.push(`${date} (مأذون)`); }
  });
  const totalDays = present + absent + late + excused;
  // Notes
  const notes = (teacherData.notes?.[student.id] || []).slice(-10).map(n => 
    `• ${n.date || ''}${n.time ? ' ' + n.time : ''} ${n.type === 'positive' ? '✅' : '⚠️'} ${n.text}`
  );
  // Evaluations
  const evals = (teacherData.evaluations || [])
    .filter(e => e.student_id === student.id)
    .slice(-5);
  const rubric = teacherData.rubric || [];
  const evalSummaries = evals.map(ev => {
    const parts = rubric.map(ax => {
      const r = ev.scores?.[ax.id];
      return r && ax.ranks?.[r-1] ? `${ax.name}: ${ax.ranks[r-1]}` : null;
    }).filter(Boolean);
    return `• ${ev.period || ev.date}: ${parts.join('، ')}`;
  });

  return `معلومات الطالب:
- الاسم: ${student.name}
- الصف: ${grade?.name || 'غير محدد'} ${section ? '- الشعبة: ' + section.name : ''}
- الرقم المدرسي: ${student.student_id || 'غير مسجل'}
- المعلم: ${teacherInfo.full_name || teacherInfo.username}
- المادة: ${teacherInfo.subject || 'غير محدد'}
- المدرسة: ${teacherInfo.school_name || ''}

الدرجات (المجموع: ${totalScore.toFixed(1)} من ${maxScore}):
${scoreDetails.join('\n') || 'لا توجد أدوات تقويم بعد'}

الحضور والغياب:
- عدد أيام التسجيل: ${totalDays}
- حاضر: ${present} | غائب: ${absent} | متأخر: ${late} | مأذون: ${excused}
${attDates.length ? 'تفاصيل أيام الغياب/التأخر الأخيرة:\n' + attDates.slice(-10).join('\n') : ''}

آخر الملاحظات (${notes.length}):
${notes.join('\n') || 'لا توجد ملاحظات مسجلة'}

آخر التقييمات الدورية:
${evalSummaries.join('\n') || 'لم يُقيّم دورياً بعد'}`;
}

async function processAiQuery({ phone, message, teacher, school }) {
  // 1. Find student by parent phone
  const match = findStudentByPhone(teacher.id, phone);
  if (!match) {
    return {
      matched: false,
      reply: 'عذراً، رقم هاتفكم غير مسجل في نظامنا. يرجى التواصل مع المعلم لتسجيل الرقم.'
    };
  }
  const { student, teacherData } = match;
  // 2. Build context
  const teacherInfo = {
    full_name: teacher.full_name,
    username: teacher.username,
    subject: teacher.subject,
    school_name: db.prepare('SELECT name_ar FROM schools WHERE id = ?').get(teacher.school_id)?.name_ar || ''
  };
  const context = buildStudentContext(student, teacherData, teacherInfo);
  // 3. Prepare system prompt
  const basePrompt = `أنت مساعد ذكي لمعلم يتواصل مع أولياء أمور الطلاب. مهمتك هي الإجابة على استفسارات ولي الأمر بشأن طفله/طفلتها فقط.

قواعد صارمة:
1. استخدم البيانات المتوفرة أدناه فقط. لا تختلق أي معلومات.
2. إذا سُئلت عن بيانات غير متوفرة، أجب بأدب: "هذه المعلومة غير متوفرة حالياً".
3. لا تُفصح عن بيانات طلاب آخرين مهما كان السؤال.
4. تحدث بالعربية بأسلوب ودود ومهذب ومهني.
5. كن مختصراً ومباشراً.
6. ابدأ رسالتك الأولى بتحية والسؤال عما يحتاجه ولي الأمر.
7. عند عرض الدرجات، استخدم تنسيقاً منظماً.
8. لا تتحدث عن أمور تقنية أو إدارية غير متعلقة بالطالب.`;
  const customPrompt = teacher.ai_system_prompt || '';
  const fullSystem = `${basePrompt}\n\n${customPrompt ? 'توجيهات إضافية من المعلم:\n' + customPrompt + '\n\n' : ''}${context}`;
  // 4. Fetch recent conversation history (last 6 exchanges for context)
  const history = db.prepare(`
    SELECT message, reply, direction, created_at 
    FROM bot_conversations 
    WHERE school_id = ? AND teacher_id = ? AND from_phone = ? 
    ORDER BY created_at DESC 
    LIMIT 12
  `).all(teacher.school_id, teacher.id, phone);
  const historyMessages = [];
  history.reverse().forEach(h => {
    if (h.message) historyMessages.push({ role: 'user', content: h.message });
    if (h.reply) historyMessages.push({ role: 'assistant', content: h.reply });
  });
  // 5. Call OpenAI
  const messages = [
    { role: 'system', content: fullSystem },
    ...historyMessages,
    { role: 'user', content: message }
  ];
  const openaiModel = school.openai_model || 'gpt-4o-mini';
  const r = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${school.openai_key}`
    },
    body: JSON.stringify({
      model: openaiModel,
      messages,
      max_tokens: 500,
      temperature: 0.4
    })
  });
  if (!r.ok) {
    const errText = await r.text();
    throw new Error(`OpenAI API error (${r.status}): ${errText.slice(0, 200)}`);
  }
  const data = await r.json();
  const reply = data.choices?.[0]?.message?.content || 'عذراً، لم أتمكن من معالجة طلبكم الآن.';
  return {
    matched: true,
    student_name: student.name,
    reply
  };
}

async function sendTwilioWhatsApp(school, to, body) {
  if (!school.twilio_sid || !school.twilio_token || !school.twilio_from) throw new Error('Twilio not configured');
  const auth = Buffer.from(`${school.twilio_sid}:${school.twilio_token}`).toString('base64');
  const toFormatted = to.startsWith('whatsapp:') ? to : `whatsapp:${to.startsWith('+') ? to : '+' + to}`;
  const fromFormatted = school.twilio_from.startsWith('whatsapp:') ? school.twilio_from : `whatsapp:${school.twilio_from.startsWith('+') ? school.twilio_from : '+' + school.twilio_from}`;
  const r = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${school.twilio_sid}/Messages.json`, {
    method: 'POST',
    headers: { 'Authorization': `Basic ${auth}`, 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ To: toFormatted, From: fromFormatted, Body: body })
  });
  if (!r.ok) {
    const errText = await r.text();
    throw new Error(`Twilio error (${r.status}): ${errText.slice(0, 200)}`);
  }
  return await r.json();
}

// ========================================
// Twilio Webhook — now AI-enabled
// ========================================
app.post('/api/webhook/twilio', express.urlencoded({ extended: false }), async (req, res) => {
  // Respond immediately to Twilio; process in background
  res.type('text/xml').send('<Response></Response>');
  try {
    const from = req.body.From || '';
    const to = req.body.To || '';
    const incomingMessage = req.body.Body || '';
    if (!from || !incomingMessage) return;
    // Find school by twilio_from
    const school = db.prepare(`
      SELECT * FROM schools 
      WHERE twilio_from = ? OR twilio_from = ? OR twilio_from = ? OR ('whatsapp:' || twilio_from) = ?
    `).get(to, to.replace('whatsapp:', ''), to.replace('whatsapp:+', '+'), to);
    if (!school) {
      console.warn(`Webhook: No school matched for To=${to}`);
      return;
    }
    // Find the teacher whose student has this parent phone
    const teachers = db.prepare('SELECT * FROM teachers WHERE school_id = ? AND ai_enabled = 1').all(school.id);
    let matchedTeacher = null, matchedStudent = null, matchedData = null;
    for (const t of teachers) {
      const m = findStudentByPhone(t.id, from);
      if (m) { matchedTeacher = t; matchedStudent = m.student; matchedData = m.teacherData; break; }
    }
    // Log incoming
    db.prepare('INSERT INTO bot_conversations (school_id, teacher_id, from_phone, to_phone, message, direction) VALUES (?, ?, ?, ?, ?, ?)')
      .run(school.id, matchedTeacher?.id || null, from, to, incomingMessage, 'in');
    let replyText;
    if (!matchedTeacher) {
      replyText = 'عذراً، رقم هاتفكم غير مسجل لدى أي معلم مفعّل للمساعد الذكي. يرجى التواصل مع المدرسة.';
    } else if (!school.openai_key) {
      replyText = 'عذراً، الخدمة الذكية غير مُفعّلة حالياً. يرجى التواصل مع إدارة المدرسة.';
    } else {
      try {
        const result = await processAiQuery({
          phone: from,
          message: incomingMessage,
          teacher: matchedTeacher,
          school
        });
        replyText = result.reply;
      } catch (e) {
        console.error('AI processing error:', e);
        replyText = 'عذراً، حدث خطأ في معالجة استفساركم. يرجى المحاولة لاحقاً.';
      }
    }
    // Send reply via Twilio
    try {
      await sendTwilioWhatsApp(school, from, replyText);
      // Log outgoing
      db.prepare('UPDATE bot_conversations SET reply = ? WHERE id = (SELECT MAX(id) FROM bot_conversations WHERE school_id = ? AND from_phone = ? AND direction = ?)')
        .run(replyText, school.id, from, 'in');
    } catch (e) {
      console.error('Twilio send error:', e);
    }
  } catch (e) { console.error('Webhook error:', e); }
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

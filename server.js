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
  CREATE TABLE IF NOT EXISTS bot_conversations (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER,
    from_phone TEXT,
    message    TEXT,
    reply      TEXT,
    direction  TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// Schema migration: add recovery columns
try {
  const cols = sqlite.prepare("PRAGMA table_info(users)").all();
  const colNames = cols.map(c => c.name);
  if (!colNames.includes('recovery_question')) {
    sqlite.exec("ALTER TABLE users ADD COLUMN recovery_question TEXT DEFAULT ''");
    console.log('✅ Added recovery_question column');
  }
  if (!colNames.includes('recovery_answer_hash')) {
    sqlite.exec("ALTER TABLE users ADD COLUMN recovery_answer_hash TEXT DEFAULT ''");
    console.log('✅ Added recovery_answer_hash column');
  }
} catch (err) {
  console.error('Migration warning:', err.message);
}

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
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
}));

// ══════════════════════════════════════
//  Twilio Webhook - بدون auth (لأنه يأتي من Twilio)
//  يجب أن يأتي قبل requireAuth
// ══════════════════════════════════════
app.post('/api/webhook/twilio', async (req, res) => {
  try {
    // Twilio يرسل application/x-www-form-urlencoded
    const from = String(req.body.From || '').replace('whatsapp:', '');
    const to = String(req.body.To || '').replace('whatsapp:', '');
    const message = String(req.body.Body || '').trim();
    const messageSid = req.body.MessageSid;

    console.log(`📨 Webhook: ${from} → ${to}: "${message}" (${messageSid})`);

    if (!from || !message) {
      return res.type('text/xml').send('<Response></Response>');
    }

    // البحث عن صاحب النظام (المعلم) حسب رقم Twilio المستخدم
    // في حالة Sandbox يكون to = +14155238886
    // نبحث في جميع المستخدمين عن من لديه هذا الرقم مُعَد
    const allUsers = sqlite.prepare('SELECT id, app_data FROM users').all();
    let targetUser = null;
    for (const u of allUsers) {
      try {
        const d = JSON.parse(u.app_data || '{}');
        const twilioFrom = (d.bot && d.bot.twilioFrom) ? d.bot.twilioFrom.replace(/\s/g, '') : '';
        if (twilioFrom && twilioFrom === to.replace(/\s/g, '')) {
          targetUser = { id: u.id, appData: d };
          break;
        }
      } catch {}
    }

    if (!targetUser) {
      console.log('⚠️ لا يوجد معلم مُعد لهذا الرقم:', to);
      // إن لم نجد، نستخدم أول حساب (للـ Sandbox البسيط)
      if (allUsers.length > 0) {
        try {
          targetUser = { id: allUsers[0].id, appData: JSON.parse(allUsers[0].app_data || '{}') };
        } catch {}
      }
    }

    if (!targetUser) {
      return res.type('text/xml').send('<Response><Message>النظام غير جاهز حالياً</Message></Response>');
    }

    // توليد رد ذكي
    const reply = await generateAIReply(targetUser.appData, from, message);

    // تسجيل المحادثة
    sqlite.prepare(
      'INSERT INTO bot_conversations (user_id, from_phone, message, reply, direction) VALUES (?, ?, ?, ?, ?)'
    ).run(targetUser.id, from, message, reply, 'incoming');

    // الرد عبر TwiML
    const xml = `<?xml version="1.0" encoding="UTF-8"?><Response><Message>${escapeXml(reply)}</Message></Response>`;
    res.type('text/xml').send(xml);
  } catch (err) {
    console.error('Webhook error:', err);
    res.type('text/xml').send('<Response><Message>عذراً، حدث خطأ. الرجاء المحاولة لاحقاً.</Message></Response>');
  }
});

function escapeXml(str) {
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

// ══════════════════════════════════════
//  AI Handler - يولّد رد ذكي على سؤال ولي الأمر
// ══════════════════════════════════════
async function generateAIReply(appData, fromPhone, userMessage) {
  const bot = appData.bot || {};

  // البحث عن الطالب حسب رقم الهاتف
  const studentInfo = findStudentByPhone(appData, fromPhone);

  // بناء context
  const teacherName = appData.teacher?.fullname || appData.teacher?.name || 'المعلم';
  const schoolName = appData.teacher?.school || '';
  const subject = appData.teacher?.subject || '';

  let studentContext = '';
  if (studentInfo) {
    const { student, section, grade } = studentInfo;
    const total = calcTotalForStudent(section, student.id);
    const level = levelOf(total);

    // آخر 3 ملاحظات
    const observations = (section.observations || [])
      .filter(o => (o.studentIds || []).includes(student.id))
      .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
      .slice(0, 3);

    const obsText = observations.length > 0
      ? observations.map(o => {
          const cat = (appData.observationCategories || []).find(c => c.id === o.categoryId);
          return `- ${o.type === 'positive' ? '✅' : '⚠️'} ${cat?.name || 'ملاحظة'}: ${o.note || '—'}`;
        }).join('\n')
      : 'لا توجد ملاحظات مسجلة';

    // آخر تقييم
    const latestEval = (section.evaluations || [])
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))[0];

    studentContext = `
بيانات ابن ولي الأمر:
- الاسم: ${student.name}
- الصف: ${grade.name}
- الشعبة: ${section.name}
- الرقم المدرسي: ${student.studentId || 'غير متوفر'}
- الدرجة الإجمالية: ${total !== null ? total + '/100' : 'لم تُدخل بعد'}
- المستوى: ${level.l}

آخر الملاحظات:
${obsText}

آخر تقييم دوري:
${latestEval ? `${latestEval.periodLabel || ''}: ${latestEval.generatedText || '—'}` : 'لا يوجد تقييم مسجل بعد'}`;
  } else {
    studentContext = `
⚠️ لم يتم التعرف على رقم الهاتف (${fromPhone}) في النظام.
ربما الرقم غير مسجل كرقم ولي أمر، أو مسجل بصيغة مختلفة.`;
  }

  const systemPrompt = bot.systemPrompt || `أنت مساعد تعليمي ذكي اسمك "بوت المعلم ${teacherName}".
تجيب على أسئلة أولياء الأمور عن درجات أبنائهم وملاحظات المعلم في مادة ${subject || 'الدراسة'}.
${schoolName ? 'مدرسة: ' + schoolName : ''}

أسلوبك:
- مهذّب ومختصر (3-5 أسطر بحد أقصى)
- ودود لكن احترافي
- ترد بالعربية الفصحى البسيطة
- إذا لم تعرف الإجابة، تقترح التواصل المباشر مع المعلم
- لا تتطوع بمعلومات غير مطلوبة
- لا تعطي آراء شخصية عن مستوى الطالب أو تشجّع التنافس`;

  const fullPrompt = `${systemPrompt}

${studentContext}

رسالة ولي الأمر:
"${userMessage}"

اكتب ردك مباشرة (بدون مقدمات مثل "بالتأكيد" أو "حسناً"):`;

  // اختيار المزود
  const provider = bot.provider || 'openai';

  try {
    if (provider === 'openai' && bot.apiKey) {
      return await callOpenAI(bot.apiKey, bot.model || 'gpt-4o-mini', fullPrompt);
    } else if (provider === 'claude' && bot.apiKey) {
      return await callClaude(bot.apiKey, bot.model || 'claude-sonnet-4-5', fullPrompt);
    } else if (provider === 'gemini' && bot.apiKey) {
      return await callGemini(bot.apiKey, bot.model || 'gemini-pro', fullPrompt);
    } else {
      // رد افتراضي بدون AI
      return fallbackReply(studentInfo, userMessage);
    }
  } catch (err) {
    console.error('AI call failed:', err);
    return fallbackReply(studentInfo, userMessage) + '\n\n(خطأ في الاتصال بخدمة الذكاء الاصطناعي)';
  }
}

// رد افتراضي بدون AI
function fallbackReply(studentInfo, userMessage) {
  if (!studentInfo) {
    return '❌ عذراً، رقمك غير مسجل في النظام. الرجاء التواصل مع المعلم لتسجيل رقمك.';
  }
  const { student, section } = studentInfo;
  const total = calcTotalForStudent(section, student.id);
  const level = levelOf(total);
  return `✅ مرحباً،\n\nالطالب: ${student.name}\nالشعبة: ${section.name}\nالدرجة: ${total !== null ? total + '/100' : 'لم تُدخل'}\nالمستوى: ${level.l}\n\nللاستفسار التفصيلي، الرجاء التواصل مع المعلم.`;
}

// OpenAI API
async function callOpenAI(apiKey, model, prompt) {
  const res = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${apiKey}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      model: model,
      messages: [{ role: 'user', content: prompt }],
      max_tokens: 500,
      temperature: 0.7
    })
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`OpenAI ${res.status}: ${err}`);
  }
  const data = await res.json();
  return data.choices?.[0]?.message?.content?.trim() || 'عذراً، لم أتمكن من الرد.';
}

// Claude API
async function callClaude(apiKey, model, prompt) {
  const res = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      model: model,
      max_tokens: 500,
      messages: [{ role: 'user', content: prompt }]
    })
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Claude ${res.status}: ${err}`);
  }
  const data = await res.json();
  return data.content?.[0]?.text?.trim() || 'عذراً، لم أتمكن من الرد.';
}

// Gemini API
async function callGemini(apiKey, model, prompt) {
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`;
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      contents: [{ parts: [{ text: prompt }] }],
      generationConfig: { maxOutputTokens: 500, temperature: 0.7 }
    })
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Gemini ${res.status}: ${err}`);
  }
  const data = await res.json();
  return data.candidates?.[0]?.content?.parts?.[0]?.text?.trim() || 'عذراً، لم أتمكن من الرد.';
}

// ══════════════════════════════════════
//  Helpers - البحث عن الطالب وحساب الدرجة
// ══════════════════════════════════════
function normalizePhone(phone) {
  return String(phone || '').replace(/[^\d]/g, '');
}

function findStudentByPhone(appData, phone) {
  const normalized = normalizePhone(phone);
  if (!normalized) return null;
  for (const grade of (appData.grades || [])) {
    for (const section of (grade.sections || [])) {
      for (const student of (section.students || [])) {
        const studentPhone = normalizePhone(student.parentPhone);
        // مطابقة: قد يختلف في البداية (مثلاً +968 vs 968)
        if (studentPhone && (
          studentPhone === normalized ||
          studentPhone.endsWith(normalized.slice(-8)) ||
          normalized.endsWith(studentPhone.slice(-8))
        )) {
          return { student, section, grade };
        }
      }
    }
  }
  return null;
}

function calcTotalForStudent(section, studentId) {
  // استخراج tools من الصف (grade-level)
  // ملاحظة: نسخة مبسطة هنا
  const gd = (section.gradeData || {})[studentId];
  if (!gd) return null;
  const tools = section.tools || [];
  let contScore = 0;
  let contMax = 0;
  (tools || []).forEach(t => {
    const v = gd[t.id];
    if (v !== undefined && v !== null && v !== '') {
      contScore += Number(v) || 0;
      contMax += Number(t.max) || 0;
    }
  });
  const contWeight = section.contWeight || 40;
  const finalWeight = section.finalWeight || 60;
  const finalMax = section.finalMax || 100;
  const contPct = contMax > 0 ? (contScore / contMax) * contWeight : 0;
  const finalExam = gd.finalExam;
  if (finalExam === undefined || finalExam === null || finalExam === '') {
    return contMax > 0 ? Math.round(contPct) : null;
  }
  const finalPct = (Number(finalExam) / finalMax) * finalWeight;
  return Math.round(contPct + finalPct);
}

function levelOf(total) {
  if (total === null || total === undefined) return { l: 'غير محدد', c: 'x' };
  if (total >= 90) return { l: 'متفوق', c: 'e' };
  if (total >= 80) return { l: 'ممتاز', c: 'g' };
  if (total >= 70) return { l: 'جيد جداً', c: 'g' };
  if (total >= 60) return { l: 'جيد', c: 'a' };
  if (total >= 50) return { l: 'مقبول', c: 'a' };
  return { l: 'يحتاج دعم', c: 'p' };
}

// ══════════════════════════════════════
//  Auth middleware
// ══════════════════════════════════════
const requireAuth = (req, res, next) => {
  if (req.session && req.session.userId) return next();
  if (req.path.startsWith('/api/')) {
    return res.status(401).json({ error: 'يرجى تسجيل الدخول أولاً' });
  }
  res.redirect('/login.html');
};

// login.html متاح بدون auth
app.get('/login.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// ══════════════════════════════════════
//  API - Setup & Login (بدون auth)
// ══════════════════════════════════════
app.get('/api/setup-status', (req, res) => {
  const result = sqlite.prepare('SELECT COUNT(*) as count FROM users').get();
  res.json({ setupDone: result.count > 0 });
});

app.post('/api/setup', (req, res) => {
  const { username, password, teacherName, recoveryQuestion, recoveryAnswer } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'اسم المستخدم وكلمة المرور مطلوبان' });
  if (!recoveryQuestion || !recoveryAnswer) return res.status(400).json({ error: 'سؤال الاسترجاع وإجابته مطلوبان' });
  if (recoveryAnswer.trim().length < 2) return res.status(400).json({ error: 'إجابة السؤال قصيرة جداً' });

  const existing = sqlite.prepare('SELECT COUNT(*) as count FROM users').get();
  if (existing.count > 0) return res.status(400).json({ error: 'الحساب موجود بالفعل. يرجى تسجيل الدخول.' });

  try {
    const hash = bcrypt.hashSync(password, 12);
    const answerHash = bcrypt.hashSync(recoveryAnswer.trim().toLowerCase(), 12);
    const defaultData = JSON.stringify({
      teacher: { name: teacherName || username, fullname: teacherName || username, subject: '', school: '', year: '2024 / 2025', phone: '', email: '', principal: '', schoolPhone: '', visitorSup: '', eduSup: '' },
      grades: [], evaluationAxes: [], observationCategories: [],
      templates: { obs: [], grades: [], behavioral: [], evaluation: [] },
      bot: {}
    });
    const result = sqlite.prepare('INSERT INTO users (username, password_hash, app_data, recovery_question, recovery_answer_hash) VALUES (?, ?, ?, ?, ?)')
      .run(username, hash, defaultData, recoveryQuestion, answerHash);
    req.session.userId = result.lastInsertRowid;
    req.session.username = username;
    res.json({ success: true });
  } catch (err) {
    if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') res.status(400).json({ error: 'اسم المستخدم مستخدم بالفعل' });
    else res.status(500).json({ error: 'خطأ في الإعداد: ' + err.message });
  }
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'أدخل اسم المستخدم وكلمة المرور' });
  const user = sqlite.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
  }
  req.session.userId = user.id;
  req.session.username = user.username;
  sqlite.prepare('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?').run(user.id);
  sqlite.prepare('INSERT INTO logs (user_id, action) VALUES (?, ?)').run(user.id, 'login');
  res.json({ success: true });
});

app.post('/api/logout', (req, res) => {
  if (req.session.userId) sqlite.prepare('INSERT INTO logs (user_id, action) VALUES (?, ?)').run(req.session.userId, 'logout');
  req.session.destroy(() => res.json({ success: true }));
});

app.get('/api/session', (req, res) => {
  if (req.session && req.session.userId) res.json({ loggedIn: true, username: req.session.username });
  else res.status(401).json({ loggedIn: false });
});

// ══════════════════════════════════════
//  API - Recovery (بدون auth)
// ══════════════════════════════════════
app.post('/api/recovery-question', (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'اسم المستخدم مطلوب' });
  const user = sqlite.prepare('SELECT recovery_question FROM users WHERE username = ?').get(username);
  if (!user) return res.status(404).json({ error: 'اسم المستخدم غير موجود' });
  if (!user.recovery_question) return res.status(400).json({ error: 'هذا الحساب لا يحتوي على سؤال استرجاع مسجّل' });
  res.json({ success: true, question: user.recovery_question });
});

app.post('/api/recovery-reset', (req, res) => {
  const { username, answer, newPassword } = req.body;
  if (!username || !answer || !newPassword) return res.status(400).json({ error: 'جميع الحقول مطلوبة' });
  if (newPassword.length < 6) return res.status(400).json({ error: 'كلمة المرور الجديدة قصيرة (6 أحرف على الأقل)' });
  const user = sqlite.prepare('SELECT id, recovery_answer_hash FROM users WHERE username = ?').get(username);
  if (!user || !user.recovery_answer_hash) return res.status(401).json({ error: 'بيانات الاسترجاع غير صحيحة' });
  const answerCheck = bcrypt.compareSync(answer.trim().toLowerCase(), user.recovery_answer_hash);
  if (!answerCheck) {
    sqlite.prepare('INSERT INTO logs (user_id, action) VALUES (?, ?)').run(user.id, 'recovery_failed');
    return res.status(401).json({ error: 'إجابة السؤال السري غير صحيحة' });
  }
  const newHash = bcrypt.hashSync(newPassword, 12);
  sqlite.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(newHash, user.id);
  sqlite.prepare('INSERT INTO logs (user_id, action) VALUES (?, ?)').run(user.id, 'recovery_reset');
  res.json({ success: true });
});

// ══════════════════════════════════════
//  Protected routes
// ══════════════════════════════════════
app.use(requireAuth, express.static(path.join(__dirname, 'public')));

app.get('/', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/api/data', requireAuth, (req, res) => {
  const user = sqlite.prepare('SELECT app_data FROM users WHERE id = ?').get(req.session.userId);
  try { res.json(JSON.parse(user.app_data || '{}')); } catch { res.json({}); }
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

app.post('/api/change-password', requireAuth, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!newPassword || newPassword.length < 6) return res.status(400).json({ error: 'كلمة المرور الجديدة قصيرة (6 أحرف على الأقل)' });
  const user = sqlite.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);
  if (!bcrypt.compareSync(currentPassword, user.password_hash)) return res.status(401).json({ error: 'كلمة المرور الحالية غير صحيحة' });
  const hash = bcrypt.hashSync(newPassword, 12);
  sqlite.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, req.session.userId);
  sqlite.prepare('INSERT INTO logs (user_id, action) VALUES (?, ?)').run(req.session.userId, 'change_password');
  res.json({ success: true });
});

// ══════════════════════════════════════
//  API - Twilio Integration
// ══════════════════════════════════════

// إرسال رسالة واتساب عبر Twilio
app.post('/api/bot/send-whatsapp', requireAuth, async (req, res) => {
  const { to, message } = req.body;
  if (!to || !message) return res.status(400).json({ error: 'الرقم والرسالة مطلوبان' });

  const user = sqlite.prepare('SELECT app_data FROM users WHERE id = ?').get(req.session.userId);
  let appData = {};
  try { appData = JSON.parse(user.app_data || '{}'); } catch {}
  const bot = appData.bot || {};

  if (!bot.twilioSid || !bot.twilioToken || !bot.twilioFrom) {
    return res.status(400).json({ error: 'إعدادات Twilio غير مكتملة. الرجاء ضبطها في الإعدادات → البوت الذكي' });
  }

  let toNumber = String(to).replace(/[^\d+]/g, '');
  if (!toNumber.startsWith('+')) toNumber = '+' + toNumber;
  const fromWa = `whatsapp:${bot.twilioFrom}`;
  const toWa = `whatsapp:${toNumber}`;

  const url = `https://api.twilio.com/2010-04-01/Accounts/${bot.twilioSid}/Messages.json`;
  const auth = Buffer.from(`${bot.twilioSid}:${bot.twilioToken}`).toString('base64');
  const params = new URLSearchParams();
  params.append('From', fromWa);
  params.append('To', toWa);
  params.append('Body', message);

  try {
    const twilioRes = await fetch(url, {
      method: 'POST',
      headers: { 'Authorization': `Basic ${auth}`, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params.toString()
    });
    const result = await twilioRes.json();
    if (!twilioRes.ok) {
      let msg = result.message || 'فشل الإرسال';
      if (result.code === 63007) msg = 'رقم المرسل غير مفعّل لـ WhatsApp في Twilio';
      else if (result.code === 63003) msg = 'المستقبل لم ينضم لـ Sandbox بعد. اطلب منه إرسال كلمة join للرقم أولاً';
      else if (result.code === 20003) msg = 'بيانات المصادقة خاطئة (Account SID أو Auth Token)';
      return res.status(400).json({ error: msg, twilioCode: result.code });
    }
    sqlite.prepare('INSERT INTO logs (user_id, action) VALUES (?, ?)').run(req.session.userId, `whatsapp_sent:${toNumber}`);
    sqlite.prepare('INSERT INTO bot_conversations (user_id, from_phone, message, reply, direction) VALUES (?, ?, ?, ?, ?)')
      .run(req.session.userId, toNumber, message, '', 'outgoing');
    res.json({ success: true, messageSid: result.sid, status: result.status });
  } catch (err) {
    console.error('Twilio error:', err);
    res.status(500).json({ error: 'خطأ في الاتصال بـ Twilio: ' + err.message });
  }
});

// اختبار اتصال Twilio
app.post('/api/bot/test-twilio', requireAuth, async (req, res) => {
  const { twilioSid, twilioToken } = req.body;
  if (!twilioSid || !twilioToken) return res.status(400).json({ error: 'Account SID و Auth Token مطلوبان' });
  const url = `https://api.twilio.com/2010-04-01/Accounts/${twilioSid}.json`;
  const auth = Buffer.from(`${twilioSid}:${twilioToken}`).toString('base64');
  try {
    const twilioRes = await fetch(url, { headers: { 'Authorization': `Basic ${auth}` } });
    const result = await twilioRes.json();
    if (!twilioRes.ok) return res.status(400).json({ error: result.message || 'فشل التحقق', twilioCode: result.code });
    res.json({ success: true, accountName: result.friendly_name, accountStatus: result.status, accountType: result.type });
  } catch (err) {
    res.status(500).json({ error: 'خطأ في الاتصال: ' + err.message });
  }
});

// اختبار AI
app.post('/api/bot/test-ai', requireAuth, async (req, res) => {
  const { provider, apiKey, model, testMessage } = req.body;
  if (!provider || !apiKey) return res.status(400).json({ error: 'المزود والمفتاح مطلوبان' });
  const msg = testMessage || 'مرحباً، هل تسمعني؟';
  try {
    let reply;
    if (provider === 'openai') reply = await callOpenAI(apiKey, model || 'gpt-4o-mini', msg);
    else if (provider === 'claude') reply = await callClaude(apiKey, model || 'claude-sonnet-4-5', msg);
    else if (provider === 'gemini') reply = await callGemini(apiKey, model || 'gemini-pro', msg);
    else return res.status(400).json({ error: 'مزود غير مدعوم' });
    res.json({ success: true, reply });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// سجل محادثات البوت
app.get('/api/bot/conversations', requireAuth, (req, res) => {
  const limit = Math.min(Number(req.query.limit) || 50, 200);
  const rows = sqlite.prepare(
    'SELECT id, from_phone, message, reply, direction, created_at FROM bot_conversations WHERE user_id = ? ORDER BY created_at DESC LIMIT ?'
  ).all(req.session.userId, limit);
  res.json({ conversations: rows });
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
  console.log('║  🤖 البوت الذكي: جاهز                    ║');
  console.log('║  📱 Twilio WhatsApp: مُفعّل              ║');
  console.log('╚══════════════════════════════════════════╝');
  console.log('');
  const users = sqlite.prepare('SELECT COUNT(*) as count FROM users').get();
  if (users.count === 0) console.log('⚠️  لا يوجد حساب — سيتم توجيهك للإعداد الأول');
  else console.log(`✅ ${users.count} حساب مسجّل`);
});

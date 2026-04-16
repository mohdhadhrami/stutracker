# 📚 نظام التقويم الذكي

نظام متكامل لإدارة درجات الطلاب والمتابعة السلوكية والتقييم الدوري.

---

## 🚀 النشر على Railway

هذا المشروع مُهيّأ للنشر على منصة Railway.

### المتغيرات البيئية المطلوبة

- `SESSION_SECRET` — مفتاح سري عشوائي (مطلوب)
- `DATA_DIR` — مسار Volume (مثلاً `/data`)
- `NODE_ENV` — اضبطها إلى `production`
- `PORT` — يُعيَّن تلقائياً بواسطة Railway

### التشغيل المحلي

```bash
npm install
cp .env.example .env
npm start
```

افتح: `http://localhost:3000`

---

## 📁 هيكل الملفات

```
├── server.js          ← السيرفر الرئيسي
├── package.json       ← معلومات المشروع
├── railway.json       ← إعدادات Railway
├── .gitignore         ← ملفات مستبعدة من Git
├── .env.example       ← نموذج الإعدادات
└── public/
    ├── index.html     ← الواجهة الرئيسية
    └── login.html     ← صفحة تسجيل الدخول
```

---

صُنع بـ ❤️ لتيسير عمل المعلمين

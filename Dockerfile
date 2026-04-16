FROM node:20-alpine

# تثبيت المكتبات المطلوبة لـ better-sqlite3
RUN apk add --no-cache python3 make g++

WORKDIR /app

# نسخ package files أولاً للاستفادة من cache
COPY package*.json ./

# تثبيت التبعيات (production فقط)
RUN npm install --production

# نسخ باقي ملفات المشروع
COPY . .

# إنشاء مجلد البيانات
RUN mkdir -p /data

# المنفذ الذي سيعمل عليه التطبيق داخل الحاوية
EXPOSE 3000

# متغير البيئة لمسار قاعدة البيانات
ENV DATA_DIR=/data
ENV NODE_ENV=production

# تشغيل التطبيق
CMD ["node", "server.js"]

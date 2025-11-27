# backend/Dockerfile
FROM python:3.11-slim

WORKDIR /app

# تثبيت المتطلبات
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# نسخ باقي الكود
COPY . /app

# بيئة متغيرة افتراضية (يمكن تعديلها عبر docker-compose)
ENV FLASK_APP=app.py
ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_ENV=production

# Expose port
EXPOSE 5000

# أمر التشغيل
CMD ["flask", "run", "--host=0.0.0.0", "--port=5000"]

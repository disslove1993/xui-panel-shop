#!/bin/bash

# =================================================================
# اسکریپت نصب خودکار پنل مدیریت X-UI
# =================================================================

# --- اطلاعات را اینجا ویرایش کنید ---
# آدرس کامل ریپازیتوری گیت‌هاب شما
GIT_REPO="https://github.com/fatemehbidel710-beep/x-ui.git"

# نام دامنه‌ای که می‌خواهید روی سرور تنظیم شود
DOMAIN_NAME="baharak.sbs"

# ایمیلی که برای دریافت گواهی SSL استفاده می‌شود
SSL_EMAIL="your_email@example.com"

# نام پروژه (نام پوشه‌ای که ساخته می‌شود)
PROJECT_NAME="xui_panel"

# مسیری که پروژه در آن نصب می‌شود
INSTALL_PATH="/var/www"
# ------------------------------------

# اطمینان از اینکه اسکریپت با دسترسی روت اجرا می‌شود
if [ "$EUID" -ne 0 ]; then
  echo "لطفاً این اسکریپت را با دسترسی روت (sudo) اجرا کنید."
  exit 1
fi

echo ">> شروع فرآیند نصب..."

# مرحله ۱: آپدیت سرور و نصب پیش‌نیازها
echo ">> ۱. آپدیت سرور و نصب پیش‌نیازها (nginx, python3, venv, certbot)..."
apt-get update
apt-get install -y nginx python3-pip python3-venv git certbot python3-certbot-nginx

# مرحله ۲: کلون کردن پروژه از گیت‌هاب
echo ">> ۲. دریافت پروژه از گیت‌هاب..."
cd $INSTALL_PATH
git clone $GIT_REPO $PROJECT_NAME
cd $PROJECT_NAME

# مرحله ۳: ساخت محیط مجازی پایتون و نصب پکیج‌ها
echo ">> ۳. ساخت محیط مجازی و نصب پکیج‌های پایتون..."
python3 -m venv venv
source venv/bin/activate
pip install wheel
pip install -r requirements.txt
deactivate

# مرحله ۴: ساخت سرویس Gunicorn با systemd
echo ">> ۴. ساخت سرویس Gunicorn برای اجرای خودکار برنامه..."
cat > /etc/systemd/system/${PROJECT_NAME}.service << EOF
[Unit]
Description=Gunicorn instance to serve ${PROJECT_NAME}
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=${INSTALL_PATH}/${PROJECT_NAME}
Environment="PATH=${INSTALL_PATH}/${PROJECT_NAME}/venv/bin"
ExecStart=${INSTALL_PATH}/${PROJECT_NAME}/venv/bin/gunicorn --workers 3 --bind unix:app.sock -m 007 wsgi:app

[Install]
WantedBy=multi-user.target
EOF

# مرحله ۵: ساخت کانفیگ Nginx
echo ">> ۵. ساخت کانفیگ Nginx برای دامنه ${DOMAIN_NAME}..."
cat > /etc/nginx/sites-available/${PROJECT_NAME} << EOF
server {
    listen 80;
    server_name ${DOMAIN_NAME} www.${DOMAIN_NAME};

    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen 443 ssl;
    server_name ${DOMAIN_NAME} www.${DOMAIN_NAME};

    # مسیر گواهی‌های SSL بعداً توسط Certbot تنظیم می‌شود
    # ssl_certificate ...
    # ssl_certificate_key ...

    location / {
        include proxy_params;
        proxy_pass http://unix:${INSTALL_PATH}/${PROJECT_NAME}/app.sock;
    }
}
EOF

# فعال‌سازی کانفیگ Nginx
ln -s /etc/nginx/sites-available/${PROJECT_NAME} /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# مرحله ۶: راه‌اندازی اولیه دیتابیس
echo ">> ۶. راه‌اندازی اولیه دیتابیس..."
cd ${INSTALL_PATH}/${PROJECT_NAME}
./venv/bin/python3 init_db.py

# تغییر مالکیت فایل‌ها به کاربر وب‌سرور
chown -R www-data:www-data ${INSTALL_PATH}/${PROJECT_NAME}

# مرحله ۷: فعال‌سازی و اجرای سرویس‌ها
echo ">> ۷. فعال‌سازی و اجرای سرویس‌های Gunicorn و Nginx..."
systemctl daemon-reload
systemctl start ${PROJECT_NAME}
systemctl enable ${PROJECT_NAME}
systemctl restart nginx

# مرحله ۸: دریافت گواهی SSL با Certbot
echo ">> ۸. دریافت گواهی SSL برای دامنه (ممکن است چند سوال پرسیده شود)..."
certbot --nginx -d ${DOMAIN_NAME} -d www.${DOMAIN_NAME} --non-interactive --agree-tos -m ${SSL_EMAIL}

# راه‌اندازی مجدد Nginx برای اعمال تنظیمات SSL
systemctl restart nginx

echo "======================================================"
echo ">> نصب با موفقیت به پایان رسید!"
echo ">> وب‌سایت شما روی آدرس https://${DOMAIN_NAME} در دسترس است."
echo ">> نام کاربری پیش‌فرض: admin"
echo ">> رمز عبور پیش‌فرض: admin"
echo "======================================================"
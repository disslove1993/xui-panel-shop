#!/bin/bash

# =================================================================
# Script Nasb Khodkar va Ta'amoli Panel Modiriat X-UI (Final Version)
# =================================================================

# --- Etela'at Sabet Proje ---
GIT_REPO="https://github.com/disslove1993/xui-panel-shop.git"
PROJECT_NAME="xui_panel"
INSTALL_PATH="/var/www"
# -------------------------

# Etminan az inke script ba dastresi root ejra mishavad
if [ "$EUID" -ne 0 ]; then
  echo "Lotfan in script ra ba dastresi root (sudo) ejra konid."
  exit 1
fi

# --- Marhale 1: Daryaft Etela'at az Karbar ---
echo "======================================================"
echo "MAHDI HAJI MOHAMMADI YAZDI!"
echo "Be script nasb panel khosh amadid!"
echo "Lotfan be soalat zir pasokh dahid:"
echo "======================================================"

read -p "Lotfan nam domain khod ra vared konid (mesalan: example.com): " DOMAIN_NAME
if [ -z "$DOMAIN_NAME" ]; then
    echo "Khata: Nam domain nemitavanad khali bashad."
    exit 1
fi

read -p "Lotfan email khod ra baraye daryaft gavahi SSL vared konid: " SSL_EMAIL
if [ -z "$SSL_EMAIL" ]; then
    echo "Khata: Email nemitavanad khali bashad."
    exit 1
fi

echo "======================================================"
echo ">> Nasb ba domain ${DOMAIN_NAME} va email ${SSL_EMAIL} shoroo mishavad..."
echo "======================================================"
sleep 3


# Marhale 2: Update Server va Nasb Pishniazha
echo ">> 1. Update server va nasb pishniazha..."
apt-get update
apt-get install -y nginx python3-pip python3-venv git certbot python3-certbot-nginx

# Marhale 3: Clone Kardan Proje az GitHub
echo ">> 2. Daryaft proje az GitHub..."
# (پاک کردن پوشه قدیمی در صورت وجود برای نصب مجدد تمیز)
rm -rf ${INSTALL_PATH}/${PROJECT_NAME}
cd $INSTALL_PATH || exit
git clone $GIT_REPO $PROJECT_NAME
cd $PROJECT_NAME || exit

# Marhale 4: Sakht Mohit Majazi Python va Nasb Package-ha
echo ">> 3. Sakht mohit majazi va nasb package-haye Python..."
python3 -m venv venv
source venv/bin/activate
pip install wheel
pip install -r requirements.txt
deactivate

# Marhale 5: Sakht Service Gunicorn ba systemd
echo ">> 4. Sakht service Gunicorn baraye ejraye khodkar barname..."
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

# Marhale 6: Sakht Config Nginx (نسخه اصلاح شده)
echo ">> 5. Sakht config sade Nginx baraye domain ${DOMAIN_NAME}..."
cat > /etc/nginx/sites-available/${PROJECT_NAME} << EOF
server {
    listen 80;
    server_name ${DOMAIN_NAME} www.${DOMAIN_NAME};

    location / {
        include proxy_params;
        proxy_pass http://unix:${INSTALL_PATH}/${PROJECT_NAME}/app.sock;
    }
}
EOF

# Fa'al sazi Config Nginx
# (پاک کردن لینک‌های قدیمی برای جلوگیری از تداخل)
rm -f /etc/nginx/sites-enabled/default
rm -f /etc/nginx/sites-enabled/${PROJECT_NAME}
ln -s /etc/nginx/sites-available/${PROJECT_NAME} /etc/nginx/sites-enabled/

# Marhale 7: Rah'andazi Avalie Database
echo ">> 6. Rah'andazi avalie database..."
cd ${INSTALL_PATH}/${PROJECT_NAME}
./venv/bin/python3 init_db.py

chown -R www-data:www-data ${INSTALL_PATH}/${PROJECT_NAME}

# Marhale 8: Fa'al sazi va Ejraye Service-ha
echo ">> 7. Fa'al sazi va ejraye service-haye Gunicorn va Nginx..."
systemctl daemon-reload
systemctl start ${PROJECT_NAME}
systemctl enable ${PROJECT_NAME}
systemctl restart nginx

# Marhale 9: Daryaft Gavahi SSL ba Certbot
echo ">> 8. Daryaft gavahi SSL va tanzim khodkar HTTPS..."
certbot --nginx -d ${DOMAIN_NAME} -d www.${DOMAIN_NAME} --non-interactive --agree-tos -m ${SSL_EMAIL} --redirect

# Rah'andazi mojadad Nginx baraye e'mal tanzimat SSL
systemctl restart nginx

echo "======================================================"
echo ">> Nasb ba movafaghiat be payan resid!"
echo ">> Website shoma rooye address https://${DOMAIN_NAME} dar dastres ast."
echo ">> Nam karbari pishfarz: admin"
echo ">> Ramz oboor pishfarz: admin"
echo "======================================================"

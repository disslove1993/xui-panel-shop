# app.py (نسخه نهایی با پشتیبانی کامل از Reality و CDN)
import os
import json
import uuid
import time
import bcrypt
import requests
import secrets
import urllib.parse
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

# --- پیکربندی مسیر مطلق ---
basedir = os.path.abspath(os.path.dirname(__file__))
instance_path = os.path.join(basedir, 'instance')

# --- راه‌اندازی اپلیکیشن و دیتابیس ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'a_very_secret_key_for_your_panel_change_this_later'
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(instance_path, 'panel_data.db')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
os.makedirs(instance_path, exist_ok=True)
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = "برای دسترسی به این صفحه، لطفاً وارد شوید."
login_manager.login_message_category = 'warning'

# --- توابع کمکی و فیلترها ---
@app.template_filter('timestamp_to_datetime')
def timestamp_to_datetime_filter(ts):
    if not ts or ts == 0: return "نامحدود"
    try: return datetime.fromtimestamp(ts / 1000).strftime('%Y-%m-%d')
    except (ValueError, TypeError): return "تاریخ نامعتبر"

def human_readable(num, suffix="B"):
    if num is None: num = 0
    for unit in ["", "K", "M", "G", "T", "P", "E", "Z"]:
        if abs(num) < 1024.0: return f"{num:3.1f} {unit}{suffix}"
        num /= 1024.0
    return f"{num:.1f} Y{suffix}"

# --- مدل‌های دیتابیس ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    wallet = db.Column(db.Float, nullable=False, default=0.0)
    role = db.Column(db.String(20), nullable=False, default='user')
    configs = db.relationship('Config', backref='owner', lazy=True, cascade="all, delete-orphan")
    transactions = db.relationship('Transaction', backref='user', lazy=True, cascade="all, delete-orphan")

class Config(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    inbound_id = db.Column(db.Integer, nullable=False)
    remark = db.Column(db.String(100), nullable=False)
    uuid = db.Column(db.String(100), unique=True, nullable=False)
    traffic_gb = db.Column(db.Integer, nullable=False)
    cost = db.Column(db.Float, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

class Setting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False)
    value = db.Column(db.String(200), nullable=True)

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    track_id = db.Column(db.String(100), unique=True, nullable=True)
    status = db.Column(db.String(50), nullable=False, default='pending')
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# --- توابع کمکی X-UI ---
def get_settings():
    return {setting.key: setting.value for setting in Setting.query.all()}

def login_to_xui(url=None, username=None, password=None):
    if not all([url, username, password]):
        settings = get_settings()
        url = settings.get('xui_panel_url')
        username = settings.get('xui_username')
        password = settings.get('xui_password')
    session = requests.Session()
    try:
        response = session.post(f"{url}/login", data={'username': username, 'password': password}, timeout=7, verify=False)
        response.raise_for_status()
        if "session" in response.cookies or "3x-ui" in response.cookies: return session, None
        return None, "نام کاربری یا رمز عبور پنل اشتباه است."
    except requests.exceptions.RequestException as e: return None, f"خطا در اتصال: {e}"
    except Exception as e: return None, f"خطای پیش‌بینی نشده: {e}"

def get_inbounds_list():
    session, error = login_to_xui()
    if error: print(f"Login Error: {error}"); return []
    settings = get_settings()
    try:
        response = session.get(f"{settings.get('xui_panel_url')}/panel/api/inbounds/list", timeout=5, verify=False)
        response.raise_for_status()
        return response.json().get("obj", [])
    except Exception as e: print(f"Error getting inbounds list: {e}"); return []

def get_all_clients():
    session, error = login_to_xui()
    if error: return {}
    try:
        inbounds = get_inbounds_list()
        all_clients = {}
        for inbound in inbounds:
            if 'clientStats' in inbound and inbound['clientStats']:
                for client in inbound['clientStats']:
                    all_clients[client['email']] = client
        return all_clients
    except Exception as e: print(f"Error getting all clients: {e}"); return {}

def add_client_to_xui(inbound_id, remark, traffic_gb, expire_days):
    session, error = login_to_xui()
    if error: return None, "خطا در اتصال به پنل X-UI"
    new_uuid = str(uuid.uuid4())
    total_gb_bytes = traffic_gb * 1024 * 1024 * 1024
    expire_millis = int((datetime.now() + timedelta(days=expire_days)).timestamp() * 1000) if expire_days > 0 else 0
    clients = [{"id": new_uuid, "email": remark, "totalGB": total_gb_bytes, "expiryTime": expire_millis, "enable": True, "subId": remark}]
    client_settings = json.dumps({"clients": clients})
    settings = get_settings()
    try:
        response = session.post(f"{settings.get('xui_panel_url')}/panel/api/inbounds/addClient", data={'id': inbound_id, 'settings': client_settings}, timeout=7, verify=False)
        response.raise_for_status()
        result = response.json()
        if result.get("success"): return new_uuid, None
        return None, result.get("msg", "خطای نامشخص از X-UI")
    except requests.exceptions.RequestException as e: return None, f"خطا در افزودن کلاینت: {e}"

def delete_client_from_xui(inbound_id, client_uuid):
    session, error = login_to_xui()
    if error: return False, "خطا در اتصال به پنل X-UI"
    settings = get_settings()
    try:
        response = session.post(f"{settings.get('xui_panel_url')}/panel/api/inbounds/{inbound_id}/delClient/{client_uuid}", timeout=5, verify=False)
        response.raise_for_status()
        return response.json().get("success", False), response.json().get("msg")
    except Exception as e: return False, str(e)

# --- تابع هوشمند ساخت لینک کانفیگ ---
def generate_config_link(config, inbound_data, panel_settings):
    try:
        protocol = inbound_data.get('protocol')
        if protocol != 'vless': return "پروتکل پشتیبانی نمی‌شود"

        remark = urllib.parse.quote(config.remark)
        stream_settings_raw = inbound_data.get('streamSettings', {})
        stream_settings = json.loads(stream_settings_raw) if isinstance(stream_settings_raw, str) else stream_settings_raw

        network = stream_settings.get('network')
        security = stream_settings.get('security')
        
        address = panel_settings.get('server_address')
        port = inbound_data.get('port')
        params = {'type': network, 'security': security}

        if network == 'xhttp':
            xhttp_settings = stream_settings.get('xhttpSettings', {})
            external_proxy = stream_settings.get('externalProxy', [{}])[0]
            address = external_proxy.get('dest', address)
            port = external_proxy.get('port', port)
            params['path'] = xhttp_settings.get('path')
            params['host'] = xhttp_settings.get('host')
        
        elif security == 'reality':
            reality_settings_raw = stream_settings.get('realitySettings', {})
            reality_settings = json.loads(reality_settings_raw) if isinstance(reality_settings_raw, str) else reality_settings_raw
            nested_settings = reality_settings.get('settings', {})
            
            params['sni'] = reality_settings.get('serverNames', [''])[0]
            params['fp'] = nested_settings.get('fingerprint', '')
            params['pbk'] = nested_settings.get('publicKey', '')
            params['sid'] = reality_settings.get('shortIds', [''])[0]
            params['spx'] = nested_settings.get('spiderX', '')
        
        elif security == 'tls':
            tls_settings = stream_settings.get('tlsSettings', {})
            params['sni'] = tls_settings.get('serverName')
            params['fp'] = tls_settings.get('fingerprint')

        if network == 'ws':
            ws_settings = stream_settings.get('wsSettings', {})
            params['path'] = ws_settings.get('path', '/')
            params['host'] = ws_settings.get('headers', {}).get('Host', '')
        elif network == 'grpc':
            grpc_settings = stream_settings.get('grpcSettings', {})
            params['serviceName'] = grpc_settings.get('serviceName')

        query_string = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None and v != ''})
        return f"vless://{config.uuid}@{address}:{port}?{query_string}#{remark}"
        
    except Exception as e:
        print(f"Error generating config link for remark {config.remark}: {e}")
        return "خطا در ساخت لینک"

# --- روت‌ها (صفحات وب) ---
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('admin_dashboard')) if current_user.role == 'admin' else redirect(url_for('user_dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('index'))
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form.get('username')).first()
        if user and bcrypt.checkpw(request.form.get('password').encode('utf-8'), user.password):
            login_user(user); return redirect(url_for('index'))
        else:
            flash("نام کاربری یا رمز عبور اشتباه است.", "danger")
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated: return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username')
        if User.query.filter_by(username=username).first():
            flash("این نام کاربری قبلاً ثبت شده است.", "warning"); return redirect(url_for('register'))
        hashed_password = bcrypt.hashpw(request.form.get('password').encode('utf-8'), bcrypt.gensalt())
        new_user = User(username=username, password=hashed_password, wallet=0.0)
        db.session.add(new_user); db.session.commit()
        flash("ثبت نام با موفقیت انجام شد. لطفاً وارد شوید.", "success")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user(); return redirect(url_for('login'))

# --- داشبورد کاربر ---
@app.route('/dashboard')
@login_required
def user_dashboard():
    if current_user.role == 'admin': return redirect(url_for('admin_dashboard'))
    
    settings = get_settings()
    transactions = Transaction.query.filter_by(user_id=current_user.id).order_by(Transaction.created_at.desc()).all()
    user_configs_db = Config.query.filter_by(user_id=current_user.id).all()
    
    inbounds_list = get_inbounds_list()
    inbounds_map = {inbound['id']: inbound for inbound in inbounds_list}
    
    all_xui_clients = get_all_clients()
    
    configs_list = []
    for config_db in user_configs_db:
        xui_data = all_xui_clients.get(config_db.remark)
        inbound_data = inbounds_map.get(config_db.inbound_id)
        
        if xui_data and inbound_data:
            config_db.config_link = generate_config_link(config_db, inbound_data, settings)
            sub_domain = settings.get('subscription_domain', settings.get('server_address'))
            config_db.sub_link = f"https://{sub_domain}/sub/{urllib.parse.quote(config_db.remark)}"

            config_db.up = xui_data.get('up', 0)
            config_db.down = xui_data.get('down', 0)
            config_db.total = xui_data.get('total', 0)
            config_db.expiryTime = xui_data.get('expiryTime', 0)
            configs_list.append(config_db)
            
    return render_template('dashboard.html',
                           configs=configs_list,
                           transactions=transactions,
                           inbounds=inbounds_list,
                           price_per_gb=settings.get('price_per_gb', 3000),
                           human_readable=human_readable)

@app.route('/create_config', methods=['POST'])
@login_required
def create_config():
    settings = get_settings()
    price_per_gb = float(settings.get('price_per_gb', 3000))
    try:
        inbound_id = int(request.form.get('inbound_id'))
        remark = request.form.get('remark')
        traffic_gb = int(request.form.get('traffic_gb'))
        expire_days = int(request.form.get('expire_days'))
    except (ValueError, TypeError):
        flash("اطلاعات وارد شده نامعتبر است.", "danger")
        return redirect(url_for('user_dashboard'))
    if Config.query.filter_by(remark=remark).first():
        flash("کانفیگی با این نام (remark) در کل سیستم وجود دارد. لطفاً نام دیگری انتخاب کنید.", "warning")
        return redirect(url_for('user_dashboard'))
    cost = traffic_gb * price_per_gb
    if current_user.wallet < cost:
        flash("موجودی کیف پول شما برای ساخت این کانفیگ کافی نیست.", "danger")
        return redirect(url_for('user_dashboard'))
    new_uuid, error = add_client_to_xui(inbound_id, remark, traffic_gb, expire_days)
    if error:
        flash(f"خطا در ساخت کانفیگ: {error}", "danger")
        return redirect(url_for('user_dashboard'))
    current_user.wallet -= cost
    new_config = Config(user_id=current_user.id, inbound_id=inbound_id, remark=remark, uuid=new_uuid, traffic_gb=traffic_gb, cost=cost)
    db.session.add(new_config)
    db.session.commit()
    flash(f"کانفیگ '{remark}' با موفقیت ساخته شد.", "success")
    return redirect(url_for('user_dashboard'))

@app.route('/delete_config/<int:config_id>', methods=['POST'])
@login_required
def delete_config(config_id):
    config = db.session.get(Config, config_id)
    if not config or config.user_id != current_user.id:
        flash("کانفیگ یافت نشد یا شما اجازه حذف آن را ندارید.", "danger")
        return redirect(url_for('user_dashboard'))
    success, msg = delete_client_from_xui(config.inbound_id, config.uuid)
    if success:
        db.session.delete(config)
        db.session.commit()
        flash(f"کانفیگ '{config.remark}' با موفقیت حذف شد.", "success")
    else:
        flash(f"خطا در حذف کانفیگ از پنل X-UI: {msg}", "danger")
        if msg and "client not found" in msg.lower():
             db.session.delete(config)
             db.session.commit()
             flash("کانفیگ از دیتابیس محلی نیز حذف شد.", "info")
    return redirect(url_for('user_dashboard'))

# --- درگاه پرداخت ---
ZIBAL_API_REQUEST = "https://gateway.zibal.ir/v1/request"
ZIBAL_API_VERIFY = "https://gateway.zibal.ir/v1/verify"
ZIBAL_GATEWAY_URL = "https://gateway.zibal.ir/start/{}"

@app.route('/create_payment', methods=['POST'])
@login_required
def create_payment():
    settings = get_settings()
    merchant_code = settings.get('zibal_merchant_code')
    if not merchant_code or merchant_code == 'zibal':
        flash("درگاه پرداخت پیکربندی نشده است. لطفاً با مدیر تماس بگیرید.", "danger")
        return redirect(url_for('user_dashboard'))
    try:
        amount = int(request.form.get('amount'))
        if amount < 10000:
            flash("مبلغ شارژ باید حداقل ۱۰,۰۰۰ ریال باشد.", "warning")
            return redirect(url_for('user_dashboard'))
    except (ValueError, TypeError):
        flash("مبلغ وارد شده نامعتبر است.", "danger")
        return redirect(url_for('user_dashboard'))
    payload = {"merchant": merchant_code, "amount": amount, "callbackUrl": url_for('verify_payment', _external=True), "description": f"شارژ کیف پول برای کاربر {current_user.username}"}
    try:
        response = requests.post(ZIBAL_API_REQUEST, json=payload, timeout=10)
        response.raise_for_status()
        result = response.json()
        if result.get("result") == 100 and result.get("trackId"):
            track_id = result.get("trackId")
            new_tx = Transaction(user_id=current_user.id, amount=amount, track_id=str(track_id), status='pending')
            db.session.add(new_tx)
            db.session.commit()
            return redirect(ZIBAL_GATEWAY_URL.format(track_id))
        else:
            flash(f"خطا در ایجاد تراکنش: {result.get('message', 'خطای نامشخص')}", "danger")
    except requests.exceptions.RequestException as e:
        flash(f"خطا در اتصال به درگاه پرداخت: {e}", "danger")
    return redirect(url_for('user_dashboard'))

@app.route('/verify_payment')
@login_required
def verify_payment():
    settings = get_settings()
    merchant_code = settings.get('zibal_merchant_code')
    track_id = request.args.get('trackId')
    success = request.args.get('success')
    if not track_id:
        flash("تراکنش نامعتبر است.", "danger")
        return redirect(url_for('user_dashboard'))
    tx = Transaction.query.filter_by(track_id=track_id, user_id=current_user.id).first()
    if not tx:
        flash("تراکنش یافت نشد.", "danger")
        return redirect(url_for('user_dashboard'))
    if tx.status == 'completed':
        flash("این تراکنش قبلاً با موفقیت تایید شده است.", "info")
        return redirect(url_for('user_dashboard'))
    if success != '1':
        tx.status = 'failed'
        db.session.commit()
        flash("پرداخت توسط شما لغو یا ناموفق بود.", "warning")
        return redirect(url_for('user_dashboard'))
    payload = {"merchant": merchant_code, "trackId": track_id}
    try:
        response = requests.post(ZIBAL_API_VERIFY, json=payload, timeout=10)
        response.raise_for_status()
        result = response.json()
        if result.get("result") == 100:
            user_to_charge = db.session.get(User, tx.user_id)
            if user_to_charge:
                user_to_charge.wallet += tx.amount
                tx.status = 'completed'
                db.session.commit()
                flash(f"پرداخت موفق! مبلغ {tx.amount:,.0f} ریال به کیف پول شما اضافه شد.", "success")
            else:
                tx.status = 'failed'; db.session.commit(); flash("خطا: کاربری برای شارژ کیف پول یافت نشد!", "danger")
        else:
            tx.status = 'failed'; db.session.commit(); flash(f"تایید پرداخت ناموفق بود: {result.get('message', 'خطای نامشخص')}", "danger")
    except requests.exceptions.RequestException as e:
        flash(f"خطا در ارتباط با سرور برای تایید پرداخت: {e}", "danger")
    return redirect(url_for('user_dashboard'))

# --- پنل ادمین ---
@app.route('/admin')
@login_required
def admin_dashboard():
    if current_user.role != 'admin': return redirect(url_for('user_dashboard'))
    stats = {
        "total_users": User.query.count(),
        "total_gb_sold": db.session.query(db.func.sum(Config.traffic_gb)).scalar() or 0,
        "total_income": db.session.query(db.func.sum(Config.cost)).scalar() or 0
    }
    return render_template('admin.html', users=User.query.all(), stats=stats)

@app.route('/admin/settings', methods=['GET', 'POST'])
@login_required
def admin_settings():
    if current_user.role != 'admin': return redirect(url_for('user_dashboard'))
    if request.method == 'POST':
        for key, value in request.form.items():
            if key.startswith('setting_'):
                setting_key = key.replace('setting_', '')
                setting = Setting.query.filter_by(key=setting_key).first()
                if setting: setting.value = value
        new_username = request.form.get('admin_username')
        new_password = request.form.get('admin_password')
        if new_username or new_password:
            admin_user = db.session.get(User, current_user.id)
            if new_username: admin_user.username = new_username
            if new_password: admin_user.password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        db.session.commit()
        flash("تنظیمات با موفقیت ذخیره شد.", "success")
        return redirect(url_for('admin_settings'))
    return render_template('admin_settings.html', settings=get_settings())

@app.route('/admin/test_xui_connection', methods=['POST'])
@login_required
def test_xui_connection():
    if current_user.role != 'admin': return jsonify({'success': False, 'message': 'دسترسی غیر مجاز'}), 403
    data = request.json
    url, username, password = data.get('url'), data.get('username'), data.get('password')
    if not all([url, username, password]):
        return jsonify({'success': False, 'message': 'لطفاً تمام فیلدهای مربوط به پنل را پر کنید.'})
    _, error = login_to_xui(url, username, password)
    if error: return jsonify({'success': False, 'message': str(error)})
    return jsonify({'success': True, 'message': 'اتصال به پنل X-UI با موفقیت برقرار شد.'})

@app.route('/admin/add_credit', methods=['POST'])
@login_required
def add_credit():
    if current_user.role != 'admin': return redirect(url_for('user_dashboard'))
    try:
        user_id = int(request.form.get('user_id'))
        amount = float(request.form.get('amount', 0))
        user = db.session.get(User, user_id)
        if user and amount > 0:
            user.wallet += amount
            db.session.commit()
            flash(f"مبلغ {amount:,.0f} ریال با موفقیت به کیف پول {user.username} اضافه شد.", "success")
    except (ValueError, TypeError):
        flash("مقدار وارد شده برای مبلغ نامعتبر است.", "danger")
    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    print("برنامه در حالت توسعه در حال اجراست...")
    app.run(host='0.0.0.0', port=5001, debug=True)
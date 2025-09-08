from app import app, db, User, Setting, bcrypt

# تنظیمات پیش‌فرض که می‌خواهید در دیتابیس ذخیره شوند
default_settings = {
    'xui_panel_url': 'http://127.0.0.1:2083',
    'xui_username': 'admin',
    'xui_password': 'admin',
    'server_address': 'yourdomain.com',
    'subscription_domain': 'sub.yourdomain.com',
    'price_per_gb': '3000',
    'zibal_merchant_code': 'zibal'
}

# استفاده از app_context برای دسترسی به اپلیکیشن و دیتابیس
with app.app_context():
    print("شروع فرآیند راه‌اندازی دیتابیس...")

    # ۱. ساخت تمام جداول
    db.create_all()
    print("جداول با موفقیت ساخته شدند.")

    # ۲. اضافه کردن تنظیمات پیش‌فرض
    for key, value in default_settings.items():
        if not Setting.query.filter_by(key=key).first():
            db.session.add(Setting(key=key, value=value))
            print(f"تنظیم '{key}' اضافه شد.")

    # ۳. ساخت کاربر ادمین
    if not User.query.filter_by(username='admin').first():
        hashed_password = bcrypt.hashpw('admin'.encode('utf-8'), bcrypt.gensalt())
        admin_user = User(username='admin', password=hashed_password, role='admin', wallet=0.0)
        db.session.add(admin_user)
        print("کاربر 'admin' با موفقیت ساخته شد.")

    # ۴. ذخیره تمام تغییرات
    db.session.commit()
    print("تغییرات با موفقیت در دیتابیس ذخیره شد.")
    print("راه‌اندازی اولیه دیتابیس به پایان رسید.")
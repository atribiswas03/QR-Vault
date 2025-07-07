# app.py — QR Vault Web App

from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, jsonify
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId
from bson import ObjectId
from bson.errors import InvalidId
from cryptography.fernet import Fernet
from dotenv import load_dotenv
import qrcode
import io
import os
import random
import smtplib
import logging
from email.message import EmailMessage
from datetime import datetime, timedelta
from qr_utils import encrypt_data, decrypt_data, generate_qr_code, decode_qr_code
from pyzbar.pyzbar import decode
from PIL import Image
import mimetypes
import string    
from uuid import uuid4
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from werkzeug.security import check_password_hash


otp_store = {}   # email: otp
otp_expiry = {}  # email: expiry_timestamp

# Load environment variables
load_dotenv()

# Flask app setup
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY") or os.urandom(24)
app.config["MONGO_URI"] = os.getenv("MONGO_URI")
app.permanent_session_lifetime = timedelta(minutes=20)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=True if os.getenv("FLASK_ENV") == "production" else False
)
mongo = PyMongo(app)

ALLOW_MULTIPLE_SESSIONS = False
# OTP utilities

def generate_otp(length=6):
    chars = string.ascii_uppercase + string.digits  # A-Z and 0-9
    return ''.join(random.choices(chars, k=length))


def send_email(to, subject, body):
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = os.getenv("EMAIL_HOST")
    msg['To'] = to
    msg.set_content(body)

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(os.getenv("EMAIL_HOST"), os.getenv("EMAIL_PASSWORD"))
            smtp.send_message(msg)
            print(f"✅ Email sent to {to}")
    except Exception as e:
        print(f"❌ Failed to send email: {e}")


def send_email_otp(recipient, otp, purpose='register'):
    if purpose == 'register':
        title = "QR Vault OTP Verification"
        greeting = "To complete your registration"
        message = "Please enter the OTP below to continue."
        subject = '🛡️ QR Vault Email OTP Verification'
        color = "#0AC6A3"
    elif purpose == 'reset':
        title = "QR Vault Password Reset Verification"
        greeting = "You requested a password reset"
        message = "Enter the OTP below to reset your password."
        subject = '🔑 QR Vault Password Reset OTP'
        color = "#FFA500"
    elif purpose == 'admin_login':
        title = "QR Vault Admin Login Verification"
        greeting = "You are attempting to login as Admin"
        message = "Use the OTP below to verify your identity and continue."
        subject = '👨‍💼 QR Vault Admin Login OTP'
        color = "#FF5733"
    else:
        title = "QR Vault Login Verification"
        greeting = "To complete your login"
        message = "Please enter the OTP below to continue."
        subject = '🔐 QR Vault Login OTP Verification'
        color = "#0AC6A3"

    html_content = f"""
    <html>
      <body style="font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 40px;">
        <div style="max-width: 500px; margin: auto; background: #ffffff; border-radius: 10px; padding: 30px; box-shadow: 0 5px 20px rgba(0,0,0,0.1);">
          <div style="text-align: center;">
            <img src="https://lh3.googleusercontent.com/d/1BRH4us8fka2YVX7pqUm627riLZ8daVuc" width='70' alt='QR Vault Logo'>
            <h2 style="color: #333; margin-top: 10px;">{title}</h2>
          </div>
          <p style="color: #555;">Hello,</p>
          <p style="color: #555;">{greeting} on <strong>QR Vault</strong>. {message}</p>
          <div style="background: {color}; color: white; font-size: 28px; font-weight: bold; text-align: center; padding: 15px; border-radius: 8px; margin: 20px 0;">
            {otp}
          </div>
          <p style="color: #555;">This OTP is valid for <strong>1 minute</strong>. Do not share it with anyone.</p>
          <p style="color: #999; font-size: 12px; text-align: center; margin-top: 40px;">
            &copy; 2025 QR Vault. All rights reserved. <br>
            Designed by <a href="https://www.linkedin.com/in/atri-biswas" style="color:{color};">Atri Biswas</a>
          </p>
        </div>
      </body>
    </html>
    """

    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = os.getenv("EMAIL_HOST")
    msg['To'] = recipient
    msg.set_content(f"Your QR Vault OTP is: {otp}\nValid for 1 minute.")
    msg.add_alternative(html_content, subtype='html')

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(os.getenv("EMAIL_HOST"), os.getenv("EMAIL_PASSWORD"))
            smtp.send_message(msg)
            print(f"✅ {purpose.capitalize()} OTP email sent.")
    except Exception as e:
        print(f"❌ Email sending failed during {purpose}: {e}")


def set_user_session(user_id, email, is_admin=False):
    session_token = str(uuid4())
    session.clear()
    session['session_token'] = session_token
    session['email'] = email
    session['is_admin'] = is_admin

    if is_admin:
        admin = mongo.db.admins.find_one({'_id': ObjectId(user_id)})
        session['username'] = admin.get('username', 'Admin')
        session['admin_id'] = str(user_id)
        session['is_mother_admin'] = admin.get('is_mother_admin', False)
    else:
        user = mongo.db.users.find_one({'_id': ObjectId(user_id)})
        session['username'] = user.get('username', 'User')
        session['user_id'] = str(user_id)

    # Save session token to DB
    target_collection = mongo.db.admins if is_admin else mongo.db.users
    target_collection.update_one(
        {'_id': ObjectId(user_id)},
        {'$set': {'session_token': session_token}}
    )


def validate_session(role='user'):
    key = 'admin_id' if role == 'admin' else 'user_id'
    if key not in session or 'session_token' not in session:
        return False

    target_collection = mongo.db.admins if role == 'admin' else mongo.db.users
    user = target_collection.find_one({'_id': ObjectId(session[key])})

    if not user or 'session_token' not in user:
        return False

    if not ALLOW_MULTIPLE_SESSIONS and user['session_token'] != session['session_token']:
        print(f"⚠️ Session mismatch for {role}. Logging out.")
        return False

    return True


def send_styled_email(to_email, subject, html_content):
    from_email = os.getenv("EMAIL_HOST")
    password = os.getenv("EMAIL_PASSWORD")

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = from_email
    msg["To"] = to_email

    html_part = MIMEText(html_content, "html")
    msg.attach(html_part)

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(from_email, password)
        server.sendmail(from_email, to_email, msg.as_string())
        server.quit()
        print(f"✅ Email sent to {to_email}")
    except Exception as e:
        print(f"❌ Failed to send email: {e}")
        
        
def generate_and_send_otp(email):

    otp = str(random.randint(100000, 999999))

    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <title>OTP Verification</title>
      <link href="https://fonts.googleapis.com/css2?family=Roboto&display=swap" rel="stylesheet">
    </head>
    <body style="margin:0;padding:0;background-color:#f4f4f4;font-family:'Roboto',sans-serif;">
      <table width="100%" cellpadding="0" cellspacing="0">
        <tr>
          <td align="center">
            <table width="500" cellpadding="0" cellspacing="0" style="margin:40px auto;background-color:#ffffff;border-radius:10px;box-shadow:0 5px 15px rgba(0,0,0,0.1);">
              <tr>
                <td style="padding:30px 40px;text-align:center;">
                  <img src="https://lh3.googleusercontent.com/d/1BRH4us8fka2YVX7pqUm627riLZ8daVuc" alt="QR Vault" style="height:50px;margin-bottom:20px;" />
                  <h2 style="color:#2c3e50;margin-bottom:10px;">🔐 Password Reset OTP</h2>
                  <p style="color:#666;font-size:16px;margin:0 0 20px;">
                    Hello, here is your one-time password (OTP) to reset your password:
                  </p>
                  <div style="font-size:28px;letter-spacing:5px;color:#222;font-weight:bold;background:#f1f1f1;padding:15px 0;border-radius:8px;margin:20px 0;">
                    {otp}
                  </div>
                  <p style="color:#999;font-size:14px;margin:10px 0 20px;">
                    This OTP is valid for the next <strong>2 minutes</strong>. Please do not share it with anyone.
                  </p>
                  <a href="#" style="display:inline-block;margin-top:10px;padding:10px 20px;background-color:#4CAF50;color:#fff;border-radius:5px;text-decoration:none;font-weight:bold;">Reset Password</a>
                  <hr style="margin:30px 0;border:none;border-top:1px solid #eee;">
                  <p style="font-size:13px;color:#999;">If you didn’t request a password reset, you can safely ignore this email.<br><br>— QR Vault Security Team</p>
                </td>
              </tr>
            </table>
          </td>
        </tr>
      </table>
    </body>
    </html>
    """

    send_styled_email(email, "🔐 Your QR Vault Password Reset OTP", html_content)
    return otp


# ==================== Routes ====================
@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('home.html')


@app.route('/send_otp', methods=['POST'])
def send_otp():
    email = request.form.get('email')
    purpose = request.form.get('purpose') or 'register'

    if not email:
        return jsonify({"status": "error", "message": "Email required"}), 400

    otp = generate_otp()
    session['otp'] = otp
    session['otp_email'] = email
    session['otp_expiry'] = (datetime.utcnow() + timedelta(minutes=1)).isoformat()

    send_email_otp(email, otp, purpose)
    return jsonify({"status": "success", "message": "OTP sent successfully."})


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        country_code = request.form['country_code']
        phonenum = request.form['phonenum']
        full_phone = f"{country_code}{phonenum}"
        otp_input = request.form['otp']

        if mongo.db.users.find_one({'email': email}) or mongo.db.admins.find_one({'email': email}):
            flash("⚠️ Email is already registered.")
            return redirect(url_for('register'))

        if 'otp' not in session or session.get('otp_email') != email or datetime.utcnow() > datetime.fromisoformat(session.get('otp_expiry')):
            flash("OTP expired or not sent.")
            return redirect(url_for('register'))

        if session.get('otp') != otp_input:
            flash("Incorrect OTP.")
            return redirect(url_for('register'))

        hash_pass = generate_password_hash(password)
        user_id = mongo.db.users.insert_one({
            'username': username,
            'email': email,
            'password': hash_pass,
            'phone': full_phone
        }).inserted_id

        session.pop('otp', None)
        session.pop('otp_email', None)
        session.pop('otp_expiry', None)

        session['user_id'] = str(user_id)
        session['username'] = username
        session['email'] = email

        flash("✅ Registered and verified!")
        return redirect(url_for('dashboard'))

    return render_template('register.html')


@app.route('/check_email', methods=['POST'])
def check_email():
    email = request.form.get('email')
    if not email:
        return jsonify({"status": "error", "message": "Email is required"}), 400

    if mongo.db.users.find_one({'email': email}) or mongo.db.admins.find_one({'email': email}):
        return jsonify({"status": "exists", "message": "Email already registered"}), 409

    return jsonify({"status": "available"}), 200


@app.route('/validate_credentials', methods=['POST'])
def validate_credentials():
    email = request.form.get('email')
    password = request.form.get('password')

    if not email or not password:
        return jsonify({
            "status": "error",
            "message": "Both email and password are required."
        }), 400

    # Check admin
    admin = mongo.db.admins.find_one({'email': email})
    if admin:
        if check_password_hash(admin['password'], password):
            return jsonify({"status": "success", "role": "admin"}), 200
        else:
            return jsonify({
                "status": "error",
                "message": "Incorrect password for admin."
            }), 403

    # Check user
    user = mongo.db.users.find_one({'email': email})
    if user:
        if check_password_hash(user['password'], password):
            return jsonify({"status": "success", "role": "user"}), 200
        else:
            return jsonify({
                "status": "error",
                "message": "Incorrect password."
            }), 403

    # Not registered
    return jsonify({
        "status": "not_found",
        "message": "No account found with this email. Please register."
    }), 404


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        otp_input = request.form.get('otp')
        local_time = request.form.get('local_login_time')
        time_zone = request.form.get('time_zone')
        
        # Step 1: Lookup user/admin by email
        admin = mongo.db.admins.find_one({'email': email})
        user = mongo.db.users.find_one({'email': email})
        account = admin if admin else user

        # Step 2: Email not found
        if not account:
            flash("❌ No account found with this email. Please register first.")
            return redirect(url_for('register'))

        # Step 3: Password mismatch
        if not check_password_hash(account['password'], password):
            flash("❌ Invalid password. Please try again.")
            return redirect(url_for('login'))

        # Step 4: OTP expired, not sent, or email mismatch
        otp = session.get('otp')
        otp_email = session.get('otp_email')
        otp_expiry = session.get('otp_expiry')

        if not otp or not otp_email or otp_email != email:
            flash("⚠️ OTP not sent or mismatched.")
            return redirect(url_for('login'))

        if datetime.utcnow() > datetime.fromisoformat(otp_expiry):
            flash("⚠️ OTP has expired.")
            return redirect(url_for('login'))

        if otp != otp_input:
            flash("❌ Incorrect OTP.")
            return redirect(url_for('login'))

        # Step 5: OTP verified → Clear OTP session
        session.pop('otp', None)
        session.pop('otp_email', None)
        session.pop('otp_expiry', None)

        # Step 6: Update last login time
        if admin:
            mongo.db.admins.update_one({'_id': admin['_id']}, {'$set': {'last_login': local_time, 'time_zone': time_zone}})
            set_user_session(admin['_id'], admin['email'], is_admin=True)
            return redirect(url_for('admin_dashboard'))
        else:
            mongo.db.users.update_one({'_id': user['_id']}, {'$set': {'last_login': local_time, 'time_zone': time_zone}})
            set_user_session(user['_id'], user['email'], is_admin=False)
            return redirect(url_for('dashboard'))

    return render_template('login.html')


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session or not validate_session('user'):
        return redirect(url_for('logout'))

    entries = mongo.db.entries.find({'email': session['email']}).sort("created_at", -1)
    decoded_text = session.pop('decoded_text', None)
    decode_warning = session.pop('decode_warning', None)
    return render_template('dashboard.html',
                           entries=entries,
                           username=session.get('username', 'User'),
                           decoded_text=decoded_text,
                           decode_warning=decode_warning)


@app.route('/generate_qr', methods=['POST'])
def generate_qr():
    if 'email' not in session:
        return redirect(url_for('login'))

    secret_text = request.form.get('secret', '').strip()
    uploaded_file = request.files.get('file')
    key = Fernet.generate_key()

    # Validate input
    if not secret_text and not uploaded_file:
        flash("⚠️ Please provide text or upload a file.", "error")
        return redirect(url_for('dashboard'))

    if uploaded_file and uploaded_file.filename != '':
        # Read and encrypt file content
        file_data = uploaded_file.read()
        if not file_data:
            flash("⚠️ Uploaded file is empty.", "error")
            return redirect(url_for('dashboard'))
        encrypted = encrypt_data(file_data, key)
        storage_type = 'file'
    else:
        # Encrypt text
        encrypted = encrypt_data(secret_text, key)
        storage_type = 'text'

    # Store in database
    timestamp = datetime.now()
    entry_id = mongo.db.entries.insert_one({
        'email': session['email'],
        'user_id': ObjectId(session['user_id']),   # ✅ Add this line
        'token': encrypted,
        'key': key,
        'type': storage_type,
        'filename': uploaded_file.filename if uploaded_file else None,
        'created_at': timestamp
    }).inserted_id


    # Generate and return QR
    qr_buf = generate_qr_code(str(entry_id))
    return send_file(qr_buf, mimetype='image/png', as_attachment=True, download_name="qr_code.png")


@app.route('/admin_dashboard')
def admin_dashboard():
    if not session.get('is_admin') or not validate_session('admin'):
        return redirect(url_for('logout'))

    users = list(mongo.db.users.find())
    entries = list(mongo.db.entries.find())
    admins = list(mongo.db.admins.find())

    # 🔄 Convert 'created_at' or 'last_login' string to datetime for entries
    for entry in entries:
        if 'created_at' in entry and isinstance(entry['created_at'], str):
            try:
                entry['created_at'] = datetime.strptime(entry['created_at'], '%d/%m/%Y, %I:%M %p')
            except Exception as e:
                print("⚠️ Error parsing created_at in entry:", e)

    # 🔄 Same for users (if last_login is stored as string)
    for user in users:
        if 'last_login' in user and isinstance(user['last_login'], str):
            try:
                user['last_login'] = datetime.strptime(user['last_login'], '%d/%m/%Y, %I:%M %p')
            except Exception as e:
                print("⚠️ Error parsing last_login in user:", e)

    return render_template('admin_panel.html', users=users, entries=entries, admins=admins)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))


@app.route('/decode_qr', methods=['POST'])
def decode_qr():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    qr_file = request.files.get('qr_file')
    if not qr_file:
        session['decode_warning'] = "No QR file provided."
        return redirect(url_for('dashboard'))

    try:
        from pyzbar.pyzbar import decode
        from PIL import Image
        import mimetypes

        img = Image.open(qr_file.stream).convert("RGB")
        decoded = decode(img)

        if not decoded:
            session['decode_warning'] = "Invalid or unreadable QR code."
            return redirect(url_for('dashboard'))

        entry_id = decoded[0].data
        if isinstance(entry_id, bytes):
            entry_id = entry_id.decode('utf-8')

        entry = mongo.db.entries.find_one({'_id': ObjectId(entry_id)})

        if not entry:
            session['decode_warning'] = "No data found for the decoded QR."
            return redirect(url_for('dashboard'))

        # ✅ Ownership validation
        if str(entry.get('user_id')) != session.get('user_id'):
            session['decode_warning'] = "This QR code does not belong to your account."
            return redirect(url_for('dashboard'))

        decrypted_data = decrypt_data(entry['token'], entry['key'], as_text=False)

        if entry['type'] == 'file':
            mime_type, _ = mimetypes.guess_type(entry['filename'])
            return send_file(
                io.BytesIO(decrypted_data),
                as_attachment=True,
                download_name=entry['filename'],
                mimetype=mime_type or "application/octet-stream"
            )
        else:
            session['decoded_text'] = decrypted_data.decode('utf-8')
            return redirect(url_for('dashboard'))

    except Exception as e:
        session['decode_warning'] = f"Error decoding QR: {str(e)}"
        return redirect(url_for('dashboard'))


@app.route('/terms')
def terms():
    return render_template('terms.html')


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')

        # First, check in users collection
        user = mongo.db.users.find_one({'email': email})
        role = 'user'

        # If not found in users, check admins
        if not user:
            user = mongo.db.admins.find_one({'email': email})
            role = 'admin'

        if not user:
            return jsonify({'status': 'not_found', 'message': 'Email not registered'})

        otp = generate_otp()
        session['reset_otp'] = otp
        session['reset_email'] = email
        session['reset_otp_expiry'] = (datetime.utcnow() + timedelta(minutes=1)).isoformat()

        # Pass correct purpose based on role
        send_email_otp(email, otp, purpose='reset')

        return jsonify({
            'status': 'otp_sent',
            'message': 'OTP sent to your email',
            'trigger_modal': True,
            'role': role
        })

    return render_template('forgot_password.html')


@app.route('/verify-forgot-otp', methods=['POST'])
def verify_forgot_otp():
    otp_input = request.form.get('otp')
    email = request.form.get('email')

    print("🔐 Debug - Input OTP:", otp_input)
    print("🔐 Debug - Session OTP:", session.get('reset_otp'))
    print("📧 Debug - Input Email:", email)
    print("📧 Debug - Session Email:", session.get('reset_email'))
    print("⏳ Debug - OTP Expiry:", session.get('reset_otp_expiry'))

    if (
        session.get('reset_otp') == otp_input and
        session.get('reset_email') == email and
        datetime.utcnow() < datetime.fromisoformat(session.get('reset_otp_expiry'))
    ):
        return jsonify({'status': 'success'})
    else:
        return jsonify({'status': 'fail'})


@app.route('/reset-password', methods=['POST'])
def reset_password():
    new_pass = request.form.get('new_password')      
    confirm_pass = request.form.get('confirm_password')

    if new_pass != confirm_pass:
        return jsonify({'status': 'mismatch'})

    email = session.get('reset_email')
    if not email:
        return jsonify({'status': 'error', 'message': 'Session expired. Try again.'})

    hashed = generate_password_hash(new_pass)
    if mongo.db.users.find_one({'email': email}):
        mongo.db.users.update_one({'email': email}, {'$set': {'password': hashed}})
    else:
        mongo.db.admins.update_one({'email': email}, {'$set': {'password': hashed}})


    send_confirmation_email(email)

    session.pop('reset_otp', None)
    session.pop('reset_email', None)
    session.pop('reset_otp_expiry', None)

    return redirect(url_for('home'))


def send_confirmation_email(email):
    html_content = f"""
    <html>
      <body style="font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 30px;">
        <div style="max-width: 600px; margin: auto; background-color: #ffffff; padding: 25px; border-radius: 8px; box-shadow: 0 5px 15px rgba(0,0,0,0.1);">
          <div style="text-align: center;">
            <img src="https://lh3.googleusercontent.com/d/1BRH4us8fka2YVX7pqUm627riLZ8daVuc" width="60" alt="QR Vault Logo" />
            <h2 style="color: #0AC6A3; margin-top: 20px;">Password Reset Successful</h2>
          </div>
          <p style="color: #333;">Hello,</p>
          <p style="color: #555;">
            This is to inform you that your <strong>QR Vault</strong> account password was successfully changed.
          </p>
          <p style="color: #555;">
            If you did not initiate this change, please contact our support team immediately.
          </p>
          <div style="margin-top: 30px; text-align: center;">
            <a href="https://your-domain.com" style="background-color: #0AC6A3; color: #fff; padding: 10px 20px; border-radius: 5px; text-decoration: none;">Visit QR Vault</a>
          </div>
          <p style="color: #999; font-size: 12px; margin-top: 40px; text-align: center;">
            &copy; 2025 QR Vault. All rights reserved.
          </p>
        </div>
      </body>
    </html>
    """

    msg = EmailMessage()
    msg['Subject'] = '🔐 QR Vault Password Reset Confirmation'
    msg['From'] = os.getenv("EMAIL_HOST")
    msg['To'] = email
    msg.set_content("Your QR Vault password was reset successfully. If this wasn't you, please contact support.")
    msg.add_alternative(html_content, subtype='html')

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(os.getenv("EMAIL_HOST"), os.getenv("EMAIL_PASSWORD"))
            smtp.send_message(msg)
            print("✅ Password reset confirmation email sent.")
    except Exception as e:
        print("❌ Failed to send password reset email:", e)


@app.route('/download_qr/<entry_id>')
def download_qr(entry_id):
    from bson.objectid import ObjectId
    entry = mongo.db.entries.find_one({'_id': ObjectId(entry_id)})
    if not entry:
        flash("QR Entry not found.")
        return redirect(url_for('dashboard'))

    buf = generate_qr_code(str(entry['_id']))  # regenerate QR from ID
    return send_file(buf, mimetype='image/png', as_attachment=True, download_name=f"QR_{entry_id}.png")


@app.route('/delete_qr/<id>', methods=['DELETE'])
def delete_qr(id):
    if 'user_id' not in session:
        return jsonify({'status': 'unauthorized'}), 401

    try:
        object_id = ObjectId(id)
    except InvalidId:
        return jsonify({'status': 'invalid_id'})

    print("🧾 Attempting delete:", object_id, "for user:", session['email'])

    result = mongo.db.entries.delete_one({'_id': object_id, 'email': session['email']})

    if result.deleted_count == 1:
        print("✅ Deleted successfully")
        return jsonify({'status': 'success'})
    else:
        print("❌ Nothing deleted: possibly wrong email or id")
        return jsonify({'status': 'fail'})


@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        message = request.form.get('message')
        local_time = request.form.get('local_time')
        time_zone = request.form.get('time_zone')

        print("Received Time:", local_time)
        print("Received Time Zone:", time_zone)

        # Store in DB as usual
        mongo.db.contacts.insert_one({
            'name': name,
            'email': email,
            'message': message,
            'local_time': local_time,
            'time_zone': time_zone,
            'solved': False
        })

        flash("✅ Thank you! Your message was sent successfully.", "success")
        return redirect(url_for('contact'))

    return render_template('contact.html')


@app.route('/send_custom_email', methods=['POST'])
def send_custom_email():
    email = request.form.get('email')
    subject = request.form.get('subject')
    content = request.form.get('content')

    if not email or not subject or not content:
        flash("❌ All fields are required.")
        return redirect(url_for('admin_dashboard'))

    try:
        send_email(
            to=email,
            subject=subject,
            body=content
        )
        flash(f"✅ Email sent successfully to {email}.")
    except Exception as e:
        flash(f"❌ Failed to send email: {str(e)}")

    return redirect(url_for('admin_dashboard'))


@app.after_request
def secure_headers(response):
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response


@app.route('/manage-admins', methods=['GET', 'POST'])
def manage_admins():
    if not session.get('is_admin') or not validate_session('admin'):
        return redirect(url_for('logout'))

    current_admin = mongo.db.admins.find_one({'_id': ObjectId(session['admin_id'])})
    if not current_admin.get('is_mother_admin'):
        flash("❌ Unauthorized access.")
        return redirect(url_for('admin_dashboard'))

    admins = list(mongo.db.admins.find())
    return render_template('manage_admins.html', admins=admins)


@app.route('/request-admin-otp', methods=['POST'])
def request_admin_otp():
    try:
        # Get JSON data from fetch body
        data = request.get_json()
        email = data.get('email')
        re_email = data.get('re_email')

        # Basic validation
        if not email or not re_email:
            return jsonify({"success": False, "message": "⚠️ Both fields are required."})
        if email != re_email:
            return jsonify({"success": False, "message": "⚠️ Emails do not match."})
        if mongo.db.admins.find_one({'email': email}):
            return jsonify({"success": False, "message": "⚠️ This email is already an admin."})
        if mongo.db.users.find_one({'email': email}):
            return jsonify({"success": False, "message": "⚠️ This email belongs to a normal user."})

        # Generate OTP
        otp = str(random.randint(100000, 999999))
        session['admin_otp'] = otp
        session['admin_otp_email'] = email
        session['admin_otp_expiry'] = (datetime.utcnow() + timedelta(minutes=2)).isoformat()

        # HTML email with animation
        otp_email_html = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <style>
            @keyframes fadeSlideIn {{
              0% {{ opacity: 0; transform: translateY(-20px); }}
              100% {{ opacity: 1; transform: translateY(0); }}
            }}
            @keyframes pulse {{
              0% {{ box-shadow: 0 0 0 0 rgba(37, 99, 235, 0.7); }}
              70% {{ box-shadow: 0 0 0 10px rgba(37, 99, 235, 0); }}
              100% {{ box-shadow: 0 0 0 0 rgba(37, 99, 235, 0); }}
            }}
            body {{
              font-family: 'Segoe UI', sans-serif;
              background-color: #f9fafb;
              padding: 20px;
            }}
            .container {{
              max-width: 600px;
              margin: auto;
              background: #ffffff;
              border-radius: 10px;
              box-shadow: 0 8px 20px rgba(0, 0, 0, 0.1);
              animation: fadeSlideIn 0.8s ease forwards;
            }}
            .header {{
              background: linear-gradient(90deg, #2563eb, #1d4ed8);
              color: white;
              padding: 20px;
              border-radius: 10px 10px 0 0;
              text-align: center;
            }}
            .header h1 {{
              margin: 0;
              font-size: 24px;
            }}
            .body {{
              padding: 30px;
              text-align: center;
            }}
            .otp {{
              display: inline-block;
              font-size: 28px;
              letter-spacing: 10px;
              font-weight: bold;
              background: #f0f4ff;
              color: #1e40af;
              padding: 10px 20px;
              border-radius: 8px;
              margin-top: 20px;
              animation: pulse 1.5s infinite;
            }}
            .footer {{
              text-align: center;
              font-size: 12px;
              color: #888;
              padding: 10px 20px 20px;
            }}
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>🔐 QR Vault Admin OTP</h1>
            </div>
            <div class="body">
              <p>Hello,</p>
              <p>We received a request to add this email as an <strong>Admin</strong> for <strong>QR Vault</strong>.</p>
              <p>Please use the following OTP to proceed:</p>
              <div class="otp">{otp}</div>
              <p>This OTP is valid for <strong>2 minutes</strong>.</p>
            </div>
            <div class="footer">
              <p>© {datetime.utcnow().year} QR Vault. All rights reserved.</p>
            </div>
          </div>
        </body>
        </html>
        """

        # Send the email
        send_html_email(
            email,
            subject="QR Vault Admin OTP",
            html_content=otp_email_html
        )

        return jsonify({"success": True, "message": "✅ OTP sent successfully."})

    except Exception as e:
        print("❌ ERROR while sending admin OTP:", str(e))
        return jsonify({"success": False, "message": f"❌ Server error: {str(e)}"})


def send_html_email(to_email, subject, html_content):
    from_email = os.getenv("EMAIL_HOST")
    password = os.getenv("EMAIL_PASSWORD")
    smtp_server = "smtp.gmail.com"
    smtp_port = 587

    if not from_email or not password:
        print("❌ EMAIL_HOST or EMAIL_PASSWORD is not set in .env")
        return

    try:
        # Create the email content
        message = MIMEMultipart("alternative")
        message["Subject"] = subject
        message["From"] = from_email
        message["To"] = to_email

        html_part = MIMEText(html_content, "html")
        message.attach(html_part)

        # Send the email
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(from_email, password)
            server.sendmail(from_email, to_email, message.as_string())

        print(f"✅ HTML email sent to {to_email}")

    except Exception as e:
        print(f"❌ Error sending HTML email: {str(e)}")
        
         
@app.route('/verify-admin-otp', methods=['POST'])
def verify_admin_otp():
    otp_input = request.form.get('otp')
    stored_otp = session.get('admin_otp')
    email = session.get('admin_otp_email')
    expiry = session.get('admin_otp_expiry')

    if not stored_otp or not email or not expiry:
        flash("⚠️ Session expired or invalid.")
        return redirect(url_for('admin_dashboard'))

    if datetime.utcnow() > datetime.fromisoformat(expiry):
        flash("⏰ OTP expired. Please request a new one.")
        return redirect(url_for('admin_dashboard'))

    if otp_input != stored_otp:
        if session.get('admin_otp_attempts', 0) >= 1:
            flash("❌ Incorrect OTP entered twice. Try again later.")
            session.pop('admin_otp', None)
            session.pop('admin_otp_email', None)
            session.pop('admin_otp_expiry', None)
            return redirect(url_for('admin_dashboard'))
        else:
            session['admin_otp_attempts'] = session.get('admin_otp_attempts', 0) + 1
            flash("⚠️ Incorrect OTP. One last attempt remaining.")
            return redirect(url_for('admin_dashboard'))

    # OTP correct
    mongo.db.admins.insert_one({
    "username": "admin",
    "email": email,
    "role": "admin",
    "is_mother_admin": False
})


    # Clear OTP session
    session.pop('admin_otp', None)
    session.pop('admin_otp_email', None)
    session.pop('admin_otp_expiry', None)
    session.pop('admin_otp_attempts', None)

    flash("✅ Admin added successfully.")
    return redirect(url_for('admin_dashboard'))


@app.route('/delete-admin', methods=['POST'])
def delete_admin():
    email = request.form.get('email')
    if email and email != "atribiswas2003@gmail.com":
        mongo.db.admins.delete_one({'email': email})
        flash(f"✅ Admin {email} deleted.")
    return redirect(url_for('admin_dashboard'))


@app.route('/make-mother-admin', methods=['POST'])
def make_mother_admin():
    email = request.form.get('email')
    if email:
        # Set is_mother_admin = true for this email
        mongo.db.admins.update_one({'email': email}, {'$set': {'is_mother_admin': True}})
        flash(f"✅ {email} promoted to Mother Admin.")
    return redirect(url_for('admin_dashboard'))


@app.route('/remove-mother-admin', methods=['POST'])
def remove_mother_admin():
    email = request.form.get('email')
    if email != "atribiswas2003@gmail.com":  # safeguard
        mongo.db.admins.update_one({'email': email}, {'$set': {'is_mother_admin': False}})
        flash(f"⚠️ {email} is no longer a Mother Admin.")
    else:
        flash("⚠️ Cannot remove default mother admin.")
    return redirect(url_for('admin_dashboard'))


@app.route('/contact-reports')
def contact_reports():
    if 'email' not in session:
        return redirect(url_for('login'))

    admin = mongo.db.admins.find_one({'email': session['email']})
    if not admin or not admin.get('is_mother_admin'):
        return redirect(url_for('admin_dashboard'))  # or return a 403 page

    reports = list(mongo.db.contacts.find().sort("timestamp", -1))
    return render_template('contact_reports.html', reports=reports)


@app.route('/mark_contact_solved/<report_id>', methods=['POST'])
def mark_contact_solved(report_id):
    if not session.get('is_admin'):
        return redirect(url_for('logout'))

    mongo.db.contacts.update_one(
        {'_id': ObjectId(report_id)},
        {'$set': {'solved': True}}
    )
    flash("✅ Marked as solved.", "success")
    return redirect(url_for('contact_reports'))


@app.route('/get_profile_data')
def get_profile_data():
    try:
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({'error': 'Unauthorized access'}), 401

        user = mongo.db.users.find_one({'_id': ObjectId(user_id)})
        if not user:
            return jsonify({'error': 'User not found'}), 404

        return jsonify({
            'username': user.get('username', ''),
            'email': user.get('email', ''),
            'phone': user.get('phone', ''),
            'country_code': user.get('country_code', '+91')
        }), 200
    except Exception as e:
        logging.error(f"[GET PROFILE ERROR] {str(e)}")
        return jsonify({'error': 'Server error'}), 500

 
@app.route('/send_password_otp', methods=['POST'])
def send_password_otp():
    try:
        data = request.get_json()
        email = data.get('email')
        new_password = data.get('new_password', '').strip()

        if not email:
            return jsonify({'status': 'error', 'message': 'Email not provided.'}), 400

        user = mongo.db.users.find_one({'email': email})
        if not user:
            return jsonify({'status': 'error', 'message': 'User not found.'}), 404

        if not new_password:
            return jsonify({'status': 'error', 'message': 'Password not provided.'}), 400

        if check_password_hash(user.get('password', ''), new_password):
            return jsonify({'status': 'error', 'message': '⚠️ New password cannot be the same as the old password.'}), 400

        otp = generate_and_send_otp(email)
        if not otp:
            return jsonify({'status': 'error', 'message': '❌ Failed to send OTP. Please try again later.'}), 500

        session['password_otp'] = otp
        session['otp_email'] = email
        session['otp_expiry'] = (datetime.utcnow() + timedelta(minutes=2)).isoformat()
        otp_store[email] = otp
        otp_expiry[email] = datetime.now() + timedelta(minutes=2)
        return jsonify({'status': 'success'})
    except Exception as e:
        app.logger.error(f"Error in /send_password_otp: {e}")
        return jsonify({'status': 'error', 'message': '❌ Internal server error.'}), 500


@app.route('/update_profile', methods=['POST'])
def update_profile():
    try:
        user_id = session.get('user_id')
        if not user_id:
            flash("⚠️ Session expired. Please log in again.")
            return redirect(url_for('login'))

        # Get form fields
        username = request.form.get('username', '').strip()
        phone = request.form.get('phone', '').strip()
        country_code = request.form.get('country_code', '').strip()
        new_password = request.form.get('new_password', '').strip()
        otp = request.form.get('password_otp', '').strip()

        # Input validation
        if not username or not phone or not country_code:
            flash("⚠️ All fields are required.")
            return redirect(url_for('dashboard'))

        # Combine full phone number with country code
        full_phone = f"{country_code}{phone}"

        update_fields = {
            'username': username,
            'phone': full_phone,
            'country_code': country_code  # optional, kept for UI separation
        }

        # Get user info from DB
        user = mongo.db.users.find_one({'_id': ObjectId(user_id)})
        if not user:
            flash("❌ User not found.")
            return redirect(url_for('dashboard'))

        user_email = user['email']

        # Handle password update
        if new_password:
            # Prevent reusing previous password
            if check_password_hash(user.get('password', ''), new_password):
                flash("⚠️ New password cannot be the same as the old password.")
                return redirect(url_for('dashboard'))

            stored_otp = session.get('password_otp')
            otp_expiry = session.get('otp_expiry')

            if not stored_otp or not otp or otp != stored_otp or not otp_expiry or datetime.utcnow() > datetime.fromisoformat(otp_expiry):
                flash("❌ Invalid or expired OTP for password change.")
                return redirect(url_for('dashboard'))

            update_fields['password'] = generate_password_hash(new_password)

            # Send styled confirmation email
            html_content = f"""
            <div style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto;background:#f9f9f9;padding:20px;border-radius:10px;">
              <h2 style="color:#4CAF50;">🔒 Password Updated Successfully</h2>
              <p style="color:#333;">Hello {user['username']},</p>
              <p style="color:#555;">
                We wanted to let you know that your password was recently updated for your QR Vault account.
                If you didn’t make this change, please contact our support immediately.
              </p>
              <p style="margin-top:20px;font-size:14px;color:#888;">Time: {datetime.now().strftime('%d %b %Y, %I:%M %p')}</p>
              <p style="margin-top:10px;font-size:14px;color:#888;">Location: {request.remote_addr}</p>
              <hr style="border:none;border-top:1px solid #eee;margin:20px 0;">
              <p style="font-size:14px;color:#aaa;">Regards,<br>QR Vault Team</p>
            </div>
            """
            send_styled_email(user_email, "🔐 Your QR Vault Password Was Changed", html_content)

        # Update user info
        mongo.db.users.update_one({'_id': ObjectId(user_id)}, {'$set': update_fields})

        # Clear OTP from session after use
        session.pop('password_otp', None)
        session.pop('otp_expiry', None)

        flash("✅ Profile updated successfully. Please re-login to see changes.")
        return redirect(url_for('dashboard'))

    except Exception as e:
        logging.error(f"[UPDATE PROFILE ERROR] {str(e)}")
        flash("❌ Something went wrong while updating your profile.")
        return redirect(url_for('dashboard'))


@app.route('/check_same_password', methods=['POST'])
def check_same_password():
    try:
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({'error': 'Unauthorized'}), 401

        data = request.get_json()
        new_password = data.get('new_password')

        user = mongo.db.users.find_one({'_id': ObjectId(user_id)})
        if not user:
            return jsonify({'error': 'User not found'}), 404

        current_password_hash = user.get('password', '')
        is_same = check_password_hash(current_password_hash, new_password)
        return jsonify({'same': is_same})
    except Exception as e:
        print(f"[CHECK PASSWORD ERROR] {e}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route("/verify_password_otp", methods=["POST"])
def verify_password_otp():
    data = request.get_json()
    email = data.get("email")
    otp = data.get("otp")

    if not email or not otp:
        return jsonify({"success": False, "message": "Missing email or OTP"}), 400

    stored_otp = otp_store.get(email)
    expiry = otp_expiry.get(email)

    if not stored_otp or not expiry:
        return jsonify({"success": False, "message": "OTP not sent or expired"}), 400

    if datetime.now() > expiry:
        return jsonify({"success": False, "message": "OTP expired"}), 400

    if otp != stored_otp:
        return jsonify({"success": False, "message": "Incorrect OTP"}), 400

    return jsonify({"success": True})


if __name__ == '__main__':
    app.run(debug=True)
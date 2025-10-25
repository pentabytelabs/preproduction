import os
import sqlite3
import secrets
from datetime import datetime, timedelta
from threading import Thread
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth
from smtplib import SMTPAuthenticationError, SMTPException
from dotenv import load_dotenv

# -----------------------------
# App setup
# -----------------------------
app = Flask(__name__)
load_dotenv()

app.secret_key = os.getenv("SECRET_KEY", secrets.token_hex(16))
DB_PATH = "auth.db"

# -----------------------------
# Mail configuration
# -----------------------------
app.config.update(
    MAIL_SERVER=os.getenv('MAIL_SERVER', 'smtp.gmail.com'),
    MAIL_PORT=int(os.getenv('MAIL_PORT', 587)),
    MAIL_USE_TLS=os.getenv('MAIL_USE_TLS', 'True') == 'True',
    MAIL_USE_SSL=os.getenv('MAIL_USE_SSL', 'False') == 'True',
    MAIL_USERNAME=os.getenv('MAIL_USERNAME'),
    MAIL_PASSWORD=os.getenv('MAIL_PASSWORD'),
    MAIL_DEFAULT_SENDER=os.getenv('MAIL_DEFAULT_SENDER', os.getenv('MAIL_USERNAME'))
)
mail = Mail(app)

# -----------------------------
# Async mail helpers
# -----------------------------
def _send_async(app, msg):
    with app.app_context():
        mail.send(msg)

def send_email_async(subject, recipients, body):
    msg = Message(subject, recipients=recipients)
    msg.body = body
    thr = Thread(target=_send_async, args=(app, msg), daemon=True)
    thr.start()
    return thr

def try_send_email(subject, recipients, body):
    msg = Message(subject, recipients=recipients)
    msg.body = body
    try:
        mail.send(msg)
        return True, None
    except SMTPAuthenticationError as e:
        app.logger.error(f"SMTPAuthenticationError: {e}")
        return False, f"SMTPAuthenticationError: {e}"
    except SMTPException as e:
        app.logger.error(f"SMTPException: {e}")
        return False, f"SMTPException: {e}"
    except Exception as e:
        app.logger.exception("Unexpected error sending email")
        return False, str(e)

# -----------------------------
# Database helpers
# -----------------------------
def get_user_by_email(email):
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE email=?", (email,))
        return c.fetchone()

def create_user(username, email, password_hash=''):
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        try:
            now = datetime.utcnow().isoformat()
            c.execute("""INSERT INTO users (username, email, password, created_at, updated_at)
                         VALUES (?, ?, ?, ?, ?)""",
                      (username, email, password_hash, now, now))
            conn.commit()
            return c.lastrowid
        except sqlite3.IntegrityError:
            raise

def login_user(user_id, username):
    session['user_id'] = user_id
    session['username'] = username

def logout_user():
    session.clear()

# -----------------------------
# OAuth configuration
# -----------------------------
oauth = OAuth(app)

# Google OAuth (fixed OpenID config)
app.config['GOOGLE_CLIENT_ID'] = os.getenv('GOOGLE_CLIENT_ID')
app.config['GOOGLE_CLIENT_SECRET'] = os.getenv('GOOGLE_CLIENT_SECRET')

google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

# LinkedIn OAuth
app.config['LINKEDIN_CLIENT_ID'] = os.getenv('LINKEDIN_CLIENT_ID')
app.config['LINKEDIN_CLIENT_SECRET'] = os.getenv('LINKEDIN_CLIENT_SECRET')

linkedin = oauth.register(
    name='linkedin',
    client_id=app.config['LINKEDIN_CLIENT_ID'],
    client_secret=app.config['LINKEDIN_CLIENT_SECRET'],
    access_token_url='https://www.linkedin.com/oauth/v2/accessToken',
    authorize_url='https://www.linkedin.com/oauth/v2/authorization',
    client_kwargs={'scope': 'r_liteprofile r_emailaddress'}
)

# -----------------------------
# UI ROUTES
# -----------------------------
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip().lower()
        password = request.form['password']
        try:
            create_user(username, email, generate_password_hash(password))
        except sqlite3.IntegrityError:
            flash("Email or username already exists", "danger")
            return render_template('signup.html')
        flash("Signup successful! Please log in.", "success")
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']
        user = get_user_by_email(email)
        if not user or not check_password_hash(user[3], password):
            flash("Invalid email or password", "danger")
            return render_template('login.html')
        login_user(user[0], user[1])
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash("Please log in first", "warning")
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session['username'])

@app.route('/logout')
def logout():
    logout_user()
    flash("Logged out successfully.", "success")
    return redirect(url_for('login'))

@app.route('/forgotpass', methods=['GET', 'POST'])
def forgotpass():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        user = get_user_by_email(email)
        if not user:
            flash("No account found with that email", "danger")
            return render_template('forgotpass.html')
        otp = f"{secrets.randbelow(1000000):06d}"
        expiry = (datetime.utcnow() + timedelta(seconds=60)).isoformat()
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute("UPDATE users SET otp=?, otp_expiry=?, updated_at=? WHERE email=?",
                      (otp, expiry, datetime.utcnow().isoformat(), email))
            conn.commit()
        send_email_async("Password Reset OTP", [email], f"Your OTP is {otp}. It expires in 60 seconds.")
        flash("OTP sent to your email (check inbox).", "info")
        return redirect(url_for('resetpass'))
    return render_template('forgotpass.html')

@app.route('/resetpass', methods=['GET', 'POST'])
def resetpass():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        otp = request.form['otp'].strip()
        new_pass = request.form['new_password']
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute("SELECT otp, otp_expiry FROM users WHERE email=?", (email,))
            record = c.fetchone()
            if not record or record[0] != otp:
                flash("Invalid OTP", "danger")
                return render_template('resetpass.html')
            try:
                expiry = datetime.fromisoformat(record[1])
            except:
                expiry = datetime.utcnow() - timedelta(seconds=1)
            if datetime.utcnow() > expiry:
                c.execute("UPDATE users SET otp=NULL, otp_expiry=NULL WHERE email=?", (email,))
                conn.commit()
                flash("OTP expired", "danger")
                return render_template('resetpass.html')
            hashed = generate_password_hash(new_pass)
            c.execute("UPDATE users SET password=?, otp=NULL, otp_expiry=NULL, updated_at=? WHERE email=?",
                      (hashed, datetime.utcnow().isoformat(), email))
            conn.commit()
        flash("Password reset successful!", "success")
        return redirect(url_for('login'))
    return render_template('resetpass.html')

# -----------------------------
# API ROUTES
# -----------------------------
@app.route('/api/forgot', methods=['POST'])
def api_forgot():
    data = request.json
    email = data.get('email', '').strip().lower()
    user = get_user_by_email(email)
    if not user:
        return jsonify({'error': 'No account found with that email'}), 404

    otp = f"{secrets.randbelow(1000000):06d}"
    expiry = (datetime.utcnow() + timedelta(seconds=60)).isoformat()
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("UPDATE users SET otp=?, otp_expiry=?, updated_at=? WHERE email=?",
                  (otp, expiry, datetime.utcnow().isoformat(), email))
        conn.commit()
    send_email_async("Your OTP for Password Reset", [email],
                     f"Your OTP is {otp}. It expires in 60 seconds.")
    return jsonify({'message': 'OTP sent to your email', 'expiry': 60}), 200

@app.route('/api/resend-otp', methods=['POST'])
def api_resend_otp():
    data = request.json
    email = data.get('email', '').strip().lower()
    user = get_user_by_email(email)
    if not user:
        return jsonify({'error': 'No account found with that email'}), 404
    otp = f"{secrets.randbelow(1000000):06d}"
    expiry = (datetime.utcnow() + timedelta(seconds=60)).isoformat()
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("UPDATE users SET otp=?, otp_expiry=?, updated_at=? WHERE email=?",
                  (otp, expiry, datetime.utcnow().isoformat(), email))
        conn.commit()
    send_email_async("Resent OTP", [email],
                     f"Your new OTP is {otp}. It expires in 60 seconds.")
    return jsonify({'message': 'New OTP sent', 'expiry': 60}), 200

@app.route('/api/reset', methods=['POST'])
def api_reset():
    data = request.json
    email = data.get('email', '').strip().lower()
    otp = data.get('otp', '').strip()
    new_pass = data.get('new_password', '')
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("SELECT otp, otp_expiry FROM users WHERE email=?", (email,))
        record = c.fetchone()
        if not record or record[0] != otp:
            return jsonify({'error': 'Invalid OTP'}), 400
        try:
            expiry = datetime.fromisoformat(record[1])
        except:
            expiry = datetime.utcnow() - timedelta(seconds=1)
        if datetime.utcnow() > expiry:
            c.execute("UPDATE users SET otp=NULL, otp_expiry=NULL WHERE email=?", (email,))
            conn.commit()
            return jsonify({'error': 'OTP expired'}), 400
        hashed = generate_password_hash(new_pass)
        c.execute("UPDATE users SET password=?, otp=NULL, otp_expiry=NULL, updated_at=? WHERE email=?",
                  (hashed, datetime.utcnow().isoformat(), email))
        conn.commit()
    return jsonify({'message': 'Password reset successful'}), 200

# -----------------------------
# OAuth routes
# -----------------------------
@app.route('/login/google')
def login_google():
    nonce = secrets.token_urlsafe(16)
    session['nonce'] = nonce
    redirect_uri = url_for('authorize_google', _external=True)
    return google.authorize_redirect(redirect_uri, nonce=nonce)


@app.route('/authorize/google')
def authorize_google():
    token = google.authorize_access_token()
    nonce = session.pop('nonce', None)
    user_info = google.parse_id_token(token, nonce=nonce)

    email = user_info['email']
    name = user_info.get('name', email.split('@')[0])

    if not get_user_by_email(email):
        create_user(name, email)
    user = get_user_by_email(email)
    login_user(user[0], user[1])
    flash("Logged in via Google!", "success")
    return redirect(url_for('dashboard'))

@app.route('/login/linkedin')
def login_linkedin():
    redirect_uri = os.getenv("LINKEDIN_REDIRECT_URI", url_for('authorize_linkedin', _external=True))
    return linkedin.authorize_redirect(redirect_uri)


@app.route('/authorize/linkedin')
def authorize_linkedin():
    token = linkedin.authorize_access_token()
    user_info = linkedin.get('me').json()
    email_resp = linkedin.get('emailAddress?q=members&projection=(elements*(handle~))').json()
    email = email_resp.get('elements', [{}])[0].get('handle~', {}).get('emailAddress')
    if not email:
        flash("Unable to retrieve LinkedIn email", "danger")
        return redirect(url_for('login'))
    name = f"{user_info.get('localizedFirstName', '')} {user_info.get('localizedLastName', '')}".strip() or "LinkedIn User"
    if not get_user_by_email(email):
        create_user(name, email)
    user = get_user_by_email(email)
    login_user(user[0], user[1])
    flash("Logged in via LinkedIn!", "success")
    return redirect(url_for('dashboard'))

# -----------------------------
# Entry point
# -----------------------------
if __name__ == "__main__":
    app.run(debug=True)
from flask import Flask, render_template, redirect, url_for, session, request, flash, jsonify
import sqlite3, secrets, os
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth
from flask_mail import Mail, Message
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", secrets.token_hex(16))
DB_PATH = "auth.db"

# ----------------- OAUTH CONFIG -----------------
oauth = OAuth(app)
app.config.update({
    'GOOGLE_CLIENT_ID': os.getenv('GOOGLE_CLIENT_ID', 'YOUR_GOOGLE_CLIENT_ID'),
    'GOOGLE_CLIENT_SECRET': os.getenv('GOOGLE_CLIENT_SECRET', 'YOUR_GOOGLE_CLIENT_SECRET'),
    'LINKEDIN_CLIENT_ID': os.getenv('LINKEDIN_CLIENT_ID', 'YOUR_LINKEDIN_CLIENT_ID'),
    'LINKEDIN_CLIENT_SECRET': os.getenv('LINKEDIN_CLIENT_SECRET', 'YOUR_LINKEDIN_CLIENT_SECRET'),
})
# top of app.py (near other imports)
from dotenv import load_dotenv
load_dotenv()

# mail config (use envs; convert strings to booleans/ints)
app.config.update(
    MAIL_SERVER=os.getenv('MAIL_SERVER', 'smtp.gmail.com'),
    MAIL_PORT=int(os.getenv('MAIL_PORT', 587)),
    MAIL_USE_TLS=os.getenv('MAIL_USE_TLS', 'True') == 'True',
    MAIL_USE_SSL=os.getenv('MAIL_USE_SSL', 'False') == 'True',
    MAIL_USERNAME=os.getenv('MAIL_USERNAME'),   # must be Gmail address
    MAIL_PASSWORD=os.getenv('MAIL_PASSWORD'),   # app password w/o spaces
    MAIL_DEFAULT_SENDER=os.getenv('MAIL_DEFAULT_SENDER', os.getenv('MAIL_USERNAME'))
)

# remove debug prints of sensitive info in production; show only username/server for debug
print("MAIL_USERNAME:", app.config.get('MAIL_USERNAME'))
print("MAIL_SERVER:", app.config.get('MAIL_SERVER'))
print("MAIL_PORT:", app.config.get('MAIL_PORT'))
print("MAIL_USE_TLS:", app.config.get('MAIL_USE_TLS'))
print("MAIL_USE_SSL:", app.config.get('MAIL_USE_SSL'))
print("MAIL_PASSWORD set:", bool(app.config.get('MAIL_PASSWORD')))

mail = Mail(app)
from threading import Thread
from smtplib import SMTPAuthenticationError, SMTPException

def _send_async(app, msg):
    with app.app_context():
        mail.send(msg)

def send_email_async(subject, recipients, body):
    msg = Message(subject, recipients=recipients)
    msg.body = body
    thr = Thread(target=_send_async, args=(app, msg), daemon=True)
    thr.start()
    return thr

# blocking send with detailed error for debug
def try_send_email(subject, recipients, body):
    msg = Message(subject, recipients=recipients)
    msg.body = body
    try:
        mail.send(msg)            # blocking so we can capture error in API response
        return True, None
    except SMTPAuthenticationError as e:
        app.logger.error("SMTPAuthenticationError: %s", e)
        return False, f"SMTPAuthenticationError: {e}"
    except SMTPException as e:
        app.logger.error("SMTPException: %s", e)
        return False, f"SMTPException: {e}"
    except Exception as e:
        app.logger.exception("Unexpected error sending email")
        return False, f"Unexpected error: {e}"

    
google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    access_token_url='https://oauth2.googleapis.com/token',
    authorize_url='https://accounts.google.com/o/oauth2/v2/auth',
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={'scope': 'openid email profile'},
)

linkedin = oauth.register(
    name='linkedin',
    client_id=app.config['LINKEDIN_CLIENT_ID'],
    client_secret=app.config['LINKEDIN_CLIENT_SECRET'],
    access_token_url='https://www.linkedin.com/oauth/v2/accessToken',
    authorize_url='https://www.linkedin.com/oauth/v2/authorization',
    api_base_url='https://api.linkedin.com/v2/',
    client_kwargs={'scope': 'r_liteprofile r_emailaddress'},
)

# ----------------- DB HELPERS -----------------
def get_user_by_email(email):
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("SELECT id, username, email, password FROM users WHERE email=?", (email,))
        return c.fetchone()

def create_user(username, email, password_hash=''):
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", (username, email, password_hash))
            conn.commit()
            return c.lastrowid
        except sqlite3.IntegrityError as e:
            raise


# ----------------- COMMON FUNCTIONS -----------------
def login_user(user_id, username):
    session['user_id'] = user_id
    session['username'] = username

def logout_user():
    session.clear()

# ----------------- UI ROUTES -----------------
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    email = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '')
    user = get_user_by_email(email)

    if not user or not check_password_hash(user[3], password):
        flash('Invalid credentials', 'danger')
        return render_template('login.html')

    login_user(user[0], user[1])
    flash('Login successful', 'success')
    return redirect(url_for('dashboard'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'GET':
        return render_template('signup.html')

    username = request.form.get('username')
    email = request.form.get('email').lower()
    password = request.form.get('password')
    if get_user_by_email(email):
        flash('Email already exists', 'danger')
        return render_template('signup.html')

    create_user(username, email, generate_password_hash(password))
    flash('Signup successful! Please log in.', 'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session['username'])

@app.route('/logout')
def logout():
    logout_user()
    flash('Logged out successfully!', 'info')
    return redirect(url_for('login'))

# ----------------- OAUTH ROUTES -----------------
@app.route('/login/google')
def login_google():
    redirect_uri = url_for('authorize_google', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/authorize/google')
def authorize_google():
    token = google.authorize_access_token()
    user_info = google.get('userinfo').json()
    email = user_info.get('email')
    name = user_info.get('name', email.split('@')[0])

    if not get_user_by_email(email):
        create_user(name, email)

    login_user(email, name)
    flash('Logged in with Google!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/login/linkedin')
def login_linkedin():
    redirect_uri = url_for('authorize_linkedin', _external=True)
    return linkedin.authorize_redirect(redirect_uri)

@app.route('/authorize/linkedin')
def authorize_linkedin():
    token = linkedin.authorize_access_token()
    profile = linkedin.get('me?projection=(id,localizedFirstName,localizedLastName)').json()
    email_resp = linkedin.get('emailAddress?q=members&projection=(elements*(handle~))').json()
    email = email_resp['elements'][0]['handle~']['emailAddress']
    name = f"{profile.get('localizedFirstName', '')} {profile.get('localizedLastName', '')}".strip()

    if not get_user_by_email(email):
        create_user(name, email)

    login_user(email, name)
    flash('Logged in with LinkedIn!', 'success')
    return redirect(url_for('dashboard'))

# ----------------- API ROUTES (JSON endpoints) -----------------
# ---------------------- API ENDPOINTS ----------------------

@app.route('/api/signup', methods=['POST'])
def api_signup():
    data = request.json
    username = data.get('username', '').strip()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')

    if not username or not email or not password:
        return jsonify({'error': 'Missing required fields'}), 400

    if get_user_by_email(email):
        return jsonify({'error': 'Email already exists'}), 409

    hashed = generate_password_hash(password)
    create_user(username, email, hashed)
    return jsonify({'message': 'User created successfully'}), 201


@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.json
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')

    user = get_user_by_email(email)
    if not user or not check_password_hash(user[3], password):
        return jsonify({'error': 'Invalid credentials'}), 401

    session['user_id'] = user[0]
    session['username'] = user[1]
    return jsonify({'message': 'Login successful', 'username': user[1]}), 200


@app.route('/api/profile', methods=['GET'])
def api_profile():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    return jsonify({'user_id': session['user_id'], 'username': session['username']}), 200


@app.route('/api/logout', methods=['POST'])
def api_logout():
    session.clear()
    return jsonify({'message': 'Logged out successfully'}), 200

@app.route('/test-email')
def test_email():
    try:
        msg = Message("Test Email from Flask", recipients=["recipient@example.com"])
        msg.body = "Hello — this is a test email from Flask-Mail."
        mail.send(msg)
        return "Email sent"
    except Exception as e:
        return f"Error: {e}", 500
OTP_RESEND_COOLDOWN = 30  # seconds - don't allow resend while previous OTP still valid

@app.route('/api/forgot', methods=['POST'])
def api_forgot():
    data = request.json
    email = data.get('email', '').strip().lower()
    user = get_user_by_email(email)
    if not user:
        return jsonify({'error': 'No account found with that email'}), 404

    otp = f"{secrets.randbelow(1000000):06d}"
    expiry_dt = datetime.utcnow() + timedelta(seconds=60)
    expiry_iso = expiry_dt.isoformat()

    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("UPDATE users SET otp=?, otp_expiry=? WHERE email=?", (otp, expiry_iso, email))
        conn.commit()

    subject = "Your OTP for Password Reset"
    body = f"Your OTP is {otp}. It will expire in 60 seconds."

    ok, err = try_send_email(subject, [email], body)
    if not ok:
        return jsonify({'error': 'Failed to send OTP', 'detail': err}), 500

    return jsonify({'message': 'OTP sent to your email', 'expiry': 60}), 200


@app.route('/api/resend-otp', methods=['POST'])
def api_resend_otp():
    data = request.json
    email = data.get('email', '').strip().lower()
    user = get_user_by_email(email)
    if not user:
        return jsonify({'error': 'No account with that email'}), 404

    # check existing expiry to avoid frequent resends
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("SELECT otp_expiry FROM users WHERE email=?", (email,))
        row = c.fetchone()
        existing_expiry = row[0] if row else None

    if existing_expiry:
        try:
            existing_dt = datetime.fromisoformat(existing_expiry)
            seconds_left = (existing_dt - datetime.utcnow()).total_seconds()
            if seconds_left > 0 and seconds_left > (60 - OTP_RESEND_COOLDOWN):
                # still recently issued: deny resend, tell user to wait
                return jsonify({'error': 'OTP recently sent. Please wait', 'wait_seconds': int(seconds_left)}), 429
        except Exception:
            # if parse fails, allow new OTP
            pass

    otp = f"{secrets.randbelow(1000000):06d}"
    expiry_dt = datetime.utcnow() + timedelta(seconds=60)
    expiry_iso = expiry_dt.isoformat()

    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("UPDATE users SET otp=?, otp_expiry=? WHERE email=?", (otp, expiry_iso, email))
        conn.commit()

    subject = "Resent OTP"
    body = f"Your new OTP is {otp}. It will expire in 60 seconds."

    ok, err = try_send_email(subject, [email], body)
    if not ok:
        return jsonify({'error': 'Failed to send OTP', 'detail': err}), 500

    return jsonify({'message': 'New OTP sent', 'expiry': 60}), 200


@app.route('/api/reset', methods=['POST'])
def api_reset():
    data = request.json
    email = data.get('email', '').strip().lower()
    otp = data.get('otp', '').strip()
    new_password = data.get('new_password', '')

    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("SELECT otp, otp_expiry FROM users WHERE email=?", (email,))
        record = c.fetchone()

        if not record or not record[0] or record[0] != otp:
            return jsonify({'error': 'Invalid OTP'}), 400

        otp_expiry = record[1]
        if not otp_expiry:
            return jsonify({'error': 'OTP not found / expired'}), 400

        try:
            expiry_dt = datetime.fromisoformat(otp_expiry)
        except Exception:
            # always safe-fail to expired if parsing fails
            expiry_dt = datetime.utcnow() - timedelta(seconds=1)

        if datetime.utcnow() > expiry_dt:
            # expired — clear OTP immediately
            c.execute("UPDATE users SET otp=NULL, otp_expiry=NULL WHERE email=?", (email,))
            conn.commit()
            return jsonify({'error': 'OTP expired'}), 400

        # valid -> update password and clear otp
        hashed = generate_password_hash(new_password)
        c.execute("UPDATE users SET password=?, otp=NULL, otp_expiry=NULL WHERE email=?", (hashed, email))
        conn.commit()

    return jsonify({'message': 'Password reset successful'}), 200


# ----------------- PASSWORD RESET (UI DEMO) -----------------
@app.route('/forgotpass', methods=['GET', 'POST'])
def forgotpass():
    if request.method == 'GET':
        return render_template('forgotpass.html')
    email = request.form.get('email', '').strip().lower()
    user = get_user_by_email(email)
    if not user:
        flash('No account with that email.', 'warning')
        return render_template('forgotpass.html')
    otp = f"{secrets.randbelow(1000000):06d}"
    expiry_iso = (datetime.utcnow() + timedelta(seconds=60)).isoformat()
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("UPDATE users SET otp=?, otp_expiry=? WHERE email=?", (otp, expiry_iso, email))
        conn.commit()
    # then send email (or flash for demo)
    send_email_async("Your OTP", [email], f"Your OTP is {otp}. Expires in 60s")
    flash("OTP sent to your email (check inbox).", "info")


    flash(f"OTP (demo only): {otp}", "info")
    return redirect(url_for('resetpass'))

@app.route('/resetpass', methods=['GET', 'POST'])
def resetpass():
    if request.method == 'GET':
        return render_template('resetpass.html')
    email = request.form.get('email', '').strip().lower()
    otp = request.form.get('otp', '').strip()
    new_pw = request.form.get('new_password', '')
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("SELECT otp FROM users WHERE email=?", (email,))
        record = c.fetchone()
        if record and record[0] == otp:
            hashed = generate_password_hash(new_pw)
            c.execute("UPDATE users SET password=?, otp=NULL WHERE email=?", (hashed, email))
            conn.commit()
            flash("Password reset successful!", "success")
            return redirect(url_for('login'))
        else:
            flash("Invalid OTP or email.", "danger")
            return render_template('resetpass.html')

# ----------------- MAIN -----------------
if __name__ == '__main__':
    if not os.path.exists(DB_PATH):
        print("⚠ Run: python db_init.py first to create the database.")
    app.run(debug=True)

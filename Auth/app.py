from flask import Flask, render_template, redirect, url_for, session, request, flash, jsonify
import sqlite3, secrets, os
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth

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
        c.execute("INSERT OR IGNORE INTO users (username, email, password) VALUES (?, ?, ?)", (username, email, password_hash))
        conn.commit()

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
@app.route('/api/signup', methods=['POST'])
def api_signup():
    data = request.json
    username, email, password = data.get('username'), data.get('email').lower(), data.get('password')
    if get_user_by_email(email):
        return jsonify({'error': 'Email already exists'}), 409

    create_user(username, email, generate_password_hash(password))
    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.json
    email, password = data.get('email').lower(), data.get('password')
    user = get_user_by_email(email)
    if not user or not check_password_hash(user[3], password):
        return jsonify({'error': 'Invalid credentials'}), 401

    login_user(user[0], user[1])
    return jsonify({'message': 'Login successful', 'username': user[1]}), 200
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
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("UPDATE users SET otp=? WHERE email=?", (otp, email))
        conn.commit()
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

@app.route('/api/profile')
def api_profile():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    return jsonify({'user_id': session['user_id'], 'username': session['username']}), 200

@app.route('/api/logout', methods=['POST'])
def api_logout():
    logout_user()
    return jsonify({'message': 'Logged out successfully'}), 200

# ----------------- MAIN -----------------
if __name__ == '__main__':
    if not os.path.exists(DB_PATH):
        print("⚠ Run: python db_init.py first to create the database.")
    app.run(debug=True)

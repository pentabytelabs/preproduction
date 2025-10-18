from flask import Flask, render_template, redirect, url_for, session, request, flash
import sqlite3, secrets, os
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", secrets.token_hex(16))

DB_PATH = "auth.db"

# ----------------- OAUTH SETUP -----------------
oauth = OAuth(app)

# NOTE: Replace with your actual credentials
app.config.update({
    'GOOGLE_CLIENT_ID': 'YOUR_GOOGLE_CLIENT_ID',
    'GOOGLE_CLIENT_SECRET': 'YOUR_GOOGLE_CLIENT_SECRET',
    'APPLE_CLIENT_ID': 'YOUR_APPLE_CLIENT_ID',
    'APPLE_CLIENT_SECRET': 'YOUR_APPLE_CLIENT_SECRET',
    'LINKEDIN_CLIENT_ID': 'YOUR_LINKEDIN_CLIENT_ID',
    'LINKEDIN_CLIENT_SECRET': 'YOUR_LINKEDIN_CLIENT_SECRET',
})

google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    access_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
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

# Apple requires JWT-based keys; skipping full setup for brevity
# You can integrate Apple Sign In later using Sign in with Apple JS or pyjwt backend.


# ----------------- DATABASE HELPERS -----------------
def get_user_by_email(email):
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE email=?", (email,))
        return c.fetchone()

def create_user(username, email, password=None, auth_key=None, customer_key=None):
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute(
            "INSERT OR IGNORE INTO users (username, email, password, auth_key, customer_key) VALUES (?, ?, ?, ?, ?)",
            (username, email, password or '', auth_key or secrets.token_hex(8), customer_key or secrets.token_hex(8)),
        )
        conn.commit()


# ----------------- AUTH ROUTES -----------------
@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/login/google')
def login_google():
    redirect_uri = url_for('authorize_google', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/authorize/google')
def authorize_google():
    token = google.authorize_access_token()
    user_info = google.get('userinfo').json()
    email = user_info['email']
    name = user_info.get('name', email.split('@')[0])

    if not get_user_by_email(email):
        create_user(name, email)

    session['user_id'] = email
    session['username'] = name
    flash('Logged in with Google!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/login/linkedin')
def login_linkedin():
    redirect_uri = url_for('authorize_linkedin', _external=True)
    return linkedin.authorize_redirect(redirect_uri)

@app.route('/authorize/linkedin')
def authorize_linkedin():
    token = linkedin.authorize_access_token()
    user_info = linkedin.get('me?projection=(id,localizedFirstName,localizedLastName)').json()
    email_resp = linkedin.get('emailAddress?q=members&projection=(elements*(handle~))').json()

    email = email_resp['elements'][0]['handle~']['emailAddress']
    name = name = f"{user_info['localizedFirstName']} {user_info['localizedLastName']}"


    if not get_user_by_email(email):
        create_user(name, email)

    session['user_id'] = email
    session['username'] = name
    flash('Logged in with LinkedIn!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please log in first.', 'warning')
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session['username'])

if __name__ == '__main__':
    app.run(debug=True)

from flask import Flask, render_template, request, redirect, url_for, flash, session
from utils import validate_email, generate_otp, send_otp_email, validate_otp, generate_totp, verify_totp, hash_password, generate_secret
import time
import os

# User database
users_db = {
    "user@example.com": {
        "name": "John Doe", 
        "verified": False,
        "totp_secret": None,
        "password_hash": None,
        "salt": None
    },
    "admin@test.com": {
        "name": "Admin User", 
        "verified": False,
        "totp_secret": None,
        "password_hash": None,
        "salt": None
    }
}

# Load environment variables from .env file
def load_env_vars():
    try:
        with open('.env', 'r') as f:
            for line in f:
                if '=' in line and not line.startswith('#'):
                    key, value = line.strip().split('=', 1)
                    os.environ[key] = value
    except FileNotFoundError:
        pass

load_env_vars()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        name = request.form['name'].strip()
        password = request.form['password'].strip()
        
        if not validate_email(email):
            flash('Invalid email format!', 'error')
            return render_template('register.html')
        
        if email in users_db:
            flash('User already exists!', 'error')
            return render_template('register.html')
        
        pwd_hash, salt = hash_password(password)
        totp_secret = generate_secret()
        
        users_db[email] = {
            "name": name,
            "verified": False,
            "password_hash": pwd_hash,
            "salt": salt,
            "totp_secret": totp_secret
        }
        
        flash(f'Registration successful! TOTP Secret: {totp_secret}', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        auth_method = request.form['auth_method']
        
        if not validate_email(email) or email not in users_db:
            flash('Invalid email or user not found!', 'error')
            return render_template('login.html')
        
        session['email'] = email
        
        if auth_method == 'password_otp':
            return redirect(url_for('password_auth'))
        else:
            return redirect(url_for('otp_method'))
    
    return render_template('login.html')

@app.route('/password_auth', methods=['GET', 'POST'])
def password_auth():
    if 'email' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        password = request.form['password'].strip()
        email = session['email']
        user = users_db[email]
        
        if verify_password(password, user["password_hash"], user["salt"]):
            session['password_verified'] = True
            return redirect(url_for('otp_method'))
        else:
            flash('Invalid password!', 'error')
    
    return render_template('password_auth.html')

@app.route('/otp_method', methods=['GET', 'POST'])
def otp_method():
    if 'email' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        otp_type = request.form['otp_type']
        
        if otp_type == 'standard':
            return redirect(url_for('standard_otp'))
        else:
            return redirect(url_for('totp_auth'))
    
    return render_template('otp_method.html')

@app.route('/standard_otp', methods=['GET', 'POST'])
def standard_otp():
    if 'email' not in session:
        return redirect(url_for('login'))
    
    email = session['email']
    
    if request.method == 'GET':
        # Generate and send OTP
        otp = generate_otp()
        session['otp'] = otp
        session['otp_time'] = time.time()
        
        print(f"[DEBUG] Generated OTP: {otp} for {email}")
        if send_otp_email(email, otp, "Standard"):
            flash('OTP sent to your email!', 'info')
        else:
            flash('Failed to send OTP. Check console for code.', 'error')
    
    elif request.method == 'POST':
        entered_otp = request.form['otp'].strip()
        
        # Debug info
        print(f"[DEBUG] Entered OTP: {entered_otp}")
        print(f"[DEBUG] Session OTP: {session.get('otp')}")
        
        # Check if OTP exists and is not expired
        if 'otp' not in session:
            flash('No OTP generated. Please try again.', 'error')
            return redirect(url_for('otp_method'))
        
        elapsed_time = time.time() - session.get('otp_time', 0)
        if elapsed_time > 60:
            flash(f'OTP expired! ({int(elapsed_time)}s elapsed)', 'error')
            session.pop('otp', None)
            session.pop('otp_time', None)
            return redirect(url_for('otp_method'))
        
        # Validate OTP
        if validate_otp(entered_otp, session['otp']):
            users_db[email]["verified"] = True
            session.pop('otp', None)
            session.pop('otp_time', None)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid OTP! Please try again.', 'error')
    
    return render_template('standard_otp.html')

@app.route('/totp_auth', methods=['GET', 'POST'])
def totp_auth():
    if 'email' not in session:
        return redirect(url_for('login'))
    
    email = session['email']
    user = users_db[email]
    
    if request.method == 'POST':
        entered_totp = request.form['totp'].strip()
        
        if verify_totp(user["totp_secret"], entered_totp):
            users_db[email]["verified"] = True
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid TOTP!', 'error')
    
    current_totp = generate_totp(user["totp_secret"])
    return render_template('totp_auth.html', secret=user["totp_secret"], demo_totp=current_totp)

@app.route('/dashboard')
def dashboard():
    if 'email' not in session:
        return redirect(url_for('login'))
    
    email = session['email']
    user = users_db[email]
    
    if not user["verified"]:
        flash('Please complete authentication first!', 'error')
        return redirect(url_for('login'))
    
    return render_template('dashboard.html', user=user, email=email)

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!', 'info')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
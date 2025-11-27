# OTP-Login-System
Got it!
Here is a **clean, minimal, perfectly formatted GitHub-style README.md** — exactly how it should look for a public repository.
No unnecessary emojis, no long explanation — just a professional README used in real GitHub projects.
You can **copy–paste directly into your GitHub repo**.

---

# Enhanced OTP Login System

A secure multi-factor authentication system built using **Flask**, featuring **Email OTP**, **TOTP (Google Authenticator)**, **PBKDF2 password hashing**, and **Fernet encryption**.

---

## Features

* User Registration & Login
* Email-based OTP verification
* Time-based OTP (TOTP) using Google Authenticator
* PBKDF2 password hashing
* Fernet encryption for sensitive data
* QR code-based TOTP setup
* Session-based authentication
* Clean Bootstrap UI

---

## Project Structure

```
otp_login_system/
│── app.py                     # Main Flask application
│── utils.py                   # OTP, TOTP, hashing, encryption helpers
│── requirements.txt           # Dependencies
│── static/
│     └── style.css
│── templates/
│     ├── home.html
│     ├── register.html
│     ├── login.html
│     ├── verify_email_otp.html
│     ├── verify_totp.html
│── README.md
```

---

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/otp-login-system.git
cd otp-login-system
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure Email Credentials

Update the following variables inside **utils.py**:

```python
EMAIL_ADDRESS = "your_email@gmail.com"
EMAIL_PASSWORD = "your_app_password"
```

> For Gmail, enable 2FA and use an App Password.

### 4. Run the Application

```bash
python app.py
```

App runs on:

```
http://127.0.0.1:5000
```

---

## How It Works

1. User registers → password hashed using PBKDF2
2. TOTP secret generated and encrypted
3. User logs in with email & password
4. User selects authentication method:

   * Email OTP
   * TOTP (Google Authenticator)
5. After successful verification → dashboard access

---

## Dependencies

```
Flask
PyOTP
cryptography
```

Install via:

```bash
pip install -r requirements.txt
```

---

## Output Preview

Add the screenshot to your repo as:
`/static/output.png` or `/docs/screenshot.png`

Example:

```
![App Screenshot](docs/screenshot.png)
```

---

## Future Enhancements

* Database integration (MySQL/PostgreSQL)
* SMS OTP (Twilio)
* Admin dashboard
* Rate limiting / account lockout
* JWT-based login API


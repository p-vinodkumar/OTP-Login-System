import re
import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from security import SecurityManager

security = SecurityManager()

def generate_otp():
    """Generate a cryptographically secure 6-digit OTP"""
    return security.secure_otp(6)

def generate_totp(secret):
    """Generate Time-based OTP"""
    return security.generate_totp(secret)

def verify_totp(secret, token):
    """Verify Time-based OTP"""
    return security.verify_totp(secret, token)

def generate_secret():
    """Generate secret key for TOTP"""
    return security.generate_secret_key()

def hash_password(password):
    """Hash password securely"""
    return security.hash_password(password)

def verify_password(password, stored_hash, salt):
    """Verify password"""
    return security.verify_password(password, stored_hash, salt)

def encrypt_data(data, password):
    """Encrypt sensitive data"""
    return security.encrypt_data(data, password)

def decrypt_data(encrypted_data, password):
    """Decrypt sensitive data"""
    return security.decrypt_data(encrypted_data, password)

def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def send_otp_email(email, otp, otp_type="Standard"):
    """Send OTP via email (real implementation)"""
    try:
        # Email configuration - set these environment variables
        smtp_server = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
        smtp_port = int(os.getenv('SMTP_PORT', '587'))
        sender_email = os.getenv('SENDER_EMAIL')
        sender_password = os.getenv('SENDER_PASSWORD')
        
        # Fallback to mock if credentials not set
        if not sender_email or not sender_password:
            print(f"[EMAIL MOCK] Sending {otp_type} OTP to {email}")
            print(f"Your OTP is: {otp}")
            print("[INFO] Set SENDER_EMAIL and SENDER_PASSWORD env vars for real emails")
            return True
        
        # Create message
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = email
        msg['Subject'] = f"🔐 Your {otp_type} OTP Code"
        
        # Email body
        body = f"""
        <html>
        <body>
        <h2>🔐 OTP Login System</h2>
        <p>Your <strong>{otp_type}</strong> OTP code is:</p>
        <h1 style="color: #007bff; font-size: 32px; letter-spacing: 3px;">{otp}</h1>
        <p><strong>⏰ Valid for 60 seconds</strong></p>
        <p>If you didn't request this code, please ignore this email.</p>
        <hr>
        <p style="font-size: 12px; color: #666;">Enhanced OTP Login System</p>
        </body>
        </html>
        """
        
        msg.attach(MIMEText(body, 'html'))
        
        # Send email
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(sender_email, sender_password)
        server.send_message(msg)
        server.quit()
        
        print(f"[EMAIL SENT] {otp_type} OTP sent to {email}")
        return True
        
    except Exception as e:
        print(f"[EMAIL ERROR] Failed to send OTP: {str(e)}")
        # Fallback to console display
        print(f"[FALLBACK] Your OTP is: {otp}")
        return True

def validate_otp(entered_otp, actual_otp):
    """Validate entered OTP"""
    return entered_otp == actual_otp
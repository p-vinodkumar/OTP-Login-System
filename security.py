import hashlib
import hmac
import secrets
import time
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class SecurityManager:
    def __init__(self):
        self.secret_key = secrets.token_bytes(32)
        self.totp_window = 30  # 30-second window for TOTP
    
    # Hashing
    def hash_password(self, password: str, salt: bytes = None) -> tuple:
        """Hash password with salt using SHA-256"""
        if salt is None:
            salt = secrets.token_bytes(32)
        pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        return pwd_hash, salt
    
    def verify_password(self, password: str, stored_hash: bytes, salt: bytes) -> bool:
        """Verify password against stored hash"""
        pwd_hash, _ = self.hash_password(password, salt)
        return hmac.compare_digest(pwd_hash, stored_hash)
    
    # HMAC
    def generate_hmac(self, message: str, key: bytes = None) -> str:
        """Generate HMAC-SHA256 for message"""
        if key is None:
            key = self.secret_key
        return hmac.new(key, message.encode(), hashlib.sha256).hexdigest()
    
    def verify_hmac(self, message: str, signature: str, key: bytes = None) -> bool:
        """Verify HMAC signature"""
        if key is None:
            key = self.secret_key
        expected = self.generate_hmac(message, key)
        return hmac.compare_digest(signature, expected)
    
    # Encryption
    def generate_key(self, password: str, salt: bytes = None) -> tuple:
        """Generate encryption key from password"""
        if salt is None:
            salt = secrets.token_bytes(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt
    
    def encrypt_data(self, data: str, password: str) -> dict:
        """Encrypt data with password"""
        key, salt = self.generate_key(password)
        f = Fernet(key)
        encrypted = f.encrypt(data.encode())
        return {
            'encrypted': base64.b64encode(encrypted).decode(),
            'salt': base64.b64encode(salt).decode()
        }
    
    def decrypt_data(self, encrypted_data: dict, password: str) -> str:
        """Decrypt data with password"""
        salt = base64.b64decode(encrypted_data['salt'])
        key, _ = self.generate_key(password, salt)
        f = Fernet(key)
        encrypted = base64.b64decode(encrypted_data['encrypted'])
        return f.decrypt(encrypted).decode()
    
    # Secure RNG
    def secure_random_int(self, min_val: int, max_val: int) -> int:
        """Generate cryptographically secure random integer"""
        return secrets.randbelow(max_val - min_val + 1) + min_val
    
    def secure_random_string(self, length: int) -> str:
        """Generate cryptographically secure random string"""
        return secrets.token_urlsafe(length)
    
    def secure_otp(self, length: int = 6) -> str:
        """Generate cryptographically secure OTP"""
        return ''.join([str(secrets.randbelow(10)) for _ in range(length)])
    
    # Key-based OTP (HOTP)
    def generate_hotp(self, secret: str, counter: int, digits: int = 6) -> str:
        """Generate HMAC-based OTP"""
        # Fix base32 padding
        secret = secret.upper().rstrip('=')
        padding = 8 - (len(secret) % 8)
        if padding != 8:
            secret += '=' * padding
        
        key = base64.b32decode(secret)
        counter_bytes = counter.to_bytes(8, 'big')
        
        hmac_hash = hmac.new(key, counter_bytes, hashlib.sha1).digest()
        offset = hmac_hash[-1] & 0x0f
        truncated = int.from_bytes(hmac_hash[offset:offset+4], 'big') & 0x7fffffff
        
        return str(truncated % (10 ** digits)).zfill(digits)
    
    # Time-based OTP (TOTP)
    def generate_totp(self, secret: str, time_step: int = None, digits: int = 6) -> str:
        """Generate Time-based OTP"""
        if time_step is None:
            time_step = int(time.time()) // self.totp_window
        return self.generate_hotp(secret, time_step, digits)
    
    def verify_totp(self, secret: str, token: str, window: int = 1) -> bool:
        """Verify TOTP with time window tolerance"""
        current_time = int(time.time()) // self.totp_window
        
        for i in range(-window, window + 1):
            if self.generate_totp(secret, current_time + i) == token:
                return True
        return False
    
    def generate_secret_key(self) -> str:
        """Generate base32 secret key for TOTP"""
        return base64.b32encode(secrets.token_bytes(20)).decode()
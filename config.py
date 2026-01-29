import os
import secrets

class Config:
    # Generate a NEW secret key each time server starts
    # This will invalidate all existing sessions on restart
    SECRET_KEY = secrets.token_hex(32)
    
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///site.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Security Configurations (Demonstrative)
    SESSION_COOKIE_SECURE = False  # Set to True in production with HTTPS
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'

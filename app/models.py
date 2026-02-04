from datetime import datetime
from flask_login import UserMixin
from app import db

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False) # 'Student', 'HR', 'Admin'
    
    # TOTP (MFA) Fields - MANDATORY FOR LAB
    totp_secret = db.Column(db.String(32), nullable=True)  # Base32 secret for TOTP
    totp_enabled = db.Column(db.Boolean, default=False)    # Whether TOTP is set up
    
    # Relationships
    resumes = db.relationship('Resume', backref='owner', lazy=True)
    jobs = db.relationship('Job', backref='author', lazy=True)
    
    def __repr__(self):
        return f"User('{self.username}', '{self.role}')"

class Resume(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(100), nullable=False)
    
    # Encryption Fields (MANDATORY FOR LAB)
    ciphertext = db.Column(db.Text, nullable=False)        # Encrypted Content
    iv = db.Column(db.String(50), nullable=False)          # Initialization Vector (Base64)
    encrypted_aes_key = db.Column(db.Text, nullable=False) # AES Key encrypted with RSA (Base64)
    
    upload_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

class Job(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    company = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    hr_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    posted_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    applications = db.relationship('Application', backref='job', lazy=True)

class Application(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.Integer, db.ForeignKey('job.id'), nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='Applied') # Applied, Shortlisted, Rejected
    date_applied = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

class PlacementResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    company_name = db.Column(db.String(100), nullable=False)
    package = db.Column(db.String(50), nullable=False)
    
    # Digital Signature Fields (MANDATORY FOR LAB)
    data_hash = db.Column(db.String(100), nullable=False) # SHA-256 of details
    digital_signature = db.Column(db.Text, nullable=False) # Signed hash
    
    published_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    student = db.relationship('User', backref='placements')

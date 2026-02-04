from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from app import db
from app.models import User
from app.security import (
    hash_password, check_password, 
    generate_totp_secret, get_current_totp, verify_totp, generate_totp_qr
)
import re

auth = Blueprint('auth', __name__)

def validate_password_strength(password):
    """
    Validates password strength:
    - Minimum 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    """
    errors = []
    
    if len(password) < 8:
        errors.append("Password must be at least 8 characters long")
    if not re.search(r'[A-Z]', password):
        errors.append("Password must contain at least one uppercase letter")
    if not re.search(r'[a-z]', password):
        errors.append("Password must contain at least one lowercase letter")
    if not re.search(r'\d', password):
        errors.append("Password must contain at least one digit")
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        errors.append("Password must contain at least one special character (!@#$%^&*)")
    
    return errors

@auth.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')
        
        # SINGLE ADMIN RESTRICTION
        if role == 'Admin':
            existing_admin = User.query.filter_by(role='Admin').first()
            if existing_admin:
                flash('System Restriction: Only ONE Administrator account is allowed.', 'danger')
                return redirect(url_for('auth.register'))

        # Validation
        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already exists.', 'danger')
            return redirect(url_for('auth.register'))
            
        email_user = User.query.filter_by(email=email).first()
        if email_user:
            flash('Email already exists.', 'danger')
            return redirect(url_for('auth.register'))
            
        if role not in ['Student', 'HR', 'Admin']:
             flash('Invalid Role.', 'danger')
             return redirect(url_for('auth.register'))
        
        # CONFIRM PASSWORD CHECK
        confirm_password = request.form.get('confirm_password')
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('auth.register'))
        
        # PASSWORD STRENGTH CHECK
        password_errors = validate_password_strength(password)
        if password_errors:
            for error in password_errors:
                flash(error, 'danger')
            return redirect(url_for('auth.register'))
             
        # Hash Password (SECURITY)
        hashed_pw = hash_password(password)
        
        new_user = User(username=username, email=email, password_hash=hashed_pw, role=role)
        db.session.add(new_user)
        db.session.commit()
        
        flash('Account created! Please login.', 'success')
        return redirect(url_for('auth.login'))
        
    return render_template('auth/register.html')

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
        
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        
        # Check Password (SECURITY)
        if user and check_password(password, user.password_hash):
            # Store user_id in session for MFA verification
            session['temp_user_id'] = user.id
            
            # Check if TOTP is already set up
            if user.totp_enabled and user.totp_secret:
                # User has TOTP enabled - go to verification
                return redirect(url_for('auth.verify_totp_route'))
            else:
                # First login - set up TOTP
                return redirect(url_for('auth.setup_totp'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
            
    return render_template('auth/login.html')

@auth.route('/setup-totp')
def setup_totp():
    """First-time TOTP setup with QR code"""
    if 'temp_user_id' not in session:
        return redirect(url_for('auth.login'))
    
    user = User.query.get(session['temp_user_id'])
    if not user:
        return redirect(url_for('auth.login'))
    
    # Generate new TOTP secret if not exists
    if not user.totp_secret:
        user.totp_secret = generate_totp_secret()
        db.session.commit()
    
    # Generate QR code
    qr_code_base64 = generate_totp_qr(user.totp_secret, user.email)
    
    # Get current OTP for demo display
    current_otp = get_current_totp(user.totp_secret)
    
    # Print to terminal for demo
    print("=" * 60)
    print(f" TOTP SETUP FOR: {user.email}")
    print(f" SECRET KEY: {user.totp_secret}")
    print(f" CURRENT OTP: {current_otp}")
    print(" Scan the QR code with Google Authenticator / Authy")
    print("=" * 60)
    
    return render_template('auth/setup_totp.html', 
                          qr_code=qr_code_base64, 
                          secret=user.totp_secret,
                          current_otp=current_otp,
                          email=user.email)

@auth.route('/verify-totp', methods=['GET', 'POST'])
def verify_totp_route():
    """Verify TOTP code from authenticator app"""
    if 'temp_user_id' not in session:
        return redirect(url_for('auth.login'))
    
    user = User.query.get(session['temp_user_id'])
    if not user:
        return redirect(url_for('auth.login'))
        
    if request.method == 'POST':
        totp_code = request.form.get('totp_code')
        
        # Verify TOTP
        if verify_totp(user.totp_secret, totp_code):
            # Mark TOTP as enabled if first time
            if not user.totp_enabled:
                user.totp_enabled = True
                db.session.commit()
            
            # Login successful
            login_user(user)
            session.pop('temp_user_id', None)
            
            print("=" * 50)
            print(f" LOGIN SUCCESS: {user.email}")
            print(f" TOTP VERIFIED: ✓")
            print("=" * 50)
            
            flash('Login Successful! MFA Verified.', 'success')
            
            # Redirect based on Role
            if user.role == 'Admin':
                return redirect(url_for('admin.dashboard'))
            elif user.role == 'HR':
                return redirect(url_for('hr.dashboard'))
            else:
                return redirect(url_for('student.dashboard'))
        else:
            flash('Invalid or Expired TOTP Code', 'danger')
    
    # Get current OTP for demo (shown in terminal)
    current_otp = get_current_totp(user.totp_secret) if user.totp_secret else ""
    print(f"[DEMO] Current TOTP for {user.email}: {current_otp}")
    
    return render_template('auth/verify_totp.html', email=user.email)

@auth.route('/complete-totp-setup', methods=['POST'])
def complete_totp_setup():
    """Complete TOTP setup after scanning QR"""
    if 'temp_user_id' not in session:
        return redirect(url_for('auth.login'))
    
    user = User.query.get(session['temp_user_id'])
    if not user:
        return redirect(url_for('auth.login'))
    
    totp_code = request.form.get('totp_code')
    
    # Verify TOTP to confirm setup
    if verify_totp(user.totp_secret, totp_code):
        user.totp_enabled = True
        db.session.commit()
        
        login_user(user)
        session.pop('temp_user_id', None)
        
        flash('MFA Setup Complete! You are now logged in.', 'success')
        
        # Redirect based on Role
        if user.role == 'Admin':
            return redirect(url_for('admin.dashboard'))
        elif user.role == 'HR':
            return redirect(url_for('hr.dashboard'))
        else:
            return redirect(url_for('student.dashboard'))
    else:
        flash('Invalid TOTP code. Please try again.', 'danger')
        return redirect(url_for('auth.setup_totp'))

@auth.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('main.home'))

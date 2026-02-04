from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user
from app import db
from app.models import Resume, Job, Application, PlacementResult, User
from app.decorators import role_required
from app.security import encrypt_data_aes, decrypt_data_aes, verify_signature, generate_qr_base64
import base64
import logging

student = Blueprint('student', __name__)

@student.route('/student/dashboard')
@login_required
@role_required('Student')
def dashboard():
    return render_template('student/dashboard.html')

@student.route('/student/resume/upload', methods=['GET', 'POST'])
@login_required
@role_required('Student')
def upload_resume():
    if request.method == 'POST':
        if 'resume' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
            
        file = request.files['resume']
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)
            
        if file:
            # Read file content
            file.seek(0)
            binary_content = file.read()
            content_str = base64.b64encode(binary_content).decode('utf-8')
            
            # CORE SECURITY: Encrypt Data (AES)
            encrypted_data = encrypt_data_aes(content_str)
            
            # Log to terminal
            logging.warning("=" * 60)
            logging.warning(f"RESUME UPLOAD for {current_user.username}")
            logging.warning(f"Filename: {file.filename}")
            logging.warning(f"Original Size: {len(binary_content)} bytes")
            logging.warning(f"Ciphertext Preview: {encrypted_data['ciphertext'][:50]}...")
            logging.warning(f"IV: {encrypted_data['iv']}")
            logging.warning("Resume is now AES-256 ENCRYPTED in database!")
            logging.warning("=" * 60)
            
            new_resume = Resume(
                user_id=current_user.id,
                filename=file.filename,
                ciphertext=encrypted_data['ciphertext'],
                iv=encrypted_data['iv'],
                encrypted_aes_key=encrypted_data['encrypted_aes_key']
            )
            
            db.session.add(new_resume)
            db.session.commit()
            
            flash('Resume uploaded and ENCRYPTED successfully!', 'success')
            return redirect(url_for('student.dashboard'))
            
    # Get existing resume if any
    existing_resume = Resume.query.filter_by(user_id=current_user.id).order_by(Resume.upload_date.desc()).first()
    return render_template('student/upload_resume.html', existing_resume=existing_resume)

@student.route('/student/jobs')
@login_required
@role_required('Student')
def view_jobs():
    jobs = Job.query.order_by(Job.posted_date.desc()).all()
    my_applications = {app.job_id for app in Application.query.filter_by(student_id=current_user.id).all()}
    return render_template('student/jobs.html', jobs=jobs, my_applications=my_applications)

@student.route('/student/apply/<int:job_id>', methods=['POST'])
@login_required
@role_required('Student')
def apply_job(job_id):
    job = Job.query.get_or_404(job_id)
    
    existing = Application.query.filter_by(job_id=job.id, student_id=current_user.id).first()
    if existing:
        flash('Already applied to this job.', 'warning')
        return redirect(url_for('student.view_jobs'))
    
    # Check if student has uploaded resume
    resume = Resume.query.filter_by(user_id=current_user.id).first()
    if not resume:
        flash('Please upload your resume before applying.', 'danger')
        return redirect(url_for('student.upload_resume'))
        
    app = Application(job_id=job.id, student_id=current_user.id)
    db.session.add(app)
    db.session.commit()
    
    flash(f'Successfully applied to {job.title}!', 'success')
    return redirect(url_for('student.view_jobs'))

@student.route('/student/applications')
@login_required
@role_required('Student')
def view_applications():
    """View all applications and their status"""
    applications = Application.query.filter_by(student_id=current_user.id).order_by(Application.date_applied.desc()).all()
    
    apps_data = []
    for app in applications:
        job = Job.query.get(app.job_id)
        hr = User.query.get(job.hr_id)
        apps_data.append({
            'id': app.id,
            'job_title': job.title,
            'company': job.company,
            'status': app.status,
            'date_applied': app.date_applied,
            'hr_name': hr.username if hr else 'N/A'
        })
    
    return render_template('student/applications.html', applications=apps_data)

@student.route('/student/results')
@login_required
@role_required('Student')
def view_results():
    """View placement results with signature verification"""
    results = PlacementResult.query.filter_by(student_id=current_user.id).all()
    
    verified_results = []
    for result in results:
        # Recreate original data for signature verification
        original_data = f"{result.student_id}:{result.company_name}:{result.package}"
        is_valid = verify_signature(original_data, result.digital_signature)
        
        # Log Verification Details
        logging.warning(f"[SIG CHECK] Student: {current_user.username}")
        logging.warning(f"  Data: {original_data}")
        logging.warning(f"  Valid: {is_valid}")
        
        # Generate QR code for result verification
        qr_data = f"VERIFIED|{result.company_name}|{result.package}|{result.published_date}"
        qr_code = generate_qr_base64(qr_data)
        
        verified_results.append({
            'id': result.id,
            'company': result.company_name,
            'package': result.package,
            'published_date': result.published_date,
            'data_hash': result.data_hash,
            'is_valid': is_valid,
            'qr_code': qr_code
        })
    
    return render_template('student/results.html', results=verified_results)

@student.route('/student/encryption-demo', methods=['GET', 'POST'])
@login_required
@role_required('Student')
def encryption_demo():
    """Interactive encryption demonstration for students"""
    result = None
    if request.method == 'POST':
        data = request.form.get('data')
        
        if data:
            # Encrypt the data
            encrypted = encrypt_data_aes(data)
            
            # Also decrypt to show full cycle
            decrypted = decrypt_data_aes(encrypted)
            
            result = {
                'original': data,
                'ciphertext': encrypted['ciphertext'],
                'iv': encrypted['iv'],
                'encrypted_key': encrypted['encrypted_aes_key'][:60] + '...',
                'decrypted': decrypted
            }
            
            # Log to terminal
            logging.warning("=" * 50)
            logging.warning("ENCRYPTION DEMO")
            logging.warning(f"Original: {data}")
            logging.warning(f"Ciphertext: {encrypted['ciphertext'][:50]}...")
            logging.warning(f"Decrypted: {decrypted}")
            logging.warning("=" * 50)
            
    return render_template('student/encryption_demo.html', result=result)

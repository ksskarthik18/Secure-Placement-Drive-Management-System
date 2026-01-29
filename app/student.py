from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user
from app import db
from app.models import Resume, Job, Application
from app.decorators import role_required
from app.security import encrypt_data_aes

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
            file_content = file.read().decode('utf-8', errors='ignore') # Assuming text/pdf as latin-1/utf-8 for demo simplicity
            # For real PDF, we would encode bytes to base64 first.
            # Let's handle binary:
            import base64
            file.seek(0)
            binary_content = file.read()
            # Convert binary to base64 string to be suitable for our string-based encryption helper
            content_str = base64.b64encode(binary_content).decode('utf-8')
            
            # CORE SECURITY: Encrypt Data (AES)
            encrypted_data = encrypt_data_aes(content_str)
            
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
            
    return render_template('student/upload_resume.html')

@student.route('/student/jobs')
@login_required
@role_required('Student')
def view_jobs():
    jobs = Job.query.order_by(Job.posted_date.desc()).all()
    # Check which jobs applied to
    my_applications = {app.job_id for app in Application.query.filter_by(student_id=current_user.id).all()}
    return render_template('student/jobs.html', jobs=jobs, my_applications=my_applications)

@student.route('/student/apply/<int:job_id>', methods=['POST'])
@login_required
@role_required('Student')
def apply_job(job_id):
    # Check if exists
    job = Job.query.get_or_404(job_id)
    
    # Check if already applied
    existing = Application.query.filter_by(job_id=job.id, student_id=current_user.id).first()
    if existing:
        flash('Already applied to this job.', 'warning')
        return redirect(url_for('student.view_jobs'))
        
    app = Application(job_id=job.id, student_id=current_user.id)
    db.session.add(app)
    db.session.commit()
    
    flash(f'Successfully applied to {job.title}!', 'success')
    return redirect(url_for('student.view_jobs'))

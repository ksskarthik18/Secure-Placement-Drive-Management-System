from flask import Blueprint, render_template, request, flash, redirect, url_for, Response
from flask_login import login_required, current_user
from app import db
from app.models import Job, Application, Resume, PlacementResult, User
from app.decorators import role_required
from app.security import decrypt_data_aes, sign_data
import base64
import logging

hr = Blueprint('hr', __name__)

@hr.route('/hr/dashboard')
@login_required
@role_required('HR')
def dashboard():
    my_jobs = Job.query.filter_by(hr_id=current_user.id).order_by(Job.posted_date.desc()).all()
    
    # Calculate application counts manually to avoid template errors
    job_stats = []
    total_applicants = 0
    for job in my_jobs:
        count = len(job.applications)
        total_applicants += count
        job_stats.append({
            'job': job,
            'count': count
        })
        
    return render_template('hr/dashboard.html', jobs=my_jobs, job_stats=job_stats, total_applicants=total_applicants)

@hr.route('/hr/job/post', methods=['GET', 'POST'])
@login_required
@role_required('HR')
def post_job():
    if request.method == 'POST':
        title = request.form.get('title')
        company = request.form.get('company')
        description = request.form.get('description')
        
        job = Job(title=title, company=company, description=description, hr_id=current_user.id)
        db.session.add(job)
        db.session.commit()
        flash('Job Posted Successfully!', 'success')
        return redirect(url_for('hr.dashboard'))
        
    return render_template('hr/post_job.html')

@hr.route('/hr/job/<int:job_id>/applicants')
@login_required
@role_required('HR')
def review_applicants(job_id):
    job = Job.query.get_or_404(job_id)
    if job.hr_id != current_user.id:
        return redirect(url_for('hr.dashboard'))
        
    applications = Application.query.filter_by(job_id=job.id).all()
    applicants_data = []
    
    for app in applications:
        student = User.query.get(app.student_id)
        resume = Resume.query.filter_by(user_id=student.id).order_by(Resume.upload_date.desc()).first()
        
        resume_info = None
        decrypted_preview = None
        
        if resume:
            # SECURITY: Decrypting the resume for authorized HR
            enc_data = {
                'ciphertext': resume.ciphertext,
                'iv': resume.iv,
                'encrypted_aes_key': resume.encrypted_aes_key
            }
            decrypted_base64 = decrypt_data_aes(enc_data)
            
            # For TEXT files, decode and show preview
            # For PDF/binary, just show that it's encrypted
            try:
                file_bytes = base64.b64decode(decrypted_base64)
                # Try to decode as text for preview
                try:
                    decrypted_preview = file_bytes.decode('utf-8')[:500]  # First 500 chars
                except:
                    decrypted_preview = f"[Binary file - {len(file_bytes)} bytes decrypted successfully]"
                
                # Log to terminal
                logging.warning("=" * 50)
                logging.warning(f"DECRYPTED RESUME for {student.username}:")
                logging.warning(f"Filename: {resume.filename}")
                logging.warning(f"Content Preview: {decrypted_preview[:200]}...")
                logging.warning("=" * 50)
                
            except Exception as e:
                decrypted_preview = f"[Decryption Error: {str(e)}]"
            
            resume_info = {
                'id': resume.id,
                'filename': resume.filename
            }
            
        applicants_data.append({
            'application_id': app.id,
            'student_name': student.username,
            'status': app.status,
            'resume': resume_info,
            'decrypted_preview': decrypted_preview,
            'student_id': student.id
        })
        
    return render_template('hr/review_applicants.html', job=job, applicants=applicants_data)

@hr.route('/hr/download-resume/<int:resume_id>')
@login_required
@role_required('HR')
def download_resume(resume_id):
    """Download and decrypt resume (PDF/any file)"""
    resume = Resume.query.get_or_404(resume_id)
    
    logging.warning("=" * 50)
    logging.warning(f"DOWNLOAD REQUEST for Resume ID: {resume_id}")
    logging.warning(f"Filename: {resume.filename}")
    logging.warning("=" * 50)
    
    # SECURITY: Decrypting the resume for authorized HR
    enc_data = {
        'ciphertext': resume.ciphertext,
        'iv': resume.iv,
        'encrypted_aes_key': resume.encrypted_aes_key
    }
    
    # Decrypt -> returns base64 string of original binary
    decrypted_base64 = decrypt_data_aes(enc_data)
    
    print(f"Decrypted base64 length: {len(decrypted_base64)}")
    
    try:
        # Decode base64 back to binary
        file_bytes = base64.b64decode(decrypted_base64)
        
        print(f"Decrypted file size: {len(file_bytes)} bytes")
        
        # Determine MIME type based on filename
        filename = resume.filename
        if filename.lower().endswith('.pdf'):
            mimetype = 'application/pdf'
        elif filename.lower().endswith('.docx'):
            mimetype = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        elif filename.lower().endswith('.txt'):
            mimetype = 'text/plain'
        else:
            mimetype = 'application/octet-stream'
        
        return Response(
            file_bytes,
            mimetype=mimetype,
            headers={'Content-Disposition': f'attachment; filename=decrypted_{filename}'}
        )
    except Exception as e:
        print(f"DECRYPTION ERROR: {str(e)}")
        flash(f'Decryption Error: {str(e)}', 'danger')
        return redirect(url_for('hr.dashboard'))

@hr.route('/hr/publish-result/<int:student_id>', methods=['GET', 'POST'])
@login_required
@role_required('HR')
def publish_result(student_id):
    student = User.query.get_or_404(student_id)
    
    if request.method == 'POST':
        company_name = request.form.get('company_name')
        package = request.form.get('package')
        
        data_to_sign = f"{student.id}:{company_name}:{package}"
        sign_result = sign_data(data_to_sign) 
        
        placement = PlacementResult(
            student_id=student.id,
            company_name=company_name,
            package=package,
            data_hash=sign_result['data_hash'],
            digital_signature=sign_result['signature']
        )
        
        db.session.add(placement)
        db.session.commit()
        
        flash('Placement Result Published with Digital Signature!', 'success')
        return redirect(url_for('hr.dashboard'))
        
    return render_template('hr/publish_result.html', student=student)

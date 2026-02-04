from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user
from app import db
from app.models import User, PlacementResult, Resume, Job, Application
from app.decorators import role_required
from app.security import encrypt_data_aes, decrypt_data_aes, verify_signature, generate_qr_base64
import base64

admin = Blueprint('admin', __name__)

@admin.route('/admin/dashboard')
@login_required
@role_required('Admin')
def dashboard():
    """Admin dashboard with real-time statistics"""
    stats = {
        'total_students': User.query.filter_by(role='Student').count(),
        'total_hrs': User.query.filter_by(role='HR').count(),
        'total_admins': User.query.filter_by(role='Admin').count(),
        'total_resumes': Resume.query.count(),
        'active_jobs': Job.query.count(),
        'total_applications': Application.query.count(),
        'results_published': PlacementResult.query.count(),
        'mfa_enabled_users': User.query.filter_by(totp_enabled=True).count()
    }
    
    # Recent activities
    recent_users = User.query.order_by(User.id.desc()).limit(5).all()
    recent_jobs = Job.query.order_by(Job.posted_date.desc()).limit(5).all()
    
    return render_template('admin/dashboard.html', stats=stats, recent_users=recent_users, recent_jobs=recent_jobs)

@admin.route('/admin/users')
@login_required
@role_required('Admin')
def manage_users():
    """User Management Page"""
    users = User.query.order_by(User.id.desc()).all()
    return render_template('admin/users.html', users=users)

@admin.route('/admin/hashes')
@login_required
@role_required('Admin')
def view_hashes():
    """Password Hash View Page (no plaintext)"""
    users = User.query.all()
    return render_template('admin/hashes.html', users=users)

@admin.route('/admin/rbac')
@login_required
@role_required('Admin')
def rbac_matrix():
    """Access Control Matrix Page"""
    return render_template('admin/rbac_matrix.html')

@admin.route('/admin/encryption-demo', methods=['GET', 'POST'])
@login_required
@role_required('Admin')
def encryption_demo():
    """Interactive Encryption Demonstration Page"""
    result = None
    if request.method == 'POST':
        action = request.form.get('action')
        data = request.form.get('data', '')
        
        if action == 'encrypt' and data:
            encrypted = encrypt_data_aes(data)
            
            # Also decrypt to show full cycle
            decrypted = decrypt_data_aes(encrypted)
            
            result = {
                'type': 'encryption',
                'original': data,
                'ciphertext': encrypted['ciphertext'],
                'iv': encrypted['iv'],
                'encrypted_aes_key': encrypted['encrypted_aes_key'][:80] + '...',
                'decrypted': decrypted
            }
            
            # Print to terminal
            print("=" * 60)
            print("ENCRYPTION DEMONSTRATION")
            print(f"Original Plaintext: {data}")
            print(f"AES Ciphertext: {encrypted['ciphertext'][:50]}...")
            print(f"IV (Base64): {encrypted['iv']}")
            print(f"RSA-Encrypted AES Key: {encrypted['encrypted_aes_key'][:40]}...")
            print(f"Decrypted Result: {decrypted}")
            print("=" * 60)
            
    return render_template('admin/encryption_demo.html', result=result)

@admin.route('/admin/signature-verify')
@login_required
@role_required('Admin')
def signature_verify():
    """Digital Signature Verification Demo"""
    results = PlacementResult.query.all()
    
    verified_results = []
    for result in results:
        student = User.query.get(result.student_id)
        
        # Recreate the original data string used for signing
        original_data = f"{result.student_id}:{result.company_name}:{result.package}"
        
        # Verify the signature
        is_valid = verify_signature(original_data, result.digital_signature)
        
        # Print to terminal
        print("=" * 50)
        print(f"SIGNATURE VERIFICATION for {student.username}")
        print(f"Data: {original_data}")
        print(f"Hash: {result.data_hash[:30]}...")
        print(f"Signature: {result.digital_signature[:30]}...")
        print(f"Status: {'VALID ✓' if is_valid else 'INVALID ✗'}")
        print("=" * 50)
        
        verified_results.append({
            'id': result.id,
            'student_name': student.username,
            'company': result.company_name,
            'package': result.package,
            'data_hash': result.data_hash,
            'signature': result.digital_signature,
            'is_valid': is_valid,
            'original_data': original_data
        })
    
    return render_template('admin/signature_verify.html', results=verified_results)

@admin.route('/admin/tamper-result/<int:result_id>', methods=['POST'])
@login_required
@role_required('Admin')
def tamper_result(result_id):
    """Simulate data tampering to show signature becomes invalid"""
    result = PlacementResult.query.get_or_404(result_id)
    
    # Tamper with the data (change package)
    old_package = result.package
    result.package = "TAMPERED_100 LPA"
    db.session.commit()
    
    print("=" * 50)
    print("DATA TAMPERING SIMULATION")
    print(f"Original Package: {old_package}")
    print(f"Tampered Package: TAMPERED_100 LPA")
    print("Signature will now FAIL verification!")
    print("=" * 50)
    
    flash(f'Data TAMPERED! Package changed from "{old_package}" to "TAMPERED_100 LPA". Signature will now be INVALID.', 'warning')
    return redirect(url_for('admin.signature_verify'))

@admin.route('/admin/encoding-demo', methods=['GET', 'POST'])
@login_required
@role_required('Admin')
def encoding_demo():
    """Encoding vs Encryption Demonstration Page"""
    result = None
    
    if request.method == 'POST':
        data = request.form.get('data', '')
        
        if data:
            # Base64 Encoding
            base64_encoded = base64.b64encode(data.encode()).decode()
            base64_decoded = base64.b64decode(base64_encoded).decode()
            
            # QR Code Encoding
            qr_code = generate_qr_base64(data)
            
            # AES Encryption for comparison
            encrypted = encrypt_data_aes(data)
            
            result = {
                'original': data,
                'base64_encoded': base64_encoded,
                'base64_decoded': base64_decoded,
                'qr_code': qr_code,
                'aes_encrypted': encrypted['ciphertext'][:60] + '...'
            }
            
            print("=" * 60)
            print("ENCODING VS ENCRYPTION DEMO")
            print(f"Original: {data}")
            print(f"Base64 Encoded: {base64_encoded}")
            print(f"AES Encrypted: {encrypted['ciphertext'][:40]}...")
            print("Note: Encoding is REVERSIBLE without key!")
            print("      Encryption REQUIRES key to reverse!")
            print("=" * 60)
    
    return render_template('admin/encoding_demo.html', result=result)

@admin.route('/admin/theory')
@login_required
@role_required('Admin')
def theory():
    """Security Theory Page"""
    return render_template('admin/theory.html')

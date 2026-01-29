from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user
from app import db
from app.models import User
from app.decorators import role_required
from app.security import encrypt_data_aes, decrypt_data_aes

admin = Blueprint('admin', __name__)

@admin.route('/admin/dashboard')
@login_required
@role_required('Admin')
def dashboard():
    return render_template('admin/dashboard.html')

@admin.route('/admin/hashes')
@login_required
@role_required('Admin')
def view_hashes():
    # SECURITY DEMO: Show password hashes
    users = User.query.all()
    return render_template('admin/hashes.html', users=users)

@admin.route('/admin/rbac')
@login_required
@role_required('Admin')
def rbac_matrix():
    return render_template('admin/rbac_matrix.html')

@admin.route('/admin/encryption-demo', methods=['GET', 'POST'])
@login_required
@role_required('Admin')
def encryption_demo():
    result = None
    if request.method == 'POST':
        action = request.form.get('action')
        data = request.form.get('data')
        
        if action == 'encrypt':
            result = encrypt_data_aes(data)
            result['type'] = 'encryption'
        elif action == 'decrypt':
            # In a real demo, we'd paste the JSON/dict, but for simplicity
            # let's just encrypt the input again to show how it changes or
            # simulate decryption if the user provides special format.
            # actually, let's just do an interactive "Encrypt This" => Shows Ciphertext
            # and "Decrypt this Ciphertext" might be too complex for a simple textual UI input
            # unless we accept JSON.
            # Let's keep it simple: Input -> Encrypt -> Output Ciphertext components
            pass
            
    return render_template('admin/encryption_demo.html', result=result)

@admin.route('/admin/theory')
@login_required
@role_required('Admin')
def theory():
    return render_template('admin/theory.html')

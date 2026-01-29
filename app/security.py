import os
import base64
import time
import json
import secrets
import qrcode
import bcrypt
from io import BytesIO
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import pad, unpad

# -------------------------------------------------------------
# 1. HASHING (Passwords)
# -------------------------------------------------------------
def hash_password(password: str) -> str:
    """Hash a password using bcrypt (SHA-256 based with salt)."""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def check_password(password: str, hashed_password: str) -> bool:
    """Check a password against a hash."""
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

# -------------------------------------------------------------
# 2. ENCRYPTION (AES + RSA Hybrid)
# -------------------------------------------------------------
# Generate a global RSA Key Pair for the application (Admin's Private Key)
# In a real app, these would be loaded from secure files.
RSA_KEY = RSA.generate(2048)
PRIVATE_KEY = RSA_KEY
PUBLIC_KEY = RSA_KEY.publickey()

def get_admin_public_key_pem():
    return PUBLIC_KEY.export_key().decode('utf-8')

def encrypt_data_aes(data: str) -> dict:
    """
    Encrypts string data using AES-256 (CBC mode).
    Returns a dict with: 'ciphertext', 'iv', 'encrypted_aes_key'.
    We encrypt the AES key with the Admin's Public RSA Key (Hybrid).
    """
    # 1. Generate AES Key and IV
    aes_key = get_random_bytes(32) # 256-bit key
    iv = get_random_bytes(16)
    
    # 2. Encrypt Data with AES
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    ciphertext_bytes = cipher_aes.encrypt(pad(data.encode('utf-8'), AES.block_size))
    ciphertext_b64 = base64.b64encode(ciphertext_bytes).decode('utf-8')
    iv_b64 = base64.b64encode(iv).decode('utf-8')
    
    # 3. Encrypt AES Key with RSA Public Key
    cipher_rsa = PKCS1_OAEP.new(PUBLIC_KEY)
    enc_aes_key_bytes = cipher_rsa.encrypt(aes_key)
    enc_aes_key_b64 = base64.b64encode(enc_aes_key_bytes).decode('utf-8')
    
    return {
        'ciphertext': ciphertext_b64,
        'iv': iv_b64,
        'encrypted_aes_key': enc_aes_key_b64
    }

def decrypt_data_aes(encrypted_data: dict) -> str:
    """
    Decrypts data using the stored IV and Encrypted AES Key.
    Requires the Admin's Private RSA Key.
    """
    try:
        # 1. Decode inputs
        iv = base64.b64decode(encrypted_data['iv'])
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        enc_aes_key = base64.b64decode(encrypted_data['encrypted_aes_key'])
        
        # 2. Decrypt AES Key using RSA Private Key
        cipher_rsa = PKCS1_OAEP.new(PRIVATE_KEY)
        aes_key = cipher_rsa.decrypt(enc_aes_key)
        
        # 3. Decrypt Data using AES
        cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
        plaintext_bytes = unpad(cipher_aes.decrypt(ciphertext), AES.block_size)
        return plaintext_bytes.decode('utf-8')
    except Exception as e:
        return f"[Decryption Failed: {str(e)}]"

# -------------------------------------------------------------
# 3. DIGITAL SIGNATURE (RSA)
# -------------------------------------------------------------
def sign_data(data: str) -> dict:
    """
    Hashes the data (SHA-256) and signs the hash with RSA Private Key.
    Returns: 'data_hash', 'signature'.
    """
    data_bytes = data.encode('utf-8')
    
    # 1. Create Hash
    h = SHA256.new(data_bytes)
    data_hash_b64 = base64.b64encode(h.digest()).decode('utf-8')
    
    # 2. Sign Hash
    signature = pkcs1_15.new(PRIVATE_KEY).sign(h)
    signature_b64 = base64.b64encode(signature).decode('utf-8')
    
    return {
        'data_hash': data_hash_b64,
        'signature': signature_b64
    }

def verify_signature(data: str, signature_b64: str) -> bool:
    """Verifies the digital signature of the data."""
    try:
        data_bytes = data.encode('utf-8')
        signature = base64.b64decode(signature_b64)
        
        h = SHA256.new(data_bytes)
        pkcs1_15.new(PUBLIC_KEY).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

# -------------------------------------------------------------
# 4. OTP (Time-based simulation)
# -------------------------------------------------------------
OTP_STORAGE = {} # In-memory storage for demo: {user_email: {'code': '123456', 'expiry': timestamp}}

def generate_otp(email: str, validity_seconds=300) -> str:
    """Generates a 6-digit OTP and stores it."""
    otp_code = f"{secrets.randbelow(1000000):06d}" # Secure random
    expiry = time.time() + validity_seconds
    OTP_STORAGE[email] = {'code': otp_code, 'expiry': expiry}
    return otp_code

def verify_otp(email: str, input_otp: str) -> bool:
    """Verifies OTP and checks expiration."""
    record = OTP_STORAGE.get(email)
    if not record:
        return False
    
    if time.time() > record['expiry']:
        del OTP_STORAGE[email] # Expired
        return False
        
    if record['code'] == input_otp:
        del OTP_STORAGE[email] # Use once
        return True
        
    return False

# -------------------------------------------------------------
# 5. ENCODING (QR Code)
# -------------------------------------------------------------
def generate_qr_base64(data: str) -> str:
    """Generates a QR code for the data and returns it as a Base64 PNG string."""
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode("utf-8")
    return img_str

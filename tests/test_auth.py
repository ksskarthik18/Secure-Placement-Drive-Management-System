import unittest
from app import create_app, db
from app.models import User
from app.security import OTP_STORAGE

class AuthTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.app.config['TESTING'] = True
        self.app.config['WTF_CSRF_ENABLED'] = False # Disable CSRF for testing
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://' # In-memory DB
        self.client = self.app.test_client()
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_register(self):
        response = self.client.post('/register', data={
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'password123',
            'role': 'Student'
        }, follow_redirects=True)
        self.assertIn(b'Account created!', response.data)
        user = User.query.filter_by(username='testuser').first()
        self.assertIsNotNone(user)
        self.assertEqual(user.role, 'Student')

    def test_login_and_otp(self):
        # 1. Register
        self.client.post('/register', data={
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'password123',
            'role': 'Student'
        })
        
        # 2. Login (Should redirect to OTP)
        response = self.client.post('/login', data={
            'email': 'test@example.com',
            'password': 'password123'
        }, follow_redirects=True)
        self.assertIn(b'Verify Identity', response.data) # Check we are on OTP page
        
        # 3. Get OTP from mock storage
        otp_record = OTP_STORAGE.get('test@example.com')
        self.assertIsNotNone(otp_record)
        otp_code = otp_record['code']
        
        # 4. Verify OTP
        with self.client.session_transaction() as sess:
            # Session must have temp_user_id. The test client handles cookies, 
            # but we need to ensure the session variable was set in previous request.
            pass
            
        response = self.client.post('/verify-otp', data={
            'otp': otp_code
        }, follow_redirects=True)
        
        self.assertIn(b'Login Successful!', response.data)
        
    def test_security_hashing(self):
        from app.security import hash_password, check_password
        pw = "secret"
        hashed = hash_password(pw)
        self.assertNotEqual(pw, hashed)
        self.assertTrue(check_password(pw, hashed))
        self.assertFalse(check_password("wrong", hashed))

if __name__ == '__main__':
    unittest.main()

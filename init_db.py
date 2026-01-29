from app import create_app, db
from app.models import User
import os

app = create_app()

def init_db():
    if os.path.exists('site.db'):
        os.remove('site.db') # clean start for testing
        print("Removed existing DB.")
        
    with app.app_context():
        db.create_all()
        print("Created database tables.")
        
        # Optionally create a seed admin
        # from app.security import hash_password
        # admin = User(username='admin', email='admin@test.com', 
        #              password_hash=hash_password('admin123'), role='Admin')
        # db.session.add(admin)
        # db.session.commit()
        # print("Created admin user.")

if __name__ == '__main__':
    init_db()

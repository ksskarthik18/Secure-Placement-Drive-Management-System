from app import create_app, db
from app.models import User
import os

app = create_app()

def init_db():
    # Database is stored in instance/site.db
    db_path = os.path.join('instance', 'site.db')
    
    if os.path.exists(db_path):
        os.remove(db_path)
        print("Removed existing database.")
        
    with app.app_context():
        db.create_all()
        print("Created fresh database tables.")

if __name__ == '__main__':
    init_db()

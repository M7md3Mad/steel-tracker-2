from app import db, app  # Importing from app.py

with app.app_context():
    db.drop_all()
    db.create_all()

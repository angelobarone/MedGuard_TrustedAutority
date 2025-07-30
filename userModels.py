import os
from faker import Faker
from flask_sqlalchemy import SQLAlchemy
from flask import Flask
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # database SQLite in un file locale
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
fake = Faker()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


def initialize_database():
    for _ in range(10):
        username = fake.user_name()
        password = fake.password(length=10)
        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

def check_database():
    print("Controllo la presenza del database...")
    with app.app_context():
        if not os.path.exists("instance/users.db"):
            db.create_all()
            initialize_database()

def validate_user(username):
    with app.app_context():
        user = User.query.filter_by(username=username).first()
        if user:
            return user.password_hash
        else:
            return False

def create_user(username, password):
    with app.app_context():
        existing = User.query.filter_by(username=username).first()
        if existing:
            print(f"Utente '{username}' esiste già.")
            return

        user = User(username=username, password_hash=password)
        db.session.add(user)
        db.session.commit()

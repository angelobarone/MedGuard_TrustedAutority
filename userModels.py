import os
from faker import Faker
from werkzeug.security import generate_password_hash, check_password_hash
from extensions import db
fake = Faker()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


def initialize_database(app):
    with app.app_context():
        username1 = "angelo"
        password1 = "barone"
        user = User(username=username1)
        user.password_hash = generate_password_hash(password1)
        db.session.add(user)
        db.session.commit()
        #for _ in range(10):
         #   username = fake.user_name()
          #  password = fake.password(length=10)
           # user = User(username=username)
            #user.password_hash = generate_password_hash(password)
            #db.session.add(user)
            #db.session.commit()

def check_database(app):
    print("Controllo la presenza del database...")
    with app.app_context():
        if not os.path.exists("instance/users.db"):
            db.create_all()
            initialize_database(app)

def validate_user(app, username):
    with app.app_context():
        user = User.query.filter_by(username=username).first()
        if user:
            return user.id
        else:
            return False

def create_user(app, username, password):
    with app.app_context():
        existing = User.query.filter_by(username=username).first()
        if existing:
            print(f"Utente '{username}' esiste già.")
            return

        user = User(username=username, password_hash=password)
        db.session.add(user)
        db.session.commit()

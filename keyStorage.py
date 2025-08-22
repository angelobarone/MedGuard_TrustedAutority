import json

from flask import jsonify
from phe import paillier
from sqlalchemy.exc import SQLAlchemyError
import keyGenerator
from extensions import db

class KeyStorage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    n = db.Column(db.String(1000), unique=True, nullable=False)
    g = db.Column(db.String(1000), unique=True, nullable=False)
    p = db.Column(db.String(1000), unique=True, nullable=False)
    q = db.Column(db.String(1000), unique=True, nullable=False)

def new_key(app):
    try:
        public_key, private_key = keyGenerator.generate_key()
        row = KeyStorage.query.first()
        if row:
            row.n = str(public_key.n)
            row.g = str(public_key.g)
            row.p = str(private_key.p)
            row.q = str(private_key.q)
        else:
            row = KeyStorage(n=str(public_key.n), g=str(public_key.g), p=str(private_key.p), q=str(private_key.q))
            db.session.add(row)

        db.session.commit()

    except SQLAlchemyError as e:
        db.session.rollback()
        print(f"Errore durante il salvataggio delle chiavi: {e}")
        raise


def get_key(app):
    with app.app_context():
        row = KeyStorage.query.first()
        if row:
            n = int(row.n)
            p = int(row.p)
            q = int(row.q)
            public_key = paillier.PaillierPublicKey(n)
            private_key = paillier.PaillierPrivateKey(public_key, p, q)
            return public_key, private_key
        else:
            new_key(app)
            row = KeyStorage.query.first()
            n = int(row.n)
            p = int(row.p)
            q = int(row.q)
            public_key = paillier.PaillierPublicKey(n)
            private_key = paillier.PaillierPrivateKey(public_key, p, q)
            return public_key, private_key
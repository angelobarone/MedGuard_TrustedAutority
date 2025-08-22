import base64
import hashlib
import json
from Crypto.Cipher import AES
from flask import Flask, request, jsonify
from flask_cors import CORS
import keyStorage
import userModels
from userModels import validate_user
from tokenManager import token_manager
from extensions import db

app = Flask(__name__)
CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///thrusted.db'  # database SQLite in un file locale
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)
with app.app_context():
    db.create_all()
userModels.check_database(app)

#Generazione chiavi
public, private = keyStorage.get_key(app)

#PRIMA DI INVIARE, LA CHIAVE VIENE SERIALIZZATA
def serialize_public_key():
    return {
        "n": str(public.n),
        "g": str(public.g)
    }

#LA CHIAVE PRIVATA VIENE CRIPTATA CON AES USANDO IL TOKEN TEMPORANEO COME CIPHER KEY SIMMETRICA
def serialize_private_key():
    return {
        "n": str(public.n),
        "g": str(public.g),
        "p": str(private.p),
        "q": str(private.q)
    }

def derive_key_from_token(token: str) -> bytes:
    return hashlib.sha256(token.encode()).digest()

def encrypt_key_with_token(data: dict, token: str) -> dict:
    key = derive_key_from_token(token)
    cipher = AES.new(key, AES.MODE_GCM)
    plaintext = json.dumps(data).encode()
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return {
        "nonce": base64.b64encode(cipher.nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "tag": base64.b64encode(tag).decode()
    }

@app.route('/getPublicKey', methods=['POST'])
def pubkey():
    try:
        if not request.is_json:
            return jsonify({"error": "Richiesta non in formato JSON"}), 400

        data = request.get_json()
        username = data.get('username')

        if not username:
            return jsonify({"error": "Username mancante"}), 400

        return jsonify(serialize_public_key()), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/getPrivateKey', methods=['POST'])
def privkey():
    try:
        if not request.is_json:
            return jsonify({"error": "Richiesta non in formato JSON"}), 400

        data = request.get_json()
        username = data.get('username')
        token = data.get('token')
        user_id = validate_user(app, username)

        if user_id:
            if token_manager.verify_token(token):
                clear_key = serialize_private_key()
                enc_key = encrypt_key_with_token(clear_key, token)
                return jsonify(enc_key), 200
            else:
                return jsonify({"error": "Token non valido"}), 401
        else:
            return jsonify({"error": "Username mancante"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/addAuthUser', methods=['POST'])
def addauthuser():
    data = request.get_json()
    userModels.create_user(app, data.get("username"), data.get("password"))
    return jsonify({"message": "Utente creato correttamente."})

@app.route('/setToken', methods=['POST'])
def settoken():
    data = request.get_json()
    username = data.get("username")
    user_id = validate_user(app, username)
    if user_id:
        token = token_manager.generate_token(user_id)
        return jsonify({"success": True, "token": token})
    else:
        return jsonify({"error": "Utente non valido."}), 401

if __name__ == "__main__":
    app.run(port=5001)
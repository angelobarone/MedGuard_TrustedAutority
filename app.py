import hashlib

from flask import Flask, request, jsonify
from phe import paillier
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

import userModels
from userModels import validate_user

app = Flask(__name__)
userModels.check_database()
public, private = paillier.generate_paillier_keypair()

@app.route('/getPublicKey', methods=['GET'])
def pubkey():
    return jsonify({"success": True, "public_key": public})

@app.route('/getPrivateKey', methods=['POST'])
def privkey():
    username = request.get_json().get("username")
    password = validate_user(username)
    if password:
        salt = hashlib.sha256(username.encode()).digest()
        key = PBKDF2(password, salt, dkLen=32, count=100_000)
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(private)
        nonce = cipher.nonce
        return jsonify({"success": True, "ciphertext": base64.b64encode(ciphertext).decode(), "tag": base64.b64encode(tag).decode(), "nonce": base64.b64encode(nonce).decode()})
    else:
        return None

@app.route('/addAuthUser', methods=['POST'])
def addauthuser():
    data = request.get_json()
    userModels.create_user(data.get("username"), data.get("password"))
    return jsonify({"message": "Utente creato correttamente."})

if __name__ == "__main__":
    app.run(port=5001)
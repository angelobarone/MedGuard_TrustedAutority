import hashlib
import json
import pickle

from flask import Flask, request, jsonify, Response
from flask_cors import CORS
from phe import paillier
from math import gcd

import userModels


app = Flask(__name__)
CORS(app)
userModels.check_database()

#Generazione chiavi
public, private = paillier.generate_paillier_keypair()

#PRIMA DI INVIARE, LA CHIAVE VIENE SERIALIZZATA
def serialize_public_key():
    return {
        "n": str(public.n),
        "g": str(public.g)
    }

def serialize_private_key():
    return {
        "n": str(public.n),
        "g": str(public.g),
        "p": str(private.p),
        "q": str(private.q)
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

        if not username:
            return jsonify({"error": "Username mancante"}), 400

        return jsonify(serialize_private_key()), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/addAuthUser', methods=['POST'])
def addauthuser():
    data = request.get_json()
    userModels.create_user(data.get("username"), data.get("password"))
    return jsonify({"message": "Utente creato correttamente."})

if __name__ == "__main__":
    app.run(port=5001)
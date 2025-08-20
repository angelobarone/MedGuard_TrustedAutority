import os
import secrets
from datetime import datetime, timedelta
import hmac
import hashlib
from typing import Optional, Tuple, Dict


class TokenManager:

    def __init__(self):
        self.secret_key = secrets.token_bytes(32)
        self.tokens: Dict[str, Tuple[int, datetime]] = {}

    def generate_token(self, user_id: int, expires_hours: int = 2) -> str:
        #Cleanup di routine
        self.cleanup_expired_tokens()

        """Genera un nuovo token per l'utente specificato."""
        # Parte randomica
        random_part = secrets.token_urlsafe(24)
        created = datetime.now()
        timestamp = int(created.timestamp())

        # Firma HMAC
        data = f"{user_id}{random_part}{timestamp}"

        if isinstance(self.secret_key, str):
            key = self.secret_key.encode()
        else:
            key = self.secret_key

        signature = hmac.new(
            key,
            data.encode(),
            hashlib.sha256
        ).hexdigest()[:16]

        # Token completo
        token = f"{user_id}|{random_part}|{timestamp}|{signature}"

        # Salvo con scadenza
        expiration = created + timedelta(hours=expires_hours)
        self.tokens[token] = (user_id, expiration)

        return token

    def verify_token(self, token: str) -> bool:
        if not token or token not in self.tokens:
            return False

        # Cerco le info sul token nel dizionario
        user_id, expiration = self.tokens[token]

        # Controllo la scadenza del token
        if datetime.now() > expiration:
            self._remove_token(token)
            return False
        else:
            # Verifico l'integrità del token
            if not self._verify_token_integrity(token, user_id):
                self._remove_token(token)
                return False
            else:
                return True

    def revoke_token(self, token: str) -> bool:
        if token in self.tokens:
            del self.tokens[token]
            return True
        return False

    def cleanup_expired_tokens(self) -> int:
        now = datetime.now()
        expired_tokens = [
            token for token, (_, expiration) in self.tokens.items()
            if now > expiration
        ]

        for token in expired_tokens:
            del self.tokens[token]

        return len(expired_tokens)

    def _verify_token_integrity(self, token: str, expected_user_id: int) -> bool:
        """Verifica l'integrità del token usando HMAC"""
        try:
            parts = token.split('|')
            if len(parts) != 4:
                return False

            user_id_str, random_part, timestamp_str, received_signature = parts

            if int(user_id_str) != expected_user_id:
                return False

            data = f"{user_id_str}{random_part}{timestamp_str}"

            if isinstance(self.secret_key, str):
                key = self.secret_key.encode()
            else:
                key = self.secret_key

            expected_signature = hmac.new(
                key,
                data.encode(),
                hashlib.sha256
            ).hexdigest()[:16]

            # DEBUG
            print(f"🔍 Data verificata: '{data}'")
            print(f"🔍 Firma ricevuta: {received_signature}")
            print(f"🔍 Firma attesa: {expected_signature}")

            # Confronto sicuro
            return secrets.compare_digest(received_signature, expected_signature)

        except (ValueError, IndexError):
            return False

    def _remove_token(self, token: str):
        """Rimuove un token in modo sicuro"""
        if token in self.tokens:
            del self.tokens[token]


token_manager = TokenManager()
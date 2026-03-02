"""PII encryption utilities using Fernet symmetric encryption.
All user credentials (AWS keys, Azure secrets, OpenAI keys) are encrypted
in-memory before being used in any processing pipeline."""

import hashlib
from cryptography.fernet import Fernet


class CredentialEncryptor:
    """Session-scoped encryption for user PII data."""

    def __init__(self):
        self._key = Fernet.generate_key()
        self._cipher = Fernet(self._key)

    def encrypt(self, plaintext: str) -> str:
        """Encrypt a plaintext string and return base64-encoded ciphertext."""
        if not plaintext:
            return ""
        return self._cipher.encrypt(plaintext.encode()).decode()

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt a base64-encoded ciphertext and return plaintext."""
        if not ciphertext:
            return ""
        return self._cipher.decrypt(ciphertext.encode()).decode()

    def mask(self, value: str, visible_chars: int = 4) -> str:
        """Return a masked version of the value showing only last N chars."""
        if not value or len(value) <= visible_chars:
            return "****"
        return "*" * (len(value) - visible_chars) + value[-visible_chars:]

    @staticmethod
    def fingerprint(key: str) -> str:
        """Generate a short SHA-256 fingerprint for audit logging."""
        return hashlib.sha256(key.encode()).hexdigest()[:12]

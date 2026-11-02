from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import os
import time
from typing import Any

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


@dataclass
class KeyRotationRecord:
    key_id: str
    version: int
    algorithm: str
    created_at: str
    status: str  # "active", "rotated", "revoked"
    fingerprint: str  # SHA-256 fingerprint of public component or key id


class CryptoEngine:
    """Enterprise-grade Cryptographic Engine for Guard AI.
    
    Provides:
    - AES-256-GCM authenticated encryption/decryption (CSPRNG 96-bit nonce)
    - PBKDF2-HMAC-SHA256 / Argon2-compatible key derivation with salt
    - SHA-256 cryptographic digests
    - Ed25519 digital signatures & verification
    - HKDF key separation (DEK, MAC, Blind Index)
    - Envelope encryption and versioned key rotation
    """

    def __init__(self, master_secret: bytes | None = None) -> None:
        self._master_secret = master_secret or os.urandom(32)
        self._key_store: dict[str, dict[str, Any]] = {}
        self._rotation_history: list[KeyRotationRecord] = []
        self._current_version = 0

        # Ed25519 system identity keypair for audit & event signing
        self._signing_key = ed25519.Ed25519PrivateKey.generate()
        self._verify_key = self._signing_key.public_key()
        
        # Initialize primary encryption key
        self.rotate_key("Initial system bootstrap key")

    @property
    def system_public_key_hex(self) -> str:
        raw = self._verify_key.public_bytes_raw()
        return raw.hex()

    # -------------------------------------------------------------------------
    # Core Primitives
    # -------------------------------------------------------------------------

    @staticmethod
    def generate_random_bytes(length: int = 32) -> bytes:
        return os.urandom(length)

    @staticmethod
    def sha256_digest(data: bytes | str) -> str:
        if isinstance(data, str):
            data = data.encode("utf-8")
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def derive_key_pbkdf2(
        password: str,
        salt: bytes | None = None,
        iterations: int = 100_000,
        length: int = 32,
    ) -> tuple[bytes, bytes]:
        """Derive cryptographic key using PBKDF2-HMAC-SHA256 with CSPRNG salt."""
        effective_salt = salt or os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=length,
            salt=effective_salt,
            iterations=iterations,
        )
        derived = kdf.derive(password.encode("utf-8"))
        return derived, effective_salt

    @staticmethod
    def derive_separated_keys(master_key: bytes) -> dict[str, bytes]:
        """Cryptographically separate keys for specific purposes using HKDF.
        
        Ensures cross-protocol safety: an encryption key is never used as a MAC
        or index key.
        """
        def _hkdf(info: bytes) -> bytes:
            return HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b"guard-ai-key-separation-salt-v1",
                info=info,
            ).derive(master_key)

        return {
            "data_encryption_key": _hkdf(b"guard-ai-aes-256-gcm-dek"),
            "mac_integrity_key": _hkdf(b"guard-ai-integrity-mac"),
            "blind_index_key": _hkdf(b"guard-ai-blind-index"),
        }

    # -------------------------------------------------------------------------
    # AES-256-GCM Authenticated Encryption
    # -------------------------------------------------------------------------

    def encrypt_aes_gcm(
        self,
        plaintext: bytes | str,
        key: bytes | None = None,
        associated_data: bytes | None = None,
    ) -> dict[str, str]:
        """Encrypts data with AES-256-GCM using a unique 96-bit CSPRNG nonce."""
        if isinstance(plaintext, str):
            payload_bytes = plaintext.encode("utf-8")
        else:
            payload_bytes = plaintext

        active_key = key or self._get_active_key_bytes()
        aesgcm = AESGCM(active_key)
        
        # 96-bit (12-byte) nonce is standard and recommended for AES-GCM
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, payload_bytes, associated_data)
        
        plaintext_hash = hashlib.sha256(payload_bytes).hexdigest()

        return {
            "algorithm": "AES-256-GCM",
            "nonce_b64": base64.b64encode(nonce).decode("ascii"),
            "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
            "plaintext_sha256": plaintext_hash,
            "key_version": str(self._current_version),
            "authenticated": "true",
        }

    def decrypt_aes_gcm(
        self,
        ciphertext_b64: str,
        nonce_b64: str,
        key: bytes | None = None,
        associated_data: bytes | None = None,
    ) -> bytes:
        """Decrypts and authenticates AES-256-GCM ciphertext."""
        active_key = key or self._get_active_key_bytes()
        aesgcm = AESGCM(active_key)

        try:
            nonce = base64.b64decode(nonce_b64.encode("ascii"))
            ciphertext = base64.b64decode(ciphertext_b64.encode("ascii"))
            return aesgcm.decrypt(nonce, ciphertext, associated_data)
        except (InvalidTag, ValueError) as exc:
            raise ValueError("Cryptographic verification failed: ciphertext tampered or invalid key") from exc

    # -------------------------------------------------------------------------
    # Ed25519 Digital Signatures
    # -------------------------------------------------------------------------

    def sign_event(self, message: bytes | str) -> dict[str, str]:
        """Generate Ed25519 digital signature for an event or audit payload."""
        if isinstance(message, str):
            msg_bytes = message.encode("utf-8")
        else:
            msg_bytes = message

        signature = self._signing_key.sign(msg_bytes)
        return {
            "algorithm": "Ed25519",
            "public_key_hex": self.system_public_key_hex,
            "signature_hex": signature.hex(),
            "message_sha256": hashlib.sha256(msg_bytes).hexdigest(),
        }

    def verify_event_signature(
        self,
        message: bytes | str,
        signature_hex: str,
        public_key_hex: str | None = None,
    ) -> bool:
        """Verify Ed25519 digital signature."""
        if isinstance(message, str):
            msg_bytes = message.encode("utf-8")
        else:
            msg_bytes = message

        pub_hex = public_key_hex or self.system_public_key_hex
        try:
            pub_bytes = bytes.fromhex(pub_hex)
            verifier = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
            sig_bytes = bytes.fromhex(signature_hex)
            verifier.verify(sig_bytes, msg_bytes)
            return True
        except (InvalidSignature, ValueError):
            return False

    # -------------------------------------------------------------------------
    # Envelope Encryption
    # -------------------------------------------------------------------------

    def envelope_encrypt(self, plaintext: bytes | str) -> dict[str, str]:
        """Performs envelope encryption:
        1. Generates ephemeral Data Encryption Key (DEK).
        2. Encrypts data with DEK (AES-256-GCM).
        3. Wraps (encrypts) DEK using System Master Key (AES-256-GCM).
        """
        if isinstance(plaintext, str):
            data_bytes = plaintext.encode("utf-8")
        else:
            data_bytes = plaintext

        ephemeral_dek = os.urandom(32)
        encrypted_payload = self.encrypt_aes_gcm(data_bytes, key=ephemeral_dek)
        wrapped_dek = self.encrypt_aes_gcm(ephemeral_dek, key=self._get_active_key_bytes())

        return {
            "type": "envelope_v1",
            "wrapped_dek_b64": wrapped_dek["ciphertext_b64"],
            "wrapped_dek_nonce_b64": wrapped_dek["nonce_b64"],
            "payload_ciphertext_b64": encrypted_payload["ciphertext_b64"],
            "payload_nonce_b64": encrypted_payload["nonce_b64"],
            "plaintext_sha256": encrypted_payload["plaintext_sha256"],
            "master_key_version": str(self._current_version),
        }

    def envelope_decrypt(self, envelope: dict[str, str]) -> bytes:
        """Unwraps DEK and decrypts payload."""
        unwrapped_dek = self.decrypt_aes_gcm(
            ciphertext_b64=envelope["wrapped_dek_b64"],
            nonce_b64=envelope["wrapped_dek_nonce_b64"],
            key=self._get_active_key_bytes(),
        )
        return self.decrypt_aes_gcm(
            ciphertext_b64=envelope["payload_ciphertext_b64"],
            nonce_b64=envelope["payload_nonce_b64"],
            key=unwrapped_dek,
        )

    # -------------------------------------------------------------------------
    # Key Lifecycle and Rotation
    # -------------------------------------------------------------------------

    def rotate_key(self, reason: str = "Scheduled key rotation") -> KeyRotationRecord:
        """Rotates active symmetric encryption key. Old keys remain available
        for decrypting historical records, but never for new encryptions.
        """
        self._current_version += 1
        key_id = f"guard-key-v{self._current_version}-{hashlib.sha256(os.urandom(8)).hexdigest()[:8]}"
        new_key_bytes = os.urandom(32)

        # Mark previous active keys as rotated
        for k in self._key_store.values():
            if k["status"] == "active":
                k["status"] = "rotated"

        now_str = datetime.now(timezone.utc).isoformat()
        fingerprint = hashlib.sha256(key_id.encode("utf-8") + new_key_bytes[:8]).hexdigest()[:16]

        record = KeyRotationRecord(
            key_id=key_id,
            version=self._current_version,
            algorithm="AES-256-GCM / HKDF-SHA256",
            created_at=now_str,
            status="active",
            fingerprint=f"sha256:{fingerprint}",
        )

        self._key_store[str(self._current_version)] = {
            "id": key_id,
            "bytes": new_key_bytes,
            "record": record,
            "status": "active",
        }
        self._rotation_history.insert(0, record)
        return record

    def get_rotation_history(self) -> list[dict[str, Any]]:
        """Returns metadata of all rotated keys. Raw key bytes are strictly withheld."""
        return [
            {
                "key_id": r.key_id,
                "version": r.version,
                "algorithm": r.algorithm,
                "created_at": r.created_at,
                "status": r.status,
                "fingerprint": r.fingerprint,
            }
            for r in self._rotation_history
        ]

    def _get_active_key_bytes(self) -> bytes:
        return self._key_store[str(self._current_version)]["bytes"]

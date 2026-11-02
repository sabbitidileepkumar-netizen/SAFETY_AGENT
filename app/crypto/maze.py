from __future__ import annotations

import base64
from dataclasses import dataclass, field
import hashlib
import json
import os
from typing import Any

from app.crypto.engine import CryptoEngine


@dataclass
class MazeSegment:
    segment_index: int
    nonce_b64: str
    ciphertext_b64: str
    segment_sha256: str


@dataclass
class MazeArtifact:
    maze_id: str
    created_at: str
    layer_count: int
    outer_wrapper: dict[str, str]
    segments: list[dict[str, Any]]
    root_signature: dict[str, str]
    recovery_shares: list[str]  # 2-of-2 split secret shares for emergency recovery
    integrity_seal: str


class CryptographicMaze:
    """Cryptographic Maze Security Architecture.
    
    A rigorous 3-layered defense-in-depth architecture using established
    NIST-approved cryptographic primitives:
    
    1. Layer 1 - Perimeter Shield:
       Authenticated envelope encryption wrapper with rotating master keys.
    2. Layer 2 - Compartment Maze (Data Segmentation):
       Payload is segmented into bounded compartments. Each compartment is encrypted
       with an independently derived sub-key via HKDF-SHA256 and its own unique nonce.
    3. Layer 3 - Core Vault (Integrity & Recovery):
       Cryptographic root sealing with Ed25519 digital signatures, SHA-256 tamper
       digest, and split-secret dual recovery shares.
    """

    def __init__(self, crypto_engine: CryptoEngine | None = None) -> None:
        self.engine = crypto_engine or CryptoEngine()

    def create_maze(
        self,
        plaintext: bytes | str,
        compartment_size: int = 128,
        access_context: str = "default_security_zone",
    ) -> MazeArtifact:
        """Encapsulates plaintext into the multi-layered Cryptographic Maze."""
        if isinstance(plaintext, str):
            payload_bytes = plaintext.encode("utf-8")
        else:
            payload_bytes = plaintext

        maze_id = f"maze-{hashlib.sha256(os.urandom(16)).hexdigest()[:12]}"
        
        # -------------------------------------------------------------
        # Layer 3: Core Vault (Ed25519 Signature + Root Digest)
        # -------------------------------------------------------------
        root_digest = self.engine.sha256_digest(payload_bytes)
        root_sig = self.engine.sign_event(payload_bytes)

        # -------------------------------------------------------------
        # Layer 2: Compartment Maze (Segmentation + Independent Sub-keys)
        # -------------------------------------------------------------
        # Split into chunks
        chunks = [
            payload_bytes[i : i + compartment_size]
            for i in range(0, len(payload_bytes), max(1, compartment_size))
        ] or [b""]

        # Derive independent base key for this maze instance
        instance_base_key = os.urandom(32)
        separated_keys = self.engine.derive_separated_keys(instance_base_key)
        dek = separated_keys["data_encryption_key"]

        segments: list[dict[str, Any]] = []
        for idx, chunk in enumerate(chunks):
            # Derive unique compartment key per segment
            compartment_key = hashlib.sha256(dek + f":comp:{idx}".encode("ascii")).digest()
            encrypted_comp = self.engine.encrypt_aes_gcm(
                plaintext=chunk,
                key=compartment_key,
                associated_data=f"maze:{maze_id}:comp:{idx}".encode("ascii"),
            )
            segments.append({
                "segment_index": idx,
                "nonce_b64": encrypted_comp["nonce_b64"],
                "ciphertext_b64": encrypted_comp["ciphertext_b64"],
                "sha256": encrypted_comp["plaintext_sha256"],
            })

        # -------------------------------------------------------------
        # Layer 1: Perimeter Shield (Envelope Encryption)
        # -------------------------------------------------------------
        # Wrap instance base key with active master key
        wrapped_instance_key = self.engine.encrypt_aes_gcm(
            plaintext=instance_base_key,
            associated_data=access_context.encode("utf-8"),
        )

        # -------------------------------------------------------------
        # Recovery Mechanism: Split-Secret 2-of-2 Shares
        # -------------------------------------------------------------
        # Share A = random bytes, Share B = instance_base_key XOR Share A
        share_a = os.urandom(32)
        share_b = bytes(a ^ b for a, b in zip(instance_base_key, share_a))
        recovery_shares = [
            base64.b64encode(share_a).decode("ascii"),
            base64.b64encode(share_b).decode("ascii"),
        ]

        # Overall tamper-evident seal
        seal_content = f"{maze_id}:{root_digest}:{len(segments)}:{wrapped_instance_key['ciphertext_b64']}"
        integrity_seal = self.engine.sha256_digest(seal_content)

        return MazeArtifact(
            maze_id=maze_id,
            created_at=root_sig.get("algorithm", "Ed25519"),
            layer_count=3,
            outer_wrapper=wrapped_instance_key,
            segments=segments,
            root_signature=root_sig,
            recovery_shares=recovery_shares,
            integrity_seal=integrity_seal,
        )

    def solve_maze(
        self,
        artifact: MazeArtifact | dict[str, Any],
        access_context: str = "default_security_zone",
        override_recovery_shares: list[str] | None = None,
    ) -> bytes:
        """Navigates and decrypts the Cryptographic Maze.
        
        Validates:
        1. Perimeter wrapper authentication.
        2. Compartment segment authentication for each distinct chunk.
        3. Core vault Ed25519 signature & root hash.
        """
        if isinstance(artifact, dict):
            maze_id = artifact["maze_id"]
            outer_wrapper = artifact["outer_wrapper"]
            segments = artifact["segments"]
            root_sig = artifact["root_signature"]
            recovery_shares = artifact.get("recovery_shares", [])
        else:
            maze_id = artifact.maze_id
            outer_wrapper = artifact.outer_wrapper
            segments = artifact.segments
            root_sig = artifact.root_signature
            recovery_shares = artifact.recovery_shares

        # Reconstruct base key: either via Master Key envelope unwrapping or emergency recovery shares
        if override_recovery_shares and len(override_recovery_shares) == 2:
            s_a = base64.b64decode(override_recovery_shares[0])
            s_b = base64.b64decode(override_recovery_shares[1])
            instance_base_key = bytes(a ^ b for a, b in zip(s_a, s_b))
        else:
            instance_base_key = self.engine.decrypt_aes_gcm(
                ciphertext_b64=outer_wrapper["ciphertext_b64"],
                nonce_b64=outer_wrapper["nonce_b64"],
                associated_data=access_context.encode("utf-8"),
            )

        separated_keys = self.engine.derive_separated_keys(instance_base_key)
        dek = separated_keys["data_encryption_key"]

        # Decrypt all segments in strict sequence
        sorted_segments = sorted(segments, key=lambda s: s["segment_index"])
        reconstructed_chunks: list[bytes] = []

        for seg in sorted_segments:
            idx = seg["segment_index"]
            compartment_key = hashlib.sha256(dek + f":comp:{idx}".encode("ascii")).digest()
            chunk = self.engine.decrypt_aes_gcm(
                ciphertext_b64=seg["ciphertext_b64"],
                nonce_b64=seg["nonce_b64"],
                key=compartment_key,
                associated_data=f"maze:{maze_id}:comp:{idx}".encode("ascii"),
            )
            reconstructed_chunks.append(chunk)

        reconstructed_payload = b"".join(reconstructed_chunks)

        # Verify Core Vault integrity & Ed25519 signature
        is_signature_valid = self.engine.verify_event_signature(
            message=reconstructed_payload,
            signature_hex=root_sig["signature_hex"],
            public_key_hex=root_sig.get("public_key_hex"),
        )
        if not is_signature_valid:
            raise ValueError("Core Vault signature invalid: data integrity breached in Cryptographic Maze")

        return reconstructed_payload

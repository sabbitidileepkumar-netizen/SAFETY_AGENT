from __future__ import annotations

from typing import Any

from app.agents.base import AgentBus, AgentStatus, SecurityAgent, SecurityEvent
from app.crypto.engine import CryptoEngine
from app.crypto.maze import CryptographicMaze, MazeArtifact


class DefenceAI(SecurityAgent):
    """Defence AI: Data Protection, Cryptography & Session Hygiene Agent.
    
    Responsibilities:
    - Executes authenticated encryption and envelope protection.
    - Manages the Cryptographic Maze 3-layered defense system.
    - Enforces zero-residual data policies (scrubs temporary memory/cache).
    - Verifies file integrity and cryptographic seals.
    """

    def __init__(self, bus: AgentBus, crypto_engine: CryptoEngine | None = None) -> None:
        super().__init__(name="Defence AI", role="Cryptographic Shield & Access Boundaries", bus=bus)
        self.engine = crypto_engine or CryptoEngine()
        self.maze = CryptographicMaze(self.engine)
        self.encryptions_performed = 0
        self.decryptions_performed = 0
        self.cleanups_verified = 0

    def protect_payload_maze(self, plaintext: bytes | str, compartment_size: int = 128) -> MazeArtifact:
        """Encapsulate data through Cryptographic Maze 3-layer security."""
        self.status = AgentStatus.DEFENDING
        self.encryptions_performed += 1

        artifact = self.maze.create_maze(plaintext, compartment_size=compartment_size)

        self.log_event(
            event_type="CRYPTOGRAPHIC_MAZE_SEALED",
            risk_level="Safe",
            details={
                "maze_id": artifact.maze_id,
                "layer_count": artifact.layer_count,
                "segment_count": len(artifact.segments),
                "integrity_seal": artifact.integrity_seal,
            },
        )

        self.telemetry = {
            "encryptions_performed": self.encryptions_performed,
            "decryptions_performed": self.decryptions_performed,
            "cleanups_verified": self.cleanups_verified,
            "system_pubkey": self.engine.system_public_key_hex[:16],
        }
        self.status = AgentStatus.MONITORING
        return artifact

    def solve_maze_payload(
        self,
        artifact: MazeArtifact | dict[str, Any],
        recovery_shares: list[str] | None = None,
    ) -> bytes:
        """Decrypts and authenticates Cryptographic Maze payload."""
        self.status = AgentStatus.DEFENDING
        self.decryptions_performed += 1

        try:
            decrypted = self.maze.solve_maze(artifact, override_recovery_shares=recovery_shares)
            self.log_event(
                event_type="CRYPTOGRAPHIC_MAZE_VERIFIED",
                risk_level="Safe",
                details={"status": "Integrity and Ed25519 signature verified"},
            )
            self.status = AgentStatus.MONITORING
            return decrypted
        except Exception as exc:
            self.log_event(
                event_type="CRYPTOGRAPHIC_INTEGRITY_BREACH",
                risk_level="Danger",
                details={"error": str(exc)},
            )
            self.status = AgentStatus.ALERTING
            raise

    def record_cleanup(self, target: str, scrubbed_items: int) -> None:
        """Logs verified cryptographic wipe of temporary session cache."""
        self.cleanups_verified += 1
        self.log_event(
            event_type="SESSION_SCRUBBED",
            risk_level="Safe",
            details={"target": target, "scrubbed_items": scrubbed_items},
        )

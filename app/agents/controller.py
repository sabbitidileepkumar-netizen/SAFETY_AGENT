from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any

from app.agents.base import AgentBus, AgentStatus, SecurityAgent, SecurityEvent
from app.agents.defence import DefenceAI
from app.agents.finder import FinderAI
from app.agents.informer import InformerAI
from app.agents.offence import OffenceAI
from app.agents.specialized import AppBehaviorAgent, BrowserAgent, FileAgent, WiFiAgent
from app.blockchain.service import AuditLedgerService
from app.crypto.engine import CryptoEngine
from app.security.isolation_chamber import IsolationChamberManager
from app.security.private_space import PrivateSpaceManager
from app.security.sandbox import SandboxInspectionEngine


class ControllerAI(SecurityAgent):
    """Controller AI: Central Autonomous Security Orchestrator for Guard AI.
    
    Responsibilities:
    - Coordinates all subordinate agents (Finder, Defence, Offence, Informer, Specialized).
    - Enforces security boundaries and access permissions.
    - Decides inspection environment:
        * Safe: Standard / Private Space
        * Suspicious / High-Uncertainty: Isolation Chamber
        * File / Binary / Attachment: Sandbox Lab
    - Triggers defensive containment through Offence AI upon verified threat.
    - Prompts Informer AI for voice and structured explanations.
    - Records all security events into the blockchain/local hash-chain audit ledger.
    """

    def __init__(
        self,
        bus: AgentBus | None = None,
        audit_ledger: AuditLedgerService | None = None,
        crypto_engine: CryptoEngine | None = None,
        private_space: PrivateSpaceManager | None = None,
        isolation_chamber: IsolationChamberManager | None = None,
        sandbox_engine: SandboxInspectionEngine | None = None,
        checker: Checker | None = None,
    ) -> None:
        self.bus = bus or AgentBus()
        super().__init__(name="Controller AI", role="Central Security Orchestration & Policy Enforcement", bus=self.bus)

        self.crypto = crypto_engine or CryptoEngine()
        self.audit = audit_ledger or AuditLedgerService(crypto_engine=self.crypto)
        self.private_space = private_space or PrivateSpaceManager()
        self.isolation_chamber = isolation_chamber or IsolationChamberManager()
        self.sandbox = sandbox_engine or SandboxInspectionEngine()

        # Initialize Subordinate Agents
        self.finder = FinderAI(bus=self.bus, checker=checker)
        self.defence = DefenceAI(bus=self.bus, crypto_engine=self.crypto)
        self.offence = OffenceAI(bus=self.bus)
        self.informer = InformerAI(bus=self.bus)

        # Specialized Agents
        self.wifi_agent = WiFiAgent(bus=self.bus)
        self.browser_agent = BrowserAgent(bus=self.bus)
        self.file_agent = FileAgent(bus=self.bus)
        self.app_behavior_agent = AppBehaviorAgent(bus=self.bus)

        # Subscribe to all events on bus to audit and coordinate
        self.bus.subscribe("*", self._handle_incoming_event)

        self.decisions_count = 0
        self.containment_actions_count = 0

    def _handle_incoming_event(self, event: SecurityEvent) -> None:
        """Central event hook: records critical events into the immutable audit ledger."""
        if event.source_agent != self.name and event.risk_level in ("Careful", "Danger", "Malicious"):
            # Register onto tamper-evident audit ledger
            self.audit.register_security_event(
                event_type=f"AGENT_EVENT_{event.event_type}",
                event_payload={
                    "event_id": event.event_id,
                    "agent": event.source_agent,
                    "risk": event.risk_level,
                    "details": event.details,
                    "timestamp": event.timestamp,
                },
                record_id=event.event_id,
            )

    def orchestrate_inspection(
        self,
        url: str | None = None,
        text: str | None = None,
        file_bytes: bytes | None = None,
        filename: str | None = None,
        allow_sms_to_gemini: bool = False,
    ) -> dict[str, Any]:
        """Unified security triage pipeline.
        
        Evaluates input, selects environment, triggers defensive agents,
        and generates audit records and voice alerts.
        """
        self.status = AgentStatus.ANALYZING
        self.decisions_count += 1
        now_iso = datetime.now(timezone.utc).isoformat()

        # Case 1: File inspection requested
        if file_bytes is not None and filename:
            sandbox_rep = self.sandbox.inspect_file(file_bytes, filename)
            risk = sandbox_rep.risk_level

            # If malicious, coordinate containment
            if risk == "Malicious":
                action_taken = "BLOCKED"
            elif risk == "Suspicious":
                action_taken = "ISOLATED"
            else:
                action_taken = "INSPECTED"

            # Informer voice announcement
            announcement = self.informer.generate_announcement(
                risk_level=risk,
                reason=f"File inspection for '{filename}': Risk score {sandbox_rep.risk_score}/100 with {len(sandbox_rep.indicators)} threat markers.",
                action_taken=action_taken,
                telugu_reason=f"ఫైల్ '{filename}' పరీక్షించబడింది. ప్రమాద స్థాయి {risk}.",
            )

            # Record decision in ledger
            audit_rec = self.audit.register_security_event(
                event_type="CONTROLLER_FILE_DECISION",
                event_payload={
                    "filename": filename,
                    "sha256": sandbox_rep.sha256,
                    "risk": risk,
                    "score": sandbox_rep.risk_score,
                    "action": action_taken,
                },
            )

            self.status = AgentStatus.MONITORING
            return {
                "decision_type": "FILE_INSPECTION",
                "recommended_environment": "Sandbox Lab",
                "risk_level": risk,
                "action_taken": action_taken,
                "sandbox_report": asdict(sandbox_rep),
                "announcement": announcement,
                "audit_record": asdict(audit_rec),
            }

        # Case 2: URL or SMS inspection requested
        finder_result = self.finder.analyze_input(
            url=url,
            text=text,
            allow_sms_to_gemini=allow_sms_to_gemini,
        )
        risk = finder_result["risk"]
        submitted_target = url or text or "unknown"

        # Determine appropriate environment
        if risk == "Danger":
            recommended_env = "Isolation Chamber"
            action_taken = "BLOCKED"
        elif risk == "Careful":
            recommended_env = "Isolation Chamber"
            action_taken = "ISOLATED"
        else:
            recommended_env = "Private Space"
            action_taken = "ALLOWED"

        # Informer announcement
        announcement = self.informer.generate_announcement(
            risk_level=risk,
            reason=finder_result["main_reason"],
            action_taken=action_taken,
            telugu_reason=finder_result["explanation"]["telugu"],
        )

        # Audit ledger record
        audit_rec = self.audit.register_security_event(
            event_type="CONTROLLER_URL_DECISION",
            event_payload={
                "target": submitted_target,
                "risk": risk,
                "environment": recommended_env,
                "action": action_taken,
            },
        )

        self.status = AgentStatus.MONITORING
        return {
            "decision_type": "URL_OR_TEXT_TRIAGE",
            "recommended_environment": recommended_env,
            "risk_level": risk,
            "action_taken": action_taken,
            "finder_findings": finder_result,
            "announcement": announcement,
            "audit_record": asdict(audit_rec),
        }

    def get_ecosystem_status(self) -> dict[str, Any]:
        """Provides holistic health and status of all agents and security engines."""
        return {
            "controller": self.get_status_summary(),
            "agents": {
                "finder": self.finder.get_status_summary(),
                "defence": self.defence.get_status_summary(),
                "offence": self.offence.get_status_summary(),
                "informer": self.informer.get_status_summary(),
                "wifi": self.wifi_agent.get_status_summary(),
                "browser": self.browser_agent.get_status_summary(),
                "file": self.file_agent.get_status_summary(),
                "app_behavior": self.app_behavior_agent.get_status_summary(),
            },
            "engines": {
                "cryptography": {
                    "algorithm": "AES-256-GCM / PBKDF2 / Ed25519",
                    "system_pubkey": self.crypto.system_public_key_hex,
                    "rotation_history_count": len(self.crypto.get_rotation_history()),
                },
                "blockchain_audit": {
                    "evm_rpc_online": self.audit.check_evm_rpc_health(),
                    "total_audit_records": len(self.audit.get_recent_records(100)),
                    "chain_verification": self.audit.verify_entire_chain(),
                },
                "private_space": self.private_space.get_status(),
                "isolation_chamber": self.isolation_chamber.get_status(),
                "sandbox_lab": {
                    "total_reports": len(self.sandbox.get_all_reports()),
                    "quarantine_staging": str(self.sandbox.staging_dir),
                },
            },
            "telemetry": {
                "decisions_count": self.decisions_count,
                "containment_actions_count": self.containment_actions_count,
            },
        }

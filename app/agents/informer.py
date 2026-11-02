from __future__ import annotations

from typing import Any

from app.agents.base import AgentBus, AgentStatus, SecurityAgent, SecurityEvent


class InformerAI(SecurityAgent):
    """Informer AI: Threat Explanation, User Communication & Voice Notification Agent.
    
    Responsibilities:
    - Synthesizes user-friendly incident summaries.
    - Generates multi-lingual voice alert payloads (English & Telugu).
    - Explains security decisions: why content was Allowed, Isolated, Inspected, or Blocked.
    - Delivers actionable safe guidance to end-users and non-technical family members.
    """

    TELUGU_RISK_PREFIX = {
        "Safe": "భద్రత నిర్ధారించబడింది:",
        "Careful": "జాగ్రత్త హెచ్చరిక:",
        "Danger": "తీవ్రమైన ప్రమాదం:",
        "Malicious": "హానికరమైన ముప్పు గుర్తించబడింది:",
    }

    def __init__(self, bus: AgentBus) -> None:
        super().__init__(name="Informer AI", role="Threat Explanations & Voice Notifications", bus=bus)
        self.notifications_issued = 0
        self.voice_alerts_generated = 0

    def generate_announcement(
        self,
        risk_level: str,
        reason: str,
        action_taken: str,  # "ALLOWED", "ISOLATED", "INSPECTED", "BLOCKED"
        telugu_reason: str | None = None,
    ) -> dict[str, Any]:
        """Creates structured bilingual explanation and voice speech synthesis parameters."""
        self.status = AgentStatus.ALERTING
        self.notifications_issued += 1
        self.voice_alerts_generated += 1

        # Action explanation
        action_descriptions = {
            "ALLOWED": "Content verified as safe under baseline security rules and permitted to load.",
            "ISOLATED": "Content flagged as unverified or suspicious. Routed to Isolation Chamber with scripts neutralized and network restricted.",
            "INSPECTED": "File payload transferred to Sandbox Lab for deep static analysis, entropy testing, and antivirus signature check.",
            "BLOCKED": "High risk detected! Malicious connection terminated and prevented from reaching your system.",
        }
        action_desc = action_descriptions.get(action_taken, f"Action enforced: {action_taken}")

        # English voice announcement
        voice_en = f"Guard AI Alert. {risk_level} detected. {reason}. Policy action: {action_taken}."

        # Telugu voice announcement
        te_prefix = self.TELUGU_RISK_PREFIX.get(risk_level, "భద్రతా హెచ్చరిక:")
        te_body = telugu_reason or "ఈ లింక్ లేదా ఫైల్ అనుమానాస్పదంగా ఉంది. దయచేసి ఎలాంటి వ్యక్తిగత వివరాలు ఇవ్వకండి."
        voice_te = f"గార్డ్ ఏఐ హెచ్చరిక. {te_prefix} {te_body}"

        speech_payload = {
            "english": {
                "text": voice_en,
                "lang": "en-IN",
                "rate": 0.95,
                "pitch": 1.0,
            },
            "telugu": {
                "text": voice_te,
                "lang": "te-IN",
                "rate": 0.9,
                "pitch": 1.0,
            },
        }

        announcement = {
            "risk_level": risk_level,
            "action_taken": action_taken,
            "action_explanation": action_desc,
            "reason_en": reason,
            "reason_te": te_body,
            "voice": speech_payload,
            "recommended_action": (
                "Do not open untrusted links or share OTPs/passwords."
                if risk_level in ("Danger", "Malicious")
                else "Proceed with standard awareness."
            ),
        }

        self.log_event(
            event_type="VOICE_ALERT_GENERATED",
            risk_level=risk_level,
            details={"voice_summary": voice_en, "action": action_taken},
        )

        self.telemetry = {
            "notifications_issued": self.notifications_issued,
            "voice_alerts_generated": self.voice_alerts_generated,
            "last_alert_level": risk_level,
        }
        self.status = AgentStatus.MONITORING

        return announcement

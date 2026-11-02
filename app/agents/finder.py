from __future__ import annotations

from typing import Any

from app.agents.base import AgentBus, AgentStatus, SecurityAgent, SecurityEvent
from app.checker import Checker
from app.config import Settings
from app.models import CheckRequest, CheckResponse
from app.risk import analyze, extract_urls, normalize_url


class FinderAI(SecurityAgent):
    """Finder AI: Threat Identification, Phishing & URL Reconnaissance Agent.
    
    Responsibilities:
    - Scans incoming URLs, SMS text, and submitted file payloads.
    - Matches lookalikes, Indian financial brand impersonations, and urgency hooks.
    - Routes high-uncertainty or binary payloads to Sandbox Lab for deep inspection.
    """

    def __init__(self, bus: AgentBus, checker: Checker | None = None) -> None:
        super().__init__(name="Finder AI", role="Threat Detection & URL/File Reconnaissance", bus=bus)
        self.checker = checker or Checker(Settings.from_env())
        self.scanned_count = 0
        self.threats_flagged = 0

    def analyze_input(
        self,
        url: str | None = None,
        text: str | None = None,
        allow_sms_to_gemini: bool = False,
    ) -> dict[str, Any]:
        """Triage input URL or SMS message."""
        self.status = AgentStatus.ANALYZING
        self.scanned_count += 1

        request = CheckRequest(url=url, text=text)
        check_result: CheckResponse = self.checker.check(request, allow_sms_to_gemini=allow_sms_to_gemini)

        risk = check_result.risk
        is_threat = risk in ("Careful", "Danger")
        if is_threat:
            self.threats_flagged += 1

        # Check if deep sandbox inspection is warranted
        needs_sandbox = False
        target_candidate = url or (text and extract_urls(text)[0] if extract_urls(text or "") else None)
        if target_candidate:
            try:
                norm_url, _, _ = normalize_url(target_candidate)
                # If target points to downloadable binary or suspicious lookalike, request sandbox
                if any(target_candidate.lower().endswith(ext) for ext in [".exe", ".apk", ".scr", ".zip", ".pdf"]):
                    needs_sandbox = True
            except Exception:
                pass

        details = {
            "risk": check_result.risk,
            "confidence": check_result.confidence,
            "main_reason": check_result.main_reason,
            "signals": [s.model_dump() for s in check_result.signals],
            "explanation": check_result.explanation.model_dump(),
            "needs_sandbox": needs_sandbox,
            "submitted_url": url,
        }

        # Publish event to bus for Controller AI
        self.log_event(
            event_type="URL_ANALYSIS_COMPLETED" if url else "TEXT_ANALYSIS_COMPLETED",
            risk_level=risk,
            details=details,
        )

        self.telemetry = {
            "scanned_count": self.scanned_count,
            "threats_flagged": self.threats_flagged,
            "last_risk_assessed": risk,
        }
        self.status = AgentStatus.MONITORING

        return details

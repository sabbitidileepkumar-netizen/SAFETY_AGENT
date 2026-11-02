from __future__ import annotations

from typing import Any

from app.agents.base import AgentBus, AgentStatus, SecurityAgent


class OffenceAI(SecurityAgent):
    """Reports approved containment demos without changing host state."""

    def __init__(self, bus: AgentBus) -> None:
        super().__init__(name="Offence AI", role="Simulated defensive response", bus=bus)
        self.simulated_actions_count = 0

    def simulate_approved_action(
        self,
        action: str,
        approval_id: str,
        details: dict[str, Any],
    ) -> dict[str, Any]:
        """Record a UI-visible simulation; this method never touches files or networking."""
        self.status = AgentStatus.CONTAINING
        self.simulated_actions_count += 1
        self.telemetry = {
            "mode": "SIMULATED",
            "simulated_actions_count": self.simulated_actions_count,
            "last_action": action,
        }
        self.log_event(
            event_type="SIMULATED_HIGH_IMPACT_ACTION",
            risk_level="Careful",
            details={"action": action, "approval_id": approval_id},
        )
        self.status = AgentStatus.MONITORING
        return {
            "mode": "SIMULATED",
            "action": action,
            "approval_id": approval_id,
            "details": details,
            "message": "SIMULATED only: no host, file, process, or network state was changed.",
        }

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
import threading
from typing import Any, Callable
import uuid


class AgentStatus(str, Enum):
    IDLE = "IDLE"
    MONITORING = "MONITORING"
    ANALYZING = "ANALYZING"
    DEFENDING = "DEFENDING"
    CONTAINING = "CONTAINING"
    ALERTING = "ALERTING"
    DEGRADED = "DEGRADED"


@dataclass
class SecurityEvent:
    event_id: str
    event_type: str
    source_agent: str
    risk_level: str  # "Safe", "Careful", "Danger", "Suspicious", "Malicious"
    details: dict[str, Any]
    timestamp: str
    signature_hex: str = ""
    contained: bool = False


class AgentBus:
    """Central Publish-Subscribe Event Bus for Guard AI Agents."""

    def __init__(self) -> None:
        self._listeners: dict[str, list[Callable[[SecurityEvent], None]]] = {}
        self._event_history: list[SecurityEvent] = []
        self._lock = threading.Lock()

    def subscribe(self, event_type: str, callback: Callable[[SecurityEvent], None]) -> None:
        with self._lock:
            self._listeners.setdefault(event_type, []).append(callback)

    def publish(self, event: SecurityEvent) -> None:
        with self._lock:
            self._event_history.insert(0, event)
            # Retain up to 200 recent events
            if len(self._event_history) > 200:
                self._event_history.pop()

            targets = list(self._listeners.get(event.event_type, [])) + list(self._listeners.get("*", []))

        for target in targets:
            try:
                target(event)
            except Exception as err:
                print(f"[AgentBus Error] Exception dispatching event {event.event_id} to handler: {err}")

    def get_recent_events(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            return [asdict(e) for e in self._event_history[:limit]]


class SecurityAgent:
    """Base class for all Guard AI autonomous agents."""

    def __init__(self, name: str, role: str, bus: AgentBus) -> None:
        self.name = name
        self.role = role
        self.bus = bus
        self.status: AgentStatus = AgentStatus.MONITORING
        self.last_action_time: str = datetime.now(timezone.utc).isoformat()
        self.telemetry: dict[str, Any] = {}

    def log_event(self, event_type: str, risk_level: str, details: dict[str, Any]) -> SecurityEvent:
        event = SecurityEvent(
            event_id=f"evt-{uuid.uuid4().hex[:8]}",
            event_type=event_type,
            source_agent=self.name,
            risk_level=risk_level,
            details=details,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        self.last_action_time = event.timestamp
        self.bus.publish(event)
        return event

    def get_status_summary(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "role": self.role,
            "status": self.status.value,
            "last_action_time": self.last_action_time,
            "telemetry": self.telemetry,
        }

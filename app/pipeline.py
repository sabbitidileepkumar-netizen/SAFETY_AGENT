from __future__ import annotations

import ipaddress
import json
import socket
from dataclasses import asdict
from typing import Any
from urllib.parse import urlparse

import httpx

from app.agents.controller import ControllerAI


MAX_DOWNLOAD_BYTES = 10 * 1024 * 1024
DOWNLOAD_TIMEOUT_SECONDS = 8.0


def _public_http_url(value: str) -> tuple[str, str]:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("A public HTTP(S) URL without embedded credentials is required")
    host = parsed.hostname.rstrip(".").lower()
    try:
        addresses = [ipaddress.ip_address(host)]
    except ValueError:
        try:
            addresses = [ipaddress.ip_address(item[4][0]) for item in socket.getaddrinfo(host, None)]
        except OSError as exc:
            raise ValueError("The download host could not be resolved") from exc
    if not addresses or any(not address.is_global for address in addresses):
        raise ValueError("Private, local, and non-public download addresses are blocked")
    return value, host


def fetch_download_for_static_scan(value: str) -> tuple[bytes, str]:
    """Fetch a bounded download for static inspection; never follows redirects or executes bytes."""
    url, host = _public_http_url(value)
    parsed = urlparse(url)
    filename = (parsed.path.rsplit("/", 1)[-1] or "download.bin")[:180]
    with httpx.Client(timeout=DOWNLOAD_TIMEOUT_SECONDS, follow_redirects=False, verify=True, trust_env=False) as client:
        with client.stream("GET", url, headers={"User-Agent": "SafeNest-Static-Inspector/1.0"}) as response:
            if 300 <= response.status_code < 400:
                raise ValueError("Download redirects are not followed by the safe inspector")
            response.raise_for_status()
            content_length = response.headers.get("content-length")
            if content_length and int(content_length) > MAX_DOWNLOAD_BYTES:
                raise ValueError("Download exceeds the 10 MB static inspection limit")
            data = bytearray()
            for chunk in response.iter_bytes():
                data.extend(chunk)
                if len(data) > MAX_DOWNLOAD_BYTES:
                    raise ValueError("Download exceeds the 10 MB static inspection limit")
    return bytes(data), filename


def run_pipeline(controller: ControllerAI, event_type: str, value: str, source: str) -> dict[str, Any]:
    steps: list[dict[str, Any]] = []

    def record(name: str, result: Any, mode: str = "automatic") -> None:
        # Audit only bounded, non-secret metadata; source URLs are represented by a digest in ledger.
        summary = result if isinstance(result, dict) else {"result": result}
        try:
            audit = controller.audit.register_security_event(
                f"PIPELINE_{name.upper()}",
                {"type": event_type, "source": source[:80], "result": summary},
            )
            audit_id = audit.record_id
        except Exception as exc:  # Continue safely when the audit backend is unavailable.
            audit_id = None
            summary = {**summary, "audit_error": str(exc)[:160]}
        steps.append({"name": name, "result": summary, "execution": mode, "audit_record_id": audit_id})

    def finish(result: dict[str, Any]) -> dict[str, Any]:
        record("audit", {"status": "signed_hash_chain_recorded", "prior_record_ids": [
            step["audit_record_id"] for step in steps if step.get("audit_record_id")
        ]})
        result["steps"] = steps
        return result

    try:
        if event_type == "wifi":
            try:
                metadata = json.loads(value)
                if not isinstance(metadata, dict):
                    raise ValueError
            except (json.JSONDecodeError, ValueError) as exc:
                raise ValueError("Wi-Fi event value must be JSON network metadata") from exc
            finder = controller.wifi_agent.scan_network(**metadata)
            risk = finder.get("risk_level", "Careful")
            record("finder", {"risk": risk, "assessment": finder})
            policy = {"decision": "inspect_metadata", "reason": "Wi-Fi checks use supplied metadata only"}
            record("controller", policy)
            record("defence", {"action": "no_device_network_changes"})
            record("informer", {"english": "Wi-Fi metadata assessment complete.", "telugu": "వై-ఫై వివరాల తనిఖీ పూర్తయింది."})
        elif event_type == "link":
            triage = controller.orchestrate_inspection(url=value)
            findings = triage["finder_findings"]
            risk = triage["risk_level"]
            record("finder", {"risk": risk, "reason": findings["main_reason"], "signals": findings["signals"]})
            action = "block" if risk == "Danger" else "isolate" if risk == "Careful" else "allow"
            record("controller", {"risk": risk, "decision": action})
            record("defence", {"action": action, "automatic": True})
            viewer_url = None
            if risk == "Careful":
                session = controller.isolation_chamber.launch_session(value)
                viewer_url = f"/api/isolation/render/{session.session_id}"
                record("isolation", {"mode": "RESTRICTED_VIEWER", "session_id": session.session_id, "viewer_url": viewer_url, "status": session.status})
            if risk in {"Danger", "Careful"}:
                record("offence", {"action": "quarantine_proposed", "mode": "SIMULATED"}, "waiting_for_approval")
            announcement = triage["announcement"]["voice"]
            record("informer", {"english": announcement["english"]["text"], "telugu": announcement["telugu"]["text"]})
        else:
            contents, filename = fetch_download_for_static_scan(value)
            report = controller.sandbox.inspect_file(contents, filename)
            risk = report.risk_level
            record("finder", {"risk": risk, "filename": filename, "sha256": report.sha256})
            record("controller", {"risk": risk, "decision": "inspect_static_bytes"})
            record("defence", {"action": "download_not_executed"})
            record("sandbox", asdict(report))
            if risk in {"Malicious", "Suspicious"}:
                record("offence", {"action": "quarantine_proposed", "mode": "SIMULATED"}, "waiting_for_approval")
            ann = controller.informer.generate_announcement(
                risk_level="Danger" if risk == "Malicious" else "Careful" if risk == "Suspicious" else "Safe",
                reason=f"Static download inspection: {report.risk_score}/100.",
                action_taken="INSPECTED",
            )["voice"]
            record("informer", {"english": ann["english"]["text"], "telugu": ann["telugu"]["text"]})
        return finish({"mode": "LOCAL_POLICY_CHAIN", "event_type": event_type, "risk": risk, "source": source, "steps": steps,
                "action": action, "viewer_url": viewer_url} if event_type == "link" else {
                    "mode": "LOCAL_POLICY_CHAIN", "event_type": event_type, "risk": risk, "source": source, "steps": steps,
                    "action": "inspect_static_bytes" if event_type == "download" else "inspect_metadata"}
        )
    except Exception as exc:
        record("pipeline_error", {"error": str(exc)[:240]})
        return finish({"mode": "LOCAL_POLICY_CHAIN", "event_type": event_type, "risk": "Careful", "source": source,
                       "action": "hold", "steps": steps, "error": str(exc)[:240]})

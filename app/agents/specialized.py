from __future__ import annotations

import ipaddress
from typing import Any

from app.agents.base import AgentBus, AgentStatus, SecurityAgent


class WiFiAgent(SecurityAgent):
    """Specialized Agent: Wi-Fi & Local Network Vigilance."""

    def __init__(self, bus: AgentBus) -> None:
        super().__init__(name="Wi-Fi Security Agent", role="Wireless & Network Interface Inspection", bus=bus)

    KNOWN_PUBLIC_DNS = frozenset(
        {"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112"}
    )

    def scan_network(
        self,
        ssid: str,
        security_protocol: str,
        is_open: bool = False,
        duplicate_ssid_count: int = 1,
        captive_portal: bool = False,
        dns_servers: list[str] | None = None,
    ) -> dict[str, Any]:
        """Assess caller-supplied Wi-Fi metadata; this does not scan the OS or radio."""
        self.status = AgentStatus.ANALYZING
        risk = "Safe"
        warnings = []
        protocol = security_protocol.strip().upper()
        dns_servers = dns_servers or []

        if is_open or protocol in ("NONE", "OPEN", "UNENCRYPTED"):
            risk = "Danger"
            warnings.append("Unencrypted Public Wi-Fi network detected! Traffic is vulnerable to eavesdropping and ARP spoofing.")
        elif protocol in ("WEP", "WPA", "WPA_PSK"):
            risk = "Careful"
            warnings.append(f"Deprecated encryption protocol '{security_protocol}' in use. Upgrade to WPA2-AES or WPA3.")

        if duplicate_ssid_count > 1:
            if risk == "Safe":
                risk = "Careful"
            warnings.append(
                f"The supplied scan reports {duplicate_ssid_count} access points with this SSID; verify the access point before connecting."
            )

        if captive_portal and protocol in ("NONE", "OPEN", "UNENCRYPTED"):
            risk = "Danger"
            warnings.append("A captive portal was reported on an unencrypted network; do not enter credentials on its page.")

        unusual_dns = []
        for server in dns_servers:
            try:
                address = ipaddress.ip_address(server)
            except ValueError:
                unusual_dns.append(server)
                continue
            if (address.is_global or address.is_reserved) and server not in self.KNOWN_PUBLIC_DNS:
                unusual_dns.append(server)
        if unusual_dns:
            if risk == "Safe":
                risk = "Careful"
            warnings.append("Nonstandard DNS resolvers were supplied; this is a heuristic and does not prove DNS hijacking.")

        res = {
            "ssid": ssid,
            "protocol": protocol,
            "risk_level": risk,
            "warnings": warnings,
            "recommendation": "Enable VPN encryption immediately" if risk != "Safe" else "Network baseline secure",
            "assessment_mode": "SUPPLIED_METADATA_ONLY",
        }

        self.log_event(
            event_type="WIFI_ASSESSMENT_COMPLETED",
            risk_level=risk,
            details=res,
        )
        self.status = AgentStatus.MONITORING
        return res


class BrowserAgent(SecurityAgent):
    """Specialized Agent: Browser Environment & Tab Quarantine Watcher."""

    def __init__(self, bus: AgentBus) -> None:
        super().__init__(name="Browser Security Agent", role="Navigation, Tabs & Isolation Policy", bus=bus)

    def assess_navigation(self, url: str, redirect_count: int, is_private_space: bool) -> dict[str, Any]:
        self.status = AgentStatus.ANALYZING
        risk = "Safe"
        flags = []

        if redirect_count > 3:
            risk = "Careful"
            flags.append(f"Extended redirect chain detected ({redirect_count} hops). Possible affiliate cloaking.")

        res = {
            "url": url,
            "redirect_count": redirect_count,
            "is_private_space": is_private_space,
            "risk": risk,
            "flags": flags,
        }

        self.log_event("BROWSER_NAVIGATION_EVALUATED", risk, res)
        self.status = AgentStatus.MONITORING
        return res


class FileAgent(SecurityAgent):
    """Specialized Agent: Filesystem & Download Vigilance."""

    def __init__(self, bus: AgentBus) -> None:
        super().__init__(name="File Security Agent", role="Filesystem, Downloads & Hash Verification", bus=bus)

    def assess_download(self, filename: str, size_bytes: int, sha256_hash: str) -> dict[str, Any]:
        self.status = AgentStatus.ANALYZING
        risk = "Safe"
        if any(filename.lower().endswith(ext) for ext in [".exe", ".scr", ".bat", ".ps1", ".vbs"]):
            risk = "Careful"

        res = {
            "filename": filename,
            "size_bytes": size_bytes,
            "sha256": sha256_hash,
            "risk": risk,
        }
        self.log_event("DOWNLOAD_EVALUATED", risk, res)
        self.status = AgentStatus.MONITORING
        return res


class AppBehaviorAgent(SecurityAgent):
    """Specialized Agent: Process & Host Application Behavior Monitor."""

    def __init__(self, bus: AgentBus) -> None:
        super().__init__(name="Application Behavior Agent", role="Process Telemetry & Suspicious Behavior", bus=bus)

    def inspect_process_activity(self, process_name: str, network_connections: int, has_persistence_hook: bool) -> dict[str, Any]:
        self.status = AgentStatus.ANALYZING
        risk = "Safe"
        anomalies = []

        if has_persistence_hook:
            risk = "Danger"
            anomalies.append("Process registered an unauthorized RunKey / scheduled startup task.")
        elif network_connections > 50:
            risk = "Careful"
            anomalies.append(f"Elevated outbound socket activity ({network_connections} sockets).")

        res = {
            "process_name": process_name,
            "risk": risk,
            "anomalies": anomalies,
        }
        self.log_event("APP_BEHAVIOR_EVALUATED", risk, res)
        self.status = AgentStatus.MONITORING
        return res

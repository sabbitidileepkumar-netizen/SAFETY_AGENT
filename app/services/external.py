from __future__ import annotations

from datetime import datetime, timezone
import base64
import hashlib
import ipaddress
import socket
from urllib.parse import quote, urljoin, urlsplit

import httpx

from app.cache import SQLiteTTLCache
from app.config import Settings


def _digest(prefix: str, value: str) -> str:
    return hashlib.sha256(f"{prefix}:{value}".encode("utf-8")).hexdigest()


def _registrable_domain(host: str) -> str:
    labels = host.lower().rstrip(".").split(".")
    if len(labels) < 2:
        return host.lower()
    if len(labels) >= 3 and labels[-2:] in (["co", "in"], ["co", "uk"], ["com", "au"]):
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _can_fetch(url: str) -> bool:
    """Reject local/reserved targets before any backend request is made."""
    parsed = urlsplit(url)
    host = parsed.hostname
    if parsed.scheme not in {"http", "https"} or not host:
        return False
    host = host.lower().rstrip(".")
    if host in {"localhost", "localhost.localdomain"} or host.endswith(
        (".local", ".internal", ".invalid", ".example", ".test")
    ):
        return False
    try:
        address = ipaddress.ip_address(host)
        return address.is_global
    except ValueError:
        pass

    # Resolve before making the request to reduce DNS-rebinding/SSRF exposure.
    try:
        addresses = socket.getaddrinfo(host, parsed.port or 443, type=socket.SOCK_STREAM)
    except (OSError, ValueError):
        return False
    return all(ipaddress.ip_address(item[4][0]).is_global for item in addresses)


class ExternalLookupService:
    """Optional threat-intelligence and metadata lookups from the backend only."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.cache = SQLiteTTLCache(settings.database_path, settings.cache_ttl_seconds)

    def safe_browsing(self, url: str) -> str | None:
        if not self.settings.enable_network_lookups or not self.settings.google_safe_browsing_api_key:
            return None
        key = _digest("google-safe-browsing", url)
        cached = self.cache.get(key)
        if cached is not None:
            return str(cached)
        endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        payload = {
            "client": {"clientId": "safenest-phase1", "clientVersion": "0.1"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        try:
            with httpx.Client(timeout=self.settings.request_timeout_seconds, trust_env=False) as client:
                response = client.post(
                    endpoint,
                    params={"key": self.settings.google_safe_browsing_api_key},
                    json=payload,
                )
            if response.status_code != 200:
                return None
            result = "malicious" if response.json().get("matches") else "clean"
            self.cache.set(key, result)
            return result
        except (httpx.HTTPError, ValueError, KeyError):
            return None

    def virustotal(self, url: str) -> str | None:
        if not self.settings.enable_network_lookups or not self.settings.virustotal_api_key:
            return None
        key = _digest("virustotal", url)
        cached = self.cache.get(key)
        if cached is not None:
            return str(cached)
        url_id = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        try:
            with httpx.Client(timeout=self.settings.request_timeout_seconds, trust_env=False) as client:
                response = client.get(
                    endpoint,
                    headers={"x-apikey": self.settings.virustotal_api_key},
                )
            if response.status_code != 200:
                return None
            stats = response.json()["data"]["attributes"]["last_analysis_stats"]
            if stats.get("malicious", 0) > 0:
                result = "malicious"
            elif stats.get("suspicious", 0) > 0:
                result = "suspicious"
            else:
                result = "clean"
            self.cache.set(key, result)
            return result
        except (httpx.HTTPError, ValueError, KeyError, TypeError):
            return None

    def domain_age_days(self, host: str) -> int | None:
        if not self.settings.enable_network_lookups:
            return None
        domain = _registrable_domain(host)
        if not domain or domain.endswith((".example", ".invalid", ".test")):
            return None
        key = _digest("domain-age", domain)
        cached = self.cache.get(key)
        if cached is not None:
            return int(cached)
        try:
            with httpx.Client(timeout=self.settings.request_timeout_seconds, trust_env=False) as client:
                response = client.get(f"https://rdap.org/domain/{quote(domain)}")
            if response.status_code != 200:
                return None
            events = response.json().get("events", [])
            registration = next(
                (event["eventDate"] for event in events if event.get("eventAction") == "registration"),
                None,
            )
            if not registration:
                return None
            registered_at = datetime.fromisoformat(registration.replace("Z", "+00:00"))
            age = max((datetime.now(timezone.utc) - registered_at).days, 0)
            self.cache.set(key, age)
            return age
        except (httpx.HTTPError, ValueError, KeyError, TypeError, OverflowError):
            return None

    def redirect_chain(self, url: str) -> dict[str, int | str | bool] | None:
        if not self.settings.enable_network_lookups or not _can_fetch(url):
            return None
        key = _digest("redirect-chain", url)
        cached = self.cache.get(key)
        if cached is not None:
            return dict(cached)

        current = url
        hops = 0
        try:
            with httpx.Client(
                timeout=self.settings.request_timeout_seconds,
                follow_redirects=False,
                trust_env=False,
                headers={"User-Agent": "SafeNest-Backend-Checker/0.1"},
            ) as client:
                while hops < self.settings.max_redirect_hops:
                    response = client.head(current)
                    if response.status_code not in {301, 302, 303, 307, 308}:
                        break
                    location = response.headers.get("location")
                    if not location:
                        break
                    next_url = urljoin(current, location)
                    if not _can_fetch(next_url):
                        result: dict[str, int | str | bool] = {
                            "hops": hops + 1,
                            "unsafe_target": True,
                        }
                        self.cache.set(key, result)
                        return result
                    current = next_url
                    hops += 1
            result = {
                "hops": hops,
                "final_host": urlsplit(current).hostname or "",
                "unsafe_target": False,
            }
            self.cache.set(key, result)
            return result
        except (httpx.HTTPError, ValueError):
            return None

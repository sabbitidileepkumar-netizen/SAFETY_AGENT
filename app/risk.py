from __future__ import annotations

from dataclasses import dataclass
import re
from urllib.parse import urlsplit

from app.india_rules import (
    BRAND_DOMAINS,
    BRAND_TEXT_PATTERNS,
    PROMPT_INJECTION_PATTERNS,
    SHORTENER_HOSTS,
    SUSPICIOUS_TLDS,
    URGENCY_PATTERNS,
)


# Common high-value brands added from the reference agent's typo-squat checks.
# The India-specific mapping remains in india_rules.py.
COMMON_BRAND_DOMAINS: dict[str, frozenset[str]] = {
    "Google": frozenset({"google.com"}),
    "Microsoft": frozenset({"microsoft.com"}),
    "Apple": frozenset({"apple.com"}),
    "Amazon": frozenset({"amazon.com"}),
    "PayPal": frozenset({"paypal.com"}),
    "Chase": frozenset({"chase.com"}),
    "Wells Fargo": frozenset({"wellsfargo.com"}),
    "Bank of America": frozenset({"bankofamerica.com"}),
    "Netflix": frozenset({"netflix.com"}),
    "GitHub": frozenset({"github.com"}),
    "Facebook": frozenset({"facebook.com"}),
    "Instagram": frozenset({"instagram.com"}),
    "Twitter": frozenset({"twitter.com"}),
    "Dropbox": frozenset({"dropbox.com"}),
}
from app.models import CheckResponse, Signal, RiskLevel


URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.I)
TRAILING_URL_PUNCTUATION = ".,;:!?)]}>\"'"


@dataclass(frozen=True)
class Finding:
    code: str
    label: str
    severity: str
    source: str
    score: int = 0
    strong: bool = False


@dataclass(frozen=True)
class UrlEvidence:
    url: str
    safe_browsing: str | None = None
    virustotal: str | None = None
    domain_age_days: int | None = None
    redirect_hops: int | None = None
    unsafe_redirect: bool = False


@dataclass(frozen=True)
class Analysis:
    response: CheckResponse
    findings: tuple[Finding, ...]
    score: int


def extract_urls(text: str) -> list[str]:
    urls: list[str] = []
    for match in URL_PATTERN.findall(text):
        candidate = match.rstrip(TRAILING_URL_PUNCTUATION)
        if candidate and candidate not in urls:
            urls.append(candidate)
    return urls[:5]


def normalize_url(raw_url: str) -> tuple[str, str, str]:
    candidate = raw_url.strip()
    parsed = urlsplit(candidate)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("url must use http or https and include a hostname")
    if parsed.username or parsed.password:
        # User-info URLs make the visible host easy to misread.
        host = parsed.hostname
    else:
        host = parsed.hostname
    try:
        ascii_host = host.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError as exc:
        raise ValueError("url hostname is invalid") from exc
    if len(ascii_host) > 253:
        raise ValueError("url hostname is too long")
    normalized = parsed._replace(netloc=ascii_host).geturl()
    return normalized, ascii_host, parsed.scheme.lower()


def _registrable_domain(host: str) -> str:
    labels = host.lower().rstrip(".").split(".")
    if len(labels) < 2:
        return host.lower()
    if len(labels) >= 3 and labels[-2:] in (["co", "in"], ["co", "uk"], ["com", "au"]):
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _levenshtein(left: str, right: str) -> int:
    previous = list(range(len(right) + 1))
    for row, left_char in enumerate(left, start=1):
        current = [row]
        for column, right_char in enumerate(right, start=1):
            current.append(
                min(
                    current[-1] + 1,
                    previous[column] + 1,
                    previous[column - 1] + (left_char != right_char),
                )
            )
        previous = current
    return previous[-1]


def _brand_lookalike(host: str) -> str | None:
    host = host.lower().rstrip(".")
    labels = host.split(".")
    for brand, domains in (*BRAND_DOMAINS.items(), *COMMON_BRAND_DOMAINS.items()):
        if any(host == domain or host.endswith(f".{domain}") for domain in domains):
            continue
        token = brand.split("/")[0].split()[0].lower()
        if any(token in label for label in labels):
            return brand
        domain_label = _registrable_domain(host).split(".")[0]
        if len(token) >= 4 and _levenshtein(domain_label, token) <= 2:
            return brand
    return None


def _add(finding_list: list[Finding], finding: Finding) -> None:
    if not any(existing.code == finding.code for existing in finding_list):
        finding_list.append(finding)


def _rule_findings(urls: list[str], text: str) -> list[Finding]:
    findings: list[Finding] = []

    for pattern in PROMPT_INJECTION_PATTERNS:
        if pattern.search(text):
            _add(
                findings,
                Finding(
                    code="prompt_injection_attempt",
                    label="The content tries to influence the security checker",
                    severity="danger",
                    source="india_rules",
                    score=8,
                    strong=True,
                ),
            )
            break

    for code, pattern in URGENCY_PATTERNS:
        if pattern.search(text):
            _add(
                findings,
                Finding(
                    code=code,
                    label="Uses urgent account, payment, or OTP language",
                    severity="careful",
                    source="india_rules",
                    score=2,
                ),
            )

    for brand, pattern in BRAND_TEXT_PATTERNS:
        if pattern.search(text):
            _add(
                findings,
                Finding(
                    code="brand_name_in_message",
                    label=f"Mentions {brand} in the message",
                    severity="careful",
                    source="india_rules",
                    score=1,
                ),
            )
            break

    for raw_url in urls:
        normalized, host, scheme = normalize_url(raw_url)
        parsed = urlsplit(normalized)
        if scheme == "http":
            _add(
                findings,
                Finding(
                    code="unencrypted_http",
                    label="The link does not use encrypted HTTPS",
                    severity="careful",
                    source="url_rules",
                    score=2,
                ),
            )
        if parsed.username or parsed.password:
            _add(
                findings,
                Finding(
                    code="misleading_url_userinfo",
                    label="The URL hides extra text before the real host",
                    severity="danger",
                    source="url_rules",
                    score=4,
                    strong=True,
                ),
            )
        if host in SHORTENER_HOSTS or any(host.endswith(f".{shortener}") for shortener in SHORTENER_HOSTS):
            _add(
                findings,
                Finding(
                    code="shortened_link",
                    label="A URL shortener hides the final destination",
                    severity="careful",
                    source="india_rules",
                    score=2,
                ),
            )
        if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
            _add(
                findings,
                Finding(
                    code="unusual_domain_ending",
                    label="The domain uses an unusual ending for this request",
                    severity="careful",
                    source="url_rules",
                    score=1,
                ),
            )
        brand = _brand_lookalike(host)
        if brand:
            _add(
                findings,
                Finding(
                    code="lookalike_domain",
                    label=f"The link imitates {brand} on a different domain",
                    severity="danger",
                    source="india_rules",
                    score=4,
                    strong=True,
                ),
            )
        path_and_query = f"{parsed.path}?{parsed.query}"
        for code, pattern in URGENCY_PATTERNS:
            if pattern.search(path_and_query):
                _add(
                    findings,
                    Finding(
                        code=code,
                        label="The link contains urgent account or payment language",
                        severity="careful",
                        source="india_rules",
                        score=2,
                    ),
                )
                break

    return findings


def _external_findings(evidence: tuple[UrlEvidence, ...]) -> list[Finding]:
    findings: list[Finding] = []
    for item in evidence:
        if item.safe_browsing == "malicious":
            _add(
                findings,
                Finding(
                    code="google_safe_browsing_malicious",
                    label="Google Safe Browsing reports this destination as dangerous",
                    severity="danger",
                    source="google_safe_browsing",
                    score=8,
                    strong=True,
                ),
            )
        elif item.safe_browsing == "clean":
            _add(
                findings,
                Finding(
                    code="google_safe_browsing_clear",
                    label="Google Safe Browsing has no known match",
                    severity="info",
                    source="google_safe_browsing",
                ),
            )
        if item.virustotal == "malicious":
            _add(
                findings,
                Finding(
                    code="virustotal_malicious",
                    label="VirusTotal reports malicious detections",
                    severity="danger",
                    source="virustotal",
                    score=8,
                    strong=True,
                ),
            )
        elif item.virustotal == "suspicious":
            _add(
                findings,
                Finding(
                    code="virustotal_suspicious",
                    label="VirusTotal reports suspicious detections",
                    severity="careful",
                    source="virustotal",
                    score=3,
                    strong=True,
                ),
            )
        elif item.virustotal == "clean":
            _add(
                findings,
                Finding(
                    code="virustotal_clear",
                    label="VirusTotal has no malicious detections",
                    severity="info",
                    source="virustotal",
                ),
            )
        if item.domain_age_days is not None and item.domain_age_days < 30:
            _add(
                findings,
                Finding(
                    code="recent_domain",
                    label="The domain appears to be less than 30 days old",
                    severity="careful",
                    source="domain_age",
                    score=2,
                ),
            )
        if item.unsafe_redirect:
            _add(
                findings,
                Finding(
                    code="unsafe_redirect",
                    label="The link redirects toward a restricted network target",
                    severity="danger",
                    source="redirect_chain",
                    score=7,
                    strong=True,
                ),
            )
        elif item.redirect_hops is not None and item.redirect_hops > 0:
            _add(
                findings,
                Finding(
                    code="redirect_chain",
                    label=f"The link redirects through {item.redirect_hops} destination(s)",
                    severity="careful",
                    source="redirect_chain",
                    score=1 if item.redirect_hops == 1 else 2,
                ),
            )
    return findings


def _decide(findings: list[Finding]) -> tuple[RiskLevel, float]:
    actionable = [finding for finding in findings if finding.severity != "info"]
    score = sum(finding.score for finding in actionable)
    strong = [finding for finding in actionable if finding.strong]
    reputation_hits = {
        finding.code
        for finding in strong
        if finding.code in {"google_safe_browsing_malicious", "virustotal_malicious"}
    }

    if any(finding.code == "prompt_injection_attempt" for finding in actionable):
        return "Danger", 0.98
    if len(strong) >= 2:
        return "Danger", min(0.99, 0.84 + (len(strong) - 2) * 0.04)
    if strong and len(actionable) >= 2 and score >= 5:
        return "Danger", min(0.96, 0.78 + score * 0.02)
    if len(reputation_hits) == 2:
        return "Danger", 0.99
    if score >= 2:
        return "Careful", min(0.88, 0.54 + score * 0.04)
    return "Safe", 0.76 if actionable else 0.84


def _main_reason(risk: RiskLevel, findings: list[Finding]) -> str:
    priority = (
        "prompt_injection_attempt",
        "google_safe_browsing_malicious",
        "virustotal_malicious",
        "unsafe_redirect",
        "lookalike_domain",
        "misleading_url_userinfo",
        "virustotal_suspicious",
        "recent_domain",
        "shortened_link",
        "otp_request",
        "kyc_expiring",
        "account_blocked",
        "urgent_action",
        "verify_now",
        "payment_reward",
        "redirect_chain",
        "unencrypted_http",
    )
    by_code = {finding.code: finding for finding in findings}
    for code in priority:
        if code in by_code:
            return by_code[code].label + "."
    if risk == "Safe":
        return "No known scam indicators were found in the submitted data."
    return "The submitted data contains a combination of caution indicators."


def analyze(url: str | None, text: str | None, evidence: tuple[UrlEvidence, ...] = ()) -> Analysis:
    raw_text = text or url or ""
    urls = [url] if url else extract_urls(raw_text)
    findings = _rule_findings(urls, raw_text)
    findings.extend(_external_findings(evidence))
    risk, confidence = _decide(findings)
    if not findings:
        findings.append(
            Finding(
                code="no_known_indicators",
                label="No rule indicators matched",
                severity="info",
                source="deterministic_rules",
            )
        )
    score = sum(finding.score for finding in findings)
    signals = [
        Signal(
            code=finding.code,
            label=finding.label,
            severity=finding.severity,  # type: ignore[arg-type]
            source=finding.source,
        )
        for finding in findings
    ]
    return Analysis(
        response=CheckResponse(
            risk=risk,
            confidence=round(confidence, 2),
            main_reason=_main_reason(risk, findings),
            signals=signals,
        ),
        findings=tuple(findings),
        score=score,
    )

"""Editable India-focused scam indicators used by the deterministic engine."""

from __future__ import annotations

import re


# A host is trusted only when it is this domain or a subdomain of it.
BRAND_DOMAINS: dict[str, frozenset[str]] = {
    "SBI": frozenset({"sbi.co.in", "onlinesbi.sbi"}),
    "HDFC Bank": frozenset({"hdfcbank.com"}),
    "ICICI Bank": frozenset({"icicibank.com"}),
    "Axis Bank": frozenset({"axisbank.com"}),
    "Kotak": frozenset({"kotak.com"}),
    "Paytm": frozenset({"paytm.com"}),
    "PhonePe": frozenset({"phonepe.com"}),
    "UPI/NPCI": frozenset({"npci.org.in", "upi.npci.org.in"}),
}

SHORTENER_HOSTS = frozenset(
    {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "cutt.ly",
        "shorturl.at",
    }
)

# Keep this list short and easy to review. Patterns are matched case-insensitively.
URGENCY_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("kyc_expiring", re.compile(r"\bkyc\b.{0,30}\b(?:expir|due|updat)", re.I)),
    ("account_blocked", re.compile(r"\baccount\b.{0,25}\b(?:block|suspend|deactivat)", re.I)),
    ("otp_request", re.compile(r"\botp\b", re.I)),
    ("verify_now", re.compile(r"\b(?:verify|confirm|update)\b.{0,20}\b(?:now|today|immediately)\b", re.I)),
    ("urgent_action", re.compile(r"\b(?:urgent|immediately|last chance|click now|act now)\b", re.I)),
    ("payment_reward", re.compile(r"\b(?:refund|cashback|reward|prize|lottery)\b", re.I)),
)

PROMPT_INJECTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bignore\s+(?:all\s+)?previous\s+instructions\b", re.I),
    re.compile(r"\b(?:say|tell|claim)\s+(?:this|it)\s+is\s+safe\b", re.I),
    re.compile(r"\bdo\s+not\s+follow\s+the\s+(?:security|safety)\s+rules\b", re.I),
)

BRAND_TEXT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (brand, re.compile(rf"\b{re.escape(brand.split()[0])}\b", re.I))
    for brand in BRAND_DOMAINS
)

SUSPICIOUS_TLDS = frozenset({".click", ".top", ".work", ".loan", ".xyz"})

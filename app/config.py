from __future__ import annotations

from dataclasses import dataclass
import os


def _as_bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _as_int(value: str | None, default: int, minimum: int) -> int:
    try:
        parsed = int(value) if value is not None else default
    except ValueError:
        return default
    return max(parsed, minimum)


def _as_float(value: str | None, default: float, minimum: float) -> float:
    try:
        parsed = float(value) if value is not None else default
    except ValueError:
        return default
    return max(parsed, minimum)


@dataclass(frozen=True)
class Settings:
    google_safe_browsing_api_key: str | None = None
    virustotal_api_key: str | None = None
    gemini_api_key: str | None = None
    gemini_model: str = "gemini-2.0-flash"
    enable_gemini_explanations: bool = True
    enable_network_lookups: bool = True
    request_limit_per_minute: int = 30
    cache_ttl_seconds: int = 900
    request_timeout_seconds: float = 4.0
    max_redirect_hops: int = 5
    database_path: str = "./safenest_cache.db"
    cors_allowed_origins: str = "*"
    session_ttl_seconds: int = 60 * 60 * 24 * 30
    free_checks_per_day: int = 10
    razorpay_key_id: str | None = None
    razorpay_key_secret: str | None = None
    razorpay_webhook_secret: str | None = None
    razorpay_api_base_url: str = "https://api.razorpay.com/v1"
    razorpay_enabled: bool = False
    payments_demo_mode: bool = False

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            google_safe_browsing_api_key=os.getenv("GOOGLE_SAFE_BROWSING_API_KEY") or None,
            virustotal_api_key=os.getenv("VIRUSTOTAL_API_KEY") or None,
            gemini_api_key=os.getenv("GEMINI_API_KEY") or None,
            gemini_model=os.getenv("GEMINI_MODEL", "gemini-2.0-flash"),
            enable_gemini_explanations=_as_bool(
                os.getenv("ENABLE_GEMINI_EXPLANATIONS"), True
            ),
            enable_network_lookups=_as_bool(os.getenv("ENABLE_NETWORK_LOOKUPS"), True),
            request_limit_per_minute=_as_int(
                os.getenv("REQUEST_LIMIT_PER_MINUTE"), 30, 1
            ),
            cache_ttl_seconds=_as_int(os.getenv("CACHE_TTL_SECONDS"), 900, 1),
            request_timeout_seconds=_as_float(
                os.getenv("REQUEST_TIMEOUT_SECONDS"), 4.0, 0.5
            ),
            max_redirect_hops=_as_int(os.getenv("MAX_REDIRECT_HOPS"), 5, 1),
            database_path=os.getenv("DATABASE_PATH", "./safenest_cache.db"),
            cors_allowed_origins=os.getenv("CORS_ALLOWED_ORIGINS", "*"),
            session_ttl_seconds=_as_int(
                os.getenv("SESSION_TTL_SECONDS"), 60 * 60 * 24 * 30, 3600
            ),
            free_checks_per_day=_as_int(os.getenv("FREE_CHECKS_PER_DAY"), 10, 1),
            razorpay_key_id=os.getenv("RAZORPAY_KEY_ID") or None,
            razorpay_key_secret=os.getenv("RAZORPAY_KEY_SECRET") or None,
            razorpay_webhook_secret=os.getenv("RAZORPAY_WEBHOOK_SECRET") or None,
            razorpay_api_base_url=os.getenv(
                "RAZORPAY_API_BASE_URL", "https://api.razorpay.com/v1"
            ).rstrip("/"),
            razorpay_enabled=_as_bool(os.getenv("RAZORPAY_ENABLED"), False),
            payments_demo_mode=_as_bool(os.getenv("PAYMENTS_DEMO_MODE"), False),
        )

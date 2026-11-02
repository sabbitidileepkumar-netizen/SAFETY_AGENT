from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator


RiskLevel = Literal["Safe", "Careful", "Danger"]
SignalSeverity = Literal["info", "careful", "danger"]
PlanName = Literal["free", "pro", "family"]


class CheckRequest(BaseModel):
    """Exactly one bounded input is accepted; content is treated as data."""

    url: str | None = Field(default=None, max_length=2048)
    text: str | None = Field(default=None, max_length=10000)

    @field_validator("url", "text", mode="before")
    @classmethod
    def trim_blank_values(cls, value: object) -> object:
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValueError("input must be text")
        value = value.strip()
        return value or None

    @model_validator(mode="after")
    def require_one_input(self) -> "CheckRequest":
        if bool(self.url) == bool(self.text):
            raise ValueError("provide exactly one of url or text")
        return self


class Signal(BaseModel):
    code: str
    label: str
    severity: SignalSeverity
    source: str


class BilingualExplanation(BaseModel):
    english: str = Field(min_length=1, max_length=320)
    telugu: str = Field(min_length=1, max_length=320)
    source: Literal["gemini", "fallback"]


class UsageInfo(BaseModel):
    plan: PlanName
    checks_used_today: int = Field(ge=0)
    checks_remaining_today: int | None = Field(default=None, ge=0)


class CheckResponse(BaseModel):
    risk: RiskLevel
    confidence: float = Field(ge=0.0, le=1.0)
    main_reason: str
    signals: list[Signal]
    explanation: BilingualExplanation | None = None
    usage: UsageInfo | None = None


class CredentialsRequest(BaseModel):
    email: str = Field(min_length=5, max_length=254)
    password: str = Field(min_length=10, max_length=128)

    @field_validator("email", mode="before")
    @classmethod
    def normalize_email(cls, value: object) -> str:
        if not isinstance(value, str):
            raise ValueError("email must be text")
        normalized = value.strip().lower()
        if "@" not in normalized or normalized.startswith("@") or normalized.endswith("@"):
            raise ValueError("enter a valid email address")
        local, domain = normalized.rsplit("@", 1)
        if not local or "." not in domain or " " in normalized:
            raise ValueError("enter a valid email address")
        return normalized


class AuthResponse(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"
    user: "UserResponse"


class UserResponse(BaseModel):
    id: str
    email: str
    plan: PlanName


class PlanRequest(BaseModel):
    plan: Literal["pro_monthly", "pro_yearly", "family_monthly"]


class PaymentVerification(BaseModel):
    order_id: str = Field(min_length=8, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    payment_id: str = Field(min_length=8, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    signature: str = Field(min_length=32, max_length=128, pattern=r"^[a-fA-F0-9]+$")


class DemoPaymentRequest(BaseModel):
    order_id: str = Field(min_length=8, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")


class OrderResponse(BaseModel):
    order_id: str
    amount: int
    currency: Literal["INR"]
    plan: Literal["pro_monthly", "pro_yearly", "family_monthly"]
    key_id: str | None = None
    demo: bool = False


class AccountResponse(BaseModel):
    user: UserResponse
    checks_used_today: int = Field(ge=0)
    checks_remaining_today: int | None = Field(default=None, ge=0)

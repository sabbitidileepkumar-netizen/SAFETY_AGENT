from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator


RiskLevel = Literal["Safe", "Careful", "Danger"]
SignalSeverity = Literal["info", "careful", "danger"]


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


class CheckResponse(BaseModel):
    risk: RiskLevel
    confidence: float = Field(ge=0.0, le=1.0)
    main_reason: str
    signals: list[Signal]
    explanation: BilingualExplanation | None = None

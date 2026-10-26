from __future__ import annotations

from fastapi import FastAPI, HTTPException, Request

from app.checker import Checker
from app.config import Settings
from app.models import CheckRequest, CheckResponse
from app.rate_limit import RateLimiter


def create_app(settings: Settings | None = None) -> FastAPI:
    active_settings = settings or Settings.from_env()
    checker = Checker(active_settings)
    limiter = RateLimiter(active_settings.request_limit_per_minute)
    api = FastAPI(title="SafeNest Link Checker", version="0.1.0")

    @api.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @api.post("/check", response_model=CheckResponse)
    def check(payload: CheckRequest, request: Request) -> CheckResponse:
        client_host = request.client.host if request.client else "unknown"
        if not limiter.allow(client_host):
            raise HTTPException(status_code=429, detail="rate limit exceeded")
        try:
            return checker.check(payload)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    return api


app = create_app()

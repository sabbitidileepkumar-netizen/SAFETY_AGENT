from __future__ import annotations

from dataclasses import dataclass

from app.config import Settings
from app.explanation import ExplanationService
from app.models import CheckRequest, CheckResponse
from app.risk import Analysis, UrlEvidence, analyze, extract_urls, normalize_url
from app.services.external import ExternalLookupService


@dataclass
class Checker:
    settings: Settings

    def __post_init__(self) -> None:
        self.external = ExternalLookupService(self.settings)
        self.explainer = ExplanationService(self.settings)

    def _urls(self, request: CheckRequest) -> list[str]:
        if request.url:
            try:
                return [normalize_url(request.url)[0]]
            except (TypeError, ValueError) as exc:
                raise ValueError(str(exc)) from exc
        urls: list[str] = []
        for candidate in extract_urls(request.text or ""):
            try:
                normalized = normalize_url(candidate)[0]
            except (TypeError, ValueError):
                continue
            if normalized not in urls:
                urls.append(normalized)
        return urls

    def _evidence(self, urls: list[str], preliminary: Analysis) -> tuple[UrlEvidence, ...]:
        if not self.settings.enable_network_lookups:
            return ()
        evidence: list[UrlEvidence] = []
        should_query_reputation = preliminary.response.risk != "Danger"
        for candidate in urls:
            _, host, _ = normalize_url(candidate)
            safe_browsing = self.external.safe_browsing(candidate) if should_query_reputation else None
            redirect = self.external.redirect_chain(candidate)
            age = self.external.domain_age_days(host)

            # VirusTotal is a second opinion only when local rules are unclear.
            virustotal = None
            if (
                should_query_reputation
                and preliminary.response.risk == "Careful"
                and not any(finding.strong for finding in preliminary.findings)
            ):
                virustotal = self.external.virustotal(candidate)
            evidence.append(
                UrlEvidence(
                    url=candidate,
                    safe_browsing=safe_browsing,
                    virustotal=virustotal,
                    domain_age_days=age,
                    redirect_hops=(int(redirect["hops"]) if redirect and "hops" in redirect else None),
                    unsafe_redirect=bool(redirect and redirect.get("unsafe_target")),
                )
            )
        return tuple(evidence)

    def check(self, request: CheckRequest) -> CheckResponse:
        urls = self._urls(request)
        preliminary = analyze(request.url, request.text)
        evidence = self._evidence(urls, preliminary)
        response = analyze(request.url, request.text, evidence).response
        return response.model_copy(update={"explanation": self.explainer.explain(response)})

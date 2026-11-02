export const RISK_LEVELS = new Set(["Safe", "Careful", "Danger"]);

export function normalizeOrigin(target) {
  try {
    const parsed = new URL(target);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return null;
    }
    return parsed.origin;
  } catch {
    return null;
  }
}

export function normalizeCheckResult(payload) {
  if (!payload || !RISK_LEVELS.has(payload.risk)) {
    throw new Error("The safety service returned an invalid risk level.");
  }
  if (typeof payload.main_reason !== "string" || !payload.main_reason.trim()) {
    throw new Error("The safety service returned no reason.");
  }
  const explanation = payload.explanation || {};
  return {
    risk: payload.risk,
    confidence: Number.isFinite(Number(payload.confidence)) ? Number(payload.confidence) : 0,
    mainReason: payload.main_reason.trim().slice(0, 320),
    signals: Array.isArray(payload.signals) ? payload.signals : [],
    explanation: {
      english: typeof explanation.english === "string" ? explanation.english.trim().slice(0, 320) : "",
      telugu: typeof explanation.telugu === "string" ? explanation.telugu.trim().slice(0, 320) : "",
      source: explanation.source === "gemini" ? "gemini" : "fallback"
    }
  };
}

export function normalizePipelineResult(payload) {
  if (!payload || !["link", "download", "wifi"].includes(payload.event_type) || !RISK_LEVELS.has(payload.risk) || !Array.isArray(payload.steps)) {
    throw new Error("The safety service returned an invalid pipeline result.");
  }
  const informer = payload.steps.find((step) => step?.name === "informer")?.result || {};
  const finder = payload.steps.find((step) => step?.name === "finder")?.result || {};
  const normalized = normalizeCheckResult({
    risk: payload.risk,
    confidence: 0.5,
    main_reason: finder.reason || payload.error || `Policy decision: ${payload.action || "hold"}.`,
    signals: finder.signals || [],
    explanation: { english: informer.english || "SafeNest checked this event.", telugu: informer.telugu || "సేఫ్‌నెస్ట్ ఈ అంశాన్ని తనిఖీ చేసింది.", source: "fallback" }
  });
  return { ...normalized, action: payload.action || "hold", viewerUrl: payload.viewer_url || null };
}

export function actionForRisk(risk, rememberedCareful = false) {
  if (risk === "Safe" || (risk === "Careful" && rememberedCareful)) {
    return "open";
  }
  if (risk === "Danger") {
    return "block";
  }
  return "warn";
}

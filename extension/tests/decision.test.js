import test from "node:test";
import assert from "node:assert/strict";

import { actionForRisk, normalizeCheckResult, normalizeOrigin, normalizePipelineResult } from "../decision.js";
import { isWebUrl, normalizeBackendUrl } from "../config.js";

test("risk actions preserve SafeNest behavior", () => {
  assert.equal(actionForRisk("Safe"), "open");
  assert.equal(actionForRisk("Careful"), "warn");
  assert.equal(actionForRisk("Careful", true), "open");
  assert.equal(actionForRisk("Danger", true), "block");
});

test("origins are remembered by origin, not by a full path", () => {
  assert.equal(normalizeOrigin("https://example.com/a?b=1"), "https://example.com");
  assert.equal(normalizeOrigin("javascript:alert(1)"), null);
  assert.equal(isWebUrl("http://example.com"), true);
  assert.equal(isWebUrl("chrome://settings"), false);
});

test("backend settings accept only web URLs", () => {
  assert.equal(normalizeBackendUrl("http://127.0.0.1:8000/"), "http://127.0.0.1:8000");
  assert.equal(normalizeBackendUrl("file:///tmp/backend"), null);
  assert.equal(normalizeBackendUrl("not-a-url"), null);
});

test("extension accepts a valid backend result and rejects invalid risk", () => {
  const result = normalizeCheckResult({
    risk: "Danger",
    confidence: 0.98,
    main_reason: "The link imitates a bank on a different domain.",
    signals: [],
    explanation: {
      english: "Danger: Do not open this link.",
      telugu: "ప్రమాదం: ఈ లింక్‌ను తెరవకండి.",
      source: "fallback"
    }
  });
  assert.equal(result.risk, "Danger");
  assert.equal(result.mainReason, "The link imitates a bank on a different domain.");
  assert.throws(
    () => normalizeCheckResult({ risk: "Unknown", main_reason: "bad" }),
    /invalid risk level/
  );
});

test("pipeline result maps bilingual explanation and action for the extension", () => {
  const result = normalizePipelineResult({
    event_type: "link", risk: "Careful", action: "isolate", viewer_url: "/api/isolation/render/iso-123",
    steps: [
      { name: "finder", result: { reason: "Unverified login page", signals: [] } },
      { name: "informer", result: { english: "Pause before opening.", telugu: "తెరవడానికి ముందు ఆగండి." } }
    ]
  });
  assert.equal(result.risk, "Careful");
  assert.equal(result.action, "isolate");
  assert.equal(result.viewerUrl, "/api/isolation/render/iso-123");
  assert.equal(result.explanation.telugu, "తెరవడానికి ముందు ఆగండి.");
});

test("extension pipeline rejects malformed service results", () => {
  assert.throws(() => normalizePipelineResult({ event_type: "link", risk: "Unknown", steps: [] }), /invalid pipeline result/);
});

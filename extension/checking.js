import { DEFAULT_BACKEND_URL } from "./config.js";
import { normalizePipelineResult } from "./decision.js";

const params = new URLSearchParams(globalThis.location.search);
const token = params.get("token");
const $ = (id) => document.getElementById(id);

function sendMessage(message) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(message, (response) => {
      if (chrome.runtime.lastError) {
        reject(new Error("SafeNest could not contact its background service."));
        return;
      }
      resolve(response);
    });
  });
}

function fallbackForUnavailableService() {
  return {
    risk: "Careful",
    confidence: 0,
    mainReason: "The safety service could not check this link.",
    signals: [],
    explanation: {
      english: "Careful: The safety service could not check this link. Pause and verify the sender before continuing.",
      telugu: "జాగ్రత్త: భద్రతా సేవ ఈ లింక్‌ను తనిఖీ చేయలేకపోయింది. కొనసాగించే ముందు పంపినవారిని నిర్ధారించండి.",
      source: "fallback"
    }
  };
}

function speak(text, language) {
  if (!text || !("speechSynthesis" in window)) {
    return;
  }
  window.speechSynthesis.cancel();
  const utterance = new SpeechSynthesisUtterance(text);
  utterance.lang = language;
  utterance.rate = 0.95;
  window.speechSynthesis.speak(utterance);
}

function showError(message) {
  $("progress").classList.add("hidden");
  $("result").classList.add("hidden");
  $("error").classList.remove("hidden");
  $("heading").textContent = "SafeNest could not continue";
  $("status").textContent = "The original page was not opened.";
  $("error-text").textContent = message;
  $("error-close").onclick = () => void sendMessage({ type: "close-target", token });
}

function renderWarning(result) {
  $("progress").classList.add("hidden");
  $("result").classList.remove("hidden");
  $("heading").textContent = result.risk === "Danger" ? "This link was blocked" : "Pause before opening";
  $("status").textContent = result.risk === "Danger"
    ? "SafeNest found strong warning signs."
    : "SafeNest found warning signs that need your attention.";
  $("reason").textContent = result.mainReason;
  $("english").textContent = result.explanation.english || result.mainReason;
  $("telugu").textContent = result.explanation.telugu || result.mainReason;

  for (const item of document.querySelectorAll("[data-risk]")) {
    item.classList.toggle("active", item.dataset.risk === result.risk);
  }

  const danger = result.risk === "Danger";
  $("danger-note").classList.toggle("hidden", !danger);
  $("danger-note").textContent = danger
    ? "Open anyway is a one-time override. Never enter an OTP, password, UPI PIN, or card details."
    : "";
  $("remember-row").classList.toggle("hidden", danger);
  $("allow").classList.add("hidden");
  $("close").onclick = async () => {
    window.speechSynthesis?.cancel();
    await sendMessage({ type: "close-target", token });
  };
  $("speak-english").onclick = () => speak(result.explanation.english || result.mainReason, "en-IN");
  $("speak-telugu").onclick = () => speak(result.explanation.telugu || result.mainReason, "te-IN");

  speak(result.explanation.english || result.mainReason, "en-IN");
}

async function check() {
  if (!token) {
    showError("This checking session is invalid.");
    return;
  }
  try {
    const context = await sendMessage({ type: "get-context", token });
    if (!context?.ok || typeof context.target !== "string") {
      showError("This checking session expired. The original page was not opened.");
      return;
    }
    const settings = await sendMessage({ type: "get-settings" });
    const backendUrl = typeof settings?.backendUrl === "string" ? settings.backendUrl : DEFAULT_BACKEND_URL;
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 10_000);
    let result;
    try {
      const response = await fetch(`${backendUrl}/api/pipeline/event`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...(settings.userToken ? { Authorization: `Bearer ${settings.userToken}` } : {}) },
        body: JSON.stringify({ type: "link", value: context.target, source: "chrome_extension_navigation" }),
        signal: controller.signal
      });
      if (!response.ok) {
        throw new Error("The safety service returned an error.");
      }
      result = normalizePipelineResult(await response.json());
    } catch {
      result = fallbackForUnavailableService();
    } finally {
      window.clearTimeout(timeout);
    }

    if (result.risk === "Safe") {
      await sendMessage({ type: "open-target", token });
      return;
    }
    if (result.risk === "Careful") {
      window.speechSynthesis?.cancel();
      const viewer = new URL(chrome.runtime.getURL("isolation.html"));
      viewer.searchParams.set("url", context.target);
      viewer.searchParams.set("reason", result.mainReason);
      viewer.searchParams.set("english", result.explanation.english);
      viewer.searchParams.set("telugu", result.explanation.telugu);
      window.location.replace(viewer.href);
      return;
    }
    renderWarning(result);
  } catch {
    showError("SafeNest could not check this link. The original page was not opened.");
  }
}

void check();

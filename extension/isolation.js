const params = new URLSearchParams(location.search);
const target = params.get("url");
const english = params.get("english") || "SafeNest recommends caution with this page.";
const telugu = params.get("telugu") || "ఈ పేజీతో జాగ్రత్తగా ఉండండి.";
document.getElementById("reason").textContent = `Reason: ${params.get("reason") || "This link needs extra review."}`;
document.getElementById("english").textContent = english;
document.getElementById("telugu").textContent = telugu;
try {
  const url = new URL(target);
  if (["http:", "https:"].includes(url.protocol)) document.getElementById("page").src = url.href;
  else throw new Error("invalid");
} catch {
  document.querySelector("main").insertAdjacentText("beforeend", " Invalid or expired web link.");
}
document.getElementById("close").addEventListener("click", () => history.back());
function speak(text, language) {
  if (!("speechSynthesis" in window)) {
    document.getElementById("voice-status").textContent = "Speech is unavailable in this browser; both messages are shown above.";
    return;
  }
  speechSynthesis.cancel();
  const utterance = new SpeechSynthesisUtterance(text);
  utterance.lang = language;
  speechSynthesis.speak(utterance);
}
document.getElementById("speak-en").addEventListener("click", () => speak(english, "en-IN"));
document.getElementById("speak-te").addEventListener("click", () => speak(telugu, "te-IN"));
function reportVoiceAvailability() {
  const voices = speechSynthesis.getVoices();
  if (voices.length && !voices.some((voice) => voice.lang.toLowerCase().startsWith("te"))) {
    document.getElementById("voice-status").textContent = "No Telugu speech voice is installed. The Telugu explanation remains visible above.";
  }
}
if ("speechSynthesis" in window) {
  speechSynthesis.addEventListener("voiceschanged", reportVoiceAvailability);
  reportVoiceAvailability();
} else {
  document.getElementById("voice-status").textContent = "Speech is unavailable in this browser; both messages are shown above.";
}

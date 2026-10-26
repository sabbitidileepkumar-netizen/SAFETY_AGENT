import { DEFAULT_BACKEND_URL } from "./config.js";

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

const form = document.getElementById("settings-form");
const input = document.getElementById("backend-url");
const status = document.getElementById("status");
const clearButton = document.getElementById("clear-remembered");
const clearStatus = document.getElementById("clear-status");

sendMessage({ type: "get-settings" })
  .then((response) => {
    input.value = response?.backendUrl || DEFAULT_BACKEND_URL;
  })
  .catch(() => {
    input.value = DEFAULT_BACKEND_URL;
  });

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const response = await sendMessage({ type: "set-settings", backendUrl: input.value });
  if (response?.ok) {
    input.value = response.backendUrl;
    status.textContent = "Saved.";
  } else {
    status.textContent = response?.error || "Could not save settings.";
  }
});

clearButton.addEventListener("click", async () => {
  const response = await sendMessage({ type: "clear-remembered" });
  clearStatus.textContent = response?.ok ? "Remembered decisions cleared." : "Could not clear decisions.";
});

import {
  CAREFUL_ALLOW_KEY,
  DEFAULT_BACKEND_URL,
  PENDING_PREFIX,
  SETTINGS_KEY,
  isWebUrl,
  normalizeBackendUrl
} from "./config.js";
import { normalizeOrigin } from "./decision.js";

const ALLOW_ONCE_TTL_MS = 15_000;
const PENDING_TTL_MS = 10 * 60_000;
const allowOnce = new Map();

function validToken(token) {
  return typeof token === "string" && /^[A-Za-z0-9-]{16,80}$/.test(token);
}

function pendingKey(token) {
  return `${PENDING_PREFIX}${token}`;
}

function newToken() {
  if (globalThis.crypto?.randomUUID) {
    return globalThis.crypto.randomUUID();
  }
  return `${Date.now()}-${Math.random().toString(36).slice(2)}-${Math.random().toString(36).slice(2)}`;
}

function sameUrl(left, right) {
  try {
    return new URL(left).href === new URL(right).href;
  } catch {
    return false;
  }
}

async function getPending(token) {
  if (!validToken(token)) {
    return null;
  }
  const stored = await chrome.storage.session.get(pendingKey(token));
  const context = stored[pendingKey(token)];
  if (!context || !isWebUrl(context.target)) {
    return null;
  }
  if (Date.now() - Number(context.createdAt || 0) > PENDING_TTL_MS) {
    await chrome.storage.session.remove(pendingKey(token));
    return null;
  }
  return context;
}

async function handleNavigation(details) {
  if (details.frameId !== 0 || details.tabId < 0 || !isWebUrl(details.url)) {
    return;
  }

  const previous = allowOnce.get(details.tabId);
  if (previous) {
    allowOnce.delete(details.tabId);
    if (previous.expiresAt >= Date.now() && sameUrl(previous.target, details.url)) {
      return;
    }
  }

  const token = newToken();
  await chrome.storage.session.set({
    [pendingKey(token)]: {
      target: details.url,
      tabId: details.tabId,
      createdAt: Date.now()
    }
  });
  const checkingUrl = chrome.runtime.getURL(`checking.html?token=${encodeURIComponent(token)}`);
  await chrome.tabs.update(details.tabId, { url: checkingUrl });
}

chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  void handleNavigation(details).catch(() => undefined);
});

async function getBackendUrl() {
  const stored = await chrome.storage.sync.get({ [SETTINGS_KEY]: DEFAULT_BACKEND_URL });
  return normalizeBackendUrl(stored[SETTINGS_KEY]) || DEFAULT_BACKEND_URL;
}

async function setBackendUrl(value) {
  const normalized = normalizeBackendUrl(value);
  if (!normalized) {
    return { ok: false, error: "Enter a valid http or https backend URL." };
  }
  await chrome.storage.sync.set({ [SETTINGS_KEY]: normalized });
  return { ok: true, backendUrl: normalized };
}

async function getAllowedOrigins() {
  const stored = await chrome.storage.sync.get({ [CAREFUL_ALLOW_KEY]: [] });
  return Array.isArray(stored[CAREFUL_ALLOW_KEY]) ? stored[CAREFUL_ALLOW_KEY] : [];
}

async function rememberCarefulOrigin(origin) {
  const origins = await getAllowedOrigins();
  const next = [...new Set([...origins, origin])].slice(-100);
  await chrome.storage.sync.set({ [CAREFUL_ALLOW_KEY]: next });
}

async function handleMessage(message, sender) {
  const token = message?.token;
  if (message?.type === "get-context") {
    const context = await getPending(token);
    return context ? { ok: true, target: context.target } : { ok: false, error: "This check expired." };
  }

  if (message?.type === "get-settings") {
    return { ok: true, backendUrl: await getBackendUrl() };
  }

  if (message?.type === "set-settings") {
    return setBackendUrl(message.backendUrl);
  }

  if (message?.type === "is-careful-allowed") {
    const context = await getPending(token);
    const origin = context ? normalizeOrigin(context.target) : null;
    const allowed = origin ? (await getAllowedOrigins()).includes(origin) : false;
    return { ok: true, allowed };
  }

  if (message?.type === "remember-careful") {
    const context = await getPending(token);
    const origin = context ? normalizeOrigin(context.target) : null;
    if (!origin) {
      return { ok: false, error: "This check expired." };
    }
    await rememberCarefulOrigin(origin);
    return { ok: true };
  }

  if (message?.type === "open-target") {
    const context = await getPending(token);
    const tabId = sender.tab?.id;
    if (!context || typeof tabId !== "number" || tabId < 0) {
      return { ok: false, error: "This check expired." };
    }
    allowOnce.set(tabId, {
      target: context.target,
      expiresAt: Date.now() + ALLOW_ONCE_TTL_MS
    });
    await chrome.storage.session.remove(pendingKey(token));
    await chrome.tabs.update(tabId, { url: context.target });
    return { ok: true };
  }

  if (message?.type === "close-target") {
    const tabId = sender.tab?.id;
    if (validToken(token)) {
      await chrome.storage.session.remove(pendingKey(token));
    }
    if (typeof tabId === "number" && tabId >= 0) {
      await chrome.tabs.remove(tabId);
    }
    return { ok: true };
  }

  if (message?.type === "clear-remembered") {
    await chrome.storage.sync.set({ [CAREFUL_ALLOW_KEY]: [] });
    return { ok: true };
  }

  return { ok: false, error: "Unknown request." };
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  void handleMessage(message, sender)
    .then(sendResponse)
    .catch(() => sendResponse({ ok: false, error: "SafeNest could not complete that action." }));
  return true;
});

chrome.runtime.onInstalled.addListener(() => {
  void chrome.storage.sync.get({ [SETTINGS_KEY]: null }).then((stored) => {
    if (!stored[SETTINGS_KEY]) {
      return chrome.storage.sync.set({ [SETTINGS_KEY]: DEFAULT_BACKEND_URL });
    }
    return undefined;
  });
});

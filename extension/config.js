export const DEFAULT_BACKEND_URL = "http://127.0.0.1:8000";
export const SETTINGS_KEY = "backendUrl";
export const TOKEN_KEY = "userToken";
export const CAREFUL_ALLOW_KEY = "carefulAllowedOrigins";
export const PENDING_PREFIX = "pending:";

export function isWebUrl(value) {
  try {
    const parsed = new URL(value);
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return false;
  }
}

export function normalizeBackendUrl(value) {
  if (typeof value !== "string") {
    return null;
  }
  try {
    const parsed = new URL(value.trim());
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return null;
    }
    return parsed.origin;
  } catch {
    return null;
  }
}

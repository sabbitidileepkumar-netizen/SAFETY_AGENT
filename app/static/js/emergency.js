(() => {
    const $ = (id) => document.getElementById(id);
    const result = $("emergency-result");
    const privacyResult = $("privacy-result");
    if (!result) return;

    function token() {
        return $("emergency-session-token").value.trim();
    }

    async function api(path, options = {}) {
        const headers = { ...(options.headers || {}), Authorization: `Bearer ${token()}` };
        if (options.body) headers["Content-Type"] = "application/json";
        const response = await fetch(path, { ...options, headers });
        const data = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(data.detail || `Request failed (${response.status})`);
        return data;
    }

    function showResult(value) {
        result.textContent = JSON.stringify(value, null, 2);
    }

    async function refreshEmergency() {
        try {
            const [status, quarantine, approvals] = await Promise.all([
                api("/api/emergency/status"),
                api("/api/emergency/quarantine"),
                api("/api/emergency/approvals"),
            ]);
            showResult({ mode: "SIMULATED", status, quarantine, approvals });
        } catch (error) {
            showResult({ mode: "SIMULATED", error: error.message });
        }
    }

    $("emergency-request").addEventListener("click", async () => {
        const action = $("emergency-action").value;
        const payload = {
            action,
            level: $("emergency-level").value,
            reason: $("emergency-reason").value,
        };
        if (action === "QUARANTINE_FILE") payload.target = $("emergency-target").value.trim();
        try {
            const data = await api("/api/emergency/approvals", {
                method: "POST",
                body: JSON.stringify(payload),
            });
            $("emergency-approval-id").value = data.approval_id;
            showResult(data);
        } catch (error) {
            showResult({ mode: "SIMULATED", error: error.message });
        }
    });

    $("emergency-approve").addEventListener("click", async () => {
        const id = $("emergency-approval-id").value.trim();
        if (!id) return showResult({ mode: "SIMULATED", error: "Create or enter an approval request ID first." });
        try {
            showResult(await api(`/api/emergency/approvals/${encodeURIComponent(id)}/approve`, {
                method: "POST",
                body: JSON.stringify({ decision: "approve" }),
            }));
        } catch (error) {
            showResult({ mode: "SIMULATED", error: error.message });
        }
    });

    $("emergency-execute").addEventListener("click", async () => {
        const id = $("emergency-approval-id").value.trim();
        if (!id) return showResult({ mode: "SIMULATED", error: "Create or enter an approval request ID first." });
        try {
            showResult(await api(`/api/emergency/actions/${encodeURIComponent(id)}/execute`, { method: "POST" }));
        } catch (error) {
            showResult({ mode: "SIMULATED", error: error.message });
        }
    });

    $("emergency-refresh").addEventListener("click", refreshEmergency);

    $("privacy-load").addEventListener("click", async () => {
        try {
            const data = await api("/api/settings/privacy");
            $("allow-sms-gemini").checked = Boolean(data.settings.allow_sms_to_gemini);
            privacyResult.textContent = "Loaded your account privacy setting.";
        } catch (error) {
            privacyResult.textContent = error.message;
        }
    });

    $("privacy-save").addEventListener("click", async () => {
        try {
            const data = await api("/api/settings/privacy", {
                method: "PUT",
                body: JSON.stringify({ allow_sms_to_gemini: $("allow-sms-gemini").checked }),
            });
            privacyResult.textContent = `Saved. SMS sharing with Gemini: ${data.settings.allow_sms_to_gemini ? "enabled" : "disabled"}.`;
        } catch (error) {
            privacyResult.textContent = error.message;
        }
    });
})();

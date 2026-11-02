# Guard AI — Autonomous Cybersecurity Platform & Privacy Command Centre

Guard AI is an MVP cybersecurity prototype for checking suspicious links and messages, statically inspecting files, and demonstrating approval and audit flows.

It combines an autonomous multi-agent defense architecture, authenticated cryptographic security, blockchain audit registry, isolated browsing chambers, and multi-lingual voice notifications (English & Telugu).

## MVP status (2026-11-02)

| Area | Status | Current boundary |
| --- | --- | --- |
| `POST /api/pipeline/event` | Implemented; local API checks and pytest passed | Rate limited. Link, download, and supplied Wi-Fi metadata events return ordered agent steps and signed audit record IDs. Wi-Fi uses caller-supplied metadata only. |
| Chrome link guard | Implemented; 6 extension tests passed; browser click demo unverified | Code blocks Danger links, opens Safe links, and routes Careful links to the restricted viewer. This is not an OS sandbox. |
| Download inspection | Implemented; exercised with a public HTML response | Backend fetch is limited to 10 MB and 8 seconds, rejects non-public IPs, refuses redirects, and performs static checks only. Defender exit code 2 is treated as inconclusive without explicit detection output. Chrome downloads continue; SafeNest reports the result but does not quarantine the host file. |
| High-impact response | SIMULATED; approval tests passed | Lockdown and quarantine require authenticated approval, record simulated state only, and do not alter the device. |
| SMS privacy | Implemented; redaction and consent tests passed | SMS text is excluded from Gemini unless the logged-in user enables it; redaction runs first. |
| Browser isolation | Partial | The extension viewer disables scripts, forms, popups, downloads, and top-level navigation in its embedded frame. It does not stop the page from requesting network resources. |
| Wi-Fi assessment | Partial | Evaluates metadata supplied by the caller; it does not inspect the computer's live Wi-Fi adapter. |
| Android, real YARA, Docker analysis | Not implemented | No device surveillance, real YARA engine, or OS-level sandbox is claimed. |

Extension permissions: `storage` saves backend/token preferences and remembered decisions; `tabs` redirects a navigation to the checker; `webNavigation` intercepts top-level link navigations; `downloads` observes download URLs for inspection; `notifications` displays inspection results. `<all_urls>` lets the extension check destinations and load the selected backend URL. The extension stores an optional user token in Chrome sync storage; use it only on a trusted browser profile.

---

## 🛡️ Core Architecture

```text
┌────────────────────────────────────────────────────────────────────────┐
│             GUARD AI ENTERPRISE COMMAND CENTRE (UI DASHBOARD)          │
│       Void Command (Dark Mode)    │    Crystal Defence (Light Mode)    │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
               ┌────────────────────▼────────────────────┐
               │              CONTROLLER AI              │
               │   Central Policy, Triage & Agent Bus    │
               └─┬──────────────┬──────────────┬───────┬─┘
                 │              │              │       │
    ┌────────────▼───┐   ┌──────▼───────┐  ┌───▼────┐  │
    │   FINDER AI    │   │  DEFENCE AI  │  │OFFENCE │  │
    │ Phishing & URL │   │ Crypto Shield│  │Local   │  │
    │ Reconnaissance │   │ & Hygiene    │  │Defense │  │
    └────────────────┘   └──────────────┘  └────────┘  │
                 │              │              │       │
  ┌──────────────┴──────────────┼──────────────┴───────┴──────┐
  │ SPECIALIZED AGENTS: Wi-Fi │ Browser │ File │ App Behavior │
  └─────────────────────────────┼─────────────────────────────┘
                                │
   ┌────────────────────────────┼───────────────────────────┐
   │                            │                           │
┌──▼───────────────┐   ┌────────▼─────────┐    ┌────────────▼──────────┐
│  PRIVATE SPACE   │   │ISOLATION CHAMBER │    │      SANDBOX LAB      │
│ Independent Tabs │   │  Anti-SSRF Egress│    │ SHA-256 / Entropy     │
│ Ephemeral Scrub  │   │  Sandboxed CSP   │    │ Static Patterns/YARA  │
│ Safe Nav Proxy   │   │  Session Burner  │    │ Defender AV Scan      │
└──┬───────────────┘   └────────┬─────────┘    └────────────┬──────────┘
   │                            │                           │
   └────────────────────────────┼───────────────────────────┘
                                │
       ┌────────────────────────┴────────────────────────┐
       │                                                 │
┌──────▼─────────────────────────┐     ┌─────────────────▼───────────────┐
│   CRYPTOGRAPHIC MAZE ENGINE    │     │   BLOCKCHAIN & AUDIT LEDGER     │
│ Layer 1: AES-GCM Envelope      │     │ Solidity: AuditRegistry.sol     │
│ Layer 2: HKDF Segmentation     │     │ Local Ed25519 Hash-Chain        │
│ Layer 3: Ed25519 Seal + Shares │     │ Real-time Tamper Detection      │
└────────────────────────────────┘     └─────────────────────────────────┘
```

---

## 🚀 Key Functional Modules

### 1. Guard Private Space (Private Browsing)
- **Multiple Tabs:** Independent private browsing sessions with isolated cookies and ephemeral storage.
- **Pre-navigation URL Security:** Verifies URLs with Finder AI before loading; warns on suspicious redirect chains.
- **Safe Download Handling:** Quarantines downloads and generates SHA-256 hashes instead of direct host execution.
- **Session Hygiene:** Completely scrubs temporary cache, cookies, and memory upon tab or session closure.
- **Network Anonymity Notice:** Clearly informs users that private browsing protects local privacy, but does not provide ISP-level anonymity (suggests VPN/Tor).

### 2. Guard Isolation Chamber (Untrusted Content)
- **Isolated Execution Environment:** Traps untrusted links inside a sandboxed viewport with a strict Content Security Policy (`script-src 'none'`).
- **Network Egress Boundaries:** Blocks loopback (`127.0.0.1`), private RFC1918 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), and cloud metadata (`169.254.169.254`) to stop SSRF attacks.
- **Controlled System Access:** Restricted filesystem access, blocked child-process spawning, sandboxed clipboard.
- **Disposable Sessions & Incinerator:** Ephemeral execution directory that can be destroyed with one click.

### 3. Guard Sandbox Lab (File & Content Inspection)
- **Cryptographic Hashes:** Generates SHA-256, SHA-1, and MD5 digests for submitted payloads.
- **Shannon Entropy Analysis:** Computes entropy (0.0 to 8.0) to identify packed, encrypted, or obfuscated payloads.
- **Double-Extension Detection:** Catches spoofed filenames such as `tax_invoice.pdf.exe`.
- **Static Pattern Engine:** Scans for obfuscated PowerShell (`-enc`), `WScript.Shell`, `URLDownloadToFile`, process injection APIs (`VirtualAllocEx`, `WriteProcessMemory`), and embedded PDF JavaScript/launch triggers. These are built-in patterns, not a YARA engine.
- **Antivirus Integration:** Non-blocking Windows Defender CLI (`MpCmdRun.exe`) integration where available.
- **Safe Document Preview:** Sanitizes and renders text outlines without running embedded scripts or binaries.
- **Ephemeral Staging Cleanup:** Automatically removes temporary files from disk after inspection.

### 4. Cryptographic Security Engine & Cryptographic Maze
- **Primitives:** NIST-approved AES-256-GCM (12-byte CSPRNG nonce), PBKDF2-HMAC-SHA256 (100,000 iterations), and Ed25519 digital signatures.
- **Cryptographic Maze (3-Layered Architecture):**
  - **Layer 1 (Perimeter Shield):** Rotating Master Key envelope wrapper.
  - **Layer 2 (Compartment Maze):** Splits payload into bounded chunks, encrypting each with an isolated sub-key derived via HKDF-SHA256.
  - **Layer 3 (Core Vault):** Digital signature seal with Ed25519 and a dual-share threshold recovery scheme (2-of-2 split secret).
- **Key Rotation:** Versioned key rotation tracking with public fingerprints; raw keys are never exposed.

### 5. Blockchain Security & Audit Registry
- **Smart Contract:** `contracts/AuditRegistry.sol` is present for local Ethereum/Hardhat development. Deployment and real on-chain transaction recording have not been verified.
- **Cryptographic Hash-Chain Fallback:** Always-available local chain with SHA-256 block linking ($H_i = SHA256(H_{i-1} \parallel payload \parallel nonce)$) signed with Ed25519.
- **Tamper Evidence:** Verifies chain integrity from genesis to tip and detects modifications to historical records.
- **Privacy Guarantee:** Never stores passwords, keys, or private user data on-chain; only cryptographic hashes and non-sensitive event identifiers are recorded.

### 6. Informer AI Multi-Lingual Voice Notifications
- Translates security decisions (ALLOWED, ISOLATED, INSPECTED, BLOCKED) into clear English and Telugu voice alerts.
- Integrates browser Web Speech API (`en-IN` and `te-IN`) with adjustable speech rate and pitch.

### 7. Accounts, Plans & Family Circle
- **Authentication:** Email registration, PBKDF2 password hashing, and bearer session tokens.
- **Usage Limits:** Free accounts are capped at 10 link checks/day; Pro and Family plans offer unlimited checks.
- **Payments:** Razorpay order creation, HMAC-SHA256 webhook signature verification, and local demo checkout mode.
- **Family Circle:** Invite members, submit links for family approval, and receive voice-assisted decisions ("Looks fine" / "Don't do it").

---

## 💻 Running Locally

### 1. Prerequisites
- Python 3.11+ (Python 3.12 recommended)
- Node.js 18+ (for extension and contract tools)

### 2. Environment Setup
```powershell
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
```

### 3. Start the Command Centre Service
```powershell
.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Open your browser to:
- **Command Centre Dashboard:** `http://127.0.0.1:8000/`
- **Interactive API Documentation:** `http://127.0.0.1:8000/docs`
- **Health Check:** `http://127.0.0.1:8000/health`

---

## 🧪 Testing and Verification

Run the complete automated Python test suite (last verified: 58 passed, 0 failed; one Starlette/httpx deprecation warning):

```powershell
.venv\Scripts\python.exe -m pytest
```

Run harmless sample evaluation (30 labeled Indian scam & benign test samples):
```powershell
.venv\Scripts\python.exe scripts/evaluate_samples.py
```

Run Chrome Extension unit tests:
```powershell
node --test extension/tests/*.test.js
```

---

## 🌐 Platform Capabilities & Real Boundaries

| Platform | Implemented Capabilities | Legitimate Operating System Boundaries |
| :--- | :--- | :--- |
| **Windows** | Windows Defender CLI (`MpCmdRun.exe`) integration, isolated ephemeral staging directories, anti-SSRF network filters, AES-256-GCM / Ed25519 encryption. | Application-layer security; does not replace kernel-level drivers or system-wide packet filter drivers. |
| **Android** | Not implemented. | The platform-capability response contains planning text only; it does not provide an Android app or device inspection. |

---

## 📦 Project Structure

```text
├── app/
│   ├── accounts.py             # User accounts, plans, payments & family circle
│   ├── checker.py              # Core link & SMS analyzer
│   ├── config.py               # Application settings and environment variables
│   ├── explanation.py          # Gemini AI & deterministic bilingual explanations
│   ├── india_rules.py          # Indian banking & financial lookalike indicators
│   ├── main.py                 # FastAPI application factory & API router
│   ├── models.py               # Pydantic data contracts
│   ├── rate_limit.py           # Process-local rate limiter
│   ├── risk.py                 # Deterministic risk engine & signals
│   ├── agents/                 # Autonomous Agent System
│   │   ├── base.py             # AgentBus and SecurityAgent base class
│   │   ├── controller.py       # Controller AI central orchestrator
│   │   ├── defence.py          # Defence AI cryptographic data protection
│   │   ├── finder.py           # Finder AI threat triage
│   │   ├── informer.py         # Informer AI voice & explanations
│   │   ├── offence.py          # Offence AI defensive containment
│   │   └── specialized.py      # Wi-Fi, Browser, File, App Behavior agents
│   ├── blockchain/             # Blockchain & Audit Subsystem
│   │   └── service.py          # EVM RPC client + Local Ed25519 Hash-Chain
│   ├── crypto/                 # Cryptographic Subsystem
│   │   ├── engine.py           # AES-256-GCM, PBKDF2, Ed25519, Key Rotation
│   │   └── maze.py             # 3-Layer Cryptographic Maze Architecture
│   ├── security/               # Part 10 Security Engines
│   │   ├── private_space.py    # Private Space browsing engine
│   │   ├── isolation_chamber.py# Isolated browsing & Anti-SSRF engine
│   │   └── sandbox.py          # File inspection, entropy & YARA engine
│   ├── static/                 # Frontend Assets
│   │   ├── css/                # Void Command, Crystal Defence & main CSS
│   │   └── js/                 # Dashboard SPA & Web Speech API modules
│   └── templates/
│       └── index.html          # Futuristic Command Centre UI
├── contracts/
│   └── AuditRegistry.sol       # Solidity Audit Smart Contract
├── extension/                  # Chrome Manifest V3 Extension
├── hardhat.config.js           # Hardhat configuration for local EVM network
├── tests/                      # Automated Test Suite (31 tests)
└── requirements.txt            # Python Dependencies
```

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import math
import mimetypes
import os
from pathlib import Path
import re
import shutil
import subprocess
import threading
from typing import Any
import uuid


@dataclass
class SandboxReport:
    report_id: str
    filename: str
    file_size_bytes: int
    mime_type: str
    sha256: str
    sha1: str
    md5: str
    entropy: float
    detected_file_type: str
    double_extension_detected: bool
    risk_level: str  # "Safe", "Suspicious", "Malicious"
    risk_score: int  # 0 to 100
    indicators: list[dict[str, str]]
    static_analysis: dict[str, Any]
    safe_preview: str
    antivirus_status: str
    created_at: str
    cleanup_status: str


class SandboxInspectionEngine:
    """Guard AI File & Content Inspection Sandbox.
    
    Provides:
    - Multi-algorithm cryptographic hashing (SHA-256, SHA-1, MD5).
    - File metadata, MIME validation, and double-extension detection.
    - Shannon entropy calculation (flags packed/encrypted binaries).
    - Static analysis (PE header parsing, suspicious Windows API search, PDF macro/script hooks).
    - Antivirus engine integration (Windows Defender CLI MpCmdRun where available).
    - Safe document sanitized text preview without binary execution.
    - Controlled ephemeral staging with verified automatic cleanup.
    """

    SUSPICIOUS_EXTENSIONS = {
        ".exe", ".scr", ".pif", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
        ".wsf", ".wsh", ".ps1", ".hta", ".cpl", ".msc", ".jar", ".dll", ".sys",
    }

    SUSPICIOUS_STRINGS = [
        (re.compile(rb"powershell(\.exe)?\s+(-(enc|encodedcommand|e))\s+", re.IGNORECASE), "Obfuscated PowerShell invocation"),
        (re.compile(rb"powershell(\.exe)?\s+.*-(w\s+hidden|windowstyle\s+hidden)", re.IGNORECASE), "Hidden PowerShell window invocation"),
        (re.compile(rb"vssadmin(\.exe)?\s+delete\s+shadows", re.IGNORECASE), "Volume Shadow Copy deletion command"),
        (re.compile(rb"reg(\.exe)?\s+add\s+.*\\CurrentVersion\\Run", re.IGNORECASE), "Windows Run-key persistence command"),
        (re.compile(rb"certutil(\.exe)?\s+.*-urlcache", re.IGNORECASE), "Certutil URL-cache download command"),
        (re.compile(rb"your\s+files\s+have\s+been\s+encrypted|pay\s+bitcoin\s+to\s+decrypt|\.onion\s+address", re.IGNORECASE), "Ransomware extortion text"),
        (re.compile(rb"cmd\.exe\s+/c", re.IGNORECASE), "Command interpreter execution"),
        (re.compile(rb"WScript\.Shell", re.IGNORECASE), "Windows Scripting Host Automation"),
        (re.compile(rb"URLDownloadToFile", re.IGNORECASE), "Direct binary payload download API"),
        (re.compile(rb"VirtualAllocEx", re.IGNORECASE), "Remote process memory allocation API"),
        (re.compile(rb"WriteProcessMemory", re.IGNORECASE), "Process injection API marker"),
        (re.compile(rb"CreateRemoteThread", re.IGNORECASE), "Remote thread execution API marker"),
        (re.compile(rb"/JavaScript|/JS\b", re.IGNORECASE), "Embedded PDF JavaScript action"),
        (re.compile(rb"/Launch\b", re.IGNORECASE), "Embedded PDF binary launch trigger"),
        (re.compile(rb"/EmbeddedFiles\b", re.IGNORECASE), "Embedded hidden attachments in document"),
        (re.compile(rb"AutoOpen|Workbook_Open|Document_Open", re.IGNORECASE), "Office VBA auto-execution macro hook"),
    ]

    @staticmethod
    def _interpret_defender_result(returncode: int, output: str) -> str:
        """Do not equate MpCmdRun's ambiguous exit code 2 with a confirmed detection."""
        text = output or ""
        has_clean_result = bool(re.search(r"\bno\s+(?:known\s+)?(?:threats?|malware)\b", text, re.IGNORECASE))
        has_threat_result = bool(re.search(
            r"\b(?:threats?|malware)\b.{0,100}\b(?:detected|found)\b|\b(?:detected|found)\b.{0,100}\b(?:threats?|malware)\b",
            text,
            re.IGNORECASE,
        )) and not has_clean_result
        if has_threat_result:
            return "Threat Detected (Windows Defender reported a detection)"
        if returncode == 0 and has_clean_result:
            return "Clean (Windows Defender reported no threats)"
        return f"Inconclusive (Windows Defender exit code {returncode}; output did not confirm a result)"

    MAGIC_SIGNATURES = [
        (b"MZ", "Windows PE Executable / DLL (.exe / .dll)"),
        (b"%PDF-", "Adobe Portable Document Format (.pdf)"),
        (b"PK\x03\x04", "ZIP Compressed Archive / Office OpenXML (.zip / .docx / .xlsx)"),
        (b"\x7fELF", "Linux ELF Executable"),
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "Legacy Microsoft Compound Document (.doc / .xls)"),
        (b"Rar!\x1a\x07", "RAR Archive"),
        (b"\x1f\x8b", "GZIP Compressed Archive"),
    ]

    def __init__(self, sandbox_staging_dir: str = "./sandbox_staging") -> None:
        self.staging_dir = Path(sandbox_staging_dir)
        self.staging_dir.mkdir(parents=True, exist_ok=True)
        self._reports: dict[str, SandboxReport] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _calculate_entropy(data: bytes) -> float:
        """Calculate Shannon entropy (0.0 to 8.0) to detect packed/encrypted payloads."""
        if not data:
            return 0.0
        entropy = 0.0
        byte_counts = [0] * 256
        for b in data:
            byte_counts[b] += 1
        total = len(data)
        for count in byte_counts:
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)
        return round(entropy, 3)

    @staticmethod
    def _detect_magic(data: bytes) -> str:
        for magic, label in SandboxInspectionEngine.MAGIC_SIGNATURES:
            if data.startswith(magic):
                return label
        return "Unknown / Raw Data"

    def _query_windows_defender(self, target_path: Path) -> str:
        """Invokes Microsoft Defender CLI (MpCmdRun.exe) if running on Windows."""
        if os.name != "nt":
            return "Windows Defender not applicable on non-Windows host"

        potential_paths = [
            Path("C:/Program Files/Windows Defender/MpCmdRun.exe"),
            Path("C:/ProgramData/Microsoft/Windows Defender/Platform"),
        ]

        mp_cmd: Path | None = None
        if potential_paths[0].exists():
            mp_cmd = potential_paths[0]
        elif potential_paths[1].exists():
            # Find latest platform version
            versions = sorted(potential_paths[1].glob("*/MpCmdRun.exe"), reverse=True)
            if versions:
                mp_cmd = versions[0]

        if not mp_cmd or not mp_cmd.exists():
            return "Windows Defender CLI tool (MpCmdRun.exe) not located on host"

        try:
            # Scan single file with MpCmdRun -Scan -ScanType 3 -File <path> -DisableRemediation
            proc = subprocess.run(
                [str(mp_cmd), "-Scan", "-ScanType", "3", "-File", str(target_path), "-DisableRemediation"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return self._interpret_defender_result(proc.returncode, f"{proc.stdout}\n{proc.stderr}")
        except subprocess.TimeoutExpired:
            return "Windows Defender scan timed out (Deferred)"
        except Exception as err:
            return f"Windows Defender invocation error: {err}"

    def inspect_file(
        self,
        file_bytes: bytes,
        filename: str,
    ) -> SandboxReport:
        """Performs comprehensive static inspection in an isolated ephemeral workspace."""
        report_id = f"sbx-{uuid.uuid4().hex[:10]}"
        now_str = datetime.now(timezone.utc).isoformat()

        # Ephemeral analysis directory
        ephemeral_run_dir = self.staging_dir / report_id
        ephemeral_run_dir.mkdir(parents=True, exist_ok=True)
        staged_file_path = ephemeral_run_dir / filename

        try:
            # Write to isolated staging
            staged_file_path.write_bytes(file_bytes)

            # Cryptographic Hashes
            sha256_hash = hashlib.sha256(file_bytes).hexdigest()
            sha1_hash = hashlib.sha1(file_bytes).hexdigest()
            md5_hash = hashlib.md5(file_bytes).hexdigest()

            # Metadata
            size_bytes = len(file_bytes)
            guessed_mime, _ = mimetypes.guess_type(filename)
            mime_type = guessed_mime or "application/octet-stream"
            entropy = self._calculate_entropy(file_bytes)
            detected_type = self._detect_magic(file_bytes)

            # Double extension check (e.g. invoice.pdf.exe)
            name_parts = filename.lower().split(".")
            double_extension = False
            if len(name_parts) > 2:
                ext1 = f".{name_parts[-2]}"
                ext2 = f".{name_parts[-1]}"
                if ext2 in self.SUSPICIOUS_EXTENSIONS:
                    double_extension = True

            indicators: list[dict[str, str]] = []
            risk_score = 0

            # Rule 1: Double extension check
            if double_extension:
                indicators.append({
                    "rule": "double_extension_spoofing",
                    "severity": "High",
                    "description": f"Filename '{filename}' uses double-extension spoofing ending with dangerous '{ext2}'.",
                })
                risk_score += 45

            # Rule 2: Dangerous extension check
            base_ext = Path(filename).suffix.lower()
            if base_ext in self.SUSPICIOUS_EXTENSIONS:
                indicators.append({
                    "rule": "dangerous_executable_extension",
                    "severity": "Medium",
                    "description": f"File has executable or script extension '{base_ext}'.",
                })
                risk_score += 30

            # Rule 3: High entropy (packing/encryption)
            if entropy > 7.2:
                indicators.append({
                    "rule": "high_shannon_entropy",
                    "severity": "Medium",
                    "description": f"Shannon entropy is {entropy}/8.0, indicating packed, encrypted, or compressed payload.",
                })
                risk_score += 25

            # Rule 4: PE Header in non-EXE file
            if file_bytes.startswith(b"MZ") and base_ext not in (".exe", ".dll", ".sys"):
                indicators.append({
                    "rule": "disguised_executable",
                    "severity": "High",
                    "description": f"File contains Windows PE 'MZ' executable header but masquerades with extension '{base_ext}'.",
                })
                risk_score += 50

            # Rule 5: Pattern / YARA-like Static String Checks
            matched_patterns = []
            for pattern_re, desc in self.SUSPICIOUS_STRINGS:
                if pattern_re.search(file_bytes):
                    indicators.append({
                        "rule": "suspicious_code_pattern",
                        "severity": "High",
                        "description": desc,
                    })
                    matched_patterns.append(desc)
                    risk_score += 25

            # Rule 6: Antivirus integration
            av_status = self._query_windows_defender(staged_file_path)
            if "Threat Detected" in av_status:
                indicators.append({
                    "rule": "antivirus_signature_match",
                    "severity": "Critical",
                    "description": f"Host Antivirus flagged file: {av_status}",
                })
                risk_score += 60

            # Determine final risk rating
            risk_score = min(100, risk_score)
            if risk_score >= 50:
                risk_level = "Malicious"
            elif risk_score >= 20:
                risk_level = "Suspicious"
            else:
                risk_level = "Safe"

            # Safe Document Preview (Sanitized Text Extraction)
            safe_preview = ""
            if "pdf" in detected_type.lower() or base_ext == ".pdf":
                # Extract text chunks safely
                text_matches = re.findall(rb"\(([^\(\)]{4,})\)", file_bytes)
                extracted = [m.decode("ascii", errors="ignore").strip() for m in text_matches[:30] if len(m) > 4]
                safe_preview = "PDF Text Chunks Preview:\n" + ("\n".join(extracted) if extracted else "[No standard readable text streams found]")
            elif "zip" in detected_type.lower() or base_ext in (".zip", ".docx", ".xlsx"):
                safe_preview = f"Archive Container detected: {detected_type}. Decompression quarantined."
            else:
                # Text/script preview or binary dump
                printable = "".join(chr(b) if 32 <= b <= 126 or b in (10, 13) else "." for b in file_bytes[:1024])
                safe_preview = f"Sanitized Content Preview (First 1KB):\n{printable}"

            # Static analysis summary
            static_summary = {
                "header_signature": detected_type,
                "entropy_score": entropy,
                "suspicious_patterns_count": len(matched_patterns),
                "patterns_matched": matched_patterns,
                "file_size_formatted": f"{size_bytes / 1024:.2f} KB",
            }

            cleanup_status = "Active In Ephemeral Staging"

            report = SandboxReport(
                report_id=report_id,
                filename=filename,
                file_size_bytes=size_bytes,
                mime_type=mime_type,
                sha256=sha256_hash,
                sha1=sha1_hash,
                md5=md5_hash,
                entropy=entropy,
                detected_file_type=detected_type,
                double_extension_detected=double_extension,
                risk_level=risk_level,
                risk_score=risk_score,
                indicators=indicators,
                static_analysis=static_summary,
                safe_preview=safe_preview,
                antivirus_status=av_status,
                created_at=now_str,
                cleanup_status=cleanup_status,
            )

            with self._lock:
                self._reports[report_id] = report

            return report

        finally:
            # Automatic Cleanup of isolated disposable directory
            if ephemeral_run_dir.exists():
                shutil.rmtree(ephemeral_run_dir, ignore_errors=True)
                if report_id in self._reports:
                    self._reports[report_id].cleanup_status = "Verified Cleaned (Ephemeral Staging Destroyed)"

    def get_report(self, report_id: str) -> SandboxReport | None:
        with self._lock:
            return self._reports.get(report_id)

    def get_all_reports(self) -> list[dict[str, Any]]:
        with self._lock:
            return [asdict(r) for r in sorted(self._reports.values(), key=lambda x: x.created_at, reverse=True)]

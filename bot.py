"""AI-enhanced APK Virus Checker Telegram bot.

User sends any .apk file in a private chat; the bot checks it step by step
like an agent AI and reports a verdict, a summary and a final risk rating:
  Step 1 — File info (name, size, MD5, SHA256)
  Step 2 — Static analysis with androguard (package, version, SDKs,
           permissions with DANGEROUS ones flagged, component counts,
           hard-coded URLs/domains, suspicious API calls, debuggable /
           allowBackup / install-packages / device-admin flags)
  Step 3 — APKiD (packers, compilers, obfuscators, anti-analysis tricks)
  Step 4 — VirusTotal v3 scan (malicious/suspicious engine counts)
  Step 5 — AI summary + final rating via OpenRouter (free tier) or a
           rule-based fallback (score out of 10 + risk level)

Batch / queue: the user can send several APKs one after another. They are
queued per user (max 5 pending) and scanned one by one, labelled
App 1, App 2, App 3, ... Each APK gets its own full report. Different users
have independent queues.

Env vars (no secrets are hardcoded or logged):
  BOT_TOKEN, API_ID, API_HASH   (required — BotFather / my.telegram.org)
  SESSION_STRING                (optional — Pyrogram user session string for the
                                 helper user client; needed only to download
                                 APKs over 20 MB, up to the 300 MB limit)
  HELPER_USER_ID                (optional — Telegram user id of the helper
                                 account, default 8657748041 = GHOST; the bot
                                 forwards >20 MB documents to this account so
                                 the helper owns the message and can download it)
  VIRUSTOTAL_API_KEY            (optional — skips the VirusTotal step if unset)
  OPENROUTER_API_KEY            (optional — falls back to rule assessment if unset)
  OPENROUTER_MODEL              (optional, default cohere/north-mini-code:free)

Pyrogram only, built-in app.run() runner. Every external call is wrapped so
one failing step never kills the whole check. Downloaded APKs are deleted
after the check. Files up to 20 MB are downloaded by the bot client
(Telegram Bot API limit); files from 20 MB up to 300 MB are downloaded by
the helper user client (MTProto) when SESSION_STRING is set — the bot first
forwards the document to the helper account (HELPER_USER_ID) because the
helper is not a participant in the user<->bot DM and cannot download the
file by file_id otherwise. Without the helper, files over 20 MB are
rejected with a clear message. Every download is verified (file exists,
non-empty, size matches Telegram's file_size) before any analysis runs —
a failed download is reported as an error, never analysed as an empty file.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile

import requests
from pyrogram import Client, filters
from pyrogram.types import Message

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("virus-checker-bot")

API_ID = int(os.environ.get("API_ID", "0") or 0)
API_HASH = os.environ.get("API_HASH", "")
BOT_TOKEN = os.environ.get("BOT_TOKEN", "")
SESSION_STRING = os.environ.get("SESSION_STRING", "").strip()
# Telegram user id of the helper account (the account behind SESSION_STRING).
# The bot forwards >20 MB documents to this account so the helper owns the
# message and can download the file. Default 8657748041 = GHOST.
HELPER_USER_ID = int(os.environ.get("HELPER_USER_ID", "") or 8657748041)
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY", "").strip()
OPENROUTER_MODEL = os.environ.get("OPENROUTER_MODEL", "cohere/north-mini-code:free")
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
VIRUSTOTAL_BASE = "https://www.virustotal.com/api/v3"

MAX_APK_BYTES = 300 * 1024 * 1024  # 300 MB — hard limit for any APK check
BOT_DOWNLOAD_LIMIT = 20 * 1024 * 1024  # Telegram Bot API download limit (~20 MB)
VT_POLL_ATTEMPTS = 12
VT_POLL_DELAY_S = 15
MAX_QUEUE_PER_USER = 5  # max APKs pending/running per user (batch cap)
QUEUE_IDLE_TIMEOUT_S = 10  # worker exits if no new APK arrives for this long

# Android permissions that are dangerous / commonly abused by malware.
DANGEROUS_PERMISSIONS = {
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.CALL_PHONE",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_MEDIA_AUDIO",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.GET_ACCOUNTS",
    "android.permission.USE_FULL_SCREEN_INTENT",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.BODY_SENSORS",
    "android.permission.BLUETOOTH_CONNECT",
    "android.permission.NEARBY_WIFI_DEVICES",
}

# Short human-readable note for the most abused permissions (shown in report).
PERMISSION_NOTES = {
    "android.permission.SEND_SMS": "SMS bhej sakta hai (paise kat sakte hain)",
    "android.permission.READ_SMS": "tumhare SMS padh sakta hai (OTP chori ka risk)",
    "android.permission.RECEIVE_SMS": "aane wale SMS rok/padh sakta hai",
    "android.permission.BIND_DEVICE_ADMIN": "device admin — uninstall rok sakta hai",
    "android.permission.REQUEST_INSTALL_PACKAGES": "dusre apps install kar sakta hai",
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "screen par sab kuch dekh sakta hai",
    "android.permission.SYSTEM_ALERT_WINDOW": "dusre apps ke upar window dikha sakta hai",
    "android.permission.RECORD_AUDIO": "mic se recording kar sakta hai",
    "android.permission.CAMERA": "camera use kar sakta hai",
    "android.permission.ACCESS_FINE_LOCATION": "exact location dekh sakta hai",
    "android.permission.READ_CONTACTS": "contacts padh sakta hai",
    "android.permission.READ_CALL_LOG": "call history padh sakta hai",
}

VERDICT_EMOJI = {"SAFE": "✅", "SUSPICIOUS": "⚠️", "MALICIOUS": "🚨"}

# URL shortener domains (suspicious when hard-coded in an APK).
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd", "cutt.ly",
    "shorturl.at", "rebrand.ly", "bitly.com", "ow.ly", "buff.ly",
    "tiny.cc", "rb.gy", "s.id", "v.gd", "clck.ru", "short.cm",
    "shrtco.de", "tinyurl", "shorturl",
}

URL_RE = re.compile(r'https?://[^\s"\'<>\)\]\}]+')
IP_URL_RE = re.compile(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')

# Suspicious API / method-call indicators searched in DEX strings.
# (substring to look for, short label shown in the report)
SUSPICIOUS_CALLS = [
    ("Ldalvik/system/DexClassLoader;", "DexClassLoader (dynamic code loading)"),
    ("Ldalvik/system/PathClassLoader;", "PathClassLoader (dynamic code loading)"),
    ("Ljava/lang/reflect/Method;", "Reflection (java.lang.reflect)"),
    ("Ljava/lang/Class;->forName", "Class.forName (reflection)"),
    ("Landroid/telephony/SmsManager;", "SmsManager (SMS sending)"),
    ("sendTextMessage", "sendTextMessage (SMS)"),
    ("Ljava/lang/Runtime;", "Runtime.exec (shell commands)"),
    ("Ljavax/crypto/Cipher;", "Crypto (javax.crypto.Cipher)"),
    ("/system/bin/su", "su binary (root check)"),
    ("/system/xbin/su", "su binary (root check)"),
]

app = Client("virus-checker-bot", api_id=API_ID, api_hash=API_HASH, bot_token=BOT_TOKEN)

# Helper user client (MTProto) for downloading APKs over the 20 MB Bot API
# limit, up to the 300 MB cap. Created only when SESSION_STRING is set;
# otherwise it stays None and large files are rejected with a clear message.
# It is started in __main__ before app.run() and stopped on shutdown.
# The session is used by this service only — never share one session string
# between two live services.
user_app: Client | None = None
if SESSION_STRING:
    user_app = Client(
        "virus-checker-helper",
        api_id=API_ID,
        api_hash=API_HASH,
        session_string=SESSION_STRING,
    )


def choose_download_path(file_size: int, user_available: bool) -> str:
    """Pick how an APK of `file_size` bytes should be downloaded.

    Returns one of:
      "bot"         — <= 20 MB, the bot client downloads it (Bot API).
      "user"        — > 20 MB and <= 300 MB, the helper user client
                      downloads it by file_id (MTProto).
      "too_big"     — > 300 MB, rejected outright.
      "need_helper" — > 20 MB but no helper user client is configured.
    Pure function (no I/O) so the routing is easy to test.
    """
    if file_size > MAX_APK_BYTES:
        return "too_big"
    if file_size <= BOT_DOWNLOAD_LIMIT:
        return "bot"
    if user_available:
        return "user"
    return "need_helper"


# ---------------------------------------------------------------- pure helpers
def format_size(num_bytes: int) -> str:
    """Human-readable file size."""
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    return f"{num_bytes} B"


def file_hashes(path: str) -> tuple[str, str]:
    """Return (md5, sha256) hex digests of a file."""
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            md5.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha256.hexdigest()


def flag_permissions(perms: list[str]) -> tuple[list[str], list[str]]:
    """Split a permission list into (dangerous, other). Order preserved."""
    dangerous = [p for p in perms if p in DANGEROUS_PERMISSIONS]
    other = [p for p in perms if p not in DANGEROUS_PERMISSIONS]
    return dangerous, other


def level_from_score(score: int) -> str:
    """Risk level from a 0-10 score."""
    if score <= 1:
        return "SAFE"
    if score <= 3:
        return "LOW"
    if score <= 5:
        return "MEDIUM"
    if score <= 7:
        return "HIGH"
    return "CRITICAL"


def verdict_from_level(level: str) -> str:
    """Top-level verdict (SAFE/SUSPICIOUS/MALICIOUS) from a risk level."""
    if level in ("SAFE", "LOW"):
        return "SAFE"
    if level == "MEDIUM":
        return "SUSPICIOUS"
    return "MALICIOUS"


def _perm_short(name: str) -> str:
    return name.replace("android.permission.", "")


# ---------------------------------------------------------------- step 2: androguard (expanded)
def _dex_strings(dex_list) -> list[str]:
    """Collect DEX strings (capped) for URL / suspicious-call scanning."""
    strings: list[str] = []
    try:
        for dex_obj in (dex_list or []):
            try:
                strings.extend(dex_obj.get_strings() or [])
            except Exception:  # noqa: BLE001 - one bad DEX must not kill the step
                continue
            if len(strings) > 200000:
                break
    except Exception:  # noqa: BLE001
        pass
    return strings


def _flag_url(url: str) -> str:
    """Return a short reason if a URL is suspicious, else ''."""
    low = url.lower()
    if IP_URL_RE.search(low):
        return "raw IP address"
    m = re.search(r'https?://([^/:\s]+)', low)
    if m:
        domain = m.group(1)
        if domain.startswith("www."):
            domain = domain[4:]
        for short in URL_SHORTENERS:
            if domain == short or domain.endswith("." + short):
                return "URL shortener"
    if low.startswith("http://"):
        return "http (not https)"
    return ""


def _get_allow_backup(apk) -> bool | None:
    """True if the manifest allows backup, False if it forbids it, None if unknown."""
    try:
        app_elem = apk.get_application()
        if app_elem is None:
            return None
        ns = "{http://schemas.android.com/apk/res/android}"
        for attr in ("allowBackup", ns + "allowBackup"):
            val = app_elem.get(attr)
            if val is not None:
                return str(val).strip().lower() in ("true", "1")
        return None
    except Exception:  # noqa: BLE001
        return None


def analyze_apk_static(path: str) -> dict:
    """Expanded static analysis with androguard. Raises on parse failure.

    Returns package/version/SDK info, permissions, component counts, plus
    hard-coded URLs (with suspicious ones flagged), suspicious API calls
    found in DEX strings, and flags for debuggable / allowBackup /
    install-packages / device-admin.
    """
    from androguard.misc import AnalyzeAPK
    apk, dex_list, _analysis = AnalyzeAPK(path)
    perms = list(apk.get_permissions() or [])

    # DEX strings -> URLs + suspicious API calls.
    strings = _dex_strings(dex_list)
    blob = "\n".join(strings)
    urls: list[str] = []
    seen_urls: set[str] = set()
    for raw in URL_RE.findall(blob):
        url = raw.rstrip(".,;:!?)]}'\"")
        if url and url not in seen_urls:
            seen_urls.add(url)
            urls.append(url)
        if len(urls) >= 20:
            break
    suspicious_urls = []
    for url in urls:
        reason = _flag_url(url)
        if reason:
            suspicious_urls.append({"url": url, "reason": reason})
        if len(suspicious_urls) >= 8:
            break
    suspicious_calls = [label for needle, label in SUSPICIOUS_CALLS if needle in blob]

    # Flags.
    flags: list[str] = []
    try:
        if apk.is_debuggable():
            flags.append("debuggable")
    except Exception:  # noqa: BLE001
        pass
    allow_backup = _get_allow_backup(apk)
    if allow_backup is True:
        flags.append("allowBackup")
    if "android.permission.REQUEST_INSTALL_PACKAGES" in perms:
        flags.append("install-packages")
    if "android.permission.BIND_DEVICE_ADMIN" in perms:
        flags.append("device-admin")

    return {
        "package": apk.get_package() or "unknown",
        "app_name": apk.get_app_name() or "unknown",
        "version_name": apk.get_version_name() or "unknown",
        "version_code": str(apk.get_version_code() or "unknown"),
        "min_sdk": str(apk.get_min_sdk_version() or "unknown"),
        "target_sdk": str(apk.get_target_sdk_version() or "unknown"),
        "permissions": perms,
        "activities": len(apk.get_activities() or []),
        "services": len(apk.get_services() or []),
        "receivers": len(apk.get_receivers() or []),
        "providers": len(apk.get_providers() or []),
        "debuggable": "debuggable" in flags,
        "allow_backup": allow_backup,
        "flags": flags,
        "urls": urls,
        "url_count": len(urls),
        "suspicious_urls": suspicious_urls,
        "suspicious_calls": suspicious_calls,
    }


# ---------------------------------------------------------------- step 3: APKiD
def _as_str_list(value) -> list[str]:
    """Coerce an APKiD result value into a list of strings."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple, set)):
        out: list[str] = []
        for item in value:
            if isinstance(item, str):
                out.append(item)
            elif isinstance(item, dict):
                name = item.get("name") or item.get("rule") or item.get("id")
                if name:
                    out.append(str(name))
            else:
                out.append(str(item))
        return out
    return [str(value)]


def _flatten_apkid_result(result) -> dict:
    """Flatten an APKiD result (flat dict, nested per-file dict, or list)
    into a single {category: [items]} dict."""
    flat: dict[str, list[str]] = {}
    if isinstance(result, dict):
        for key, val in result.items():
            if isinstance(val, dict):
                for k2, v2 in val.items():
                    flat.setdefault(k2, []).extend(_as_str_list(v2))
            else:
                flat.setdefault(key, []).extend(_as_str_list(val))
    elif isinstance(result, list):
        for entry in result:
            if isinstance(entry, dict):
                sub = _flatten_apkid_result(entry)
                for k, v in sub.items():
                    flat.setdefault(k, []).extend(v)
    return flat


def _normalize_apkid(flat: dict) -> dict:
    """Map APKiD categories (singular or plural keys) to our fields."""
    def pick(*keys: str) -> list[str]:
        out: list[str] = []
        for key in keys:
            out.extend(_as_str_list(flat.get(key)))
        return sorted(set(out))[:5]

    packers = pick("packer", "packers")
    compilers = pick("compiler", "compilers")
    obfuscators = pick("obfuscator", "obfuscators")
    protectors = pick("protector", "protectors")
    anti: list[str] = []
    for key in ("anti_vm", "anti_disassembly", "anti_debug", "anti_emulator", "anti"):
        for item in _as_str_list(flat.get(key)):
            anti.append(f"{key}:{item}")
    anti = sorted(set(anti))[:8]
    known = {"packer", "packers", "compiler", "compilers", "obfuscator",
             "obfuscators", "protector", "protectors", "anti_vm",
             "anti_disassembly", "anti_debug", "anti_emulator", "anti",
             "file", "filename", "path"}
    other: list[str] = []
    for key, val in flat.items():
        if key in known:
            continue
        for item in _as_str_list(val):
            other.append(f"{key}:{item}")
    other = sorted(set(other))[:8]
    return {
        "packers": packers,
        "compilers": compilers,
        "obfuscators": obfuscators,
        "protectors": protectors,
        "anti_flags": anti,
        "other": other,
    }


def analyze_apkid(path: str) -> dict:
    """APKiD scan (packers, compilers, obfuscators, anti-analysis tricks).

    Tries the Python API first, then the `apkid -j` CLI. Never raises:
    if APKiD is missing or fails, returns available=False with a note so
    the step is skipped gracefully.
    """
    result: dict = {"available": False, "note": "", "packers": [],
                    "compilers": [], "obfuscators": [], "protectors": [],
                    "anti_flags": [], "other": []}
    # 1. Python API.
    try:
        try:
            from apkid.apkid import APKiD
        except ImportError:
            from apkid import APKiD  # fallback import path
        raw = APKiD().analyze(path)
        result.update(_normalize_apkid(_flatten_apkid_result(raw)))
        result["available"] = True
        result["note"] = "APKiD scan complete."
        return result
    except ImportError:
        pass  # APKiD not installed — try the CLI, then give up gracefully
    except Exception as exc:  # noqa: BLE001
        log.warning("APKiD Python API failed: %s", exc)
    # 2. CLI fallback (`apkid <apk> -j`).
    try:
        proc = subprocess.run(["apkid", path, "-j"], capture_output=True,
                              text=True, timeout=180)
        if proc.returncode != 0 or not proc.stdout.strip():
            result["note"] = "APKiD run fail hua — ye step skip kiya gaya."
            return result
        data = json.loads(proc.stdout)
        result.update(_normalize_apkid(_flatten_apkid_result(data)))
        result["available"] = True
        result["note"] = "APKiD scan complete."
        return result
    except FileNotFoundError:
        result["note"] = "APKiD installed nahi hai — ye step skip kiya gaya."
        return result
    except Exception as exc:  # noqa: BLE001
        log.warning("APKiD CLI failed: %s", exc)
        result["note"] = "APKiD run fail hua — ye step skip kiya gaya."
        return result


# ---------------------------------------------------------------- step 4: VirusTotal
def virustotal_scan(path: str, sha256: str, filename: str) -> dict:
    """VirusTotal v3 scan. Returns a dict; never raises for API problems.

    Flow: first look up the SHA256 (file may already be known), else upload
    the file and poll the analysis until it completes. 429 (rate limit) and
    timeouts are reported as 'unavailable' instead of failing the check.
    """
    result: dict = {"available": False, "note": "", "malicious": 0,
                    "suspicious": 0, "harmless": 0, "undetected": 0,
                    "flagged_engines": []}
    if not VIRUSTOTAL_API_KEY:
        result["note"] = "VirusTotal API key set nahi hai — ye step skip kiya gaya."
        return result
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        # 1. Already known? Look up by SHA256.
        resp = requests.get(f"{VIRUSTOTAL_BASE}/files/{sha256}",
                            headers=headers, timeout=30)
        if resp.status_code == 200:
            attrs = resp.json().get("data", {}).get("attributes", {})
            return _vt_from_attributes(result, attrs)
        if resp.status_code == 429:
            result["note"] = "VirusTotal rate limit (429) — thodi der baad dobara try karo."
            return result
        if resp.status_code not in (200, 404):
            result["note"] = f"VirusTotal lookup fail hua (HTTP {resp.status_code})."
            return result
        # 2. Not known — upload the file.
        with open(path, "rb") as fh:
            files = {"file": (filename, fh)}
            up = requests.post(f"{VIRUSTOTAL_BASE}/files", headers=headers,
                               files=files, timeout=120)
        if up.status_code == 429:
            result["note"] = "VirusTotal rate limit (429) — thodi der baad dobara try karo."
            return result
        if up.status_code not in (200, 201):
            result["note"] = f"VirusTotal upload fail hua (HTTP {up.status_code})."
            return result
        analysis_id = up.json().get("data", {}).get("id", "")
        if not analysis_id:
            result["note"] = "VirusTotal se analysis ID nahi mili."
            return result
        # 3. Poll the analysis until it completes.
        for _ in range(VT_POLL_ATTEMPTS):
            import time as _time
            _time.sleep(VT_POLL_DELAY_S)
            poll = requests.get(f"{VIRUSTOTAL_BASE}/analyses/{analysis_id}",
                                headers=headers, timeout=30)
            if poll.status_code == 429:
                result["note"] = "VirusTotal rate limit (429) — scan adhoora reh gaya."
                return result
            if poll.status_code != 200:
                continue
            attrs = poll.json().get("data", {}).get("attributes", {})
            if attrs.get("status") == "completed":
                return _vt_from_attributes(result, attrs)
        result["note"] = "VirusTotal scan time par complete nahi hua — dobara try karo."
        return result
    except requests.RequestException as exc:
        log.warning("VirusTotal request failed: %s", exc)
        result["note"] = "VirusTotal se connect nahi ho paya — ye step skip kiya gaya."
        return result


def _vt_from_attributes(result: dict, attrs: dict) -> dict:
    """Fill the result dict from a VirusTotal attributes payload."""
    stats = attrs.get("last_analysis_stats") or attrs.get("stats") or {}
    result["malicious"] = int(stats.get("malicious", 0) or 0)
    result["suspicious"] = int(stats.get("suspicious", 0) or 0)
    result["harmless"] = int(stats.get("harmless", 0) or 0)
    result["undetected"] = int(stats.get("undetected", 0) or 0)
    flagged: list[str] = []
    analyses = attrs.get("last_analysis_results") or attrs.get("results") or {}
    if isinstance(analyses, dict):
        for engine, entry in analyses.items():
            if not isinstance(entry, dict):
                continue
            if entry.get("category") in ("malicious", "suspicious"):
                flagged.append(engine)
            if len(flagged) >= 5:
                break
    result["flagged_engines"] = flagged
    result["available"] = True
    total = (result["malicious"] + result["suspicious"] + result["harmless"]
             + result["undetected"])
    result["note"] = (f"{total} engines ne check kiya: "
                      f"{result['malicious']} malicious, {result['suspicious']} suspicious.")
    return result


# ---------------------------------------------------------------- combined report + assessment
def build_combined_report(f: dict) -> str:
    """Build ONE combined report with every tool's findings, for the AI.

    The AI reasons over this whole report in a single call and returns a
    summary, a risk score out of 10, a risk level and reasons.
    """
    lines: list[str] = []
    lines.append(f"File: {f['filename']} ({format_size(f['file_size'])})")
    lines.append(f"MD5: {f['md5']}")
    lines.append(f"SHA256: {f['sha256']}")
    static = f.get("static")
    if static:
        lines.append(f"Package: {static['package']}")
        lines.append(
            f"App: {static['app_name']} v{static['version_name']} "
            f"(code {static['version_code']})")
        lines.append(f"SDK: min {static['min_sdk']} / target {static['target_sdk']}")
        lines.append(
            f"Permissions: {len(static['permissions'])} total, "
            f"{len(f.get('dangerous', []))} dangerous")
        if f.get("dangerous"):
            lines.append("Dangerous permissions: " + ", ".join(
                _perm_short(p) for p in f["dangerous"]))
        lines.append(
            f"Components: {static['activities']} activities, "
            f"{static['services']} services, {static['receivers']} receivers, "
            f"{static['providers']} providers")
        if static.get("flags"):
            lines.append("Flags: " + ", ".join(static["flags"]))
        lines.append(f"Hard-coded URLs found: {static.get('url_count', 0)}")
        if static.get("suspicious_urls"):
            lines.append("Suspicious URLs:")
            for u in static["suspicious_urls"][:8]:
                lines.append(f"  - {u['url']} ({u['reason']})")
        if static.get("suspicious_calls"):
            lines.append("Suspicious API calls: " + "; ".join(static["suspicious_calls"]))
    else:
        lines.append(f"Static analysis failed: {f.get('static_error', 'parse error')}")
    apkid = f.get("apkid", {})
    if apkid.get("available"):
        lines.append("APKiD:")
        if apkid.get("packers"):
            lines.append("  Packers: " + ", ".join(apkid["packers"]))
        if apkid.get("compilers"):
            lines.append("  Compilers: " + ", ".join(apkid["compilers"]))
        if apkid.get("obfuscators"):
            lines.append("  Obfuscators: " + ", ".join(apkid["obfuscators"]))
        if apkid.get("protectors"):
            lines.append("  Protectors: " + ", ".join(apkid["protectors"]))
        if apkid.get("anti_flags"):
            lines.append("  Anti-analysis: " + ", ".join(apkid["anti_flags"]))
        if apkid.get("other"):
            lines.append("  Other: " + ", ".join(apkid["other"]))
        if not (apkid.get("packers") or apkid.get("compilers")
                or apkid.get("obfuscators") or apkid.get("protectors")
                or apkid.get("anti_flags") or apkid.get("other")):
            lines.append("  No packer / obfuscator / anti-analysis trick detected.")
    else:
        lines.append(f"APKiD: not available — {apkid.get('note', 'skipped')}")
    vt = f.get("vt", {})
    if vt.get("available"):
        lines.append(
            f"VirusTotal: {vt.get('malicious', 0)} malicious, "
            f"{vt.get('suspicious', 0)} suspicious, {vt.get('harmless', 0)} harmless, "
            f"{vt.get('undetected', 0)} undetected")
        if vt.get("flagged_engines"):
            lines.append("Flagging engines: " + ", ".join(vt["flagged_engines"]))
    else:
        lines.append(f"VirusTotal: not available — {vt.get('note', 'skipped')}")
    return "\n".join(lines)


def parse_ai_assessment(text: str) -> dict:
    """Parse the AI's structured assessment. Any field may be None.

    Expected AI format:
      Summary:
      <4-6 lines>
      Rating: <number>/10
      Risk: <SAFE|LOW|MEDIUM|HIGH|CRITICAL>
      Reasons:
      - ...
    """
    summary = None
    score = None
    level = None
    reasons: list[str] = []
    m = re.search(r"Summary:\s*(.*?)\s*Rating:", text, re.S | re.I)
    if m:
        summary = m.group(1).strip()
    m = re.search(r"Rating:\s*(\d+(?:\.\d+)?)\s*/\s*10", text, re.I)
    if not m:
        m = re.search(r"(\d+(?:\.\d+)?)\s*/\s*10", text)
    if m:
        try:
            score = int(round(float(m.group(1))))
            score = max(0, min(10, score))
        except ValueError:
            score = None
    m = re.search(r"Risk:\s*(SAFE|LOW|MEDIUM|HIGH|CRITICAL)", text, re.I)
    if m:
        level = m.group(1).upper()
    m = re.search(r"Reasons:\s*(.*)", text, re.S | re.I)
    if m:
        for ln in m.group(1).splitlines():
            ln = ln.strip()
            if ln.startswith(("-", "•", "*")):
                cleaned = ln.lstrip("-•* ").strip()
                if cleaned:
                    reasons.append(cleaned)
            if len(reasons) >= 5:
                break
    if summary:
        summary_lines = [ln.strip() for ln in summary.splitlines() if ln.strip()]
        summary = "\n".join(summary_lines[:6])
    return {"summary": summary, "score": score, "level": level,
            "reasons": reasons[:5]}


# Midpoints used when the AI gives a level but no score (and vice versa).
_LEVEL_MIDPOINT = {"SAFE": 0, "LOW": 2, "MEDIUM": 4, "HIGH": 6, "CRITICAL": 9}


def ai_assessment(combined: str) -> dict | None:
    """Ask OpenRouter for a summary + rating + reasons over the combined report.

    Returns a full assessment dict, or None when the key is missing or the
    call fails (caller then uses the rule-based assessment).
    """
    if not OPENROUTER_API_KEY:
        return None
    system = (
        "You are a mobile-security analyst. You check Android APKs step by step "
        "like an agent using several tools (file info, androguard static analysis, "
        "APKiD packer detection, VirusTotal antivirus scan). You get ONE combined "
        "report with every tool's findings. Reason step by step over ALL the "
        "evidence and reply in Hinglish (simple Hindi mixed with English). "
        "Use EXACTLY this format:\n\n"
        "Summary:\n"
        "<4-6 short lines, Hinglish, covering what each tool found>\n\n"
        "Rating: <number>/10\n"
        "Risk: <SAFE, LOW, MEDIUM, HIGH, or CRITICAL>\n\n"
        "Reasons:\n"
        "- <reason 1>\n"
        "- <reason 2>\n"
        "- <reason 3>\n\n"
        "Rating guide: 0-1 = SAFE (clean), 2-3 = LOW, 4-5 = MEDIUM, "
        "6-7 = HIGH, 8-10 = CRITICAL (definitely malicious). Be strict: any "
        "VirusTotal malicious flag, a packer, or several dangerous permissions "
        "pushes the rating up."
    )
    user = (
        "Is APK ki combined report padho aur assessment do:\n\n" + combined
    )
    body = json.dumps({
        "model": OPENROUTER_MODEL,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "temperature": 0.3,
        "max_tokens": 1000,
    }).encode("utf-8")
    try:
        req = requests.Request(
            "POST", OPENROUTER_URL,
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                "HTTP-Referer": "https://t.me/",
                "X-Title": "APK Virus Checker Bot",
            },
        )
        prepared = req.prepare()
        with requests.Session() as session:
            resp = session.send(prepared, timeout=120)
        if resp.status_code != 200:
            log.warning("OpenRouter call failed (HTTP %s)", resp.status_code)
            return None
        text = resp.json()["choices"][0]["message"]["content"].strip()
        if not text:
            return None
        parsed = parse_ai_assessment(text)
        score, level = parsed["score"], parsed["level"]
        if score is None and level is None:
            return None
        if score is None:
            score = _LEVEL_MIDPOINT.get(level, 5)
        if level is None:
            level = level_from_score(score)
        summary = parsed["summary"] or "AI ne summary nahi di — neeche reasons dekho."
        reasons = parsed["reasons"] or [text[:300]]
        return {
            "summary": summary,
            "score": score,
            "level": level,
            "reasons": reasons[:5],
            "verdict": verdict_from_level(level),
            "ai": True,
        }
    except Exception as exc:  # noqa: BLE001 - any AI failure falls back to rules
        log.warning("OpenRouter call failed: %s", exc)
        return None


def rule_assessment(f: dict) -> dict:
    """Rule-based summary + rating from the same tool findings.

    Used when the AI step is skipped or fails. Scores 0-10 from VirusTotal
    flags, dangerous permissions, APKiD packers/obfuscators, app flags,
    suspicious URLs and suspicious API calls.
    """
    vt = f.get("vt", {})
    vt_m = int(vt.get("malicious", 0) or 0)
    vt_s = int(vt.get("suspicious", 0) or 0)
    dangerous = f.get("dangerous", [])
    apkid = f.get("apkid", {})
    static = f.get("static") or {}
    score = 0.0
    reasons: list[str] = []

    if vt_m >= 3:
        score += 5
        reasons.append(f"VirusTotal pe {vt_m} antivirus engines ne isko malicious bataya.")
    elif vt_m >= 1:
        score += 3
        reasons.append(f"VirusTotal pe {vt_m} engine ne malicious bataya.")
    elif vt_s >= 1:
        score += 1
        reasons.append(f"VirusTotal pe {vt_s} suspicious flag mila.")

    n_d = len(dangerous)
    if n_d >= 6:
        score += 2
        reasons.append(f"{n_d} dangerous permissions maangi hain — normal apps itni nahi maangti.")
    elif n_d >= 4:
        score += 1.5
        reasons.append(f"{n_d} dangerous permissions maangi hain.")
    elif n_d >= 2:
        score += 1

    packers = apkid.get("packers", []) if apkid.get("available") else []
    if packers:
        score += 2
        reasons.append(f"Packer mila: {packers[0]} — code chhupane ki koshish lagti hai.")
    if apkid.get("available") and apkid.get("obfuscators"):
        score += 1
        reasons.append("Code obfuscate kiya gaya hai.")
    if apkid.get("available") and apkid.get("anti_flags"):
        score += 1
        reasons.append("Anti-analysis trick mili (anti-vm / anti-debug).")

    flags = static.get("flags", []) if isinstance(static, dict) else []
    if "debuggable" in flags:
        score += 1
        reasons.append("App debuggable hai — production app me ye nahi hona chahiye.")
    if "device-admin" in flags:
        score += 2
        reasons.append("Device admin permission maangi hai — uninstall rok sakta hai.")
    if "install-packages" in flags:
        score += 1
        reasons.append("Dusre apps install karne ki permission hai.")

    sus_urls = static.get("suspicious_urls", []) if isinstance(static, dict) else []
    if sus_urls:
        score += 1
        reasons.append(f"{len(sus_urls)} suspicious URL mili (shortener / IP / http).")

    calls = static.get("suspicious_calls", []) if isinstance(static, dict) else []
    if any("DexClassLoader" in c for c in calls):
        score += 2
        reasons.append("DexClassLoader mila — dynamic code loading ka risk hai.")
    if any("Reflection" in c for c in calls):
        score += 1
    if any("SmsManager" in c or "sendTextMessage" in c for c in calls):
        score += 1
        reasons.append("SMS bhejne wala code mila.")

    score = max(0, min(10, int(round(score))))
    level = level_from_score(score)

    summary_lines = [
        f"File: {f['filename']} ({format_size(f['file_size'])}) — "
        f"package {static.get('package', 'unknown') if isinstance(static, dict) else 'unknown'}.",
        f"Permissions: {len(static.get('permissions', [])) if isinstance(static, dict) else 0} total, "
        f"{n_d} dangerous.",
    ]
    if apkid.get("available"):
        if packers:
            summary_lines.append(f"APKiD: packer mila ({packers[0]}).")
        else:
            summary_lines.append("APKiD: koi packer/obfuscator nahi mila.")
    else:
        summary_lines.append("APKiD: scan nahi ho paya.")
    if vt.get("available"):
        summary_lines.append(
            f"VirusTotal: {vt_m} malicious, {vt_s} suspicious.")
    else:
        summary_lines.append("VirusTotal: scan nahi ho paya.")
    if not reasons:
        reasons = [
            "VirusTotal pe koi malicious flag nahi mila.",
            "Koi bahut khatarnak permission combo nahi dikha.",
            "Phir bhi sirf bharosemand source se hi APK install karo.",
        ]
    return {
        "summary": "\n".join(summary_lines[:6]),
        "score": score,
        "level": level,
        "reasons": reasons[:5],
        "verdict": verdict_from_level(level),
        "ai": False,
    }


# ---------------------------------------------------------------- progress + report
STEP_LABELS = [
    "File check (hash nikal raha hun)",
    "Static analysis (permissions, URLs, calls)",
    "APKiD (packer / obfuscator check)",
    "VirusTotal scan (antivirus engines)",
    "AI summary + final rating",
]


def _progress_text(states: list[str], seq: int) -> str:
    icons = {"done": "✅", "doing": "🔨", "todo": "⬜", "fail": "❌", "skip": "⏭️"}
    lines = [f"🔍 **App {seq} — APK check ho raha hai…**", ""]
    for i, label in enumerate(STEP_LABELS):
        lines.append(f"{icons.get(states[i], '⬜')} Step {i + 1}: {label}")
    return "\n".join(lines)


# ---------------------------------------------------------------- commands
@app.on_message(filters.command("start") & filters.private)
async def cmd_start(client: Client, message: Message):
    await message.reply_text(
        "Namaste! Main **APK Virus Checker** hun — AI se APK check karne wala bot. 🤖🔍\n\n"
        "Mujhe koi bhi **.apk file** bhejo, main use agent ki tarah step by step check karunga:\n"
        "1️⃣ File info — naam, size, MD5/SHA256 hash\n"
        "2️⃣ Static analysis — permissions (khatarnak wali flag hongi), URLs, "
        "suspicious calls, debuggable/backup flags\n"
        "3️⃣ APKiD — packer, obfuscator aur anti-analysis tricks\n"
        "4️⃣ VirusTotal scan — kitne antivirus engines ne flag kiya\n"
        "5️⃣ AI summary + final rating — poori report padh ke AI summary aur "
        "risk score (0-10) degi\n\n"
        "📦 **Ek saath kai APK bhej sakte ho** — wo queue me lag jayenge aur "
        "ek-ek karke scan honge (App 1, App 2, App 3…). Ek baar me 5 tak APK "
        "queue kar sakte ho.\n\n"
        "⚠️ Limit: file 300 MB tak ki ho sakti hai. 20 MB tak ki file bot khud "
        "download karta hai; 20 MB se badi file (300 MB tak) helper se download "
        "hoti hai.\n"
        "Bas APK file bhej do — baaki sab main kar lunga. 😎"
    )


@app.on_message(filters.command("help") & filters.private)
async def cmd_help(client: Client, message: Message):
    await message.reply_text(
        "❓ **Kaise use karein**\n\n"
        "1. Koi bhi .apk file yahan bhej do (document ke roop me).\n"
        "2. Main use download karke 5 steps me check karunga — progress yahin dikhega.\n"
        "3. Aakhir me ek report milegi: verdict, AI summary, har tool ki ek line, "
        "aur aakhir me **FINAL RATING (0-10)**.\n\n"
        "📦 **Batch scan:** ek ke baad ek kai APK bhej do — wo queue me lag "
        "jayenge aur ek-ek karke scan honge, har report pe 'App 1', 'App 2' "
        "likha hoga. Ek baar me 5 tak APK queue kar sakte ho; 6th bhejo ge to "
        "bot mana kar dega jab tak pehli batch khatam na ho.\n\n"
        "📌 Sirf .apk files check hoti hain — dusri file bhejoge to main mana kar dunga.\n"
        "📌 File 300 MB tak ki ho sakti hai. 20 MB se badi file helper se download "
        "hoti hai — agar helper set nahi hai to 20 MB se badi file ka check nahi hoga.\n"
        "📌 Check ke baad file mere server se delete kar di jati hai."
    )


# ---------------------------------------------------------------- batch queue (per user)
# chat_id -> {"queue": asyncio.Queue, "worker": Task|None,
#             "pending": int (queued + running), "next_seq": int,
#             "current_seq": int}
_user_queues: dict[int, dict] = {}
_queue_lock = asyncio.Lock()


async def _enqueue_apk(message: Message, doc, filename: str,
                       file_size: int, route: str) -> None:
    """Queue one APK for this user and start their worker if needed."""
    chat_id = message.chat.id
    async with _queue_lock:
        uq = _user_queues.get(chat_id)
        if uq is None:
            uq = {"queue": asyncio.Queue(), "worker": None, "pending": 0,
                  "next_seq": 1, "current_seq": 0}
            _user_queues[chat_id] = uq
        if uq["pending"] >= MAX_QUEUE_PER_USER:
            await message.reply_text(
                "Queue full hai — 5 APKs already pending hain. "
                "Current batch khatam hone ke baad dobara bhejo. 🙏"
            )
            return
        seq = uq["next_seq"]
        uq["next_seq"] += 1
        uq["pending"] += 1
        item = {"seq": seq, "message": message, "doc": doc,
                "filename": filename, "file_size": file_size, "route": route}
        uq["queue"].put_nowait(item)
        start_worker = uq["worker"] is None or uq["worker"].done()
        if start_worker:
            uq["worker"] = asyncio.create_task(_user_worker(chat_id, uq))
    if seq == 1:
        await message.reply_text(
            f"📥 App 1 mil gayi ({filename}) — scan shuru ho raha hai…")
    else:
        await message.reply_text(
            f"📥 App {seq} queue mein hai ({filename}) — "
            f"App {seq - 1} ke baad scan hoga.")


async def _user_worker(chat_id: int, uq: dict) -> None:
    """Sequential worker for one user: scan queued APKs one by one."""
    try:
        while True:
            try:
                item = await asyncio.wait_for(
                    uq["queue"].get(), timeout=QUEUE_IDLE_TIMEOUT_S)
            except asyncio.TimeoutError:
                break
            uq["current_seq"] = item["seq"]
            try:
                await _run_single_check(item)
            except Exception:  # noqa: BLE001 - one bad APK must not kill the queue
                log.exception("queued APK check failed (App %s)", item["seq"])
            finally:
                uq["pending"] -= 1
                uq["queue"].task_done()
    finally:
        async with _queue_lock:
            uq["worker"] = None
            uq["current_seq"] = 0
            if uq["pending"] <= 0:
                uq["next_seq"] = 1
                uq["pending"] = 0


# ---------------------------------------------------------------- APK check flow
@app.on_message(filters.private & filters.document)
async def on_document(client: Client, message: Message):
    """Entry point: validate the file, then queue it for this user."""
    doc = message.document
    filename = (doc.file_name or "file.apk").strip()
    if not filename.lower().endswith(".apk"):
        await message.reply_text(
            "Sirf **.apk file** bhejo — ye file APK nahi hai. 🙏\n"
            "APK file bhejte hi main use virus scan karke report dunga."
        )
        return
    file_size = doc.file_size or 0
    route = choose_download_path(file_size, user_app is not None)
    if route == "too_big":
        await message.reply_text(
            f"Ye file bahut badi hai ({format_size(file_size)}). "
            "Main sirf 300 MB tak ki APK check kar sakta hun — "
            "is se badi file ka check nahi ho payega. 🙏"
        )
        return
    if route == "need_helper":
        await message.reply_text(
            f"Ye file {format_size(file_size)} ki hai — 20 MB se badi hai, isliye "
            "Bot API se download nahi ho sakti. Badi file (300 MB tak) download "
            "karne ke liye helper set nahi hai, isliye iska check nahi ho payega. "
            "Chhoti APK bhejo (20 MB tak), ya helper set hone ke baad dobara try karo. 🙏"
        )
        return
    await _enqueue_apk(message, doc, filename, file_size, route)


class DownloadError(Exception):
    """Raised when an APK cannot be downloaded or fails verification."""


def verify_download(path: str, expected_size: int) -> tuple[bool, str]:
    """Check a downloaded file before any analysis runs.

    Returns (ok, reason). `reason` is '' when ok. Fails when the file is
    missing, empty (0 bytes), or its size differs wildly from Telegram's
    file_size (small ~1% tolerance for rounding). A failed download must
    never be analysed — an empty file would produce a misleading verdict.
    """
    if not os.path.isfile(path):
        return False, "file download nahi hui (file mili nahi)"
    size = os.path.getsize(path)
    if size <= 0:
        return False, "file 0 bytes aayi (khali download)"
    if expected_size > 0:
        tolerance = max(1024, expected_size // 100)  # ~1%
        if abs(size - expected_size) > tolerance:
            return False, (
                f"file adhoori aayi ({format_size(size)} mili, "
                f"{format_size(expected_size)} expected thi)")
    return True, ""


async def _download_via_helper(message: Message, doc, local_path: str) -> None:
    """Download a >20 MB APK via the helper user client.

    The helper is NOT a participant in the user<->bot DM, so it cannot
    download the file by file_id directly — that silently yields 0 bytes.
    The bot therefore first forwards the document to the helper account
    (HELPER_USER_ID), so the helper owns the message; then the helper
    fetches its own copy of the forwarded message and downloads the file
    from it. The forwarded message lives in the helper's DM with the BOT
    (chat = the bot's user id, fetched at runtime via app.get_me()) —
    NOT in the helper's Saved Messages, so the helper must fetch and
    delete it from the bot's chat id. The forwarded copy is deleted from
    that DM afterwards (best-effort). Raises DownloadError on any failure.
    """
    assert user_app is not None
    # The forwarded message will live in the helper's DM with the bot, so
    # the helper must fetch/delete it from the chat with the bot (the
    # bot's user id) — NOT from the helper's own id, which for the helper
    # client is its Saved Messages. Get the bot id at runtime; never
    # hardcode it. Fetch it before forwarding so a failure here leaves
    # no orphaned forwarded message behind.
    try:
        bot_me = await app.get_me()
        bot_user_id = bot_me.id
    except Exception as exc:  # noqa: BLE001
        raise DownloadError(f"bot ki id nahi mili ({exc})") from exc
    # 1. Forward the document to the helper account.
    try:
        fwd = await app.forward_messages(
            HELPER_USER_ID, message.chat.id, message.id)
    except Exception as exc:  # noqa: BLE001
        raise DownloadError(
            f"helper ko file forward nahi ho payi ({exc})") from exc
    # forward_messages returns one Message for a single id, a list otherwise.
    if isinstance(fwd, list):
        fwd = fwd[0] if fwd else None
    if fwd is None:
        raise DownloadError(
            "helper ko file forward nahi ho payi (koi message nahi mila)")
    fwd_msg_id = fwd.id
    try:
        # 2. Helper fetches its own copy of the forwarded message and
        # downloads the file from it (its own file reference). Retry a
        # few times — the forwarded message may take a moment to
        # propagate to the helper's session.
        helper_msg = None
        for attempt in range(3):
            try:
                fetched = await user_app.get_messages(bot_user_id, fwd_msg_id)
            except Exception:  # noqa: BLE001 - retry on transient fetch errors
                fetched = None
            if isinstance(fetched, list):
                fetched = fetched[0] if fetched else None
            if fetched is not None and getattr(fetched, "document", None) is not None:
                helper_msg = fetched
                break
            if attempt < 2:
                await asyncio.sleep(1.5)
        if helper_msg is None:
            raise DownloadError("helper ko forwarded file nahi mili")
        await user_app.download_media(helper_msg, file_name=local_path)
    except DownloadError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise DownloadError(f"helper se download nahi ho paya ({exc})") from exc
    finally:
        # 3. Clean up the forwarded copy from the helper's DM with the bot.
        try:
            await user_app.delete_messages(bot_user_id, fwd_msg_id)
        except Exception:  # noqa: BLE001 - cleanup must never break the check
            pass


async def _run_single_check(item: dict) -> None:
    """Run the FULL check pipeline for one queued APK and send its report."""
    message: Message = item["message"]
    doc = item["doc"]
    filename = item["filename"]
    file_size = item["file_size"]
    route = item["route"]
    seq = item["seq"]

    states = ["doing", "todo", "todo", "todo", "todo"]
    progress = await message.reply_text(_progress_text(states, seq))

    async def update(idx: int, state: str) -> None:
        states[idx] = state
        try:
            await progress.edit_text(_progress_text(states, seq))
        except Exception:  # noqa: BLE001
            pass

    tmpdir = tempfile.mkdtemp(prefix="apk-check-")
    local_path = os.path.join(tmpdir, filename)
    expected_size = file_size  # Telegram's file_size — the download must match it
    try:
        # Download the APK. <= 20 MB: bot client (Bot API). > 20 MB: the bot
        # first forwards the document to the helper account (so the helper
        # owns the message), then the helper user client downloads it
        # (MTProto). The downloaded file is verified BEFORE any analysis —
        # an empty/truncated download is a download error, never a verdict.
        try:
            if route == "user":
                assert user_app is not None
                await _download_via_helper(message, doc, local_path)
            else:
                await message.download(file_name=local_path)
        except DownloadError as exc:
            log.warning("APK download failed (%s path): %s", route, exc)
            await update(0, "fail")
            await message.reply_text(
                f"App {seq} ({filename}): download nahi ho paya — {exc}. "
                "File dobara bhej do. 🙏")
            return
        except Exception as exc:  # noqa: BLE001 - a failed download is reported, not a crash
            log.warning("APK download failed (%s path): %s", route, exc)
            await update(0, "fail")
            await message.reply_text(
                f"App {seq} ({filename}): file download nahi ho payi — dobara try karo. "
                "(Badi file ho to helper se download me dikkat aa sakti hai.)"
            )
            return
        ok, reason = verify_download(local_path, expected_size)
        if not ok:
            log.warning("APK download verification failed (App %s): %s", seq, reason)
            await update(0, "fail")
            await message.reply_text(
                f"App {seq} ({filename}): download nahi ho paya — {reason}. "
                "File dobara bhej do. 🙏")
            return
        file_size = os.path.getsize(local_path)

        # Step 1 — file info / hashes.
        try:
            md5, sha256 = await asyncio.to_thread(file_hashes, local_path)
        except Exception as exc:  # noqa: BLE001
            log.warning("hashing failed: %s", exc)
            md5, sha256 = "unknown", "unknown"
        await update(0, "done")

        # Step 2 — expanded static analysis (androguard).
        static: dict | None = None
        static_error = ""
        await update(1, "doing")
        try:
            static = await asyncio.to_thread(analyze_apk_static, local_path)
            await update(1, "done")
        except Exception as exc:  # noqa: BLE001
            static_error = str(exc)[:200]
            log.warning("androguard failed: %s", exc)
            await update(1, "fail")

        # Step 3 — APKiD.
        await update(2, "doing")
        apkid = await asyncio.to_thread(analyze_apkid, local_path)
        await update(2, "done" if apkid.get("available") else "skip")

        # Step 4 — VirusTotal.
        await update(3, "doing")
        vt = await asyncio.to_thread(virustotal_scan, local_path, sha256, filename)
        await update(3, "done" if vt.get("available") else "skip")

        # Step 5 — AI summary + final rating (or rule fallback).
        await update(4, "doing")
        dangerous: list[str] = []
        if static:
            dangerous, _other = flag_permissions(static["permissions"])
        findings = {
            "filename": filename,
            "file_size": file_size,
            "md5": md5,
            "sha256": sha256,
            "static": static,
            "static_error": static_error,
            "dangerous": dangerous,
            "apkid": apkid,
            "vt": vt,
        }
        combined = build_combined_report(findings)
        assessment = await asyncio.to_thread(ai_assessment, combined)
        if assessment is None:
            assessment = rule_assessment(findings)
            ai_note = ("AI step skip hua (key nahi hai ya call fail hui) — "
                       "rule-based summary aur rating hai.")
        else:
            ai_note = "AI (OpenRouter) ne ye summary aur rating di hai."
        await update(4, "done")

        # Final report, labelled with the App number.
        try:
            await progress.delete()
        except Exception:  # noqa: BLE001
            pass
        await message.reply_text(
            _build_report(findings, assessment, seq, ai_note))
    except Exception as exc:  # noqa: BLE001
        log.exception("APK check failed (App %s)", seq)
        try:
            await message.reply_text(
                f"App {seq} ({filename}): check ke dauraan dikkat aayi: {exc}. "
                "Dobara try karo.")
        except Exception:  # noqa: BLE001
            pass
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def _build_report(f: dict, assessment: dict, seq: int, ai_note: str) -> str:
    """Final report: verdict, summary, per-tool one-liners, FINAL RATING last.

    Kept under Telegram's 4096-character limit — the per-tool lines are
    trimmed first if needed; the FINAL RATING is never dropped.
    """
    verdict = assessment["verdict"]
    emoji = VERDICT_EMOJI.get(verdict, "❓")
    score = assessment["score"]
    level = assessment["level"]
    summary = assessment["summary"]
    reasons = assessment.get("reasons", [])

    lines: list[str] = []
    lines.append(f"{emoji} **Verdict: {verdict}**  •  App {seq}: {f['filename']}")
    lines.append("")
    lines.append("📝 **Summary:**")
    for ln in str(summary).splitlines():
        lines.append(ln.strip()[:200])
    if reasons:
        lines.append("")
        lines.append("**Reasons:**")
        for r in reasons[:5]:
            lines.append(f"• {str(r)[:150]}")
    lines.append("")
    lines.append("🔧 **Tools:**")
    lines.append(
        f"• 📦 File: {f['filename']} ({format_size(f['file_size'])}) | "
        f"SHA256 `{f['sha256'][:16]}…`")
    static = f.get("static")
    if static:
        lines.append(
            f"• 📱 Androguard: `{static['package']}` | "
            f"{len(static['permissions'])} perms "
            f"({len(f.get('dangerous', []))} dangerous) | "
            f"flags: {', '.join(static.get('flags', [])) or 'none'} | "
            f"URLs: {static.get('url_count', 0)} "
            f"({len(static.get('suspicious_urls', []))} suspicious)")
    else:
        lines.append(
            f"• 📱 Androguard: failed — {f.get('static_error', 'parse error')}")
    apkid = f.get("apkid", {})
    if apkid.get("available"):
        bits: list[str] = []
        if apkid.get("packers"):
            bits.append("packer: " + ", ".join(apkid["packers"][:2]))
        if apkid.get("compilers"):
            bits.append("compiler: " + ", ".join(apkid["compilers"][:2]))
        if apkid.get("obfuscators"):
            bits.append("obfuscator: " + ", ".join(apkid["obfuscators"][:2]))
        if apkid.get("anti_flags"):
            bits.append("anti: " + ", ".join(apkid["anti_flags"][:3]))
        lines.append("• 📦 APKiD: " + ("; ".join(bits) if bits
                                       else "clean — no packer/obfuscator detected"))
    else:
        lines.append(f"• 📦 APKiD: not available — {apkid.get('note', 'skipped')}")
    vt = f.get("vt", {})
    if vt.get("available"):
        vt_line = (f"• 🛡️ VirusTotal: {vt.get('malicious', 0)} malicious, "
                   f"{vt.get('suspicious', 0)} suspicious")
        if vt.get("flagged_engines"):
            vt_line += " (" + ", ".join(vt["flagged_engines"][:3]) + ")"
        lines.append(vt_line)
    else:
        lines.append("• 🛡️ VirusTotal: not available")
    lines.append("")
    lines.append(f"🤖 {ai_note}")
    lines.append("")
    rating_line = f"⭐ **FINAL RATING: {score}/10 — {level}**"
    lines.append(rating_line)
    lines.append("_Check ke baad file delete kar di gayi hai._")
    report = "\n".join(lines)
    if len(report) > 4096:
        # Safety net: truncate the middle, always keep the rating line.
        keep = 4096 - len(rating_line) - 60
        report = report[:keep].rsplit("\n", 1)[0] + "\n\n" + rating_line
    return report


@app.on_message(filters.private & filters.text & ~filters.command(["start", "help"]))
async def on_private_text(client: Client, message: Message):
    await message.reply_text(
        "Mujhe koi **.apk file** bhejo, main use virus scan karke report dunga. 🔍\n"
        "Ek saath kai APK bhi bhej sakte ho — wo queue me lag kar ek-ek karke "
        "scan honge (App 1, App 2…). Details ke liye /help bhejo."
    )


# Ignore group messages entirely — this bot is DM-only by design.
@app.on_message(filters.group)
async def on_group_message(client: Client, message: Message):
    return


if __name__ == "__main__":
    log.info("APK Virus Checker bot starting…")
    if user_app is not None:
        try:
            user_app.start()
            log.info("Helper user client started — APKs up to 300 MB can be downloaded.")
        except Exception as exc:  # noqa: BLE001 - bad/expired session must not kill the bot
            log.warning(
                "Helper user client failed to start (%s) — files over 20 MB will "
                "be rejected until SESSION_STRING is fixed.", exc)
            user_app = None
    else:
        log.info("No SESSION_STRING set — files over 20 MB will be rejected.")
    try:
        app.run()
    finally:
        if user_app is not None:
            try:
                user_app.stop()
            except Exception:  # noqa: BLE001
                pass

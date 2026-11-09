"""AI-enhanced APK Virus Checker Telegram bot.

User sends any .apk file in a private chat; the bot checks it step by step
like an agent AI and reports a verdict:
  Step 1 — File info (name, size, MD5, SHA256)
  Step 2 — Static analysis with androguard (package, version, SDKs,
           permissions with DANGEROUS ones flagged, component counts)
  Step 3 — VirusTotal v3 scan (malicious/suspicious engine counts)
  Step 4 — AI verdict via OpenRouter (free tier) or a rule-based fallback

Env vars (no secrets are hardcoded or logged):
  BOT_TOKEN, API_ID, API_HASH   (required — BotFather / my.telegram.org)
  VIRUSTOTAL_API_KEY            (optional — skips the VirusTotal step if unset)
  OPENROUTER_API_KEY            (optional — falls back to rule verdict if unset)
  OPENROUTER_MODEL              (optional, default cohere/north-mini-code:free)

Pyrogram only, built-in app.run() runner. Every external call is wrapped so
one failing step never kills the whole check. Downloaded APKs are deleted
after the check. Telegram Bot API download limit is ~20 MB — bigger files
are rejected with a clear message.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import shutil
import tempfile

import requests
from pyrogram import Client, filters
from pyrogram.types import Message

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("virus-checker-bot")

API_ID = int(os.environ.get("API_ID", "0") or 0)
API_HASH = os.environ.get("API_HASH", "")
BOT_TOKEN = os.environ.get("BOT_TOKEN", "")
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY", "").strip()
OPENROUTER_MODEL = os.environ.get("OPENROUTER_MODEL", "cohere/north-mini-code:free")
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
VIRUSTOTAL_BASE = "https://www.virustotal.com/api/v3"

MAX_APK_BYTES = 20 * 1024 * 1024  # Telegram Bot API download limit (~20 MB)
VT_POLL_ATTEMPTS = 12
VT_POLL_DELAY_S = 15

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

app = Client("virus-checker-bot", api_id=API_ID, api_hash=API_HASH, bot_token=BOT_TOKEN)


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


def rule_verdict(vt_malicious: int, vt_suspicious: int,
                 dangerous: list[str]) -> tuple[str, list[str]]:
    """Rule-based verdict used when the AI step is skipped/failed.

    Returns (verdict, reasons in Hinglish).
    """
    reasons: list[str] = []
    perms = set(dangerous)
    if vt_malicious >= 3:
        return ("MALICIOUS", [
            f"VirusTotal pe {vt_malicious} antivirus engines ne isko malicious bataya.",
            "Itne engines ka flag hona matlab file kharab hone ke chances bahut zyada hain.",
        ])
    if "android.permission.BIND_DEVICE_ADMIN" in perms:
        return ("MALICIOUS", [
            "Is app ne device admin permission maangi hai — aisi apps ko uninstall karna mushkil hota hai.",
            "Device admin + dusri dangerous permissions milke malware jaisa behave karti hain.",
        ])
    if ("android.permission.REQUEST_INSTALL_PACKAGES" in perms
            and "android.permission.SEND_SMS" in perms):
        return ("MALICIOUS", [
            "Ye app dusre apps install kar sakti hai AUR SMS bhej sakti hai — ye combo malware me aam hai.",
        ])
    if vt_malicious >= 1 or vt_suspicious >= 1:
        reasons.append(
            f"VirusTotal pe {vt_malicious} malicious aur {vt_suspicious} suspicious flags mile.")
    if len(dangerous) >= 4:
        reasons.append(
            f"{len(dangerous)} dangerous permissions maangi hain — normal apps itni nahi maangti.")
    if ("android.permission.READ_SMS" in perms
            and "android.permission.SEND_SMS" in perms):
        reasons.append("SMS padhna + bhejna dono permissions hain — OTP chori ka risk hai.")
    if reasons:
        reasons.append("Isliye is APK ko install karne se pehle soch lo.")
        return ("SUSPICIOUS", reasons)
    return ("SAFE", [
        "VirusTotal pe koi malicious flag nahi mila.",
        "Koi bahut khatarnak permission combo nahi dikha.",
        "Phir bhi sirf bharosemand source se hi APK install karo.",
    ])


# ---------------------------------------------------------------- step 2: androguard
def analyze_apk_static(path: str) -> dict:
    """Static analysis with androguard. Raises on parse failure."""
    from androguard.misc import AnalyzeAPK
    apk, _dex, _analysis = AnalyzeAPK(path)
    perms = list(apk.get_permissions() or [])
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
    }


# ---------------------------------------------------------------- step 3: VirusTotal
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


# ---------------------------------------------------------------- step 4: AI verdict
def ai_verdict(context: str) -> tuple[str | None, str | None]:
    """Ask OpenRouter (free tier) for a verdict. Returns (verdict, ai_text).

    Returns (None, None) when the key is missing or the call fails, so the
    caller falls back to the rule-based verdict.
    """
    if not OPENROUTER_API_KEY:
        return None, None
    system = (
        "You are a mobile-security analyst. You check Android APKs step by step "
        "like an agent and give a final verdict. Reply in Hinglish (simple Hindi "
        "mixed with English). First line must be exactly one of: "
        "Verdict: SAFE, Verdict: SUSPICIOUS, or Verdict: MALICIOUS. "
        "Then give 3-5 short reasons, one per line. Be strict: a file with "
        "several dangerous permissions or any VirusTotal flag is at least SUSPICIOUS."
    )
    user = (
        "Is APK ko step by step check karo aur final verdict do:\n\n" + context
    )
    body = json.dumps({
        "model": OPENROUTER_MODEL,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "temperature": 0.3,
        "max_tokens": 800,
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
            return None, None
        text = resp.json()["choices"][0]["message"]["content"].strip()
        if not text:
            return None, None
        match = re.search(r"\b(SAFE|SUSPICIOUS|MALICIOUS)\b", text)
        verdict = match.group(1) if match else None
        return verdict, text
    except Exception as exc:  # noqa: BLE001 - any AI failure falls back to rules
        log.warning("OpenRouter call failed: %s", exc)
        return None, None


# ---------------------------------------------------------------- progress + report
STEP_LABELS = [
    "File check (hash nikal raha hun)",
    "Static analysis (permissions aur details)",
    "VirusTotal scan (antivirus engines)",
    "AI verdict (final faisla)",
]


def _progress_text(states: list[str]) -> str:
    icons = {"done": "✅", "doing": "🔨", "todo": "⬜", "fail": "❌", "skip": "⏭️"}
    lines = ["🔍 **APK check ho raha hai…**", ""]
    for i, label in enumerate(STEP_LABELS):
        lines.append(f"{icons.get(states[i], '⬜')} Step {i + 1}: {label}")
    return "\n".join(lines)


def _perm_short(name: str) -> str:
    return name.replace("android.permission.", "")


# ---------------------------------------------------------------- commands
@app.on_message(filters.command("start") & filters.private)
async def cmd_start(client: Client, message: Message):
    await message.reply_text(
        "Namaste! Main **APK Virus Checker** hun — AI se APK check karne wala bot. 🤖🔍\n\n"
        "Mujhe koi bhi **.apk file** bhejo, main use agent ki tarah step by step check karunga:\n"
        "1️⃣ File info — naam, size, MD5/SHA256 hash\n"
        "2️⃣ Static analysis — permissions (khatarnak wali flag hongi), app details\n"
        "3️⃣ VirusTotal scan — kitne antivirus engines ne flag kiya\n"
        "4️⃣ AI verdict — SAFE, SUSPICIOUS ya MALICIOUS, reasons ke saath\n\n"
        "⚠️ Limit: file 20 MB se chhoti honi chahiye (Telegram Bot API limit).\n"
        "Bas APK file bhej do — baaki sab main kar lunga. 😎"
    )


@app.on_message(filters.command("help") & filters.private)
async def cmd_help(client: Client, message: Message):
    await message.reply_text(
        "❓ **Kaise use karein**\n\n"
        "1. Koi bhi .apk file yahan bhej do (document ke roop me).\n"
        "2. Main use download karke 4 steps me check karunga — progress yahin dikhega.\n"
        "3. Aakhir me ek report milegi: verdict, permissions, VirusTotal result aur AI reasons.\n\n"
        "📌 Sirf .apk files check hoti hain — dusri file bhejoge to main mana kar dunga.\n"
        "📌 File 20 MB se badi ho to bhej nahi paunga (Telegram ki limit hai).\n"
        "📌 Check ke baad file mere server se delete kar di jati hai."
    )


# ---------------------------------------------------------------- APK check flow
@app.on_message(filters.private & filters.document)
async def on_document(client: Client, message: Message):
    doc = message.document
    filename = (doc.file_name or "file.apk").strip()
    if not filename.lower().endswith(".apk"):
        await message.reply_text(
            "Sirf **.apk file** bhejo — ye file APK nahi hai. 🙏\n"
            "APK file bhejte hi main use virus scan karke report dunga."
        )
        return
    if (doc.file_size or 0) > MAX_APK_BYTES:
        await message.reply_text(
            f"Ye file bahut badi hai ({format_size(doc.file_size or 0)}). "
            "Telegram Bot API sirf 20 MB tak ki file download kar sakta hai, "
            "isliye iska check nahi ho payega. Chhoti APK bhejo. 🙏"
        )
        return

    states = ["doing", "todo", "todo", "todo"]
    progress = await message.reply_text(_progress_text(states))

    async def update(idx: int, state: str) -> None:
        states[idx] = state
        try:
            await progress.edit_text(_progress_text(states))
        except Exception:  # noqa: BLE001
            pass

    tmpdir = tempfile.mkdtemp(prefix="apk-check-")
    local_path = os.path.join(tmpdir, filename)
    try:
        # Download the APK.
        await message.download(file_name=local_path)
        if not os.path.isfile(local_path):
            await update(0, "fail")
            await message.reply_text("File download nahi ho payi — dobara try karo.")
            return
        file_size = os.path.getsize(local_path)

        # Step 1 — file info / hashes.
        try:
            md5, sha256 = await asyncio.to_thread(file_hashes, local_path)
        except Exception as exc:  # noqa: BLE001
            log.warning("hashing failed: %s", exc)
            md5, sha256 = "unknown", "unknown"
        await update(0, "done")

        # Step 2 — static analysis (androguard).
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

        # Step 3 — VirusTotal.
        await update(2, "doing")
        vt = await asyncio.to_thread(virustotal_scan, local_path, sha256, filename)
        await update(2, "done" if vt.get("available") else "skip")

        # Step 4 — AI verdict (or rule fallback).
        await update(3, "doing")
        dangerous: list[str] = []
        if static:
            dangerous, _other = flag_permissions(static["permissions"])
        context_lines = [
            f"File: {filename} ({format_size(file_size)})",
            f"SHA256: {sha256}",
            f"Package: {static['package'] if static else 'unknown'}",
            f"App: {static['app_name'] if static else 'unknown'} "
            f"v{static['version_name'] if static else '?'} "
            f"(code {static['version_code'] if static else '?'})",
            f"SDK: min {static['min_sdk'] if static else '?'} / "
            f"target {static['target_sdk'] if static else '?'}",
            f"Total permissions: {len(static['permissions']) if static else 0}",
            "Dangerous permissions: " + (
                ", ".join(_perm_short(p) for p in dangerous) if dangerous else "koi nahi"),
            "VirusTotal: " + (vt.get("note", "") if vt.get("available")
                              else "scan nahi ho paya — " + vt.get("note", "")),
        ]
        if vt.get("flagged_engines"):
            context_lines.append(
                "Flag karne wale engines: " + ", ".join(vt["flagged_engines"]))
        verdict, ai_text = await asyncio.to_thread(ai_verdict, "\n".join(context_lines))
        if verdict is None:
            verdict, reasons = rule_verdict(
                vt.get("malicious", 0), vt.get("suspicious", 0), dangerous)
            ai_note = "AI step skip hua (key nahi hai ya call fail hui) — rule-based verdict hai."
        else:
            # Use the AI text as the reasons (strip the verdict line).
            reasons = [ln.strip("-• ").strip() for ln in ai_text.splitlines()
                       if ln.strip() and "Verdict" not in ln][:5]
            if not reasons:
                reasons = [ai_text[:300]]
            ai_note = "AI (OpenRouter) ne ye verdict diya hai."
        await update(3, "done")

        # Final report.
        try:
            await progress.delete()
        except Exception:  # noqa: BLE001
            pass
        await message.reply_text(_build_report(
            filename, file_size, md5, sha256, static, static_error,
            dangerous, vt, verdict, reasons, ai_note))
    except Exception as exc:  # noqa: BLE001
        log.exception("APK check failed")
        try:
            await message.reply_text(
                f"Check ke dauraan dikkat aayi: {exc}. Dobara try karo.")
        except Exception:  # noqa: BLE001
            pass
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def _build_report(filename: str, file_size: int, md5: str, sha256: str,
                  static: dict | None, static_error: str,
                  dangerous: list[str], vt: dict, verdict: str,
                  reasons: list[str], ai_note: str) -> str:
    emoji = VERDICT_EMOJI.get(verdict, "❓")
    lines = [
        f"{emoji} **Verdict: {verdict}**",
        "",
        f"📦 **File:** {filename} ({format_size(file_size)})",
        f"🔑 **MD5:** `{md5}`",
        f"🔑 **SHA256:** `{sha256}`",
    ]
    if static:
        lines += [
            "",
            "📱 **App details:**",
            f"• Package: `{static['package']}`",
            f"• App: {static['app_name']} v{static['version_name']} "
            f"(code {static['version_code']})",
            f"• SDK: min {static['min_sdk']} / target {static['target_sdk']}",
            f"• Components: {static['activities']} activities, "
            f"{static['services']} services, {static['receivers']} receivers, "
            f"{static['providers']} providers",
            f"• Total permissions: {len(static['permissions'])}",
        ]
    else:
        lines += ["", f"⚠️ Static analysis nahi ho payi: {static_error or 'parse error'}"]
    if dangerous:
        lines += ["", "🚩 **Dangerous permissions:**"]
        for perm in dangerous:
            note = PERMISSION_NOTES.get(perm, "")
            lines.append(f"• `{_perm_short(perm)}`" + (f" — {note}" if note else ""))
    else:
        lines += ["", "✅ Koi dangerous permission nahi mili."]
    lines += ["", "🛡️ **VirusTotal:**"]
    if vt.get("available"):
        lines.append(
            f"• {vt.get('malicious', 0)} malicious, {vt.get('suspicious', 0)} suspicious, "
            f"{vt.get('harmless', 0)} harmless, {vt.get('undetected', 0)} undetected")
        if vt.get("flagged_engines"):
            lines.append("• Flag karne wale: " + ", ".join(vt["flagged_engines"]))
    else:
        lines.append(f"• Scan nahi ho paya — {vt.get('note', 'key ya network issue')}")
    lines += ["", f"🤖 **AI verdict:** {ai_note}"]
    for reason in reasons[:5]:
        lines.append(f"• {reason}")
    lines += ["", "_Check ke baad file delete kar di gayi hai._"]
    return "\n".join(lines)


@app.on_message(filters.private & filters.text & ~filters.command(["start", "help"]))
async def on_private_text(client: Client, message: Message):
    await message.reply_text(
        "Mujhe koi **.apk file** bhejo, main use virus scan karke report dunga. 🔍\n"
        "Details ke liye /help bhejo."
    )


# Ignore group messages entirely — this bot is DM-only by design.
@app.on_message(filters.group)
async def on_group_message(client: Client, message: Message):
    return


if __name__ == "__main__":
    log.info("APK Virus Checker bot starting…")
    app.run()

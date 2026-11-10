# APK Virus Checker Bot 🤖🔍

AI-enhanced Telegram bot — koi bhi `.apk` file bhejo, bot use agent ki tarah
step by step check karke verdict, summary aur **final risk rating (0-10)**
deta hai.

## Ye bot kya karta hai

User APK bhejta hai → bot 5 steps me full check karta hai (progress message
live update hota hai). Har tool ki report AI ko di jati hai, aur AI poori
report padh ke summary + final rating deta hai:

1. **File info** — naam, size, MD5 aur SHA256 hash
2. **Static analysis (androguard)** — package name, app name, version,
   min/target SDK, poori permission list (dangerous permissions flag hoti hain
   jaise `SEND_SMS`, `READ_CONTACTS`, `RECORD_AUDIO`, `CAMERA`,
   `ACCESS_FINE_LOCATION`, `REQUEST_INSTALL_PACKAGES`, `BIND_DEVICE_ADMIN`,
   `SYSTEM_ALERT_WINDOW`), activities/services/receivers/providers ki ginti,
   APK ke andar hard-coded **URLs/domains** (shortener, raw IP aur non-HTTPS
   URLs flag hote hain), **suspicious API calls** (DexClassLoader, reflection,
   SmsManager, Runtime.exec, crypto) aur flags — debuggable, allowBackup,
   install-packages, device-admin
3. **APKiD** — packer, compiler, obfuscator aur anti-analysis tricks
   (anti-vm / anti-disassembly / anti-debug) detect karta hai. Ye step
   local hai, koi API key nahi chahiye. Agar APKiD install nahi hai ya fail
   ho jaye to ye step skip ho jata hai, baaki steps chalte hain.
4. **VirusTotal scan** — kitne antivirus engines ne malicious/suspicious
   bataya, aur kaunse engines ne flag kiya (max 5 naam). Free API key se
   chalta hai; key na ho to ye step skip ho jata hai.
5. **AI summary + final rating (OpenRouter, free tier)** — upar ke saare
   tools ki reports ek saath AI ko di jati hain. AI step by step sochta hai
   aur deta hai: (a) **summary** (4-6 lines, Hinglish), (b) **final rating**
   — risk score **0-10** (0 = fully safe, 10 = definitely malicious) +
   risk level **SAFE / LOW / MEDIUM / HIGH / CRITICAL**, (c) 3-5 short
   reasons. AI key na ho ya call fail ho to rule-based summary + rating
   milta hai (VirusTotal flags, dangerous permissions, packer, debuggable
   aadi se score banta hai).

Aakhir me ek clean report milti hai: verdict (emoji ke saath), AI/rule
summary, har tool ki ek line, aur sabse aakhir me **FINAL RATING (X/10 —
LEVEL)** bold me. Check ke baad download ki hui APK file delete kar di
jati hai.

## Commands aur buttons

- **/start** — welcome message + inline keyboard: 📤 Scan APK, 🛡️ Safety
  Guide, ℹ️ About, 📊 Status
- **/help** — kaise use karein (scan, batch, limits)
- **/id** — tumhara Telegram ID
- **/status** — bot Online hai ya nahi, abhi kitne scans queued/running hain
  (saare users mila ke), aur VirusTotal configured hai ya nahi (key kabhi
  dikhai nahi jati)
- **Buttons:** Scan APK → APK bhejne ka tarika batata hai; Safety Guide →
  chhota safety guide; About → bot kya check karta hai; Status → alert me
  active/queued scan count

## Batch scan — ek saath kai APK

Ek ke baad ek kai APK bhej do — wo **queue** me lag jayenge aur ek-ek karke
scan honge. Har APK ki report pe **App 1, App 2, App 3…** likha hota hai,
taaki pata chale kaunsi report kiski hai. Ek baar me **5 tak APK** queue kar
sakte ho; 6th bhejo ge to bot mana kar dega jab tak pehli batch khatam na
ho. Ek hi APK bhejo ge to wo bas **App 1** ki tarah scan hoga — single-APK
behaviour bilkul waisa hi hai. Alag users ki queues alag-alag hoti hain.

## Limits

- File **300 MB tak** ki ho sakti hai. 20 MB tak ki file bot khud download
  karta hai (Telegram Bot API limit); 20 MB se badi file (300 MB tak) helper
  user client se download hoti hai — uske liye `SESSION_STRING` chahiye.
  Helper set nahi ho to 20 MB se badi file ka check nahi hoga.
- **Download verification:** har download ke baad bot check karta hai ki
  file mili, khali (0 bytes) to nahi hai, aur size Telegram ke file_size se
  match karta hai ya nahi. Agar download fail ho (0 bytes / adhoori file)
  to bot us APK ka check **nahi** karta — uski jagah saaf Hinglish error
  bhejta hai ("download nahi ho paya — file 0 bytes aayi, dobara bhej do")
  aur batch me agle APK pe badh jata hai. Khali file pe kabhi verdict
  nahi banta.
- Sirf `.apk` files check hoti hain — dusri file bhejoge to bot mana kar dega.
- Bot sirf private chat (DM) me kaam karta hai, groups me nahi.

## Setup

```bash
pip install -r requirements.txt
```

Phir neeche wale environment variables set karo aur bot chalao:

```bash
python bot.py
```

> ⚠️ **APKiD note:** APKiD ko RedNaga ke custom yara-python fork ki zaroorat
> hoti hai (DEX support ke saath). Plain `pip install apkid` kuch systems
> par fail ho sakta hai. Agar Railway ya local install `apkid` pe atak jaye
> to `requirements.txt` se `apkid` line hata do — bot phir bhi chalega, bas
> APKiD step skip ho jayega (baaki saare tools chalte rahenge).

## Environment variables

| Variable | Required? | Kya hai |
|---|---|---|
| `BOT_TOKEN` | ✅ Yes | BotFather se `/newbot` karke mila token |
| `API_ID` | ✅ Yes | my.telegram.org se API ID |
| `API_HASH` | ✅ Yes | my.telegram.org se API Hash |
| `SESSION_STRING` | ❌ Optional | Pyrogram user session string (helper) — sirf 20 MB se badi APK (300 MB tak) download karne ke liye chahiye; nahi ho to 20 MB tak ki files hi check hoti hain |
| `HELPER_USER_ID` | ❌ Optional | Helper account ka Telegram user id — default **8657748041** (GHOST). Bot 20 MB se badi file ko pehle is account ko forward karta hai, tabhi helper use download kar pata hai. Set na ho to bhi default se kaam chal jata hai, lekin explicitly set karna safe hai |
| `VIRUSTOTAL_API_KEY` | ❌ Optional | VirusTotal API key (free) — nahi ho to Step 4 skip ho jata hai, baaki steps chalte hain |
| `OPENROUTER_API_KEY` | ❌ Optional | OpenRouter API key — nahi ho to AI summary/rating ki jagah rule-based summary + rating milta hai |
| `OPENROUTER_MODEL` | ❌ Optional | Default `cohere/north-mini-code:free` (free tier) |

> ⚠️ Koi bhi token/key/session code me hardcode mat karo — sirf environment
> variables me daalo. Bot kabhi koi token, key ya session log nahi karta.

## SESSION_STRING — 20 MB se badi files ke liye

Telegram Bot API se bot sirf 20 MB tak ki file download kar sakta hai. 20 MB
se badi APK (300 MB tak) download karne ke liye bot ke saath ek helper
**user client** (MTProto) chalta hai, jo `SESSION_STRING` env var se login
hota hai. Ye ek Pyrogram user session string hai — kisi user account ka
login, bot token nahi.

**Forward-to-helper flow (zaroori samajhna):** helper user↔bot DM ka
participant nahi hota, isliye wo file ko seedha file_id se download nahi
kar sakta — aisa karne par download chupchaap 0 bytes ki aati hai. Isliye
bot 20 MB se badi file ko pehle helper account (`HELPER_USER_ID`, default
8657748041 = GHOST) ko **forward** karta hai — ye forwarded message helper
ke DM me bot ke saath aata hai (helper ke Saved Messages me nahi), isliye
helper use bot ke chat id se fetch karta hai (runtime me `app.get_me()` se
liya jata hai, hardcode nahi). Phir helper apni copy se file download karta
hai, aur baad me forwarded copy usi DM se delete kar deta hai. Fetch 3
baar retry hota hai (1.5 s gap) kyunki forwarded message helper ke session
me aane me thoda time lag sakta hai. Iske liye helper account ne bot ko
`/start` kiya hua hona chahiye (warna bot usko forward nahi kar payega aur
download error aayega). Agar fetch 3 baar fail ho jaye to bot ek **fallback**
try karta hai: original document ke file_id se seedha download (forward se
helper ko file ka access mil chuka hota hai). Har download ke baad size
verify hoti hai — 0 bytes ya galat size aaye to analysis skip karke clear
download error milta hai, galat verdict kabhi nahi. Helper download ke
har step ka **debug log** bhi aata hai (INFO level, Railway logs me):
bot_user_id, helper_user_id, forwarded msg id, har fetch attempt ka
result, aur fallback ka result — sirf ids aur exception TYPE log hote
hain, kabhi koi token/session/key nahi.

Session string kaise lein:
- **Sanji Bot Factory** ke `/userbot` flow se (phone number → OTP → 2FA
  password) — wo session string de deta hai. Use yahan `SESSION_STRING` me
  daalo.
- Ya kisi Pyrogram session generator script se (phone + OTP + 2FA).

⚠️ **Ek session, ek service:** ek hi session string ko do live services me
kabhi share mat karo — is bot ke helper ke liye alag/dedicated session use
karo, warna session invalid ho jayega (AUTH_KEY_DUPLICATED). Helper ke liye
ek alag Telegram account use karna sabse safe hai.

`SESSION_STRING` set nahi ho to bot phir bhi chalta hai — bas 20 MB se badi
file ka check nahi hoga (bot saaf mana kar dega).

## Free API keys kaise lein

### VirusTotal (free) — Step 4 ke liye
1. https://www.virustotal.com/ pe jao aur free account banao (sign up).
2. Login karke apne profile/avatar → **API key** pe click karo.
3. Wahan dikh rahi key ko `VIRUSTOTAL_API_KEY` me daalo.
4. **Free tier limits:** 500 requests/day, 4 requests/minute. Rate limit
   (429) aane par bot scan ko "unavailable" batakar aage badh jata hai,
   crash nahi hota.
5. Key na ho to bhi bot chalta hai — tab VirusTotal step skip ho jata hai
   aur baaki tools (androguard, APKiD, AI) se rating banti hai.

### OpenRouter (free) — AI summary + rating ke liye
1. https://openrouter.ai/ pe jao aur account banao (Google se bhi sign up hota hai).
2. **Keys** page pe jao → **Create Key** pe click karo.
3. Key ko `OPENROUTER_API_KEY` me daalo. Is bot ke liye free model
   `cohere/north-mini-code:free` use hota hai — iska koi charge nahi hai.
4. Key na ho to bhi bot chalta hai — tab AI ki jagah rule-based summary +
   rating milta hai.

## BotFather se bot banana

1. Telegram pe **@BotFather** ko `/newbot` bhejo.
2. Bot ka naam aur username do — token milega.
3. Token ko `BOT_TOKEN` env var me daalo (chat me kisi ko mat bhejo).

## Commands

- `/start` — bot kya karta hai, ye batata hai
- `/help` — kaise use karein, ye batata hai
- Bas `.apk` file bhej do — check apne aap shuru ho jata hai; kai APK bhej
  do to wo queue me lag kar ek-ek karke scan honge

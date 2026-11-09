# APK Virus Checker Bot 🤖🔍

AI-enhanced Telegram bot — koi bhi `.apk` file bhejo, bot use agent ki tarah
step by step check karke verdict deta hai: **SAFE, SUSPICIOUS ya MALICIOUS**.

## Ye bot kya karta hai

User APK bhejta hai → bot 4 steps me check karta hai (progress message live update hota hai):

1. **File info** — naam, size, MD5 aur SHA256 hash
2. **Static analysis (androguard)** — package name, app name, version,
   min/target SDK, poori permission list (dangerous permissions flag hoti hain
   jaise `SEND_SMS`, `READ_CONTACTS`, `RECORD_AUDIO`, `CAMERA`,
   `ACCESS_FINE_LOCATION`, `REQUEST_INSTALL_PACKAGES`, `BIND_DEVICE_ADMIN`,
   `SYSTEM_ALERT_WINDOW`), aur activities/services/receivers/providers ki ginti
3. **VirusTotal scan** — kitne antivirus engines ne malicious/suspicious bataya,
   aur kaunse engines ne flag kiya (max 5 naam)
4. **AI verdict (OpenRouter, free tier)** — file info + permissions + VirusTotal
   result dekh ke AI step by step sochta hai aur final verdict deta hai,
   3-5 short reasons ke saath (Hinglish me)

Aakhir me ek clean report milti hai: verdict (emoji ke saath), file info,
flagged permissions, VirusTotal counts aur AI/rules reasons. Check ke baad
download ki hui APK file delete kar di jati hai.

## Limits

- File **20 MB se chhoti** honi chahiye (Telegram Bot API ki download limit).
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

## Environment variables

| Variable | Required? | Kya hai |
|---|---|---|
| `BOT_TOKEN` | ✅ Yes | BotFather se `/newbot` karke mila token |
| `API_ID` | ✅ Yes | my.telegram.org se API ID |
| `API_HASH` | ✅ Yes | my.telegram.org se API Hash |
| `VIRUSTOTAL_API_KEY` | ❌ Optional | VirusTotal API key — nahi ho to Step 3 skip ho jata hai, baaki steps chalte hain |
| `OPENROUTER_API_KEY` | ❌ Optional | OpenRouter API key — nahi ho to AI verdict ki jagah rule-based verdict milta hai |
| `OPENROUTER_MODEL` | ❌ Optional | Default `cohere/north-mini-code:free` (free tier) |

> ⚠️ Koi bhi token/key code me hardcode mat karo — sirf environment variables
> me daalo. Bot kabhi koi token ya key log nahi karta.

## Free API keys kaise lein

### VirusTotal (free)
1. https://www.virustotal.com/ pe jao aur free account banao (sign up).
2. Login karke apne profile/avatar → **API key** pe click karo.
3. Wahan dikh rahi key ko `VIRUSTOTAL_API_KEY` me daalo.
4. Free key se har minute limited requests milti hain — rate limit (429) aane par
   bot scan ko "unavailable" batakar aage badh jata hai, crash nahi hota.

### OpenRouter (free)
1. https://openrouter.ai/ pe jao aur account banao (Google se bhi sign up hota hai).
2. **Keys** page pe jao → **Create Key** pe click karo.
3. Key ko `OPENROUTER_API_KEY` me daalo. Is bot ke liye free model
   `cohere/north-mini-code:free` use hota hai — iska koi charge nahi hai.
4. Key na ho to bhi bot chalta hai — tab AI ki jagah rule-based verdict milta hai.

## BotFather se bot banana

1. Telegram pe **@BotFather** ko `/newbot` bhejo.
2. Bot ka naam aur username do — token milega.
3. Token ko `BOT_TOKEN` env var me daalo (chat me kisi ko mat bhejo).

## Commands

- `/start` — bot kya karta hai, ye batata hai
- `/help` — kaise use karein, ye batata hai
- Bas `.apk` file bhej do — check apne aap shuru ho jata hai

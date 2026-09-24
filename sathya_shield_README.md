# SatyaShield — Multilingual Scam and Phishing Detection System

An on-device scam detection system for Android, backed by a Python ML API.
Built for Smart India Hackathon 2026 (Theme 12: Blockchain & Cybersecurity).

---

## What it does

SatyaShield analyses incoming messages, shared links, and notifications to
judge whether they are scams, and delivers that verdict — in the user's
language, out loud — before they act.

**Two trained detectors:**

| Model | Training data | ROC-AUC | PR-AUC |
|---|---|---|---|
| URL classifier | 72,880 PhishTank + OpenPhish phishing URLs vs 19,000 Tranco benign domains | 0.82 | 0.81 |
| SMS text classifier | 5,574-message UCI Spam Collection | 0.995 | 0.986 |

**Three-state fusion policy (GREEN / AMBER / RED):**

Only deterministic rule signals (URL rules, email headers) may raise a RED
alert. Model confidence alone cannot trigger a screen takeover — a 90%-precision
interrupt firing twice daily causes users to uninstall within a month.
Models inform; rules interrupt.

**Honest limitation documented:**

The SMS classifier was trained on an English-only corpus. When probed against
hand-written Hindi and Hinglish inputs, it scored 0.045 on Devanagari script
and 0.22 on a CBI impersonation pattern common in India. The fusion policy
was designed around this gap, not despite it.

---

## Architecture

```
android/          Kotlin Android client
  detect/
    Fusion.kt     On-device fusion policy (port of backend fusion.py)
    LocalRules.kt Deterministic URL and text rules
    Model.kt      On-device model wrapper
  alert/
    AlertPresenter.kt  Overlay alert (screen takeover)
    Speaker.kt         Text-to-speech output
  service/
    SatyaNotificationListener.kt
  ui/
    MainActivity.kt

backend/
  app/
    main.py       FastAPI service
    fusion.py     Risk scoring and decision policy
    pipeline.py   Detection pipeline
    assembler.py  Evidence assembler
    explain.py    Explainability layer
    pillars/
      url_rules.py
      text_intent.py
      email_headers.py
    models/
      url_model.py
      text_model.py
    artifacts/
      url_model.joblib     Trained URL classifier
      url_model_report.json
      text_model.joblib    Trained SMS classifier
      text_model_report.json
  ml/
    train_url.py
    train_text.py
    url_features.py
    fetch_data.py
  tests/
    test_fusion.py
    test_models.py
    test_pillars.py
    test_pipeline_and_api.py
```

---

## Key design decisions

**Why saturating risk score?**
`score = 100 * raw / (raw + 5)` — approaches 100 but never exceeds it.
No pile of weak signals can fake a critical one.

**Why benign domains sampled across all Tranco rank decades?**
If the benign set is only top-ranked domains, the model learns "popular equals
safe" rather than phishing structure. Sampling uniformly across all rank
decades forces it onto actual URL characteristics.

**Why URLhaus excluded from training data?**
URLhaus indexes malware droppers, not phishing pages — a different problem
with a different signal profile. Including it would pollute the feature space.

**Why identical invariant tests in Kotlin and Python?**
The on-device and server-side implementations must produce the same verdict
for the same input. Testing the same invariant in both languages prevents
silent drift between deployments.

---

## Data provenance

Full provenance is recorded in `backend/data/provenance.json`:
sources, counts, licences, known label noise and caveats.

| Source | Use | Licence |
|---|---|---|
| PhishTank | Phishing URLs | Community feeds, free access |
| OpenPhish | Phishing URLs | Community feeds, free access |
| Tranco Top-1M | Benign domains | Free for research |
| UCI SMS Spam Collection | SMS training data | UCI ML Repository, free for research |

**Known limitation:** SMS training corpus is English-only and not Indian.
The model underperforms on Hinglish and Devanagari. See `text_model_report.json`
for probe results.

---

## Running the backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

To retrain models:
```bash
python ml/fetch_data.py
python ml/train_url.py
python ml/train_text.py
```

To run tests:
```bash
pytest tests/
```

---

## Android build

Open `android/` in Android Studio. Requires Android SDK 26+.

Localisations: Hindi (`values-hi/strings.xml`), Tamil (`values-ta/strings.xml`).

---

## Tech stack

**Backend:** Python, Scikit-learn, FastAPI, pytest, joblib
**Android:** Kotlin, Android SDK, Notification Listener Service, Overlay API

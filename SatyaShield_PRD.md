# SatyaShield — Product Requirements Document
### AI-Based Phishing & Deepfake Detection System
**SIH 2026 · Theme 12 (Blockchain & Cybersecurity) · Problem Statement 2**

| | |
|---|---|
| **Version** | 3.1 — alert-trust hardening |
| **Date** | August 19, 2026 |
| **Status** | Scope locked, ready for build |
| **Changed in v3.0** | Added PS compliance matrix and closed two hard gaps (email pillar, website-characteristics pillar). Fixed a false architectural assumption about passive media capture. Added competitive reality and standalone-viability assessment. Added model licensing, data acquisition and training-cost plans. Revised decision policy so only deterministic rules can raise a red alert. Added OCR path. |
| **Changed in v3.1** | Three trust-hardening fixes after use, all with regression tests. (1) The text model no longer scores bare URLs as prose — it was flagging legitimate bank homepages (axisbank.com 0.86, irctc.co.in 0.84) because the UCI corpus ties URLs to spam. (2) Every alert now quotes the message that triggered it, in the overlay, the notification and the family SMS. (3) Email detection is now reachable on the phone: `EmailRules.kt` ports the backend header forensics on-device and the share sheet routes shared emails through it. See §5.8, §5.9, §11.5, §14.4. |

**One-line pitch:** *One explainable verdict on any link, email, website, video or voice note — delivered before you act, in your language, out loud.*

---

## 0. Read This First — Honest Assessment

This section exists because the rest of the document is easier to write than to defend. Read it before committing to the build.

### 0.1 Does this solve the given problem statement?

**Now, yes. In v2.0 it did not.** Two clauses of the PS were explicitly named and materially unaddressed: *email content* and *website characteristics*. The mobile-first pivot had quietly abandoned both. §1.2 is the clause-by-clause audit and §6.2–6.3 are the pillars that close them.

After those additions, the system covers every named requirement and adds three things the PS does not ask for: the literacy layer (§8), family escalation (§9), and explainability-as-teaching, which is arguably the PS's own third sentence taken seriously.

### 0.2 Would this stand alone as a product?

**As a consumer app sold to the target user: no.** Three reasons, none of them technical.

1. **The core of it already ships, free, to hundreds of millions of Indians.** Truecaller has AI SMS fraud protection, scam call detection, community reporting, fraud insurance, and — this is the uncomfortable one — [a family group feature where an admin gets alerts about relatives' fraud calls and can end a call on their behalf](https://techcrunch.com/?p=3101896). That is our "Ask family" differentiator, already shipped, at scale, with a capability we do not have. Meanwhile Google ships [on-device scam detection in Messages and real-time scam call warnings in the OS itself](https://security.googleblog.com/2024/11/new-real-time-protections-on-Android.html).
2. **The models we would build on are licensed for research only.** FaceForensics++ terms state the [database is for non-commercial research and educational use](https://kaldir.vc.in.tum.de/faceforensics/webpage/FaceForensics_TOS.pdf). Celeb-DF and DFDC carry comparable restrictions. A detector trained on them cannot legally ship in a commercial product. See §11.4.
3. **The target user cannot be acquired economically.** She does not search app stores, does not pay subscriptions, and does not trust software recommendations. Customer acquisition cost for a low-literacy semi-urban user is prohibitive for a standalone consumer play.

**As a licensed capability, yes — and that is the honest go-to-market.** The realistic paths are an SDK or API sold to banks, telecoms and insurers; OEM preinstallation; or deployment through I4C / CERT-In / Sanchar Saathi as public infrastructure. That is a fundamentally different company from "an app we market," and the PRD should say so rather than pretend otherwise.

**Where genuine open space remains:** nobody — not Truecaller, not Google — is checking whether a *forwarded video or voice note is synthetic*, nobody covers *WhatsApp message content* (the dominant Indian fraud channel), and nobody *explains why* in a way that teaches the user to recognise the next one unaided. Those three, plus email and website analysis, are the defensible product. §3 works through this.

### 0.3 The three things most likely to kill this

| Risk | Why it is severe |
|---|---|
| **Deepfake video detection does not survive WhatsApp** | Our flagship pillar depends on forensic cues that platform re-encoding destroys, and reported in-the-wild AUC drops for open-source detectors are in the 45–50% range (§13.2). We are aiming our least reliable model at its hardest possible input |
| **The passive interrupt is a permission gauntlet** | Notification access, overlay permission, battery-optimisation exemption, and aggressive OEM process killing on exactly the budget Indian handsets our persona owns (§17) |
| **False positives destroy the product faster than false negatives** | One wrong red alert on a genuine family video and the app is uninstalled. This forces a decision policy where models are not allowed to raise red alerts at all (§14.2) |

---

## 1. Problem Statement & Compliance

### 1.1 The given problem statement

> Develop an AI-powered cybersecurity system that detects phishing emails, malicious websites, and deepfake audio or video content using machine learning and pretrained classification models. The system should analyze URLs, email content, website characteristics, and multimedia inputs to identify suspicious patterns and generate appropriate risk scores or warnings. The proposed solution should enable early detection of multiple forms of digital deception and improve users' ability to identify potentially fraudulent or manipulated content.

### 1.2 Clause-by-clause compliance matrix

Every requirement, traced to where it is satisfied. Treat this as the acceptance checklist.

| # | PS clause | Where satisfied | Status |
|---|---|---|---|
| 1 | detects **phishing emails** | §6.3 backend + §5.9 on-device (`EmailRules.kt`) — header forensics + body through URL/text rules | **On-device in v3.1** |
| 2 | detects **malicious websites** | §6.1 URL pillar + §6.2 Website pillar | Covered |
| 3 | detects **deepfake audio or video** | §6.5, §6.6 | Covered |
| 4 | uses **machine learning** | §11.5 — domain-reputation model (gradient boosting) and text classifier (TF-IDF + logistic regression), both trained and wired in | **Implemented and measured** |
| 5 | uses **pretrained classification models** | CLIP probe (video), AASIST (audio) — §11.1. Not yet implemented | Planned, not built |
| 6 | analyzes **URLs** | §6.1 — lexical, rules, WHOIS, redirect chain | Covered |
| 7 | analyzes **email content** | §6.3 backend + §5.9 on-device — headers, body, links, attachments | **On-device in v3.1** |
| 8 | analyzes **website characteristics** | §6.2 — DOM, forms, TLS cert, favicon, resource origins, visual similarity | **Added in v3.0** |
| 9 | analyzes **multimedia inputs** | §6.5, §6.6 | Covered |
| 10 | generates **risk scores or warnings** | §14 — three-state verdict, numeric drill-down | Covered |
| 11 | enables **early detection** | §2.1 — push model, interrupts before the user acts | Covered, and this is our strongest reading of the clause |
| 12 | **improves users' ability to identify** manipulated content | §8 explainability + §6.x named red flags | Covered, and deliberately over-delivered — see §2.3 |

**Verdict: 12 of 12, with surplus on clauses 11 and 12.** In v2.0 it was 10 of 12.

### 1.3 The delivery gap (our own addition to the problem)

The PS asks for detection. It does not ask who will actually use the thing, and that is where comparable systems fail. Every existing "check this link" tool requires the user to already suspect something, then copy the content, open a tool and paste it. Anyone who completes that sequence was probably never going to be defrauded. The victims never reach step one — that is *why* they are victims.

Clause 11 ("early detection") and clause 12 ("improve users' ability to identify") are the PS's own invitation to solve this. We read them as a mandate for a system that (a) intervenes unprompted and (b) teaches rather than merely blocks.

---

# PPT — Slide Content (Slides 2–6)

> Final presentation copy. Text is written to be pasted onto slides as-is. Lines marked **[SPEAK]** are speaker notes, not on-slide text. Keep on-slide bullets at this length or shorter — the SIH template boxes are small.

---

## SLIDE 2 — IDEA TITLE

### Title

**SatyaShield — One Explainable Verdict on Any Link, Email, Website, Video or Voice**

*Spoken tagline:* **"Your phone notices the scam before you do — and tells you what to do, out loud, in your language."**

### Proposed Solution

A single AI system that judges **any** digital artifact a fraudster can send you, and returns one verdict a non-reader can act on.

**Six detection pillars, one fused verdict**

| Input | What we analyse |
|---|---|
| Link / URL | Domain age, redirect chains, brand lookalikes, APK links, UPI handles |
| Website | Login-form targets, TLS certificate, favicon hash, resource origins, page-vs-domain brand mismatch |
| Email | SPF/DKIM/DMARC, `Received` chain, `Reply-To` vs `From`, display-name spoofing, attachments |
| Message text | Urgency, payment pressure, credential requests — in English, Hindi and Tamil, including Roman-script Hinglish |
| Video / image | Frame-sampled deepfake detection on a CLIP foundation backbone |
| Voice note | Voice-clone detection using pretrained anti-spoofing models |

**Four surfaces, one backend**
- **Android app** — reads incoming message text automatically and interrupts on danger
- **WhatsApp bot** — forward anything to a number, get a verdict. Zero install
- **Web checker** — paste an email or URL for a full forensic scan
- **Browser extension** — desktop link protection

**Output built for someone who cannot read**
- Three states, never a number: **SAFE / SUSPICIOUS / DANGER**, encoded redundantly in colour, icon, word and sound
- **The verdict is spoken aloud** in English, Hindi or Tamil
- Every verdict ends in an **instruction**, not a diagnosis — *"Do not send money"*, not *"deepfake likelihood 0.87"*
- **"Ask family"** — one tap forwards the content and the evidence to a trusted relative

### How It Addresses the Problem

**Every clause of the problem statement, mapped:**

| Requirement | Our answer |
|---|---|
| Detect phishing emails | Header forensics + body classifier |
| Detect malicious websites | URL rules + live page analysis |
| Detect deepfake audio/video | Pretrained CLIP and AASIST detectors |
| Analyse URLs, email content, website characteristics, multimedia | All four, one fused pipeline |
| Use ML + pretrained models | XGBoost, MuRIL, CLIP, AASIST — pretrained by design |
| Generate risk scores or warnings | Three-state warning, numeric score on drill-down |
| **Enable early detection** | We intervene **before** the user acts, unprompted — not on request |
| **Improve users' ability to identify** | Every verdict names its evidence in plain language, so the user learns the pattern |

**And the problem behind the problem:** every tool that exists today waits to be asked. Copy the link, open the app, paste it. But anyone who completes that sequence already knew to be suspicious — and was never the likely victim. The people losing lakhs never reach step one. **A detector that only answers when asked cannot protect the people who need it.**

### Innovation and Uniqueness

1. **Push, not pull.** The system watches incoming messages and takes over the screen at the moment of danger. No copying, no pasting, no asking
2. **We score the message, not the file.** One WhatsApp message carries a video, a link and text. Fusing *"this face shows manipulation"* + *"this domain is 4 days old"* + *"this text demands urgent payment"* into one verdict is real inference — and it keeps working when any single detector is unsure
3. **Only rules may raise a red alert. Models can only reach amber.** A probabilistic model is never allowed to seize a frightened user's screen. Deterministic, near-100%-precision signals interrupt; models inform. We believe this is the correct safety posture for this user, and no consumer product states it
4. **Literacy-first, not literacy-assumed.** Spoken Indic verdicts, near-textless UI, banned jargon, hand-authored language (never machine-translated). Built for a user who may not read comfortably in any language
5. **Explainability as teaching.** We show *why* — the four-day-old domain, the spoofed sender, the highlighted pressure phrase, the face heatmap. The goal is a user who spots the next one without us
6. **Designed to be installed by one person and used by another.** All configuration sits in a setup flow the adult child completes; the parent only ever sees a verdict

**[SPEAK] If asked about Truecaller:** *"Truecaller owns calls and SMS and we deliberately don't compete there. What nobody does is tell you whether the video your cousin forwarded is synthetic, on WhatsApp, in Tamil, spoken aloud, with the evidence shown. That's the gap we're in."*

---

## SLIDE 3 — TECHNICAL APPROACH

### Technologies

**Mobile (primary surface)**
- Kotlin + Jetpack Compose
- `NotificationListenerService` — passive message-text capture
- `SYSTEM_ALERT_WINDOW` — screen-takeover alert
- ML Kit Text Recognition — on-device OCR (Devanagari, Tamil)
- Android TTS — spoken Indic verdicts
- TensorFlow Lite / ONNX Runtime Mobile — on-device inference

**Backend**
- Python · FastAPI · Docker
- Playwright headless Chromium — sandboxed page fetch
- `python-whois`, TLS inspection, perceptual hashing (favicon)
- SPF / DKIM / DMARC verification + raw header parsing

**Models — all open, all free, no paid APIs**

| Pillar | Model | Licence |
|---|---|---|
| URL | XGBoost | Apache 2.0 |
| Text | MuRIL (17 Indian languages) / HingBERT | Apache 2.0 |
| Video | CLIP ViT-L/14 + lightweight probe | MIT |
| Audio | AASIST — pretrained, no training needed | Open |
| OCR / TTS | ML Kit, Android TTS | Free |

**Explainability:** Grad-CAM (video), token attribution (text), named rule hits (URL, website, email)
**Delivery:** Twilio WhatsApp API · Firebase Cloud Messaging · React web client

### Methodology and Process

**System flow**

```
   INGEST                    PROCESSING                     OUTPUT
 ─────────────         ──────────────────────         ──────────────────
 Notification    ─┐
 listener         │    ┌─────────────────────┐
 (message text)   │    │  MESSAGE ASSEMBLER  │
 Share sheet     ─┼───▶│  text + links +     │
 OCR (image→text)│    │  media + sender      │
 WhatsApp bot    ─┤    └──────────┬──────────┘
 Web checker     ─┘               │
                   ┌──────────────┴──────────────┐
                   ▼                             ▼
          ON-DEVICE  (<100ms)            SERVER (explicit submit)
          • Rule engine                  • Website fetch + analysis
          • Small text classifier        • Email header forensics
          • OCR                          • CLIP video detector
          Nothing leaves the phone       • AASIST audio detector
                   │                             │
                   └──────────────┬──────────────┘
                                  ▼
                    ┌─────────────────────────────┐
                    │     EVIDENCE FUSION         │
                    │  rules → RED                │
                    │  models → AMBER only        │
                    └─────────────┬───────────────┘
                                  │
              ┌───────────────────┼───────────────────┐
              ▼                   ▼                   ▼
      3-STATE VERDICT      NAMED EVIDENCE        "ASK FAMILY"
      + spoken EN/HI/TA    heatmap / phrases /   escalation to
                           red flags             trusted relative
```

**Implementation phases**

| Phase | Deliverable |
|---|---|
| **0** | Request gated deepfake datasets. Prove notification listener + overlay alert on a real budget handset |
| **1** | URL, website, email and text pillars + web checker — **satisfies 10 of 12 PS clauses, no GPU required** |
| **2** | Android app: passive capture, OCR, three-state verdict, spoken output, "Ask family", guided setup |
| **3** | Fusion with rule-gated red alerts, explainability layer, deepfake video detector |
| **4** | Voice notes, WhatsApp bot, stretch goals |
| **5** | Measure red-alert precision. Rehearse on the actual demo device |

**Key sequencing decision:** the reliable, GPU-free pillars are built first. If the schedule slips, a compliant working product still exists.

---

## SLIDE 4 — FEASIBILITY AND VIABILITY

### Feasibility

**Strong, because the reliable core is deliberately cheap**

- **4 of 6 pillars need no GPU and are largely deterministic** — URL, website, email, text. These are feature engineering, not model gambling
- **Every model is free and pretrained.** Audio needs zero training. Video uses a frozen backbone with a light probe
- **Total training budget: under one day on a single T4 GPU.** The bottleneck is CPU video decoding, not model training
- **The MVP satisfies 11 of 12 PS clauses even if the deepfake video detector is dropped entirely** — resilience by design, not optimism
- Every platform API required has been verified against current Android and Play policy documentation

### Potential Challenges and Risks

| Risk | Reality |
|---|---|
| **Deepfake detectors fail on real-world video** | Open-source detectors show reported in-the-wild AUC drops of **45–50%**. WhatsApp re-encoding launders the very artifacts detectors rely on |
| **Passive media capture is impossible on Android** | Notifications carry text, not files; WhatsApp media sits in restricted scoped storage |
| **OEM battery managers kill background services** | Xiaomi, Oppo, Vivo and Realme are aggressive — and dominate our target user segment |
| **False positives are more damaging than misses** | One wrong red alert on a genuine family video and the app is uninstalled |
| **No large public corpus of current Indian scam messages** | Existing datasets are small, dated, or not Indian |
| **Deepfake datasets are gated and research-licensed** | Manual approval before download; commercial use prohibited |
| **Incumbents cover part of the space** | Truecaller and Android already protect SMS and calls |

### Strategies for Overcoming Them

| Challenge | Strategy |
|---|---|
| Deepfake generalisation | CLIP foundation backbone (generalises better than Xception/CNNs) + **train on WhatsApp-recompressed video** + prefer temporal cues + allow the model to abstain |
| No passive media capture | Passive alert prompts a **one-tap** media check — and doubles as the moment we teach that videos can be faked |
| Battery / OEM process killing | Battery-exemption request, per-OEM setup guidance, testing on real low-cost handsets |
| False positives | **Rule-gated red alerts** — models cannot interrupt. Target red precision **≥98%**, measured and reported |
| Indian-language data gap | Hand-label 500–1,000 current scam messages + templated augmentation + **the bot's own SCAM/SAFE feedback becomes a live labelling pipeline** |
| Gated datasets | Requests submitted in hour one; pretrained public checkpoint as fallback; research use is exactly what the licence permits |
| Incumbents | **Do not compete on SMS and calls.** Own what is unserved: WhatsApp content, synthetic media verdicts, plain-language explanation, email and website forensics |

**[SPEAK] On honesty:** *"This is a prototype risk signal, not a certified forensic tool. We publish the numbers we can defend and name the dataset for every one of them."*

---

## SLIDE 5 — IMPACT AND BENEFITS

### Impact on the Target Audience

**The person who actually loses the money**
- Protection that requires **no literacy, no technical skill and no initiative** — the verdict arrives unasked and is spoken aloud
- Restores **autonomy**: an elderly user can judge a message without waiting for a relative
- Every alert **teaches** the pattern, so the user's own judgement improves over time

**The family**
- The adult child stops being a 24/7 helpdesk and becomes an escalation path, notified automatically with full evidence

**Small businesses and salaried users**
- Email and invoice fraud checking with specific, legible reasons — not an opaque spam verdict

**Institutions**
- A structured, consented stream of current Indian fraud indicators usable by banks, telecoms and I4C/CERT-In

### Benefits

**Social**
- Directly protects the most vulnerable: elderly, low-literacy, first-generation smartphone users
- Multilingual and spoken-first by design — accessible to non-readers and to visually impaired users via full TalkBack support
- Reduces the shame and silence around being defrauded by making "check this" routine and private
- Builds population-level fraud literacy rather than dependence on a black box

**Economic**
- Indians lost close to **₹22,500 crore** to cyber fraud in 2025, across ~**2.8 million** complaints, up 24% year on year
- **83%** of Indian AI-voice-scam victims lost money; nearly half lost over **₹50,000** — for most households, catastrophic
- Deflecting even a small fraction of this is enormous value, and prevention is far cheaper than post-fraud investigation and recovery
- Protects the credibility of UPI and digital banking, on which India's digital economy depends

**Environmental**
- Text and URL checks run **entirely on-device**, so the overwhelming majority of checks consume no server compute or network at all — a deliberately low-energy architecture. Cloud GPU inference is reserved for the rare explicit media check

**Governance**
- Optional tamper-evident evidence bundles give a victim's cybercrime complaint a verifiable integrity claim
- Aggregate, anonymised fraud-pattern data supports national threat intelligence

---

## SLIDE 6 — RESEARCH AND REFERENCES

### Deepfake detection — feasibility and generalisation
- In-the-wild collapse of open-source detectors (45–50% AUC drop) — https://arxiv.org/abs/2607.13234
- What FaceForensics++-trained models actually learn — https://arxiv.org/html/2606.00098
- Social-network compression launders forensic cues — https://arxiv.org/abs/2508.08765
- Temporal artifacts survive re-encoding — https://arxiv.org/pdf/2605.17573
- CLIP for generalizable deepfake detection — https://arxiv.org/abs/2503.19683
- Transformer vs CNN cross-dataset generalisation — https://www.mdpi.com/2673-2688/7/2/68/htm

### Audio anti-spoofing
- AASIST — official implementation and pretrained checkpoints — https://github.com/clovaai/aasist
- AASIST2, short-utterance anti-spoofing — https://arxiv.org/html/2309.08279

### Indian-language NLP
- MuRIL — 17 Indian languages (Apache 2.0) — https://huggingface.co/google/muril-base-cased
- HingBERT / L3Cube-HingCorpus, code-mixed Hindi-English — https://huggingface.co/papers/2204.08398
- Transformer classification of Hinglish cybercrime complaints (I4C data) — https://arxiv.org/html/2412.16614v1

### Datasets
- FaceForensics++ — https://github.com/ondyari/FaceForensics
- Celeb-DF / DFDC — https://ai.meta.com/datasets/dfdc
- ASVspoof — https://www.asvspoof.org
- PhishTank — https://phishtank.org · OpenPhish — https://openphish.com
- UCI Phishing Websites — https://archive.ics.uci.edu
- Nazario Phishing Corpus — https://monkey.org/~jose/phishing

### Android platform constraints (verified)
- Full-screen intent restrictions, Android 14+ — https://source.android.com/docs/core/permissions/fsi-limits
- `MANAGE_EXTERNAL_STORAGE` eligibility limits — Google Play policy
- SMS / Call Log permission policy — https://support.google.com/googleplay/android-developer/answer/10208820
- CallScreeningService — https://developer.android.com/develop/connectivity/telecom/dialer-app/screen-calls

### Threat landscape and existing solutions
- CERT-In incident reporting, 2025 — phishing at 22% of handled incidents
- I4C / NCRP complaint and loss figures, 2025
- Android on-device scam protection — https://security.googleblog.com/2024/11/new-real-time-protections-on-Android.html
- Truecaller AI SMS fraud protection — https://corporate.truecaller.com/newsroom/press-release/28923657E2813595

*All external source content was rephrased; figures are attributed to the cited originators.*

---

## 2. Product Thesis

### 2.1 Push, not pull

The system notices on its own and interrupts at the moment of danger. This is the antivirus *interaction model* — resident, silent until it matters, then unmissable — with none of the antivirus vocabulary. "Threat quarantined" assumes security literacy. "Protect your device" is the wrong promise; this user cares about her money and her family, not her handset.

### 2.2 One backend, four surfaces

The PS demands email and website analysis, which do not belong on a phone. The mobile pivot in v2.0 created a false conflict. Resolution: **one detection backend, four thin clients.**

| Surface | Serves | Pillars exposed |
|---|---|---|
| **Android app** | Reach and early detection for the primary persona | Text, URL, media, voice notes, calls |
| **WhatsApp bot** | Zero-install reach, judge testing | All, via forwarding |
| **Web checker** | Email and website pillars the PS names | Email paste/`.eml` upload, URL deep-scan, media upload |
| **Browser extension** | Desktop link protection | URL + website |

The web surface is not a fallback. It is the natural home for the two pillars a phone cannot host well.

### 2.3 Explainability as pedagogy

Clause 12 asks the system to improve the *user's* ability to identify fraud. That is a teaching requirement, and it is the part no incumbent attempts. Truecaller tells you a message is fraudulent. It does not show you that the domain was registered four days ago, or that the sender's display name and actual address disagree, or which phrase was the pressure tactic.

Every verdict therefore names its evidence in plain language. The goal is a user who, after a few weeks, spots the next one without us. That is a strange goal for a product that wants retention, and it is the right one here.

## 3. Competitive Reality

Omitting this section would be the single biggest credibility hole in the pitch, because any judge with an Indian phone has Truecaller installed.

### 3.1 What already exists

| Player | Already ships | Implication |
|---|---|---|
| **Truecaller** | AI SMS fraud protection with a persistent red warning; scam call detection; community reporting; fraud insurance up to ₹10,000; family group with cross-account fraud alerts and remote call termination | Owns calls and SMS. **Also owns our family-escalation idea, and does it better** |
| **Google / Android** | [On-device scam detection in Messages, real-time scam call warnings, ongoing expansion through 2026](https://security.googleblog.com/2026/02/strengthening-android-lead-in-scam-protection.html?hl=en_GB); Play Protect; Safe Browsing | The platform owner is commoditising SMS and call protection. Competing here is a losing position |
| **Email providers** | Gmail/Outlook spam and phishing filtering at enormous scale | Do not attempt to beat them on volume. Our email angle is *explanation*, not filtering |

### 3.2 What is genuinely unserved

1. **Is this forwarded video or voice note synthetic?** No mainstream Indian consumer product answers this. This is real open space
2. **WhatsApp message content.** Truecaller and Google Messages cannot see it. Our notification-listener route can. A head start, not a moat — but a real one
3. **Explanation that teaches** (§2.3)
4. **Email and website forensics presented to a non-technical user** in plain language
5. **The literacy layer.** Spoken Indic verdicts, textless UI, instruction-not-diagnosis. Incumbent UIs assume a literate, English-comfortable user

### 3.3 Where we deliberately do not compete

**Scam call labelling and SMS spam filtering are demoted to P2/roadmap.** Truecaller and the OS own them. Building a worse Truecaller is the most likely way to waste this project. Our call-adjacent contribution is voice-note analysis, which nobody does.

*This repositioning is a v3.0 change and it removes features v2.0 had at P1.*

## 4. Target Users

| Persona | Reality | Need |
|---|---|---|
| **Primary: low-literacy WhatsApp user** (58, semi-urban parent) | Reads slowly or not at all. Will not install or configure anything. Trusts voice over text. Under social pressure when it matters | To be interrupted and told, out loud, *do not send money* |
| **Secondary: the adult child** | Installs and configures the app on the parent's phone. Is who the parent actually calls when unsure | To be looped in automatically |
| **Tertiary: self-serve checker / small business owner** | Receives phishing email, unsure about a link or invoice | Fast forward-to-check, and an email/website deep scan |
| **Judge** | Must test it themselves in the demo window, zero setup | Live arbitrary input, legible explanation |

**The app is installed by the child and used by the parent.** All configuration complexity is deliberately concentrated in a setup flow the competent persona completes once.

## 5. Delivery Surfaces

### 5.1 Channel A — Android app (flagship)

Ambient protection. Native Kotlin. See §7 for the feature inventory and §17 for the permission risks, which are substantial.

### 5.2 Channel B — WhatsApp forward-bot (zero install)

For users who will never install anything, and the fastest path for a judge to test from their own phone.

**Hard constraint:** there is no API to read a user's personal WhatsApp chats. The Cloud API and Twilio sandbox only receive messages sent *to our* number. The bot cannot monitor passively. It works because forwarding is already the native verb of Indian WhatsApp — we intercept an existing behaviour rather than teaching a new one.

| Aspect | Decision |
|---|---|
| Provider | Twilio WhatsApp Sandbox for the hackathon (minutes to set up, `join <code>` opt-in). WhatsApp Cloud API is the production path (Meta business verification, days). Build behind an adapter interface |
| Accepts | Text, links, images, video, voice notes. Polite unsupported-type reply for anything else, never a silent failure |
| Media ceiling | ~16MB provider limit. Reply "send a shorter clip" rather than erroring |
| Reply format | Emoji + word + action line + at most three named reasons. Never lead with a number |
| **Voice-note reply** | The verdict is also rendered to audio and sent as a WhatsApp voice message. This carries the literacy guarantee into a channel with no UI. Small build, largest payoff |
| Commands | Forward anything (default, no command); `HI`/`START`; `1`/`2`/`3` for language; `HELP` to escalate to family; `SCAM`/`SAFE` for feedback |
| Feedback loop | `SCAM`/`SAFE` produces labelled, current, real Indian scam data — the scarcest resource in this project (§12.3). The bot is the data pipeline, not just a demo feature |
| Limits | 24-hour free-form reply window; sandbox opt-in friction; no passive monitoring |

Sample reply:

```
🔴 खतरा — यह नकली है

पैसे मत भेजिए। यह बैंक का संदेश नहीं है।

क्यों:
• यह वेबसाइट 4 दिन पहले बनी है
• SBI की नकली नकल है
• "तुरंत" शब्द — यह दबाव बनाने की चाल है

परिवार को दिखाएँ? "HELP" भेजें
```

### 5.3 Channel C — Web checker

Where the email and website pillars live. Paste an email or upload `.eml`, paste a URL for a full page scan, upload media. Also the judge-friendly surface that needs no install. Plain React, no auth for MVP.

**Security note:** an unauthenticated endpoint that fetches arbitrary URLs and accepts file uploads is an SSRF and abuse target. For MVP, rate-limit by IP, block private/link-local address ranges in the fetcher, cap upload size, and run page fetching in a sandboxed worker with no access to internal network. This is not optional even for a prototype, because the fetcher is a genuine server-side vulnerability.

### 5.4 Channel D — Browser extension (stretch)

Reuses the URL and website APIs. High demo value, low novelty.

### 5.5 Android API reality

Verified against current platform and policy documentation. Binding on scope.

| Capability | API | Status |
|---|---|---|
| Read incoming message **text** passively | `NotificationListenerService` | **Available — the product rests on this** |
| Manual check of anything | `ACTION_SEND` share target | Available. One gesture, replaces copy-paste |
| On-device OCR of scam screenshots | ML Kit Text Recognition | Available, free, offline, Devanagari and Tamil support |
| Screen-takeover alert | `SYSTEM_ALERT_WINDOW` | Available as special access, user-granted via Settings. **Use this, not full-screen intents** |
| Screen-takeover via notification | `USE_FULL_SCREEN_INTENT` | **Unreliable.** [Android 14 restricted it to calling and alarm apps by default](https://source.android.com/docs/core/permissions/fsi-limits) — a change made to curb credential phishing — and it [reportedly only goes full-screen on a locked device](https://proandroiddev.com/full-screen-intent-fsi-notifications-in-android-14-15-what-changed-why-its-breaking-and-e5e862a75936) |
| Label incoming calls | `CallScreeningService` | Available via `RoleManager`. **Demoted to P2 — see §3.3** |
| Device-wide DNS blocking | local `VpnService` | Available. Stretch |
| Record the other party in a live call | — | **Not possible.** API removed in Android 6, accessibility workaround closed May 2022, now treated as spyware under Play policy |
| Read SMS directly | `READ_SMS` | Restricted to default SMS handler or an approved exception. Unnecessary — notifications already carry SMS text |

### 5.6 The media interception limit — architectural correction

**v2.0 contained a false assumption and the architecture diagram was wrong.**

A notification carries *text*, not files. A WhatsApp image or video notification shows a placeholder such as "📷 Photo", and the media itself lives in WhatsApp's scoped storage at `/Android/media/com.whatsapp/...`, which requires `MANAGE_EXTERNAL_STORAGE` — [a permission Play restricts to narrow categories such as file managers, backup tools and antivirus apps](https://stackoverflow.com/questions/79723799/cant-access-whatsapp-status-folder-using-saf-or-mediastore-without-manage-exter).

**Therefore: passive deepfake detection is impossible. The media path is always user-initiated.**

Consequences, all of which we now design around:

- The passive path handles **text and links only** — which happens to be the reliable pillar anyway
- The media path is **share-sheet or bot forward**, always an explicit user action
- **The UX turns the limit into a prompt:** when a passive scan sees a message that also contains media, the alert says *this message also has a video — tap to check it*. One tap, and it doubles as the moment we teach the user that videos can be fake
- Bundled notifications ("3 new messages"), disabled notification previews, and long-message truncation all degrade the passive path. Handle gracefully, never guess
- The demo script in Appendix A is rewritten accordingly. Do not demo a passive video catch — it cannot happen

### 5.7 Sensitive-notification redaction — investigated on real hardware, and largely a non-issue

**Status: resolved in our favour. The passive path works.** This section previously called redaction the project's biggest blocker, based on emulator measurements. Testing on a retail device overturned that. The history is kept because the emulator result is a trap anyone reproducing this work will fall into.

#### What the emulator showed (misleading)

On an API 35 emulator, our listener received the literal string `Sensitive notification content hidden` instead of message content. Every *message* notification was redacted regardless of content — including "Meeting moved to 3pm tomorrow" — while non-message notifications ("Messages is syncing with your device") came through intact. That looked like a platform-level shutdown of the entire thesis.

#### What retail hardware shows (authoritative)

Measured on a **Pixel 7, Android 17 (API 37)**, July 2026 security patch, with Android System Intelligence active and unmodified (`isUserChanged: false`, so a default configuration):

| Input | Source field | Result |
|---|---|---|
| WhatsApp message from another person, containing two links | `MessagingStyle` | **Full content, 129 chars, 2 URLs extracted → RED 81.1, 8 signals, 8.4ms** |
| Our own app's notification, scam text | `bigText` | **Full content, 130 chars, 2 URLs → RED 83.0, 10 signals** |

No redaction. Decisively, the `RECEIVE_SENSITIVE_NOTIFICATIONS` appop was **never consulted** for these notifications — its `rejectTime` remained hours stale throughout — so the redaction path was not merely permissive, it was not invoked at all.

**Conclusion:** the emulator's blanket redaction is almost certainly the classifier failing closed in the absence of its on-device model, not intended platform behaviour. Never characterise this feature on an emulator.

#### Residual risk, honestly bounded

- Verified on **one device, one OEM, one OS version**. A Pixel is the reference implementation, which is the strongest single data point available, but it is still one point.
- Published accounts describe a content classifier that targets things like 2FA codes. We did not test a message containing an OTP-like numeric code, so a narrower redaction may still apply to exactly those. Worth testing, though a message whose payload is a bare code is not our threat model.
- Samsung One UI and Chinese OEM builds may differ. Unverified.

#### The escape hatch, if a device does redact

The gate is `RECEIVE_SENSITIVE_NOTIFICATIONS`. It is **not a runtime permission** — `pm grant` fails with *"managed by role"* — it is an **appop**. Two routes, both confirmed working on the emulator:

1. `adb shell appops set <pkg> RECEIVE_SENSITIVE_NOTIFICATIONS allow`, **plus a listener rebind** (disallow then allow, or a reboot). Trust is evaluated when the listener binds, so setting the appop alone changes nothing — this cost several confusing iterations to establish.
2. The user disabling **Enhanced notifications** in Settings, which turns off the classifier driving the redaction, at the cost of smart replies and notification actions.

Neither is available to an app installed from the Play Store onto a parent's phone, so if redaction did apply broadly, unassisted consumer distribution would be off the table. Since it does not apply on current Pixel hardware, this stays a contingency rather than a constraint.

### 5.8 MessagingStyle extraction — the bug that would have silently broken WhatsApp

Found in the same session, and more consequential in practice than the redaction scare.

**WhatsApp posts `MessagingStyle` notifications with no `EXTRA_BIG_TEXT` at all, and `EXTRA_TEXT` holds only a short fragment.** Our original extractor read `EXTRA_BIG_TEXT` then fell back to `EXTRA_TEXT`, which on a real WhatsApp message yielded **34 characters and zero URLs** out of a 129-character message containing two links. The verdict was GREEN. The pipeline was working perfectly and analysing almost nothing.

This would not have been caught by any unit test, by the emulator SMS path (Google Messages populates `EXTRA_TEXT` usefully), or by our own synthetic notifications (which used `BigTextStyle`). It required a real message from a real person in the actual target app.

The fix reads `MessagingStyle` first via `NotificationCompat.MessagingStyle.extractMessagingStyleFromNotification()`, joining the message list so a link split across consecutive messages is still seen whole, and falls back to `bigText` then `text`. The extraction source is now logged (`src=messagingStyle(1)`, `src=bigText`) so a regression is visible immediately.

**Generalisable lesson for the build:** every messaging app must be verified individually with a real inbound message. Telegram, Instagram and Signal all use their own notification styles and none is covered by testing WhatsApp. Treat "which field holds the body" as per-app knowledge to be measured, not assumed.

### 5.9 Email detection now runs on-device (v3.1)

Email header forensics existed only on the backend, and the app never called the backend — the phone is 100% on-device, and OkHttp is a dependency that nothing uses. So on the actual product, email detection did not exist. PS clauses 1 and 7 were satisfied on paper (the FastAPI endpoint) and unreachable in the hand.

**Fix:** `EmailRules.kt` ports the header forensics to Kotlin — display-name-brand-vs-sending-domain (`EMAIL_BRAND_FROM_FREEMAIL` CRITICAL: a bank never mails from Gmail), sender-domain lookalike, `Reply-To` divergence, `Return-Path` mismatch, and SPF/DKIM/DMARC. The share sheet detects email-shaped content (`From:`/`Subject:` header lines, or an angle-bracketed address) and routes it through `LocalRules.analyseEmail`, which runs the header rules and also passes the body through the ordinary URL and text rules. The manifest now advertises `message/rfc822`, so mail apps offer SatyaShield in their share menu.

**Honest constraint on the entry point.** The realistic on-device source is "share this email" from a mail app, which hands over the body and usually a `From` line but **not** the full RFC 822 header block. So on a phone the forensics are partial by construction: display-name and sender-domain checks fire whenever those lines are present and degrade to silence when they are not. Crucially, **`Authentication-Results` is not trusted on the phone** — a shared or pasted blob has attacker-controllable headers, so SPF/DKIM/DMARC evaluation is gated behind `trustAuthHeaders`, which is false for shared content and would only be true for mail retrieved through an authenticated account (not built). The full-fidelity path remains the web checker / API, where the complete raw message is available. Verified end to end in unit tests: a phishing email reaches RED, a legitimate bank email stays GREEN.

## 6. Detection Pillars

### 6.1 URL and link

The most reliable pillar, and mostly not machine learning.

**Rule signals** (deterministic, explainable, high precision): domain age via WHOIS; redirect-chain resolution behind shorteners; IP-literal hosts; punycode and homoglyph distance to Indian brand terms (`sbi`, `hdfc`, `icici`, `npci`, `upi`, `irctc`, `indiapost`, `aadhaar`, `trai`); excessive subdomain depth; risky TLDs; **APK download links**, which for this user segment are near-conclusively malicious and drive the "wedding invitation" and "courier parcel" scams; UPI handles from unknown senders; urgency-plus-payment keyword co-occurrence including the *digital arrest* pattern.

**ML signal:** XGBoost over lexical and domain features. Secondary to the rules, never primary.

### 6.2 Website characteristics — new in v3.0

PS clause 8, previously unaddressed. Fetch the page in a sandboxed headless browser and analyse:

| Signal | Why it matters |
|---|---|
| Login form action target on a different domain | Classic credential-harvest tell |
| Password input over plain HTTP | Near-conclusive |
| TLS certificate issuer, age, subject mismatch, self-signed | Fresh free certs on brand-lookalike domains are a strong pattern |
| Favicon perceptual hash matching a known brand while the domain does not | Very high precision clone detector |
| External resource origins | Clones commonly hotlink assets from the genuine bank's CDN |
| Brand name in page text vs domain registration | "State Bank of India" on `sbi-verify.top` |
| Hidden fields, obfuscated JS, right-click/devtools suppression | Weak individually, useful in aggregate |
| Optional: screenshot + visual similarity to known login pages | Strong demo artifact, moderate effort |

Nearly all of these are deterministic and legible, which suits §14.2 and clause 12.

### 6.3 Email — new in v3.0

PS clauses 1 and 7, previously unaddressed. The substance of email phishing detection is in the headers, and headers are cheap, deterministic and highly explainable.

| Signal | Source |
|---|---|
| SPF / DKIM / DMARC evaluation | `Authentication-Results` and raw header re-check |
| `Received` chain anomalies | Origin geography, hop count, mismatched relays |
| `Reply-To` vs `From` divergence | The single most common business-email-compromise tell |
| Display-name spoofing | `"HDFC Bank" <random@gmail.com>` |
| Sender-domain homoglyph and lookalike distance | Same engine as §6.1 |
| `Return-Path` mismatch | Envelope vs header sender |
| Body: urgency, payment instruction, credential request | Shared text classifier (§6.4) |
| Embedded links | Handed to the URL pillar (§6.1) and optionally §6.2 |
| Attachment type and macro presence | Static inspection only, no execution |

**Ingestion:** `.eml` upload or paste in the web checker; share-from-Gmail into the Android app yields body text but not full headers, so the app path is explicitly degraded and says so.

**Why this pillar is worth real effort:** it is pure feature engineering with no data-scarcity problem, it satisfies two PS clauses, it produces beautifully specific explanations, and it needs no GPU.

### 6.4 Message and email text

Multilingual scam-intent classification: urgency, payment pressure, credential requests, authority impersonation.

- **Model:** MuRIL (Apache 2.0, 17 Indian languages plus transliteration) or HingBERT for Roman-script code-mixed Hinglish. TF-IDF + logistic regression as the always-works fallback and as the on-device tier
- **OCR path, new in v3.0:** a large and growing share of Indian scam content is **an image containing text**, which defeats a text classifier entirely. ML Kit on-device OCR extracts it first. Free, offline, supports Devanagari and Tamil. Cheap fix for a gap that would otherwise be trivially exploited

### 6.5 Deepfake video and image

CLIP ViT-L/14 frozen backbone with a lightweight probe, frame-sampled, trained with compression augmentation. Grad-CAM for the face heatmap. Server-side only. **Demo flagship, deliberately not load-bearing** — see §13.2 for why, and §14 for how the system stays useful when this model is uncertain.

### 6.6 Deepfake audio and voice notes

AASIST or a wav2vec2 front end on forwarded WhatsApp voice notes. [Pretrained ASVspoof 2019 LA checkpoints are published by the original authors](https://github.com/clovaai/aasist) and mirrored on Hugging Face, so inference needs no training at all. [AASIST2 improves short-utterance performance](https://arxiv.org/html/2309.08279), which matters because voice notes are short.

Cheaper than video, no face pipeline, and voice cloning is among the fastest-growing Indian vectors. Explainability is harder — a spectrogram is not legible to our persona — so the output leans entirely on the spoken plain-language verdict.

## 7. Feature Inventory

Grouped by area. All capture paths funnel into one message assembler so detection is written once.

### 7.1 Capture

| ID | Feature | Pri | Notes |
|---|---|---|---|
| F1 | Passive message **text** scanning | P0 | Notification listener + foreground service. **Text only** — see §5.6 |
| F2 | Share-sheet target | P0 | Text, image, video, audio. The only route to media |
| F3 | Media-present prompt | P0 | Passive alert offers a one-tap media check (§5.6) |
| F4 | On-device OCR | P0 | Scam text inside images |
| F5 | Web checker: email paste / `.eml` upload | P0 | PS clauses 1, 7 |
| F6 | Web checker: URL deep scan | P0 | PS clauses 2, 8 |
| F7 | In-app paste box | P0 | Judge and tertiary persona path |
| F8 | Gallery / file picker | P1 | |
| F9 | WhatsApp bot ingestion | P1 | |
| — | ~~Clipboard auto-check~~ | **Cut** | Android 10+ blocks background clipboard reads |
| — | ~~Call screening~~ | **P2** | Truecaller owns this (§3.3) |

### 7.2 Detection

| ID | Feature | Pri |
|---|---|---|
| F10 | URL rule engine | P0 |
| F11 | India-specific high-precision rules (APK, UPI, brand homoglyph) | P0 |
| F12 | Domain intelligence (WHOIS age, blocklists) | P0 |
| F13 | URL classifier (XGBoost) | P0 |
| F14 | Website characteristics analyser | P0 |
| F15 | Email header forensics | P0 |
| F16 | Multilingual text classifier | P0 |
| F17 | Deepfake video/image detector | P0 |
| F18 | Voice-note deepfake detector | P1 |
| F19 | Attachment static inspection | P1 |
| F20 | Sender reputation | P1 |

### 7.3 Fusion and decision

| ID | Feature | Pri |
|---|---|---|
| F21 | Message assembler | P0 |
| F22 | Evidence fusion with named contributions | P0 |
| F23 | Three-state policy with abstention | P0 |
| F24 | Rule-gated red escalation (§14.2) | P0 |
| F25 | Numeric confidence drill-down | P0 |

### 7.4 Verdict and output

| ID | Feature | Pri |
|---|---|---|
| F26 | Overlay interrupt on red (`SYSTEM_ALERT_WINDOW`) | P0 |
| F27 | Three-state verdict card (colour + icon + word + sound) | P0 |
| F28 | Spoken verdict, EN/HI/TA | P0 |
| F29 | Action instruction line | P0 |
| F30 | Face heatmap explanation | P0 |
| F31 | Highlighted phrase explanation | P0 |
| F32 | Named red flags (URL, website, email) | P0 |
| F33 | Repeat-aloud | P0 |
| F34 | Quiet amber (no screen seizure) | P0 |

### 7.5 Family escalation

| ID | Feature | Pri |
|---|---|---|
| F35 | "Ask family" one-tap | P0 |
| F36 | Trusted contact registration | P0 |
| F37 | Family-side alert with full evidence | P0 |
| F38 | Family-side reply pushed back to the parent | P1 |

### 7.6 Setup, history, stretch

| ID | Feature | Pri |
|---|---|---|
| F39 | Guided permission flow with deep links | P0 |
| F40 | Language selection | P0 |
| F41 | Self-test "prove it works" flow | P0 |
| F42 | Persistent protection indicator | P0 |
| F43 | Battery-optimisation exemption prompt + OEM guidance | P0 |
| F44 | Setup handoff mode | P1 |
| F45 | Verdict history | P1 |
| F46 | "Was this right?" feedback | P1 |
| F47 | Family dashboard (consent-gated) | P1 |
| F48 | Browser extension | Stretch |
| F49 | Local VPN DNS blocking | Stretch |
| F50 | Community forward-count signal | Stretch |
| F51 | Tamper-evident evidence bundle (§16) | Stretch |

### 7.7 MVP cut line

If time collapses: **F1, F2, F3, F5, F6, F10, F11, F12, F14, F15, F16, F21, F22, F23, F24, F26, F27, F28, F29, F32, F35, F39, F40, F41, F43.**

That is passive text interception, the email and website pillars, the reliable detectors, rule-gated fusion, the interrupting spoken verdict, family escalation and a working setup flow. **F17, the deepfake video detector, is not on the list** — and the system still satisfies 11 of 12 PS clauses without it. That is deliberate resilience, not hedging.

## 8. Approachability Layer

### 8.1 No numeric score in the primary view

"Trust Score 34/100" demands numeracy and is ambiguous about direction. Three states instead:

| State | Meaning | Encoding |
|---|---|---|
| **Safe** | No significant signals | Green + tick + word + soft chime |
| **Suspicious** | Signals present, or models uncertain | Amber + question + word + neutral tone |
| **Danger** | Deterministic fraud indicators | Red + stop + word + urgent tone |

Redundant encoding across colour, icon, word and sound. Colour alone fails colourblind users and anyone who does not read red as danger. Numeric confidence remains one tap away.

### 8.2 Speak the verdict

Android TTS with Indic voices. Reaches a user who cannot read the screen at all. Highest impact per unit of effort in the product.

> यह संदेश धोखा है। पैसे मत भेजिए।

### 8.3 Instruct, do not describe

| Bad | Good |
|---|---|
| "Suspicious link detected" | "Do not open this. It is not really from the bank." |
| "Deepfake likelihood 0.87" | "This video is fake. Do not send money." |
| "Potential vishing attempt" | "Do not share the OTP with anyone. Not even a bank officer." |

### 8.4 Author the language, do not translate it

Machine-translating "phishing detected with 87% confidence" into Hindi yields something *less* comprehensible than the English. Hand-write colloquial, spoken-register templates per language. Formal register is a failure mode.

**Banned:** phishing, deepfake, URL, malicious, vishing, credential, authenticate, verify.
**Use:** trap link, fake video, fake voice, money fraud, do not click, do not send money.

### 8.5 Interface constraints

Icon-driven home screen, two buttons maximum. Minimum 20sp body text, high contrast, large targets. No settings reachable by the primary persona. Full TalkBack labelling.

## 9. Family Escalation

**The failure mode:** correct detection, clear warning, user proceeds anyway because a live human is more persuasive than a popup. Social engineering beats UI.

On red or amber, one large button — **"Ask family"** — forwards the content, the verdict and the evidence to a registered trusted contact, who gets an immediate push. Converts an isolated decision under pressure into a supported one.

**Honest note:** Truecaller ships a stronger version of this (§3.1), including remote call termination. We should not present it as novel. We present it as necessary, and integrated with explanation and multimedia verdicts in a way theirs is not.

## 10. Architecture

```
INGEST                        PROCESSING                        OUTPUT
──────────────────            ────────────────────────          ──────────────────
NotificationListener ─┐
  (TEXT ONLY, §5.6)   │
Share sheet ──────────┤
OCR (image→text) ─────┼──▶ Message Assembler ──┬──▶ ON-DEVICE
WhatsApp bot ─────────┤    (text + links +     │    • Rule engine
Web checker ──────────┘     media + sender)    │    • Small text classifier
                                               │    • OCR
                                               │      (<100ms, offline, no data leaves)
                                               │
                                               └──▶ SERVER (explicit submit only)
                                                    • Website fetch + analysis
                                                    • Email header forensics
                                                    • CLIP video detector
                                                    • AASIST audio detector
                                                    • WHOIS / blocklist intel
                                                            │
                                                            ▼
                                              EVIDENCE FUSION (§14)
                                              rule-gated red, model→amber
                                                            │
                                    ┌───────────────────────┼───────────────────┐
                                    ▼                       ▼                   ▼
                            3-state verdict          Named explanation    "Ask family"
                            + TTS (EN/HI/TA)         (heatmap/phrases/     escalation
                                                      red flags)
```

**Split rationale:** the automatic path is entirely on-device, so passively scanned message content never leaves the phone. Server processing happens only on explicit user submission. This is what makes §15.1 true rather than aspirational.

## 11. Models — Inventory, Licensing, Cost, Training

### 11.1 Inventory

| Pillar | Model | License | Paid? | Size | Training needed |
|---|---|---|---|---|---|
| URL | XGBoost | Apache 2.0 | Free | <5MB | Yes, trivial |
| Text | [MuRIL base](https://huggingface.co/google/muril-base-cased) | Apache 2.0 | Free | ~470MB fp32 / ~120MB int8 | Fine-tune |
| Text (Hinglish) | [HingBERT / HingRoBERTa](https://huggingface.co/papers/2204.08398) (L3Cube) | Check repo terms | Free | BERT-base class | Fine-tune |
| Text fallback | TF-IDF + LogReg | scikit-learn, BSD | Free | <10MB | Minutes |
| Video | CLIP ViT-L/14 (OpenAI / OpenCLIP) | MIT / permissive | Free | ~1.7GB, server-side | Probe only |
| Audio | [AASIST / AASIST-L](https://github.com/clovaai/aasist) | Verify repo license | Free | ~1–20MB | **None — pretrained checkpoint** |
| OCR | ML Kit Text Recognition | Free tier, on-device | Free | Bundled | None |
| TTS | Android platform TTS | Free | Free | OS | None |

**Nothing here costs money.** No OpenAI, Anthropic or Google API calls in the inference path. Total software licensing cost is zero. Infrastructure cost is one GPU instance for media inference, which can be a Colab or a rented T4 for the hackathon.

### 11.2 On-device size, the real constraint

MuRIL is BERT-base scale. Quantised to int8 it is roughly 120MB, which is heavy for a sub-₹10,000 Android phone with 2–3GB RAM — exactly the hardware our primary persona owns. This is in direct tension with the on-device privacy claim.

**Resolution:** tier it. Rules plus TF-IDF+LogReg on-device (a few MB, sub-100ms, covers most traffic and all of the high-precision red signals). The transformer runs server-side, invoked only when the cheap tier is uncertain *and* the user has consented, or on explicit submission. State this tiering openly; do not claim a transformer runs on-device when it realistically will not on the target hardware.

### 11.3 Training plan and compute budget

| Task | Data volume | Hardware | Wall-clock estimate |
|---|---|---|---|
| URL XGBoost | ~100k rows, ~30 features | CPU | **Under 5 minutes** |
| Text: TF-IDF + LogReg | ~20k messages | CPU | **Under 2 minutes** |
| Text: MuRIL fine-tune | ~10k labelled, 3 epochs | 1× T4 | **20–40 minutes** |
| Video: face extraction | ~5k videos → ~50k crops | CPU, parallelised | **3–6 hours. This is the real bottleneck** |
| Video: CLIP feature extraction | ~50k crops | 1× T4 | **15–30 minutes** |
| Video: probe training | 50k feature vectors | CPU/GPU | **Under 10 minutes** |
| Video: compression-augmented rerun | 2× the above | | Double the video budget |
| Audio | none — pretrained inference | — | **Zero** |
| Optional audio fine-tune | ASVspoof LA subset | 1× T4 | 1–3 hours |

**Total realistic GPU budget: under one day on a single T4.** The dominant cost is CPU-bound video decoding and face cropping, not model training. This is only true because we use frozen backbones with light probes — a full fine-tune of a video model would blow the budget entirely and is out of scope.

### 11.4 The commercial licensing blocker

This is the finding that most affects the standalone-product question.

FaceForensics++ terms restrict the [database to non-commercial research and educational use](https://kaldir.vc.in.tum.de/faceforensics/webpage/FaceForensics_TOS.pdf). Celeb-DF and DFDC carry comparable research-only restrictions. Consequences:

- A hackathon prototype and academic work: **fine, this is exactly the permitted use**
- A commercial product shipping a detector trained on that data: **not permitted**
- The general principle applies broadly — [downloadable weights do not by themselves grant commercial rights, and the whole license chain must be traced](https://quasa.io/media/open-weight-does-not-mean-safe-for-commercial-use-check-the-license-chain)

**Commercialisation path if this ever leaves the hackathon:** license data commercially, generate our own synthetic training corpus with tools we hold rights to, or partner with an institution that holds usable data. Budget months, not weeks. Note also that the backbones themselves (CLIP, MuRIL) are permissively licensed — the restriction is on the *training data*, so a probe trained on self-generated data is clean.

### 11.5 Trained models — measured results

Both models are built, evaluated and wired into the pipeline. Neither needs a GPU
or a gated dataset; total training time is under two minutes on a laptop CPU.

#### Domain-reputation model (URL pillar)

Gradient boosting over 19 features derived from the **registrable domain only**,
with isotonic calibration.

| | |
|---|---|
| Training data | PhishTank + OpenPhish (72,880 URLs → 12,610 unique malicious domains) vs Tranco sampled across all rank bands (19,000 benign domains) |
| Held-out | ROC AUC **0.815**, PR AUC **0.805** |
| Operating point used | p ≥ 0.90 → **97.8% precision**, 32.5% recall |
| Leakage probe | Top feature accounts for 25.4% of permutation importance — no single source artifact dominates |

**Two data-hygiene decisions that changed the design, both forced by inspecting the data:**

- **Subdomain and path features are excluded.** 72.1% of phishing hostnames carry a subdomain versus 0.0% of Tranco benign domains, because the two sources publish different granularities. Any subdomain feature would let the model score near-perfectly by detecting which *file* a row came from.
- **Phishing on shared hosting is excluded from training.** 54% of the feed's URLs sit on registrable domains that also appear in the benign list — `google.com` alone accounts for 7,141 entries, alongside `weebly.com`, `pages.dev`, `firebaseapp.com`, `bit.ly`, `dropbox.com`. Those are phishing pages on legitimate infrastructure; no domain-level model can separate them because the domain genuinely is benign. Training on them would teach the model that Google is malicious.

The honest consequence: this model detects **maliciously registered domains**. Phishing hosted on legitimate platforms is a real and acknowledged gap, addressed by page-content analysis (§6.2) and blocklists, not by this classifier.

#### Text classifier (message pillar)

TF-IDF over word and character n-grams into logistic regression. Character n-grams are what let it degrade gracefully on transliterated Hinglish, where word tokens are unreliable.

| | |
|---|---|
| Training data | UCI SMS Spam Collection, 5,574 messages (747 spam) |
| Held-out, English | ROC AUC **0.995**, precision 0.989, recall 0.952 |
| **Indian scam probe** | **caught 2 of 8** hand-written current Indian scam messages |
| Benign Indian probe | **0 of 6** false positives |

**This is §12.3's data gap turned into a number.** The model scores 0.995 AUC in distribution and misses the SBI KYC phishing, the CBI digital-arrest script, the Hinglish, and rates a Devanagari scam at 0.045. The fix is the hand-collected Indian corpus, not a larger model. Quote both figures together or neither.

It also validates the architecture: the deterministic rules catch the SBI message the model misses.

#### What wiring the models in cost us

Adding classifiers to a working rule engine **introduced a false positive**: a genuine HDFC transaction SMS moved from GREEN to AMBER, because the text model scores real bank messages at ~0.75 — they resemble the promotional spam in the UCI corpus.

Three fixes, all now regression-tested:

1. **Model output is only surfaced at high-precision operating points.** URL floor raised to p ≥ 0.90 (97.8% measured precision), text floor to p ≥ 0.85. Recall is traded away deliberately: a model can only reach AMBER, but a stream of unjustified ambers still teaches the user to ignore us, and recall is the rule engine's job.
2. **Protective credential advice no longer counts as evidence.** "Never share your OTP or PIN" is what real banks put in every transaction SMS. The strong rule already handled negation; the weak residue signal did not, and "Do not share **it** with anyone" needed pronoun handling too.
3. **The text model never scores a bare URL as prose (v3.1).** Found in use: legitimate bank homepages were pushed to AMBER — `axisbank.com` scored 0.858, `irctc.co.in` 0.835, even `google.com` 0.652 — because the UCI corpus ties URLs to spam, so the classifier learned "contains a link ⇒ scam". The fix strips URLs before scoring and, when what remains is essentially just a link (under 12 alphanumeric characters of prose), does not consult the model at all. URLs are the URL pillar's job; the text model judges the words a human wrote around them. `axisbank.com` and friends are now GREEN, and a scam with a link is unaffected because its prose still scores. The on-device engine never had this bug — it carries no text model and its URL rules allowlist real bank domains — but it gained a matching `stripUrls` helper so the two engines cannot diverge once a model is added on-device.

Current behaviour on an unknown sender, which is the realistic case since bank shortcodes are never saved contacts:

| Message | Verdict |
|---|---|
| APK link | RED, interrupts |
| SBI lookalike + credential path | RED, interrupts |
| Digital-arrest script (no link) | AMBER, routes to family |
| Model-only spam (no rule hits) | **AMBER — 99.5% model confidence still cannot interrupt** |
| Real HDFC transaction SMS | GREEN |
| Real OTP SMS | GREEN |
| Amazon delivery notice | GREEN |
| Bare bank URL (axisbank.com, irctc.co.in) | GREEN *(v3.1; was AMBER)* |
| Family message | GREEN |
| Hinglish scam | AMBER |

The model-only-spam row is the §14.2 guarantee demonstrated with a real classifier rather than a synthetic test signal.

## 12. Data Acquisition Plan

### 12.1 Sources, access process and volume

| Pillar | Source | Access | Volume | Reliability |
|---|---|---|---|---|
| URL — malicious | PhishTank feed | Account/API key registration | Continuous feed | Good, but community-reported and noisy |
| URL — malicious | OpenPhish community feed | Free tier | Continuous | Good |
| URL — benign | Tranco / Majestic top-sites list | Direct download | ~1M domains | Good. **Beware the trap in §12.4** |
| URL — features | UCI Phishing Websites | Direct, instant | ~11k rows | Dated. Baseline only |
| Website | Live fetch of the above URLs | Our own crawler | On demand | We generate this ourselves — no dataset needed |
| Email | Nazario Phishing Corpus | Direct download | Thousands of messages | Standard, but old |
| Email — benign | Enron corpus | Direct download | ~1.7GB | Standard, but old and American |
| Text — Indian | [L3Cube Hindi/English SMS spam](https://github.com/princebari/-SMS-Spam-Classification-on-Indian-Dataset-A-Crowdsourced-Collection-of-Hindi-and-English-Messages) | Direct | ~2k messages | Small and dated, but genuinely Indian |
| Text — multilingual | [SpamShield corpus](https://huggingface.co/datasets/M-Arjun/SpamShield-Datasets) | Hugging Face | ~149k, 23 languages | Useful volume, verify label quality |
| Text — current Indian | **Hand-collected** | Manual | Target 500–1,000 | See §12.3 |
| Video | FaceForensics++ (c23) | **Google form + manual approval, then a download script** | Tens of GB for a c23 subset; the full multi-compression release is far larger | Gold standard, research-only license |
| Video | Celeb-DF v2 | Agreement form | ~600 real / ~5,600 fake | Good, harder than FF++ |
| Video | DFDC | Licensed download | Full set is hundreds of GB — **use the preview subset** | Large, unwieldy |
| Audio | ASVspoof 2019 LA | Direct download | Tens of GB | Standard benchmark |

### 12.2 Timeline reality — act on this in the first hour

**FaceForensics++ and Celeb-DF require a form submission and human approval before you receive a download link.** That approval is not instant and is entirely outside our control. If the request goes in on day three, the flagship pillar has no data.

**Submit both dataset requests before writing a single line of code.** Meanwhile build the URL, email and text pillars, which need no gated data. If approval does not arrive in time, fall back to a pretrained Hugging Face deepfake checkpoint and be transparent that we validated rather than trained it.

Plan disk for tens of GB minimum, and download over a connection you trust. On typical hackathon wifi, a large dataset pull is itself a multi-hour risk.

### 12.3 Closing the Indian-language gap

The honest position: **there is no large, clean, current public corpus of Indian scam messages, and this is the single biggest data weakness in the project.** Existing sets are small, dated or not Indian.

Three-part mitigation:

1. **Hand-collect 500–1,000 current examples** from public sources: r/india and r/IndiaTech scam threads, X screenshots, Sanchar Saathi and TRAI complaint reports, published I4C advisories, and the team's own message histories. A few focused hours yields a usable fine-tuning set. Label for scam type, language and vector
2. **Augment with templated variation** — swap bank names, amounts, UPI handles and urgency phrasings across collected patterns to multiply the set without pretending it is organically larger
3. **The bot feedback loop is the long-term answer.** `SCAM`/`SAFE` replies (§5.2) generate exactly the labelled, current, in-distribution data nothing else provides. Say so in the pitch: the product's own usage is its data strategy

**Report the true size of the hand-collected set in the presentation.** A team that says "we labelled 800 real messages ourselves" is more credible than one implying it had tens of thousands.

### 12.4 Source reliability traps

- **Top-sites lists are not clean negatives.** Training benign-vs-phishing on Tranco-vs-PhishTank teaches the model to detect *popularity*, not safety. Include unpopular-but-legitimate sites (small business, government subdomains, regional sites) or accuracy figures will be inflated and the model will flag every obscure legitimate Indian site
- **PhishTank is community-reported**, so labels carry noise and a recency skew toward already-dead URLs
- **Nazario and Enron are old and American.** An email classifier trained solely on them will underperform on current Indian phishing. Weight header features, which age far better than vocabulary
- **FF++ is not WhatsApp.** Anything trained on it must be validated on recompressed video or the number is meaningless (§13.2)
- **Never train on data we do not have rights to**, and record provenance per source in the repo

## 13. Feasibility Assessment by Pillar

### 13.1 Summary

| Pillar | Buildable in the window | Real-world reliability | Role |
|---|---|---|---|
| URL / link | **Yes, comfortably** | High. Rules alone are strong | Load-bearing |
| Website characteristics | **Yes** | High. Mostly deterministic | Load-bearing |
| Email | **Yes** | High for headers, moderate for body | Load-bearing |
| Text / message | **Yes** | Good in English, weaker in Hinglish | Load-bearing |
| Voice note | **Yes, pretrained** | Moderate. Degrades on unseen synthesis | Supporting |
| **Deepfake video** | **Yes, to demo standard** | **Low in the wild** | Demo flagship, not load-bearing |

Four of six pillars are reliable and none of the four needs a GPU. This is the project's real technical foundation, and it is a stronger one than v2.0 implied.

### 13.2 Why video is the weak pillar

Three compounding, documented problems:

**Benchmarks do not survive reality.** Detectors with near-perfect benchmark AUC show [in-the-wild drops reported in the 45–50% range for state-of-the-art open-source models](https://arxiv.org/abs/2607.13234), framed there as structural: static detectors versus a moving generative frontier.

**FF++-trained models often learn the wrong thing** — [codec traces, compression level, background statistics, actor distribution and method-specific texture](https://arxiv.org/html/2606.00098) rather than manipulation itself.

**Our channel is the worst case.** Platform compression [launders precisely those cues](https://arxiv.org/abs/2508.08765). Every WhatsApp video has been aggressively re-encoded. **Our primary delivery channel systematically destroys the signal our flagship model needs.** Acknowledge this directly; most teams will not have noticed it.

### 13.3 Mitigations

1. **Foundation backbone, not Xception/MesoNet.** [CLIP ViT-L/14 with parameter-efficient fine-tuning reports competitive cross-dataset results](https://arxiv.org/abs/2503.19683), and [transformers lose less accuracy across datasets than CNNs](https://www.mdpi.com/2673-2688/7/2/68/htm). Frozen backbone plus probe is also the cheapest thing to train
2. **Train on WhatsApp-laundered data.** Push clips through actual WhatsApp or emulate the re-encode with ffmpeg. Directly targets the failure mode, and "we trained on WhatsApp-compressed video" is a specific, credible claim
3. **Prefer temporal cues** — [temporal artefacts reportedly generalise better and survive re-encoding](https://arxiv.org/pdf/2605.17573)
4. **Let it abstain** (§14.2)

*Sources in this section were rephrased for compliance with licensing restrictions.*

## 14. Fusion and Decision Policy

### 14.1 Score the message, not the file

Averaging a URL score and a video score for unrelated inputs produces a meaningless number. Fusion is only defensible across signals describing the **same artifact**. The unit is therefore the message: one WhatsApp message containing a video, a link and text yields one verdict fusing "this face shows manipulation artefacts" + "this domain is four days old" + "this text uses payment urgency."

This is also the mitigation for our weakest model. When the video score is uncertain but the domain is four days old and the text is coercive, the message is still flagged correctly. Defence in depth, where no single weak signal decides the outcome.

### 14.2 Only rules may raise a red alert — new in v3.0

This follows from taking false positives seriously, and it is the most consequential design decision in the document.

| Verdict | May be triggered by |
|---|---|
| **Red** | **Deterministic rule hits only** — APK link, blocklisted domain, password field over HTTP, form posting off-domain, DKIM/SPF failure plus display-name spoofing, brand homoglyph plus payment request. Near-100% precision signals |
| **Amber** | **Any model output**, any single soft signal, or model uncertainty. Never seizes the screen |
| **Green** | No signals above threshold |

A probabilistic model is not permitted to take over a frightened user's screen and tell her something is fraud. Models inform, rules interrupt. This costs some recall on red, and that trade is correct: amber plus "Ask family" still routes the user to safety, while a wrong red costs the install.

### 14.3 False positive budget

Concretely: a user receiving ~40 messages a day, with a handful from unknown senders. If red fires roughly weekly at 90% precision, she sees a wrong terrifying alert every ten weeks or so and the app survives. At 2 red alerts a day and 90% precision, she sees one every five days and the app is uninstalled inside a month.

**Target: red precision ≥98%, measured and reported. Amber may be noisy because amber does not interrupt.** This is why §14.2 exists.

### 14.4 Every alert quotes the message that triggered it (v3.1)

An alert that says "this is a fraud" without showing *what* is a fraud asks the user to take our word for it, and a warning the user cannot connect to a specific message is easy to dismiss as noise. So every verdict now carries the triggering text (`LocalVerdict.sourceText`), and it is shown back to the user in three places: the overlay (a boxed, quoted block under the reasons), the amber notification, and the "Ask family" forward. The quote is whitespace-collapsed and truncated to ~220 characters, and it is carried on the verdict object rather than passed alongside it, so what the user sees is provably the same text that was analysed — the two cannot drift.

This also strengthens the family-escalation loop (§9): the trusted contact receives the flagged message verbatim plus the verdict and reasons, so they can make the call the primary user could not.

Nothing about this weakens the privacy posture (§15.1): the quote is assembled and displayed entirely on-device and is never logged, consistent with the rule that message content stays on the phone.

## 15. Privacy, Policy and Compliance

### 15.1 Privacy posture

A judge will ask: *you built an app that reads all my WhatsApp messages?* Rehearse this.

- Text and URL analysis is **fully on-device**. Automatically scanned content never leaves the phone
- Media and website/email scans leave the device **only on explicit user action**
- **No message content persisted server-side.** Verdict logs hold hashes and feature vectors
- Notification access is a **visible, revocable** grant made in system settings with a plain-language explanation
- Family forwarding is **opt-in, one tap, one named recipient**
- The family dashboard (F47) is surveillance-adjacent and is consent-gated and disclosed at setup

### 15.2 Play Store policy risk

Honest assessment: reading every notification, requesting overlay permission, and requesting battery exemption is a combination that attracts review scrutiny. Notification access is not prohibited and legitimate apps use it, but expect friction and prepare a clear core-functionality justification. Sideloaded APKs are fine for the hackathon; Play distribution is a real, separate project.

### 15.3 Liability

A false green preceding a large loss is the nightmare scenario. Position the output as a **risk signal, not a certified forensic determination**, keep that language in the UI as well as the terms, and avoid accuracy claims in marketing copy. This constrains a paid consumer product more than a B2B2C one, where the partner carries the customer relationship.

## 16. Blockchain — Honest Framing

The theme is "Blockchain & Cybersecurity," but the problem statement does not mention blockchain, and forcing it into the detection path would make the system worse.

**The least-dishonest genuine use:** a tamper-evident evidence bundle. When a user is defrauded, they must file with I4C or a bank, and the value of their evidence depends on it being demonstrably unaltered. Hash the verdict record — content hashes, detector outputs, timestamp — into an append-only chain and anchor it periodically to a public testnet. That gives a victim's complaint a verifiable integrity claim without any central party being trusted.

**What we will say if asked:** a signed append-only database would achieve nearly the same thing with less complexity; the ledger adds value only when multiple mutually distrusting institutions (banks, telecoms, CERT-In) need to share threat indicators with provenance and no central authority. That is a real but *future* use, and we are not going to pretend the MVP needs it.

Implement it as F51 if there is spare time. It is roughly an hour of work and it is thematically expected. It is not load-bearing and we will not claim it is.

## 17. Risk Register

Ranked by expected damage.

| # | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| 1 | **Per-app notification field differences silently break extraction** | **Confirmed on-device** | **High — fails silently** | §5.8. WhatsApp uses `MessagingStyle` with no `bigText`; reading `EXTRA_TEXT` returned 34 of 129 chars and zero URLs, producing GREEN on a live scam. Fixed, and extraction source is now logged. **Every messaging app must be verified individually with a real inbound message** |
| 2 | Video detector fails on real WhatsApp content | High | High | §13.3. System designed to work without it (§7.7) |
| 3 | FF++/Celeb-DF approval arrives too late | Medium | High | Submit day zero (§12.2). Pretrained HF checkpoint as fallback |
| 4 | **OEM battery managers kill the foreground service** | **High** | **High** | Xiaomi, Oppo, Vivo and Realme are aggressive, and dominate our target segment. Request battery exemption (F43), ship per-OEM instructions, test on a real budget handset. **A Pixel cannot test this** — our listener survived six hours untouched on one, which is no evidence at all |
| 5 | Red-alert false positives erode trust | Medium | High | §14.2 rule-gating, §14.3 precision target |
| 5a | **Model false positives on legitimate content erode trust more slowly** | **Was confirmed; fixed** | Medium | The text model pushed real bank SMS and even bare bank URLs (axisbank.com, irctc.co.in) to AMBER — the UCI corpus ties URLs and bank-style promo text to spam. Fixed three ways (§11.5): high-precision thresholds only, protective-advice suppression, and never scoring a bare URL as prose. Amber does not interrupt, but a stream of unjustified ambers still trains the user to ignore us |
| 6 | Overlay/notification permissions not granted or revoked | Medium | High | F39 guided flow, F41 self-test to verify grants took effect |
| 7 | Replayed notification history causes alert bursts | **Confirmed on-device** | High | Content fingerprints retained 24h plus an 8s cold-start warm-up. Measured: Google Messages re-posts sibling conversation notifications with refreshed timestamps, so an age check alone is insufficient |
| 8 | Sensitive-notification redaction on untested OEMs/versions | Low–Medium | High if hit | §5.7. Does **not** occur on Pixel 7 / Android 17. Samsung and Chinese OEM builds unverified. `appops` escape hatch documented if encountered |
| 9 | Alert unusable in landscape | **Was confirmed on-device** | High | Fixed. A fixed 180dp top inset is 472px at 420dpi, which on a 1080px-tall landscape screen pushed the reasons and all three buttons off the bottom — a full-screen warning that could be neither read nor dismissed. Orientation-specific dimens plus a `ScrollView` |
| 10 | Hinglish accuracy disappoints | High | Medium | §12.3, and set expectations at 75–85% |
| 11 | Scammers shift to image-only text | High | Medium | F4 OCR |
| 12 | Notification text truncated or bundled | High | Medium | Degrade gracefully, never guess (§5.6) |
| 13 | Incumbents make us redundant | High | Medium (hackathon) / High (product) | §3.2 positioning on unserved space |
| 14 | Web checker abused as SSRF/upload vector | Medium | Medium | §5.3 sandboxing and rate limits |
| 15 | On-device model too heavy for target hardware | Medium | Medium | §11.2 tiering |
| 16 | Team lacks Kotlin experience | Unknown | High | **Surface on day one.** The alternative is losing the passive path, which is the whole thesis |

## 18. Success Metrics

| Metric | Target | Confidence |
|---|---|---|
| URL classifier accuracy | 90%+ | High |
| Website-characteristics rule precision | 95%+ | High — mostly deterministic |
| Email header-forensics precision | 95%+ | High |
| Text classifier, English | 90%+ | High |
| Text classifier, Hinglish | 75–85% | Medium, data-limited |
| Video detector, in-distribution | 80–90% | High |
| Video detector, cross-dataset | 60–75% AUC | **Low — state openly** |
| Video detector, WhatsApp-recompressed | **Measure and report honestly** | Unknown until tested. This is the number that matters |
| Voice-note detector, in-distribution | 85%+ | Medium |
| **Red-alert precision** | **≥98%** | The metric that decides whether the product survives |
| Notification-to-verdict latency, text path | <500ms on-device | High |
| End-to-end with media | <10s | High |

**Product acceptance:** passive interception fires unprompted on a live message; a judge operates it with no explanation; the spoken Hindi verdict is intelligible to a native speaker seeing it for the first time; "Ask family" reaches a second device in under 5 seconds; the team can explain why models are not allowed to raise red alerts.

## 19. Known Limitations

State these before a judge finds them.

- **Passive scanning covers text only.** Media checks require a user tap. This is an Android platform limit (§5.6), not a design choice
- **Video deepfake detection is our weakest pillar and our own channel makes it harder.** We mitigate and measure; we do not claim it is solved
- **Cross-dataset generalisation is structural.** Any accuracy figure is dataset-specific and we will name the dataset
- **Hinglish is data-limited.** Our fine-tuning set is small and hand-collected, and we will report its true size
- **Live call analysis is impossible on stock Android.** Voice coverage means voice notes, not calls in progress
- **Zero-day phishing domains** resembling nothing in training data will slip through. Blocklist plus heuristics is mitigation, not solution
- **Notification access is a broad permission** and some users will reasonably decline
- **Training data is research-licensed**, so this prototype cannot be commercialised as-is (§11.4)
- **Most Indian fraud is not AI-generated at all** — it is a human being talking persuasively on a phone. We cover digital-artifact vectors; against pure voice social engineering, "Ask family" is the only defence we offer, and we should say so plainly
- **This is a prototype risk signal, not a certified forensic tool**

## 20. Build Timeline

| Phase | Focus |
|---|---|
| **Phase 0 (first hours)** | **Submit FF++ and Celeb-DF access requests.** Prove the notification listener works end-to-end with real WhatsApp messages on a real budget handset. Confirm overlay permission produces a genuine screen takeover. **If either spike fails, the thesis changes and we need to know immediately** |
| **Phase 1** | Rule engine, URL pillar, email header forensics, website analyser, text classifier. Web checker wired. **This alone satisfies 10 of 12 PS clauses** |
| **Phase 2** | Android app: passive path, share sheet, OCR, three-state verdict, TTS in EN/HI/TA, hand-authored templates, "Ask family", guided setup, self-test |
| **Phase 3** | Fusion with rule-gated red, explainability (heatmaps, phrase highlighting, named flags), video detector behind the API, compression-augmented retraining |
| **Phase 4** | Voice notes, WhatsApp bot, stretch goals. Only if the core is stable |
| **Phase 5** | Demo rehearsal on the actual device and network. Measure red-alert precision. Prepare limitations Q&A |

**Sequencing logic:** Phase 1 front-loads everything reliable and GPU-free. If the schedule slips, we still have a compliant, demonstrable product. Had the video model been Phase 1 and underperformed, we would have nothing.

## 21. Team & Roles

| Role | Owner | Covers |
|---|---|---|
| Android app | | Kotlin, Compose, notification listener, overlay, TTS, OCR, permission flow |
| ML — text + URL | | Rules, XGBoost, MuRIL fine-tune, on-device export |
| ML — video + audio | | CLIP probe, compression augmentation, AASIST inference |
| Backend — email, website, fusion | | FastAPI, header forensics, headless fetch, decision policy |
| Data | | Dataset requests, hand-collection, labelling, provenance tracking |
| Language + UX authoring | | Hindi/Tamil templates, icon set, accessibility |
| Pitch | | Demo script, competitive and limitations Q&A |

Two roles are commonly underestimated and are on the critical path: **data** (§12.3 is manual labour nobody volunteers for) and **language authoring** (§8.4 cannot be machine-translated).

## 22. Deferred — Needs a Human, or Needs Hardware

Tracked here so nothing that cannot be coded away gets quietly forgotten. Ordered by how badly the demo suffers if it is still open on the day.

| # | Item | Blocked on | Why it matters |
|---|---|---|---|
| 1 | **Hindi and Tamil string review** | A native speaker for each. Cannot be done by us or by machine translation | Every user-facing string in `values-hi` and `values-ta`, plus the backend `explain.py` templates, is a first draft. Two script-mixing bugs have already been caught (Devanagari fragments inside Tamil sentences) and there is no reason to think those were the last. §8.4 forbids machine translation, so this is genuinely a human task and it sits on the demo's critical path: the spoken verdict is the product's single highest-impact feature and a native speaker in the room will hear a bad register immediately |
| 2 | ~~Redaction on retail hardware~~ **RESOLVED** | — | Answered on a Pixel 7 / Android 17: no redaction, full WhatsApp content reaches the listener, appop never consulted. See §5.7. Remaining gap is Samsung and Chinese OEM builds, now tracked as risk #8 rather than a blocker |
| 3 | **Per-app notification-style verification** | An inbound real message in each app | §5.8. WhatsApp is verified. **Telegram, Instagram, Signal and Facebook Messenger are not**, and each uses its own notification style. This needs a real message from a second person per app; nothing else reproduces it |
| 4 | **OEM battery-killing behaviour** | A Xiaomi, Oppo, Vivo or Realme handset | Risk #4. A Pixel **cannot** test this — Pixels are the least aggressive Android builds in existence, so surviving six hours on one is not evidence. Unverified until budget hardware is available, and the PRD should not claim otherwise |
| 5 | **FaceForensics++ / Celeb-DF access** | Manual approval by the dataset maintainers, days of latency, entirely outside our control | §12.2. The request costs five minutes and gates the whole flagship pillar. Submit it before anything else, because no amount of engineering shortens the queue |
| 6 | **TTS audio verified audibly** | Any device with a speaker | Wired and running, but a headless emulator produces no sound, so "the Hindi voice actually says the right thing intelligibly" is currently unverified. The Pixel is now available for this |
| 7 | **Real Indian scam corpus** | Manual collection and labelling, 500–1,000 messages | §12.3. Nobody volunteers for this and it is the project's scarcest input. The WhatsApp bot's SCAM/SAFE loop turns it into a pipeline, but the initial set has to be gathered by hand |

---

## Appendix A: Pitch and Demo

**Opening hook:**
*"In 2025, Indians lost close to ₹22,500 crore to cyber fraud — complaints up 24% to about 2.8 million cases. Nearly half of Indian adults have already been targeted by an AI voice-cloning or deepfake scam, almost double the global rate. A Bengaluru chartered accountant lost ₹23 lakh to a deepfake. A Pune investor was fooled by a fake video of Narayana and Sudha Murthy. Faking a face or a voice now takes seconds and costs nothing. Catching it still takes a human noticing something feels off. We built the thing that notices instead."*

**The beat that separates us:**
*"Every tool that exists waits to be asked. Copy the link, open the app, paste it. But think about who actually loses the money — if she already knew to check, she wouldn't have been a victim. So we stopped building something that answers questions and built something that interrupts. And then it explains why, so that next time she doesn't need us."*

**If asked about Truecaller — answer it head-on, do not dodge:**
*"Truecaller owns calls and SMS, and we're not going to pretend otherwise — we deliberately don't compete there. What nobody does is tell you whether the video your cousin forwarded is synthetic, on WhatsApp, in Tamil, out loud, with the evidence shown. That's the gap."*

**Backup stats:** phishing was 22% of CERT-In-handled Indian cyber incidents in 2025; deepfake images in India projected near 8 million in 2025, up roughly 900% year-on-year (I4C / industry estimates); 83% of Indian AI-voice-scam victims lost money, nearly half over ₹50,000.

### Demo script — 90 seconds, revised for §5.6

1. **Phone mirrored to the projector.** App installed, nothing open, silence
2. **An SMS or WhatsApp message arrives** with a typosquatted `sbi-rewards.xyz` link and urgency text. Nobody touches the phone
3. **The phone takes over its own screen.** Red, stop icon, and a Hindi voice: *this is fake, do not send money.* This is the moment no other team will have
4. **The alert notes the message also contains a video.** One tap sends it for checking — and this is where we explain, in one sentence, that passive media capture is an Android limitation rather than an oversight. Owning a constraint reads as competence
5. **Verdict on the video, with the face heatmap.** Alongside it: domain registered four days ago, urgency phrase highlighted. The credibility moment
6. **Tap "Ask family."** A second phone on the table lights up with the evidence
7. **Then switch to the web checker** and paste a real phishing email. Show SPF failure, `Reply-To` mismatch, display-name spoofing. *This is the PS's email and website clauses, demonstrated live*
8. **Hand a judge a phone** and let them forward anything they like to the bot

**Close:** return to the opening story, then one line on deployability — notification listener plus WhatsApp bot means no new user behaviour, and the person who installs it need not be the person it protects.

## Appendix B: References

**Datasets**
- PhishTank — phishtank.org · OpenPhish — openphish.com
- UCI Phishing Websites — archive.ics.uci.edu
- Tranco top-sites list — tranco-list.eu
- Nazario Phishing Corpus — monkey.org/~jose/phishing · Enron corpus — cs.cmu.edu/~enron
- [FaceForensics++ (access form + research-only terms)](https://github.com/ondyari/FaceForensics/blob/master/dataset/README.md) · [FF++ terms of service](https://kaldir.vc.in.tum.de/faceforensics/webpage/FaceForensics_TOS.pdf)
- Celeb-DF, DFDC — ai.meta.com/datasets/dfdc · ASVspoof — asvspoof.org
- [Hindi/English crowdsourced SMS spam](https://github.com/princebari/-SMS-Spam-Classification-on-Indian-Dataset-A-Crowdsourced-Collection-of-Hindi-and-English-Messages) · [SpamShield multilingual corpus](https://huggingface.co/datasets/M-Arjun/SpamShield-Datasets)

**Models**
- [MuRIL base (Apache 2.0)](https://huggingface.co/google/muril-base-cased) · [HingBERT / L3Cube-HingCorpus](https://huggingface.co/papers/2204.08398)
- [AASIST official implementation and checkpoints](https://github.com/clovaai/aasist) · [AASIST2 short-utterance](https://arxiv.org/html/2309.08279)
- [CLIP for generalizable deepfake detection](https://arxiv.org/abs/2503.19683)
- [HingBERT/HingRoBERTa on Indian cybercrime text](https://arxiv.org/html/2412.16614v1)

**Feasibility evidence**
- [In-the-wild AUC collapse in open-source detectors](https://arxiv.org/abs/2607.13234)
- [What FF++-trained models actually learn](https://arxiv.org/html/2606.00098)
- [Social-network compression launders forensic cues](https://arxiv.org/abs/2508.08765)
- [Temporal artefacts survive re-encoding](https://arxiv.org/pdf/2605.17573)
- [Transformer vs CNN cross-dataset generalisation](https://www.mdpi.com/2673-2688/7/2/68/htm)
- [Open weights do not imply commercial rights](https://quasa.io/media/open-weight-does-not-mean-safe-for-commercial-use-check-the-license-chain)

**Platform and policy**
- [Full-screen intent restrictions, Android 14+](https://source.android.com/docs/core/permissions/fsi-limits) · [FSI behaviour in practice](https://proandroiddev.com/full-screen-intent-fsi-notifications-in-android-14-15-what-changed-why-its-breaking-and-e5e862a75936)
- [MANAGE_EXTERNAL_STORAGE eligibility limits](https://stackoverflow.com/questions/79723799/cant-access-whatsapp-status-folder-using-saf-or-mediastore-without-manage-exter) · [WhatsApp scoped-storage media paths](https://stackoverflow.com/questions/67129484/how-can-i-access-whatsapp-media-directory-in-android-11-scoped-storage)
- [Play policy on SMS/Call Log permissions](https://support.google.com/googleplay/android-developer/answer/10208820) · [Call recording restrictions](https://www.theverge.com/2022/4/21/23036078/google-android-call-recording-apps-accessibility-loopholes-play-store-rules)
- [CallScreeningService](https://developer.android.com/develop/connectivity/telecom/dialer-app/screen-calls)

**Competitive landscape**
- [Truecaller AI SMS fraud protection](https://corporate.truecaller.com/newsroom/press-release/28923657E2813595) · [Truecaller family fraud alerts](https://techcrunch.com/?p=3101896) · [Truecaller fraud insurance](https://www.truecaller.com/blog/news/truecaller-fraud-insurance)
- [Android on-device scam detection](https://security.googleblog.com/2024/11/new-real-time-protections-on-Android.html) · [Android scam protection, Feb 2026](https://security.googleblog.com/2026/02/strengthening-android-lead-in-scam-protection.html?hl=en_GB) · [Google Messages spam detection privacy](https://support.google.com/messages/answer/9327903)

*Content from external sources in this document was rephrased for compliance with licensing restrictions.*

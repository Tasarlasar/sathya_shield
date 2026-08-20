"""Text pillar: scam-intent detection over message and email body text.

PRD v3.0 sections 6.4, 7.2 (F16).

This is the deterministic keyword-and-pattern tier that runs on-device per
section 11.2. It is intentionally the *cheap* tier: a few milliseconds, a few
kilobytes, no network, no transformer. The MuRIL/HingBERT model is a separate
non-deterministic detector that will feed in later via `attach_model_score`.

Severity discipline matters more here than anywhere else. Language on its own is
weak evidence: a genuine bank SMS also contains the words "OTP" and "account".
So single-category hits are scored LOW or MEDIUM, and only specific
*combinations* that describe a known fraud script reach HIGH. Nothing in this
module returns CRITICAL, because no phrase alone justifies taking over a
frightened user's screen.

Vocabulary is hand-authored per language, including Roman-script Hinglish, per
section 8.4. It is deliberately not machine-translated.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from ..schemas import Pillar, Severity, Signal


class Category(str, Enum):
    URGENCY = "urgency"
    PAYMENT = "payment"
    CREDENTIAL = "credential"
    AUTHORITY = "authority"
    PRIZE = "prize"
    KYC = "kyc"
    JOB = "job"
    THREAT = "threat"


# Hand-authored vocabulary. Devanagari, Tamil and Roman-script Hinglish are
# included because Indian scam messages routinely mix scripts within one SMS.
LEXICON: dict[Category, tuple[str, ...]] = {
    Category.URGENCY: (
        "urgent", "urgently", "immediately", "immediate action", "right now",
        "within 24 hours", "within 2 hours", "last warning", "final notice",
        "expires today", "expiring today", "expire soon", "act now", "hurry",
        "time is running out", "before midnight",
        "turant", "abhi", "jaldi", "aaj hi", "antim chetavni",
        "तुरंत", "अभी", "जल्दी", "आज ही", "अंतिम चेतावनी",
        "உடனே", "இப்போதே", "அவசரம்",
    ),
    Category.PAYMENT: (
        "send money", "transfer money", "transfer the amount", "pay now",
        "make payment", "deposit", "processing fee", "registration fee",
        "clearance fee", "customs duty", "penalty", "fine", "outstanding dues",
        "pay immediately", "scan the qr", "scan qr", "upi id", "google pay",
        "phonepe", "paytm number",
        "paise bhejo", "paisa bhej", "rupay bhejo", "bhugtan karein",
        "पैसे भेजो", "पैसा भेज", "भुगतान करें", "शुल्क",
        "பணம் அனுப்ப", "கட்டணம்",
    ),
    Category.CREDENTIAL: (
        "otp", "one time password", "pin number", "atm pin", "cvv",
        "card number", "netbanking password", "login password", "user id and password",
        "aadhaar number", "pan number", "account number and ifsc",
        "otp bhejo", "otp batao", "pin batao",
        "ओटीपी", "पिन", "पासवर्ड", "आधार नंबर",
        "ஓடிபி", "கடவுச்சொல்",
    ),
    Category.AUTHORITY: (
        "police", "cbi", "central bureau", "customs department", "narcotics",
        "income tax department", "enforcement directorate", "cyber cell",
        "cyber crime branch", "court notice", "arrest warrant", "warrant",
        "fir has been", "legal notice", "trai", "department of telecom",
        "supreme court", "high court", "government of india",
        "police station", "adalat", "giraftari",
        "पुलिस", "गिरफ्तारी", "अदालत", "वारंट", "आयकर विभाग",
        "காவல்", "நீதிமன்றம்",
    ),
    Category.PRIZE: (
        "you have won", "you won", "congratulations you", "lucky winner",
        "lottery", "jackpot", "prize money", "lucky draw", "selected winner",
        "claim your prize", "claim your reward", "cashback offer", "free gift",
        "kaun banega", "inaam jeeta", "lottery jeet",
        "बधाई हो", "इनाम", "लॉटरी", "जीत",
        "வாழ்த்துகள்", "பரிசு",
    ),
    Category.KYC: (
        "kyc", "re-kyc", "complete your kyc", "kyc pending", "kyc expired",
        "update your details", "verify your account", "re-verify",
        "account will be blocked", "account has been suspended",
        "account will be closed", "reactivate your account",
        "unblock your account", "link your aadhaar", "sim will be blocked",
        "खाता बंद", "सत्यापन", "केवाईसी",
        "கணக்கு முடக்கம்",
    ),
    Category.JOB: (
        "work from home", "part time job", "earn daily", "earn per day",
        "daily income", "easy money", "no experience needed", "join now and earn",
        "task based earning", "telegram task",
        "ghar baithe kamao", "roz kamao",
        "घर बैठे कमाओ", "रोज कमाई",
    ),
    Category.THREAT: (
        "legal action will", "legal action against", "you will be arrested",
        "arrest you", "case has been registered", "case registered against",
        "your number will be", "service will be terminated",
        "will be blocked", "will be suspended", "non-bailable",
        "kanooni karyavahi", "band kar diya jayega",
        "कानूनी कार्रवाई", "गिरफ्तार", "बंद कर दिया जाएगा",
        "சட்ட நடவடிக்கை",
    ),
}

# An explicit request to hand over a secret. Legitimate senders never do this.
_CREDENTIAL_REQUEST_RE = re.compile(
    r"(share|send|sent|give|tell|forward|provide|submit|enter|confirm)"
    r"(?:\s+(?:me|us|your|the|this|that|it))*"
    r"\s+(otp|o\.t\.p|one[\s-]?time[\s-]?password|pin|cvv|password)",
    re.IGNORECASE,
)

# Negation window: banks legitimately say "never share your OTP".
_NEGATION_RE = re.compile(
    r"\b(never|not|dont|don't|do not|do'nt|avoid|no need to|kabhi nahi|mat|nahi)\b",
    re.IGNORECASE,
)

_NEGATION_WINDOW = 45

# A negated instruction to share, with no requirement that a credential word
# follow directly. Catches "Do not share it with anyone", where the secret is
# referred to by pronoun and the earlier mention of "OTP" would otherwise be
# counted as evidence against a legitimate bank message.
_PROTECTIVE_ADVICE_RE = re.compile(
    r"\b(never|do\s*not|do\s*n't|dont|don't|avoid|kabhi\s+nahi|kisi\s+ko\s+mat|mat)\s+"
    r"(share|shares|sharing|disclose|reveal|give|tell|forward|send|bataye|batao)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class CategoryHit:
    category: Category
    terms: tuple[str, ...]


def _normalise(text: str) -> str:
    """Lowercase and collapse whitespace, preserving non-Latin scripts."""
    return re.sub(r"\s+", " ", (text or "").lower()).strip()


def find_categories(text: str) -> list[CategoryHit]:
    """Which scam-script categories appear in this text."""
    normalised = _normalise(text)
    if not normalised:
        return []
    hits: list[CategoryHit] = []
    for category, terms in LEXICON.items():
        matched = tuple(term for term in terms if term in normalised)
        if matched:
            hits.append(CategoryHit(category=category, terms=matched[:4]))
    return hits


def has_protective_credential_advice(text: str) -> bool:
    """True when the text *warns against* sharing a secret.

    "Never share your OTP or PIN" is the opposite of a scam: it is what real
    banks put in every transaction SMS. Treating the mere presence of the word
    OTP as evidence therefore penalises legitimate messages, which is how a real
    HDFC alert ended up AMBER once the classifiers were wired in.

    Distinct from the negation check inside `_is_credential_request`: that one
    suppresses a strong signal, this one suppresses the weak residue signal and
    is a mild indicator of legitimacy.
    """
    if not text:
        return False

    # "Do not share it with anyone" - pronoun reference, no credential word.
    if _PROTECTIVE_ADVICE_RE.search(text):
        return True

    # "Never share your OTP" - credential word present and negated.
    for match in _CREDENTIAL_REQUEST_RE.finditer(text):
        window_start = max(0, match.start() - _NEGATION_WINDOW)
        if _NEGATION_RE.search(text[window_start : match.start()]):
            return True
    return False


def _is_credential_request(text: str) -> tuple[bool, str]:
    """Detect a genuine request for a secret, excluding safety warnings.

    Distinguishing "share the OTP" from "never share your OTP" is the whole
    game here. Without the negation check this rule would fire on every
    legitimate bank message, which is precisely the false-positive pattern
    section 14.3 warns about.
    """
    for match in _CREDENTIAL_REQUEST_RE.finditer(text or ""):
        window_start = max(0, match.start() - _NEGATION_WINDOW)
        preceding = text[window_start : match.start()]
        if _NEGATION_RE.search(preceding):
            continue
        return True, match.group(0)[:60]
    return False, ""


def analyse_text(text: str, sender_known: bool = False) -> list[Signal]:
    """Evaluate message or email body text for scam intent.

    All signals are deterministic keyword or pattern matches. None is CRITICAL:
    text alone never authorises a red alert.
    """
    signals: list[Signal] = []
    if not text or not text.strip():
        return signals

    hits = find_categories(text)
    present = {hit.category for hit in hits}
    terms_by_category = {hit.category: hit.terms for hit in hits}

    # --- Explicit request for a secret -----------------------------------
    is_request, phrase = _is_credential_request(text)
    if is_request:
        signals.append(
            Signal(
                code="TEXT_CREDENTIAL_REQUEST",
                pillar=Pillar.TEXT,
                severity=Severity.HIGH,
                deterministic=True,
                weight=1.3,
                detail={"phrase": phrase},
            )
        )

    # --- Digital arrest script -------------------------------------------
    # Fake police/CBI/customs officer + threat of arrest + demand for money.
    # Highly specific to a known and currently high-value Indian fraud.
    if Category.AUTHORITY in present and (
        Category.THREAT in present or Category.PAYMENT in present
    ):
        severity = (
            Severity.HIGH
            if Category.THREAT in present and Category.PAYMENT in present
            else Severity.MEDIUM
        )
        signals.append(
            Signal(
                code="TEXT_DIGITAL_ARREST_PATTERN",
                pillar=Pillar.TEXT,
                severity=severity,
                deterministic=True,
                weight=1.3,
                detail={
                    "authority": ",".join(terms_by_category.get(Category.AUTHORITY, ())[:2]),
                    "has_threat": Category.THREAT in present,
                    "has_payment": Category.PAYMENT in present,
                },
            )
        )

    # --- Advance-fee fraud: pay to collect a prize -----------------------
    if Category.PRIZE in present and Category.PAYMENT in present:
        signals.append(
            Signal(
                code="TEXT_ADVANCE_FEE_PATTERN",
                pillar=Pillar.TEXT,
                severity=Severity.HIGH,
                deterministic=True,
                weight=1.2,
                detail={
                    "prize": ",".join(terms_by_category.get(Category.PRIZE, ())[:2]),
                },
            )
        )

    # --- Urgency applied to a money or credential ask --------------------
    if Category.URGENCY in present and (
        Category.PAYMENT in present or Category.CREDENTIAL in present
    ):
        signals.append(
            Signal(
                code="TEXT_URGENT_MONEY_REQUEST",
                pillar=Pillar.TEXT,
                severity=Severity.MEDIUM,
                deterministic=True,
                weight=1.1,
                detail={
                    "urgency": ",".join(terms_by_category.get(Category.URGENCY, ())[:2]),
                },
            )
        )

    # --- Account-blocking pressure ---------------------------------------
    if Category.KYC in present and (
        Category.URGENCY in present or Category.THREAT in present
    ):
        signals.append(
            Signal(
                code="TEXT_KYC_PRESSURE",
                pillar=Pillar.TEXT,
                severity=Severity.MEDIUM,
                deterministic=True,
                weight=1.1,
                detail={"kyc": ",".join(terms_by_category.get(Category.KYC, ())[:2])},
            )
        )

    # --- Job-bait -------------------------------------------------------
    if Category.JOB in present and (
        Category.PAYMENT in present or Category.URGENCY in present
    ):
        signals.append(
            Signal(
                code="TEXT_JOB_BAIT",
                pillar=Pillar.TEXT,
                severity=Severity.MEDIUM,
                deterministic=True,
                detail={"job": ",".join(terms_by_category.get(Category.JOB, ())[:2])},
            )
        )

    # --- Weak single-category residue ------------------------------------
    # Reported so the drill-down view can show everything that was noticed,
    # but scored LOW so it cannot meaningfully move the band on its own.
    if not signals:
        protective = has_protective_credential_advice(text)
        for hit in hits:
            if hit.category not in (
                Category.PAYMENT,
                Category.CREDENTIAL,
                Category.KYC,
            ):
                continue
            # A message telling the user *not* to share their OTP is evidence of
            # legitimacy, not of fraud. Emitting a residue signal here is what
            # made genuine bank alerts reach AMBER.
            if hit.category is Category.CREDENTIAL and protective:
                continue
            signals.append(
                Signal(
                    code=f"TEXT_MENTIONS_{hit.category.value.upper()}",
                    pillar=Pillar.TEXT,
                    severity=Severity.LOW,
                    deterministic=True,
                    weight=0.6,
                    detail={"terms": ",".join(hit.terms[:3])},
                )
            )

    # --- Unknown sender amplifier ----------------------------------------
    # Not a finding in itself; raises the weight of everything else.
    if signals and not sender_known:
        signals.append(
            Signal(
                code="SENDER_UNKNOWN",
                pillar=Pillar.SENDER,
                severity=Severity.LOW,
                deterministic=True,
                weight=0.8,
                detail={},
            )
        )

    return signals


def attach_model_score(probability: float, model_name: str = "muril-scam-v0") -> Signal:
    """Wrap a text-classifier probability as a NON-deterministic signal.

    Kept separate from `analyse_text` so the boundary is impossible to blur.
    Because `deterministic=False`, this signal can raise a verdict to AMBER but
    can never reach RED, no matter how confident the model is. That is the
    section 14.2 guarantee.
    """
    # Thresholds are deliberately conservative. The classifier's in-distribution
    # English precision is excellent, but it scores a genuine HDFC transaction
    # SMS at 0.75 — bank messages look like promotional spam to a model trained
    # on UCI SMS data. Treating 0.6 as meaningful therefore flags real bank
    # traffic, which section 14.3 identifies as the fastest route to being
    # uninstalled.
    probability = max(0.0, min(1.0, probability))
    if probability >= 0.95:
        severity = Severity.HIGH
    elif probability >= 0.85:
        severity = Severity.MEDIUM
    else:
        severity = Severity.LOW
    return Signal(
        code="TEXT_MODEL_SCAM_SCORE",
        pillar=Pillar.TEXT,
        severity=severity,
        deterministic=False,
        weight=1.0,
        detail={"probability": round(probability, 4), "model": model_name},
    )

"""Plain-language explanation layer.

PRD v3.0 sections 7.4 (F29, F32), 8.2-8.4.

Three rules govern every string in this file.

1. **Instruct, do not describe** (section 8.3). The user gets told what to DO.
   "Do not send money", never "deepfake likelihood 0.87".

2. **No jargon** (section 8.4). The words phishing, deepfake, URL, malicious,
   vishing, credential, authenticate and verify are banned from user-facing
   output. We say trap link, fake video, fake voice, money fraud.

3. **Authored, not translated** (section 8.4). Each language is written
   separately in colloquial spoken register. Machine-translating
   "phishing detected with 87% confidence" into Hindi produces something less
   comprehensible than the English, not more. `check_coverage()` exists so a
   missing translation is caught by the test suite rather than silently falling
   back to English in front of a user.

TRANSLATION STATUS: the Hindi and Tamil strings below are first-draft and need
review by a native speaker before any demo. Section 21 flags language authoring
as a critical-path role for exactly this reason.
"""

from __future__ import annotations

from .schemas import Band, Explanation, Language, Signal

# --------------------------------------------------------------------------
# Band-level headline and action
# --------------------------------------------------------------------------

_HEADLINES: dict[Band, dict[Language, str]] = {
    Band.RED: {
        Language.EN: "This is a fraud",
        Language.HI: "यह धोखा है",
        Language.TA: "இது மோசடி",
    },
    Band.AMBER: {
        Language.EN: "Be careful with this",
        Language.HI: "इससे सावधान रहें",
        Language.TA: "இதில் கவனமாக இருங்கள்",
    },
    Band.GREEN: {
        Language.EN: "Nothing wrong found",
        Language.HI: "कुछ गलत नहीं मिला",
        Language.TA: "தவறு எதுவும் இல்லை",
    },
}

_ACTIONS: dict[Band, dict[Language, str]] = {
    Band.RED: {
        Language.EN: "Do not send money. Do not open the link. Do not share any number.",
        Language.HI: "पैसे मत भेजिए। लिंक मत खोलिए। कोई नंबर मत बताइए।",
        Language.TA: "பணம் அனுப்ப வேண்டாம். இணைப்பைத் திறக்க வேண்டாம். எந்த எண்ணையும் சொல்ல வேண்டாம்.",
    },
    Band.AMBER: {
        Language.EN: "Do not do anything yet. Show this to your family first.",
        Language.HI: "अभी कुछ मत कीजिए। पहले यह अपने परिवार को दिखाइए।",
        Language.TA: "இப்போது எதுவும் செய்ய வேண்டாம். முதலில் இதை உங்கள் குடும்பத்தில் காட்டுங்கள்.",
    },
    Band.GREEN: {
        Language.EN: "This looks alright. Stay careful with money requests.",
        Language.HI: "यह ठीक लगता है। पैसे मांगने वालों से सावधान रहिए।",
        Language.TA: "இது சரியாகத் தெரிகிறது. பணம் கேட்பவர்களிடம் கவனமாக இருங்கள்.",
    },
}

# --------------------------------------------------------------------------
# Per-signal reasons
# --------------------------------------------------------------------------
# Placeholders in braces are filled from Signal.detail. Missing keys degrade to
# a neutral word rather than raising.

_REASONS: dict[str, dict[Language, str]] = {
    # --- URL ---------------------------------------------------------------
    "URL_APK_DOWNLOAD": {
        Language.EN: "This link puts a new app on your phone. Banks never send app links.",
        Language.HI: "यह लिंक आपके फ़ोन में नया ऐप डालता है। बैंक कभी ऐप का लिंक नहीं भेजता।",
        Language.TA: "இந்த இணைப்பு உங்கள் தொலைபேசியில் புதிய செயலியை நிறுவும். வங்கிகள் செயலி இணைப்பு அனுப்புவதில்லை.",
    },
    "URL_USERINFO_OBFUSCATION": {
        Language.EN: "The link looks like a bank name but actually goes somewhere else.",
        Language.HI: "लिंक में बैंक का नाम दिखता है, लेकिन वह कहीं और ले जाता है।",
        Language.TA: "இணைப்பில் வங்கிப் பெயர் தெரிகிறது, ஆனால் அது வேறு இடத்திற்குச் செல்கிறது.",
    },
    "URL_IP_HOST": {
        Language.EN: "This link has numbers instead of a website name. Real banks do not do this.",
        Language.HI: "इस लिंक में वेबसाइट के नाम की जगह नंबर हैं। सच्चे बैंक ऐसा नहीं करते।",
        Language.TA: "இந்த இணைப்பில் இணையதள பெயருக்குப் பதிலாக எண்கள் உள்ளன. உண்மையான வங்கிகள் இப்படிச் செய்வதில்லை.",
    },
    "URL_PUNYCODE_HOST": {
        Language.EN: "The website name uses look-alike letters to copy a real name.",
        Language.HI: "वेबसाइट के नाम में मिलते-जुलते अक्षर हैं, जो असली नाम की नकल करते हैं।",
        Language.TA: "இணையதள பெயரில் ஒத்த எழுத்துகள் உள்ளன, உண்மையான பெயரைப் போலியாகக் காட்ட.",
    },
    "URL_BRAND_LOOKALIKE": {
        Language.EN: "This website pretends to be {brand} but it is not. The real one is different.",
        Language.HI: "यह वेबसाइट {brand} होने का नाटक करती है, पर है नहीं। असली वेबसाइट अलग है।",
        Language.TA: "இந்த இணையதளம் {brand} போல் நடிக்கிறது, ஆனால் அது இல்லை. உண்மையானது வேறு.",
    },
    "URL_SHORTENER": {
        Language.EN: "This is a short link. You cannot see where it really goes.",
        Language.HI: "यह छोटा लिंक है। यह असल में कहाँ जाता है, दिखता नहीं।",
        Language.TA: "இது சுருக்கிய இணைப்பு. இது உண்மையில் எங்கு செல்கிறது எனத் தெரியாது.",
    },
    "URL_RISKY_TLD": {
        Language.EN: "This kind of website address is often used for cheating.",
        Language.HI: "इस तरह के वेबसाइट पते अक्सर ठगी में इस्तेमाल होते हैं।",
        Language.TA: "இந்த வகை இணையதள முகவரி பெரும்பாலும் ஏமாற்றுவதற்குப் பயன்படுகிறது.",
    },
    "URL_CREDENTIAL_PATH": {
        Language.EN: "This page will ask for your password or number.",
        Language.HI: "यह पेज आपका पासवर्ड या नंबर मांगेगा।",
        Language.TA: "இந்தப் பக்கம் உங்கள் கடவுச்சொல் அல்லது எண்ணைக் கேட்கும்.",
    },
    "URL_DEEP_SUBDOMAIN": {
        Language.EN: "The website name is made unnecessarily long to confuse you.",
        Language.HI: "वेबसाइट का नाम जानबूझकर लंबा किया गया है, ताकि आप उलझ जाएँ।",
        Language.TA: "இணையதள பெயர் உங்களைக் குழப்ப வேண்டுமென்றே நீளமாக்கப்பட்டுள்ளது.",
    },
    "URL_NO_TLS": {
        Language.EN: "This website is not secure.",
        Language.HI: "यह वेबसाइट सुरक्षित नहीं है।",
        Language.TA: "இந்த இணையதளம் பாதுகாப்பானது அல்ல.",
    },
    "URL_UNPARSEABLE": {
        Language.EN: "This link is broken or hidden in a strange way.",
        Language.HI: "यह लिंक टूटा है या किसी अजीब तरीके से छिपाया गया है।",
        Language.TA: "இந்த இணைப்பு உடைந்துள்ளது அல்லது வித்தியாசமாக மறைக்கப்பட்டுள்ளது.",
    },
    "UPI_HANDLE_FROM_UNKNOWN": {
        Language.EN: "An unknown person is asking you to pay them directly.",
        Language.HI: "कोई अनजान व्यक्ति आपसे सीधे पैसे भेजने को कह रहा है।",
        Language.TA: "தெரியாத ஒருவர் நேரடியாகப் பணம் அனுப்பச் சொல்கிறார்.",
    },
    # --- Email -------------------------------------------------------------
    "EMAIL_NO_FROM": {
        Language.EN: "This mail does not show who really sent it.",
        Language.HI: "इस मेल में यह नहीं दिखता कि इसे असल में किसने भेजा।",
        Language.TA: "இந்த அஞ்சலை உண்மையில் யார் அனுப்பினார் என்று தெரியவில்லை.",
    },
    "EMAIL_BRAND_FROM_FREEMAIL": {
        Language.EN: "The name says {brand} but the mail came from a personal account, not the bank.",
        Language.HI: "नाम में {brand} लिखा है, पर मेल किसी निजी खाते से आया है, बैंक से नहीं।",
        Language.TA: "பெயரில் {brand} உள்ளது, ஆனால் அஞ்சல் தனிநபர் கணக்கிலிருந்து வந்தது, வங்கியிலிருந்து அல்ல.",
    },
    "EMAIL_DISPLAY_NAME_SPOOF": {
        Language.EN: "The sender's name says {brand}, but the real address does not match it.",
        Language.HI: "भेजने वाले का नाम {brand} है, पर असली पता उससे मेल नहीं खाता।",
        Language.TA: "அனுப்புநர் பெயர் {brand}, ஆனால் உண்மையான முகவரி அதற்குப் பொருந்தவில்லை.",
    },
    "EMAIL_SENDER_DOMAIN_LOOKALIKE": {
        Language.EN: "The sender's address copies {brand} but is not the real one.",
        Language.HI: "भेजने वाले का पता {brand} की नकल करता है, पर असली नहीं है।",
        Language.TA: "அனுப்புநர் முகவரி {brand} ஐப் போலியாகப் பிரதிபலிக்கிறது, உண்மையானது அல்ல.",
    },
    "EMAIL_ADDRESS_IN_DISPLAY_NAME": {
        Language.EN: "The address you see is not the address the mail came from.",
        Language.HI: "जो पता आपको दिख रहा है, मेल उस पते से नहीं आया।",
        Language.TA: "நீங்கள் பார்க்கும் முகவரியிலிருந்து அஞ்சல் வரவில்லை.",
    },
    "EMAIL_REPLY_TO_MISMATCH": {
        Language.EN: "If you reply, your answer goes to a different person than you expect.",
        Language.HI: "अगर आप जवाब देंगे, तो वह किसी और के पास जाएगा।",
        Language.TA: "நீங்கள் பதிலளித்தால், அது வேறு ஒருவரிடம் செல்லும்.",
    },
    "EMAIL_RETURN_PATH_MISMATCH": {
        Language.EN: "The mail was posted from a different place than it claims.",
        Language.HI: "मेल जहाँ से भेजा गया है, वह बताई गई जगह से अलग है।",
        Language.TA: "அஞ்சல் கூறப்பட்ட இடத்தைவிட வேறு இடத்திலிருந்து அனுப்பப்பட்டது.",
    },
    "EMAIL_AUTH_HARD_FAIL": {
        Language.EN: "The sender could not be proved. The mail is very likely faked.",
        Language.HI: "भेजने वाले की पहचान साबित नहीं हुई। मेल बहुत संभव है नकली हो।",
        Language.TA: "அனுப்புநரை நிரூபிக்க முடியவில்லை. அஞ்சல் போலியாக இருக்க வாய்ப்பு அதிகம்.",
    },
    "EMAIL_AUTH_WEAK": {
        Language.EN: "The sender's identity could not be fully checked.",
        Language.HI: "भेजने वाले की पहचान पूरी तरह जाँची नहीं जा सकी।",
        Language.TA: "அனுப்புநரின் அடையாளத்தை முழுமையாகச் சரிபார்க்க முடியவில்லை.",
    },
    "EMAIL_AUTH_ABSENT": {
        Language.EN: "There is no proof of who sent this mail.",
        Language.HI: "इस मेल को किसने भेजा, इसका कोई सबूत नहीं है।",
        Language.TA: "இந்த அஞ்சலை யார் அனுப்பினார் என்பதற்கு எந்த ஆதாரமும் இல்லை.",
    },
    "EMAIL_NO_RECEIVED_CHAIN": {
        Language.EN: "The mail's delivery history is missing.",
        Language.HI: "मेल कहाँ-कहाँ से गुज़रा, वह जानकारी गायब है।",
        Language.TA: "அஞ்சல் எங்கு சென்றது என்ற விவரம் இல்லை.",
    },
    "EMAIL_ATTACHMENT_DOUBLE_EXTENSION": {
        Language.EN: "The attached file pretends to be a document but it is a program.",
        Language.HI: "साथ लगी फ़ाइल दस्तावेज़ जैसी दिखती है, पर वह एक प्रोग्राम है।",
        Language.TA: "இணைக்கப்பட்ட கோப்பு ஆவணம் போலத் தெரிகிறது, ஆனால் அது நிரல்.",
    },
    "EMAIL_ATTACHMENT_EXECUTABLE": {
        Language.EN: "The attached file can take over your computer if you open it.",
        Language.HI: "साथ लगी फ़ाइल खोलने पर आपका कंप्यूटर उनके क़ाबू में जा सकता है।",
        Language.TA: "இணைக்கப்பட்ட கோப்பைத் திறந்தால் உங்கள் கணினி அவர்கள் கட்டுப்பாட்டில் செல்லும்.",
    },
    "EMAIL_ATTACHMENT_MACRO": {
        Language.EN: "The attached file can run hidden instructions.",
        Language.HI: "साथ लगी फ़ाइल छिपे निर्देश चला सकती है।",
        Language.TA: "இணைக்கப்பட்ட கோப்பு மறைந்த கட்டளைகளை இயக்கக்கூடும்.",
    },
    "EMAIL_ATTACHMENT_HTML": {
        Language.EN: "The attached file opens a fake login page on your device.",
        Language.HI: "साथ लगी फ़ाइल आपके फ़ोन पर नकली लॉगिन पेज खोलती है।",
        Language.TA: "இணைக்கப்பட்ட கோப்பு உங்கள் சாதனத்தில் போலி உள்நுழைவுப் பக்கத்தைத் திறக்கும்.",
    },
    # --- Text --------------------------------------------------------------
    "TEXT_CREDENTIAL_REQUEST": {
        Language.EN: "They are asking for your OTP or PIN. No real bank or officer ever asks for this.",
        Language.HI: "वे आपका ओटीपी या पिन मांग रहे हैं। कोई सच्चा बैंक या अफ़सर यह कभी नहीं मांगता।",
        Language.TA: "அவர்கள் உங்கள் ஓடிபி அல்லது பின் கேட்கிறார்கள். உண்மையான வங்கி அல்லது அதிகாரி இதைக் கேட்பதில்லை.",
    },
    "TEXT_DIGITAL_ARREST_PATTERN": {
        Language.EN: "Someone is pretending to be police and demanding money. Police never ask for money on a call.",
        Language.HI: "कोई पुलिस बनकर पैसे मांग रहा है। पुलिस फ़ोन पर कभी पैसे नहीं मांगती।",
        Language.TA: "யாரோ காவல்துறை போல் நடித்துப் பணம் கேட்கிறார்கள். காவல்துறை தொலைபேசியில் பணம் கேட்பதில்லை.",
    },
    "TEXT_ADVANCE_FEE_PATTERN": {
        Language.EN: "They say you won something, then ask you to pay first. That is always a cheat.",
        Language.HI: "वे कहते हैं आपने कुछ जीता है, फिर पहले पैसे मांगते हैं। यह हमेशा ठगी होती है।",
        Language.TA: "நீங்கள் ஏதோ வென்றதாகச் சொல்லி, முதலில் பணம் கேட்கிறார்கள். இது எப்போதும் ஏமாற்று.",
    },
    "TEXT_URGENT_MONEY_REQUEST": {
        Language.EN: "They are rushing you about money. Hurrying you is the trick.",
        Language.HI: "वे पैसे के लिए आपको जल्दी करा रहे हैं। जल्दबाज़ी कराना ही उनकी चाल है।",
        Language.TA: "பணத்திற்காக அவர்கள் உங்களை அவசரப்படுத்துகிறார்கள். அவசரமே அவர்களின் தந்திரம்.",
    },
    "TEXT_KYC_PRESSURE": {
        Language.EN: "They are threatening to close your account. Banks do not do this by message.",
        Language.HI: "वे आपका खाता बंद करने की धमकी दे रहे हैं। बैंक संदेश से ऐसा नहीं करता।",
        Language.TA: "உங்கள் கணக்கை மூடுவதாக மிரட்டுகிறார்கள். வங்கிகள் செய்தி மூலம் இதைச் செய்வதில்லை.",
    },
    "TEXT_JOB_BAIT": {
        Language.EN: "Easy-money job offers like this take your money instead of paying you.",
        Language.HI: "ऐसी आसान कमाई वाली नौकरी पैसे देती नहीं, आपसे पैसे ले लेती है।",
        Language.TA: "இதுபோன்ற எளிய வருமான வேலை உங்களுக்குப் பணம் தராது, உங்கள் பணத்தை எடுக்கும்.",
    },
    "TEXT_MENTIONS_PAYMENT": {
        Language.EN: "This message talks about sending money.",
        Language.HI: "यह संदेश पैसे भेजने की बात करता है।",
        Language.TA: "இந்தச் செய்தி பணம் அனுப்புவது பற்றிப் பேசுகிறது.",
    },
    "TEXT_MENTIONS_CREDENTIAL": {
        Language.EN: "This message talks about your OTP, PIN or password.",
        Language.HI: "यह संदेश आपके ओटीपी, पिन या पासवर्ड की बात करता है।",
        Language.TA: "இந்தச் செய்தி உங்கள் ஓடிபி, பின் அல்லது கடவுச்சொல் பற்றிப் பேசுகிறது.",
    },
    "TEXT_MENTIONS_KYC": {
        Language.EN: "This message talks about your account being blocked.",
        Language.HI: "यह संदेश आपका खाता बंद होने की बात करता है।",
        Language.TA: "இந்தச் செய்தி உங்கள் கணக்கு முடக்கப்படுவது பற்றிப் பேசுகிறது.",
    },
    "TEXT_MODEL_SCAM_SCORE": {
        Language.EN: "This message is written the way cheating messages are usually written.",
        Language.HI: "यह संदेश उसी तरह लिखा है जैसे ठगी के संदेश लिखे जाते हैं।",
        Language.TA: "இந்தச் செய்தி ஏமாற்று செய்திகள் எழுதப்படும் விதத்தில் உள்ளது.",
    },
    # --- Model signals -----------------------------------------------------
    "URL_MODEL_DOMAIN_REPUTATION": {
        Language.EN: "This website name looks like one made only for cheating people.",
        Language.HI: "इस वेबसाइट का नाम ऐसा लगता है जो सिर्फ़ ठगी के लिए बनाया गया है।",
        Language.TA: "இந்த இணையதளப் பெயர் ஏமாற்றுவதற்காக மட்டுமே உருவாக்கப்பட்டது போல் தெரிகிறது.",
    },
    # --- Sender ------------------------------------------------------------
    "SENDER_UNKNOWN": {
        Language.EN: "This came from a number that is not in your contacts.",
        Language.HI: "यह उस नंबर से आया है जो आपके संपर्कों में नहीं है।",
        Language.TA: "இது உங்கள் தொடர்புகளில் இல்லாத எண்ணிலிருந்து வந்தது.",
    },
}

# Media-present prompt (PRD 5.6). Passive capture cannot read attached media, so
# we invite one tap rather than staying silent about it.
_MEDIA_PROMPT: dict[Language, str] = {
    Language.EN: "This message also has a photo or video. Tap to check it.",
    Language.HI: "इस संदेश में फ़ोटो या वीडियो भी है। जाँचने के लिए दबाइए।",
    Language.TA: "இந்தச் செய்தியில் படம் அல்லது காணொளியும் உள்ளது. சரிபார்க்க தட்டுங்கள்.",
}

MAX_REASONS = 3


class _Defaulting(dict):
    """Format mapping that yields a neutral word for absent keys."""

    def __missing__(self, key: str) -> str:  # noqa: D105
        return "this"


def _fill(template: str, detail: dict) -> str:
    try:
        return template.format_map(_Defaulting(detail))
    except (ValueError, IndexError):
        return template


def reason_for(signal: Signal, language: Language) -> str | None:
    """Plain-language reason for one signal, or None if untranslated."""
    entry = _REASONS.get(signal.code)
    if not entry:
        return None
    template = entry.get(language) or entry.get(Language.EN)
    if not template:
        return None
    return _fill(template, signal.detail)


def build_explanation(
    band: Band,
    signals: list[Signal],
    language: Language = Language.EN,
    media_present: bool = False,
) -> Explanation:
    """Assemble the user-facing explanation for a verdict.

    `signals` is expected pre-ranked by `fusion.rank_signals`, so the most
    severe and most conclusive evidence surfaces first. At most `MAX_REASONS`
    reasons are shown: a list of eight findings is not more convincing to this
    user, only more overwhelming.
    """
    reasons: list[str] = []
    for signal in signals:
        text = reason_for(signal, language)
        if text and text not in reasons:
            reasons.append(text)
        if len(reasons) >= MAX_REASONS:
            break

    headline = _HEADLINES[band][language]
    action = _ACTIONS[band][language]

    if media_present:
        reasons.append(_MEDIA_PROMPT[language])

    # The spoken string is deliberately just headline plus action. Reading a
    # list of reasons aloud buries the instruction, and the instruction is the
    # only part that changes what the user does.
    spoken = f"{headline}. {action}"

    return Explanation(
        language=language,
        headline=headline,
        action=action,
        reasons=reasons,
        spoken=spoken,
    )


def check_coverage() -> dict[str, list[str]]:
    """Report signal codes missing a translation, for the test suite.

    Returns a mapping of language value to the codes it lacks.
    """
    gaps: dict[str, list[str]] = {}
    for language in Language:
        missing = [
            code
            for code, entry in _REASONS.items()
            if not entry.get(language)
        ]
        if missing:
            gaps[language.value] = sorted(missing)
    return gaps

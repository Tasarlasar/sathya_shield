"""URL pillar: deterministic rule engine plus India-specific high-precision rules.

PRD v3.0 sections 6.1, 7.2 (F10, F11).

Every signal here is deterministic: each fires on a fact observable from the URL
string itself, with no model and no network call. That is what makes them
eligible to raise RED under section 14.2.

Network-dependent signals (WHOIS domain age, redirect-chain resolution,
blocklist lookups) live in `domain_intel` so this module stays pure, fast and
offline-safe. It is the tier that runs on-device.
"""

from __future__ import annotations

import re
from urllib.parse import unquote, urlsplit

import tldextract

from ..schemas import Pillar, Severity, Signal

# Offline extractor: use only the bundled public-suffix snapshot. Without
# suffix_list_urls=() tldextract tries to fetch the live list on first use,
# which would make this module fail closed on a device with no connectivity.
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


# --------------------------------------------------------------------------
# Reference data
# --------------------------------------------------------------------------

# Indian brand tokens that fraudsters impersonate, mapped to the registrable
# domains that legitimately own them. A brand token appearing in a domain that
# is NOT in its allowlist is the core typosquat signal.
BRAND_DOMAINS: dict[str, frozenset[str]] = {
    "sbi": frozenset({"sbi.co.in", "onlinesbi.sbi", "sbi", "sbicard.com"}),
    "hdfc": frozenset({"hdfcbank.com", "hdfc.com", "hdfclife.com"}),
    "icici": frozenset({"icicibank.com", "icicidirect.com", "icicilombard.com"}),
    "axis": frozenset({"axisbank.com", "axisbank.co.in"}),
    "kotak": frozenset({"kotak.com"}),
    "pnb": frozenset({"pnbindia.in", "netpnb.com"}),
    "canara": frozenset({"canarabank.com", "canarabank.in"}),
    "npci": frozenset({"npci.org.in"}),
    "upi": frozenset({"npci.org.in", "bhimupi.org.in"}),
    "irctc": frozenset({"irctc.co.in", "irctc.com"}),
    "indiapost": frozenset({"indiapost.gov.in"}),
    "aadhaar": frozenset({"uidai.gov.in"}),
    "uidai": frozenset({"uidai.gov.in"}),
    "trai": frozenset({"trai.gov.in"}),
    "epfo": frozenset({"epfindia.gov.in"}),
    "paytm": frozenset({"paytm.com", "paytmbank.com"}),
    "phonepe": frozenset({"phonepe.com"}),
    "digilocker": frozenset({"digilocker.gov.in"}),
    "incometax": frozenset({"incometax.gov.in", "incometaxindia.gov.in"}),
}

# TLDs disproportionately used for throwaway phishing infrastructure. On its own
# this is weak evidence (plenty of legitimate .xyz sites exist), so it is
# deliberately scored LOW and only becomes meaningful in combination.
RISKY_TLDS = frozenset(
    {
        "xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "click", "link",
        "work", "fit", "loan", "win", "bid", "review", "country", "stream",
        "download", "racing", "party", "rest", "icu", "cyou", "sbs", "quest",
        "monster", "cam", "surf", "online", "site", "website", "shop",
    }
)

URL_SHORTENERS = frozenset(
    {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
        "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "bl.ink",
        "t.ly", "short.io", "surl.li", "clck.ru", "v.gd", "soo.gd", "s.id",
        "urlz.fr", "hyperurl.co", "tny.im", "u.to", "qr.ae", "adf.ly", "wa.link",
    }
)

# Payment service provider suffixes for UPI virtual payment addresses. A UPI
# handle is distinguishable from an email address because the suffix is a bare
# PSP token with no dot-TLD following it.
UPI_PSP = frozenset(
    {
        "ybl", "okaxis", "oksbi", "okhdfcbank", "okicici", "paytm", "apl", "axl",
        "ibl", "upi", "airtel", "freecharge", "jio", "sbi", "hdfcbank", "icici",
        "axisbank", "kotak", "yesbank", "idfcbank", "indus", "barodampay",
    }
)

# Path or query tokens that indicate a credential or payment workflow.
SENSITIVE_PATH_TOKENS = frozenset(
    {
        "login", "signin", "sign-in", "verify", "verification", "kyc", "update",
        "secure", "account", "netbanking", "otp", "wallet", "payment", "pay",
        "refund", "reward", "prize", "claim", "unblock", "reactivate", "confirm",
        "authenticate", "password", "pin", "card", "cvv", "billdesk",
    }
)

_URL_RE = re.compile(
    r"""(?xi)
    \b(
        (?:https?://|www\.)          # explicit scheme, or a www. prefix
        [^\s<>"'\]\[{}|\\^`]+        # bounded run of non-delimiter characters
    )
    """
)

_IPV4_HOST_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

_UPI_RE = re.compile(
    r"\b([a-z0-9][a-z0-9._-]{1,64})@(" + "|".join(sorted(UPI_PSP)) + r")\b(?!\.)",
    re.IGNORECASE,
)

_APK_RE = re.compile(r"\.apk(?:$|[?#/])", re.IGNORECASE)


# --------------------------------------------------------------------------
# Extraction helpers
# --------------------------------------------------------------------------


def extract_urls(text: str) -> list[str]:
    """Pull candidate URLs out of free text, normalising bare www. hosts."""
    if not text:
        return []
    found: list[str] = []
    for match in _URL_RE.finditer(text):
        raw = match.group(1).rstrip(".,;:!?)")
        if raw.lower().startswith("www."):
            raw = "http://" + raw
        if raw not in found:
            found.append(raw)
    return found


def extract_upi_handles(text: str) -> list[str]:
    """Find UPI virtual payment addresses in free text."""
    if not text:
        return []
    seen: list[str] = []
    for match in _UPI_RE.finditer(text):
        handle = match.group(0)
        if handle not in seen:
            seen.append(handle)
    return seen


def _registrable(host: str) -> str:
    """Return the registrable domain (eTLD+1) for a host."""
    parts = _EXTRACT(host)
    if parts.domain and parts.suffix:
        return f"{parts.domain}.{parts.suffix}".lower()
    return host.lower()


def _brand_hits(host: str, registrable: str) -> list[str]:
    """Brand tokens present in the host but not owned by its registrable domain.

    This is the typosquat / lookalike detector. `sbi-rewards.xyz` contains the
    token `sbi` while its registrable domain is not on SBI's allowlist, so it
    reports a hit. `onlinesbi.sbi` also contains `sbi` but is allowlisted, so it
    does not. Allowlisting is what keeps this rule high-precision enough to be
    RED-eligible.
    """
    host_l = host.lower()
    hits: list[str] = []
    for brand, owners in BRAND_DOMAINS.items():
        if brand not in host_l:
            continue
        if registrable in owners:
            continue
        # A brand token owned via a bare suffix (e.g. the `.sbi` gTLD) is fine.
        if any(registrable.endswith("." + owner) for owner in owners):
            continue
        hits.append(brand)
    return hits


# --------------------------------------------------------------------------
# Rules
# --------------------------------------------------------------------------


def analyse_url(url: str) -> list[Signal]:
    """Evaluate a single URL. All signals returned are deterministic."""
    signals: list[Signal] = []
    if not url:
        return signals

    if "://" not in url:
        url = "http://" + url

    try:
        parts = urlsplit(url)
    except ValueError:
        return [
            Signal(
                code="URL_UNPARSEABLE",
                pillar=Pillar.URL,
                severity=Severity.MEDIUM,
                deterministic=True,
                detail={"url": url[:200]},
            )
        ]

    host = (parts.hostname or "").lower()
    if not host:
        return signals

    registrable = _registrable(host)
    suffix = _EXTRACT(host).suffix.lower()
    path_and_query = unquote(f"{parts.path}?{parts.query}").lower()
    full_lower = url.lower()

    # --- CRITICAL: Android package download -------------------------------
    # PRD 6.1: for this user segment an APK link is near-conclusively
    # malicious. Drives the "wedding invitation" and "courier parcel" scams.
    if _APK_RE.search(full_lower):
        signals.append(
            Signal(
                code="URL_APK_DOWNLOAD",
                pillar=Pillar.URL,
                severity=Severity.CRITICAL,
                deterministic=True,
                weight=1.5,
                detail={"url": url[:200], "host": host},
            )
        )

    # --- Userinfo confusion: http://sbi.co.in@evil.com --------------------
    if "@" in (parts.netloc or ""):
        signals.append(
            Signal(
                code="URL_USERINFO_OBFUSCATION",
                pillar=Pillar.URL,
                severity=Severity.CRITICAL,
                deterministic=True,
                weight=1.3,
                detail={"netloc": parts.netloc[:120]},
            )
        )

    # --- Bare IP address as host -----------------------------------------
    if _IPV4_HOST_RE.match(host):
        signals.append(
            Signal(
                code="URL_IP_HOST",
                pillar=Pillar.URL,
                severity=Severity.HIGH,
                deterministic=True,
                weight=1.2,
                detail={"host": host},
            )
        )

    # --- Punycode homograph ----------------------------------------------
    if "xn--" in host:
        signals.append(
            Signal(
                code="URL_PUNYCODE_HOST",
                pillar=Pillar.URL,
                severity=Severity.HIGH,
                deterministic=True,
                weight=1.2,
                detail={"host": host},
            )
        )

    # --- Indian brand impersonation --------------------------------------
    brands = _brand_hits(host, registrable)
    if brands:
        signals.append(
            Signal(
                code="URL_BRAND_LOOKALIKE",
                pillar=Pillar.URL,
                severity=Severity.HIGH,
                deterministic=True,
                weight=1.4,
                detail={
                    "brand": brands[0],
                    "brands": ",".join(brands),
                    "host": host,
                    "registrable": registrable,
                },
            )
        )

    # --- URL shortener ----------------------------------------------------
    if registrable in URL_SHORTENERS:
        signals.append(
            Signal(
                code="URL_SHORTENER",
                pillar=Pillar.URL,
                severity=Severity.MEDIUM,
                deterministic=True,
                detail={"host": host},
            )
        )

    # --- Risky TLD --------------------------------------------------------
    if suffix in RISKY_TLDS:
        signals.append(
            Signal(
                code="URL_RISKY_TLD",
                pillar=Pillar.URL,
                severity=Severity.LOW,
                deterministic=True,
                detail={"tld": suffix, "host": host},
            )
        )

    # --- Credential or payment workflow in the path ----------------------
    tokens = {t for t in re.split(r"[^a-z0-9]+", path_and_query) if t}
    sensitive = sorted(tokens & SENSITIVE_PATH_TOKENS)
    if sensitive:
        # Severity escalates when a credential path is combined with a
        # lookalike host: that pairing is what an actual harvest page looks
        # like, whereas /login on its own is completely ordinary.
        severity = Severity.HIGH if brands else Severity.LOW
        signals.append(
            Signal(
                code="URL_CREDENTIAL_PATH",
                pillar=Pillar.URL,
                severity=severity,
                deterministic=True,
                detail={"tokens": ",".join(sensitive[:5]), "host": host},
            )
        )

    # --- Excessive subdomain depth ---------------------------------------
    subdomain = _EXTRACT(host).subdomain
    depth = len([p for p in subdomain.split(".") if p]) if subdomain else 0
    if depth >= 4:
        signals.append(
            Signal(
                code="URL_DEEP_SUBDOMAIN",
                pillar=Pillar.URL,
                severity=Severity.MEDIUM,
                deterministic=True,
                detail={"depth": depth, "host": host},
            )
        )

    # --- Plaintext transport ---------------------------------------------
    if parts.scheme == "http":
        signals.append(
            Signal(
                code="URL_NO_TLS",
                pillar=Pillar.URL,
                severity=Severity.LOW,
                deterministic=True,
                detail={"host": host},
            )
        )

    return signals


def analyse_urls(urls: list[str]) -> list[Signal]:
    """Evaluate several URLs, de-duplicating by signal code and host."""
    seen: set[tuple[str, str]] = set()
    out: list[Signal] = []
    for url in urls:
        for signal in analyse_url(url):
            key = (signal.code, str(signal.detail.get("host", "")))
            if key in seen:
                continue
            seen.add(key)
            out.append(signal)
    return out


def analyse_upi(text: str, sender_known: bool) -> list[Signal]:
    """Flag UPI payment addresses arriving from an unrecognised sender.

    A UPI handle from a saved contact is unremarkable. One from an unknown
    number in an unsolicited message is a direct request to move money.
    """
    handles = extract_upi_handles(text)
    if not handles or sender_known:
        return []
    return [
        Signal(
            code="UPI_HANDLE_FROM_UNKNOWN",
            pillar=Pillar.URL,
            severity=Severity.HIGH,
            deterministic=True,
            weight=1.2,
            detail={"handle": handles[0], "count": len(handles)},
        )
    ]


# --------------------------------------------------------------------------
# Public helpers shared with other pillars
# --------------------------------------------------------------------------

# Consumer mail providers. An institution claiming to be a bank while sending
# from one of these is near-conclusive: banks do not send from Gmail.
FREEMAIL_DOMAINS = frozenset(
    {
        "gmail.com", "googlemail.com", "yahoo.com", "yahoo.in", "yahoo.co.in",
        "outlook.com", "hotmail.com", "live.com", "msn.com", "aol.com",
        "rediffmail.com", "protonmail.com", "proton.me", "zoho.com", "zohomail.com",
        "icloud.com", "me.com", "mail.com", "gmx.com", "yandex.com", "inbox.com",
    }
)


def registrable_domain(host: str) -> str:
    """Public wrapper: registrable domain (eTLD+1) for a host."""
    return _registrable(host)


def brand_tokens_not_owned(host: str) -> list[str]:
    """Public wrapper: Indian brand tokens present in a host that does not own them."""
    return _brand_hits(host, _registrable(host))


def brand_tokens_in_display_name(name: str) -> list[str]:
    """Find Indian brand tokens in a human-readable display name.

    Uses word-start anchoring rather than plain substring matching. A naive
    substring search would match `trai` inside `straight`, which would generate
    exactly the kind of false positive that section 14.3 says destroys the
    product. Anchoring to a word start still catches run-together forms such as
    `HDFCBank`.
    """
    if not name:
        return []
    lowered = name.lower()
    hits: list[str] = []
    for brand in BRAND_DOMAINS:
        if re.search(r"\b" + re.escape(brand), lowered):
            hits.append(brand)
    return hits


def brand_owns_domain(brand: str, domain: str) -> bool:
    """Whether `domain` legitimately belongs to `brand`."""
    owners = BRAND_DOMAINS.get(brand, frozenset())
    domain = domain.lower()
    return domain in owners or any(domain.endswith("." + o) for o in owners)

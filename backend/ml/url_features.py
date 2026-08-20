"""Feature extraction for the URL classifier.

SCOPE, and why it is narrower than it first appears.

Features are computed from the **registrable domain only** (eTLD+1), never the
full hostname or path. Two properties of the available data force this:

1. **Subdomain presence is a perfect source artifact.** Measured on our fetched
   data: 72.1% of phishing hostnames carry a subdomain versus 0.0% of the Tranco
   benign domains, because Tranco publishes registrable domains and the phishing
   feeds publish full URLs. Any feature touching subdomains would let the model
   score ~100% by detecting which *file* a row came from.

2. **Path and query are absent from the benign class entirely.** Including them
   would be the same leak in a different coat.

So this model answers one question: *does this registrable domain look
maliciously registered?* Path semantics (credential paths, `.apk` links) and
subdomain tricks stay with the deterministic rule engine in
`app/pillars/url_rules.py`, which already handles them and does so
explainably. ML where it earns its place, rules where rules are better.
"""

from __future__ import annotations

import math
import re
from collections import Counter

import tldextract

from app.pillars.url_rules import (
    RISKY_TLDS,
    brand_tokens_not_owned,
)

_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

_VOWELS = set("aeiou")

# Words attackers put in domains they register themselves. Distinct from the
# brand allowlist: these are generic lures rather than impersonations.
LURE_WORDS = (
    "login", "signin", "secure", "security", "verify", "verified", "account",
    "update", "confirm", "alert", "service", "support", "help", "recovery",
    "recover", "unlock", "wallet", "pay", "payment", "billing", "invoice",
    "refund", "bonus", "gift", "free", "win", "prize", "claim", "reward",
    "bank", "card", "kyc", "otp", "auth", "session", "portal", "official",
    "customer", "client", "mail", "webmail", "office", "cloud", "drive",
)

_TOKEN_SPLIT = re.compile(r"[^a-z0-9]+")


def _entropy(text: str) -> float:
    """Shannon entropy of a string, in bits per character."""
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def _max_consonant_run(text: str) -> int:
    """Longest run of consecutive consonants: a crude gibberish signal."""
    best = run = 0
    for char in text:
        if char.isalpha() and char not in _VOWELS:
            run += 1
            best = max(best, run)
        else:
            run = 0
    return best


def _max_digit_run(text: str) -> int:
    best = run = 0
    for char in text:
        if char.isdigit():
            run += 1
            best = max(best, run)
        else:
            run = 0
    return best


def registrable_of(host_or_domain: str) -> str:
    """Registrable domain (eTLD+1) for a hostname or bare domain."""
    parts = _EXTRACT(host_or_domain)
    if parts.domain and parts.suffix:
        return f"{parts.domain}.{parts.suffix}".lower()
    return host_or_domain.lower()


FEATURE_NAMES: tuple[str, ...] = (
    "domain_len",
    "sld_len",
    "tld_len",
    "tld_risky",
    "hyphen_count",
    "digit_count",
    "digit_ratio",
    "sld_entropy",
    "vowel_ratio",
    "max_consonant_run",
    "max_digit_run",
    "unique_char_ratio",
    "token_count",
    "longest_token_len",
    "brand_lookalike",
    "lure_word_count",
    "has_lure_word",
    "sld_all_digits",
    "repeated_char_run",
)


def extract(domain: str) -> list[float]:
    """Feature vector for one registrable domain. Order matches FEATURE_NAMES."""
    domain = (domain or "").strip().lower()
    parts = _EXTRACT(domain)
    sld = parts.domain or domain.split(".")[0]
    tld = parts.suffix or domain.rsplit(".", 1)[-1] if "." in domain else ""

    letters_digits = [c for c in sld if c.isalnum()]
    alpha = [c for c in sld if c.isalpha()]
    tokens = [t for t in _TOKEN_SPLIT.split(sld) if t]

    repeated = 0
    run = 1
    for i in range(1, len(sld)):
        if sld[i] == sld[i - 1]:
            run += 1
            repeated = max(repeated, run)
        else:
            run = 1

    lures = sum(1 for word in LURE_WORDS if word in sld)

    return [
        float(len(domain)),
        float(len(sld)),
        float(len(tld)),
        1.0 if tld in RISKY_TLDS else 0.0,
        float(sld.count("-")),
        float(sum(c.isdigit() for c in sld)),
        (sum(c.isdigit() for c in sld) / len(sld)) if sld else 0.0,
        _entropy(sld),
        (sum(1 for c in alpha if c in _VOWELS) / len(alpha)) if alpha else 0.0,
        float(_max_consonant_run(sld)),
        float(_max_digit_run(sld)),
        (len(set(letters_digits)) / len(letters_digits)) if letters_digits else 0.0,
        float(len(tokens)),
        float(max((len(t) for t in tokens), default=0)),
        1.0 if brand_tokens_not_owned(domain) else 0.0,
        float(lures),
        1.0 if lures else 0.0,
        1.0 if sld.isdigit() else 0.0,
        float(repeated),
    ]


def extract_many(domains: list[str]) -> list[list[float]]:
    return [extract(d) for d in domains]

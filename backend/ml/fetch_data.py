"""Download the public training data, recording provenance.

PRD v3.0 section 12. Every source is free and needs no approval, which is why
these two classifiers are the cheapest way to close PS clauses 4 and 5.

Provenance is written to `data/provenance.json` because section 12.4 requires
recording where every row came from. Accuracy figures are meaningless without
knowing the source, and a stale phishing feed inflates results.

Run:  python -m ml.fetch_data
"""

from __future__ import annotations

import csv
import io
import json
import sys
import urllib.request
import zipfile
from datetime import datetime, timezone

from .paths import PROVENANCE_PATH, RAW_DIR, ensure_dirs

# Use the operating system's trust store rather than the bundled CA list.
#
# Networks that terminate TLS for inspection (common on college and corporate
# wifi) present a locally-trusted root that the OS keychain knows about but
# Python's bundled certifi does not, producing
# "self-signed certificate in certificate chain". This is the correct fix;
# disabling verification would be the wrong one.
try:
    import truststore

    truststore.inject_into_ssl()
except ImportError:  # pragma: no cover - optional on networks without interception
    pass

USER_AGENT = "SatyaShield-research/0.1 (SIH 2026 academic project)"
TIMEOUT = 90

SOURCES = {
    "phishtank": "https://data.phishtank.com/data/online-valid.csv",
    "openphish": "https://openphish.com/feed.txt",
    "tranco": "https://tranco-list.eu/top-1m.csv.zip",
    "uci_sms": "https://archive.ics.uci.edu/static/public/228/sms+spam+collection.zip",
}

# Deliberately NOT used as phishing data: https://urlhaus.abuse.ch/
#
# URLhaus lists malware *distribution* URLs (droppers, shell scripts, bare
# IP:port binaries). Those are a different threat class from credential
# phishing, and mixing them in would train the model on a blend of two labels,
# inflating apparent accuracy while degrading the thing we actually want.
# Worth revisiting as its own malware-URL signal, which would pair well with the
# existing APK-link rule.


def _get(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        return response.read()


def fetch_phishing_urls() -> list[str]:
    """Verified phishing URLs from PhishTank, topped up with the OpenPhish feed.

    Both are community-reported and recency-skewed, per section 12.4. Treat this
    as a sample of *currently live* phishing infrastructure rather than a
    balanced historical corpus: many entries point at throwaway subdomains on
    free hosting platforms, which is itself a real and learnable signal.
    """
    urls: list[str] = []

    # PhishTank ships a CSV whose second column is the URL.
    raw = _get(SOURCES["phishtank"]).decode("utf-8", errors="replace")
    reader = csv.DictReader(io.StringIO(raw))
    for row in reader:
        url = (row.get("url") or "").strip()
        if url.startswith("http"):
            urls.append(url)

    # OpenPhish is a plain URL-per-line feed and overlaps only partially.
    feed = _get(SOURCES["openphish"]).decode("utf-8", errors="replace")
    urls.extend(
        line.strip() for line in feed.splitlines() if line.strip().startswith("http")
    )

    urls = list(dict.fromkeys(urls))
    (RAW_DIR / "phishing_urls.txt").write_text("\n".join(urls), encoding="utf-8")
    return urls


def fetch_benign_domains(sample_per_decade: int = 6000) -> list[str]:
    """Legitimate domains sampled across the whole Tranco rank range.

    Section 12.4 names the trap this avoids: training benign-vs-phishing using
    only the *top* of a popularity list teaches the model to detect popularity,
    not safety, and the result flags every obscure but legitimate Indian site.

    We therefore sample evenly from each power-of-ten band of ranks, so the
    benign class contains plenty of unglamorous, low-traffic, entirely real
    domains alongside the famous ones.
    """
    archive = zipfile.ZipFile(io.BytesIO(_get(SOURCES["tranco"])))
    name = archive.namelist()[0]
    rows = list(csv.reader(io.TextIOWrapper(archive.open(name), encoding="utf-8")))

    bands: dict[int, list[str]] = {}
    for row in rows:
        if len(row) < 2:
            continue
        try:
            rank = int(row[0])
        except ValueError:
            continue
        decade = len(str(rank))  # 1-9 -> 1, 10-99 -> 2, ...
        bands.setdefault(decade, []).append(row[1].strip().lower())

    sampled: list[str] = []
    for decade in sorted(bands):
        entries = bands[decade]
        step = max(1, len(entries) // sample_per_decade)
        sampled.extend(entries[::step][:sample_per_decade])

    sampled = list(dict.fromkeys(sampled))
    (RAW_DIR / "benign_domains.txt").write_text("\n".join(sampled), encoding="utf-8")
    return sampled


def fetch_sms_corpus() -> list[tuple[str, str]]:
    """UCI SMS Spam Collection: 5,574 labelled English SMS messages.

    Old and not Indian, per section 12.4. It gives the text classifier a real
    labelled base; Indian-language coverage has to come from the hand-collected
    set described in section 12.3.
    """
    archive = zipfile.ZipFile(io.BytesIO(_get(SOURCES["uci_sms"])))
    target = next(n for n in archive.namelist() if n.endswith("SMSSpamCollection"))
    text = archive.read(target).decode("utf-8", errors="replace")

    rows: list[tuple[str, str]] = []
    for line in text.splitlines():
        if "\t" not in line:
            continue
        label, message = line.split("\t", 1)
        label = label.strip().lower()
        if label in {"ham", "spam"} and message.strip():
            rows.append((label, message.strip()))

    with (RAW_DIR / "sms_corpus.tsv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, delimiter="\t")
        writer.writerows(rows)
    return rows


def main() -> int:
    ensure_dirs()
    provenance: dict[str, object] = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "sources": {},
    }

    print("fetching phishing URLs (PhishTank + OpenPhish)...")
    phishing = fetch_phishing_urls()
    provenance["sources"]["phishing_urls"] = {
        "urls": [SOURCES["phishtank"], SOURCES["openphish"]],
        "count": len(phishing),
        "licence": "community feeds, free access",
        "caveat": "community-reported, recency-skewed, label noise likely",
        "excluded": "URLhaus deliberately omitted: malware droppers, not phishing",
    }
    print(f"  {len(phishing)} phishing URLs")

    print("fetching benign domains (Tranco, sampled across rank bands)...")
    benign = fetch_benign_domains()
    provenance["sources"]["benign_domains"] = {
        "url": SOURCES["tranco"],
        "count": len(benign),
        "licence": "free for research",
        "caveat": "sampled across all rank decades to avoid learning popularity",
    }
    print(f"  {len(benign)} benign domains")

    print("fetching SMS corpus (UCI SMS Spam Collection)...")
    sms = fetch_sms_corpus()
    spam = sum(1 for label, _ in sms if label == "spam")
    provenance["sources"]["sms_corpus"] = {
        "url": SOURCES["uci_sms"],
        "count": len(sms),
        "spam": spam,
        "ham": len(sms) - spam,
        "licence": "UCI ML Repository, free for research",
        "caveat": "English only, dated, not Indian",
    }
    print(f"  {len(sms)} messages ({spam} spam / {len(sms) - spam} ham)")

    PROVENANCE_PATH.write_text(json.dumps(provenance, indent=2), encoding="utf-8")
    print(f"\nprovenance written to {PROVENANCE_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Train the URL (domain-reputation) classifier.

PRD v3.0 sections 6.1, 11.1, 12.4. Closes PS clauses 4 and 5 ("using machine
learning and pretrained classification models") for the URL pillar.

Three data-hygiene decisions, all forced by what the raw feeds actually contain.
Skipping any of them produces an impressive number and a useless model.

1. **Shared-hosting phishing is excluded.** 54% of PhishTank/OpenPhish URLs sit
   on registrable domains that also appear in the benign list: google.com (7,141
   entries), weebly.com, pages.dev, firebaseapp.com, bit.ly, dropbox.com. Those
   are phishing pages on legitimate infrastructure. No domain-level model can
   separate them, because the domain genuinely is benign. Training on them
   teaches the model that google.com is malicious.

   This narrows the model to *maliciously registered* domains. Phishing on
   shared platforms is a real gap, addressed by page-content analysis (section
   6.2) and blocklists, not here. Say so rather than hiding it.

2. **One row per registrable domain.** The feeds carry 5.7 URLs per domain on
   average. Leaving them as separate rows would put the same domain in both train
   and test, which is leakage dressed as a large dataset.

3. **Domain-only features.** See `url_features` for why subdomains and paths are
   excluded.

Run:  python -m ml.train_url
"""

from __future__ import annotations

import json
import sys
from urllib.parse import urlsplit

import joblib
import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.inspection import permutation_importance
from sklearn.metrics import (
    average_precision_score,
    classification_report,
    confusion_matrix,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

from .paths import ARTIFACT_DIR, RAW_DIR, URL_MODEL_PATH, ensure_dirs
from .url_features import FEATURE_NAMES, extract_many, registrable_of

RANDOM_SEED = 20260819


def load_domains() -> tuple[list[str], list[str], dict[str, int]]:
    """Return (malicious_domains, benign_domains, stats)."""
    phishing_urls = [
        line.strip()
        for line in (RAW_DIR / "phishing_urls.txt").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    benign = [
        line.strip().lower()
        for line in (RAW_DIR / "benign_domains.txt").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    benign_set = set(benign)

    phishing_domains: set[str] = set()
    unparsed = 0
    for url in phishing_urls:
        try:
            host = (urlsplit(url).hostname or "").lower()
        except ValueError:
            unparsed += 1
            continue
        if not host:
            unparsed += 1
            continue
        phishing_domains.add(registrable_of(host))

    # Decision 1: drop anything whose registrable domain is legitimately in use.
    shared_hosting = phishing_domains & benign_set
    malicious = sorted(phishing_domains - benign_set)

    stats = {
        "phishing_urls": len(phishing_urls),
        "unparsed": unparsed,
        "phishing_unique_domains": len(phishing_domains),
        "excluded_shared_hosting": len(shared_hosting),
        "malicious_domains": len(malicious),
        "benign_domains": len(benign),
    }
    return malicious, sorted(benign_set), stats


def main() -> int:
    ensure_dirs()
    malicious, benign, stats = load_domains()

    print("=== data ===")
    for key, value in stats.items():
        print(f"  {key:26s} {value}")

    if len(malicious) < 500:
        print("\nERROR: too few malicious domains to train on", file=sys.stderr)
        return 1

    domains = malicious + benign
    labels = np.array([1] * len(malicious) + [0] * len(benign))
    features = np.array(extract_many(domains), dtype=np.float64)

    x_train, x_test, y_train, y_test, d_train, d_test = train_test_split(
        features,
        labels,
        np.array(domains),
        test_size=0.25,
        random_state=RANDOM_SEED,
        stratify=labels,
    )

    print(f"\n  train {len(y_train)} ({y_train.sum()} malicious)")
    print(f"  test  {len(y_test)} ({y_test.sum()} malicious)")

    base = HistGradientBoostingClassifier(
        max_iter=300,
        learning_rate=0.08,
        max_depth=6,
        l2_regularization=1.0,
        random_state=RANDOM_SEED,
        early_stopping=True,
        validation_fraction=0.15,
    )
    # Calibration matters here: the fusion engine maps probability onto a
    # severity band, so a probability that does not mean what it says would
    # distort every downstream verdict.
    model = CalibratedClassifierCV(base, method="isotonic", cv=3)
    model.fit(x_train, y_train)

    proba = model.predict_proba(x_test)[:, 1]
    predictions = (proba >= 0.5).astype(int)

    print("\n=== held-out performance ===")
    print(f"  ROC AUC          {roc_auc_score(y_test, proba):.4f}")
    print(f"  PR AUC           {average_precision_score(y_test, proba):.4f}")
    print()
    print(
        classification_report(
            y_test, predictions, target_names=["benign", "malicious"], digits=4
        )
    )
    matrix = confusion_matrix(y_test, predictions)
    print("  confusion matrix (rows true, cols pred)")
    print(f"    benign     {matrix[0]}")
    print(f"    malicious  {matrix[1]}")

    # Precision at a high threshold. The model can only ever raise AMBER
    # (section 14.2), but a noisy AMBER still costs trust, so we record what a
    # conservative operating point buys.
    print("\n=== precision at higher thresholds ===")
    for threshold in (0.5, 0.7, 0.8, 0.9, 0.95):
        flagged = proba >= threshold
        if flagged.sum() == 0:
            continue
        precision = y_test[flagged].mean()
        recall = flagged[y_test == 1].mean()
        print(
            f"  p>={threshold:.2f}  precision {precision:.4f}  "
            f"recall {recall:.4f}  flagged {int(flagged.sum())}"
        )

    print("\n=== leakage probe: permutation importance ===")
    print("  (a single dominant feature usually means a source artifact)")
    importance = permutation_importance(
        model, x_test, y_test, n_repeats=5, random_state=RANDOM_SEED, scoring="roc_auc"
    )
    ranked = sorted(
        zip(FEATURE_NAMES, importance.importances_mean), key=lambda p: -p[1]
    )
    for name, score in ranked[:10]:
        print(f"    {name:22s} {score:+.4f}")

    top_share = ranked[0][1] / max(sum(max(s, 0) for _, s in ranked), 1e-9)
    print(f"\n  top feature accounts for {top_share:.1%} of total importance")
    if top_share > 0.6:
        print("  WARNING: one feature dominates; check for a source artifact")

    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "model": model,
            "feature_names": list(FEATURE_NAMES),
            "trained_at": __import__("datetime").datetime.now(
                __import__("datetime").timezone.utc
            ).isoformat(),
            "data_stats": stats,
            "metrics": {
                "roc_auc": float(roc_auc_score(y_test, proba)),
                "pr_auc": float(average_precision_score(y_test, proba)),
            },
            "scope": (
                "Registrable-domain reputation only. Excludes phishing hosted on "
                "shared platforms, and uses no subdomain or path features."
            ),
        },
        URL_MODEL_PATH,
    )
    print(f"\nmodel written to {URL_MODEL_PATH}")

    (ARTIFACT_DIR / "url_model_report.json").write_text(
        json.dumps(
            {
                "data_stats": stats,
                "roc_auc": float(roc_auc_score(y_test, proba)),
                "pr_auc": float(average_precision_score(y_test, proba)),
                "feature_importance": {n: float(s) for n, s in ranked},
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

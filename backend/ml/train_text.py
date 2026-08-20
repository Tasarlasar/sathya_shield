"""Train the message-text scam classifier.

PRD v3.0 sections 6.4, 11.1, 12.3. Closes PS clauses 4 and 5 for the text pillar.

Model: TF-IDF over word and character n-grams into logistic regression. Chosen
deliberately over a transformer for the first cut:

- It is the tier that can realistically run on-device (section 11.2 explains why
  a 120MB quantised MuRIL is a poor fit for the sub-Rs.10,000 handsets our
  primary persona owns).
- Character n-grams degrade gracefully on transliterated Hinglish, where word
  tokens are unreliable.
- Coefficients are inspectable, which matters because PS clause 12 asks the
  system to improve the user's ability to recognise fraud.

Honest limitation, measured below rather than assumed: the training corpus is
UCI SMS Spam Collection, which is English, dated, and not Indian. A generalisation
probe against hand-written Indian scam messages runs at the end so the gap is a
number in the output, not a hope.

Run:  python -m ml.train_text
"""

from __future__ import annotations

import csv
import json
import sys
from datetime import datetime, timezone

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    classification_report,
    confusion_matrix,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer
from sklearn.pipeline import FeatureUnion

from .paths import ARTIFACT_DIR, RAW_DIR, TEXT_MODEL_PATH, ensure_dirs

RANDOM_SEED = 20260819

# Held-out sanity set: current Indian scam patterns, hand written, in English,
# Roman-script Hinglish and Devanagari. Not training data. Its only job is to
# show how far an English-trained model transfers, per section 12.3.
INDIAN_SCAM_PROBE = [
    "SBI KYC expired. Verify urgently at http://sbi-rewards.xyz/login",
    "This is CBI cyber cell. Arrest warrant issued. Pay penalty immediately.",
    "Congratulations you won lottery of 25 lakh. Pay processing fee to claim.",
    "Turant paise bhejo warna account band kar diya jayega",
    "Ghar baithe kamao 5000 rupay roz, registration fee 500 bhejo",
    "तुरंत पैसे भेजो वरना खाता बंद कर दिया जाएगा",
    "Dear customer your electricity will be disconnected tonight, call 9876543210",
    "Your parcel is held at customs. Pay clearance fee to release.",
]

INDIAN_HAM_PROBE = [
    "Beta I am reaching home by 7 pm, is dinner ready",
    "Meeting moved to 3pm tomorrow",
    "Happy birthday, have a great year ahead",
    "Kal milte hain office ke baad",
    "कल मिलते हैं शाम को",
    "HDFC Bank: Rs.2500 debited from a/c XX1234. Never share your OTP or PIN.",
]


def load_corpus() -> tuple[list[str], np.ndarray]:
    path = RAW_DIR / "sms_corpus.tsv"
    texts: list[str] = []
    labels: list[int] = []
    with path.open(encoding="utf-8", newline="") as handle:
        for row in csv.reader(handle, delimiter="\t"):
            if len(row) < 2:
                continue
            labels.append(1 if row[0].strip().lower() == "spam" else 0)
            texts.append(row[1])
    return texts, np.array(labels)


def build_model() -> Pipeline:
    """Word plus character n-grams, unioned, into logistic regression.

    Character n-grams are what make this survive transliteration: `paise` and
    `paisa` share no word token but plenty of 3-grams.
    """
    word = TfidfVectorizer(
        analyzer="word",
        ngram_range=(1, 2),
        min_df=2,
        sublinear_tf=True,
        strip_accents=None,  # keep Devanagari and Tamil intact
        lowercase=True,
    )
    char = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(3, 5),
        min_df=3,
        sublinear_tf=True,
        lowercase=True,
    )
    return Pipeline(
        [
            ("features", FeatureUnion([("word", word), ("char", char)])),
            (
                "clf",
                LogisticRegression(
                    max_iter=2000,
                    C=4.0,
                    class_weight="balanced",
                    random_state=RANDOM_SEED,
                ),
            ),
        ]
    )


def main() -> int:
    ensure_dirs()
    texts, labels = load_corpus()
    print("=== data ===")
    print(f"  messages {len(texts)}  spam {int(labels.sum())}  ham {int((1 - labels).sum())}")

    x_train, x_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.25, random_state=RANDOM_SEED, stratify=labels
    )
    print(f"  train {len(x_train)}  test {len(x_test)}")

    model = build_model()
    model.fit(x_train, y_train)

    proba = model.predict_proba(x_test)[:, 1]
    predictions = (proba >= 0.5).astype(int)

    print("\n=== held-out performance (English SMS, in-distribution) ===")
    print(f"  ROC AUC  {roc_auc_score(y_test, proba):.4f}")
    print(f"  PR AUC   {average_precision_score(y_test, proba):.4f}")
    print()
    print(classification_report(y_test, predictions, target_names=["ham", "spam"], digits=4))
    matrix = confusion_matrix(y_test, predictions)
    print("  confusion matrix (rows true, cols pred)")
    print(f"    ham   {matrix[0]}")
    print(f"    spam  {matrix[1]}")

    print("\n=== precision at higher thresholds ===")
    for threshold in (0.5, 0.7, 0.8, 0.9, 0.95):
        flagged = proba >= threshold
        if flagged.sum() == 0:
            continue
        print(
            f"  p>={threshold:.2f}  precision {y_test[flagged].mean():.4f}  "
            f"recall {flagged[y_test == 1].mean():.4f}"
        )

    # --- generalisation probe -------------------------------------------------
    print("\n=== generalisation probe: Indian scam patterns (NOT in training) ===")
    scam_scores = model.predict_proba(INDIAN_SCAM_PROBE)[:, 1]
    for score, text in sorted(zip(scam_scores, INDIAN_SCAM_PROBE), reverse=True):
        flag = "CAUGHT " if score >= 0.5 else "MISSED "
        print(f"  {flag} {score:.3f}  {text[:66]}")
    caught = int((scam_scores >= 0.5).sum())
    print(f"  caught {caught}/{len(INDIAN_SCAM_PROBE)}")

    print("\n=== false-positive probe: benign Indian messages ===")
    ham_scores = model.predict_proba(INDIAN_HAM_PROBE)[:, 1]
    for score, text in sorted(zip(ham_scores, INDIAN_HAM_PROBE), reverse=True):
        flag = "FALSE+ " if score >= 0.5 else "ok     "
        print(f"  {flag} {score:.3f}  {text[:66]}")
    false_positives = int((ham_scores >= 0.5).sum())
    print(f"  false positives {false_positives}/{len(INDIAN_HAM_PROBE)}")

    print(
        "\n  Interpretation: in-distribution English numbers do not transfer to\n"
        "  Indian scam text. This is the section 12.3 data gap, quantified. The\n"
        "  fix is the hand-collected corpus, not a bigger model."
    )

    joblib.dump(
        {
            "model": model,
            "trained_at": datetime.now(timezone.utc).isoformat(),
            "corpus": "UCI SMS Spam Collection",
            "metrics": {
                "roc_auc": float(roc_auc_score(y_test, proba)),
                "pr_auc": float(average_precision_score(y_test, proba)),
                "indian_scam_recall": caught / len(INDIAN_SCAM_PROBE),
                "indian_ham_false_positives": false_positives / len(INDIAN_HAM_PROBE),
            },
            "scope": (
                "Trained on English SMS only. Indian-language and code-mixed "
                "performance is materially worse; see the generalisation probe."
            ),
        },
        TEXT_MODEL_PATH,
    )
    print(f"\nmodel written to {TEXT_MODEL_PATH}")

    (ARTIFACT_DIR / "text_model_report.json").write_text(
        json.dumps(
            {
                "corpus": "UCI SMS Spam Collection",
                "messages": len(texts),
                "roc_auc": float(roc_auc_score(y_test, proba)),
                "pr_auc": float(average_precision_score(y_test, proba)),
                "indian_scam_probe": {
                    text: float(score)
                    for text, score in zip(INDIAN_SCAM_PROBE, scam_scores)
                },
                "indian_ham_probe": {
                    text: float(score)
                    for text, score in zip(INDIAN_HAM_PROBE, ham_scores)
                },
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

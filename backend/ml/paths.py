"""Filesystem layout for the ML pipeline."""

from __future__ import annotations

from pathlib import Path

ML_DIR = Path(__file__).resolve().parent
BACKEND_DIR = ML_DIR.parent

DATA_DIR = BACKEND_DIR / "data"
RAW_DIR = DATA_DIR / "raw"
ARTIFACT_DIR = BACKEND_DIR / "app" / "artifacts"

URL_MODEL_PATH = ARTIFACT_DIR / "url_model.joblib"
TEXT_MODEL_PATH = ARTIFACT_DIR / "text_model.joblib"
PROVENANCE_PATH = DATA_DIR / "provenance.json"


def ensure_dirs() -> None:
    for path in (DATA_DIR, RAW_DIR, ARTIFACT_DIR):
        path.mkdir(parents=True, exist_ok=True)

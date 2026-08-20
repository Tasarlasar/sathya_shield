"""End-to-end detection pipeline.

Single entry point wiring assembler -> pillars -> fusion -> explanation, so the
Android client, the WhatsApp bot, the web checker and the tests all exercise
exactly the same path. Any divergence between surfaces would be a correctness
bug, not a convenience issue.
"""

from __future__ import annotations

from . import assembler, explain, fusion
from .schemas import Language, MessageInput, Signal, Verdict


def check_message(payload: MessageInput) -> Verdict:
    """Analyse one message and return a complete verdict."""
    message = assembler.assemble(payload)
    signals = assembler.collect_signals(message)
    return _finalise(signals, payload.language, message.has_media)


def check_url(url: str, language: Language = Language.EN) -> Verdict:
    """Analyse a bare URL with no surrounding message."""
    return check_message(MessageInput(text=url, language=language))


def check_email(
    raw_email: str, language: Language = Language.EN, trusted_source: bool = True
) -> Verdict:
    """Analyse a raw RFC 5322 email.

    `trusted_source` reflects whether Authentication-Results headers were
    written by a mail server we control. False for user-pasted text, where those
    headers are attacker-controllable.
    """
    from .schemas import Source

    payload = MessageInput(
        raw_email=raw_email,
        source=Source.EMAIL if trusted_source else Source.WEB,
        language=language,
    )
    return check_message(payload)


def _finalise(
    signals: list[Signal], language: Language, media_present: bool
) -> Verdict:
    band, score, red_eligible = fusion.decide_band(signals)
    ranked = fusion.rank_signals(signals)
    explanation = explain.build_explanation(
        band=band,
        signals=ranked,
        language=language,
        media_present=media_present,
    )
    return Verdict(
        band=band,
        score=score,
        red_eligible=red_eligible,
        signals=ranked,
        explanation=explanation,
        media_present=media_present,
    )

"""Message assembler.

PRD v3.0 sections 7.3 (F21), 14.1.

The unit of analysis is a *message*, not a file. One WhatsApp message may carry
text, a link and a video; one email carries headers, a body and attachments.
Assembling all of that into a single object before any detector runs is what
makes fusion coherent: we end up scoring one artifact with several kinds of
evidence, rather than averaging unrelated scores.

Every capture path (notification listener, share sheet, WhatsApp bot, web
checker, .eml upload) funnels through here, so detection logic is written once.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import text_model, url_model
from .pillars import email_headers, text_intent, url_rules
from .schemas import MessageInput, Signal, Source


@dataclass
class AssembledMessage:
    """Normalised view of one message, ready for detection."""

    text: str
    urls: list[str] = field(default_factory=list)
    upi_handles: list[str] = field(default_factory=list)
    sender: str | None = None
    sender_known: bool = False
    source: Source = Source.MANUAL
    raw_email: str | None = None
    has_media: bool = False

    @property
    def has_email_headers(self) -> bool:
        return bool(self.raw_email and self.raw_email.strip())


def assemble(payload: MessageInput) -> AssembledMessage:
    """Normalise raw input into a single analysable message."""
    text = payload.text or ""

    # An .eml upload carries its own body. Merge it with any supplied text so
    # the text pillar sees the prose regardless of which field was populated.
    if payload.raw_email:
        body = email_headers.email_body_text(payload.raw_email)
        if body and body.strip() and body.strip() not in text:
            text = f"{text}\n{body}".strip() if text else body

    return AssembledMessage(
        text=text,
        urls=url_rules.extract_urls(text),
        upi_handles=url_rules.extract_upi_handles(text),
        sender=payload.sender,
        sender_known=payload.sender_known,
        source=payload.source,
        raw_email=payload.raw_email,
        has_media=payload.has_media,
    )


def collect_signals(message: AssembledMessage) -> list[Signal]:
    """Run every applicable pillar over an assembled message.

    Pillars are independent and order-free; each returns a list of `Signal`.
    Only the pillars relevant to the available inputs are invoked, so a plain
    SMS does not pay the cost of email parsing.
    """
    signals: list[Signal] = []

    if message.urls:
        signals.extend(url_rules.analyse_urls(message.urls))

    if message.upi_handles:
        signals.extend(
            url_rules.analyse_upi(message.text, sender_known=message.sender_known)
        )

    if message.has_email_headers:
        # Authentication-Results headers are only trustworthy when written by a
        # mail server, not when a user pasted the text. Section 6.3.
        trust = message.source is Source.EMAIL
        signals.extend(
            email_headers.analyse_email(
                message.raw_email or "", trust_auth_headers=trust
            )
        )

    if message.text:
        signals.extend(
            text_intent.analyse_text(
                message.text, sender_known=message.sender_known
            )
        )

    # Trained models run last and contribute NON-deterministic signals only.
    # Under the section 14.2 policy these can raise a verdict to AMBER but can
    # never open the RED gate, no matter how confident they are. Both degrade to
    # returning nothing when their artifact is absent, so the pipeline is
    # unaffected on a checkout that has not trained them.
    if message.urls:
        signals.extend(url_model.analyse_urls(message.urls))

    if message.text:
        signals.extend(text_model.analyse_text(message.text))

    return signals

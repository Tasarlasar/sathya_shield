"""Core evidence and verdict types.

The single most important field in this module is `Signal.deterministic`.

PRD v3.0 section 14.2 requires that only deterministic rule hits may raise a RED
verdict; probabilistic model outputs are capped at AMBER. That invariant is
enforced in `app.fusion`, but it is only expressible because every signal
carries its own provenance. Any new detector MUST set `deterministic` honestly:

    deterministic=True   a rule fired on a fact we directly observed
                         (this URL ends in .apk, this DKIM check failed)
    deterministic=False  a model produced a score
                         (classifier thinks this text is 0.82 scam-like)

Setting `deterministic=True` on a model output would let a probabilistic
detector seize a frightened user's screen. That is the specific failure this
codebase is designed to prevent.
"""

from __future__ import annotations

from enum import Enum, IntEnum

from pydantic import BaseModel, Field


class Pillar(str, Enum):
    """Which detector produced a signal."""

    URL = "url"
    WEBSITE = "website"
    EMAIL = "email"
    TEXT = "text"
    VIDEO = "video"
    AUDIO = "audio"
    SENDER = "sender"


class Severity(IntEnum):
    """How much a single signal contributes to concern.

    CRITICAL is reserved for signals that are, on their own, near-conclusive
    evidence of fraud for our target user. A single deterministic CRITICAL
    signal is sufficient to raise RED. Use it sparingly.
    """

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class Band(str, Enum):
    """The three-state verdict (PRD section 8.1).

    Deliberately not a number. The numeric score exists only on drill-down for
    judges and the secondary persona.
    """

    GREEN = "green"
    AMBER = "amber"
    RED = "red"


class Language(str, Enum):
    EN = "en"
    HI = "hi"
    TA = "ta"


class Signal(BaseModel):
    """One piece of evidence produced by one detector."""

    code: str = Field(
        description="Stable machine key, e.g. URL_APK_LINK. Used to look up "
        "hand-authored explanation templates per language."
    )
    pillar: Pillar
    severity: Severity
    deterministic: bool = Field(
        description="True for observed-fact rules, False for model scores. "
        "Gates RED eligibility. See module docstring."
    )
    weight: float = Field(
        default=1.0,
        ge=0.0,
        description="Relative contribution to the aggregate risk score.",
    )
    detail: dict[str, str | int | float | bool] = Field(
        default_factory=dict,
        description="Structured facts interpolated into explanation text, "
        "e.g. {'domain': 'sbi-rewards.xyz', 'age_days': 4}.",
    )

    @property
    def contribution(self) -> float:
        """Risk points this signal adds before normalisation."""
        return float(self.severity) * self.weight


class Explanation(BaseModel):
    """Plain-language output for one verdict (PRD sections 8.2-8.4)."""

    language: Language
    headline: str = Field(description="Short verdict phrase, e.g. 'This is fake'.")
    action: str = Field(
        description="What to DO. Never a diagnosis. PRD section 8.3."
    )
    reasons: list[str] = Field(
        default_factory=list,
        description="Named evidence in plain language, most severe first.",
    )
    spoken: str = Field(
        description="Single string for text-to-speech. Headline plus action."
    )


class Verdict(BaseModel):
    """The complete result of analysing one message."""

    band: Band
    score: float = Field(
        ge=0.0,
        le=100.0,
        description="Aggregate risk 0-100. Drill-down only, never the primary "
        "output shown to the primary persona.",
    )
    red_eligible: bool = Field(
        description="Whether any deterministic signal authorised a RED verdict. "
        "If False, the band cannot be RED regardless of score."
    )
    signals: list[Signal] = Field(default_factory=list)
    explanation: Explanation
    media_present: bool = Field(
        default=False,
        description="True when the message references media we could not scan "
        "passively. Drives the one-tap check prompt (PRD section 5.6).",
    )

    @property
    def interrupts(self) -> bool:
        """Whether this verdict may take over the screen.

        Only RED interrupts. AMBER badges quietly (PRD section 8.1, F34).
        """
        return self.band is Band.RED


class Source(str, Enum):
    """Where a message reached us. Affects how much we trust its metadata."""

    NOTIFICATION = "notification"  # passive capture, text only (PRD 5.6)
    SHARE = "share"  # user-initiated share sheet
    BOT = "bot"  # WhatsApp forward
    WEB = "web"  # web checker paste
    EMAIL = "email"  # .eml upload
    MANUAL = "manual"


class MediaKind(str, Enum):
    IMAGE = "image"
    VIDEO = "video"
    AUDIO = "audio"


class MessageInput(BaseModel):
    """Raw input to the pipeline, before assembly."""

    text: str = Field(default="", description="Message body or pasted text.")
    sender: str | None = Field(
        default=None, description="Phone number, handle or email address."
    )
    sender_known: bool = Field(
        default=False,
        description="True if the sender is a saved contact. An unknown sender "
        "amplifies other signals but is never a finding on its own.",
    )
    source: Source = Source.MANUAL
    raw_email: str | None = Field(
        default=None, description="Full RFC 5322 source for the email pillar."
    )
    has_media: bool = Field(
        default=False,
        description="Message references media. Under passive capture we cannot "
        "read it (PRD 5.6), which drives the one-tap check prompt.",
    )
    media_kind: MediaKind | None = None
    language: Language = Language.EN

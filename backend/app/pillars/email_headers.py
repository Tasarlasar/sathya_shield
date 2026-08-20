"""Email pillar: header forensics.

PRD v3.0 sections 6.3, 7.2 (F15). Closes PS clauses 1 and 7.

The substance of email phishing detection lives in the headers, not the prose.
Headers are cheap to parse, deterministic, need no GPU, and produce unusually
specific explanations ("the sender's name says HDFC Bank but the message was
actually sent from a Gmail account"), which is exactly what PS clause 12 asks
for.

Every signal in this module is deterministic. Uses only the standard library
`email` package, so there is no parsing dependency to audit.
"""

from __future__ import annotations

import re
from email import message_from_string, policy
from email.message import EmailMessage
from email.utils import getaddresses, parseaddr

from ..schemas import Pillar, Severity, Signal
from .url_rules import (
    FREEMAIL_DOMAINS,
    brand_owns_domain,
    brand_tokens_in_display_name,
    brand_tokens_not_owned,
    registrable_domain,
)

# Attachment extensions that execute code or are used to smuggle it.
EXECUTABLE_EXTENSIONS = frozenset(
    {
        "apk", "exe", "scr", "com", "pif", "bat", "cmd", "js", "jse", "vbs",
        "vbe", "wsf", "wsh", "hta", "jar", "msi", "ps1", "reg", "lnk", "iso",
        "img", "vhd", "dll", "cpl", "msc",
    }
)

# Macro-enabled Office formats.
MACRO_EXTENSIONS = frozenset({"docm", "xlsm", "pptm", "dotm", "xltm", "potm", "xlsb"})

# Extensions that are harmless as documents but are a classic phishing vector
# when delivered as an attachment, because they render a local login form.
HTML_ATTACHMENT_EXTENSIONS = frozenset({"html", "htm", "shtml", "mht", "mhtml"})

_AUTH_RESULT_RE = re.compile(
    r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.IGNORECASE
)

# SPF/DKIM/DMARC outcomes that indicate the sender could not be verified.
_FAIL_STATES = frozenset({"fail", "softfail", "permerror", "temperror", "none", "neutral"})
_HARD_FAIL_STATES = frozenset({"fail", "permerror"})

_DOUBLE_EXT_RE = re.compile(
    r"\.(pdf|doc|docx|xls|xlsx|jpg|jpeg|png|txt|zip)\.([a-z0-9]{2,4})$", re.IGNORECASE
)


def parse_email(raw: str) -> EmailMessage:
    """Parse a raw RFC 5322 message. Never raises on malformed input."""
    return message_from_string(raw, policy=policy.default)  # type: ignore[return-value]


def _domain_of(address: str) -> str:
    """Registrable domain of an email address, or empty string."""
    if "@" not in address:
        return ""
    return registrable_domain(address.rsplit("@", 1)[1].strip().lower())


def _auth_results(msg: EmailMessage) -> dict[str, str]:
    """Collect SPF/DKIM/DMARC outcomes from authentication headers.

    Reads `Authentication-Results` plus the older `Received-SPF` and
    `DKIM-Signature` presence. Trusting these headers means trusting the
    receiving mail server that wrote them, which is correct for mail we
    received but must not be trusted for a message pasted in by a user. The
    caller signals that distinction via `trust_auth_headers`.
    """
    found: dict[str, str] = {}
    headers = msg.get_all("Authentication-Results") or []
    headers += msg.get_all("ARC-Authentication-Results") or []
    for header in headers:
        for mech, result in _AUTH_RESULT_RE.findall(str(header)):
            mech_l = mech.lower()
            result_l = result.lower()
            # Keep the worst outcome seen for each mechanism.
            if mech_l not in found or result_l in _HARD_FAIL_STATES:
                found[mech_l] = result_l

    if "spf" not in found:
        for header in msg.get_all("Received-SPF") or []:
            first = str(header).strip().split(None, 1)
            if first:
                found["spf"] = first[0].lower().rstrip(":")
            break
    return found


def _attachment_names(msg: EmailMessage) -> list[str]:
    names: list[str] = []
    if not msg.is_multipart():
        name = msg.get_filename()
        return [name] if name else []
    for part in msg.walk():
        if part.is_multipart():
            continue
        name = part.get_filename()
        disposition = str(part.get("Content-Disposition") or "")
        if name or "attachment" in disposition.lower():
            names.append(name or "unnamed")
    return names


def analyse_email(raw: str, trust_auth_headers: bool = True) -> list[Signal]:
    """Run header forensics over a raw email.

    Args:
        raw: the full message source, ideally including headers.
        trust_auth_headers: whether `Authentication-Results` was written by a
            mail server we control. False for user-pasted content, where those
            headers are attacker-controllable and must be ignored rather than
            believed.
    """
    signals: list[Signal] = []
    if not raw or not raw.strip():
        return signals

    msg = parse_email(raw)

    from_name, from_addr = parseaddr(str(msg.get("From") or ""))
    from_domain = _domain_of(from_addr)

    # --- Missing From ------------------------------------------------------
    if not from_addr:
        signals.append(
            Signal(
                code="EMAIL_NO_FROM",
                pillar=Pillar.EMAIL,
                severity=Severity.MEDIUM,
                deterministic=True,
                detail={},
            )
        )

    # --- Display-name brand claim vs actual sending domain ----------------
    claimed_brands = brand_tokens_in_display_name(from_name)
    impersonated = [
        brand
        for brand in claimed_brands
        if from_domain and not brand_owns_domain(brand, from_domain)
    ]

    if impersonated and from_domain in FREEMAIL_DOMAINS:
        # Near-conclusive. A bank or government body never sends from Gmail.
        signals.append(
            Signal(
                code="EMAIL_BRAND_FROM_FREEMAIL",
                pillar=Pillar.EMAIL,
                severity=Severity.CRITICAL,
                deterministic=True,
                weight=1.5,
                detail={
                    "brand": impersonated[0],
                    "display_name": from_name[:80],
                    "domain": from_domain,
                },
            )
        )
    elif impersonated:
        signals.append(
            Signal(
                code="EMAIL_DISPLAY_NAME_SPOOF",
                pillar=Pillar.EMAIL,
                severity=Severity.HIGH,
                deterministic=True,
                weight=1.3,
                detail={
                    "brand": impersonated[0],
                    "display_name": from_name[:80],
                    "domain": from_domain,
                },
            )
        )

    # --- Sender domain itself is a brand lookalike ------------------------
    if from_addr and "@" in from_addr:
        sender_host = from_addr.rsplit("@", 1)[1].lower()
        lookalikes = brand_tokens_not_owned(sender_host)
        if lookalikes:
            signals.append(
                Signal(
                    code="EMAIL_SENDER_DOMAIN_LOOKALIKE",
                    pillar=Pillar.EMAIL,
                    severity=Severity.HIGH,
                    deterministic=True,
                    weight=1.3,
                    detail={"brand": lookalikes[0], "domain": sender_host},
                )
            )

    # --- Display name is itself a different email address -----------------
    # "support@hdfcbank.com" <attacker@evil.ru> renders as the safe address in
    # most clients while delivering from the attacker's domain.
    if "@" in from_name:
        _, embedded = parseaddr(from_name)
        embedded_domain = _domain_of(embedded or from_name)
        if embedded_domain and from_domain and embedded_domain != from_domain:
            signals.append(
                Signal(
                    code="EMAIL_ADDRESS_IN_DISPLAY_NAME",
                    pillar=Pillar.EMAIL,
                    severity=Severity.HIGH,
                    deterministic=True,
                    weight=1.3,
                    detail={"display_name": from_name[:80], "actual": from_domain},
                )
            )

    # --- Reply-To divergence ----------------------------------------------
    # Scored MEDIUM, not HIGH. Legitimate mailing lists, ticketing systems and
    # marketing platforms routinely set a Reply-To on a different domain, so
    # treating this as strong evidence on its own would be a false-positive
    # factory. It escalates only in combination (see fusion).
    reply_to_pairs = getaddresses([str(h) for h in (msg.get_all("Reply-To") or [])])
    for _, reply_addr in reply_to_pairs:
        reply_domain = _domain_of(reply_addr)
        if reply_domain and from_domain and reply_domain != from_domain:
            severity = (
                Severity.HIGH
                if (impersonated or reply_domain in FREEMAIL_DOMAINS and claimed_brands)
                else Severity.MEDIUM
            )
            signals.append(
                Signal(
                    code="EMAIL_REPLY_TO_MISMATCH",
                    pillar=Pillar.EMAIL,
                    severity=severity,
                    deterministic=True,
                    weight=1.1,
                    detail={"from_domain": from_domain, "reply_to_domain": reply_domain},
                )
            )
            break

    # --- Return-Path / envelope mismatch ----------------------------------
    _, return_path = parseaddr(str(msg.get("Return-Path") or ""))
    return_domain = _domain_of(return_path)
    if return_domain and from_domain and return_domain != from_domain:
        signals.append(
            Signal(
                code="EMAIL_RETURN_PATH_MISMATCH",
                pillar=Pillar.EMAIL,
                severity=Severity.LOW,
                deterministic=True,
                detail={"from_domain": from_domain, "return_path_domain": return_domain},
            )
        )

    # --- SPF / DKIM / DMARC -----------------------------------------------
    if trust_auth_headers:
        auth = _auth_results(msg)
        failed = sorted(
            mech for mech, result in auth.items() if result in _FAIL_STATES
        )
        hard_failed = sorted(
            mech for mech, result in auth.items() if result in _HARD_FAIL_STATES
        )
        if hard_failed:
            signals.append(
                Signal(
                    code="EMAIL_AUTH_HARD_FAIL",
                    pillar=Pillar.EMAIL,
                    severity=Severity.HIGH,
                    deterministic=True,
                    weight=1.4,
                    detail={
                        "mechanisms": ",".join(hard_failed),
                        "results": ",".join(f"{m}={auth[m]}" for m in hard_failed),
                    },
                )
            )
        elif failed:
            signals.append(
                Signal(
                    code="EMAIL_AUTH_WEAK",
                    pillar=Pillar.EMAIL,
                    severity=Severity.MEDIUM,
                    deterministic=True,
                    detail={"mechanisms": ",".join(failed)},
                )
            )
        elif not auth:
            signals.append(
                Signal(
                    code="EMAIL_AUTH_ABSENT",
                    pillar=Pillar.EMAIL,
                    severity=Severity.LOW,
                    deterministic=True,
                    detail={},
                )
            )

    # --- Received chain ---------------------------------------------------
    received = msg.get_all("Received") or []
    if not received:
        signals.append(
            Signal(
                code="EMAIL_NO_RECEIVED_CHAIN",
                pillar=Pillar.EMAIL,
                severity=Severity.LOW,
                deterministic=True,
                detail={},
            )
        )

    # --- Attachments ------------------------------------------------------
    for name in _attachment_names(msg):
        lowered = name.lower()
        ext = lowered.rsplit(".", 1)[-1] if "." in lowered else ""

        if _DOUBLE_EXT_RE.search(lowered):
            signals.append(
                Signal(
                    code="EMAIL_ATTACHMENT_DOUBLE_EXTENSION",
                    pillar=Pillar.EMAIL,
                    severity=Severity.CRITICAL,
                    deterministic=True,
                    weight=1.5,
                    detail={"filename": name[:120]},
                )
            )
        elif ext in EXECUTABLE_EXTENSIONS:
            signals.append(
                Signal(
                    code="EMAIL_ATTACHMENT_EXECUTABLE",
                    pillar=Pillar.EMAIL,
                    severity=Severity.CRITICAL,
                    deterministic=True,
                    weight=1.5,
                    detail={"filename": name[:120], "ext": ext},
                )
            )
        elif ext in MACRO_EXTENSIONS:
            signals.append(
                Signal(
                    code="EMAIL_ATTACHMENT_MACRO",
                    pillar=Pillar.EMAIL,
                    severity=Severity.HIGH,
                    deterministic=True,
                    weight=1.2,
                    detail={"filename": name[:120], "ext": ext},
                )
            )
        elif ext in HTML_ATTACHMENT_EXTENSIONS:
            signals.append(
                Signal(
                    code="EMAIL_ATTACHMENT_HTML",
                    pillar=Pillar.EMAIL,
                    severity=Severity.HIGH,
                    deterministic=True,
                    weight=1.2,
                    detail={"filename": name[:120], "ext": ext},
                )
            )

    return signals


def email_body_text(raw: str) -> str:
    """Extract the plain-text body for handoff to the text pillar."""
    if not raw or not raw.strip():
        return ""
    msg = parse_email(raw)
    try:
        body = msg.get_body(preferencelist=("plain", "html"))
    except Exception:
        body = None
    if body is None:
        payload = msg.get_payload(decode=False)
        return payload if isinstance(payload, str) else ""
    content = body.get_content()
    return content if isinstance(content, str) else ""

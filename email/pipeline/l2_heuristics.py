"""
pipeline/l2_heuristics.py — Deterministic rule engine (mirrors EOP Transport Rules).

No ML — pure pattern matching. Each rule is an independent function returning
(score_delta, reason_string | None). Rules are additive; the orchestrator
collects all fired reasons for the pipeline result.

Maximum contribution: 4 points (L2H_CAP in scoring.py).
"""

import re
import math
import logging
from email.utils import parseaddr

from pipeline.email_parser import EmailContext

logger = logging.getLogger(__name__)

# ── Shared helpers ────────────────────────────────────────────────────────────
_FREE_DOMAINS = frozenset({
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "aol.com", "protonmail.com", "icloud.com", "live.com",
    "mail.com", "zoho.com", "yandex.com", "gmx.com",
})

_INSTITUTIONAL_KEYWORDS = re.compile(
    r'\b(university|college|institute|corp|inc|ltd|bank|paypal|'
    r'amazon|microsoft|google|apple|netflix|linkedin|facebook|'
    r'instagram|twitter|support|helpdesk|it\s*support)\b',
    re.IGNORECASE,
)

_URGENCY_PATTERNS = re.compile(
    r'\b(act now|immediate action|urgent|account suspended|'
    r'verify immediately|limited time|expires? (today|soon|in \d+ hours?)|'
    r'respond within|time sensitive|action required)\b',
    re.IGNORECASE,
)

_CREDENTIAL_PATTERNS = re.compile(
    r'\b(click here to verify|confirm your password|login to restore|'
    r'your account (will be|has been) (closed|suspended|deactivated)|'
    r'verify your (account|identity|email)|update your (payment|billing)|'
    r'enter your (credentials|password|pin)|reset your password)\b',
    re.IGNORECASE,
)

_PIVOT_PATTERNS = re.compile(
    r'\b(whatsapp|telegram|signal|text me|message me|contact me (at|on|via)|'
    r'reach me (at|on)|my (number|phone) is)\b',
    re.IGNORECASE,
)

_SUSPICIOUS_SENDER_PREFIX = re.compile(
    r'^(no-?reply[-.]|security[-.]|admin[-.]|noreply[@]|support[-.])',
    re.IGNORECASE,
)


def _get_domain(email_str: str) -> str:
    """Extract domain from a full email address string."""
    _, addr = parseaddr(email_str)
    if "@" in addr:
        return addr.split("@", 1)[1].lower().strip()
    return ""


def _shannon_entropy(s: str) -> float:
    """Compute Shannon entropy of a string (used for domain randomness check)."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


# ── Individual rule functions ─────────────────────────────────────────────────

def _rule_reply_to_mismatch(ctx: EmailContext) -> tuple[int, str | None]:
    """
    Reply-To domain differs from From domain — a classic phishing redirect trick.
    Sender wants responses to go to an attacker-controlled address.
    """
    if not ctx.reply_to:
        return 0, None
    from_domain = ctx.sender_domain
    reply_domain = _get_domain(ctx.reply_to)
    if reply_domain and from_domain and reply_domain != from_domain:
        return 2, f"L2H:reply_to_mismatch (from={from_domain}, reply_to={reply_domain})"
    return 0, None


def _rule_pivot_to_external(ctx: EmailContext) -> tuple[int, str | None]:
    """
    Body contains pivot language directing the user to WhatsApp / Telegram /
    an external contact — used to move phishing off email into unmonitored channels.
    """
    if _PIVOT_PATTERNS.search(ctx.body_text):
        return 2, "L2H:pivot_to_external"
    return 0, None


def _rule_urgency_language(ctx: EmailContext) -> tuple[int, str | None]:
    """Urgency or scarcity language designed to bypass critical thinking."""
    if _URGENCY_PATTERNS.search(ctx.body_text) or _URGENCY_PATTERNS.search(ctx.subject):
        return 1, "L2H:urgency_language"
    return 0, None


def _rule_credential_harvesting(ctx: EmailContext) -> tuple[int, str | None]:
    """Phrases associated with credential collection / account-takeover phishing."""
    if _CREDENTIAL_PATTERNS.search(ctx.body_text):
        return 2, "L2H:credential_harvesting"
    return 0, None


def _rule_blank_body_with_attachment(ctx: EmailContext) -> tuple[int, str | None]:
    """
    Very short/empty body + attachment = delivery vehicle phishing.
    All the malicious content is in the attachment.
    """
    body_short = len(ctx.body_text.strip()) < 30
    has_attachment = len(ctx.attachments) > 0
    if body_short and has_attachment:
        return 3, f"L2H:blank_body_with_attachment (body_len={len(ctx.body_text.strip())})"
    return 0, None


def _rule_suspicious_sender_pattern(ctx: EmailContext) -> tuple[int, str | None]:
    """
    Sender address starts with common spoofed prefix patterns (no-reply-, security-)
    AND uses a free email domain — hallmark of bulk-sent phishing.
    """
    _, addr = parseaddr(ctx.sender)
    local = addr.split("@")[0] if "@" in addr else ""
    is_free = ctx.sender_domain in _FREE_DOMAINS
    has_prefix = bool(_SUSPICIOUS_SENDER_PREFIX.match(local))
    if has_prefix and is_free:
        return 1, f"L2H:suspicious_sender_pattern (addr={addr})"
    return 0, None


def _rule_free_domain_impersonation(ctx: EmailContext) -> tuple[int, str | None]:
    """
    Sender uses a free email provider (gmail, yahoo, etc.) but the display name
    implies an institutional identity (bank, university, corp, tech company).
    """
    display_name = ctx.sender.split("<")[0].strip().strip('"')
    is_free = ctx.sender_domain in _FREE_DOMAINS
    has_institutional = bool(_INSTITUTIONAL_KEYWORDS.search(display_name))
    if is_free and has_institutional:
        return 2, (
            f"L2H:free_domain_impersonation "
            f"(display={display_name!r}, domain={ctx.sender_domain})"
        )
    return 0, None


def _rule_excessive_urls(ctx: EmailContext) -> tuple[int, str | None]:
    """More than 5 URLs suggests link-spam or a phishing kit with decoy links."""
    if len(ctx.urls) > 5:
        return 1, f"L2H:excessive_urls (count={len(ctx.urls)})"
    return 0, None


def _rule_newly_registered_domain_pattern(ctx: EmailContext) -> tuple[int, str | None]:
    """
    High Shannon entropy in the domain name suggests a randomly generated domain
    (common in disposable phishing infrastructure).
    Threshold: entropy > 3.5 on the domain label (before the TLD).
    """
    domain = ctx.sender_domain
    if not domain:
        return 0, None
    # Check only the second-level domain label
    parts = domain.split(".")
    label = parts[-2] if len(parts) >= 2 else parts[0]
    entropy = _shannon_entropy(label)
    if entropy > 3.5:
        return 1, f"L2H:high_entropy_domain (domain={domain}, entropy={entropy:.2f})"
    return 0, None


# ── Public API ────────────────────────────────────────────────────────────────

_RULES = [
    _rule_reply_to_mismatch,
    _rule_pivot_to_external,
    _rule_urgency_language,
    _rule_credential_harvesting,
    _rule_blank_body_with_attachment,
    _rule_suspicious_sender_pattern,
    _rule_free_domain_impersonation,
    _rule_excessive_urls,
    _rule_newly_registered_domain_pattern,
]


def check_heuristics(ctx: EmailContext) -> tuple[int, list[str]]:
    """
    Run all heuristic rules against the email context.

    Args:
        ctx: Parsed EmailContext.

    Returns:
        (total_score, list_of_fired_reason_strings)
        Score is NOT capped here — scoring.py applies L2H_CAP.
    """
    total = 0
    reasons: list[str] = []

    for rule_fn in _RULES:
        try:
            score, reason = rule_fn(ctx)
            if score > 0 and reason:
                total += score
                reasons.append(reason)
        except Exception as exc:
            logger.warning("[L2H] Rule %s failed: %s", rule_fn.__name__, exc)

    logger.info("[L2H] [%s] fired=%d rules score=%d", ctx.message_id, len(reasons), total)
    return total, reasons

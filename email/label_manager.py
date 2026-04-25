"""
label_manager.py — Creates and applies PhishGuard Gmail labels.

Phase 2 adds two severity labels and a verdict-routing function.
The original [PhishGuard] base label is preserved for backwards compatibility.

Labels managed:
    [PhishGuard]            — base label (Phase 1, kept for compatibility)
    [PhishGuard] Suspicious — applied on SUSPICIOUS verdict (SCL 4–6)
    [PhishGuard] Phishing   — applied on LIKELY_PHISH + PHISH verdicts (SCL 7–10)

For PHISH verdict, the built-in SPAM label is also applied.
"""

import logging
from googleapiclient.errors import HttpError

from pipeline.scoring import PipelineResult

logger = logging.getLogger(__name__)

# ── Label definitions ─────────────────────────────────────────────────────────
_LABEL_DEFS = {
    "base": {
        "name": "[PhishGuard]",
        "color": None,
    },
    "suspicious": {
        "name": "[PhishGuard] Suspicious",
        # Gmail allowed palette: ffad47 = amber, ffffff = white text
        "color": {"backgroundColor": "#ffad47", "textColor": "#ffffff"},
    },
    "phishing": {
        "name": "[PhishGuard] Phishing",
        # Gmail allowed palette: cc3a21 = deep red, ffffff = white text
        "color": {"backgroundColor": "#cc3a21", "textColor": "#ffffff"},
    },
}

# In-memory cache: label_key → Gmail label ID
_label_cache: dict[str, str] = {}


def _get_or_create(service, label_key: str, user_id: str = "me") -> str | None:
    """
    Resolve a label to its Gmail ID. Creates it if it does not yet exist.
    Caches the ID for the process lifetime.

    Returns:
        The Gmail label ID string, or None on error.
    """
    if label_key in _label_cache:
        return _label_cache[label_key]

    label_def = _LABEL_DEFS[label_key]
    name = label_def["name"]

    # ── Scan existing labels ──────────────────────────────────────────────────
    try:
        response = service.users().labels().list(userId=user_id).execute()
    except HttpError as exc:
        logger.error("Failed to list labels: %s", exc)
        return None

    for lbl in response.get("labels", []):
        if lbl.get("name") == name:
            _label_cache[label_key] = lbl["id"]
            logger.info("Found existing label %r → %s", name, lbl["id"])
            return lbl["id"]

    # ── Create label ──────────────────────────────────────────────────────────
    body = {
        "name": name,
        "labelListVisibility": "labelShow",
        "messageListVisibility": "show",
    }
    if label_def["color"]:
        body["color"] = label_def["color"]

    try:
        created = service.users().labels().create(userId=user_id, body=body).execute()
        _label_cache[label_key] = created["id"]
        logger.info("Created label %r → %s", name, created["id"])
        return created["id"]
    except HttpError as exc:
        logger.error("Failed to create label %r: %s", name, exc)
        return None


# ── Public API ────────────────────────────────────────────────────────────────

def ensure_label_exists(service, user_id: str = "me") -> None:
    """Phase 1 compatibility — warm the base label cache."""
    _get_or_create(service, "base", user_id)


def ensure_all_labels_exist(service, user_id: str = "me") -> None:
    """
    Called at startup to warm the cache for all three labels.
    Creates any label that does not yet exist.
    """
    for key in _LABEL_DEFS:
        _get_or_create(service, key, user_id)


def apply_phishguard_label(service, message_id: str, user_id: str = "me") -> bool:
    """Phase 1 compatibility — apply the base [PhishGuard] label."""
    label_id = _get_or_create(service, "base", user_id)
    if not label_id:
        return False
    return _apply_labels(service, message_id, [label_id], [], user_id)


def apply_verdict_labels(
    service,
    message_id: str,
    result: PipelineResult,
    user_id: str = "me",
) -> None:
    """
    Apply the appropriate PhishGuard label(s) based on the pipeline verdict.

    Verdict → Action:
        CLEAN        → no action
        SUSPICIOUS   → [PhishGuard] Suspicious
        LIKELY_PHISH → [PhishGuard] Phishing + log warning
        PHISH        → [PhishGuard] Phishing + move to SPAM

    Args:
        service:    Authenticated Gmail API resource.
        message_id: Gmail message ID to label.
        result:     PipelineResult from orchestrator.
        user_id:    Gmail user identifier.
    """
    verdict = result.verdict

    if verdict == "CLEAN":
        logger.info("[LABELS] [%s] CLEAN — no labels applied", message_id)
        return

    add_labels = []
    remove_labels = []

    if verdict == "SUSPICIOUS":
        label_id = _get_or_create(service, "suspicious", user_id)
        if label_id:
            add_labels.append(label_id)
        # Archive out of inbox — user can find it under [PhishGuard] Suspicious
        remove_labels.append("INBOX")
        logger.info("[LABELS] [%s] SUSPICIOUS — labelling + removing from INBOX", message_id)

    elif verdict in ("LIKELY_PHISH", "PHISH"):
        label_id = _get_or_create(service, "phishing", user_id)
        if label_id:
            add_labels.append(label_id)
        # Always remove from inbox
        remove_labels.append("INBOX")

        if verdict == "PHISH":
            logger.warning(
                "[LABELS] [%s] PHISH (SCL=%d) — [PhishGuard] Phishing + INBOX removed",
                message_id, result.scl_score,
            )
        else:
            logger.warning(
                "[LABELS] [%s] LIKELY_PHISH (SCL=%d) — [PhishGuard] Phishing + INBOX removed",
                message_id, result.scl_score,
            )

    if add_labels:
        _apply_labels(service, message_id, add_labels, remove_labels, user_id)


def _apply_labels(
    service,
    message_id: str,
    add_label_ids: list[str],
    remove_label_ids: list[str],
    user_id: str,
) -> bool:
    """Call users.messages.modify to add/remove label IDs."""
    try:
        service.users().messages().modify(
            userId=user_id,
            id=message_id,
            body={
                "addLabelIds": add_label_ids,
                "removeLabelIds": remove_label_ids,
            },
        ).execute()
        logger.info(
            "✅ Labels updated for %s | add=%s remove=%s",
            message_id, add_label_ids, remove_label_ids,
        )
        return True
    except HttpError as exc:
        logger.error("❌ Failed to apply labels to %s: %s", message_id, exc)
        return False

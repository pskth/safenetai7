"""
watch_manager.py — Registers a Gmail Pub/Sub watch on the user's inbox.

Important lifecycle notes:
  • A Gmail watch expires after exactly 7 days (Google enforces this).
  • You MUST call register_watch() again before expiration or new emails
    will stop triggering Pub/Sub notifications.
  • Production tip: schedule a daily Cloud Scheduler job that calls
    POST /internal/renew-watch (not implemented in Phase 1) to keep the
    watch fresh well before its expiry.
"""

import logging
from googleapiclient.errors import HttpError

from config import PUBSUB_TOPIC_NAME, GMAIL_USER_ID

logger = logging.getLogger(__name__)


def register_watch(service) -> dict:
    """
    Register (or re-register) a Gmail Pub/Sub watch on the inbox.

    Each call overwrites any previously active watch for this user+topic pair,
    so it is safe to call at every application startup.

    Args:
        service: Authenticated Gmail API resource (from gmail_client.get_gmail_service).

    Returns:
        dict: The raw watch response from Gmail, containing:
              - historyId (str): The current history cursor; persist this.
              - expiration (str): Unix-ms timestamp when the watch expires (~7 days).

    Raises:
        HttpError: On any Gmail API failure (e.g. bad topic name, auth issues).
        ValueError: If PUBSUB_TOPIC_NAME is not configured.
    """
    if not PUBSUB_TOPIC_NAME:
        raise ValueError(
            "PUBSUB_TOPIC_NAME is not set in .env. "
            "It must be the full topic path: projects/{PROJECT_ID}/topics/{TOPIC}"
        )

    logger.info(
        "Registering Gmail watch for user '%s' on topic '%s'...",
        GMAIL_USER_ID,
        PUBSUB_TOPIC_NAME,
    )

    try:
        # ── Call users.watch ──────────────────────────────────────────────────
        # labelIds filter restricts notifications to INBOX events only.
        # Remove the filter to watch all labels (more noise, same cost).
        response = (
            service.users()
            .watch(
                userId=GMAIL_USER_ID,
                body={
                    "topicName": PUBSUB_TOPIC_NAME,
                    "labelIds": ["INBOX"],          # Only notify on inbox changes
                    "labelFilterAction": "include", # Include only the listed labels
                },
            )
            .execute()
        )

        history_id = response.get("historyId")
        expiration_ms = response.get("expiration")

        # Log both values — historyId is the starting cursor for history.list calls
        logger.info(
            "✅ Gmail watch registered. historyId=%s | expiration=%s ms (≈7 days)",
            history_id,
            expiration_ms,
        )

        # NOTE: In Phase 2, persist historyId to a database / Redis so the
        # webhook can resume from the correct point after a restart.

        return response

    except HttpError as exc:
        logger.error("❌ Failed to register Gmail watch: %s", exc)
        raise

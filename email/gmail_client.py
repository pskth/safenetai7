"""
gmail_client.py — OAuth 2.0 authentication and Gmail API resource factory.

Flow:
  1. First run  → browser opens for consent → token saved to GOOGLE_TOKEN_PATH
  2. Later runs → token loaded from disk and auto-refreshed when expired

The returned service object is the entry point for all Gmail API calls in
every other module.  No other file should import google-auth directly.
"""

import os
import logging
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

from config import GOOGLE_CLIENT_CREDENTIALS_PATH, GOOGLE_TOKEN_PATH

logger = logging.getLogger(__name__)

# ── OAuth scope ───────────────────────────────────────────────────────────────
# gmail.modify lets us read messages AND add/remove labels.
# If you change the scope you MUST delete token.json and re-authenticate.
SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]


def get_gmail_service():
    """
    Authenticate with Gmail via OAuth 2.0 and return a Gmail API service object.

    Returns:
        googleapiclient.discovery.Resource: Authenticated Gmail API client.

    Raises:
        FileNotFoundError: If credentials.json is missing.
        google.auth.exceptions.RefreshError: If the stored token cannot be refreshed.
    """
    creds: Credentials | None = None

    # ── Step 1: Load existing token (if any) ─────────────────────────────────
    if os.path.exists(GOOGLE_TOKEN_PATH):
        creds = Credentials.from_authorized_user_file(GOOGLE_TOKEN_PATH, SCOPES)
        logger.debug("Loaded OAuth token from %s", GOOGLE_TOKEN_PATH)

    # ── Step 2: Refresh or run the browser consent flow ──────────────────────
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            # Token exists but is expired — refresh silently
            logger.info("OAuth token expired, refreshing...")
            creds.refresh(Request())
        else:
            # No usable token — open browser for first-time consent
            if not os.path.exists(GOOGLE_CLIENT_CREDENTIALS_PATH):
                raise FileNotFoundError(
                    f"credentials.json not found at '{GOOGLE_CLIENT_CREDENTIALS_PATH}'. "
                    "Download it from Google Cloud Console → APIs & Services → Credentials."
                )
            logger.info("No valid OAuth token found — opening browser for consent...")
            flow = InstalledAppFlow.from_client_secrets_file(
                GOOGLE_CLIENT_CREDENTIALS_PATH, SCOPES
            )
            creds = flow.run_local_server(port=0)

        # ── Step 3: Persist the (new/refreshed) token for next run ───────────
        with open(GOOGLE_TOKEN_PATH, "w") as token_file:
            token_file.write(creds.to_json())
        logger.info("OAuth token saved to %s", GOOGLE_TOKEN_PATH)

    # ── Step 4: Build and return the Gmail API resource ───────────────────────
    service = build("gmail", "v1", credentials=creds)
    logger.info("Gmail API service created successfully")
    return service

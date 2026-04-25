"""
pipeline/email_parser.py — Parses raw MIME bytes into a structured EmailContext.

This is the first stage of the pipeline.  Everything downstream works only
with EmailContext — no module ever touches raw MIME directly.

Key design choices:
  • Python's built-in `email` library handles MIME parsing (no third-party dep)
  • BeautifulSoup strips HTML to readable plain text
  • URLs are deduplicated and extracted from both plain text and HTML hrefs
  • Attachments store content_bytes so L3 can hash them locally
"""

import re
import logging
from dataclasses import dataclass, field
from email import message_from_string
from email.header import decode_header, make_header
from email.utils import parseaddr
from urllib.parse import urlparse

from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

# ── URL extraction regex ──────────────────────────────────────────────────────
# Matches http/https/ftp URLs in plain text
_URL_RE = re.compile(
    r'https?://[^\s<>"\')\]]+',
    re.IGNORECASE,
)

# ── MIME types that warrant a file hash check at L3 ──────────────────────────
SUSPICIOUS_MIME_TYPES = {
    "application/pdf",
    "application/zip",
    "application/x-zip-compressed",
    "application/octet-stream",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/msword",
    "application/vnd.ms-excel",
}


@dataclass
class EmailContext:
    """
    All data extracted from a single email, passed between pipeline stages.

    thread_id is populated from Gmail API msg["threadId"] so Phase 2.5
    (warning draft injection) can thread the draft into the original conversation.
    """
    message_id: str
    thread_id: str = ""

    subject: str = ""
    sender: str = ""          # Full From header value ("Name <addr@domain.com>")
    sender_domain: str = ""   # Root domain extracted from From address
    reply_to: str = ""
    to: str = ""
    date: str = ""

    body_text: str = ""       # Plain text (HTML stripped via BeautifulSoup)
    body_html: str = ""       # Raw HTML body if present

    headers: dict = field(default_factory=dict)
    attachments: list = field(default_factory=list)  # [{filename, mime_type, content_bytes}]
    urls: list = field(default_factory=list)          # Deduplicated URL strings
    raw_mime: str = ""


def _decode_header_value(raw: str) -> str:
    """Safely decode an RFC 2047 encoded header value to a plain string."""
    try:
        return str(make_header(decode_header(raw)))
    except Exception:
        return raw or ""


def _extract_domain(email_address: str) -> str:
    """Extract the root domain from a full email address string."""
    _, addr = parseaddr(email_address)
    if "@" in addr:
        return addr.split("@", 1)[1].lower().strip()
    return ""


def _extract_urls(text: str, html: str) -> list[str]:
    """
    Deduplicated URL list from:
      1. Bare URLs in plain text (regex)
      2. href attributes in HTML (html.parser via BeautifulSoup)
    """
    found = set()

    # Plain text URLs
    for url in _URL_RE.findall(text):
        found.add(url.rstrip(".,;"))

    # HTML href attributes
    if html:
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup.find_all(href=True):
            href = tag["href"].strip()
            if href.startswith(("http://", "https://", "ftp://")):
                found.add(href)

    return sorted(found)


def _strip_html(html: str) -> str:
    """Convert HTML to readable plain text using BeautifulSoup."""
    try:
        soup = BeautifulSoup(html, "html.parser")
        return soup.get_text(separator=" ", strip=True)
    except Exception:
        return html


def _walk_parts(msg) -> tuple[str, str, list[dict]]:
    """
    Recursively walk the MIME tree to collect:
      - body_text (from text/plain parts)
      - body_html (from text/html parts)
      - attachments (filename + mime_type + raw bytes)
    """
    body_text_parts: list[str] = []
    body_html_parts: list[str] = []
    attachments: list[dict] = []

    for part in msg.walk():
        content_type = part.get_content_type()
        disposition = str(part.get("Content-Disposition", ""))
        is_attachment = "attachment" in disposition.lower()

        # ── Text / HTML body parts ────────────────────────────────────────────
        if not is_attachment:
            charset = part.get_content_charset() or "utf-8"
            payload = part.get_payload(decode=True)
            if payload is None:
                continue
            try:
                decoded = payload.decode(charset, errors="replace")
            except (LookupError, UnicodeDecodeError):
                decoded = payload.decode("utf-8", errors="replace")

            if content_type == "text/plain":
                body_text_parts.append(decoded)
            elif content_type == "text/html":
                body_html_parts.append(decoded)

        # ── Attachments ───────────────────────────────────────────────────────
        elif is_attachment:
            filename = part.get_filename() or "unnamed"
            content_bytes = part.get_payload(decode=True) or b""
            if content_type in SUSPICIOUS_MIME_TYPES:
                attachments.append({
                    "filename": filename,
                    "mime_type": content_type,
                    "content_bytes": content_bytes,
                })
                logger.debug("Found suspicious attachment: %s (%s)", filename, content_type)

    body_text = "\n".join(body_text_parts)
    body_html = "\n".join(body_html_parts)

    # If there's no plain text but there is HTML, convert HTML → text
    if not body_text and body_html:
        body_text = _strip_html(body_html)

    return body_text, body_html, attachments


def parse_email(raw_mime: str, message_id: str, thread_id: str = "") -> EmailContext:
    """
    Parse a raw MIME string into a structured EmailContext.

    Args:
        raw_mime:   The full raw MIME email as a string (base64-decoded from Gmail).
        message_id: Gmail message ID (not the Message-ID header — the API's ID).
        thread_id:  Gmail thread ID for Phase 2.5 draft threading.

    Returns:
        EmailContext populated with all extracted fields.
    """
    ctx = EmailContext(message_id=message_id, thread_id=thread_id, raw_mime=raw_mime)

    try:
        msg = message_from_string(raw_mime)
    except Exception as exc:
        logger.error("[email_parser] Failed to parse MIME for %s: %s", message_id, exc)
        return ctx

    # ── Headers ───────────────────────────────────────────────────────────────
    ctx.headers = {k.lower(): v for k, v in msg.items()}

    ctx.subject = _decode_header_value(msg.get("Subject", ""))
    ctx.sender = _decode_header_value(msg.get("From", ""))
    ctx.reply_to = _decode_header_value(msg.get("Reply-To", ""))
    ctx.to = _decode_header_value(msg.get("To", ""))
    ctx.date = msg.get("Date", "")

    ctx.sender_domain = _extract_domain(ctx.sender)

    # ── Body + attachments ────────────────────────────────────────────────────
    ctx.body_text, ctx.body_html, ctx.attachments = _walk_parts(msg)

    # ── URL extraction ────────────────────────────────────────────────────────
    ctx.urls = _extract_urls(ctx.body_text, ctx.body_html)

    logger.debug(
        "[email_parser] %s | subject=%r sender_domain=%s urls=%d attachments=%d",
        message_id, ctx.subject, ctx.sender_domain, len(ctx.urls), len(ctx.attachments),
    )

    return ctx

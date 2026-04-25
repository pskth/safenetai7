import base64
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import urllib.parse
import logging

from pipeline.email_parser import EmailContext
from pipeline.scoring import PipelineResult

logger = logging.getLogger(__name__)

# Note: In production this should be your deployed server URL or ngrok
BASE_URL = "http://localhost:8080"

async def inject_warning_draft(
    service,
    context: EmailContext,
    result: PipelineResult,
    user_id: str = "me"
) -> None:
    """
    Inject a warning draft into the original email thread.
    Includes a 'Report to College Admins' button.
    """
    if not context.thread_id:
        logger.warning("[DRAFT] No thread_id available, skipping draft injection.")
        return

    logger.info("[DRAFT] Injecting warning draft for thread %s", context.thread_id)

    # Build the report link parameters
    url_to_report = context.urls[0] if context.urls else ""
    domain_to_report = context.sender_domain
    
    query = urllib.parse.urlencode({
        "url": url_to_report,
        "domain": domain_to_report
    })
    report_link = f"{BASE_URL}/api/report?{query}"

    # Build HTML body
    rules_html = "".join(f"<li>{rule}</li>" for rule in result.fired_rules)
    urls_html = "".join(f"<li>{u}</li>" for u in result.flagged_urls)

    html_content = f"""
    <html>
      <body style="font-family: sans-serif; line-height: 1.6; color: #333;">
        <div style="background-color: #fee2e2; border-left: 4px solid #ef4444; padding: 16px; margin-bottom: 24px;">
          <h2 style="color: #b91c1c; margin-top: 0;">⚠️ PhishGuard Security Warning</h2>
          <p>This email has been flagged as <strong>{result.verdict}</strong>.</p>
          
          <p><strong>Spam Confidence Level (SCL):</strong> {result.scl_score}/10</p>
          
          <h3>Why was this flagged?</h3>
          <ul>
            {rules_html}
          </ul>
          
          {f"<h3>Flagged URLs:</h3><ul>{urls_html}</ul>" if urls_html else ""}
          
          <div style="margin-top: 24px;">
            <a href="{report_link}" style="background-color: #ef4444; color: white; padding: 10px 20px; text-decoration: none; border-radius: 6px; font-weight: bold; display: inline-block;">
              Report to College Admins
            </a>
          </div>
        </div>
        <hr style="border: 0; border-top: 1px solid #ccc; margin: 24px 0;" />
        <div style="color: #666;">
          <p><em>Original message snippet:</em></p>
          <blockquote style="border-left: 2px solid #ccc; padding-left: 10px; background: #f9f9f9; padding: 10px;">
            {context.body_text[:1000]}...
          </blockquote>
        </div>
      </body>
    </html>
    """

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"⚠️ [PHISHGUARD BLOCKED] — {context.subject}"
    msg["In-Reply-To"] = context.message_id
    msg["References"] = context.message_id
    
    msg.attach(MIMEText(html_content, "html"))

    raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()

    try:
        service.users().drafts().create(
            userId=user_id,
            body={
                "message": {
                    "raw": raw,
                    "threadId": context.thread_id
                }
            }
        ).execute()
        logger.info("[DRAFT] Successfully created warning draft in thread %s", context.thread_id)
    except Exception as e:
        logger.error("[DRAFT] Failed to create warning draft: %s", e)

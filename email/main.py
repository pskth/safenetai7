"""
main.py — PhishGuard FastAPI application: Pub/Sub webhook listener.

Phase 2 changes (marked ── PHASE 2 ──):
  • _process_message is now async and calls the full analysis pipeline
  • _fetch_raw_mime() added to retrieve the raw MIME from Gmail
  • log_pipeline_result() added for structured result logging
  • Startup calls ensure_all_labels_exist instead of ensure_label_exists
  • apply_verdict_labels() replaces apply_phishguard_label()

Everything else (lifespan, webhook routing, history.list logic,
always-HTTP-200 contract) is unchanged from Phase 1.
"""

import base64
import json
import logging
import logging.config

from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, HTMLResponse
import html

from config import GMAIL_USER_ID
from gmail_client import get_gmail_service
from label_manager import apply_verdict_labels, ensure_all_labels_exist
from watch_manager import register_watch
from pipeline.orchestrator import run_pipeline
from pipeline.scoring import PipelineResult

# ── Logging setup ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("phishguard")

# ── Module-level state ────────────────────────────────────────────────────────
gmail_service = None
last_history_id: str | None = None

# SSE state
recent_results = []
sse_queues = []

def broadcast_sse(event_type: str, data: dict):
    payload = json.dumps({"type": event_type, "data": data})
    for q in sse_queues:
        q.put_nowait(payload)


# ── Lifespan ──────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Run startup tasks before accepting requests."""
    global gmail_service, last_history_id

    logger.info("=== PhishGuard starting up ===")

    gmail_service = get_gmail_service()

    # ── PHASE 2: ensure all three labels exist at startup ─────────────────────
    ensure_all_labels_exist(gmail_service, GMAIL_USER_ID)

    watch_response = register_watch(gmail_service)
    last_history_id = watch_response.get("historyId")

    logger.info("Startup complete. Listening for Pub/Sub notifications...")
    yield
    logger.info("=== PhishGuard shutting down ===")


app = FastAPI(title="PhishGuard", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For local dev frontend
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Helper: decode Pub/Sub envelope ──────────────────────────────────────────
def _decode_pubsub_payload(body: dict) -> dict | None:
    """
    Extract and JSON-decode the base64 data field from a Pub/Sub push message.
    Returns dict with 'emailAddress' and 'historyId', or None on failure.
    """
    try:
        raw_data = body["message"]["data"]
        decoded = base64.b64decode(raw_data).decode("utf-8")
        return json.loads(decoded)
    except Exception as exc:
        logger.warning("Could not decode Pub/Sub payload: %s", exc)
        return None


# ── Helper: fetch new message IDs ────────────────────────────────────────────
def _get_new_message_ids(new_history_id: str) -> list[str]:
    """Use history.list to return message IDs added since last_history_id."""
    global last_history_id

    if not last_history_id:
        logger.warning("No previous historyId stored — skipping history.list.")
        return []

    try:
        history_response = (
            gmail_service.users()
            .history()
            .list(
                userId=GMAIL_USER_ID,
                startHistoryId=last_history_id,
                historyTypes=["messageAdded"],
                labelId="INBOX",
            )
            .execute()
        )
    except Exception as exc:
        logger.error("history.list failed: %s", exc)
        return []

    last_history_id = new_history_id

    message_ids: list[str] = []
    for record in history_response.get("history", []):
        for added in record.get("messagesAdded", []):
            msg_id = added.get("message", {}).get("id")
            if msg_id:
                message_ids.append(msg_id)

    logger.info("history.list returned %d new message(s)", len(message_ids))
    return message_ids


# ── PHASE 2: fetch raw MIME from Gmail ───────────────────────────────────────
def _fetch_raw_mime(service, message_id: str) -> tuple[str, str]:
    """
    Retrieve the full raw MIME of a message via messages.get(format="raw").

    Returns:
        (raw_mime_string, thread_id) — thread_id needed for Phase 2.5 draft.
    """
    msg = (
        service.users()
        .messages()
        .get(userId=GMAIL_USER_ID, id=message_id, format="raw")
        .execute()
    )
    raw_b64 = msg.get("raw", "")
    # Gmail uses URL-safe base64
    raw_bytes = base64.urlsafe_b64decode(raw_b64 + "==")
    raw_mime = raw_bytes.decode("utf-8", errors="replace")
    thread_id = msg.get("threadId", "")
    return raw_mime, thread_id


# ── PHASE 2: structured result logger ────────────────────────────────────────
def log_pipeline_result(message_id: str, result: PipelineResult) -> None:
    """Emit a single structured summary line for each processed email."""
    logger.info(
        "📊 [%s] verdict=%s scl=%d | L1=%d L2H=%d L2N=%d L3=%d | "
        "nlp=%s(%.2f) | rules=%d flagged_urls=%d",
        message_id,
        result.verdict,
        result.scl_score,
        result.l1_score,
        result.l2_heuristics_score,
        result.l2_nlp_score,
        result.l3_score,
        result.nlp_label,
        result.nlp_confidence,
        len(result.fired_rules),
        len(result.flagged_urls),
    )
    if result.fired_rules:
        logger.info("🔍 [%s] Fired rules: %s", message_id, " | ".join(result.fired_rules))


# ── PHASE 2: process a single message through the pipeline ───────────────────
async def _process_message(message_id: str) -> None:
    """
    Fetch the raw MIME for message_id, run the full security pipeline,
    log the result, and apply the verdict labels.

    Replaces the Phase 1 trigger-word check entirely.
    Any exception inside run_pipeline is caught there; any exception here
    is logged and swallowed so the webhook always returns HTTP 200.
    """
    logger.info("--- Processing message ID: %s ---", message_id)

    try:
        raw_mime, thread_id = _fetch_raw_mime(gmail_service, message_id)
    except Exception as exc:
        logger.error("_fetch_raw_mime failed for %s: %s", message_id, exc)
        return

    # run_pipeline never raises for normal errors — it returns CLEAN on internal failure.
    # CancelledError (server shutdown) is the only thing that can propagate here.
    try:
        ctx, result = await run_pipeline(
            raw_mime=raw_mime,
            gmail_service=gmail_service,
            message_id=message_id,
            thread_id=thread_id,
        )
    except asyncio.CancelledError:
        logger.info("[%s] Pipeline cancelled — server shutting down, skipping label step.", message_id)
        return

    log_pipeline_result(message_id, result)
    apply_verdict_labels(gmail_service, message_id, result, GMAIL_USER_ID)

    # Broadcast to dashboard
    if ctx and result:
        from datetime import datetime
        import dataclasses
        event_data = {
            "id": message_id,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "context": {
                "message_id": ctx.message_id,
                "subject": ctx.subject,
                "sender": ctx.sender,
                "date": ctx.date,
            },
            "result": dataclasses.asdict(result),
        }
        recent_results.append(event_data)
        if len(recent_results) > 50:
            recent_results.pop(0)
        broadcast_sse("new_result", event_data)

    # ── Phase 2.5: Warning Draft Injection ────────────────────────────────────
    if result.verdict in ("PHISH", "LIKELY_PHISH", "SUSPICIOUS"):
        from pipeline.warning_composer import inject_warning_draft
        await inject_warning_draft(gmail_service, ctx, result)


# ── Webhook endpoint ──────────────────────────────────────────────────────────
@app.post("/webhook/gmail")
async def gmail_webhook(request: Request) -> Response:
    """
    Receive Pub/Sub push notifications from Gmail.
    Always returns HTTP 200 — never lets Pub/Sub retry storm the endpoint.
    """
    try:
        body = await request.json()
    except Exception:
        logger.warning("Received non-JSON body on /webhook/gmail — ignoring.")
        return Response(status_code=200)

    payload = _decode_pubsub_payload(body)
    if not payload:
        return Response(status_code=200)

    email_address = payload.get("emailAddress", "unknown")
    new_history_id = str(payload.get("historyId", ""))

    logger.info("📬 Notification received for %s | historyId=%s", email_address, new_history_id)

    message_ids = _get_new_message_ids(new_history_id)

    for msg_id in message_ids:
        await _process_message(msg_id)

    return Response(status_code=200)


# ── Reporting Endpoint ────────────────────────────────────────────────────────
from pipeline.l3_threat_intel import get_supabase_client
import urllib.parse

@app.get("/api/report", response_class=HTMLResponse)
async def report_scam(url: str = "", domain: str = ""):
    """Endpoint for students to report phishing links via the email button."""
    client = get_supabase_client()
    if client and (url or domain):
        try:
            # Insert into pending_reports table
            client.table('pending_reports').insert({
                "url": url,
                "domain": domain
            }).execute()
            logger.info("Report submitted to pending_reports: url=%s domain=%s", url, domain)
        except Exception as e:
            logger.error("Failed to insert pending report: %s", e)
            
    safe_url = html.escape(url) if url else 'None'
    safe_domain = html.escape(domain) if domain else 'None'
            
    return f"""
    <html>
      <body style="font-family: sans-serif; text-align: center; padding-top: 50px; background-color: #f9fafb;">
        <div style="background: white; max-width: 500px; margin: 0 auto; padding: 40px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
            <h1 style="color: #10b981; margin-top: 0;">Report Submitted! ✅</h1>
            <p style="color: #4b5563; font-size: 16px;">Thank you. Your report has been sent to the college admins for review.</p>
            <div style="margin-top: 30px; text-align: left; background: #f3f4f6; padding: 15px; border-radius: 8px;">
                <p style="margin: 5px 0;"><strong>Reported URL:</strong> <span style="font-family: monospace; word-break: break-all;">{safe_url}</span></p>
                <p style="margin: 5px 0;"><strong>Reported Domain:</strong> <span style="font-family: monospace;">{safe_domain}</span></p>
            </div>
        </div>
      </body>
    </html>
    """

# ── Dashboard SSE Endpoint ────────────────────────────────────────────────────
import asyncio
@app.get("/api/stream")
async def stream_results():
    """SSE endpoint for pushing live analysis results to the React dashboard."""
    q = asyncio.Queue()
    sse_queues.append(q)
    
    async def event_generator():
        try:
            # Send initial history payload
            yield f"data: {json.dumps({'type': 'history', 'data': recent_results})}\n\n"
            while True:
                # Send ping to keep connection alive
                try:
                    payload = await asyncio.wait_for(q.get(), timeout=15.0)
                    yield f"data: {payload}\n\n"
                except asyncio.TimeoutError:
                    yield f"data: {json.dumps({'type': 'ping'})}\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            if q in sse_queues:
                sse_queues.remove(q)
                
    return StreamingResponse(event_generator(), media_type="text/event-stream")


# ── Local dev entry point ─────────────────────────────────────────────────────
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8080, reload=True)

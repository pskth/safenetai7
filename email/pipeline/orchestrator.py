"""
pipeline/orchestrator.py — Master pipeline coordinator.

Runs all analysis stages in order and returns a PipelineResult.

Stage order:
    1. email_parser    → EmailContext
    2. l1_authentication → SPF/DKIM/DMARC/spoofing
    3. l2_heuristics   → 9 deterministic rules
    4. l2_nlp          → TF-IDF + LogReg classifier
    5. l3_threat_intel → VirusTotal MCP (concurrent URL + domain + file checks)
    6. scoring         → aggregate → PipelineResult

CRITICAL: The orchestrator must NEVER raise an exception.
Any failure is caught, logged, and returns a CLEAN verdict so the webhook
always returns HTTP 200 (preventing Pub/Sub redelivery storms).
"""

import asyncio
import base64
import logging

from pipeline.email_parser import parse_email
from pipeline.l1_authentication import check_authentication
from pipeline.l2_heuristics import check_heuristics
from pipeline.l2_nlp import check_nlp
from pipeline.l3_threat_intel import check_threat_intel
from pipeline.scoring import PipelineResult, aggregate_scores, clean_result

logger = logging.getLogger(__name__)


async def run_pipeline(
    raw_mime: str,
    gmail_service,
    message_id: str,
    thread_id: str = "",
) -> tuple[any, PipelineResult]:
    """
    Execute the full PhishGuard analysis pipeline for a single email.

    Args:
        raw_mime:       The decoded raw MIME string of the email.
        gmail_service:  Authenticated Gmail API resource (reserved for Phase 2.5).
        message_id:     Gmail message ID (for logging and label application).
        thread_id:      Gmail thread ID (for Phase 2.5 draft threading).

    Returns:
        Tuple of (EmailContext, PipelineResult).
        Never raises — returns CLEAN verdict with error note on unexpected failure.
    """
    logger.info("[PIPELINE] [%s] Starting analysis", message_id)

    try:
        # ── Stage 1: Parse MIME into EmailContext ─────────────────────────────
        ctx = parse_email(raw_mime, message_id=message_id, thread_id=thread_id)
        logger.info(
            "[PIPELINE] [%s] Parsed | subject=%r sender=%s urls=%d attachments=%d",
            message_id, ctx.subject, ctx.sender_domain,
            len(ctx.urls), len(ctx.attachments),
        )

        # ── Stage 2: L1 Authentication ────────────────────────────────────────
        l1_score, l1_reasons = check_authentication(ctx)
        logger.info("[PIPELINE] [%s] L1 score=%d reasons=%s", message_id, l1_score, l1_reasons)

        # ── Stage 3: L2 Heuristics ────────────────────────────────────────────
        l2h_score, l2h_reasons = check_heuristics(ctx)
        logger.info("[PIPELINE] [%s] L2H score=%d reasons=%s", message_id, l2h_score, l2h_reasons)

        # ── Stage 4: L2 NLP ───────────────────────────────────────────────────
        l2n_score, nlp_label, nlp_confidence = check_nlp(ctx.body_text, message_id)
        logger.info(
            "[PIPELINE] [%s] L2N score=%d label=%s confidence=%.3f",
            message_id, l2n_score, nlp_label, nlp_confidence,
        )

        # ── Stage 5: L3 VirusTotal MCP ────────────────────────────────────────
        # Runs URL scan, domain scan, and attachment hash check concurrently.
        # Fails gracefully — if VT is unavailable, l3_score returns 0.
        try:
            l3_score, l3_reasons, flagged_urls = await check_threat_intel(ctx)
            logger.info("[PIPELINE] [%s] L3 score=%d flagged_urls=%d", message_id, l3_score, len(flagged_urls))
        except asyncio.CancelledError:
            raise  # always propagate shutdown signals
        except Exception as l3_exc:
            logger.error("[PIPELINE] [%s] L3 stage failed (fail-open): %s", message_id, l3_exc)
            l3_score, l3_reasons, flagged_urls = 0, ["L3:error_fail_open"], []

        # ── Stage 6: Aggregate scores ─────────────────────────────────────────
        all_reasons = l1_reasons + l2h_reasons + l3_reasons
        if nlp_label == "phish":
            all_reasons.append(f"L2N:phish_classified confidence={nlp_confidence:.3f}")

        result = aggregate_scores(
            l1_score=l1_score,
            l2_heuristics_score=l2h_score,
            l2_nlp_score=l2n_score,
            l3_score=l3_score,
            fired_rules=all_reasons,
            nlp_label=nlp_label,
            nlp_confidence=nlp_confidence,
            flagged_urls=flagged_urls,
        )

        logger.info(
            "[PIPELINE] [%s] RESULT | verdict=%s scl=%d "
            "(L1=%d L2H=%d L2N=%d L3=%d) rules=%d",
            message_id,
            result.verdict,
            result.scl_score,
            result.l1_score,
            result.l2_heuristics_score,
            result.l2_nlp_score,
            result.l3_score,
            len(result.fired_rules),
        )

        return ctx, result

    except asyncio.CancelledError:
        raise  # propagate — uvicorn shutdown is in progress
    except Exception as exc:
        # ── Fail-safe: never crash the webhook ───────────────────────────────
        logger.exception(
            "[PIPELINE] [%s] Unexpected pipeline failure — returning CLEAN: %s",
            message_id, exc,
        )
        return None, clean_result(message=f"pipeline_exception:{type(exc).__name__}")

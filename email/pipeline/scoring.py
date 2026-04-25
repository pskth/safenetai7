"""
pipeline/scoring.py — SCL score aggregation and verdict assignment.

Mirrors Microsoft's Exchange Online Protection Spam Confidence Level (SCL).
Each pipeline stage contributes points; this module sums them, caps at 10,
and maps to a verdict tier.

Verdict tiers:
    CLEAN        0–3   → no action
    SUSPICIOUS   4–6   → [PhishGuard] Suspicious label
    LIKELY_PHISH 7–8   → [PhishGuard] Phishing label + log warning
    PHISH        9–10  → [PhishGuard] Phishing label + move to SPAM
"""

from dataclasses import dataclass, field

# ── Score ceiling ─────────────────────────────────────────────────────────────
SCL_MAX = 10

# ── Stage contribution caps ───────────────────────────────────────────────────
L1_CAP = 4   # authentication (SPF / DKIM / DMARC / spoofing)
L2H_CAP = 4  # heuristics (deterministic rules)
L2N_CAP = 3  # NLP classifier
L3_CAP = 5   # VirusTotal MCP & Custom College DB threat intel


@dataclass
class PipelineResult:
    """Complete output of a single email's pipeline run."""
    scl_score: int            # 0–10, capped
    verdict: str              # CLEAN / SUSPICIOUS / LIKELY_PHISH / PHISH
    l1_score: int             # Authentication stage contribution
    l2_heuristics_score: int  # Heuristics stage contribution
    l2_nlp_score: int         # NLP stage contribution
    l3_score: int             # Threat intel stage contribution
    fired_rules: list[str]    # Human-readable reasons from all stages
    nlp_label: str            # "phish" or "ham"
    nlp_confidence: float     # Classifier confidence 0.0–1.0
    flagged_urls: list[str]   # URLs flagged by L3


def _verdict(scl: int) -> str:
    """Map a numeric SCL score to a verdict string."""
    if scl <= 3:
        return "CLEAN"
    if scl <= 6:
        return "SUSPICIOUS"
    if scl <= 8:
        return "LIKELY_PHISH"
    return "PHISH"


def aggregate_scores(
    l1_score: int,
    l2_heuristics_score: int,
    l2_nlp_score: int,
    l3_score: int,
    fired_rules: list[str],
    nlp_label: str,
    nlp_confidence: float,
    flagged_urls: list[str],
) -> PipelineResult:
    """
    Sum all stage scores (each already capped at their stage limit),
    apply the global SCL ceiling, and return a PipelineResult.

    Args:
        l1_score:              Points from L1 authentication (0–4).
        l2_heuristics_score:   Points from L2 heuristic rules (0–4).
        l2_nlp_score:          Points from L2 NLP classifier (0–3).
        l3_score:              Points from L3 VirusTotal checks (0–3).
        fired_rules:           All human-readable rule strings.
        nlp_label:             "phish" or "ham".
        nlp_confidence:        Classifier confidence score.
        flagged_urls:          URLs flagged by L3.

    Returns:
        PipelineResult with scl_score, verdict, and per-stage breakdown.
    """
    # Clamp each stage to its defined maximum
    l1 = min(l1_score, L1_CAP)
    l2h = min(l2_heuristics_score, L2H_CAP)
    l2n = min(l2_nlp_score, L2N_CAP)
    l3 = min(l3_score, L3_CAP)

    # Sum and apply global ceiling
    total = min(l1 + l2h + l2n + l3, SCL_MAX)

    return PipelineResult(
        scl_score=total,
        verdict=_verdict(total),
        l1_score=l1,
        l2_heuristics_score=l2h,
        l2_nlp_score=l2n,
        l3_score=l3,
        fired_rules=fired_rules,
        nlp_label=nlp_label,
        nlp_confidence=nlp_confidence,
        flagged_urls=flagged_urls,
    )


def clean_result(message: str = "pipeline_error") -> PipelineResult:
    """
    Return a safe CLEAN result used when the pipeline throws an unexpected exception.
    Ensures the webhook always returns HTTP 200 even on internal failures.
    """
    return PipelineResult(
        scl_score=0,
        verdict="CLEAN",
        l1_score=0,
        l2_heuristics_score=0,
        l2_nlp_score=0,
        l3_score=0,
        fired_rules=[message],
        nlp_label="ham",
        nlp_confidence=0.0,
        flagged_urls=[],
    )

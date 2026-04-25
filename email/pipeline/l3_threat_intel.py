"""
pipeline/l3_threat_intel.py — VirusTotal MCP threat intelligence checks.

Mirrors Microsoft Defender Safe Links / MDO URL detonation pipeline.
All checks go through mcp_client.py (stdio JSON-RPC) rather than direct REST.

Three async checks:
    scan_url(url)                   → UrlScanResult
    scan_domain(domain)             → DomainScanResult
    scan_file_hash(name,mime,bytes) → FileScanResult

In-memory cache and token bucket rate limiter keep us within VT free tier
(4 calls/min, 500 calls/day).

Maximum contribution: 3 points total (L3_CAP in scoring.py).
"""

import asyncio
import hashlib
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

import os
from supabase import create_client, Client

from pipeline.email_parser import EmailContext
from pipeline.mcp_client import call_mcp_tool

logger = logging.getLogger(__name__)

# ── Supabase Client (Lazy init) ──────────────────────────────────────────────
_supabase_client: Client | None = None

def get_supabase_client() -> Client | None:
    global _supabase_client
    supabase_url = os.getenv("SUPABASE_URL", "")
    supabase_key = os.getenv("SUPABASE_KEY", "")
    
    if _supabase_client is None and supabase_url and supabase_key:
        try:
            _supabase_client = create_client(supabase_url, supabase_key)
        except Exception as e:
            logger.error("[L3-DB] Failed to initialize Supabase client: %s", e)
    return _supabase_client

# ── In-memory result cache ────────────────────────────────────────────────────
# Key: url / sha256 hash / domain  →  Value: cached result dict
_vt_cache: dict[str, dict] = {}

# ── Token bucket rate limiter ─────────────────────────────────────────────────
_RATE_LIMIT = 4          # max calls per window
_RATE_WINDOW = 60.0      # seconds
_call_timestamps: list[float] = []


async def _rate_limit() -> None:
    """
    Block until we are within the VT free-tier rate limit (4 calls/min).
    Uses a sliding window of call timestamps.
    """
    now = time.monotonic()
    # Purge timestamps older than the window
    while _call_timestamps and now - _call_timestamps[0] > _RATE_WINDOW:
        _call_timestamps.pop(0)

    if len(_call_timestamps) >= _RATE_LIMIT:
        wait = _RATE_WINDOW - (now - _call_timestamps[0]) + 0.1
        logger.info("[L3-VT] Rate limit reached — sleeping %.1fs", wait)
        await asyncio.sleep(wait)

    _call_timestamps.append(time.monotonic())


async def _cached_call(cache_key: str, tool_name: str, arguments: dict) -> dict:
    """Check cache first, then call MCP tool if needed."""
    if cache_key in _vt_cache:
        logger.debug("[L3-VT] Cache hit for %s", cache_key[:60])
        return _vt_cache[cache_key]

    await _rate_limit()
    result = await call_mcp_tool(tool_name, arguments)
    if "error" not in result:
        _vt_cache[cache_key] = result
    return result


# ── Result dataclasses ────────────────────────────────────────────────────────

@dataclass
class UrlScanResult:
    url: str
    malicious_count: int = 0
    suspicious_count: int = 0
    total_engines: int = 0
    final_verdict: str = "clean"
    categories: list[str] = field(default_factory=list)
    score: int = 0
    error: bool = False


@dataclass
class DomainScanResult:
    domain: str
    reputation_score: int = 0
    malicious_votes: int = 0
    categories: list[str] = field(default_factory=list)
    newly_seen: bool = False
    score: int = 0
    error: bool = False


@dataclass
class FileScanResult:
    filename: str
    sha256: str
    malicious_count: int = 0
    suspicious_count: int = 0
    score: int = 0
    error: bool = False


@dataclass
class CollegeDBScanResult:
    matched_urls: list[str] = field(default_factory=list)
    matched_domains: list[str] = field(default_factory=list)
    score: int = 0
    error: bool = False


# ── Parsing helpers ───────────────────────────────────────────────────────────

def _parse_url_result(raw: dict) -> tuple[int, int, int, list[str]]:
    """Extract malicious/suspicious/total counts and categories from VT response."""
    if not raw or "error" in raw:
        return 0, 0, 0, []

    # VT API wraps stats in data.attributes.last_analysis_stats
    attrs = raw.get("data", {}).get("attributes", raw)
    stats = attrs.get("last_analysis_stats", attrs)

    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    harmless = int(stats.get("harmless", 0))
    undetected = int(stats.get("undetected", 0))
    total = malicious + suspicious + harmless + undetected

    categories = list(attrs.get("categories", {}).values()) if isinstance(
        attrs.get("categories"), dict
    ) else attrs.get("categories", [])

    return malicious, suspicious, total, categories


def _url_score(malicious: int, suspicious: int) -> int:
    """Score logic: malicious≥5→+3, 1–4→+2, suspicious≥3→+1."""
    if malicious >= 5:
        return 3
    if malicious >= 1:
        return 2
    if suspicious >= 3:
        return 1
    return 0


def _file_score(malicious: int, suspicious: int) -> int:
    """Score logic: malicious≥3→+3, 1–2→+2, suspicious≥2→+1."""
    if malicious >= 3:
        return 3
    if malicious >= 1:
        return 2
    if suspicious >= 2:
        return 1
    return 0


def _days_since(date_str: str) -> int | None:
    """Parse an ISO date string and return days since that date. Returns None on failure."""
    try:
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).days
    except Exception:
        return None


# ── Three async check functions ───────────────────────────────────────────────

async def scan_url(url: str) -> UrlScanResult:
    """
    Submit a single URL to VirusTotal via MCP and score the consensus verdict.

    Args:
        url: The URL to scan.

    Returns:
        UrlScanResult with engine counts and score contribution.
    """
    result = UrlScanResult(url=url)
    try:
        raw = await _cached_call(url, "get_url_report", {"url": url})
        if "error" in raw:
            result.error = True
            return result

        malicious, suspicious, total, categories = _parse_url_result(raw)
        result.malicious_count = malicious
        result.suspicious_count = suspicious
        result.total_engines = total
        result.categories = categories
        result.score = _url_score(malicious, suspicious)
        result.final_verdict = (
            "malicious" if malicious >= 1
            else "suspicious" if suspicious >= 3
            else "clean"
        )

        logger.info(
            "[L3-VT] url=%s engines=%d malicious=%d suspicious=%d score=+%d",
            url[:80], total, malicious, suspicious, result.score,
        )
    except Exception as exc:
        logger.error("[L3-VT] scan_url failed for %s: %s", url[:80], exc)
        result.error = True

    return result


async def scan_domain(domain: str) -> DomainScanResult:
    """
    Fetch VirusTotal domain report and score reputation + voting signals.

    Args:
        domain: Root domain from the sender's From address.

    Returns:
        DomainScanResult with reputation data and score contribution.
    """
    result = DomainScanResult(domain=domain)
    if not domain:
        return result

    try:
        raw = await _cached_call(domain, "get_domain_report", {"domain": domain})
        if "error" in raw:
            result.error = True
            return result

        attrs = raw.get("data", {}).get("attributes", raw)
        reputation = int(attrs.get("reputation", 0))
        votes = attrs.get("total_votes", {})
        malicious_votes = int(votes.get("malicious", 0)) if isinstance(votes, dict) else 0
        categories = list(attrs.get("categories", {}).values()) if isinstance(
            attrs.get("categories"), dict
        ) else []

        # Check creation date
        creation_date = attrs.get("creation_date", "")
        days_old = _days_since(str(creation_date)) if creation_date else None
        newly_seen = days_old is not None and days_old < 30

        result.reputation_score = reputation
        result.malicious_votes = malicious_votes
        result.categories = categories
        result.newly_seen = newly_seen

        score = 0
        if reputation < -20:
            score += 2
        if malicious_votes >= 3:
            score += 2
        if newly_seen:
            score += 1
        result.score = min(score, 3)

        logger.info(
            "[L3-VT] domain=%s reputation=%d votes=%d newly_seen=%s score=+%d",
            domain, reputation, malicious_votes, newly_seen, result.score,
        )
    except Exception as exc:
        logger.error("[L3-VT] scan_domain failed for %s: %s", domain, exc)
        result.error = True

    return result


async def scan_file_hash(filename: str, mime_type: str, content_bytes: bytes) -> FileScanResult:
    """
    Compute SHA-256 hash of an attachment and query VirusTotal's file database.
    The file is NEVER uploaded — only the hash is sent.

    Args:
        filename:      Original attachment filename (for logging).
        mime_type:     MIME type of the attachment.
        content_bytes: Raw bytes of the attachment.

    Returns:
        FileScanResult with engine counts and score contribution.
    """
    sha256 = hashlib.sha256(content_bytes).hexdigest()
    result = FileScanResult(filename=filename, sha256=sha256)

    try:
        raw = await _cached_call(sha256, "get_file_report", {"hash": sha256})
        if "error" in raw:
            # Hash not in VT database — not a flag (unknown ≠ malicious)
            result.error = False
            logger.info("[L3-VT] attachment=%s hash=%s not_in_vt_db score=+0", filename, sha256[:16])
            return result

        malicious, suspicious, _, _ = _parse_url_result(raw)
        result.malicious_count = malicious
        result.suspicious_count = suspicious
        result.score = _file_score(malicious, suspicious)

        logger.info(
            "[L3-VT] attachment=%s hash=%s malicious=%d suspicious=%d score=+%d",
            filename, sha256[:16], malicious, suspicious, result.score,
        )
    except Exception as exc:
        logger.error("[L3-VT] scan_file_hash failed for %s: %s", filename, exc)
        result.error = True

    return result


# ── College Database Checks ───────────────────────────────────────────────────

def _sync_check_scam_urls(urls: list[str]) -> list[str]:
    """Synchronous Supabase query for scam URLs."""
    client = get_supabase_client()
    if not client or not urls:
        return []
    
    # We query the 'scam_urls' table (user will create this with a 'url' column)
    # Using 'in_' filter for batched lookup
    try:
        response = client.table('scam_urls').select('url').in_('url', urls[:10]).execute()
        return [row['url'] for row in response.data]
    except Exception as e:
        logger.error("[L3-DB] Error querying scam_urls: %s", e)
        return []

def _sync_check_suspicious_domain(domain: str) -> list[str]:
    """Synchronous Supabase query for suspicious domain."""
    client = get_supabase_client()
    if not client or not domain:
        return []
    
    # We query the 'suspicious_domains' table (user will create this with a 'domain' column)
    try:
        response = client.table('suspicious_domains').select('domain').eq('domain', domain).execute()
        return [row['domain'] for row in response.data]
    except Exception as e:
        logger.error("[L3-DB] Error querying suspicious_domains: %s", e)
        return []

async def scan_college_database(urls: list[str], domain: str) -> CollegeDBScanResult:
    """Check extracted URLs and domain against custom Supabase college DB."""
    result = CollegeDBScanResult()
    
    # Execute synchronous DB queries in a thread pool
    try:
        matched_urls, matched_domains = await asyncio.gather(
            asyncio.to_thread(_sync_check_scam_urls, urls),
            asyncio.to_thread(_sync_check_suspicious_domain, domain)
        )
        
        result.matched_urls = matched_urls
        result.matched_domains = matched_domains
        
        # Scoring logic (+5 for any url match, +5 for domain match, but we'll sum and cap at 5 later)
        score = 0
        if matched_urls:
            score += 5
        if matched_domains:
            score += 5
            
        result.score = min(score, 5)
        
        if matched_urls or matched_domains:
            logger.info("[L3-DB] College DB Match! URLs: %s, Domains: %s, Score: +%d", 
                        len(matched_urls), len(matched_domains), result.score)
            
    except Exception as exc:
        logger.error("[L3-DB] scan_college_database failed: %s", exc)
        result.error = True

    return result


# ── Batch helpers (called by orchestrator) ────────────────────────────────────

async def scan_all_urls(urls: list[str]) -> list[UrlScanResult]:
    """
    Scan up to 3 URLs (respecting rate limits) and return results.
    We cap at 3 to stay within the free-tier budget per email.
    """
    results = []
    for url in urls[:3]:  # max 3 URL checks per email
        res = await scan_url(url)
        results.append(res)
    return results


async def scan_attachments(attachments: list[dict]) -> list[FileScanResult]:
    """Scan up to 1 suspicious attachment hash per email."""
    results = []
    for att in attachments[:1]:  # max 1 attachment check per email
        res = await scan_file_hash(
            att["filename"], att["mime_type"], att["content_bytes"]
        )
        results.append(res)
    return results


def aggregate_l3_score(
    url_results: list[UrlScanResult],
    domain_result: DomainScanResult,
    file_results: list[FileScanResult],
    college_db_result: CollegeDBScanResult,
) -> tuple[int, list[str], list[str]]:
    """
    Combine all L3 sub-results into a single capped score.

    Returns:
        (total_score, fired_reasons, flagged_urls)
        Score is capped at 3 (L3_CAP).
    """
    reasons: list[str] = []
    flagged_urls: list[str] = []
    max_score = 0

    for ur in url_results:
        if ur.score > 0:
            reasons.append(
                f"L3:url_malicious (url={ur.url[:60]} malicious={ur.malicious_count})"
            )
            flagged_urls.append(ur.url)
        max_score = max(max_score, ur.score)

    if domain_result.score > 0:
        reasons.append(
            f"L3:domain_flagged (domain={domain_result.domain} "
            f"reputation={domain_result.reputation_score} "
            f"votes={domain_result.malicious_votes})"
        )
        max_score = max(max_score, domain_result.score)

    for fr in file_results:
        if fr.score > 0:
            reasons.append(
                f"L3:attachment_malicious (file={fr.filename} malicious={fr.malicious_count})"
            )
        max_score = max(max_score, fr.score)

    if college_db_result.score > 0:
        if college_db_result.matched_urls:
            reasons.append(f"L3:college_db_url_match (count={len(college_db_result.matched_urls)})")
            flagged_urls.extend(college_db_result.matched_urls)
        if college_db_result.matched_domains:
            reasons.append(f"L3:college_db_domain_match (domain={college_db_result.matched_domains[0]})")
        
        # Max score considers the +3 from the college database match
        max_score = max(max_score, college_db_result.score)

    # Deduplicate flagged urls
    flagged_urls = list(set(flagged_urls))

    return min(max_score, 5), reasons, flagged_urls


async def check_threat_intel(ctx: EmailContext) -> tuple[int, list[str], list[str]]:
    """
    Full L3 stage: run URL, domain, and attachment checks concurrently.

    Args:
        ctx: Parsed EmailContext.

    Returns:
        (score, fired_reasons, flagged_urls)
    """
    url_results, domain_result, file_results, college_db_result = await asyncio.gather(
        scan_all_urls(ctx.urls),
        scan_domain(ctx.sender_domain),
        scan_attachments(ctx.attachments),
        scan_college_database(ctx.urls, ctx.sender_domain),
    )

    score, reasons, flagged_urls = aggregate_l3_score(
        url_results, domain_result, file_results, college_db_result
    )

    logger.info("[L3] [%s] total_score=%d flagged_urls=%d", ctx.message_id, score, len(flagged_urls))
    return score, reasons, flagged_urls

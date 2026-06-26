"""
ai_client.py — calls the Gemini API to enrich one finding.
Returns a dict with EXACTLY these keys: severity_rating, explanation,
remediation, cwe. Never raises to the caller — on any failure it returns a safe
stub so one bad API call can't stall the queue.

Uses the current `google-genai` SDK (`from google import genai`); the older
`google-generativeai` package is deprecated/unsupported.
"""

import json
import asyncio
import logging

from google import genai
from google.genai import types, errors

from app.config import GEMINI_API_KEY, GEMINI_MODEL

logger = logging.getLogger(__name__)

# Shape we promise the rest of the pipeline. Used as the failure fallback too.
_REQUIRED_KEYS = ("severity_rating", "explanation", "remediation", "cwe")

# Free-tier rate limits return HTTP 429 (errors.ClientError.code == 429). Back off and retry.
_BACKOFF_SCHEDULE = (5, 10, 20)   # seconds — exponential

SYSTEM_PROMPT = (
    "You are a senior application security engineer. You receive one security finding "
    "as JSON and explain it for a developer who is NOT a security expert. "
    "Respond with a SINGLE JSON object and nothing else — no markdown, no code fences, "
    "no prose before or after. The object MUST have exactly these keys: "
    "severity_rating, explanation, remediation, cwe."
)

# Build the client + per-request config once, at import time. Guard on the key so the
# stub path (Option B / missing key) never touches the network.
_client = None
_GEN_CONFIG = types.GenerateContentConfig(
    system_instruction=SYSTEM_PROMPT,
    response_mime_type="application/json",   # ask the API itself for valid JSON
)
if GEMINI_API_KEY:
    _client = genai.Client(api_key=GEMINI_API_KEY)


def _build_user_prompt(finding: dict) -> str:
    return (
        "Analyse this finding and produce the JSON described in your instructions.\n"
        "- severity_rating: one of CRITICAL/HIGH/MEDIUM/LOW, your assessment of real-world risk.\n"
        "- explanation: 2-3 sentences, plain English, what the risk is.\n"
        "- remediation: the concrete change to make, with a short code snippet if helpful.\n"
        "- cwe: the most relevant CWE identifier (e.g. \"CWE-502\").\n\n"
        f"FINDING:\n{json.dumps(finding, indent=2)}"
    )


def _safe_stub(finding: dict, reason: str) -> dict:
    """Returned when the API key is missing or the call/parse fails."""
    return {
        "severity_rating": finding.get("severity", "UNKNOWN"),
        "explanation": f"(AI enrichment unavailable: {reason}) "
                       f"{finding.get('description', 'Security finding')}.",
        "remediation": finding.get("recommendation", "Review against OWASP Top 10."),
        "cwe": finding.get("cwe", "CWE-Unknown"),
    }


def _coerce_json(text: str) -> dict:
    """Strip accidental code fences and parse. Raises on genuine non-JSON."""
    t = text.strip()
    if t.startswith("```"):
        # remove leading ```json / ``` and trailing ```
        t = t.split("\n", 1)[1] if "\n" in t else t
        t = t.rsplit("```", 1)[0]
    return json.loads(t.strip())


async def _generate(prompt: str) -> str:
    """Call Gemini, retrying free-tier rate limits (HTTP 429) with 5s/10s/20s backoff."""
    for delay in (*_BACKOFF_SCHEDULE, None):
        try:
            resp = await _client.aio.models.generate_content(
                model=GEMINI_MODEL, contents=prompt, config=_GEN_CONFIG)
            return resp.text
        except errors.APIError as e:
            # 429 = rate limited; retry until backoffs exhausted. Anything else -> caller stubs.
            if getattr(e, "code", None) != 429 or delay is None:
                raise
            logger.warning("Gemini rate limited (429); retrying in %ss", delay)
            await asyncio.sleep(delay)


async def enrich(finding: dict) -> dict:
    """Enrich one finding. Always returns a dict with _REQUIRED_KEYS."""
    if not _client:
        return _safe_stub(finding, "no GEMINI_API_KEY set")

    try:
        text = await _generate(_build_user_prompt(finding))   # the model's reply
        parsed = _coerce_json(text)

        # Guarantee the contract: fill any missing key rather than trust the model blindly.
        return {k: parsed.get(k, _safe_stub(finding, "missing key")[k]) for k in _REQUIRED_KEYS}

    except errors.APIError as e:
        logger.error("Gemini API error (code %s); using stub", getattr(e, "code", "?"))
        return _safe_stub(finding, f"API {getattr(e, 'code', 'error')}")
    except (json.JSONDecodeError, ValueError, KeyError) as e:
        logger.error("Gemini call/parse failed: %s", e)
        return _safe_stub(finding, type(e).__name__)
    except Exception as e:                          # belt-and-braces: never raise to consumer
        logger.error("Gemini unexpected error: %s", e)
        return _safe_stub(finding, type(e).__name__)
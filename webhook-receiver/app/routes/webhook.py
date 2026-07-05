import logging
from fastapi import APIRouter, Request
from app.publisher import publish_message

router = APIRouter()

@router.post("/webhook")
async def handle_webhook(request: Request):
    payload = await request.json()
    try:
        pr   = payload.get("pull_request", {})
        repo = payload.get("repository", {})
        job = {
            "job_id":   str(pr.get("id") or payload.get("after") or "manual"),
            "language": "python",
            "code":     "",                       # Phase 10 fills this from the PR diff; empty is OK now
            "meta": {
                "repo":       repo.get("full_name", ""),     # "owner/name"
                "pr_number":  pr.get("number"),
                "commit_sha": (pr.get("head") or {}).get("sha", ""),
            },
        }
        await publish_message(job)  # mints + sets correlation_id_var for this request's context
        logging.info("received webhook payload", extra={"repo": repo.get("full_name", "")})
    except Exception as e:
        logging.error(f"publisher failed: {e}")
    return {"status": "received"}

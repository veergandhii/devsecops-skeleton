from fastapi import APIRouter, Request
from app.publisher import publish_message

router = APIRouter()

@router.post("/webhook")
async def handle_webhook(request: Request):
    payload = await request.json()
    try:
        await publish_message(payload)
        print("Received webhook payload:", payload)
    except Exception as e:
        print(f"Publisher failed: {e}")  # this will show what's actually breaking
    return {"status": "received"}
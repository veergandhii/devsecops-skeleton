from fastapi import  APIRouter,Request 
router=APIRouter()
@router.post("/webhook")
async def handle_webhook(request:Request):
    payload=await request.json()
    print("Received webhook payload:",payload)
    return{"status":"received"}

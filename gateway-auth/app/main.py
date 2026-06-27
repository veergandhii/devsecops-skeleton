import os
import jwt                       # PyJWT
from fastapi import FastAPI, Request, Response

app = FastAPI(title="gateway-auth")

JWT_SECRET = os.getenv("JWT_SECRET", "")     # MUST match the secret used to mint tokens
ALGORITHM  = "HS256"


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "gateway-auth"}


# Traefik's ForwardAuth middleware calls THIS for every protected request. It forwards the
# original headers, so we read the caller's Authorization header here. Return 200 → allow;
# any 4xx → Traefik blocks the request with that status.
@app.get("/verify")
async def verify(request: Request):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return Response(status_code=401, content="missing bearer token")
    token = auth.split(" ", 1)[1]
    try:
        jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])  # raises if bad sig / expired
        return Response(status_code=200, content="ok")
    except jwt.PyJWTError as e:
        return Response(status_code=401, content=f"invalid token: {e}")
    
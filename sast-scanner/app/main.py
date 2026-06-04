import asyncio
import uvicorn
from contextlib import asynccontextmanager
from fastapi import FastAPI

from app.routes.health import router as health_router
from app.consumer import start_consumer
from app.config import PORT


# ── Lifespan: start the RabbitMQ consumer alongside the HTTP server ──────────
# Using asynccontextmanager lifespan (FastAPI 0.93+) instead of deprecated
# on_event("startup") — runs start_consumer as a background task so it doesn't
# block uvicorn from finishing startup.
@asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.create_task(start_consumer())
    yield
    task.cancel()   # graceful shutdown: cancel consumer when uvicorn stops


app = FastAPI(title="sast-scanner", lifespan=lifespan)
app.include_router(health_router)


# ── Entrypoint (used by Dockerfile CMD via uvicorn CLI, but kept here for
#    local `python -m app.main` runs too) ─────────────────────────────────────
if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=PORT, reload=False)
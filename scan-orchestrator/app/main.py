import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI
from app.routes.health import router as health_router
from app import config
from app.consumer import start_consumer

from app.logging_config import setup_logging
setup_logging("scan-orchestrator")

async def keep_loop_alive():
    while True:
        await asyncio.sleep(0.1)  # yields to event loop every 100ms

@asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.create_task(start_consumer())
    ticker = asyncio.create_task(keep_loop_alive())
    yield
    task.cancel()
    ticker.cancel()
    try:
        await task
        await ticker
    except asyncio.CancelledError:
        pass

app = FastAPI(title=config.APP_NAME, version=config.APP_VERSION, lifespan=lifespan)

@app.get("/")
def root():
    return {"name": config.APP_NAME, "version": config.APP_VERSION}

app.include_router(health_router)
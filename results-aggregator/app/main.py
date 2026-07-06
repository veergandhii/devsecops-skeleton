import asyncio, uvicorn
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.logging_config import setup_logging      # from Phase 11
from app.models import init_db
from app.consumer import start_consumer
from app.api import router as api_router
from app.routes.health import router as health_router
from app.config import PORT

setup_logging("results-aggregator")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()                                       # create tables before consuming
    task = asyncio.create_task(start_consumer())
    yield
    task.cancel()


app = FastAPI(title="results-aggregator", lifespan=lifespan)
app.mount("/static", StaticFiles(directory="app/static"), name="static")
app.include_router(health_router)
app.include_router(api_router)

if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=int(PORT))
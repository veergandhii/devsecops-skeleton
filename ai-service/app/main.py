import asyncio
import uvicorn
from contextlib import asynccontextmanager
from fastapi import FastAPI

from app.routes.health import router as health_router
from app.consumer import start_consumer
from app.config import PORT
from app.logging_config import setup_logging
setup_logging("ai-service")

# Lifespan replaces the deprecated @app.on_event("startup"). Code before `yield`
# runs at startup, code after runs at shutdown. We launch the RabbitMQ consumer as
# a background task so it runs concurrently with the HTTP server (it never returns —
# it loops forever consuming messages — so it must NOT be awaited directly here).
@asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.create_task(start_consumer())
    yield
    task.cancel()   # graceful shutdown: stop the consumer when uvicorn stops


app = FastAPI(title="ai-service", lifespan=lifespan)
app.include_router(health_router)




# Lets you run `python -m app.main` locally; the Dockerfile uses the uvicorn CLI.
if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=int(PORT), reload=False)
from fastapi import FastAPI
from app.routes.health import router as health_router
from app.routes.webhook import router as webhook_router
from app import config
app= FastAPI(title=config.APP_NAME,version=config.APP_VERSION)
app.include_router(health_router)
app.include_router(webhook_router)
@app.get("/")
def root():
    return{"name":config.APP_NAME,"version":config.APP_VERSION}


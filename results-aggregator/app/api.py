from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
import httpx

from app.config import SERVICES
from app import models

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


@router.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse(request, "index.html", {
        "runs": models.get_runs(), "counts": models.severity_counts(),
    })


@router.get("/findings", response_class=HTMLResponse)
async def findings(request: Request, severity: str = None, tool: str = None):
    return templates.TemplateResponse(request, "findings.html", {
        "findings": models.get_findings(severity, tool),
        "severity": severity, "tool": tool,
    })


@router.get("/fixes", response_class=HTMLResponse)
async def fixes(request: Request):
    # group findings by file (location's path part) for the AI Fixes page
    grouped = {}
    for f in models.get_findings():
        grouped.setdefault(f["location"], []).append(f)
    return templates.TemplateResponse(request, "fixes.html", {"grouped": grouped})


@router.get("/services", response_class=HTMLResponse)
async def services(request: Request):
    statuses = {}
    async with httpx.AsyncClient(timeout=3) as client:
        for name, url in SERVICES.items():
            try:
                statuses[name] = (await client.get(url)).json().get("status", "down")
            except Exception:
                statuses[name] = "down"
    return templates.TemplateResponse(request, "services.html", {"statuses": statuses})


@router.get("/api/severity")           # JSON for the Chart.js severity bar on Home
async def api_severity():
    return JSONResponse(models.severity_counts())
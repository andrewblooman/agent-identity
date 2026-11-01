"""The FastAPI app. It has no login, so it must stay bound to localhost."""

from __future__ import annotations

import threading
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.trustedhost import TrustedHostMiddleware

from agent_identity import db, scan
from agent_identity.config import Settings, get_settings
from agent_identity.models import Result, Snapshot
from agent_identity.web import charts, filters, views

WEB = Path(__file__).parent / "web"
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
    "form-action 'self'"
)


@lru_cache(maxsize=4)
def _parse(scan_id: int, snapshot_json: str, result_json: str) -> tuple[Snapshot, Result]:
    return Snapshot.model_validate_json(snapshot_json), Result.model_validate_json(result_json)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    engine = db.create_db(settings.database_path)
    db.fail_interrupted_scans(engine)
    scan.seed_demo(engine)

    app = FastAPI(title="Agent Identity", docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)
    app.mount("/static", StaticFiles(directory=WEB / "static"), name="static")
    templates = Jinja2Templates(directory=WEB / "templates")
    filters.register(templates.env)
    templates.env.globals["charts"] = charts
    scan_lock = threading.Lock()

    @app.middleware("http")
    async def security(request: Request, call_next):
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            origin = request.headers.get("origin")
            host = request.headers.get("host", "")
            cross_origin = origin is not None and urlsplit(origin).netloc != host
            if cross_origin or request.headers.get("sec-fetch-site") == "cross-site":
                return PlainTextResponse("Cross-site request blocked", status_code=403)
        response: Response = await call_next(request)
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    def current_view(request: Request) -> str:
        view = request.cookies.get("view", settings.default_view)
        return view if view in {"demo", "live"} else "demo"

    def render(request: Request, template: str, build, **extra) -> HTMLResponse:
        view = current_view(request)
        latest = db.latest_scan(engine, view)
        context = {
            "view": view,
            "path": request.url.path,
            "running": db.running_scan(engine),
            "latest": latest,
            **extra,
        }
        if latest is None:
            return templates.TemplateResponse(request, "empty.html", context)
        snapshot, result = _parse(latest.id, latest.snapshot_json, latest.result_json)
        estate = views.Estate(snapshot, result)
        context["estate"] = estate
        context.update(build(estate))
        if request.headers.get("hx-request") and "partial" in context:
            return templates.TemplateResponse(request, context["partial"], context)
        return templates.TemplateResponse(request, template, context)

    @app.get("/", response_class=HTMLResponse)
    def overview(request: Request):
        view = current_view(request)

        def build(estate: views.Estate) -> dict:
            previous = db.previous_scan(engine, view, db.latest_scan(engine, view))
            prior = None
            if previous is not None:
                prior = _parse(previous.id, previous.snapshot_json, previous.result_json)[1]
            return views.overview(estate, prior)

        return render(request, "overview.html", build)

    @app.get("/agents", response_class=HTMLResponse)
    def agents(request: Request):
        params = dict(request.query_params)
        return render(request, "agents.html", lambda e: views.agents(e, params))

    @app.get("/agents/{agent_id}", response_class=HTMLResponse)
    def agent_detail(request: Request, agent_id: str):
        def build(estate: views.Estate) -> dict:
            if agent_id not in estate.agents:
                raise HTTPException(404, "No agent with that ID in this scan")
            return views.agent_detail(estate, agent_id)

        return render(request, "agent.html", build)

    @app.get("/data", response_class=HTMLResponse)
    def data(request: Request):
        params = dict(request.query_params)
        return render(request, "data.html", lambda e: views.data_access(e, params))

    @app.get("/data/store", response_class=HTMLResponse)
    def data_store(request: Request, arn: str):
        def build(estate: views.Estate) -> dict:
            if arn not in estate.stores:
                raise HTTPException(404, "No data store with that ARN in this scan")
            return views.store_detail(estate, arn)

        return render(request, "store.html", build)

    @app.get("/identity", response_class=HTMLResponse)
    def identity(request: Request):
        return render(request, "identity.html", views.identity)

    @app.get("/identity/detail", response_class=HTMLResponse)
    def identity_detail(request: Request, arn: str):
        def build(estate: views.Estate) -> dict:
            if arn not in estate.identities:
                raise HTTPException(404, "No identity with that ARN in this scan")
            return views.identity_detail(estate, arn)

        return render(request, "identity_detail.html", build)

    @app.get("/secrets", response_class=HTMLResponse)
    def secrets(request: Request):
        return render(request, "secrets.html", views.secrets)

    @app.get("/network", response_class=HTMLResponse)
    def network(request: Request):
        return render(request, "network.html", views.network)

    @app.get("/runtime", response_class=HTMLResponse)
    def runtime(request: Request):
        return render(request, "runtime.html", views.runtime)

    @app.get("/saas", response_class=HTMLResponse)
    def saas(request: Request):
        return render(request, "saas.html", views.saas)

    @app.get("/findings", response_class=HTMLResponse)
    def findings(request: Request):
        params = dict(request.query_params)
        return render(request, "findings.html", lambda e: views.findings(e, params))

    @app.get("/frameworks", response_class=HTMLResponse)
    def frameworks(request: Request):
        return render(request, "frameworks.html", views.frameworks)

    @app.get("/scans", response_class=HTMLResponse)
    def scans(request: Request):
        view = current_view(request)
        context = {
            "view": view,
            "path": "/scans",
            "running": db.running_scan(engine),
            "history": db.scan_history(engine),
            "settings": settings,
        }
        latest = db.latest_scan(engine, view)
        context["latest"] = latest
        if latest is not None:
            snapshot, result = _parse(latest.id, latest.snapshot_json, latest.result_json)
            context["estate"] = views.Estate(snapshot, result)
        return templates.TemplateResponse(request, "scans.html", context)

    @app.get("/scans/status", response_class=HTMLResponse)
    def scan_status(request: Request):
        running = db.running_scan(engine)
        response = templates.TemplateResponse(request, "_scan_status.html", {"running": running})
        if running is None and request.query_params.get("was") == "running":
            response.headers["HX-Refresh"] = "true"
        return response

    @app.post("/scans/live")
    def start_live_scan():
        with scan_lock:
            if db.running_scan(engine) is None:
                scan_id = db.start_scan(engine, "live")
                threading.Thread(
                    target=scan.run_live_scan, args=(engine, settings, scan_id), daemon=True
                ).start()
        response = RedirectResponse("/scans", status_code=303)
        response.set_cookie("view", "live", httponly=True, samesite="strict")
        return response

    @app.post("/view/{mode}")
    def switch_view(mode: str):
        if mode not in {"demo", "live"}:
            raise HTTPException(404, "Unknown view")
        response = RedirectResponse("/", status_code=303)
        response.set_cookie("view", mode, httponly=True, samesite="strict")
        return response

    return app

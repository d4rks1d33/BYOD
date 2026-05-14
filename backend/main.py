from __future__ import annotations
import uuid
import logging
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from core.config import get_settings
from core.database import init_db, close_db
from core.logging import setup_logging
from core.redis import close_redis

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    setup_logging(settings.LOG_LEVEL)
    await init_db()
    logger.info("AutoPentest API started", extra={"environment": settings.ENVIRONMENT})
    yield
    await close_db()
    await close_redis()
    logger.info("AutoPentest API shutdown")


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title="AutoPentest API",
        version="1.0.0",
        description="AI-powered DAST/SAST security platform",
        lifespan=lifespan,
        docs_url="/docs" if settings.ENVIRONMENT != "production" else None,
        redoc_url="/redoc" if settings.ENVIRONMENT != "production" else None,
        redirect_slashes=False,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Security headers middleware
    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response

    # Request ID middleware
    @app.middleware("http")
    async def request_id_middleware(request: Request, call_next):
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        request.state.request_id = request_id
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response

    # Global exception handler
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        request_id = getattr(request.state, "request_id", None)
        logger.error(f"Unhandled error: {exc}", exc_info=True, extra={"request_id": request_id})
        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "code": "INTERNAL_ERROR",
                    "message": "An unexpected error occurred",
                    "request_id": request_id,
                }
            },
        )

    # Include routers
    from api.routers import auth, projects, scans, findings, evidence, reports
    from api.routers import ai_models, plugins, users, audit, health, metrics
    from api import websocket

    app.include_router(auth.router, prefix="/auth", tags=["auth"])
    app.include_router(projects.router, prefix="/projects", tags=["projects"])
    app.include_router(scans.router, tags=["scans"])
    app.include_router(findings.router, tags=["findings"])
    app.include_router(evidence.router, tags=["evidence"])
    app.include_router(reports.router, tags=["reports"])
    app.include_router(ai_models.router, tags=["ai"])
    app.include_router(plugins.router, tags=["plugins"])
    app.include_router(users.router, tags=["users"])
    app.include_router(audit.router, tags=["audit"])
    app.include_router(health.router, prefix="/health", tags=["health"])
    app.include_router(metrics.router, tags=["metrics"])
    app.include_router(websocket.router, tags=["websocket"])

    return app


app = create_app()

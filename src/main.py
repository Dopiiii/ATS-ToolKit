"""
FastAPI application entry point.

This module creates and configures the FastAPI application,
including middleware, exception handlers, and routers.
"""

import time
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from src import __version__
from src.api.v1 import router as v1_router
from src.config import settings
from src.core.database import close_db, init_db
from src.core.exceptions import APIError
from src.core.logging import get_logger, log_request, setup_logging

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator:
    """
    Application lifespan handler.

    Runs startup and shutdown logic.
    """
    # Startup
    setup_logging()
    logger.info(
        "Starting OSINT Platform",
        version=__version__,
        env=settings.ENV,
        debug=settings.DEBUG,
    )

    # Initialize database (for dev; use migrations in production)
    if settings.DEBUG:
        await init_db()
        logger.info("Database tables initialized")

    yield

    # Shutdown
    logger.info("Shutting down OSINT Platform")
    await close_db()


# Create FastAPI app
app = FastAPI(
    title=settings.APP_NAME,
    description="""
## OSINT Platform API

Enterprise intelligence gathering and analysis platform.

### Features
- **Authentication**: JWT-based auth with refresh tokens
- **User Management**: RBAC with admin, analyst, viewer roles
- **API Keys**: Scoped API keys for programmatic access
- **Audit Logging**: Complete audit trail of all actions

### Authentication

Use one of:
- **Bearer Token**: `Authorization: Bearer <jwt_token>`
- **API Key**: `X-API-Key: <api_key>`
    """,
    version=__version__,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)


# =============================================================================
# Middleware
# =============================================================================


# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all requests with timing."""
    start_time = time.perf_counter()

    # Process request
    response = await call_next(request)

    # Calculate duration
    duration_ms = (time.perf_counter() - start_time) * 1000

    # Log request (skip health checks in production)
    if settings.DEBUG or request.url.path != "/api/v1/health":
        log_request(
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            duration_ms=duration_ms,
            client_ip=request.client.host if request.client else None,
        )

    # Add timing header
    response.headers["X-Response-Time"] = f"{duration_ms:.2f}ms"

    return response


# =============================================================================
# Exception Handlers
# =============================================================================


@app.exception_handler(APIError)
async def api_error_handler(request: Request, exc: APIError) -> JSONResponse:
    """Handle custom API exceptions."""
    return JSONResponse(
        status_code=exc.status_code,
        content=exc.to_dict(),
    )


@app.exception_handler(RequestValidationError)
async def validation_error_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """Handle Pydantic validation errors."""
    errors = []
    for error in exc.errors():
        field = ".".join(str(loc) for loc in error["loc"])
        errors.append({
            "field": field,
            "message": error["msg"],
            "type": error["type"],
        })

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": {
                "code": "validation_error",
                "message": "Request validation failed",
                "details": {"errors": errors},
            }
        },
    )


@app.exception_handler(Exception)
async def generic_error_handler(request: Request, exc: Exception) -> JSONResponse:
    """Handle unexpected exceptions."""
    logger.exception(
        "Unhandled exception",
        path=request.url.path,
        method=request.method,
        error=str(exc),
    )

    # Don't expose internal errors in production
    if settings.DEBUG:
        message = str(exc)
    else:
        message = "An internal error occurred"

    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": {
                "code": "internal_error",
                "message": message,
            }
        },
    )


# =============================================================================
# Routes
# =============================================================================


# Include API v1 router
app.include_router(v1_router, prefix="/api")


@app.get("/", include_in_schema=False)
async def root():
    """Redirect to API docs."""
    return {
        "message": "OSINT Platform API",
        "version": __version__,
        "docs": "/docs",
        "api": "/api/v1",
    }


# =============================================================================
# CLI Entry Point
# =============================================================================


def cli():
    """CLI entry point for running the server."""
    import uvicorn

    uvicorn.run(
        "src.main:app",
        host=settings.API_HOST,
        port=settings.API_PORT,
        reload=settings.DEBUG,
        workers=1 if settings.DEBUG else settings.API_WORKERS,
        log_level=settings.LOG_LEVEL.lower(),
    )


if __name__ == "__main__":
    cli()

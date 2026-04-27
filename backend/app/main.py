import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.router import api_router
from app.core.config import settings
from app.db.session import create_database_tables
from app.db.session import SessionLocal
from app.services.detection_service import seed_default_rules


@asynccontextmanager
async def lifespan(app: FastAPI):
    create_database_tables()
    db = SessionLocal()
    try:
        seed_default_rules(db)
    finally:
        db.close()

    # Start syslog TCP receiver if enabled
    syslog_task: asyncio.Task | None = None
    if settings.syslog_tcp_enabled:
        from app.services.syslog_tcp_service import run_syslog_server
        syslog_task = asyncio.create_task(
            run_syslog_server(settings.syslog_tcp_host, settings.syslog_tcp_port),
            name="syslog-tcp-receiver",
        )
        import logging
        logging.getLogger("techvsoc.syslog").info(
            "Syslog TCP receiver starting on %s:%d",
            settings.syslog_tcp_host,
            settings.syslog_tcp_port,
        )

    yield

    # Cancel syslog task on shutdown
    if syslog_task and not syslog_task.done():
        syslog_task.cancel()
        try:
            await syslog_task
        except asyncio.CancelledError:
            pass


def create_application() -> FastAPI:
    app = FastAPI(
        title=settings.app_name,
        version="0.1.0",
        debug=settings.debug,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url=f"{settings.api_v1_prefix}/openapi.json",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(api_router, prefix=settings.api_v1_prefix)

    @app.get("/", tags=["root"])
    async def root() -> dict[str, str]:
        return {
            "app": settings.app_name,
            "status": "running",
            "docs": "/docs",
        }

    return app


app = create_application()

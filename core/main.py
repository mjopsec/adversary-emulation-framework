"""
AE Platform — Entry Point Utama

Dua mode penggunaan:
1. API Server:  python -m core.main serve
2. CLI Tools:   python -m core.main [command]

CLI Commands:
- serve          Jalankan API server (default)
- init-db        Inisialisasi/migrasi database
- sync-attack    Download dan sinkronisasi data MITRE ATT&CK
- version        Tampilkan versi platform
"""

import asyncio
import sys

import typer
import uvicorn
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from loguru import logger
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from core.config import get_settings
from core.database import close_database, create_all_tables, init_database
from core.logging_setup import setup_logging

console = Console()
cli_app = typer.Typer(
    name="aep",
    help="AE Platform — AI-Powered Adversary Emulation Platform",
    add_completion=False,
)


# ─── FastAPI Application ──────────────────────────────────────────────────────

def create_app() -> FastAPI:
    """Factory function untuk membuat FastAPI app instance."""
    settings = get_settings()

    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description=(
            "AI-Powered Adversary Emulation Platform untuk ICS/OT + Enterprise IT. "
            "Hanya untuk authorized engagement dengan scope dan RoE yang jelas."
        ),
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )

    # ─── CORS ─────────────────────────────────────────────────────────────────
    # Wildcard digunakan karena ini tools lokal — tidak ada credential cookie.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ─── Event Handlers ───────────────────────────────────────────────────────
    @app.on_event("startup")
    async def on_startup() -> None:
        setup_logging(settings)
        logger.info("=" * 60)
        logger.info("  {} v{}", settings.app_name, settings.app_version)
        logger.info("  Mode: {}", "DEBUG" if settings.debug else "PRODUCTION")
        logger.info("  AI Engine: {}", "AKTIF" if settings.has_ai_configured else "DETERMINISTIK")
        logger.info("=" * 60)

        init_database(settings.database_url, settings.debug)
        await create_all_tables()

        # Load APT profiles bawaan jika belum ada
        from core.database import _session_factory
        if _session_factory:
            async with _session_factory() as session:
                from core.intel.apt_profiles_loader import load_builtin_profiles
                await load_builtin_profiles(session)

        logger.info("Platform siap. API tersedia di http://{}:{}", settings.api_host, settings.api_port)

    @app.on_event("shutdown")
    async def on_shutdown() -> None:
        await close_database()
        logger.info("Platform shutdown selesai.")

    # ─── Global Exception Handler ─────────────────────────────────────────────
    @app.exception_handler(Exception)
    async def global_exception_handler(request, exc: Exception) -> JSONResponse:
        logger.error("Unhandled exception: {}", exc)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error. Cek log untuk detail."},
        )

    # ─── Routes ───────────────────────────────────────────────────────────────
    from core.api.v1.router import api_router
    app.include_router(api_router, prefix=settings.api_prefix)

    # ─── Frontend Dashboard (Static SPA) ──────────────────────────────────────
    _frontend_dir = Path(__file__).parent.parent / "frontend"
    if _frontend_dir.exists():
        app.mount("/ui", StaticFiles(directory=str(_frontend_dir), html=True), name="frontend")

        @app.get("/ui", include_in_schema=False)
        @app.get("/ui/", include_in_schema=False)
        async def ui_index() -> FileResponse:
            return FileResponse(str(_frontend_dir / "index.html"))

    # ─── Agent Script Download ────────────────────────────────────────────────
    _agent_script = Path(__file__).parent.parent / "agents" / "aep_agent.py"

    @app.get("/agent.py", include_in_schema=False, tags=["agent-deploy"])
    async def download_agent() -> FileResponse:
        """Serve aep_agent.py — untuk quick-deploy ke target machine."""
        if not _agent_script.exists():
            return JSONResponse({"detail": "Agent script not found."}, status_code=404)
        return FileResponse(
            str(_agent_script),
            media_type="text/x-python",
            filename="aep_agent.py",
        )

    # Root — tampilkan info platform + link ke UI
    @app.get("/", include_in_schema=False)
    async def root() -> JSONResponse:
        return JSONResponse({
            "platform": settings.app_name,
            "version": settings.app_version,
            "ui": "http://localhost:8000/ui",
            "docs": "/docs",
            "api": settings.api_prefix,
            "agent_download": "http://localhost:8000/agent.py",
        })

    return app


# ─── CLI Commands ─────────────────────────────────────────────────────────────

@cli_app.command()
def serve(
    host: str = typer.Option(None, "--host", "-h", help="Host untuk server API"),
    port: int = typer.Option(None, "--port", "-p", help="Port untuk server API"),
    reload: bool = typer.Option(False, "--reload", help="Auto-reload saat development"),
) -> None:
    """Jalankan AE Platform API server."""
    settings = get_settings()

    _print_banner()

    uvicorn.run(
        "core.main:create_app",
        factory=True,
        host=host or settings.api_host,
        port=port or settings.api_port,
        reload=reload,
        log_level="debug" if settings.debug else "info",
        access_log=True,
    )


@cli_app.command()
def init_db() -> None:
    """Inisialisasi database dan buat semua tabel."""
    async def _init() -> None:
        settings = get_settings()
        setup_logging(settings)
        init_database(settings.database_url, settings.debug)
        await create_all_tables()

        from core.database import _session_factory
        if _session_factory:
            async with _session_factory() as session:
                from core.intel.apt_profiles_loader import load_builtin_profiles
                result = await load_builtin_profiles(session)
                console.print(f"[green]APT profiles loaded: {result}[/green]")

        await close_database()
        console.print("[green]✓ Database berhasil diinisialisasi.[/green]")

    asyncio.run(_init())


@cli_app.command()
def sync_attack(
    skip_enterprise: bool = typer.Option(False, help="Lewati Enterprise ATT&CK"),
    skip_ics: bool = typer.Option(False, help="Lewati ICS ATT&CK"),
) -> None:
    """Download dan sinkronisasi data MITRE ATT&CK ke database."""
    async def _sync() -> None:
        settings = get_settings()
        setup_logging(settings)
        init_database(settings.database_url, settings.debug)
        await create_all_tables()

        from core.intel.attack_loader import ATTACKLoader
        from core.database import _session_factory

        loader = ATTACKLoader(settings)

        with console.status("[bold green]Mengunduh dan memproses data ATT&CK..."):
            await loader.ensure_data_available(auto_download=True)

        if _session_factory:
            async with _session_factory() as session:
                result = await loader.sync_to_database(session)
                console.print(
                    f"[green]✓ Sync selesai: {result['inserted']} teknik baru, "
                    f"{result['updated']} teknik diupdate.[/green]"
                )

        await close_database()

    asyncio.run(_sync())


@cli_app.command()
def version() -> None:
    """Tampilkan versi platform."""
    settings = get_settings()
    console.print(f"[bold]{settings.app_name}[/bold] v{settings.app_version}")


# ─── Banner ───────────────────────────────────────────────────────────────────

def _print_banner() -> None:
    settings = get_settings()
    banner_text = Text()
    banner_text.append("AE PLATFORM", style="bold red")
    banner_text.append(f"  v{settings.app_version}\n", style="dim")
    banner_text.append("AI-Powered Adversary Emulation Platform\n", style="cyan")
    banner_text.append("ICS/OT + Enterprise IT\n\n", style="cyan")
    banner_text.append(f"API: http://{settings.api_host}:{settings.api_port}\n", style="green")
    banner_text.append(f"AI Engine: ", style="white")
    if settings.has_ai_configured:
        banner_text.append("AKTIF ✓\n", style="green")
    else:
        banner_text.append("Mode Deterministik (set ANTHROPIC_API_KEY untuk AI penuh)\n", style="yellow")
    banner_text.append(
        "\n⚠  Hanya untuk authorized engagement dengan scope dan RoE yang jelas.",
        style="bold yellow",
    )

    console.print(Panel(banner_text, border_style="red", padding=(1, 2)))


# ─── Entry Points ─────────────────────────────────────────────────────────────

# Untuk: python -m core.main
if __name__ == "__main__":
    cli_app()

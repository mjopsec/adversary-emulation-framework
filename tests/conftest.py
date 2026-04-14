"""Konfigurasi pytest dan fixtures bersama."""

import asyncio
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from core.config import Settings
from core.database import Base, init_database
from core.main import create_app


# ─── Settings Override untuk Testing ─────────────────────────────────────────

@pytest.fixture(scope="session")
def test_settings() -> Settings:
    """Settings dengan SQLite in-memory untuk testing."""
    settings = Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        debug=True,
        log_level="DEBUG",
        anthropic_api_key=None,  # Mode deterministik untuk tests
    )
    settings.ensure_directories()
    return settings


# ─── Database Fixtures ────────────────────────────────────────────────────────

@pytest_asyncio.fixture(scope="function")
async def db_session(test_settings: Settings):
    """Sesi database in-memory per test, auto-rollback setelah selesai."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)

    # Buat tabel
    from core.models import (  # noqa: F401
        APTProfile, Campaign, CampaignStep, Execution, Finding, Technique
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        yield session

    await engine.dispose()


# ─── HTTP Client Fixture ──────────────────────────────────────────────────────

@pytest_asyncio.fixture(scope="function")
async def client(test_settings: Settings):
    """HTTP test client untuk FastAPI app."""
    app = create_app()
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as ac:
        yield ac

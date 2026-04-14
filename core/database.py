"""
Konfigurasi database menggunakan SQLAlchemy 2.0 async.
Mendukung SQLite (development) dan PostgreSQL (production).
"""

from collections.abc import AsyncGenerator

from loguru import logger
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """
    Base class untuk semua ORM model.
    Semua model mewarisi dari class ini.
    """
    pass


# Variabel engine dan session_factory diinisialisasi saat startup
_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def init_database(database_url: str, debug: bool = False) -> None:
    """
    Inisialisasi async engine dan session factory.
    Dipanggil satu kali saat aplikasi startup.
    """
    global _engine, _session_factory

    # SQLite memerlukan flag check_same_thread=False via connect_args
    connect_args = {}
    if database_url.startswith("sqlite"):
        connect_args["check_same_thread"] = False

    _engine = create_async_engine(
        database_url,
        echo=debug,           # Log SQL queries jika debug mode aktif
        future=True,
        connect_args=connect_args,
    )

    _session_factory = async_sessionmaker(
        _engine,
        class_=AsyncSession,
        expire_on_commit=False,  # Hindari lazy-load error setelah commit
    )

    logger.info("Database engine diinisialisasi | url={}", _mask_url(database_url))


async def create_all_tables() -> None:
    """
    Buat semua tabel berdasarkan model yang terdaftar.
    Hanya untuk development — production menggunakan Alembic.
    """
    if _engine is None:
        raise RuntimeError("Database belum diinisialisasi. Panggil init_database() dulu.")

    # Import semua models agar metadata terdaftar di Base
    from core.models import (  # noqa: F401
        Agent,
        AgentTask,
        APTProfile,
        Campaign,
        CampaignStep,
        Execution,
        Finding,
        PurpleEvent,
        PurpleSession,
        Technique,
    )

    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    logger.info("Semua tabel database berhasil dibuat/diverifikasi.")


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency injection untuk FastAPI.
    Menghasilkan sesi database per request, lalu menutupnya otomatis.

    Penggunaan di router:
        async def endpoint(db: AsyncSession = Depends(get_session)):
            ...
    """
    if _session_factory is None:
        raise RuntimeError("Database belum diinisialisasi. Panggil init_database() dulu.")

    async with _session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def close_database() -> None:
    """Tutup koneksi database saat aplikasi shutdown."""
    if _engine is not None:
        await _engine.dispose()
        logger.info("Koneksi database ditutup.")


def _mask_url(url: str) -> str:
    """Sembunyikan password dari URL database untuk logging."""
    if "@" in url:
        scheme_and_user, rest = url.rsplit("@", 1)
        if ":" in scheme_and_user:
            scheme, _ = scheme_and_user.rsplit(":", 1)
            return f"{scheme}:***@{rest}"
    return url

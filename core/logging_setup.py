"""
Konfigurasi logging terpusat menggunakan Loguru.
Mendukung output ke konsol (dengan warna) dan file (dengan rotasi).
"""

import sys
from typing import TYPE_CHECKING

from loguru import logger

if TYPE_CHECKING:
    from core.config import Settings


def setup_logging(settings: "Settings") -> None:
    """
    Inisialisasi konfigurasi logging berdasarkan settings.
    Dipanggil sekali saat aplikasi startup.
    """
    # Hapus handler default Loguru
    logger.remove()

    # ─── Console Handler ──────────────────────────────────────────────────────
    log_format_console = (
        "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
        "<level>{level: <8}</level> | "
        "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> — "
        "<level>{message}</level>"
    )
    logger.add(
        sys.stdout,
        format=log_format_console,
        level=settings.log_level,
        colorize=True,
        backtrace=True,
        diagnose=settings.debug,
    )

    # ─── File Handler ─────────────────────────────────────────────────────────
    log_format_file = (
        "{time:YYYY-MM-DD HH:mm:ss.SSS} | "
        "{level: <8} | "
        "{name}:{function}:{line} — "
        "{message}"
    )
    logger.add(
        str(settings.log_file),
        format=log_format_file,
        level=settings.log_level,
        rotation=settings.log_rotation,
        retention=settings.log_retention,
        compression="zip",
        backtrace=True,
        diagnose=settings.debug,
        encoding="utf-8",
    )

    logger.info(
        "Logging diinisialisasi | level={} | file={}",
        settings.log_level,
        settings.log_file,
    )


def get_logger(name: str):
    """
    Kembalikan logger yang sudah dikonfigurasi untuk modul tertentu.
    Penggunaan: log = get_logger(__name__)
    """
    return logger.bind(name=name)

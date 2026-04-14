"""
Base class untuk semua implementasi teknik serangan.

Setiap teknik yang dapat dieksekusi platform ini harus mewarisi BaseTechnique
dan mengimplementasikan method execute(). Framework ini menangani:
- Validasi scope sebelum eksekusi
- Logging otomatis
- Penanganan error dan cleanup
- Pencatatan artefak
"""

import abc
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class ExecutionStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    PARTIAL = "partial"
    ABORTED = "aborted"
    SKIPPED = "skipped"


class Environment(str, Enum):
    IT = "it"
    OT = "ot"
    BOTH = "both"


@dataclass
class TechniqueContext:
    """
    Konteks eksekusi yang diberikan ke setiap teknik.
    Berisi informasi target, scope, dan credential yang tersedia.
    """
    # Identitas target
    target_host: str
    target_ip: str | None = None
    target_port: int | None = None

    # Kredensial (jika greybox/whitebox)
    username: str | None = None
    password: str | None = None
    domain: str | None = None
    hash_value: str | None = None      # NTLM hash untuk Pass-the-Hash
    token: str | None = None           # JWT atau token lainnya

    # Scope dan constraint
    campaign_id: str = ""
    scope_ips: list[str] = field(default_factory=list)
    scope_domains: list[str] = field(default_factory=list)
    excluded_targets: list[str] = field(default_factory=list)
    production_safe_mode: bool = True  # Jika True, write OT diblokir

    # Informasi OS/platform target (bisa diisi dari hasil discovery)
    target_os: str | None = None        # Windows, Linux, macOS
    target_arch: str | None = None      # x64, x86, arm
    target_vendor: str | None = None    # Untuk OT: Siemens, Rockwell, dll.

    # Konteks OT spesifik
    plc_model: str | None = None
    protocol: str | None = None         # Modbus, DNP3, OPC-UA, dll.
    ot_zone: str | None = None          # DMZ, Purdue Level, dll.

    # Metadata tambahan
    extra: dict[str, Any] = field(default_factory=dict)

    def is_in_scope(self, target: str) -> bool:
        """Verifikasi apakah target ada dalam scope yang ditentukan."""
        if target in self.excluded_targets:
            return False
        if self.scope_ips and target not in self.scope_ips:
            # Cek apakah target match dengan CIDR range
            return self._matches_any_cidr(target, self.scope_ips)
        return True

    def _matches_any_cidr(self, ip: str, cidr_list: list[str]) -> bool:
        """Cek apakah IP masuk dalam salah satu CIDR range."""
        import ipaddress
        try:
            ip_obj = ipaddress.ip_address(ip)
            for cidr in cidr_list:
                try:
                    if ip_obj in ipaddress.ip_network(cidr, strict=False):
                        return True
                except ValueError:
                    # Bukan CIDR, coba sebagai hostname exact match
                    if ip == cidr:
                        return True
        except ValueError:
            pass
        return False


@dataclass
class TechniqueResult:
    """
    Hasil eksekusi sebuah teknik.
    Dikembalikan oleh method execute() dari setiap teknik.
    """
    status: ExecutionStatus
    technique_id: str
    target: str

    # Output
    output: str = ""
    error: str = ""

    # Timing
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: datetime | None = None
    duration_seconds: float | None = None

    # Artefak yang ditinggalkan di sistem target
    artifacts_created: list[str] = field(default_factory=list)

    # Data yang berhasil dikumpulkan (credentials, data, dll.)
    collected_data: dict[str, Any] = field(default_factory=dict)

    # Rekomendasi langkah selanjutnya (untuk AI decision engine)
    next_step_hints: list[str] = field(default_factory=list)

    # Metadata tambahan
    extra: dict[str, Any] = field(default_factory=dict)

    def mark_completed(self) -> None:
        """Set timestamp selesai dan hitung durasi."""
        self.completed_at = datetime.utcnow()
        if self.started_at:
            delta = self.completed_at - self.started_at
            self.duration_seconds = delta.total_seconds()

    @property
    def is_success(self) -> bool:
        return self.status == ExecutionStatus.SUCCESS

    @property
    def summary(self) -> str:
        return (
            f"[{self.status.value.upper()}] {self.technique_id} → {self.target} "
            f"({self.duration_seconds:.1f}s)" if self.duration_seconds else
            f"[{self.status.value.upper()}] {self.technique_id} → {self.target}"
        )


class BaseTechnique(abc.ABC):
    """
    Base class abstrak untuk semua implementasi teknik serangan.

    Subclass harus mengimplementasikan:
    - technique_id: ATT&CK technique ID (misal "T1566")
    - name: Nama teknik
    - description: Deskripsi singkat
    - supported_environments: IT, OT, atau BOTH
    - execute(): Logika eksekusi utama

    Subclass bisa mengoverride:
    - pre_execute(): Validasi tambahan sebelum eksekusi
    - post_execute(): Cleanup atau logging tambahan setelah eksekusi
    - cleanup(): Hapus artefak yang ditinggalkan
    """

    # ─── Metadata (wajib diisi subclass) ──────────────────────────────────────
    technique_id: str = ""
    name: str = ""
    description: str = ""
    supported_environments: list[Environment] = [Environment.IT]
    risk_level: str = "medium"   # low | medium | high | critical
    is_destructive: bool = False
    requires_elevated_privileges: bool = False

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        # Validasi metadata wajib untuk subclass konkret.
        # Gunakan getattr dengan sentinel karena __abstractmethods__ belum
        # diset oleh ABCMeta pada saat __init_subclass__ dipanggil (Python 3.13+).
        # Sentinel non-kosong memastikan kita tidak raise error untuk abstract class.
        abstract = getattr(cls, "__abstractmethods__", {"_pending_"})
        if not abstract and not cls.technique_id:
            raise TypeError(
                f"Kelas {cls.__name__} harus mendefinisikan attribute 'technique_id'."
            )

    # ─── Template Method Pattern ───────────────────────────────────────────────

    async def run(self, context: TechniqueContext) -> TechniqueResult:
        """
        Entry point utama. Jangan override method ini.
        Jalankan pre_execute → execute → post_execute dengan penanganan error.
        """
        from loguru import logger

        result = TechniqueResult(
            status=ExecutionStatus.PENDING,
            technique_id=self.technique_id,
            target=context.target_host,
            started_at=datetime.utcnow(),
        )

        # ─── Validasi Scope ──────────────────────────────────────────────────
        if not context.is_in_scope(context.target_host):
            logger.warning(
                "Target {} TIDAK dalam scope kampanye {}. Eksekusi dibatalkan.",
                context.target_host, context.campaign_id,
            )
            result.status = ExecutionStatus.ABORTED
            result.error = f"Target {context.target_host} berada di luar scope engagement."
            result.mark_completed()
            return result

        # ─── Validasi OT Safety ─────────────────────────────────────────────
        if (
            self.is_destructive
            and Environment.OT in self.supported_environments
            and context.production_safe_mode
        ):
            logger.error(
                "Teknik destruktif {} DIBLOKIR: production_safe_mode=True. "
                "Butuh izin eksplisit dari RoE untuk dijalankan.",
                self.technique_id,
            )
            result.status = ExecutionStatus.ABORTED
            result.error = (
                "Teknik destruktif di lingkungan OT membutuhkan izin eksplisit. "
                "Set production_safe_mode=False di kampanye setelah mendapat persetujuan."
            )
            result.mark_completed()
            return result

        # ─── Pre-execute ────────────────────────────────────────────────────
        try:
            await self.pre_execute(context, result)
        except Exception as e:
            logger.error("pre_execute gagal untuk {}: {}", self.technique_id, e)
            result.status = ExecutionStatus.FAILED
            result.error = f"Pre-execute error: {e}"
            result.mark_completed()
            return result

        # ─── Execute ────────────────────────────────────────────────────────
        result.status = ExecutionStatus.RUNNING
        logger.info(
            "Eksekusi: {} ({}) → target={}",
            self.technique_id, self.name, context.target_host,
        )

        try:
            await self.execute(context, result)
        except Exception as e:
            logger.error("execute gagal untuk {}: {}", self.technique_id, e)
            result.status = ExecutionStatus.FAILED
            result.error = str(e)
        finally:
            result.mark_completed()

        # ─── Post-execute ───────────────────────────────────────────────────
        try:
            await self.post_execute(context, result)
        except Exception as e:
            logger.warning("post_execute error untuk {}: {}", self.technique_id, e)

        logger.info(result.summary)
        return result

    # ─── Abstract Methods ─────────────────────────────────────────────────────

    @abc.abstractmethod
    async def execute(self, context: TechniqueContext, result: TechniqueResult) -> None:
        """
        Implementasi utama teknik. Ubah result.status dan isi result.output.
        JANGAN raise exception — tangkap di dalam method dan set result.status = FAILED.
        """

    # ─── Optional Override Methods ────────────────────────────────────────────

    async def pre_execute(
        self, context: TechniqueContext, result: TechniqueResult
    ) -> None:
        """Hook sebelum eksekusi. Override untuk validasi tambahan."""
        pass

    async def post_execute(
        self, context: TechniqueContext, result: TechniqueResult
    ) -> None:
        """Hook setelah eksekusi. Override untuk logging atau cleanup."""
        pass

    async def cleanup(self, context: TechniqueContext) -> list[str]:
        """
        Hapus artefak yang ditinggalkan di sistem target.
        Kembalikan daftar artefak yang berhasil dihapus.
        """
        return []

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} id={self.technique_id!r}>"

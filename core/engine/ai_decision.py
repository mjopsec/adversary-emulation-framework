"""
AI Decision Engine — Otak dari platform AEP.

Menggunakan Claude (Anthropic) untuk:
1. Memvalidasi konteks engagement sebelum kampanye dimulai
2. Memilih teknik yang paling optimal berdasarkan kondisi saat ini
3. Menganalisis hasil eksekusi dan menentukan langkah selanjutnya
4. Menilai detection gap dan merekomendasikan perbaikan
5. Menghasilkan narasi laporan eksekutif

Semua keputusan AI dicatat dalam decision log untuk auditabilitas.
"""

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from loguru import logger

from core.config import Settings


@dataclass
class DecisionContext:
    """Konteks yang diberikan ke AI untuk pengambilan keputusan."""
    campaign_id: str
    campaign_name: str
    client_name: str
    engagement_type: str
    environment_type: str
    apt_profile_name: str | None
    objectives: list[str]
    current_step_index: int
    total_steps: int
    previous_results: list[dict]    # Hasil langkah-langkah sebelumnya
    available_techniques: list[dict]  # Teknik yang bisa dipilih
    target_info: dict[str, Any] = field(default_factory=dict)
    detection_controls: list[str] = field(default_factory=list)


@dataclass
class AIDecision:
    """Keputusan yang dikembalikan oleh AI Decision Engine."""
    recommended_technique_id: str
    reasoning: str
    confidence: float               # 0.0 - 1.0
    estimated_success_rate: float   # 0.0 - 1.0
    risk_assessment: str            # low | medium | high | critical
    alternative_techniques: list[str] = field(default_factory=list)
    fallback_if_fail: str | None = None
    notes: str = ""
    timestamp: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> dict:
        return {
            "recommended_technique_id": self.recommended_technique_id,
            "reasoning": self.reasoning,
            "confidence": self.confidence,
            "estimated_success_rate": self.estimated_success_rate,
            "risk_assessment": self.risk_assessment,
            "alternative_techniques": self.alternative_techniques,
            "fallback_if_fail": self.fallback_if_fail,
            "notes": self.notes,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class EngagementValidation:
    """Hasil validasi kelengkapan konteks engagement oleh AI."""
    is_valid: bool
    missing_fields: list[str]
    warnings: list[str]
    recommendations: list[str]
    validation_summary: str


class AIDecisionEngine:
    """
    Engine pengambilan keputusan berbasis AI (Claude).

    Jika ANTHROPIC_API_KEY tidak dikonfigurasi, engine berjalan dalam
    'deterministic mode': menggunakan heuristik sederhana tanpa AI.
    """

    # System prompt untuk semua interaksi AI
    SYSTEM_PROMPT = """Kamu adalah mesin analisis untuk platform emulasi adversari yang authorized.
Kamu membantu red team analyst dalam memilih teknik yang tepat, menganalisis hasil,
dan menghasilkan rekomendasi yang dapat dipertanggungjawabkan.

Prinsip utama:
- Selalu prioritaskan keamanan dan scope engagement
- Setiap rekomendasi harus memiliki alasan yang jelas
- Untuk lingkungan OT, selalu rekomendasikan pendekatan minimal-impact terlebih dahulu
- Semua teknik yang direkomendasikan harus sesuai dengan Rules of Engagement

Format output: Selalu kembalikan JSON yang valid sesuai struktur yang diminta.
Bahasa: Gunakan Bahasa Indonesia yang profesional dan jelas."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._client = None
        self._ai_available = False
        self._initialize_client()

    def _initialize_client(self) -> None:
        """Inisialisasi Anthropic client jika API key tersedia."""
        if not self.settings.has_ai_configured:
            logger.warning(
                "ANTHROPIC_API_KEY tidak dikonfigurasi. "
                "AI Decision Engine berjalan dalam mode deterministik (heuristik)."
            )
            return

        try:
            import anthropic
            self._client = anthropic.AsyncAnthropic(
                api_key=self.settings.anthropic_api_key
            )
            self._ai_available = True
            logger.info(
                "AI Decision Engine diinisialisasi dengan model: {}",
                self.settings.ai_model,
            )
        except ImportError:
            logger.error(
                "Package 'anthropic' tidak terinstall. "
                "Jalankan: pip install anthropic"
            )

    async def _call_ai(self, user_prompt: str) -> str:
        """Panggil Claude API dan kembalikan response sebagai string."""
        if not self._ai_available or self._client is None:
            raise RuntimeError("AI tidak tersedia.")

        message = await self._client.messages.create(
            model=self.settings.ai_model,
            max_tokens=self.settings.ai_max_tokens,
            system=self.SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_prompt}],
        )
        return message.content[0].text

    # ─── Fungsi Utama ──────────────────────────────────────────────────────────

    async def validate_engagement_context(
        self,
        campaign_data: dict,
    ) -> EngagementValidation:
        """
        Validasi kelengkapan dan konsistensi konteks engagement sebelum kampanye dimulai.
        Memastikan semua field wajib (scope, RoE, kontak, dll.) sudah diisi.
        """
        if not self._ai_available:
            return self._deterministic_validate(campaign_data)

        prompt = f"""Analisis kelengkapan konteks engagement berikut:

```json
{json.dumps(campaign_data, indent=2, ensure_ascii=False)}
```

Evaluasi:
1. Apakah semua field wajib sudah diisi? (scope, RoE, tanggal, kontak darurat)
2. Apakah ada inkonsistensi? (misalnya tipe engagement tidak sesuai scope)
3. Apakah ada risiko khusus berdasarkan tipe lingkungan?

Kembalikan JSON dengan struktur:
{{
  "is_valid": true/false,
  "missing_fields": ["field1", "field2"],
  "warnings": ["warning1", "warning2"],
  "recommendations": ["rec1", "rec2"],
  "validation_summary": "ringkasan dalam 1-2 kalimat"
}}"""

        try:
            response = await self._call_ai(prompt)
            data = self._parse_json_response(response)
            return EngagementValidation(**data)
        except Exception as e:
            logger.error("AI validation error: {}. Fallback ke mode deterministik.", e)
            return self._deterministic_validate(campaign_data)

    async def select_next_technique(
        self,
        context: DecisionContext,
    ) -> AIDecision:
        """
        Pilih teknik terbaik untuk langkah selanjutnya berdasarkan:
        - Kondisi saat ini (hasil langkah sebelumnya)
        - Tujuan kampanye
        - Profil APT yang disimulasikan
        - Teknik yang tersedia
        """
        if not self._ai_available:
            return self._deterministic_select(context)

        prev_results_summary = self._summarize_results(context.previous_results)

        prompt = f"""Kamu sedang membantu red team analyst dalam kampanye authorized:

**Kampanye:** {context.campaign_name} (Client: {context.client_name})
**APT Profile:** {context.apt_profile_name or "Custom"}
**Lingkungan:** {context.environment_type}
**Langkah saat ini:** {context.current_step_index + 1} dari {context.total_steps}
**Tujuan:** {", ".join(context.objectives)}

**Hasil langkah sebelumnya:**
{prev_results_summary}

**Teknik yang tersedia untuk dipilih:**
{json.dumps(context.available_techniques[:20], indent=2, ensure_ascii=False)}

Pilih teknik yang paling optimal. Pertimbangkan:
1. Probabilitas sukses berdasarkan kondisi saat ini
2. Kesesuaian dengan taktik APT yang disimulasikan
3. Risiko deteksi oleh blue team
4. Dampak ke availability sistem (terutama jika OT)
5. Kemajuan menuju tujuan kampanye

Kembalikan JSON:
{{
  "recommended_technique_id": "Txxx",
  "reasoning": "alasan pemilihan dalam 2-3 kalimat",
  "confidence": 0.0-1.0,
  "estimated_success_rate": 0.0-1.0,
  "risk_assessment": "low|medium|high|critical",
  "alternative_techniques": ["Txxx", "Txxx"],
  "fallback_if_fail": "Txxx atau null",
  "notes": "catatan tambahan jika ada"
}}"""

        try:
            response = await self._call_ai(prompt)
            data = self._parse_json_response(response)
            return AIDecision(**data)
        except Exception as e:
            logger.error("AI technique selection error: {}. Fallback ke heuristik.", e)
            return self._deterministic_select(context)

    async def analyze_execution_result(
        self,
        technique_id: str,
        technique_name: str,
        target: str,
        execution_status: str,
        result_detail: str,
        campaign_context: dict,
    ) -> dict:
        """
        Analisis hasil eksekusi dan hasilkan:
        - Finding (deteksi gap)
        - Rekomendasi langkah berikutnya
        - Apakah perlu pivot ke teknik lain
        """
        if not self._ai_available:
            return self._deterministic_analyze(technique_id, execution_status)

        prompt = f"""Analisis hasil eksekusi teknik ATT&CK berikut:

**Teknik:** {technique_id} - {technique_name}
**Target:** {target}
**Status:** {execution_status}
**Detail:** {result_detail[:2000]}

**Konteks kampanye:**
{json.dumps(campaign_context, indent=2, ensure_ascii=False)}

Berikan analisis:
1. Apakah eksekusi berhasil mencapai tujuannya?
2. Apa detection gap yang ditemukan? (berdasarkan apakah ada alert/response dari target)
3. Langkah selanjutnya yang direkomendasikan
4. Apakah perlu pivot ke teknik alternatif?

Kembalikan JSON:
{{
  "detection_analysis": {{
    "detected": true/false,
    "detection_quality": "none|partial|full",
    "evidence": "bukti deteksi atau non-deteksi"
  }},
  "gap_description": "deskripsi gap jika tidak terdeteksi",
  "severity": "critical|high|medium|low",
  "next_recommended_technique": "Txxx atau null",
  "should_pivot": true/false,
  "pivot_reason": "alasan pivot jika diperlukan",
  "sigma_rule_hint": "hint untuk membuat Sigma rule jika ada gap"
}}"""

        try:
            response = await self._call_ai(prompt)
            return self._parse_json_response(response)
        except Exception as e:
            logger.error("AI analysis error: {}. Fallback ke heuristik.", e)
            return self._deterministic_analyze(technique_id, execution_status)

    async def generate_executive_summary(
        self,
        campaign_data: dict,
        executions: list[dict],
        findings: list[dict],
    ) -> str:
        """
        Hasilkan narasi laporan eksekutif dari keseluruhan kampanye.
        Ditulis untuk audiens C-level (non-teknis).
        """
        if not self._ai_available:
            return self._deterministic_summary(campaign_data, findings)

        gaps = [f for f in findings if not f.get("detected", True)]
        critical_gaps = [f for f in gaps if f.get("severity") == "critical"]

        prompt = f"""Buatkan ringkasan eksekutif untuk laporan red team engagement berikut.
Tulis untuk audiens C-level (CEO, CISO, Board) — hindari jargon teknis berlebihan.
Fokus pada risiko bisnis dan dampak nyata.

**Data kampanye:**
- Nama: {campaign_data.get('name')}
- Klien: {campaign_data.get('client_name')}
- Tipe: {campaign_data.get('engagement_type')} / {campaign_data.get('environment_type')}
- Total teknik dieksekusi: {len(executions)}
- Total gap ditemukan: {len(gaps)} (termasuk {len(critical_gaps)} kritis)

**Ringkasan teknik yang berhasil (tidak terdeteksi):**
{json.dumps([f.get('technique_id') for f in gaps[:10]], ensure_ascii=False)}

Tulis narasi dalam 3-4 paragraf:
1. Gambaran umum engagement dan pendekatan
2. Temuan utama dan risiko yang paling signifikan
3. Dampak potensial jika penyerang nyata menggunakan teknik ini
4. Rekomendasi prioritas perbaikan (3-5 poin)

Gunakan Bahasa Indonesia yang formal dan mudah dipahami."""

        try:
            return await self._call_ai(prompt)
        except Exception as e:
            logger.error("AI summary generation error: {}", e)
            return self._deterministic_summary(campaign_data, findings)

    # ─── Deterministic Fallback (tanpa AI) ────────────────────────────────────

    def _deterministic_validate(self, campaign_data: dict) -> EngagementValidation:
        """Validasi berbasis rule tanpa AI."""
        missing = []
        warnings = []
        recommendations = []

        required_fields = {
            "client_name": "Nama klien",
            "target_ips": "Target IP/CIDR (minimal 1)",
            "rules_of_engagement": "Rules of Engagement",
            "emergency_contact": "Kontak darurat",
            "start_date": "Tanggal mulai",
            "end_date": "Tanggal berakhir",
        }

        for field_key, field_label in required_fields.items():
            value = campaign_data.get(field_key)
            if not value or (isinstance(value, list) and not value):
                missing.append(field_label)

        if campaign_data.get("environment_type") in ("ot", "hybrid_it_ot"):
            if campaign_data.get("production_safe_mode") is False:
                warnings.append(
                    "Production safe mode dinonaktifkan untuk lingkungan OT — "
                    "pastikan ada izin eksplisit dan pengawasan langsung."
                )

        is_valid = len(missing) == 0
        return EngagementValidation(
            is_valid=is_valid,
            missing_fields=missing,
            warnings=warnings,
            recommendations=recommendations,
            validation_summary=(
                "Konteks engagement lengkap dan siap dieksekusi."
                if is_valid else
                f"Masih ada {len(missing)} field yang harus dilengkapi sebelum kampanye dapat dimulai."
            ),
        )

    def _deterministic_select(self, context: DecisionContext) -> AIDecision:
        """Pilih teknik secara deterministik berdasarkan urutan dan availability."""
        if not context.available_techniques:
            raise ValueError("Tidak ada teknik yang tersedia untuk dipilih.")

        # Default: pilih teknik pertama yang tersedia
        technique = context.available_techniques[0]
        return AIDecision(
            recommended_technique_id=technique["id"],
            reasoning="Dipilih secara otomatis (AI tidak tersedia) berdasarkan urutan prioritas.",
            confidence=0.5,
            estimated_success_rate=0.5,
            risk_assessment=technique.get("risk_level", "medium"),
            alternative_techniques=[
                t["id"] for t in context.available_techniques[1:4]
            ],
        )

    def _deterministic_analyze(
        self, technique_id: str, execution_status: str
    ) -> dict:
        """Analisis sederhana tanpa AI."""
        detected = execution_status in ("failed", "partial")
        return {
            "detection_analysis": {
                "detected": detected,
                "detection_quality": "partial" if detected else "none",
                "evidence": "Analisis otomatis berdasarkan status eksekusi.",
            },
            "gap_description": (
                None if detected else
                f"Teknik {technique_id} berhasil dieksekusi tanpa deteksi."
            ),
            "severity": "medium",
            "next_recommended_technique": None,
            "should_pivot": execution_status == "failed",
            "pivot_reason": "Eksekusi gagal, perlu teknik alternatif." if execution_status == "failed" else None,
            "sigma_rule_hint": None,
        }

    def _deterministic_summary(
        self, campaign_data: dict, findings: list[dict]
    ) -> str:
        """Hasilkan ringkasan sederhana tanpa AI."""
        gaps = [f for f in findings if not f.get("detected", True)]
        return (
            f"Ringkasan Engagement: {campaign_data.get('name', 'N/A')}\n\n"
            f"Kampanye red team selesai dilaksanakan untuk klien {campaign_data.get('client_name', 'N/A')}. "
            f"Total {len(findings)} teknik dievaluasi, dengan {len(gaps)} teknik yang tidak terdeteksi "
            f"oleh stack pertahanan yang ada.\n\n"
            f"[Catatan: Ringkasan eksekutif penuh memerlukan konfigurasi AI Engine. "
            f"Silakan atur ANTHROPIC_API_KEY di file .env]"
        )

    # ─── Helpers ──────────────────────────────────────────────────────────────

    def _parse_json_response(self, response: str) -> dict:
        """
        Parse JSON dari response AI.
        Handle kasus di mana AI membungkus JSON dengan markdown code block.
        """
        text = response.strip()
        # Hapus markdown code block jika ada
        if text.startswith("```"):
            lines = text.split("\n")
            # Hapus baris pertama (```json) dan terakhir (```)
            text = "\n".join(lines[1:-1]) if lines[-1] == "```" else "\n".join(lines[1:])
        return json.loads(text)

    def _summarize_results(self, results: list[dict]) -> str:
        """Buat ringkasan hasil eksekusi sebelumnya untuk konteks AI."""
        if not results:
            return "Belum ada hasil eksekusi sebelumnya (ini adalah langkah pertama)."

        lines = []
        for r in results[-5:]:  # Ambil 5 hasil terakhir saja
            status = r.get("status", "unknown")
            technique = r.get("technique_id", "?")
            target = r.get("target", "?")
            lines.append(f"- [{status.upper()}] {technique} → {target}")

        return "\n".join(lines)

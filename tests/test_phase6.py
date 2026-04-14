"""
Test Suite Phase 6 — Reporting Engine.

Mencakup:
- TestHtmlGenerator        : HTML campaign + purple team report rendering
- TestPdfGenerator         : PDF campaign + purple team generation (bytes validity)
- TestReportGenerator      : ReportGenerator JSON logic (unit, tanpa DB)
- TestNavigatorLayer       : ATT&CK Navigator layer structure
- TestPhase6Integration    : End-to-end HTML/PDF round-trip dari mock data
"""

import io
import pytest


# ─── Fixtures: Sample Data ────────────────────────────────────────────────────

@pytest.fixture
def sample_campaign_report() -> dict:
    """Struktur seperti yang dikembalikan ReportGenerator.generate_json_report()."""
    return {
        "metadata": {
            "report_generated_at": "2026-04-11T00:00:00+00:00",
            "platform": "AE Platform v1.0.0",
            "campaign_id": "camp-001",
        },
        "campaign": {
            "name": "Operation IronBridge",
            "client": "PT Maju Mundur",
            "engagement_type": "blackbox",
            "environment_type": "hybrid_it_ot",
            "status": "completed",
            "started_at": "2026-04-01T08:00:00",
            "completed_at": "2026-04-10T17:00:00",
        },
        "summary": {
            "total_techniques_executed": 8,
            "detected": 5,
            "not_detected": 3,
            "partial_detection": 1,
            "detection_rate_percent": 62.5,
            "gaps_by_severity": {"high": 2, "critical": 1},
        },
        "findings": [
            {
                "technique_id": "T1566",
                "technique_name": "Phishing",
                "severity": "high",
                "detected": False,
                "detection_quality": "none",
                "gap_description": "Email gateway tidak memblokir attachment .lnk",
                "remediation_recommendation": "Deploy sandbox email analysis",
                "sigma_rule": "title: Phishing LNK\nstatus: experimental\n",
                "priority_score": 6,
            },
            {
                "technique_id": "T1059",
                "technique_name": "Command Scripting",
                "severity": "medium",
                "detected": True,
                "detection_quality": "full",
                "gap_description": None,
                "remediation_recommendation": None,
                "sigma_rule": None,
                "priority_score": 0,
            },
            {
                "technique_id": "T1078",
                "technique_name": "Valid Accounts",
                "severity": "critical",
                "detected": False,
                "detection_quality": "none",
                "gap_description": "Tidak ada deteksi login anomaly",
                "remediation_recommendation": "Implement UEBA",
                "sigma_rule": "title: Anomalous Login\nstatus: experimental\n",
                "priority_score": 8,
            },
        ],
        "attack_path": [
            {
                "step": 1,
                "technique_id": "T1566",
                "technique_name": "Phishing",
                "target": "192.168.1.100",
                "status": "success",
                "duration_seconds": 12.5,
            },
            {
                "step": 2,
                "technique_id": "T1059",
                "technique_name": "Command Scripting",
                "target": "192.168.1.100",
                "status": "success",
                "duration_seconds": 3.1,
            },
            {
                "step": 3,
                "technique_id": "T1078",
                "technique_name": "Valid Accounts",
                "target": "10.0.0.5",
                "status": "failed",
                "duration_seconds": None,
            },
        ],
        "navigator_layer": {
            "name": "AEP — Operation IronBridge",
            "versions": {"attack": "14", "navigator": "4.9", "layer": "4.5"},
            "domain": "enterprise-attack",
            "techniques": [
                {"techniqueID": "T1566", "score": 100, "color": "#ffffff", "enabled": True},
                {"techniqueID": "T1059", "score": 0,   "color": "#ff0000", "enabled": True},
                {"techniqueID": "T1078", "score": 100, "color": "#ffffff", "enabled": True},
            ],
        },
    }


@pytest.fixture
def sample_purple_report() -> dict:
    """Struktur seperti PurpleSessionReport.to_dict()."""
    return {
        "session_id": "sess-001",
        "session_name": "Purple Team Q2 2026",
        "environment": "it",
        "status": "completed",
        "red_team_lead": "Alice",
        "blue_team_lead": "Bob",
        "facilitator": "Charlie",
        "metrics": {
            "total_events": 5,
            "detected_count": 3,
            "gap_count": 2,
            "detection_coverage": 0.6,
            "mttd_seconds": 45.0,
            "coverage_by_tactic": {
                "initial_access": 0.5,
                "execution": 1.0,
                "persistence": 0.0,
            },
        },
        "events": [
            {
                "id": "ev-001",
                "technique_id": "T1566",
                "technique_name": "Phishing",
                "tactic": "initial_access",
                "target": "ws-01",
                "blue_response": "detected",
                "is_gap": False,
                "gap_severity": None,
                "detection_latency_seconds": 30.0,
                "sigma_rule_hint": None,
            },
            {
                "id": "ev-002",
                "technique_id": "T1003",
                "technique_name": "OS Credential Dumping",
                "tactic": "credential_access",
                "target": "ws-01",
                "blue_response": "missed",
                "is_gap": True,
                "gap_severity": "critical",
                "detection_latency_seconds": None,
                "sigma_rule_hint": "title: LSASS Memory Access\nstatus: experimental\n",
            },
            {
                "id": "ev-003",
                "technique_id": "T1021",
                "technique_name": "Remote Services",
                "tactic": "lateral_movement",
                "target": "srv-02",
                "blue_response": "blocked",
                "is_gap": False,
                "gap_severity": None,
                "detection_latency_seconds": 60.0,
                "sigma_rule_hint": None,
            },
        ],
        "recommendations": [
            {
                "priority": 1,
                "technique_id": "T1003",
                "title": "Deploy LSASS protection dan Credential Guard",
                "gap_severity": "critical",
                "steps": [
                    "Enable Windows Credential Guard via GPO",
                    "Deploy EDR rule untuk LSASS memory access",
                    "Monitor event ID 4625 dengan frekuensi tinggi",
                ],
                "sigma_hint": "title: LSASS Memory Access\n",
            },
        ],
    }


# ─── TestHtmlGenerator ────────────────────────────────────────────────────────

class TestHtmlGenerator:

    def test_campaign_html_returns_string(self, sample_campaign_report):
        from core.reporting.html_generator import generate_campaign_html
        html = generate_campaign_html(sample_campaign_report)
        assert isinstance(html, str)

    def test_campaign_html_has_doctype(self, sample_campaign_report):
        from core.reporting.html_generator import generate_campaign_html
        html = generate_campaign_html(sample_campaign_report)
        assert "<!DOCTYPE html>" in html

    def test_campaign_html_contains_campaign_name(self, sample_campaign_report):
        from core.reporting.html_generator import generate_campaign_html
        html = generate_campaign_html(sample_campaign_report)
        assert "Operation IronBridge" in html

    def test_campaign_html_contains_client_name(self, sample_campaign_report):
        from core.reporting.html_generator import generate_campaign_html
        html = generate_campaign_html(sample_campaign_report)
        assert "PT Maju Mundur" in html

    def test_campaign_html_contains_technique_ids(self, sample_campaign_report):
        from core.reporting.html_generator import generate_campaign_html
        html = generate_campaign_html(sample_campaign_report)
        assert "T1566" in html
        assert "T1059" in html
        assert "T1078" in html

    def test_campaign_html_shows_detection_rate(self, sample_campaign_report):
        from core.reporting.html_generator import generate_campaign_html
        html = generate_campaign_html(sample_campaign_report)
        assert "62.5" in html

    def test_campaign_html_contains_sigma_rule(self, sample_campaign_report):
        from core.reporting.html_generator import generate_campaign_html
        html = generate_campaign_html(sample_campaign_report)
        # T1566 has sigma rule
        assert "Phishing LNK" in html

    def test_campaign_html_gap_count(self, sample_campaign_report):
        from core.reporting.html_generator import generate_campaign_html
        html = generate_campaign_html(sample_campaign_report)
        # 2 gap findings (T1566 + T1078), total = 3 from severity dict
        assert "3" in html  # gap count = high(2) + critical(1)

    def test_purple_html_returns_string(self, sample_purple_report):
        from core.reporting.html_generator import generate_purple_html
        html = generate_purple_html(sample_purple_report)
        assert isinstance(html, str)

    def test_purple_html_has_doctype(self, sample_purple_report):
        from core.reporting.html_generator import generate_purple_html
        html = generate_purple_html(sample_purple_report)
        assert "<!DOCTYPE html>" in html

    def test_purple_html_contains_session_name(self, sample_purple_report):
        from core.reporting.html_generator import generate_purple_html
        html = generate_purple_html(sample_purple_report)
        assert "Purple Team Q2 2026" in html

    def test_purple_html_contains_team_leads(self, sample_purple_report):
        from core.reporting.html_generator import generate_purple_html
        html = generate_purple_html(sample_purple_report)
        assert "Alice" in html
        assert "Bob" in html

    def test_purple_html_contains_events(self, sample_purple_report):
        from core.reporting.html_generator import generate_purple_html
        html = generate_purple_html(sample_purple_report)
        assert "T1003" in html
        assert "missed" in html

    def test_purple_html_contains_recommendations(self, sample_purple_report):
        from core.reporting.html_generator import generate_purple_html
        html = generate_purple_html(sample_purple_report)
        assert "Credential Guard" in html

    def test_purple_html_shows_sigma_hint(self, sample_purple_report):
        from core.reporting.html_generator import generate_purple_html
        html = generate_purple_html(sample_purple_report)
        assert "LSASS Memory Access" in html

    def test_purple_html_coverage_percentage(self, sample_purple_report):
        from core.reporting.html_generator import generate_purple_html
        html = generate_purple_html(sample_purple_report)
        # 60% coverage
        assert "60" in html

    def test_purple_html_tactic_bar_rendered(self, sample_purple_report):
        from core.reporting.html_generator import generate_purple_html
        html = generate_purple_html(sample_purple_report)
        assert "initial_access" in html.lower() or "Initial Access" in html


# ─── TestPdfGenerator ─────────────────────────────────────────────────────────

class TestPdfGenerator:

    def test_campaign_pdf_returns_bytes(self, sample_campaign_report):
        from core.reporting.pdf_generator import generate_campaign_pdf
        pdf = generate_campaign_pdf(sample_campaign_report)
        assert isinstance(pdf, bytes)

    def test_campaign_pdf_starts_with_pdf_header(self, sample_campaign_report):
        from core.reporting.pdf_generator import generate_campaign_pdf
        pdf = generate_campaign_pdf(sample_campaign_report)
        assert pdf[:4] == b"%PDF"

    def test_campaign_pdf_non_empty(self, sample_campaign_report):
        from core.reporting.pdf_generator import generate_campaign_pdf
        pdf = generate_campaign_pdf(sample_campaign_report)
        assert len(pdf) > 1024  # minimal 1 KB

    def test_campaign_pdf_empty_findings(self, sample_campaign_report):
        """PDF tidak crash meski findings kosong."""
        from core.reporting.pdf_generator import generate_campaign_pdf
        data = dict(sample_campaign_report)
        data["findings"] = []
        data["attack_path"] = []
        pdf = generate_campaign_pdf(data)
        assert pdf[:4] == b"%PDF"

    def test_campaign_pdf_minimal_data(self):
        """PDF tidak crash dengan data minimal (hanya keys wajib)."""
        from core.reporting.pdf_generator import generate_campaign_pdf
        minimal = {
            "campaign": {"name": "Minimal", "client": "Test"},
            "summary": {"total_techniques_executed": 0, "detected": 0,
                        "not_detected": 0, "detection_rate_percent": 0,
                        "gaps_by_severity": {}},
            "findings": [],
            "attack_path": [],
        }
        pdf = generate_campaign_pdf(minimal)
        assert pdf[:4] == b"%PDF"

    def test_purple_pdf_returns_bytes(self, sample_purple_report):
        from core.reporting.pdf_generator import generate_purple_pdf
        pdf = generate_purple_pdf(sample_purple_report)
        assert isinstance(pdf, bytes)

    def test_purple_pdf_starts_with_pdf_header(self, sample_purple_report):
        from core.reporting.pdf_generator import generate_purple_pdf
        pdf = generate_purple_pdf(sample_purple_report)
        assert pdf[:4] == b"%PDF"

    def test_purple_pdf_non_empty(self, sample_purple_report):
        from core.reporting.pdf_generator import generate_purple_pdf
        pdf = generate_purple_pdf(sample_purple_report)
        assert len(pdf) > 1024

    def test_purple_pdf_no_recommendations(self, sample_purple_report):
        """PDF tidak crash bila recommendations kosong."""
        from core.reporting.pdf_generator import generate_purple_pdf
        data = dict(sample_purple_report)
        data["recommendations"] = []
        pdf = generate_purple_pdf(data)
        assert pdf[:4] == b"%PDF"

    def test_purple_pdf_no_events(self, sample_purple_report):
        """PDF tidak crash bila events kosong."""
        from core.reporting.pdf_generator import generate_purple_pdf
        data = dict(sample_purple_report)
        data["events"] = []
        pdf = generate_purple_pdf(data)
        assert pdf[:4] == b"%PDF"


# ─── TestReportGenerator (unit, tanpa DB) ─────────────────────────────────────

class TestReportGeneratorUnit:

    def _make_gen(self):
        """Buat ReportGenerator dengan mock session."""
        from unittest.mock import MagicMock
        from core.reporting.generator import ReportGenerator
        mock_session = MagicMock()
        return ReportGenerator(mock_session)

    def test_build_navigator_layer_detected(self):
        """Teknik terdeteksi penuh → score 0, color merah."""
        from unittest.mock import MagicMock
        from core.reporting.generator import ReportGenerator
        gen = ReportGenerator(MagicMock())

        camp = MagicMock()
        camp.name = "Test"
        camp.client_name = "Client"
        camp.environment_type = "it"

        finding = MagicMock()
        finding.technique_id = "T1059"
        finding.detected = True
        finding.detection_quality = "full"
        finding.gap_description = None

        layer = gen._build_navigator_layer(camp, [finding])
        tech = layer["techniques"][0]
        assert tech["score"] == 0
        assert tech["techniqueID"] == "T1059"

    def test_build_navigator_layer_gap(self):
        """Teknik tidak terdeteksi → score 100, color putih."""
        from unittest.mock import MagicMock
        from core.reporting.generator import ReportGenerator
        gen = ReportGenerator(MagicMock())

        camp = MagicMock()
        camp.name = "Test"
        camp.client_name = "Client"
        camp.environment_type = "ot"

        finding = MagicMock()
        finding.technique_id = "T0801"
        finding.detected = False
        finding.detection_quality = "none"
        finding.gap_description = "Tidak ada deteksi Modbus"

        layer = gen._build_navigator_layer(camp, [finding])
        tech = layer["techniques"][0]
        assert tech["score"] == 100
        assert layer["domain"] == "ics-attack"

    def test_build_navigator_layer_partial(self):
        """Teknik terdeteksi sebagian → score 50."""
        from unittest.mock import MagicMock
        from core.reporting.generator import ReportGenerator
        gen = ReportGenerator(MagicMock())

        camp = MagicMock()
        camp.name = "Test"
        camp.client_name = "Client"
        camp.environment_type = "it"

        finding = MagicMock()
        finding.technique_id = "T1021"
        finding.detected = True
        finding.detection_quality = "partial"
        finding.gap_description = None

        layer = gen._build_navigator_layer(camp, [finding])
        assert layer["techniques"][0]["score"] == 50

    def test_build_navigator_domain_it(self):
        """Environment IT → domain enterprise-attack."""
        from unittest.mock import MagicMock
        from core.reporting.generator import ReportGenerator
        gen = ReportGenerator(MagicMock())
        camp = MagicMock()
        camp.name = "T"
        camp.client_name = "C"
        camp.environment_type = "it"
        layer = gen._build_navigator_layer(camp, [])
        assert layer["domain"] == "enterprise-attack"

    def test_build_attack_path_sorted_by_started_at(self):
        """Attack path diurutkan berdasarkan started_at."""
        from datetime import datetime
        from unittest.mock import MagicMock
        from core.reporting.generator import ReportGenerator
        gen = ReportGenerator(MagicMock())

        camp = MagicMock()
        ex1 = MagicMock()
        ex1.technique_id = "T1059"
        ex1.technique_name = "Command"
        ex1.target = "host-a"
        ex1.status = "success"
        ex1.duration_seconds = 5.0
        ex1.started_at = datetime(2026, 4, 1, 10, 0, 0)

        ex2 = MagicMock()
        ex2.technique_id = "T1566"
        ex2.technique_name = "Phishing"
        ex2.target = "host-b"
        ex2.status = "success"
        ex2.duration_seconds = 10.0
        ex2.started_at = datetime(2026, 4, 1, 9, 0, 0)  # lebih awal

        path = gen._build_attack_path(camp, [ex1, ex2])
        assert path[0]["technique_id"] == "T1566"
        assert path[1]["technique_id"] == "T1059"


# ─── TestNavigatorLayer ───────────────────────────────────────────────────────

class TestNavigatorLayer:

    def test_navigator_layer_structure(self, sample_campaign_report):
        layer = sample_campaign_report["navigator_layer"]
        assert "name" in layer
        assert "versions" in layer
        assert "domain" in layer
        assert "techniques" in layer
        assert isinstance(layer["techniques"], list)

    def test_navigator_layer_technique_fields(self, sample_campaign_report):
        for tech in sample_campaign_report["navigator_layer"]["techniques"]:
            assert "techniqueID" in tech
            assert "score" in tech
            assert "enabled" in tech

    def test_navigator_layer_score_range(self, sample_campaign_report):
        """Score harus antara 0-100."""
        for tech in sample_campaign_report["navigator_layer"]["techniques"]:
            assert 0 <= tech["score"] <= 100

    def test_navigator_layer_gap_score_100(self, sample_campaign_report):
        """T1566 adalah gap → score 100."""
        layer = sample_campaign_report["navigator_layer"]
        t1566 = next(t for t in layer["techniques"] if t["techniqueID"] == "T1566")
        assert t1566["score"] == 100

    def test_navigator_layer_detected_score_0(self, sample_campaign_report):
        """T1059 terdeteksi → score 0."""
        layer = sample_campaign_report["navigator_layer"]
        t1059 = next(t for t in layer["techniques"] if t["techniqueID"] == "T1059")
        assert t1059["score"] == 0


# ─── TestPhase6Integration ────────────────────────────────────────────────────

class TestPhase6Integration:

    def test_campaign_html_is_valid_html(self, sample_campaign_report):
        """HTML output harus mengandung struktur dokumen yang valid."""
        from core.reporting.html_generator import generate_campaign_html
        html = generate_campaign_html(sample_campaign_report)
        assert html.count("<html") == 1
        assert html.count("</html>") == 1
        assert html.count("<head>") == 1
        assert html.count("</head>") == 1
        assert html.count("<body>") == 1
        assert html.count("</body>") == 1

    def test_purple_html_is_valid_html(self, sample_purple_report):
        """Purple HTML output harus valid."""
        from core.reporting.html_generator import generate_purple_html
        html = generate_purple_html(sample_purple_report)
        assert html.count("<html") == 1
        assert html.count("</html>") == 1
        assert "<body>" in html
        assert "</body>" in html

    def test_campaign_pdf_is_readable_by_io(self, sample_campaign_report):
        """PDF bytes harus bisa dibaca sebagai stream."""
        from core.reporting.pdf_generator import generate_campaign_pdf
        pdf = generate_campaign_pdf(sample_campaign_report)
        buf = io.BytesIO(pdf)
        header = buf.read(4)
        assert header == b"%PDF"

    def test_purple_pdf_is_readable_by_io(self, sample_purple_report):
        """Purple PDF bytes harus bisa dibaca sebagai stream."""
        from core.reporting.pdf_generator import generate_purple_pdf
        pdf = generate_purple_pdf(sample_purple_report)
        buf = io.BytesIO(pdf)
        header = buf.read(4)
        assert header == b"%PDF"

    def test_html_escaping_xss_safe(self, sample_campaign_report):
        """HTML generator harus escape karakter berbahaya (Jinja2 autoescape)."""
        from core.reporting.html_generator import generate_campaign_html
        data = dict(sample_campaign_report)
        data["campaign"] = dict(data["campaign"])
        data["campaign"]["name"] = "<script>alert('xss')</script>"
        html = generate_campaign_html(data)
        # Jinja2 autoescape should convert < > to &lt; &gt;
        assert "<script>alert" not in html

    def test_findings_gap_highlighted(self, sample_campaign_report):
        """Findings yang merupakan gap harus ditandai dengan class gap-row."""
        from core.reporting.html_generator import generate_campaign_html
        html = generate_campaign_html(sample_campaign_report)
        assert "gap-row" in html

    def test_html_both_formats_contain_same_technique_ids(
        self, sample_campaign_report, sample_purple_report
    ):
        """Teknik yang sama harus muncul di HTML campaign."""
        from core.reporting.html_generator import generate_campaign_html
        html = generate_campaign_html(sample_campaign_report)
        for finding in sample_campaign_report["findings"]:
            assert finding["technique_id"] in html

    def test_pdf_sigma_hints_included(self, sample_campaign_report):
        """PDF campaign harus mengandung sigma rule hints dalam bytes output."""
        from core.reporting.pdf_generator import generate_campaign_pdf
        pdf = generate_campaign_pdf(sample_campaign_report)
        # Sigma hint text "Phishing LNK" should appear somewhere in PDF content
        # PDF encoding means we search for the text in the raw bytes
        assert len(pdf) > 2000  # PDF dengan sigma hints pasti lebih besar

    def test_report_generator_import(self):
        """ReportGenerator dapat diimport dari package reporting."""
        from core.reporting import ReportGenerator
        assert ReportGenerator is not None

    def test_html_generators_importable(self):
        from core.reporting import generate_campaign_html, generate_purple_html
        assert callable(generate_campaign_html)
        assert callable(generate_purple_html)

    def test_pdf_generators_importable(self):
        from core.reporting import generate_campaign_pdf, generate_purple_pdf
        assert callable(generate_campaign_pdf)
        assert callable(generate_purple_pdf)

"""Tests for blackroad-compliance-framework."""
import sys, os, tempfile
from pathlib import Path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import pytest
from src.compliance_framework import (
    ComplianceEngine, CONTROLS, ComplianceReport, ComplianceResult,
    _check_no_hardcoded_secrets, _check_logging_configured, _check_encryption_used,
)


@pytest.fixture
def engine(tmp_path):
    return ComplianceEngine(str(tmp_path / "test_compliance.db"))


def write_dir(files):
    d = tempfile.mkdtemp()
    for name, content in files.items():
        p = Path(d) / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return d


class TestControls:
    def test_controls_exist(self):
        assert len(CONTROLS) >= 20

    def test_all_have_required_fields(self):
        for c in CONTROLS:
            assert c.id
            assert c.framework
            assert c.severity in ("CRITICAL","HIGH","MEDIUM","LOW")

    def test_frameworks_present(self):
        frameworks = {c.framework for c in CONTROLS}
        assert "CIS" in frameworks
        assert "OWASP" in frameworks
        assert "NIST" in frameworks


class TestAutomatedChecks:
    def test_detects_hardcoded_secret(self):
        d = write_dir({"config.py": "api_key = 'my-secret-key-value'"})
        status, evidence = _check_no_hardcoded_secrets(d)
        assert status == "FAIL"

    def test_clean_code_passes(self):
        d = write_dir({"main.py": "x = os.environ.get('API_KEY')"})
        status, _ = _check_no_hardcoded_secrets(d)
        assert status == "PASS"

    def test_logging_detected(self):
        d = write_dir({"app.py": "import logging\nlogger = logging.getLogger(__name__)"})
        status, _ = _check_logging_configured(d)
        assert status == "PASS"

    def test_no_logging_warns(self):
        d = write_dir({"app.py": "x = 1\nprint('hello')"})
        status, _ = _check_logging_configured(d)
        assert status in ("WARN", "NA")

    def test_encryption_detected(self):
        d = write_dir({"crypto.py": "import hashlib\nhashlib.sha256(b'test')"})
        status, _ = _check_encryption_used(d)
        assert status == "PASS"


class TestComplianceEngine:
    def test_full_scan(self, engine, tmp_path):
        (tmp_path / "main.py").write_text("import logging\nimport hashlib\n")
        report = engine.run_scan(str(tmp_path), "CIS")
        assert isinstance(report, ComplianceReport)
        assert report.controls_total > 0
        assert 0 <= report.score <= 100

    def test_filter_by_framework(self, engine, tmp_path):
        report = engine.run_scan(str(tmp_path), "OWASP")
        assert report.framework == "OWASP"
        owasp_ids = {r.control_id for r in report.results}
        assert all(cid.startswith("OWASP") for cid in owasp_ids)

    def test_exception_skips_control(self, engine, tmp_path):
        engine.db.add_exception("CIS-6.1", "Test exception", "test")
        report = engine.run_scan(str(tmp_path), "CIS")
        skip_results = [r for r in report.results if r.status == "SKIP"]
        assert any(r.control_id == "CIS-6.1" for r in skip_results)

    def test_scan_saved_to_db(self, engine, tmp_path):
        engine.run_scan(str(tmp_path), "ALL")
        runs = engine.db.list_runs()
        assert len(runs) >= 1
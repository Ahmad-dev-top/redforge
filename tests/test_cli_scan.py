import json

from redforge.cli import write_findings
from redforge.config import settings
from redforge.schemas import Finding, Severity, VulnClass


def test_write_findings_json(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "reports_root", tmp_path)
    findings = [
        Finding(
            id="slither-0",
            detector="reentrancy-eth",
            vuln_class=VulnClass.REENTRANCY,
            severity=Severity.HIGH,
            confidence=0.9,
            contract="Vault",
            function="withdraw",
        )
    ]
    path = write_findings("abc123", findings)
    assert path == tmp_path / "abc123" / "findings.json"
    again = [Finding(**row) for row in json.loads(path.read_text(encoding="utf-8"))]
    assert again == findings


def test_write_findings_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "reports_root", tmp_path)
    path = write_findings("empty", [])
    assert json.loads(path.read_text(encoding="utf-8")) == []

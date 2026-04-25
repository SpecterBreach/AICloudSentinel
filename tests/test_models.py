"""
Basic smoke tests for AICloudSentinel models.
Run with: pytest tests/ -v
"""
from aicloudsentinel.models import (
    Finding, ScanResult, RiskLevel, CloudProvider, OWASPMapping
)
from datetime import datetime, timezone


def _make_finding(risk: RiskLevel = RiskLevel.HIGH) -> Finding:
    return Finding(
        finding_id    = "TEST-001",
        title         = "Test finding",
        provider      = CloudProvider.OCI,
        resource_type = "Object Storage Bucket",
        resource_name = "test-bucket",
        resource_id   = "ocid1.bucket.test",
        region        = "us-ashburn-1",
        risk_level    = risk,
        owasp         = OWASPMapping(llm_ids=["LLM02"], agentic_ids=["ASI08"]),
        description   = "Test description",
        evidence      = "public_access_type=ObjectRead",
        recommendation= "Set NoPublicAccess",
    )


def test_finding_to_dict():
    f = _make_finding()
    d = f.to_dict()
    assert d["finding_id"] == "TEST-001"
    assert d["provider"] == "OCI"
    assert d["risk_level"] == "HIGH"
    assert "LLM02" in d["owasp_llm"]
    assert "ASI08" in d["owasp_agentic"]


def test_owasp_mapping_describe():
    m = OWASPMapping(llm_ids=["LLM02", "LLM06"], agentic_ids=["ASI04"])
    desc = m.describe()
    assert "LLM02" in desc
    assert "ASI04" in desc


def test_scan_result_counts():
    result = ScanResult(
        scan_id    = "TEST-SCAN-001",
        provider   = CloudProvider.OCI,
        scope      = "ocid1.compartment.test",
        started_at = datetime.now(timezone.utc).isoformat(),
        findings   = [
            _make_finding(RiskLevel.CRITICAL),
            _make_finding(RiskLevel.CRITICAL),
            _make_finding(RiskLevel.HIGH),
            _make_finding(RiskLevel.LOW),
        ],
    )
    assert result.critical_count == 2
    assert result.high_count == 1
    assert result.low_count == 1
    assert result.total == 4


def test_scan_result_sorted():
    result = ScanResult(
        scan_id    = "TEST-SCAN-002",
        provider   = CloudProvider.AWS,
        scope      = "123456789",
        started_at = datetime.now(timezone.utc).isoformat(),
        findings   = [
            _make_finding(RiskLevel.LOW),
            _make_finding(RiskLevel.CRITICAL),
            _make_finding(RiskLevel.MEDIUM),
        ],
    )
    sorted_f = result.sorted_findings()
    assert sorted_f[0].risk_level == RiskLevel.CRITICAL
    assert sorted_f[-1].risk_level == RiskLevel.LOW

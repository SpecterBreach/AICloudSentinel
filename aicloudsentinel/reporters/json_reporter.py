"""
reporters/json_reporter.py
===========================
Writes ScanResult to structured JSON — useful for CI/CD pipelines,
SIEM ingestion, and programmatic consumption.
"""

from __future__ import annotations
import json
import logging
from pathlib import Path

from ..models import ScanResult

log = logging.getLogger(__name__)


class JSONReporter:
    def write(self, result: ScanResult, output_path: str | Path = "aicloudsentinel_report.json") -> Path:
        path = Path(output_path)
        payload = {
            "scan_id":           result.scan_id,
            "provider":          result.provider.value,
            "scope":             result.scope,
            "started_at":        result.started_at,
            "completed_at":      result.completed_at,
            "summary": {
                "total":    result.total,
                "critical": result.critical_count,
                "high":     result.high_count,
                "medium":   result.medium_count,
                "low":      result.low_count,
            },
            "executive_summary": result.executive_summary,
            "risk_narrative":    result.risk_narrative,
            "findings":          [f.to_dict() for f in result.sorted_findings()],
        }
        path.write_text(json.dumps(payload, indent=2, default=str))
        log.info("JSON report saved → %s", path.resolve())
        return path

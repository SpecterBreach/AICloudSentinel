"""
models.py — Core data models for AICloudSentinel findings and results.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from datetime import datetime, timezone


class RiskLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class CloudProvider(str, Enum):
    OCI   = "OCI"
    AWS   = "AWS"
    AZURE = "Azure"


# ── OWASP mappings ──────────────────────────────────────────────────────────

# OWASP Top 10 for LLM Applications 2025
OWASP_LLM_TOP10 = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain Vulnerabilities",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}

# OWASP Top 10 for Agentic Applications 2026 (ASI prefix — official)
OWASP_AGENTIC_TOP10 = {
    "ASI01": "Agent Goal Hijack",
    "ASI02": "Tool Misuse",
    "ASI03": "Memory Poisoning",
    "ASI04": "Identity Abuse",
    "ASI05": "Insecure Inter-Agent Communication",
    "ASI06": "Cascading Failure",
    "ASI07": "Resource and Cost Exhaustion",
    "ASI08": "Data Exfiltration via Agent",
    "ASI09": "Rogue or Compromised Agent",
    "ASI10": "Human-Agent Trust Exploitation",
}


@dataclass
class OWASPMapping:
    """Maps a finding to OWASP LLM and/or Agentic Top 10 categories."""
    llm_ids:     list[str] = field(default_factory=list)   # e.g. ["LLM02", "LLM07"]
    agentic_ids: list[str] = field(default_factory=list)   # e.g. ["ASI04"]

    def describe(self) -> str:
        parts = []
        for lid in self.llm_ids:
            parts.append(f"{lid}: {OWASP_LLM_TOP10.get(lid, lid)}")
        for aid in self.agentic_ids:
            parts.append(f"{aid}: {OWASP_AGENTIC_TOP10.get(aid, aid)}")
        return " | ".join(parts) if parts else "—"


@dataclass
class Finding:
    """
    A single security finding from a cloud AI workload scan.
    """
    # Identity
    finding_id:       str
    title:            str
    provider:         CloudProvider
    resource_type:    str
    resource_name:    str
    resource_id:      str
    region:           str

    # Risk
    risk_level:       RiskLevel
    owasp:            OWASPMapping

    # Detail
    description:      str
    evidence:         str                  # raw data that triggered this finding
    recommendation:   str

    # AI analysis (populated by ClaudeAnalyzer)
    ai_explanation:   str = ""
    ai_remediation:   str = ""
    ai_attack_scenario: str = ""

    # Metadata
    tags:             dict = field(default_factory=dict)
    timestamp:        str  = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {
            "finding_id":          self.finding_id,
            "title":               self.title,
            "provider":            self.provider.value,
            "resource_type":       self.resource_type,
            "resource_name":       self.resource_name,
            "resource_id":         self.resource_id,
            "region":              self.region,
            "risk_level":          self.risk_level.value,
            "owasp_llm":           self.owasp.llm_ids,
            "owasp_agentic":       self.owasp.agentic_ids,
            "owasp_description":   self.owasp.describe(),
            "description":         self.description,
            "evidence":            self.evidence,
            "recommendation":      self.recommendation,
            "ai_explanation":      self.ai_explanation,
            "ai_remediation":      self.ai_remediation,
            "ai_attack_scenario":  self.ai_attack_scenario,
            "tags":                self.tags,
            "timestamp":           self.timestamp,
        }


@dataclass
class ScanResult:
    """
    Aggregated result from a full AICloudSentinel scan.
    """
    scan_id:      str
    provider:     CloudProvider
    scope:        str                      # compartment / account / subscription
    started_at:   str
    completed_at: str = ""
    findings:     list[Finding] = field(default_factory=list)

    # AI-generated executive summary (populated after Claude analysis)
    executive_summary: str = ""
    risk_narrative:    str = ""

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.risk_level == RiskLevel.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.risk_level == RiskLevel.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.risk_level == RiskLevel.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.risk_level == RiskLevel.LOW)

    @property
    def total(self) -> int:
        return len(self.findings)

    def sorted_findings(self) -> list[Finding]:
        order = {RiskLevel.CRITICAL: 0, RiskLevel.HIGH: 1,
                 RiskLevel.MEDIUM: 2,   RiskLevel.LOW: 3, RiskLevel.INFO: 4}
        return sorted(self.findings, key=lambda f: order.get(f.risk_level, 9))

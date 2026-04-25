"""
analyzers/claude_analyzer.py
=============================
Uses the Anthropic Claude API to enrich AICloudSentinel findings with:

  - Plain-English attack scenario ("what could an attacker actually do?")
  - Detailed AI-driven remediation steps (context-aware, not generic)
  - Executive summary for the full scan
  - Risk narrative tying findings to business/operational impact

This is the core AI layer that differentiates AICloudSentinel from
rule-only CSPM scanners.
"""

from __future__ import annotations
import os
import json
import logging
import time
from typing import Optional

from ..models import Finding, ScanResult, RiskLevel

log = logging.getLogger(__name__)

_SYSTEM_PROMPT = """You are AICloudSentinel's AI security analyst — a senior cloud security
engineer specialising in AI/LLM workload security across OCI, AWS, and Azure.

Your job is to enrich raw infrastructure security findings with:
1. A concrete, realistic attack scenario (2-3 sentences) — what an attacker
   could actually do if they exploited this finding, specific to AI/LLM context.
2. Step-by-step remediation instructions tailored to the cloud provider and
   resource type (4-6 numbered steps, actionable and specific).
3. Business/operational impact if exploited (1-2 sentences).

Tone: direct, technical, no filler. Write as a peer speaking to a security engineer.
Do NOT use markdown headers. Respond ONLY with a JSON object containing exactly:
{
  "attack_scenario": "...",
  "remediation_steps": "...",
  "business_impact": "..."
}"""

_EXECUTIVE_SYSTEM = """You are writing the executive summary section of an AI workload
security audit report. Your audience is a CISO or security lead — technically literate
but needs a clear narrative, not a list dump.

Write 3-4 concise paragraphs covering:
1. Overall posture and most critical risk theme
2. Specific highest-risk findings and their AI/LLM security implications
3. Immediate priority actions (top 3)
4. Closing risk statement

Tone: professional, clear, no bullet points in the paragraphs, no markdown headers.
Respond with plain text only."""


class ClaudeAnalyzer:
    """
    Enriches ScanResult findings using the Anthropic Claude API.

    The API key is read from the ANTHROPIC_API_KEY environment variable.

    Usage:
        analyzer = ClaudeAnalyzer()
        result   = analyzer.analyze(scan_result)  # mutates findings in-place
    """

    MODEL   = "claude-sonnet-4-20250514"
    MAX_TOK = 800

    def __init__(self, api_key: Optional[str] = None, max_findings_to_enrich: int = 20):
        self.api_key   = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self.max_enrich = max_findings_to_enrich
        if not self.api_key:
            log.warning(
                "ANTHROPIC_API_KEY not set. AI enrichment will be skipped. "
                "Export ANTHROPIC_API_KEY=<your-key> to enable AI analysis."
            )

    # ── Public API ───────────────────────────────────────────────────────────

    def analyze(self, result: ScanResult) -> ScanResult:
        """
        Enrich findings with AI analysis and generate executive summary.
        Mutates result in-place and returns it.
        """
        if not self.api_key:
            log.info("Skipping AI analysis (no API key)")
            result.executive_summary = self._fallback_summary(result)
            return result

        # Enrich individual findings (prioritise CRITICAL/HIGH)
        priority_findings = [
            f for f in result.sorted_findings()
            if f.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH)
        ][:self.max_enrich]

        log.info("[Claude] Enriching %d priority findings...", len(priority_findings))
        for idx, finding in enumerate(priority_findings, 1):
            log.info("[Claude] Enriching %d/%d: %s", idx, len(priority_findings), finding.title)
            self._enrich_finding(finding)
            time.sleep(0.3)  # gentle rate limiting

        # Generate executive summary
        log.info("[Claude] Generating executive summary...")
        result.executive_summary = self._generate_executive_summary(result)
        result.risk_narrative    = self._generate_risk_narrative(result)

        return result

    # ── Finding enrichment ───────────────────────────────────────────────────

    def _enrich_finding(self, finding: Finding) -> None:
        prompt = f"""Cloud provider: {finding.provider.value}
Resource type: {finding.resource_type}
Resource name: {finding.resource_name}
Finding title: {finding.title}
Risk level: {finding.risk_level.value}
OWASP mappings: {finding.owasp.describe()}
Description: {finding.description}
Evidence: {finding.evidence}
Existing recommendation: {finding.recommendation}

Enrich this AI workload security finding with a realistic attack scenario,
detailed remediation steps, and business impact."""

        response = self._call_claude(prompt, _SYSTEM_PROMPT)
        if not response:
            return

        try:
            # Strip any accidental markdown fences
            clean = response.strip()
            if clean.startswith("```"):
                clean = clean.split("```")[1]
                if clean.startswith("json"):
                    clean = clean[4:]
            data = json.loads(clean)
            finding.ai_attack_scenario = data.get("attack_scenario", "")
            finding.ai_remediation     = data.get("remediation_steps", "")
            # Append business impact to the AI explanation field
            finding.ai_explanation     = data.get("business_impact", "")
        except (json.JSONDecodeError, KeyError) as exc:
            log.debug("JSON parse error for finding enrichment: %s", exc)
            finding.ai_explanation = response[:500]

    # ── Executive summary ────────────────────────────────────────────────────

    def _generate_executive_summary(self, result: ScanResult) -> str:
        top_findings = "\n".join([
            f"- [{f.risk_level.value}] {f.title} ({f.provider.value} / {f.resource_type})"
            for f in result.sorted_findings()[:15]
        ])

        prompt = f"""AI workload security scan results for {result.provider.value}:
Scan scope: {result.scope}
Scan date: {result.started_at[:10]}

Risk breakdown:
  CRITICAL: {result.critical_count}
  HIGH:     {result.high_count}
  MEDIUM:   {result.medium_count}
  LOW:      {result.low_count}
  TOTAL:    {result.total}

Top findings:
{top_findings}

Write the executive summary."""

        summary = self._call_claude(
            prompt, _EXECUTIVE_SYSTEM, max_tokens=600
        )
        return summary or self._fallback_summary(result)

    def _generate_risk_narrative(self, result: ScanResult) -> str:
        if result.critical_count == 0 and result.high_count == 0:
            return (
                f"This {result.provider.value} scan identified {result.total} findings "
                f"with no critical or high severity issues. The AI workload posture "
                f"is relatively healthy, with medium and low issues requiring attention "
                f"as part of normal security hygiene."
            )

        prompt = f"""Write a 2-sentence risk narrative for a security dashboard.
Provider: {result.provider.value}
Critical findings: {result.critical_count}
High findings: {result.high_count}
Most severe finding: {result.sorted_findings()[0].title if result.findings else 'none'}

The narrative should state the risk posture and the single most urgent action.
Plain text, no markdown."""

        narrative = self._call_claude(prompt, _SYSTEM_PROMPT, max_tokens=150)
        return narrative or (
            f"{result.critical_count} critical and {result.high_count} high severity "
            f"AI workload security issues detected in {result.provider.value}. "
            f"Immediate remediation required."
        )

    # ── Claude API call ──────────────────────────────────────────────────────

    def _call_claude(
        self,
        user_message: str,
        system_prompt: str,
        max_tokens: int = None,
        retries: int = 2,
    ) -> str:
        import urllib.request
        import urllib.error

        max_tokens = max_tokens or self.MAX_TOK
        payload = json.dumps({
            "model":      self.MODEL,
            "max_tokens": max_tokens,
            "system":     system_prompt,
            "messages":   [{"role": "user", "content": user_message}],
        }).encode()

        for attempt in range(retries + 1):
            try:
                req = urllib.request.Request(
                    "https://api.anthropic.com/v1/messages",
                    data    = payload,
                    headers = {
                        "x-api-key":         self.api_key,
                        "anthropic-version": "2023-06-01",
                        "content-type":      "application/json",
                    },
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=30) as resp:
                    body = json.loads(resp.read())
                    return body["content"][0]["text"]
            except urllib.error.HTTPError as exc:
                if exc.code == 429 and attempt < retries:
                    wait = 2 ** attempt * 2
                    log.warning("[Claude] Rate limited — retrying in %ds", wait)
                    time.sleep(wait)
                    continue
                log.warning("[Claude] API error %s: %s", exc.code, exc.read()[:200])
                break
            except Exception as exc:
                log.warning("[Claude] Request failed: %s", exc)
                break

        return ""

    # ── Fallback ─────────────────────────────────────────────────────────────

    def _fallback_summary(self, result: ScanResult) -> str:
        return (
            f"AICloudSentinel scan completed for {result.provider.value} "
            f"(scope: {result.scope}) on {result.started_at[:10]}.\n\n"
            f"Total findings: {result.total} | "
            f"Critical: {result.critical_count} | "
            f"High: {result.high_count} | "
            f"Medium: {result.medium_count} | "
            f"Low: {result.low_count}\n\n"
            f"AI-powered analysis unavailable (ANTHROPIC_API_KEY not set). "
            f"Set the environment variable and re-run to enable attack scenario "
            f"generation and executive summary."
        )

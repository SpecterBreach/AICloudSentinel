#!/usr/bin/env python3
"""
aicloudsentinel/cli.py
======================
Command-line interface for AICloudSentinel.

Usage examples:
  # Scan OCI with AI analysis and Excel + JSON output
  aicloudsentinel scan oci \\
    --compartment-id ocid1.compartment.oc1..example \\
    --region us-ashburn-1 \\
    --output report.xlsx

  # Scan AWS (no AI enrichment)
  aicloudsentinel scan aws \\
    --region us-east-1 \\
    --no-ai

  # Scan Azure
  aicloudsentinel scan azure \\
    --subscription-id xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
"""

from __future__ import annotations
import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime

from . import __version__
from .models import CloudProvider, RiskLevel

# ── ANSI colour helpers ───────────────────────────────────────────────────────
RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[91m"
ORANGE = "\033[93m"
YELLOW = "\033[33m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BLUE   = "\033[94m"
GRAY   = "\033[90m"
WHITE  = "\033[97m"

def _c(text: str, color: str) -> str:
    return f"{color}{text}{RESET}"

RISK_COLORS = {
    "CRITICAL": RED,
    "HIGH":     ORANGE,
    "MEDIUM":   YELLOW,
    "LOW":      GREEN,
    "INFO":     CYAN,
}

BANNER = f"""{CYAN}
  ╔═══════════════════════════════════════════════════════════╗
  ║   █████╗ ██╗ ██████╗██╗      ██████╗ ██╗   ██╗██████╗   ║
  ║  ██╔══██╗██║██╔════╝██║     ██╔═══██╗██║   ██║██╔══██╗  ║
  ║  ███████║██║██║     ██║     ██║   ██║██║   ██║██║  ██║  ║
  ║  ██╔══██║██║██║     ██║     ██║   ██║██║   ██║██║  ██║  ║
  ║  ██║  ██║██║╚██████╗███████╗╚██████╔╝╚██████╔╝██████╔╝  ║
  ║  ╚═╝  ╚═╝╚═╝ ╚═════╝╚══════╝ ╚═════╝  ╚═════╝ ╚═════╝  ║
  ║                                                           ║
  ║        ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗  ║
  ║        ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║  ║
  ║        ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║  ║
  ║        ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║  ║
  ║        ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║  ║
  ║        ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝  ║
  ╚═══════════════════════════════════════════════════════════╝
{RESET}"""

def _print_banner() -> None:
    print(BANNER)
    print(f"  {_c('AI Workload Security Scanner', BOLD)}  "
          f"{_c(f'v{__version__}', GRAY)}  "
          f"{_c('OCI · AWS · Azure', CYAN)}")
    print(f"  {_c('OWASP LLM Top 10 · OWASP Agentic AI Top 10 · Powered by Claude', GRAY)}")
    print(f"  {_c('github.com/SpecterBreach/AICloudSentinel', BLUE)}\n")


def _print_finding_table(findings) -> None:
    if not findings:
        print(f"\n  {_c('✓  No findings detected.', GREEN)}\n")
        return

    print(f"\n  {'RISK':<10} {'TITLE':<52} {'RESOURCE':<30} {'OWASP'}")
    print(f"  {'─'*10} {'─'*52} {'─'*30} {'─'*20}")

    for f in findings:
        risk_col = _c(f"{f.risk_level.value:<10}", RISK_COLORS.get(f.risk_level.value, WHITE))
        title    = f.title[:50] + ".." if len(f.title) > 52 else f.title
        resource = f.resource_name[:28] + ".." if len(f.resource_name) > 30 else f.resource_name
        owasp    = ", ".join(f.owasp.llm_ids[:2] + f.owasp.agentic_ids[:1])
        print(f"  {risk_col} {title:<52} {resource:<30} {_c(owasp, CYAN)}")


def _print_summary(result) -> None:
    print(f"\n  {'─'*72}")
    print(f"  {_c('SCAN COMPLETE', BOLD)}  ·  {result.scan_id}  ·  {result.provider.value}")
    print(f"  {'─'*72}")
    print(f"  {_c('CRITICAL', RED):20}  {result.critical_count}")
    print(f"  {_c('HIGH',     ORANGE):20}  {result.high_count}")
    print(f"  {_c('MEDIUM',   YELLOW):20}  {result.medium_count}")
    print(f"  {_c('LOW',      GREEN):20}  {result.low_count}")
    print(f"  {_c('TOTAL',    BOLD):20}  {result.total}")
    print(f"  {'─'*72}\n")

    if result.risk_narrative:
        print(f"  {_c('Risk Narrative:', BOLD)}")
        for line in result.risk_narrative.split(". "):
            if line.strip():
                print(f"  {line.strip()}.")
        print()


# ── Argument parsing ──────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aicloudsentinel",
        description="AI Workload Security Scanner — OCI, AWS, Azure",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--version", action="version", version=f"AICloudSentinel {__version__}")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    sub = parser.add_subparsers(dest="command", required=True)

    # ── scan ──
    scan = sub.add_parser("scan", help="Run a security scan")
    scan.add_argument("provider", choices=["oci", "aws", "azure"],
                      help="Cloud provider to scan")

    # OCI options
    oci_g = scan.add_argument_group("OCI options")
    oci_g.add_argument("--compartment-id", help="OCI compartment OCID")
    oci_g.add_argument("--oci-profile", default="DEFAULT", help="OCI config profile")
    oci_g.add_argument("--region", default="us-ashburn-1", help="OCI / AWS region")

    # AWS options
    aws_g = scan.add_argument_group("AWS options")
    aws_g.add_argument("--aws-profile", default="default", help="AWS CLI profile")
    aws_g.add_argument("--account-id", default="", help="AWS account ID (optional)")

    # Azure options
    az_g = scan.add_argument_group("Azure options")
    az_g.add_argument("--subscription-id", help="Azure subscription ID")
    az_g.add_argument("--resource-group", default="", help="Azure resource group (optional)")

    # Output options
    out_g = scan.add_argument_group("Output options")
    out_g.add_argument("--output", default="aicloudsentinel_report.xlsx",
                       help="Output file path (.xlsx or .json)")
    out_g.add_argument("--json", action="store_true", help="Also write JSON report")
    out_g.add_argument("--no-ai", action="store_true",
                       help="Skip Claude AI enrichment (faster, no API key needed)")
    out_g.add_argument("--max-enrich", type=int, default=20,
                       help="Max findings to enrich with Claude (default: 20)")

    return parser


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = build_parser()
    args   = parser.parse_args()

    logging.basicConfig(
        level   = logging.DEBUG if args.debug else logging.WARNING,
        format  = "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    _print_banner()

    provider = args.provider.lower()
    result   = None

    # ── Run scanner ───────────────────────────────────────────────────────────
    print(f"  {_c('►', CYAN)} Starting {provider.upper()} scan...\n")
    t0 = time.time()

    try:
        if provider == "oci":
            if not args.compartment_id:
                print(f"  {_c('ERROR:', RED)} --compartment-id is required for OCI scans")
                return 1
            from .scanners.oci_scanner import OCIScanner
            scanner = OCIScanner(
                compartment_id = args.compartment_id,
                profile        = args.oci_profile,
                region         = args.region,
            )
            result = scanner.scan()

        elif provider == "aws":
            from .scanners.aws_scanner import AWSScanner
            scanner = AWSScanner(
                region     = args.region,
                profile    = args.aws_profile,
                account_id = args.account_id,
            )
            result = scanner.scan()

        elif provider == "azure":
            if not args.subscription_id:
                print(f"  {_c('ERROR:', RED)} --subscription-id is required for Azure scans")
                return 1
            from .scanners.azure_scanner import AzureScanner
            scanner = AzureScanner(
                subscription_id = args.subscription_id,
                resource_group  = args.resource_group,
            )
            result = scanner.scan()

    except RuntimeError as exc:
        print(f"  {_c('ERROR:', RED)} {exc}")
        return 1
    except Exception as exc:
        print(f"  {_c('ERROR:', RED)} Scan failed: {exc}")
        if args.debug:
            raise
        return 1

    scan_time = time.time() - t0
    print(f"  {_c('✓', GREEN)} Scan completed in {scan_time:.1f}s — "
          f"{_c(str(result.total), BOLD)} findings\n")

    # ── AI enrichment ─────────────────────────────────────────────────────────
    if not args.no_ai:
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if api_key:
            print(f"  {_c('►', CYAN)} Running Claude AI analysis "
                  f"({min(args.max_enrich, result.critical_count + result.high_count)} "
                  f"priority findings)...\n")
            from .analyzers.claude_analyzer import ClaudeAnalyzer
            analyzer = ClaudeAnalyzer(api_key=api_key, max_findings_to_enrich=args.max_enrich)
            result   = analyzer.analyze(result)
            print(f"  {_c('✓', GREEN)} AI analysis complete\n")
        else:
            print(f"  {_c('⚠', YELLOW)}  ANTHROPIC_API_KEY not set — skipping AI enrichment")
            print(f"     Export ANTHROPIC_API_KEY=<key> to enable attack scenario generation\n")
            from .analyzers.claude_analyzer import ClaudeAnalyzer
            result.executive_summary = ClaudeAnalyzer()._fallback_summary(result)

    # ── Print findings table ──────────────────────────────────────────────────
    _print_finding_table(result.sorted_findings())
    _print_summary(result)

    # ── Write reports ─────────────────────────────────────────────────────────
    output = args.output
    if output.endswith(".json") or args.json:
        from .reporters.json_reporter import JSONReporter
        json_path = output if output.endswith(".json") else output.replace(".xlsx", ".json")
        JSONReporter().write(result, json_path)
        print(f"  {_c('JSON report:', BOLD)} {json_path}")

    if not output.endswith(".json"):
        from .reporters.excel_reporter import ExcelReporter
        ExcelReporter().write(result, output)
        print(f"  {_c('Excel report:', BOLD)} {output}")

    print()

    # Exit code reflects severity
    if result.critical_count > 0:
        return 2   # critical findings
    if result.high_count > 0:
        return 1   # high findings
    return 0       # clean / low/medium only


if __name__ == "__main__":
    sys.exit(main())

# Changelog

All notable changes to AICloudSentinel are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project follows [Semantic Versioning](https://semver.org/).

---

## [1.0.0] — 2026-04-25

### Added
- **OCI Scanner** — Object Storage (public access, versioning, replication),
  OCI Functions (LLM API key exposure), IAM over-privilege detection,
  Compute IMDS v1 on AI/GPU workloads, Data Science notebook VCN checks
- **AWS Scanner** — S3 (public access block, versioning), Lambda (LLM API key
  in env vars), IAM/Bedrock over-privilege, EC2 IMDSv1 on GPU instances,
  SageMaker notebook direct internet access, Bedrock invocation logging
- **Azure Scanner** — Blob Storage (public access, HTTPS-only), Function App
  LLM key exposure, Cognitive Services / Azure OpenAI public access + static
  key auth, Azure ML workspace public network access, Key Vault soft-delete
- **Claude AI Analyzer** — ANTHROPIC_API_KEY-driven attack scenario generation,
  context-aware remediation steps, executive summary, risk narrative
- **Excel Reporter** — 4-sheet workbook: Executive Summary, All Findings,
  Priority Actions, OWASP Heatmap
- **JSON Reporter** — structured output for CI/CD and SIEM ingestion
- **CLI** — `aicloudsentinel scan {oci|aws|azure}` with coloured terminal output,
  exit codes (0/1/2) for CI/CD integration
- **OWASP mappings** — full OWASP LLM Top 10 (2025) and OWASP Agentic AI
  Top 10 (2026) framework coverage
- pip-installable as `aicloudsentinel[oci|aws|azure|all]`

---

## Roadmap

See [README.md#roadmap](README.md#roadmap) for planned features including
GCP support, IaC scanning, SARIF output, and custom YAML rules.

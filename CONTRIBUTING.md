# Contributing to AICloudSentinel

Thank you for your interest in contributing. AICloudSentinel is an open-source
AI workload security scanner and all contributions — new checks, cloud provider
support, bug fixes, and documentation — are welcome.

---

## Ways to Contribute

### 1. New Security Checks
The highest-value contributions are new detection checks. Good candidates:

- **GCP** — Vertex AI, Cloud Functions, Cloud Storage model buckets, Artifact Registry
- **OCI** — OCI Generative AI Service, AI Quick Actions, additional Data Science checks
- **AWS** — Amazon Comprehend, Amazon Rekognition, SageMaker Pipelines exposure
- **Azure** — Azure AI Studio, Prompt Flow, Azure ML compute clusters

Each check should:
- Target a resource type that specifically hosts AI/LLM workloads
- Map to at least one OWASP LLM Top 10 or OWASP Agentic AI Top 10 category
- Include `finding_id`, `title`, `description`, `evidence`, and `recommendation`

### 2. Bug Reports
Open a GitHub Issue with:
- Cloud provider and resource type
- Python version and OS
- Full error traceback
- Sanitised example (no real OCIDs, account IDs, or credentials)

### 3. Documentation
- Fix typos, clarify setup steps, add examples
- Add a `docs/checks/` page describing what each check tests and why it matters

---

## Development Setup

```bash
git clone https://github.com/SpecterBreach/AICloudSentinel.git
cd AICloudSentinel

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Install in editable mode with dev dependencies
pip install -e ".[all,dev]"
```

---

## Adding a New Check

1. Open the relevant scanner: `aicloudsentinel/scanners/{oci,aws,azure}_scanner.py`
2. Add a new `_scan_*` method following the existing pattern
3. Call it from the `scan()` method
4. Map findings to OWASP using `OWASPMapping(llm_ids=[...], agentic_ids=[...])`
5. Open a PR with a description of what the check detects and a real-world scenario where it matters

### Check template

```python
def _scan_my_new_check(self, client, config) -> None:
    log.info("[OCI] Scanning <resource type>...")
    try:
        resources = ...  # list resources
    except Exception as exc:
        log.warning("[OCI] Scan failed: %s", exc)
        return

    for r in resources:
        if <misconfiguration_condition>:
            self._findings.append(Finding(
                finding_id    = _make_id(),
                title         = "Short, specific title",
                provider      = CloudProvider.OCI,
                resource_type = "Resource Type",
                resource_name = r.display_name,
                resource_id   = r.id,
                region        = self.region,
                risk_level    = RiskLevel.HIGH,
                owasp         = OWASPMapping(
                    llm_ids     = ["LLM02"],
                    agentic_ids = ["ASI04"],
                ),
                description   = "What is wrong and why it is a security risk.",
                evidence      = f"property={value}",
                recommendation= "Specific steps to fix the issue.",
            ))
```

---

## Pull Request Guidelines

- One logical change per PR
- Branch naming: `feat/gcp-vertex-scanner`, `fix/oci-pagination`, `docs/check-descriptions`
- Keep PRs focused — large refactors should be discussed in an issue first
- No real credentials, OCIDs, account IDs, or internal hostnames in any commit

---

## Code Style

```bash
# Lint
ruff check .

# Type check
mypy aicloudsentinel/
```

---

## Questions

Open a GitHub Discussion or Issue. We'll respond promptly.

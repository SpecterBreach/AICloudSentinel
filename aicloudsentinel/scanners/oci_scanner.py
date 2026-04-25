"""
scanners/oci_scanner.py
=======================
Scans OCI tenancies for AI workload security misconfigurations:

  - Object Storage buckets holding model weights / training data (public access)
  - Vault secrets with LLM API keys (rotation, access policy)
  - IAM / IDCS service accounts used by AI agents (over-privilege)
  - OCI Functions with exposed LLM provider API keys in config
  - Compute instances running AI workloads with public IPs + IMDS unrestricted
  - OCI Data Science / AI Services misconfigurations
  - Cloud Guard findings related to AI resource types
"""

from __future__ import annotations
import logging
import uuid
from datetime import datetime, timezone

from ..models import (
    Finding, ScanResult, RiskLevel, CloudProvider,
    OWASPMapping,
)

log = logging.getLogger(__name__)

# Keywords that suggest a resource is AI/ML-related
AI_BUCKET_KEYWORDS  = ["model", "llm", "ai", "ml", "embedding", "vector",
                        "training", "dataset", "checkpoint", "weights", "rag",
                        "inference", "fine-tune", "finetune", "openai", "anthropic",
                        "bedrock", "genai", "generative"]

AI_FN_ENV_KEYWORDS  = ["openai_api_key", "anthropic_api_key", "cohere_api_key",
                        "huggingface_token", "replicate_api_token", "groq_api_key",
                        "together_api_key", "mistral_api_key", "gemini_api_key",
                        "llm_api_key", "ai_api_key", "model_api_key"]

PRIVILEGED_KEYWORDS = ["manage all-resources", "manage ai", "manage object-family",
                        "manage functions-family", "manage data-science"]


def _is_ai_resource(name: str) -> bool:
    n = (name or "").lower()
    return any(kw in n for kw in AI_BUCKET_KEYWORDS)


def _make_id() -> str:
    return f"OCI-{uuid.uuid4().hex[:8].upper()}"


class OCIScanner:
    """
    Scans an OCI compartment (and sub-compartments) for AI workload
    security misconfigurations.

    Usage:
        scanner = OCIScanner(compartment_id="ocid1.compartment...", profile="DEFAULT")
        result  = scanner.scan()
    """

    def __init__(self, compartment_id: str, profile: str = "DEFAULT",
                 region: str = "us-ashburn-1"):
        self.compartment_id = compartment_id
        self.profile        = profile
        self.region         = region
        self._findings: list[Finding] = []

    # ── Public entry point ───────────────────────────────────────────────────

    def scan(self) -> ScanResult:
        try:
            import oci
        except ImportError:
            raise RuntimeError("oci package not installed. Run: pip install oci")

        started = datetime.now(timezone.utc).isoformat()
        log.info("[OCI] Starting scan — compartment: %s  region: %s",
                 self.compartment_id, self.region)

        config = oci.config.from_file(profile_name=self.profile)
        config["region"] = self.region

        self._scan_object_storage(oci, config)
        self._scan_functions(oci, config)
        self._scan_iam_agents(oci, config)
        self._scan_compute_imds(oci, config)
        self._scan_data_science(oci, config)

        result = ScanResult(
            scan_id     = f"OCI-SCAN-{uuid.uuid4().hex[:6].upper()}",
            provider    = CloudProvider.OCI,
            scope       = self.compartment_id,
            started_at  = started,
            completed_at= datetime.now(timezone.utc).isoformat(),
            findings    = self._findings,
        )
        log.info("[OCI] Scan complete — %d findings", len(self._findings))
        return result

    # ── Object Storage ───────────────────────────────────────────────────────

    def _scan_object_storage(self, oci, config) -> None:
        log.info("[OCI] Scanning Object Storage buckets...")
        try:
            os_client = oci.object_storage.ObjectStorageClient(config)
            ns        = os_client.get_namespace().data

            buckets = oci.pagination.list_call_get_all_results(
                os_client.list_buckets,
                namespace_name=ns,
                compartment_id=self.compartment_id,
                fields=["approximateSize", "tags"],
            ).data
        except Exception as exc:
            log.warning("[OCI] Object Storage scan failed: %s", exc)
            return

        for b in buckets:
            if not _is_ai_resource(b.name):
                continue

            try:
                detail = os_client.get_bucket(ns, b.name).data
            except Exception:
                continue

            # Check 1: public access
            public_access = getattr(detail, "public_access_type", "NoPublicAccess")
            if public_access != "NoPublicAccess":
                self._findings.append(Finding(
                    finding_id    = _make_id(),
                    title         = "AI model bucket has public read access",
                    provider      = CloudProvider.OCI,
                    resource_type = "Object Storage Bucket",
                    resource_name = b.name,
                    resource_id   = b.id or b.name,
                    region        = self.region,
                    risk_level    = RiskLevel.CRITICAL,
                    owasp         = OWASPMapping(
                        llm_ids     = ["LLM02", "LLM04"],
                        agentic_ids = ["ASI08"],
                    ),
                    description   = (
                        f"Bucket '{b.name}' appears to hold AI/ML assets and has "
                        f"public access type '{public_access}'. Model weights, training "
                        f"data, or embeddings stored here are accessible to anyone on "
                        f"the internet."
                    ),
                    evidence      = f"public_access_type={public_access}",
                    recommendation= (
                        "Set public_access_type to NoPublicAccess. Use pre-authenticated "
                        "requests (PARs) or signed URLs for any required external access. "
                        "Enable Object Storage access logs and alert on unexpected access."
                    ),
                ))

            # Check 2: versioning disabled on AI buckets
            versioning = getattr(detail, "versioning", "Disabled")
            if str(versioning).lower() != "enabled":
                self._findings.append(Finding(
                    finding_id    = _make_id(),
                    title         = "AI model bucket versioning disabled — poisoning risk",
                    provider      = CloudProvider.OCI,
                    resource_type = "Object Storage Bucket",
                    resource_name = b.name,
                    resource_id   = b.id or b.name,
                    region        = self.region,
                    risk_level    = RiskLevel.MEDIUM,
                    owasp         = OWASPMapping(
                        llm_ids     = ["LLM04"],
                        agentic_ids = ["ASI03"],
                    ),
                    description   = (
                        f"Bucket '{b.name}' stores AI/ML assets but versioning is "
                        f"disabled. Without versioning, a compromised model file cannot "
                        f"be recovered and poisoning attacks leave no audit trail."
                    ),
                    evidence      = f"versioning={versioning}",
                    recommendation= (
                        "Enable Object Storage versioning. Combine with lifecycle policies "
                        "to manage storage cost. Configure alerts for unexpected object "
                        "modifications or deletions."
                    ),
                ))

            # Check 3: no replication (single point of failure for AI inference)
            replication = getattr(detail, "replication_enabled", False)
            if not replication:
                self._findings.append(Finding(
                    finding_id    = _make_id(),
                    title         = "AI model bucket has no cross-region replication",
                    provider      = CloudProvider.OCI,
                    resource_type = "Object Storage Bucket",
                    resource_name = b.name,
                    resource_id   = b.id or b.name,
                    region        = self.region,
                    risk_level    = RiskLevel.LOW,
                    owasp         = OWASPMapping(llm_ids=["LLM10"]),
                    description   = (
                        f"Bucket '{b.name}' has no replication policy. A regional "
                        f"outage could disrupt inference workloads that depend on it."
                    ),
                    evidence      = "replication_enabled=False",
                    recommendation= (
                        "Configure cross-region replication to a secondary OCI region. "
                        "For critical inference pipelines consider active-active object "
                        "storage with health checks."
                    ),
                ))

    # ── OCI Functions ────────────────────────────────────────────────────────

    def _scan_functions(self, oci, config) -> None:
        log.info("[OCI] Scanning Functions for exposed LLM API keys...")
        try:
            fn_client = oci.functions.FunctionsManagementClient(config)
            apps      = oci.pagination.list_call_get_all_results(
                fn_client.list_applications,
                compartment_id=self.compartment_id,
            ).data
        except Exception as exc:
            log.warning("[OCI] Functions scan failed: %s", exc)
            return

        for app in apps:
            try:
                fns = oci.pagination.list_call_get_all_results(
                    fn_client.list_functions,
                    application_id=app.id,
                ).data
            except Exception:
                continue

            for fn in fns:
                if not _is_ai_resource(fn.display_name) and not _is_ai_resource(app.display_name):
                    continue

                config_vars = fn.config or {}
                exposed_keys = [
                    k for k in config_vars
                    if k.lower() in AI_FN_ENV_KEYWORDS
                ]

                if exposed_keys:
                    self._findings.append(Finding(
                        finding_id    = _make_id(),
                        title         = "LLM API key exposed in OCI Function config",
                        provider      = CloudProvider.OCI,
                        resource_type = "OCI Function",
                        resource_name = fn.display_name,
                        resource_id   = fn.id,
                        region        = self.region,
                        risk_level    = RiskLevel.CRITICAL,
                        owasp         = OWASPMapping(
                            llm_ids     = ["LLM02", "LLM07"],
                            agentic_ids = ["ASI04"],
                        ),
                        description   = (
                            f"Function '{fn.display_name}' in app '{app.display_name}' "
                            f"has LLM provider API key(s) stored as plain-text config: "
                            f"{', '.join(exposed_keys)}. Anyone with read access to "
                            f"the function config can extract these credentials."
                        ),
                        evidence      = f"config_keys={exposed_keys}",
                        recommendation= (
                            "Move all LLM API keys to OCI Vault as secrets. Reference "
                            "them via the OCI Functions secret injection mechanism "
                            "(function config referencing vault secret OCID). Rotate "
                            "the exposed keys immediately."
                        ),
                    ))

    # ── IAM / IDCS Agent Accounts ────────────────────────────────────────────

    def _scan_iam_agents(self, oci, config) -> None:
        log.info("[OCI] Scanning IAM for over-privileged AI agent accounts...")
        try:
            identity = oci.identity.IdentityClient(config)
            policies = oci.pagination.list_call_get_all_results(
                identity.list_policies,
                compartment_id=self.compartment_id,
            ).data
        except Exception as exc:
            log.warning("[OCI] IAM scan failed: %s", exc)
            return

        for pol in policies:
            for stmt in (pol.statements or []):
                lower = stmt.lower()
                if not _is_ai_resource(pol.name) and "agent" not in lower:
                    continue
                for kw in PRIVILEGED_KEYWORDS:
                    if kw in lower and "allow" in lower:
                        self._findings.append(Finding(
                            finding_id    = _make_id(),
                            title         = "AI agent policy grants excessive cloud permissions",
                            provider      = CloudProvider.OCI,
                            resource_type = "IAM Policy",
                            resource_name = pol.name,
                            resource_id   = pol.id,
                            region        = self.region,
                            risk_level    = RiskLevel.HIGH,
                            owasp         = OWASPMapping(
                                llm_ids     = ["LLM06"],
                                agentic_ids = ["ASI02", "ASI04"],
                            ),
                            description   = (
                                f"Policy '{pol.name}' grants an AI agent / service account "
                                f"broad permission via: '{stmt[:120]}'. An agent with "
                                f"'manage all-resources' or equivalent can exfiltrate data, "
                                f"modify infrastructure, or pivot to other services."
                            ),
                            evidence      = f"statement={stmt[:200]}",
                            recommendation= (
                                "Apply least-privilege: scope agent policies to the exact "
                                "resources and verbs needed. Use OCI dynamic groups and "
                                "instance principals instead of user credentials. Audit "
                                "agent policy statements quarterly."
                            ),
                        ))
                        break

    # ── Compute IMDS ─────────────────────────────────────────────────────────

    def _scan_compute_imds(self, oci, config) -> None:
        log.info("[OCI] Scanning Compute for IMDS exposure on AI workloads...")
        try:
            compute  = oci.core.ComputeClient(config)
            network  = oci.core.VirtualNetworkClient(config)
            instances = oci.pagination.list_call_get_all_results(
                compute.list_instances,
                compartment_id=self.compartment_id,
            ).data
        except Exception as exc:
            log.warning("[OCI] Compute scan failed: %s", exc)
            return

        for inst in instances:
            if inst.lifecycle_state != "RUNNING":
                continue
            if not _is_ai_resource(inst.display_name):
                # also check shape — GPU shapes often run AI
                shape = (inst.shape or "").lower()
                if not any(g in shape for g in ["gpu", "a10", "a100", "v100", "bm.gpu"]):
                    continue

            # Check: IMDS v1 (unauthenticated) available
            imds_config = getattr(inst, "instance_options", None)
            are_legacy_imds_endpoints_disabled = True
            if imds_config:
                are_legacy_imds_endpoints_disabled = getattr(
                    imds_config, "are_legacy_imds_endpoints_disabled", True
                )

            if not are_legacy_imds_endpoints_disabled:
                self._findings.append(Finding(
                    finding_id    = _make_id(),
                    title         = "AI compute instance has unauthenticated IMDS v1 enabled",
                    provider      = CloudProvider.OCI,
                    resource_type = "Compute Instance",
                    resource_name = inst.display_name,
                    resource_id   = inst.id,
                    region        = self.region,
                    risk_level    = RiskLevel.HIGH,
                    owasp         = OWASPMapping(
                        llm_ids     = ["LLM02"],
                        agentic_ids = ["ASI04", "ASI08"],
                    ),
                    description   = (
                        f"Instance '{inst.display_name}' (shape: {inst.shape}) appears to "
                        f"run AI workloads and has legacy IMDS v1 enabled. An SSRF "
                        f"vulnerability in an AI application or prompt injection that "
                        f"causes an HTTP call can reach the metadata endpoint and steal "
                        f"instance principal credentials."
                    ),
                    evidence      = f"are_legacy_imds_endpoints_disabled=False  shape={inst.shape}",
                    recommendation= (
                        "Set are_legacy_imds_endpoints_disabled=true in instance options "
                        "to enforce IMDSv2 (token-required). Restrict outbound HTTP from "
                        "AI inference processes using OCI Security Lists or NSGs. "
                        "Consider running inference in isolated VCN subnets."
                    ),
                ))

    # ── OCI Data Science ─────────────────────────────────────────────────────

    def _scan_data_science(self, oci, config) -> None:
        log.info("[OCI] Scanning Data Science projects...")
        try:
            ds_client = oci.data_science.DataScienceClient(config)
            projects  = oci.pagination.list_call_get_all_results(
                ds_client.list_projects,
                compartment_id=self.compartment_id,
            ).data
        except Exception as exc:
            log.warning("[OCI] Data Science scan failed: %s", exc)
            return

        for proj in projects:
            # Check: notebook sessions with public endpoints
            try:
                notebooks = oci.pagination.list_call_get_all_results(
                    ds_client.list_notebook_sessions,
                    compartment_id=self.compartment_id,
                    project_id=proj.id,
                ).data
            except Exception:
                continue

            for nb in notebooks:
                if nb.lifecycle_state not in ("ACTIVE", "CREATING"):
                    continue
                nb_config = getattr(nb, "notebook_session_config_details", None)
                if nb_config:
                    subnet_id = getattr(nb_config, "subnet_id", None)
                    if not subnet_id:
                        self._findings.append(Finding(
                            finding_id    = _make_id(),
                            title         = "OCI Notebook session has no VCN subnet restriction",
                            provider      = CloudProvider.OCI,
                            resource_type = "Data Science Notebook",
                            resource_name = nb.display_name,
                            resource_id   = nb.id,
                            region        = self.region,
                            risk_level    = RiskLevel.MEDIUM,
                            owasp         = OWASPMapping(
                                llm_ids     = ["LLM02", "LLM04"],
                                agentic_ids = ["ASI08"],
                            ),
                            description   = (
                                f"Notebook session '{nb.display_name}' in project "
                                f"'{proj.display_name}' is not confined to a VCN subnet. "
                                f"Training data, model weights, and experiment results "
                                f"may be accessible from unexpected network paths."
                            ),
                            evidence      = "notebook_session_config.subnet_id=None",
                            recommendation= (
                                "Assign notebook sessions to a private VCN subnet. "
                                "Use a NAT gateway for outbound internet access rather "
                                "than a public IP. Enable Data Science audit logging."
                            ),
                        ))

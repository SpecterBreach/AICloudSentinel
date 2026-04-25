"""
scanners/aws_scanner.py
=======================
Scans AWS accounts for AI workload security misconfigurations:

  - S3 buckets holding model weights / training data (public ACL / policy)
  - Lambda functions with exposed LLM API keys in environment variables
  - IAM roles/policies granting excessive Bedrock / SageMaker permissions
  - EC2 instances (GPU) with IMDSv1 enabled running AI workloads
  - SageMaker notebook instances with direct internet access
  - Bedrock model invocation logging disabled
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

AI_S3_KEYWORDS  = ["model", "llm", "ai", "ml", "embedding", "vector",
                    "training", "dataset", "checkpoint", "weights", "rag",
                    "inference", "fine-tune", "finetune", "genai", "generative"]

AI_ENV_SECRETS  = ["openai_api_key", "anthropic_api_key", "cohere_api_key",
                    "huggingface_token", "replicate_api_token", "groq_api_key",
                    "together_api_key", "mistral_api_key", "gemini_api_key",
                    "llm_api_key", "ai_api_key", "model_api_key",
                    "openai_organization", "anthropic_base_url"]

OVERPRIVILEGED_ACTIONS = [
    "bedrock:*", "sagemaker:*", "s3:*",
    "*:*", "iam:*", "lambda:*",
]


def _is_ai_resource(name: str) -> bool:
    n = (name or "").lower()
    return any(kw in n for kw in AI_S3_KEYWORDS)


def _make_id() -> str:
    return f"AWS-{uuid.uuid4().hex[:8].upper()}"


class AWSScanner:
    """
    Scans an AWS account for AI workload security misconfigurations.

    Usage:
        scanner = AWSScanner(region="us-east-1", profile="default")
        result  = scanner.scan()
    """

    def __init__(self, region: str = "us-east-1", profile: str = "default",
                 account_id: str = ""):
        self.region     = region
        self.profile    = profile
        self.account_id = account_id
        self._findings: list[Finding] = []

    def scan(self) -> ScanResult:
        try:
            import boto3
            from botocore.exceptions import ClientError, NoCredentialsError
        except ImportError:
            raise RuntimeError("boto3 not installed. Run: pip install boto3")

        started = datetime.now(timezone.utc).isoformat()
        log.info("[AWS] Starting scan — region: %s", self.region)

        import boto3
        session = boto3.Session(profile_name=self.profile, region_name=self.region)

        self._scan_s3(session)
        self._scan_lambda(session)
        self._scan_iam_bedrock(session)
        self._scan_ec2_imds(session)
        self._scan_sagemaker(session)
        self._scan_bedrock_logging(session)

        result = ScanResult(
            scan_id      = f"AWS-SCAN-{uuid.uuid4().hex[:6].upper()}",
            provider     = CloudProvider.AWS,
            scope        = self.account_id or "current-account",
            started_at   = started,
            completed_at = datetime.now(timezone.utc).isoformat(),
            findings     = self._findings,
        )
        log.info("[AWS] Scan complete — %d findings", len(self._findings))
        return result

    # ── S3 ───────────────────────────────────────────────────────────────────

    def _scan_s3(self, session) -> None:
        log.info("[AWS] Scanning S3 buckets for AI model exposure...")
        s3 = session.client("s3")
        try:
            buckets = s3.list_buckets().get("Buckets", [])
        except Exception as exc:
            log.warning("[AWS] S3 list failed: %s", exc); return

        for b in buckets:
            name = b["Name"]
            if not _is_ai_resource(name):
                continue

            # Public access block check
            try:
                pub = s3.get_public_access_block(Bucket=name)
                cfg = pub["PublicAccessBlockConfiguration"]
                fully_blocked = all([
                    cfg.get("BlockPublicAcls", False),
                    cfg.get("IgnorePublicAcls", False),
                    cfg.get("BlockPublicPolicy", False),
                    cfg.get("RestrictPublicBuckets", False),
                ])
            except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
                fully_blocked = False
            except Exception:
                fully_blocked = True  # assume blocked if we can't check

            if not fully_blocked:
                self._findings.append(Finding(
                    finding_id    = _make_id(),
                    title         = "AI model S3 bucket missing full public access block",
                    provider      = CloudProvider.AWS,
                    resource_type = "S3 Bucket",
                    resource_name = name,
                    resource_id   = f"arn:aws:s3:::{name}",
                    region        = "global",
                    risk_level    = RiskLevel.CRITICAL,
                    owasp         = OWASPMapping(
                        llm_ids     = ["LLM02", "LLM04"],
                        agentic_ids = ["ASI08"],
                    ),
                    description   = (
                        f"S3 bucket '{name}' appears to store AI/ML assets but does not "
                        f"have all four public access block settings enabled. Model weights, "
                        f"training data, or vector embeddings could be publicly accessible."
                    ),
                    evidence      = f"PublicAccessBlockConfiguration={cfg if 'cfg' in dir() else 'missing'}",
                    recommendation= (
                        "Enable all four S3 Block Public Access settings at account and "
                        "bucket level. Use bucket policies with explicit Deny for public "
                        "access. Enable S3 server access logging and S3 Object Lambda "
                        "for access monitoring."
                    ),
                ))

            # Versioning check
            try:
                ver = s3.get_bucket_versioning(Bucket=name)
                versioning_on = ver.get("Status") == "Enabled"
            except Exception:
                versioning_on = False

            if not versioning_on:
                self._findings.append(Finding(
                    finding_id    = _make_id(),
                    title         = "AI model S3 bucket versioning disabled",
                    provider      = CloudProvider.AWS,
                    resource_type = "S3 Bucket",
                    resource_name = name,
                    resource_id   = f"arn:aws:s3:::{name}",
                    region        = "global",
                    risk_level    = RiskLevel.MEDIUM,
                    owasp         = OWASPMapping(
                        llm_ids     = ["LLM04"],
                        agentic_ids = ["ASI03"],
                    ),
                    description   = (
                        f"S3 bucket '{name}' stores AI/ML assets but versioning is disabled. "
                        f"Model poisoning attacks that overwrite checkpoint files leave no "
                        f"recovery path."
                    ),
                    evidence      = "versioning_status!=Enabled",
                    recommendation= (
                        "Enable S3 versioning and configure MFA Delete for production "
                        "model buckets. Use S3 Object Lock for immutable storage of "
                        "approved model versions."
                    ),
                ))

    # ── Lambda ───────────────────────────────────────────────────────────────

    def _scan_lambda(self, session) -> None:
        log.info("[AWS] Scanning Lambda for exposed LLM API keys...")
        lam = session.client("lambda")
        try:
            paginator = lam.get_paginator("list_functions")
            functions = []
            for page in paginator.paginate():
                functions.extend(page.get("Functions", []))
        except Exception as exc:
            log.warning("[AWS] Lambda list failed: %s", exc); return

        for fn in functions:
            name = fn["FunctionName"]
            if not _is_ai_resource(name):
                continue

            env_vars = fn.get("Environment", {}).get("Variables", {})
            exposed  = [k for k in env_vars if k.lower() in AI_ENV_SECRETS]

            if exposed:
                self._findings.append(Finding(
                    finding_id    = _make_id(),
                    title         = "LLM API key in Lambda environment variable (plaintext)",
                    provider      = CloudProvider.AWS,
                    resource_type = "Lambda Function",
                    resource_name = name,
                    resource_id   = fn["FunctionArn"],
                    region        = self.region,
                    risk_level    = RiskLevel.CRITICAL,
                    owasp         = OWASPMapping(
                        llm_ids     = ["LLM02", "LLM07"],
                        agentic_ids = ["ASI04"],
                    ),
                    description   = (
                        f"Lambda function '{name}' stores LLM provider credentials as "
                        f"plaintext environment variables: {', '.join(exposed)}. "
                        f"These are visible to anyone with lambda:GetFunction permission "
                        f"and logged in CloudTrail."
                    ),
                    evidence      = f"env_keys={exposed}",
                    recommendation= (
                        "Move secrets to AWS Secrets Manager or SSM Parameter Store "
                        "(SecureString). Reference via the Lambda execution role at "
                        "runtime. Rotate all exposed keys immediately. Enable Lambda "
                        "environment variable encryption with a customer-managed KMS key."
                    ),
                ))

    # ── IAM / Bedrock ────────────────────────────────────────────────────────

    def _scan_iam_bedrock(self, session) -> None:
        log.info("[AWS] Scanning IAM for over-privileged Bedrock/SageMaker roles...")
        iam = session.client("iam")
        try:
            paginator = iam.get_paginator("list_roles")
            roles = []
            for page in paginator.paginate():
                roles.extend(page.get("Roles", []))
        except Exception as exc:
            log.warning("[AWS] IAM scan failed: %s", exc); return

        for role in roles:
            rname = role["RoleName"]
            if not _is_ai_resource(rname) and "agent" not in rname.lower():
                continue

            try:
                attached = iam.list_attached_role_policies(RoleName=rname).get(
                    "AttachedPolicies", []
                )
            except Exception:
                continue

            for pol in attached:
                pname = pol["PolicyName"]
                if "FullAccess" in pname and any(
                    svc in pname for svc in ["Bedrock", "SageMaker", "S3", "AdministratorAccess"]
                ):
                    self._findings.append(Finding(
                        finding_id    = _make_id(),
                        title         = f"AI agent IAM role has overly broad policy: {pname}",
                        provider      = CloudProvider.AWS,
                        resource_type = "IAM Role",
                        resource_name = rname,
                        resource_id   = role["Arn"],
                        region        = "global",
                        risk_level    = RiskLevel.HIGH,
                        owasp         = OWASPMapping(
                            llm_ids     = ["LLM06"],
                            agentic_ids = ["ASI02", "ASI04"],
                        ),
                        description   = (
                            f"IAM role '{rname}' used by an AI workload has the managed "
                            f"policy '{pname}' attached, granting broad permissions. "
                            f"A compromised agent or prompt injection could abuse these "
                            f"permissions to exfiltrate data or modify AWS resources."
                        ),
                        evidence      = f"attached_policy={pname}  role_arn={role['Arn']}",
                        recommendation= (
                            "Replace FullAccess policies with custom least-privilege "
                            "policies scoped to specific resources and actions. Use "
                            "IAM Access Analyzer to identify unused permissions. "
                            "Enable AWS CloudTrail for all Bedrock/SageMaker API calls."
                        ),
                    ))

    # ── EC2 IMDS ─────────────────────────────────────────────────────────────

    def _scan_ec2_imds(self, session) -> None:
        log.info("[AWS] Scanning EC2 GPU instances for IMDSv1...")
        ec2 = session.client("ec2")
        try:
            paginator = ec2.get_paginator("describe_instances")
            instances = []
            for page in paginator.paginate(
                Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
            ):
                for r in page.get("Reservations", []):
                    instances.extend(r.get("Instances", []))
        except Exception as exc:
            log.warning("[AWS] EC2 scan failed: %s", exc); return

        for inst in instances:
            itype = inst.get("InstanceType", "")
            name  = next(
                (t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"),
                inst["InstanceId"],
            )
            is_gpu = any(g in itype for g in ["p3", "p4", "p5", "g4", "g5", "inf1", "inf2", "trn1"])
            if not is_gpu and not _is_ai_resource(name):
                continue

            meta = inst.get("MetadataOptions", {})
            if meta.get("HttpTokens") != "required":
                self._findings.append(Finding(
                    finding_id    = _make_id(),
                    title         = "AI/GPU EC2 instance has IMDSv1 enabled (unauthenticated)",
                    provider      = CloudProvider.AWS,
                    resource_type = "EC2 Instance",
                    resource_name = name,
                    resource_id   = inst["InstanceId"],
                    region        = self.region,
                    risk_level    = RiskLevel.HIGH,
                    owasp         = OWASPMapping(
                        llm_ids     = ["LLM02"],
                        agentic_ids = ["ASI04", "ASI08"],
                    ),
                    description   = (
                        f"EC2 instance '{name}' ({itype}) appears to run AI workloads "
                        f"and has IMDSv1 enabled (HttpTokens!=required). SSRF via a "
                        f"vulnerable AI web endpoint or prompt injection causing an "
                        f"HTTP request can reach http://169.254.169.254 and steal IAM "
                        f"instance credentials without any token."
                    ),
                    evidence      = f"HttpTokens={meta.get('HttpTokens')}  InstanceType={itype}",
                    recommendation= (
                        "Set HttpTokens=required (IMDSv2) via instance metadata options. "
                        "Apply at account level with an SCP: require IMDSv2 for all new "
                        "instances. Use AWS Config rule ec2-imdsv2-check for detection."
                    ),
                ))

    # ── SageMaker ────────────────────────────────────────────────────────────

    def _scan_sagemaker(self, session) -> None:
        log.info("[AWS] Scanning SageMaker notebook instances...")
        sm = session.client("sagemaker")
        try:
            paginator = sm.get_paginator("list_notebook_instances")
            notebooks = []
            for page in paginator.paginate():
                notebooks.extend(page.get("NotebookInstances", []))
        except Exception as exc:
            log.warning("[AWS] SageMaker scan failed: %s", exc); return

        for nb in notebooks:
            if nb.get("NotebookInstanceStatus") not in ("InService", "Pending"):
                continue
            if nb.get("DirectInternetAccess") == "Enabled":
                self._findings.append(Finding(
                    finding_id    = _make_id(),
                    title         = "SageMaker notebook has direct internet access enabled",
                    provider      = CloudProvider.AWS,
                    resource_type = "SageMaker Notebook",
                    resource_name = nb["NotebookInstanceName"],
                    resource_id   = nb["NotebookInstanceArn"],
                    region        = self.region,
                    risk_level    = RiskLevel.HIGH,
                    owasp         = OWASPMapping(
                        llm_ids     = ["LLM02", "LLM04"],
                        agentic_ids = ["ASI08"],
                    ),
                    description   = (
                        f"SageMaker notebook '{nb['NotebookInstanceName']}' has "
                        f"DirectInternetAccess=Enabled. Training data and model "
                        f"artefacts can be exfiltrated directly to the internet "
                        f"without passing through VPC controls."
                    ),
                    evidence      = "DirectInternetAccess=Enabled",
                    recommendation= (
                        "Set DirectInternetAccess=Disabled and route traffic via a "
                        "VPC with a NAT gateway. Apply security groups that restrict "
                        "outbound access to required endpoints only."
                    ),
                ))

    # ── Bedrock logging ──────────────────────────────────────────────────────

    def _scan_bedrock_logging(self, session) -> None:
        log.info("[AWS] Checking Bedrock model invocation logging...")
        try:
            bedrock = session.client("bedrock")
            cfg     = bedrock.get_model_invocation_logging_configuration()
            lc      = cfg.get("loggingConfig", {})
            enabled = lc.get("cloudWatchConfig", {}).get("logGroupName") or \
                      lc.get("s3Config", {}).get("bucketName")
        except Exception as exc:
            log.warning("[AWS] Bedrock logging check failed: %s", exc); return

        if not enabled:
            self._findings.append(Finding(
                finding_id    = _make_id(),
                title         = "AWS Bedrock model invocation logging is disabled",
                provider      = CloudProvider.AWS,
                resource_type = "Bedrock Configuration",
                resource_name = "model-invocation-logging",
                resource_id   = f"aws:bedrock:{self.region}:logging",
                region        = self.region,
                risk_level    = RiskLevel.MEDIUM,
                owasp         = OWASPMapping(
                    llm_ids     = ["LLM02", "LLM07"],
                    agentic_ids = ["ASI08", "ASI09"],
                ),
                description   = (
                    "AWS Bedrock model invocation logging is not configured. Without "
                    "logging, prompt injection attacks, data exfiltration via model "
                    "outputs, and abuse of Bedrock APIs cannot be detected or audited."
                ),
                evidence      = "loggingConfig has no CloudWatch or S3 destination",
                recommendation= (
                    "Enable Bedrock model invocation logging to CloudWatch Logs or S3. "
                    "Set up CloudWatch metric filters to alert on anomalous invocation "
                    "volumes or unusual output patterns. Retain logs for at least 90 days."
                ),
            ))

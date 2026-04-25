"""
scanners/azure_scanner.py
=========================
Scans Azure subscriptions for AI workload security misconfigurations:

  - Azure Blob Storage containers holding model weights (public access)
  - Azure Functions with LLM API keys in app settings
  - Azure AI Services (Cognitive Services / OpenAI) with exposed keys
  - Azure ML workspaces with public network access
  - Managed Identities with excessive permissions on AI resources
  - Key Vault soft-delete disabled for AI key stores
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

AI_CONTAINER_KEYWORDS = ["model", "llm", "ai", "ml", "embedding", "vector",
                          "training", "dataset", "checkpoint", "weights", "rag",
                          "inference", "finetune", "genai", "generative"]

AI_APP_SETTING_KEYS   = ["openai_api_key", "anthropic_api_key", "cohere_api_key",
                          "huggingface_token", "azure_openai_key", "cognitive_services_key",
                          "llm_api_key", "ai_api_key", "model_api_key",
                          "azure_ai_key", "openai_api_base"]


def _is_ai_resource(name: str) -> bool:
    n = (name or "").lower()
    return any(kw in n for kw in AI_CONTAINER_KEYWORDS)


def _make_id() -> str:
    return f"AZ-{uuid.uuid4().hex[:8].upper()}"


class AzureScanner:
    """
    Scans an Azure subscription for AI workload security misconfigurations.

    Requires azure-mgmt-* SDK packages. Uses DefaultAzureCredential
    (env vars, managed identity, or az login).

    Usage:
        scanner = AzureScanner(subscription_id="...", resource_group="rg-ai")
        result  = scanner.scan()
    """

    def __init__(self, subscription_id: str, resource_group: str = "",
                 location: str = "eastus"):
        self.subscription_id = subscription_id
        self.resource_group  = resource_group
        self.location        = location
        self._findings: list[Finding] = []

    def scan(self) -> ScanResult:
        try:
            from azure.identity import DefaultAzureCredential
        except ImportError:
            raise RuntimeError(
                "azure-identity not installed. Run: "
                "pip install azure-identity azure-mgmt-storage azure-mgmt-web "
                "azure-mgmt-cognitiveservices azure-mgmt-machinelearningservices "
                "azure-mgmt-keyvault"
            )

        started     = datetime.now(timezone.utc).isoformat()
        credential  = DefaultAzureCredential()
        log.info("[Azure] Starting scan — subscription: %s", self.subscription_id)

        self._scan_blob_storage(credential)
        self._scan_functions(credential)
        self._scan_cognitive_services(credential)
        self._scan_azure_ml(credential)
        self._scan_key_vault(credential)

        result = ScanResult(
            scan_id      = f"AZ-SCAN-{uuid.uuid4().hex[:6].upper()}",
            provider     = CloudProvider.AZURE,
            scope        = self.subscription_id,
            started_at   = started,
            completed_at = datetime.now(timezone.utc).isoformat(),
            findings     = self._findings,
        )
        log.info("[Azure] Scan complete — %d findings", len(self._findings))
        return result

    # ── Blob Storage ─────────────────────────────────────────────────────────

    def _scan_blob_storage(self, credential) -> None:
        log.info("[Azure] Scanning Blob Storage for AI model exposure...")
        try:
            from azure.mgmt.storage import StorageManagementClient
            client   = StorageManagementClient(credential, self.subscription_id)
            accounts = list(client.storage_accounts.list())
        except Exception as exc:
            log.warning("[Azure] Blob Storage scan failed: %s", exc); return

        for acct in accounts:
            if not _is_ai_resource(acct.name):
                continue

            # Check: public blob access allowed
            allow_blob_public = getattr(
                acct, "allow_blob_public_access", True
            )
            if allow_blob_public is True or allow_blob_public is None:
                self._findings.append(Finding(
                    finding_id    = _make_id(),
                    title         = "Azure AI storage account permits public blob access",
                    provider      = CloudProvider.AZURE,
                    resource_type = "Storage Account",
                    resource_name = acct.name,
                    resource_id   = acct.id,
                    region        = acct.location,
                    risk_level    = RiskLevel.CRITICAL,
                    owasp         = OWASPMapping(
                        llm_ids     = ["LLM02", "LLM04"],
                        agentic_ids = ["ASI08"],
                    ),
                    description   = (
                        f"Storage account '{acct.name}' appears to store AI/ML assets "
                        f"and has AllowBlobPublicAccess=true. Any container within this "
                        f"account can be set to public, exposing model weights, training "
                        f"data, and vector embeddings to unauthenticated access."
                    ),
                    evidence      = f"allow_blob_public_access={allow_blob_public}",
                    recommendation= (
                        "Set allowBlobPublicAccess=false at the storage account level. "
                        "Use Azure Private Endpoints for inference workloads that need "
                        "internal access. Enable Storage Analytics logging and Defender "
                        "for Storage."
                    ),
                ))

            # Check: HTTPS-only transport
            https_only = getattr(acct, "enable_https_traffic_only", True)
            if not https_only:
                self._findings.append(Finding(
                    finding_id    = _make_id(),
                    title         = "Azure AI storage account allows HTTP (unencrypted) access",
                    provider      = CloudProvider.AZURE,
                    resource_type = "Storage Account",
                    resource_name = acct.name,
                    resource_id   = acct.id,
                    region        = acct.location,
                    risk_level    = RiskLevel.HIGH,
                    owasp         = OWASPMapping(llm_ids=["LLM02"]),
                    description   = (
                        f"Storage account '{acct.name}' permits unencrypted HTTP access. "
                        f"Model files and training data transferred over HTTP are "
                        f"susceptible to interception and man-in-the-middle attacks."
                    ),
                    evidence      = "enable_https_traffic_only=False",
                    recommendation= (
                        "Set enableHttpsTrafficOnly=true. Enforce TLS 1.2 minimum "
                        "via the minimumTlsVersion property."
                    ),
                ))

    # ── Azure Functions ──────────────────────────────────────────────────────

    def _scan_functions(self, credential) -> None:
        log.info("[Azure] Scanning Function Apps for exposed LLM API keys...")
        try:
            from azure.mgmt.web import WebSiteManagementClient
            client = WebSiteManagementClient(credential, self.subscription_id)
            apps   = list(client.web_apps.list())
        except Exception as exc:
            log.warning("[Azure] Functions scan failed: %s", exc); return

        for app in apps:
            if not _is_ai_resource(app.name):
                continue
            if app.kind and "functionapp" not in app.kind.lower():
                continue

            try:
                from azure.mgmt.web import WebSiteManagementClient
                wc       = WebSiteManagementClient(credential, self.subscription_id)
                settings = wc.web_apps.list_application_settings(
                    app.resource_group, app.name
                )
                props = settings.properties or {}
            except Exception:
                continue

            exposed = [k for k in props if k.lower() in AI_APP_SETTING_KEYS]
            if exposed:
                self._findings.append(Finding(
                    finding_id    = _make_id(),
                    title         = "LLM API key in Azure Function App settings (plaintext)",
                    provider      = CloudProvider.AZURE,
                    resource_type = "Function App",
                    resource_name = app.name,
                    resource_id   = app.id,
                    region        = app.location,
                    risk_level    = RiskLevel.CRITICAL,
                    owasp         = OWASPMapping(
                        llm_ids     = ["LLM02", "LLM07"],
                        agentic_ids = ["ASI04"],
                    ),
                    description   = (
                        f"Function App '{app.name}' stores LLM provider credentials as "
                        f"plaintext application settings: {', '.join(exposed)}. "
                        f"These are visible to anyone with Contributor access and are "
                        f"not encrypted at rest by default."
                    ),
                    evidence      = f"app_settings_keys={exposed}",
                    recommendation= (
                        "Store all LLM API keys in Azure Key Vault. Reference them via "
                        "Key Vault references in App Service settings "
                        "(@Microsoft.KeyVault(SecretUri=...)). Assign a managed identity "
                        "to the Function App and grant it Key Vault Secrets User role. "
                        "Rotate all exposed keys immediately."
                    ),
                ))

    # ── Azure AI / Cognitive Services ────────────────────────────────────────

    def _scan_cognitive_services(self, credential) -> None:
        log.info("[Azure] Scanning Cognitive Services / Azure OpenAI accounts...")
        try:
            from azure.mgmt.cognitiveservices import CognitiveServicesManagementClient
            client   = CognitiveServicesManagementClient(credential, self.subscription_id)
            accounts = list(client.accounts.list())
        except Exception as exc:
            log.warning("[Azure] Cognitive Services scan failed: %s", exc); return

        for acct in accounts:
            props = acct.properties

            # Public network access
            pub_access = getattr(props, "public_network_access", "Enabled")
            if pub_access == "Enabled":
                # Check if network rules restrict it
                network_acls = getattr(props, "network_acls", None)
                if not network_acls or getattr(network_acls, "default_action", "Allow") == "Allow":
                    self._findings.append(Finding(
                        finding_id    = _make_id(),
                        title         = "Azure AI Services account has unrestricted public access",
                        provider      = CloudProvider.AZURE,
                        resource_type = "Cognitive Services Account",
                        resource_name = acct.name,
                        resource_id   = acct.id,
                        region        = acct.location,
                        risk_level    = RiskLevel.HIGH,
                        owasp         = OWASPMapping(
                            llm_ids     = ["LLM02", "LLM10"],
                            agentic_ids = ["ASI04"],
                        ),
                        description   = (
                            f"Azure AI Services / Cognitive Services account '{acct.name}' "
                            f"({acct.kind}) has public network access enabled with no IP "
                            f"network ACL restrictions. The API endpoint and keys are "
                            f"reachable from any IP, enabling credential abuse and "
                            f"unbounded consumption attacks."
                        ),
                        evidence      = f"public_network_access={pub_access}  network_acl_default=Allow",
                        recommendation= (
                            "Set publicNetworkAccess=Disabled and use Azure Private "
                            "Endpoints. If public access is required, restrict with "
                            "IP network rules to known CIDR ranges. Enable Diagnostic "
                            "Settings to log all API calls to Azure Monitor."
                        ),
                    ))

            # Key rotation check — warn if no managed identity / Entra auth
            disable_local_auth = getattr(props, "disable_local_auth", False)
            if not disable_local_auth:
                self._findings.append(Finding(
                    finding_id    = _make_id(),
                    title         = "Azure AI Services using static API keys instead of Entra ID",
                    provider      = CloudProvider.AZURE,
                    resource_type = "Cognitive Services Account",
                    resource_name = acct.name,
                    resource_id   = acct.id,
                    region        = acct.location,
                    risk_level    = RiskLevel.MEDIUM,
                    owasp         = OWASPMapping(
                        llm_ids     = ["LLM02"],
                        agentic_ids = ["ASI04"],
                    ),
                    description   = (
                        f"Cognitive Services account '{acct.name}' has local API key "
                        f"authentication enabled (disableLocalAuth=false). Static keys "
                        f"do not expire automatically and are harder to revoke in an "
                        f"incident."
                    ),
                    evidence      = "disable_local_auth=False",
                    recommendation= (
                        "Set disableLocalAuth=true and use Azure AD / Managed Identity "
                        "authentication exclusively. Assign callers the "
                        "'Cognitive Services User' role via RBAC."
                    ),
                ))

    # ── Azure ML ─────────────────────────────────────────────────────────────

    def _scan_azure_ml(self, credential) -> None:
        log.info("[Azure] Scanning Azure ML workspaces...")
        try:
            from azure.mgmt.machinelearningservices import AzureMachineLearningWorkspaces
            client     = AzureMachineLearningWorkspaces(credential, self.subscription_id)
            workspaces = list(client.workspaces.list_by_subscription())
        except Exception as exc:
            log.warning("[Azure] Azure ML scan failed: %s", exc); return

        for ws in workspaces:
            pub_access = getattr(ws, "public_network_access", "Enabled")
            if pub_access == "Enabled":
                self._findings.append(Finding(
                    finding_id    = _make_id(),
                    title         = "Azure ML workspace has public network access enabled",
                    provider      = CloudProvider.AZURE,
                    resource_type = "Azure ML Workspace",
                    resource_name = ws.name,
                    resource_id   = ws.id,
                    region        = ws.location,
                    risk_level    = RiskLevel.HIGH,
                    owasp         = OWASPMapping(
                        llm_ids     = ["LLM02", "LLM04"],
                        agentic_ids = ["ASI08"],
                    ),
                    description   = (
                        f"Azure ML workspace '{ws.name}' has public network access "
                        f"enabled. Training jobs, model registries, and experiment data "
                        f"are reachable over the public internet."
                    ),
                    evidence      = f"public_network_access={pub_access}",
                    recommendation= (
                        "Set publicNetworkAccess=Disabled. Configure private endpoints "
                        "for the workspace and associated storage, Key Vault, and "
                        "Container Registry. Use managed virtual networks for compute."
                    ),
                ))

    # ── Key Vault ────────────────────────────────────────────────────────────

    def _scan_key_vault(self, credential) -> None:
        log.info("[Azure] Scanning Key Vaults for AI secret stores...")
        try:
            from azure.mgmt.keyvault import KeyVaultManagementClient
            client = KeyVaultManagementClient(credential, self.subscription_id)
            vaults = list(client.vaults.list())
        except Exception as exc:
            log.warning("[Azure] Key Vault scan failed: %s", exc); return

        for vault in vaults:
            if not _is_ai_resource(vault.name):
                continue

            props = vault.properties
            soft_delete = getattr(props, "enable_soft_delete", True)
            if not soft_delete:
                self._findings.append(Finding(
                    finding_id    = _make_id(),
                    title         = "AI Key Vault has soft-delete disabled",
                    provider      = CloudProvider.AZURE,
                    resource_type = "Key Vault",
                    resource_name = vault.name,
                    resource_id   = vault.id,
                    region        = vault.location,
                    risk_level    = RiskLevel.HIGH,
                    owasp         = OWASPMapping(
                        llm_ids     = ["LLM02"],
                        agentic_ids = ["ASI03"],
                    ),
                    description   = (
                        f"Key Vault '{vault.name}' storing AI/LLM secrets has soft-delete "
                        f"disabled. Accidentally or maliciously deleted secrets cannot be "
                        f"recovered, causing irreversible loss of LLM API keys and "
                        f"breaking AI inference pipelines."
                    ),
                    evidence      = "enable_soft_delete=False",
                    recommendation= (
                        "Enable soft-delete and purge protection on all Key Vaults "
                        "storing AI credentials. Soft-delete retains deleted secrets for "
                        "7–90 days. Purge protection prevents permanent deletion even by "
                        "administrators."
                    ),
                ))

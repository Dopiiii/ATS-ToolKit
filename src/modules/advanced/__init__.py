"""Advanced modules for ATS-Toolkit (2026 features)."""

from .cloud_s3_scanner import CloudS3ScannerModule
from .cloud_iam_analyzer import CloudIamAnalyzerModule
from .cloud_metadata_exploit import CloudMetadataExploitModule
from .cloud_container_scanner import CloudContainerScannerModule
from .cloud_serverless_audit import CloudServerlessAuditModule
from .cloud_storage_enum import CloudStorageEnumModule
from .cloud_network_mapper import CloudNetworkMapperModule
from .cloud_secrets_scanner import CloudSecretsScannerModule
from .cloud_compliance_audit import CloudComplianceAuditModule
from .cloud_cost_attack import CloudCostAttackModule
from .web3_contract_analyzer import Web3ContractAnalyzerModule
from .web3_wallet_tracker import Web3WalletTrackerModule
from .web3_defi_scanner import Web3DefiScannerModule
from .web3_nft_analyzer import Web3NftAnalyzerModule
from .web3_token_auditor import Web3TokenAuditorModule
from .web3_bridge_scanner import Web3BridgeScannerModule
from .web3_governance_audit import Web3GovernanceAuditModule
from .web3_phishing_detector import Web3PhishingDetectorModule

__all__ = [
    "CloudS3ScannerModule",
    "CloudIamAnalyzerModule",
    "CloudMetadataExploitModule",
    "CloudContainerScannerModule",
    "CloudServerlessAuditModule",
    "CloudStorageEnumModule",
    "CloudNetworkMapperModule",
    "CloudSecretsScannerModule",
    "CloudComplianceAuditModule",
    "CloudCostAttackModule",
    "Web3ContractAnalyzerModule",
    "Web3WalletTrackerModule",
    "Web3DefiScannerModule",
    "Web3NftAnalyzerModule",
    "Web3TokenAuditorModule",
    "Web3BridgeScannerModule",
    "Web3GovernanceAuditModule",
    "Web3PhishingDetectorModule",
]

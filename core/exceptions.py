#!/usr/bin/env python3
"""
ATS-Toolkit - Custom Exceptions
Specialized exception classes for better error handling

⚠️ EDUCATIONAL USE ONLY - AUTHORIZED SYSTEMS ONLY ⚠️
"""


class ATSToolkitError(Exception):
    """Base exception for all ATS-Toolkit errors"""
    pass


# ============================================================================
# LEGAL & CONSENT ERRORS
# ============================================================================

class LegalError(ATSToolkitError):
    """Base class for legal/consent related errors"""
    pass


class ConsentNotGivenError(LegalError):
    """Raised when user has not accepted legal disclaimer"""
    def __init__(self, message="Legal disclaimer not accepted. Run with --accept-legal first."):
        self.message = message
        super().__init__(self.message)


class InvalidConsentHashError(LegalError):
    """Raised when consent hash is invalid or expired"""
    def __init__(self, consent_hash: str):
        self.consent_hash = consent_hash
        self.message = f"Invalid or expired consent hash: {consent_hash}"
        super().__init__(self.message)


class UnauthorizedTargetError(LegalError):
    """Raised when target is not authorized for scanning"""
    def __init__(self, target: str):
        self.target = target
        self.message = f"Target '{target}' is not authorized. Obtain written permission first."
        super().__init__(self.message)


# ============================================================================
# MODULE ERRORS
# ============================================================================

class ModuleError(ATSToolkitError):
    """Base class for module-related errors"""
    pass


class ModuleNotFoundError(ModuleError):
    """Raised when requested module doesn't exist"""
    def __init__(self, module_name: str):
        self.module_name = module_name
        self.message = f"Module '{module_name}' not found. Check available modules with --list-modules"
        super().__init__(self.message)


class ModuleExecutionError(ModuleError):
    """Raised when module execution fails"""
    def __init__(self, module_name: str, reason: str):
        self.module_name = module_name
        self.reason = reason
        self.message = f"Module '{module_name}' execution failed: {reason}"
        super().__init__(self.message)


class ModuleDependencyError(ModuleError):
    """Raised when module dependencies are not met"""
    def __init__(self, module_name: str, missing_deps: list):
        self.module_name = module_name
        self.missing_deps = missing_deps
        self.message = f"Module '{module_name}' requires: {', '.join(missing_deps)}"
        super().__init__(self.message)


# ============================================================================
# VALIDATION ERRORS
# ============================================================================

class ValidationError(ATSToolkitError):
    """Base class for validation errors"""
    pass


class InvalidTargetError(ValidationError):
    """Raised when target format is invalid"""
    def __init__(self, target: str, expected_format: str):
        self.target = target
        self.expected_format = expected_format
        self.message = f"Invalid target '{target}'. Expected format: {expected_format}"
        super().__init__(self.message)


class InvalidConfigError(ValidationError):
    """Raised when configuration is invalid"""
    def __init__(self, config_file: str, reason: str):
        self.config_file = config_file
        self.reason = reason
        self.message = f"Invalid config file '{config_file}': {reason}"
        super().__init__(self.message)


# ============================================================================
# PIPELINE ERRORS
# ============================================================================

class PipelineError(ATSToolkitError):
    """Base class for pipeline execution errors"""
    pass


class PipelineNotFoundError(PipelineError):
    """Raised when pipeline configuration not found"""
    def __init__(self, pipeline_name: str):
        self.pipeline_name = pipeline_name
        self.message = f"Pipeline '{pipeline_name}' not found in config/"
        super().__init__(self.message)


class PipelineExecutionError(PipelineError):
    """Raised when pipeline execution fails"""
    def __init__(self, pipeline_name: str, stage: str, reason: str):
        self.pipeline_name = pipeline_name
        self.stage = stage
        self.reason = reason
        self.message = f"Pipeline '{pipeline_name}' failed at stage '{stage}': {reason}"
        super().__init__(self.message)


# ============================================================================
# CACHE ERRORS
# ============================================================================

class CacheError(ATSToolkitError):
    """Base class for cache-related errors"""
    pass


class CacheCorruptedError(CacheError):
    """Raised when cache database is corrupted"""
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.message = f"Cache database corrupted: {db_path}. Run --clear-cache to rebuild."
        super().__init__(self.message)


class CacheEncryptionError(CacheError):
    """Raised when cache encryption/decryption fails"""
    def __init__(self, reason: str):
        self.reason = reason
        self.message = f"Cache encryption error: {reason}"
        super().__init__(self.message)


# ============================================================================
# API ERRORS
# ============================================================================

class APIError(ATSToolkitError):
    """Base class for API-related errors"""
    pass


class APIKeyMissingError(APIError):
    """Raised when API key is not configured"""
    def __init__(self, service: str):
        self.service = service
        self.message = f"API key for '{service}' not found. Configure in config/api_keys.env"
        super().__init__(self.message)


class APIRateLimitError(APIError):
    """Raised when API rate limit is exceeded"""
    def __init__(self, service: str, retry_after: int = None):
        self.service = service
        self.retry_after = retry_after
        msg = f"API rate limit exceeded for '{service}'"
        if retry_after:
            msg += f". Retry after {retry_after} seconds."
        self.message = msg
        super().__init__(self.message)


class APIAuthenticationError(APIError):
    """Raised when API authentication fails"""
    def __init__(self, service: str):
        self.service = service
        self.message = f"API authentication failed for '{service}'. Check API key validity."
        super().__init__(self.message)


# ============================================================================
# NETWORK ERRORS
# ============================================================================

class NetworkError(ATSToolkitError):
    """Base class for network-related errors"""
    pass


class ConnectionError(NetworkError):
    """Raised when connection to target fails"""
    def __init__(self, target: str, reason: str):
        self.target = target
        self.reason = reason
        self.message = f"Connection to '{target}' failed: {reason}"
        super().__init__(self.message)


class TimeoutError(NetworkError):
    """Raised when operation times out"""
    def __init__(self, operation: str, timeout: int):
        self.operation = operation
        self.timeout = timeout
        self.message = f"Operation '{operation}' timed out after {timeout} seconds"
        super().__init__(self.message)


class DNSResolutionError(NetworkError):
    """Raised when DNS resolution fails"""
    def __init__(self, domain: str):
        self.domain = domain
        self.message = f"DNS resolution failed for domain: {domain}"
        super().__init__(self.message)


# ============================================================================
# REPORT ERRORS
# ============================================================================

class ReportError(ATSToolkitError):
    """Base class for report generation errors"""
    pass


class ReportGenerationError(ReportError):
    """Raised when report generation fails"""
    def __init__(self, format: str, reason: str):
        self.format = format
        self.reason = reason
        self.message = f"Failed to generate {format} report: {reason}"
        super().__init__(self.message)


class InvalidReportFormatError(ReportError):
    """Raised when report format is not supported"""
    def __init__(self, format: str, supported: list):
        self.format = format
        self.supported = supported
        self.message = f"Unsupported report format '{format}'. Supported: {', '.join(supported)}"
        super().__init__(self.message)


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def handle_exception(exception: Exception, debug: bool = False):
    """
    Handle exception with appropriate error message.
    
    Args:
        exception: Exception instance
        debug: Show full traceback if True
    """
    from core.utils import print_error, print_warning
    import traceback
    
    if isinstance(exception, ConsentNotGivenError):
        print_error("❌ LEGAL CONSENT REQUIRED")
        print_warning("Run with --accept-legal to accept terms and conditions")
        
    elif isinstance(exception, ModuleNotFoundError):
        print_error(f"❌ {exception.message}")
        print_warning("Use --list-modules to see available modules")
        
    elif isinstance(exception, APIKeyMissingError):
        print_error(f"❌ {exception.message}")
        print_warning(f"Get API key from the service website and add to config/api_keys.env")
        
    elif isinstance(exception, ATSToolkitError):
        print_error(f"❌ {exception.message}")
        
    else:
        print_error(f"❌ Unexpected error: {str(exception)}")
        
    if debug:
        print("\n--- Full Traceback ---")
        traceback.print_exc()


# ============================================================================
# TESTING
# ============================================================================

if __name__ == "__main__":
    # Demo/test exceptions
    print("Testing ATS-Toolkit Custom Exceptions\n")
    
    # Test legal errors
    try:
        raise ConsentNotGivenError()
    except ATSToolkitError as e:
        print(f"✓ Legal Error: {e}")
    
    # Test module errors
    try:
        raise ModuleNotFoundError("nonexistent_module")
    except ATSToolkitError as e:
        print(f"✓ Module Error: {e}")
    
    # Test validation errors
    try:
        raise InvalidTargetError("invalid..domain", "valid.domain.com")
    except ATSToolkitError as e:
        print(f"✓ Validation Error: {e}")
    
    # Test API errors
    try:
        raise APIKeyMissingError("shodan")
    except ATSToolkitError as e:
        print(f"✓ API Error: {e}")
    
    print("\n✅ All exception tests passed!")
CORE_INIT = '''#!/usr/bin/env python3
"""
ATS-Toolkit - Core Engine Package
Central components for consent, caching, and pipeline management

⚠️ EDUCATIONAL USE ONLY - AUTHORIZED SYSTEMS ONLY ⚠️
"""

__version__ = "2.0.0-alpha"
__author__ = "Eric - Strasbourg, France"
__phase__ = "Phase 1: Core Engine + First Module"

# Import main classes for easy access
from .consent_manager import ConsentManager
from .cache_manager import CacheManager
from .utils import (
    print_banner, print_success, print_error, print_info, print_warning,
    is_valid_domain, is_valid_ip, is_valid_email, is_valid_url,
    generate_hash, get_timestamp
)
from .exceptions import (
    ATSToolkitError,
    ConsentNotGivenError,
    InvalidConsentHashError,
    ModuleNotFoundError,
    ModuleExecutionError,
    InvalidTargetError,
    handle_exception
)

__all__ = [
    # Managers
    'ConsentManager',
    'CacheManager',
    
    # Utils
    'print_banner',
    'print_success',
    'print_error',
    'print_info',
    'print_warning',
    'is_valid_domain',
    'is_valid_ip',
    'is_valid_email',
    'is_valid_url',
    'generate_hash',
    'get_timestamp',
    
    # Exceptions
    'ATSToolkitError',
    'ConsentNotGivenError',
    'InvalidConsentHashError',
    'ModuleNotFoundError',
    'ModuleExecutionError',
    'InvalidTargetError',
    'handle_exception',
]
'''
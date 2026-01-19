#!/usr/bin/env python3
"""
ATS-Toolkit - Core Engine Package
Central components for consent, caching, and pipeline management

Educational platform for authorized cybersecurity professionals.
"""

__version__ = "2.0.0-alpha"
__author__ = "ATS Team"
__phase__ = "Phase 1: Core Architecture + Module System"

# Import main classes for easy access
from .consent_manager import ConsentManager
from .cache_manager import CacheManager
from .module_registry import ModuleRegistry, ModuleInfo, ModuleStatus
from .pipeline_engine import PipelineEngine, ModuleResult, PipelineResult
from .utils import (
    print_banner, print_success, print_error, print_info, print_warning,
    print_section, is_valid_domain, is_valid_ip, is_valid_email, is_valid_url,
    generate_hash, get_timestamp
)
from .exceptions import (
    ATSToolkitError,
    ConsentNotGivenError,
    InvalidConsentHashError,
    ModuleNotFoundError,
    ModuleExecutionError,
    ModuleLoadError,
    InvalidTargetError,
    PipelineExecutionError,
    handle_exception
)

__all__ = [
    # Version
    '__version__',
    '__author__',
    '__phase__',

    # Managers
    'ConsentManager',
    'CacheManager',
    'ModuleRegistry',
    'PipelineEngine',

    # Data classes
    'ModuleInfo',
    'ModuleStatus',
    'ModuleResult',
    'PipelineResult',

    # Utils
    'print_banner',
    'print_success',
    'print_error',
    'print_info',
    'print_warning',
    'print_section',
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
    'ModuleLoadError',
    'InvalidTargetError',
    'PipelineExecutionError',
    'handle_exception',
]

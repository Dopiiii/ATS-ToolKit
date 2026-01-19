LEGAL_INIT = '''#!/usr/bin/env python3
"""
ATS-Toolkit - Legal Package
Legal disclaimer and consent management

⚠️ EDUCATIONAL USE ONLY - AUTHORIZED SYSTEMS ONLY ⚠️
"""

from .disclaimer import (
    LegalDisclaimer,
    show_disclaimer,
    check_acceptance_log
)

__all__ = [
    'LegalDisclaimer',
    'show_disclaimer',
    'check_acceptance_log',
]
'''
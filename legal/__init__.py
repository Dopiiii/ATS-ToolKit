#!/usr/bin/env python3
"""
ATS-Toolkit - Legal Package
Legal disclaimer and consent management

Educational platform for authorized cybersecurity professionals.
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

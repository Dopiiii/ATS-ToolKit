OSINT_INIT = '''#!/usr/bin/env python3
"""
ATS-Toolkit - OSINT Package
Open Source Intelligence gathering modules

⚠️ EDUCATIONAL USE ONLY - AUTHORIZED SYSTEMS ONLY ⚠️
"""

__category__ = "osint"
__description__ = "Open Source Intelligence Gathering"
__modules_count__ = 1  # Phase 1: whois_lookup

# Module registry
MODULES = {
    'whois_lookup': {
        'name': 'WHOIS Lookup',
        'description': 'Domain registration information',
        'requires': [],
        'status': 'active',
        'phase': 1
    }
}

__all__ = [
    'MODULES',
]
'''
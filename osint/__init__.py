#!/usr/bin/env python3
"""
ATS-Toolkit - OSINT Package
Open Source Intelligence gathering modules

Educational platform for authorized cybersecurity professionals.
"""

__category__ = "osint"
__description__ = "Open Source Intelligence Gathering"

# Module registry - dynamically updated by ModuleRegistry
MODULES = {
    'dns_enum': {
        'name': 'DNS Enumeration',
        'description': 'Comprehensive DNS record enumeration',
        'requires': ['dnspython'],
        'status': 'active'
    },
    'subdomain_enum': {
        'name': 'Subdomain Enumeration',
        'description': 'Discover subdomains via Certificate Transparency',
        'requires': ['aiohttp'],
        'status': 'active'
    },
    'ip_geolocate': {
        'name': 'IP Geolocation',
        'description': 'Geolocate IP addresses',
        'requires': ['aiohttp'],
        'status': 'active'
    }
}

__all__ = [
    'MODULES',
    '__category__',
    '__description__',
]

#!/usr/bin/env python3
"""
ATS-Toolkit - WHOIS Lookup Module
Simple WHOIS information gathering (no external dependencies)

⚠️ EDUCATIONAL USE ONLY - AUTHORIZED SYSTEMS ONLY ⚠️

Module: whois_lookup
Category: OSINT
Requires: None (uses built-in socket)
"""

import socket
import re
from typing import Dict, Optional
from datetime import datetime

from core.utils import print_info, print_success, print_error, is_valid_domain
from core.exceptions import InvalidTargetError, ModuleExecutionError


# WHOIS Servers by TLD
WHOIS_SERVERS = {
    '.com': 'whois.verisign-grs.com',
    '.net': 'whois.verisign-grs.com',
    '.org': 'whois.pir.org',
    '.info': 'whois.afilias.net',
    '.biz': 'whois.biz',
    '.us': 'whois.nic.us',
    '.uk': 'whois.nic.uk',
    '.fr': 'whois.nic.fr',
    '.de': 'whois.denic.de',
    '.it': 'whois.nic.it',
    '.nl': 'whois.domain-registry.nl',
    '.be': 'whois.dns.be',
    '.ch': 'whois.nic.ch',
    '.at': 'whois.nic.at',
    '.se': 'whois.iis.se',
    '.no': 'whois.norid.no',
    '.dk': 'whois.dk-hostmaster.dk',
    '.es': 'whois.nic.es',
    '.pl': 'whois.dns.pl',
    '.io': 'whois.nic.io',
    '.ai': 'whois.nic.ai',
    '.co': 'whois.nic.co',
    '.me': 'whois.nic.me',
    '.tv': 'whois.nic.tv',
    # Add more as needed
}


def get_whois_server(domain: str) -> str:
    """
    Get appropriate WHOIS server for domain TLD.
    
    Args:
        domain: Domain name
        
    Returns:
        WHOIS server hostname
    """
    # Extract TLD
    tld = '.' + domain.split('.')[-1].lower()
    
    # Return specific server or default
    return WHOIS_SERVERS.get(tld, 'whois.iana.org')


def query_whois(domain: str, server: str, port: int = 43, timeout: int = 10) -> Optional[str]:
    """
    Query WHOIS server for domain information.
    
    Args:
        domain: Domain to query
        server: WHOIS server hostname
        port: WHOIS port (default: 43)
        timeout: Socket timeout in seconds
        
    Returns:
        WHOIS response text or None on failure
    """
    try:
        # Create socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        # Connect to WHOIS server
        sock.connect((server, port))
        
        # Send domain query
        sock.send(f"{domain}\r\n".encode())
        
        # Receive response
        response = b""
        while True:
            data = sock.recv(4096)
            if not data:
                break
            response += data
        
        sock.close()
        
        return response.decode('utf-8', errors='ignore')
        
    except socket.timeout:
        return None
    except Exception as e:
        return None


def parse_whois_response(response: str) -> Dict:
    """
    Parse WHOIS response text into structured data.
    
    Args:
        response: Raw WHOIS response
        
    Returns:
        Dictionary with parsed WHOIS data
    """
    data = {
        'raw_response': response,
        'registrar': None,
        'creation_date': None,
        'expiration_date': None,
        'updated_date': None,
        'name_servers': [],
        'status': [],
        'registrant': None,
        'admin_contact': None,
        'tech_contact': None,
    }
    
    lines = response.split('\n')
    
    for line in lines:
        line = line.strip()
        
        # Skip empty lines and comments
        if not line or line.startswith('%') or line.startswith('#'):
            continue
        
        # Parse key-value pairs
        if ':' in line:
            key, value = line.split(':', 1)
            key = key.strip().lower()
            value = value.strip()
            
            # Registrar
            if 'registrar' in key and not data['registrar']:
                data['registrar'] = value
            
            # Dates
            elif 'creation' in key or 'created' in key:
                data['creation_date'] = value
            elif 'expir' in key:
                data['expiration_date'] = value
            elif 'updated' in key or 'modified' in key:
                data['updated_date'] = value
            
            # Name servers
            elif 'name server' in key or 'nserver' in key:
                if value and value not in data['name_servers']:
                    data['name_servers'].append(value.lower())
            
            # Status
            elif 'status' in key:
                if value and value not in data['status']:
                    data['status'].append(value)
            
            # Contacts
            elif 'registrant' in key and not data['registrant']:
                data['registrant'] = value
            elif 'admin' in key and not data['admin_contact']:
                data['admin_contact'] = value
            elif 'tech' in key and not data['tech_contact']:
                data['tech_contact'] = value
    
    return data


def whois_lookup(domain: str, cache_manager=None) -> Dict:
    """
    Perform WHOIS lookup on domain.
    
    Args:
        domain: Target domain
        cache_manager: Optional CacheManager instance for caching
        
    Returns:
        Dictionary with WHOIS results
        
    Raises:
        InvalidTargetError: If domain format is invalid
        ModuleExecutionError: If WHOIS query fails
        
    Example:
        >>> result = whois_lookup("example.com")
        >>> print(result['registrar'])
        'RESERVED-Internet Assigned Numbers Authority'
    """
    # Validate domain
    if not is_valid_domain(domain):
        raise InvalidTargetError(domain, "valid.domain.com")
    
    # Check cache
    cache_key = f"whois:{domain}"
    if cache_manager:
        cached = cache_manager.get(cache_key)
        if cached:
            print_info(f"Using cached WHOIS data for {domain}")
            return cached
    
    print_info(f"Performing WHOIS lookup for: {domain}")
    
    # Get appropriate WHOIS server
    whois_server = get_whois_server(domain)
    print_info(f"Using WHOIS server: {whois_server}")
    
    # Query WHOIS
    response = query_whois(domain, whois_server)
    
    if not response:
        raise ModuleExecutionError(
            "whois_lookup",
            f"Failed to query WHOIS server {whois_server}"
        )
    
    # Parse response
    parsed = parse_whois_response(response)
    
    # Add metadata
    result = {
        'module': 'whois_lookup',
        'target': domain,
        'timestamp': datetime.utcnow().isoformat(),
        'whois_server': whois_server,
        'success': True,
        'data': parsed
    }
    
    # Cache result (24 hours)
    if cache_manager:
        cache_manager.set(cache_key, result, ttl=86400)
    
    return result


def display_whois_results(result: Dict):
    """
    Display WHOIS results in formatted output.
    
    Args:
        result: WHOIS lookup result dictionary
    """
    data = result['data']
    
    print_success(f"\n[+] WHOIS Information for {result['target']}")
    print(f"{'='*70}")
    
    if data['registrar']:
        print(f"Registrar:        {data['registrar']}")
    
    if data['creation_date']:
        print(f"Created:          {data['creation_date']}")
    
    if data['expiration_date']:
        print(f"Expires:          {data['expiration_date']}")
    
    if data['updated_date']:
        print(f"Updated:          {data['updated_date']}")
    
    if data['status']:
        print(f"Status:           {', '.join(data['status'][:3])}")
    
    if data['name_servers']:
        print(f"\nName Servers:")
        for ns in data['name_servers'][:5]:
            print(f"  - {ns}")
    
    if data['registrant']:
        print(f"\nRegistrant:       {data['registrant']}")
    
    print(f"\nWHOIS Server:     {result['whois_server']}")
    print(f"Timestamp:        {result['timestamp']}")
    print(f"{'='*70}\n")


# ============================================================================
# MODULE INTERFACE (for pipeline integration)
# ============================================================================

async def execute(target: str, config: Dict = None) -> Dict:
    """
    Execute WHOIS lookup module (async interface for pipeline).
    
    Args:
        target: Domain to lookup
        config: Module configuration (optional)
        
    Returns:
        Module result dictionary
    """
    try:
        cache_manager = config.get('cache_manager') if config else None
        result = whois_lookup(target, cache_manager)
        return result
    except Exception as e:
        return {
            'module': 'whois_lookup',
            'target': target,
            'timestamp': datetime.utcnow().isoformat(),
            'success': False,
            'error': str(e)
        }


# ============================================================================
# CLI INTERFACE
# ============================================================================

if __name__ == "__main__":
    import argparse
    import sys
    from pathlib import Path
    
    # Add parent directory to path for imports
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))
    
    from core.cache_manager import CacheManager
    from core.utils import print_banner
    
    parser = argparse.ArgumentParser(
        description="ATS-Toolkit WHOIS Lookup Module"
    )
    parser.add_argument("domain", help="Domain to lookup")
    parser.add_argument("--no-cache", action="store_true",
                       help="Disable cache")
    parser.add_argument("--raw", action="store_true",
                       help="Show raw WHOIS response")
    
    args = parser.parse_args()
    
    print_banner()
    
    try:
        # Initialize cache
        cache = None if args.no_cache else CacheManager()
        
        # Perform lookup
        result = whois_lookup(args.domain, cache)
        
        # Display results
        if args.raw:
            print(result['data']['raw_response'])
        else:
            display_whois_results(result)
        
    except InvalidTargetError as e:
        print_error(f"[x] Invalid domain: {e}")
        sys.exit(1)
    except ModuleExecutionError as e:
        print_error(f"[x] WHOIS lookup failed: {e}")
        sys.exit(1)
    except Exception as e:
        print_error(f"[x] Unexpected error: {e}")
        sys.exit(1)
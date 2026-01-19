"""
ATS-Toolkit - Subdomain Enumeration Module
Certificate Transparency Log subdomain discovery

Educational platform for authorized cybersecurity professionals.
[!]  AUTHORIZED USE ONLY [!]
"""

import aiohttp
import asyncio
from typing import Dict, List, Any, Set
from datetime import datetime
import json


# ============================================================================
# MODULE METADATA
# ============================================================================

MODULE_METADATA = {
    'name': 'Subdomain Enumeration',
    'description': 'Discover subdomains via Certificate Transparency logs (crt.sh)',
    'version': '1.0.0',
    'author': 'ATS Team',
    'requires': ['aiohttp'],
    'requires_tools': [],
    'requires_api_keys': []
}


# ============================================================================
# MAIN EXECUTION FUNCTION
# ============================================================================

async def execute(target: str, config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Execute subdomain enumeration on target domain.

    Args:
        target: Domain name to enumerate
        config: Module configuration

    Returns:
        Dictionary containing discovered subdomains
    """
    result = {
        'success': False,
        'target': target,
        'timestamp': datetime.utcnow().isoformat(),
        'module': 'subdomain_enum',
        'data': {}
    }

    try:
        # Query crt.sh Certificate Transparency logs
        subdomains = await query_crtsh(target, config)

        # Filter and clean subdomains
        unique_subdomains = clean_subdomains(subdomains, target)

        # Organize results
        subdomain_data = {
            'subdomains': sorted(list(unique_subdomains)),
            'count': len(unique_subdomains),
            'source': 'crt.sh',
            'wildcard_found': any('*' in sub for sub in subdomains)
        }

        # Optional: resolve subdomains to IPs
        if config.get('resolve', False):
            resolved = await resolve_subdomains(unique_subdomains, config)
            subdomain_data['resolved'] = resolved

        result['data'] = subdomain_data
        result['success'] = True

    except Exception as e:
        result['success'] = False
        result['error'] = str(e)
        result['error_type'] = type(e).__name__

    return result


async def query_crtsh(domain: str, config: Dict[str, Any]) -> List[str]:
    """
    Query crt.sh for certificates containing domain.

    Args:
        domain: Target domain
        config: Configuration

    Returns:
        List of discovered subdomains
    """
    subdomains = []

    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        timeout = aiohttp.ClientTimeout(total=config.get('timeout', 30))

        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()

                    for cert in data:
                        name_value = cert.get('name_value', '')

                        # Split multiple names (sometimes separated by newlines)
                        names = name_value.split('\n')

                        for name in names:
                            name = name.strip().lower()
                            if name and domain in name:
                                subdomains.append(name)

    except Exception as e:
        if config.get('verbose'):
            print(f"Error querying crt.sh: {e}")

    return subdomains


def clean_subdomains(subdomains: List[str], base_domain: str) -> Set[str]:
    """
    Clean and deduplicate subdomain list.

    Args:
        subdomains: Raw subdomain list
        base_domain: Base domain to filter

    Returns:
        Set of cleaned subdomains
    """
    cleaned = set()

    for subdomain in subdomains:
        # Remove wildcards
        subdomain = subdomain.replace('*', '').replace('..', '.')

        # Remove leading/trailing dots
        subdomain = subdomain.strip('.')

        # Must end with base domain
        if subdomain.endswith(base_domain) and subdomain != base_domain:
            cleaned.add(subdomain)

    return cleaned


async def resolve_subdomains(subdomains: Set[str], config: Dict[str, Any]) -> Dict[str, List[str]]:
    """
    Resolve subdomains to IP addresses.

    Args:
        subdomains: Set of subdomains to resolve
        config: Configuration

    Returns:
        Dictionary mapping subdomain -> IP list
    """
    import socket

    resolved = {}
    timeout = config.get('resolve_timeout', 5)

    for subdomain in subdomains:
        try:
            # Set socket timeout
            socket.setdefaulttimeout(timeout)

            ips = socket.gethostbyname_ex(subdomain)[2]

            if ips:
                resolved[subdomain] = ips

        except Exception:
            # Resolution failed - skip
            pass

    return resolved


# ============================================================================
# DISPLAY FUNCTION
# ============================================================================

def display_results(result: Dict[str, Any]):
    """
    Pretty-print subdomain enumeration results.

    Args:
        result: Module execution result
    """
    from core.utils import print_section, print_success, print_info, print_error

    if not result.get('success'):
        print_error(f"Subdomain Enumeration failed: {result.get('error', 'Unknown error')}")
        return

    data = result.get('data', {})
    target = result.get('target')
    subdomains = data.get('subdomains', [])
    count = data.get('count', 0)

    print_section(f"Subdomain Enumeration Results: {target}")

    print_success(f"\n[+] Found {count} subdomains")

    if data.get('wildcard_found'):
        print_info("[!]  Wildcard certificate detected")

    # Display subdomains
    if subdomains:
        print("\nDiscovered Subdomains:")

        # Group by depth
        by_depth = {}
        for sub in subdomains:
            depth = sub.count('.')
            if depth not in by_depth:
                by_depth[depth] = []
            by_depth[depth].append(sub)

        # Display grouped
        for depth in sorted(by_depth.keys()):
            print(f"\n  Depth {depth}:")
            for sub in sorted(by_depth[depth]):
                # Show resolved IPs if available
                resolved = data.get('resolved', {})
                if sub in resolved:
                    ips = ', '.join(resolved[sub])
                    print(f"    - {sub} -> {ips}")
                else:
                    print(f"    - {sub}")

    # Statistics
    print_section("\nStatistics")
    print(f"  Total Subdomains: {count}")
    print(f"  Data Source:      {data.get('source', 'Unknown')}")

    if 'resolved' in data:
        resolved_count = len(data['resolved'])
        print(f"  Resolved:         {resolved_count}/{count}")


# ============================================================================
# TESTING
# ============================================================================

if __name__ == "__main__":
    async def test():
        """Test subdomain enumeration module"""
        config = {'verbose': True, 'timeout': 30, 'resolve': True}
        target = "example.com"

        print(f"Testing Subdomain Enumeration on {target}...")
        result = await execute(target, config)

        display_results(result)

    asyncio.run(test())

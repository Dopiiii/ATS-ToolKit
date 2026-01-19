"""
ATS-Toolkit - IP Geolocation Module
Geolocate IP addresses and gather network information

Educational platform for authorized cybersecurity professionals.
[!]  AUTHORIZED USE ONLY [!]
"""

import aiohttp
import asyncio
import socket
from typing import Dict, List, Any, Optional
from datetime import datetime


# ============================================================================
# MODULE METADATA
# ============================================================================

MODULE_METADATA = {
    'name': 'IP Geolocation',
    'description': 'Geolocate IP addresses using ip-api.com (free, no API key required)',
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
    Execute IP geolocation on target.

    Args:
        target: IP address or domain name
        config: Module configuration

    Returns:
        Dictionary containing geolocation data
    """
    result = {
        'success': False,
        'target': target,
        'timestamp': datetime.utcnow().isoformat(),
        'module': 'ip_geolocate',
        'data': {}
    }

    try:
        # Resolve domain to IP if needed
        ip_address = target
        if not is_valid_ip(target):
            ip_address = await resolve_to_ip(target)

            if not ip_address:
                result['error'] = f"Could not resolve {target} to IP address"
                return result

        # Query geolocation API
        geo_data = await query_ipapi(ip_address, config)

        if geo_data:
            result['data'] = {
                'ip': ip_address,
                'original_target': target,
                'geolocation': geo_data,
                'is_private': is_private_ip(ip_address),
                'is_reserved': is_reserved_ip(ip_address)
            }
            result['success'] = True
        else:
            result['error'] = "Failed to retrieve geolocation data"

    except Exception as e:
        result['success'] = False
        result['error'] = str(e)
        result['error_type'] = type(e).__name__

    return result


def is_valid_ip(ip: str) -> bool:
    """Check if string is valid IP address"""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False


async def resolve_to_ip(domain: str) -> Optional[str]:
    """Resolve domain to IP address"""
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except Exception:
        return None


def is_private_ip(ip: str) -> bool:
    """Check if IP is in private range"""
    parts = list(map(int, ip.split('.')))

    # Private IP ranges
    if parts[0] == 10:
        return True
    if parts[0] == 172 and 16 <= parts[1] <= 31:
        return True
    if parts[0] == 192 and parts[1] == 168:
        return True

    return False


def is_reserved_ip(ip: str) -> bool:
    """Check if IP is in reserved range"""
    parts = list(map(int, ip.split('.')))

    # Reserved ranges
    if parts[0] == 0:  # 0.0.0.0/8
        return True
    if parts[0] == 127:  # 127.0.0.0/8 (localhost)
        return True
    if parts[0] == 169 and parts[1] == 254:  # 169.254.0.0/16 (link-local)
        return True
    if parts[0] >= 224:  # 224.0.0.0/4 (multicast/reserved)
        return True

    return False


async def query_ipapi(ip: str, config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Query ip-api.com for geolocation data.

    Free API, no key required, 45 requests/minute limit.

    Args:
        ip: IP address to geolocate
        config: Configuration

    Returns:
        Dictionary with geolocation data or None
    """
    try:
        url = f"http://ip-api.com/json/{ip}"
        timeout = aiohttp.ClientTimeout(total=config.get('timeout', 10))

        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()

                    if data.get('status') == 'success':
                        return {
                            'country': data.get('country'),
                            'country_code': data.get('countryCode'),
                            'region': data.get('regionName'),
                            'region_code': data.get('region'),
                            'city': data.get('city'),
                            'zip_code': data.get('zip'),
                            'latitude': data.get('lat'),
                            'longitude': data.get('lon'),
                            'timezone': data.get('timezone'),
                            'isp': data.get('isp'),
                            'organization': data.get('org'),
                            'as': data.get('as'),
                            'as_name': data.get('asname'),
                            'reverse_dns': data.get('reverse'),
                            'mobile': data.get('mobile', False),
                            'proxy': data.get('proxy', False),
                            'hosting': data.get('hosting', False)
                        }

    except Exception as e:
        if config.get('verbose'):
            print(f"Error querying ip-api.com: {e}")

    return None


# ============================================================================
# DISPLAY FUNCTION
# ============================================================================

def display_results(result: Dict[str, Any]):
    """
    Pretty-print IP geolocation results.

    Args:
        result: Module execution result
    """
    from core.utils import print_section, print_success, print_info, print_error, print_warning

    if not result.get('success'):
        print_error(f"IP Geolocation failed: {result.get('error', 'Unknown error')}")
        return

    data = result.get('data', {})
    ip = data.get('ip')
    original = data.get('original_target')
    geo = data.get('geolocation', {})

    print_section(f"IP Geolocation Results: {original}")

    # IP Info
    print_success(f"\n[+] IP Address: {ip}")

    if data.get('is_private'):
        print_warning("[!]  This is a PRIVATE IP address (RFC1918)")
        print("   Geolocation data may not be available.")
        return

    if data.get('is_reserved'):
        print_warning("[!]  This is a RESERVED IP address")
        print("   Geolocation data may not be available.")
        return

    # Location
    if geo:
        print_info("\n📍 Location")
        if geo.get('city'):
            print(f"  City:        {geo['city']}")
        if geo.get('region'):
            print(f"  Region:      {geo['region']} ({geo.get('region_code', 'N/A')})")
        if geo.get('country'):
            print(f"  Country:     {geo['country']} ({geo.get('country_code', 'N/A')})")
        if geo.get('zip_code'):
            print(f"  Zip Code:    {geo['zip_code']}")

        # Coordinates
        if geo.get('latitude') and geo.get('longitude'):
            lat = geo['latitude']
            lon = geo['longitude']
            print(f"\n  Coordinates: {lat}, {lon}")
            print(f"  Google Maps: https://www.google.com/maps?q={lat},{lon}")

        # Timezone
        if geo.get('timezone'):
            print(f"  Timezone:    {geo['timezone']}")

        # Network Info
        print_info("\n🌐 Network Information")
        if geo.get('isp'):
            print(f"  ISP:          {geo['isp']}")
        if geo.get('organization'):
            print(f"  Organization: {geo['organization']}")
        if geo.get('as'):
            print(f"  AS Number:    {geo['as']}")
        if geo.get('as_name'):
            print(f"  AS Name:      {geo['as_name']}")
        if geo.get('reverse_dns'):
            print(f"  Reverse DNS:  {geo['reverse_dns']}")

        # Flags
        flags = []
        if geo.get('mobile'):
            flags.append("Mobile")
        if geo.get('proxy'):
            flags.append("Proxy")
        if geo.get('hosting'):
            flags.append("Hosting")

        if flags:
            print(f"\n  Flags:        {', '.join(flags)}")


# ============================================================================
# TESTING
# ============================================================================

if __name__ == "__main__":
    async def test():
        """Test IP geolocation module"""
        config = {'verbose': True, 'timeout': 10}

        # Test with IP
        print("=" * 60)
        print("Test 1: IP Address")
        print("=" * 60)
        result1 = await execute("8.8.8.8", config)
        display_results(result1)

        print("\n\n")

        # Test with domain
        print("=" * 60)
        print("Test 2: Domain Name")
        print("=" * 60)
        result2 = await execute("google.com", config)
        display_results(result2)

    asyncio.run(test())

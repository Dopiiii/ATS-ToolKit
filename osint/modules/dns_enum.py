"""
ATS-Toolkit - DNS Enumeration Module
Comprehensive DNS record enumeration and analysis

Educational platform for authorized cybersecurity professionals.
⚠️  AUTHORIZED USE ONLY ⚠️
"""

import socket
import dns.resolver
import dns.reversename
from typing import Dict, List, Any, Optional
from datetime import datetime


# ============================================================================
# MODULE METADATA
# ============================================================================

MODULE_METADATA = {
    'name': 'DNS Enumeration',
    'description': 'Comprehensive DNS record enumeration (A, AAAA, MX, NS, TXT, SOA, etc.)',
    'version': '1.0.0',
    'author': 'ATS Team',
    'requires': ['dnspython'],
    'requires_tools': [],
    'requires_api_keys': []
}


# ============================================================================
# MAIN EXECUTION FUNCTION
# ============================================================================

async def execute(target: str, config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Execute DNS enumeration on target domain.

    Args:
        target: Domain name to enumerate
        config: Module configuration

    Returns:
        Dictionary containing DNS records and analysis
    """
    result = {
        'success': False,
        'target': target,
        'timestamp': datetime.utcnow().isoformat(),
        'module': 'dns_enum',
        'data': {}
    }

    try:
        # Initialize DNS resolver
        resolver = dns.resolver.Resolver()
        resolver.timeout = config.get('timeout', 5)
        resolver.lifetime = config.get('lifetime', 10)

        # Custom nameservers (optional)
        nameservers = config.get('nameservers')
        if nameservers:
            resolver.nameservers = nameservers

        dns_data = {
            'records': {},
            'nameservers': [],
            'mail_servers': [],
            'txt_records': [],
            'ipv4_addresses': [],
            'ipv6_addresses': [],
            'soa_info': None,
            'reverse_dns': []
        }

        # ==================================================================
        # A RECORDS (IPv4)
        # ==================================================================
        try:
            answers = resolver.resolve(target, 'A')
            a_records = [str(rdata) for rdata in answers]
            dns_data['records']['A'] = a_records
            dns_data['ipv4_addresses'] = a_records

            # Reverse DNS for each IP
            for ip in a_records:
                try:
                    reverse_name = dns.reversename.from_address(ip)
                    reverse = resolver.resolve(reverse_name, 'PTR')
                    reverse_dns = [str(rdata) for rdata in reverse]
                    dns_data['reverse_dns'].append({
                        'ip': ip,
                        'hostnames': reverse_dns
                    })
                except Exception:
                    pass

        except Exception as e:
            dns_data['records']['A'] = []
            if config.get('verbose'):
                dns_data['errors'] = dns_data.get('errors', {})
                dns_data['errors']['A'] = str(e)

        # ==================================================================
        # AAAA RECORDS (IPv6)
        # ==================================================================
        try:
            answers = resolver.resolve(target, 'AAAA')
            aaaa_records = [str(rdata) for rdata in answers]
            dns_data['records']['AAAA'] = aaaa_records
            dns_data['ipv6_addresses'] = aaaa_records
        except Exception as e:
            dns_data['records']['AAAA'] = []

        # ==================================================================
        # NS RECORDS (Nameservers)
        # ==================================================================
        try:
            answers = resolver.resolve(target, 'NS')
            ns_records = [str(rdata) for rdata in answers]
            dns_data['records']['NS'] = ns_records
            dns_data['nameservers'] = ns_records

            # Resolve nameserver IPs
            for ns in ns_records:
                try:
                    ns_ips = socket.gethostbyname_ex(ns)[2]
                    dns_data['nameservers'].append({
                        'hostname': ns,
                        'ips': ns_ips
                    })
                except Exception:
                    pass

        except Exception:
            dns_data['records']['NS'] = []

        # ==================================================================
        # MX RECORDS (Mail Servers)
        # ==================================================================
        try:
            answers = resolver.resolve(target, 'MX')
            mx_records = []

            for rdata in answers:
                mx_info = {
                    'priority': rdata.preference,
                    'hostname': str(rdata.exchange),
                    'ips': []
                }

                # Resolve MX hostname to IPs
                try:
                    mx_ips = socket.gethostbyname_ex(str(rdata.exchange))[2]
                    mx_info['ips'] = mx_ips
                except Exception:
                    pass

                mx_records.append(mx_info)

            # Sort by priority
            mx_records.sort(key=lambda x: x['priority'])

            dns_data['records']['MX'] = mx_records
            dns_data['mail_servers'] = mx_records

        except Exception:
            dns_data['records']['MX'] = []

        # ==================================================================
        # TXT RECORDS
        # ==================================================================
        try:
            answers = resolver.resolve(target, 'TXT')
            txt_records = []

            for rdata in answers:
                txt_value = b''.join(rdata.strings).decode('utf-8')
                txt_records.append(txt_value)

                # Parse common TXT record types
                if txt_value.startswith('v=spf1'):
                    dns_data['spf_record'] = txt_value
                elif txt_value.startswith('v=DMARC1'):
                    dns_data['dmarc_record'] = txt_value
                elif 'google-site-verification' in txt_value:
                    dns_data['google_verification'] = txt_value

            dns_data['records']['TXT'] = txt_records
            dns_data['txt_records'] = txt_records

        except Exception:
            dns_data['records']['TXT'] = []

        # ==================================================================
        # SOA RECORD
        # ==================================================================
        try:
            answers = resolver.resolve(target, 'SOA')
            soa = answers[0]

            soa_info = {
                'mname': str(soa.mname),  # Primary nameserver
                'rname': str(soa.rname),  # Email (encoded)
                'serial': soa.serial,
                'refresh': soa.refresh,
                'retry': soa.retry,
                'expire': soa.expire,
                'minimum': soa.minimum
            }

            dns_data['records']['SOA'] = soa_info
            dns_data['soa_info'] = soa_info

        except Exception:
            dns_data['records']['SOA'] = None

        # ==================================================================
        # CNAME RECORDS
        # ==================================================================
        try:
            answers = resolver.resolve(target, 'CNAME')
            cname_records = [str(rdata) for rdata in answers]
            dns_data['records']['CNAME'] = cname_records
        except Exception:
            dns_data['records']['CNAME'] = []

        # ==================================================================
        # CAA RECORDS (Certificate Authority Authorization)
        # ==================================================================
        try:
            answers = resolver.resolve(target, 'CAA')
            caa_records = []

            for rdata in answers:
                caa_records.append({
                    'flags': rdata.flags,
                    'tag': rdata.tag,
                    'value': rdata.value
                })

            dns_data['records']['CAA'] = caa_records

        except Exception:
            dns_data['records']['CAA'] = []

        # ==================================================================
        # ANALYSIS
        # ==================================================================

        dns_data['analysis'] = {
            'has_ipv4': len(dns_data['ipv4_addresses']) > 0,
            'has_ipv6': len(dns_data['ipv6_addresses']) > 0,
            'has_mail_servers': len(dns_data['mail_servers']) > 0,
            'has_spf': 'spf_record' in dns_data,
            'has_dmarc': 'dmarc_record' in dns_data,
            'nameserver_count': len(dns_data['nameservers']),
            'total_records_found': sum(
                len(v) if isinstance(v, list) else (1 if v else 0)
                for v in dns_data['records'].values()
            )
        }

        result['data'] = dns_data
        result['success'] = True

    except Exception as e:
        result['success'] = False
        result['error'] = str(e)
        result['error_type'] = type(e).__name__

    return result


# ============================================================================
# DISPLAY FUNCTION
# ============================================================================

def display_results(result: Dict[str, Any]):
    """
    Pretty-print DNS enumeration results.

    Args:
        result: Module execution result
    """
    from core.utils import print_section, print_success, print_info, print_error

    if not result.get('success'):
        print_error(f"DNS Enumeration failed: {result.get('error', 'Unknown error')}")
        return

    data = result.get('data', {})
    target = result.get('target')

    print_section(f"DNS Enumeration Results: {target}")

    # IPv4 Addresses
    if data.get('ipv4_addresses'):
        print_success(f"\nIPv4 Addresses ({len(data['ipv4_addresses'])})")
        for ip in data['ipv4_addresses']:
            print(f"  - {ip}")

    # IPv6 Addresses
    if data.get('ipv6_addresses'):
        print_success(f"\nIPv6 Addresses ({len(data['ipv6_addresses'])})")
        for ip in data['ipv6_addresses']:
            print(f"  - {ip}")

    # Nameservers
    if data.get('nameservers'):
        print_success(f"\nNameservers ({len(data['nameservers'])})")
        for ns in data['nameservers']:
            if isinstance(ns, dict):
                print(f"  - {ns['hostname']} -> {', '.join(ns['ips'])}")
            else:
                print(f"  - {ns}")

    # Mail Servers
    if data.get('mail_servers'):
        print_success(f"\nMail Servers ({len(data['mail_servers'])})")
        for mx in data['mail_servers']:
            priority = mx.get('priority', '?')
            hostname = mx.get('hostname', '?')
            ips = ', '.join(mx.get('ips', []))
            print(f"  - Priority {priority}: {hostname}")
            if ips:
                print(f"    -> {ips}")

    # TXT Records
    if data.get('txt_records'):
        print_success(f"\nTXT Records ({len(data['txt_records'])})")
        for txt in data['txt_records']:
            # Truncate long records
            display_txt = txt[:80] + '...' if len(txt) > 80 else txt
            print(f"  - {display_txt}")

    # SPF
    if data.get('spf_record'):
        print_info("\nSPF Record Found")
        print(f"  {data['spf_record']}")

    # DMARC
    if data.get('dmarc_record'):
        print_info("\nDMARC Record Found")
        print(f"  {data['dmarc_record']}")

    # Analysis Summary
    analysis = data.get('analysis', {})
    print_section("\nAnalysis Summary")
    print(f"  IPv4:          {'Yes' if analysis.get('has_ipv4') else 'No'}")
    print(f"  IPv6:          {'Yes' if analysis.get('has_ipv6') else 'No'}")
    print(f"  Mail Servers:  {'Yes' if analysis.get('has_mail_servers') else 'No'}")
    print(f"  SPF Record:    {'Yes' if analysis.get('has_spf') else 'No'}")
    print(f"  DMARC Record:  {'Yes' if analysis.get('has_dmarc') else 'No'}")
    print(f"  Total Records: {analysis.get('total_records_found', 0)}")


# ============================================================================
# TESTING
# ============================================================================

if __name__ == "__main__":
    import asyncio

    async def test():
        """Test DNS enumeration module"""
        config = {'verbose': True, 'timeout': 10}
        target = "google.com"

        print(f"Testing DNS Enumeration on {target}...")
        result = await execute(target, config)

        display_results(result)

    asyncio.run(test())

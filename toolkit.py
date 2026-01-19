#!/usr/bin/env python3
"""
ATS-Toolkit v2.0 - Main CLI Interface
Attack & Testing Suite - Professional Red Team Platform

⚠️ EDUCATIONAL USE ONLY - AUTHORIZED SYSTEMS ONLY ⚠️

Author: Eric - Strasbourg, France
Version: 2.0.0-alpha
Phase: 1 (Core Engine + First Module)
"""

import sys
import argparse
import asyncio
from pathlib import Path
from typing import Dict, Optional

# Add project root to Python path
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

from core.utils import (
    print_banner, print_success, print_error, print_info, 
    print_warning, print_section, get_timestamp
)
from core.exceptions import (
    ATSToolkitError, ConsentNotGivenError, ModuleNotFoundError,
    InvalidTargetError, handle_exception
)
from core.consent_manager import ConsentManager
from core.cache_manager import CacheManager
from legal.disclaimer import show_disclaimer, check_acceptance_log


# ============================================================================
# VERSION & METADATA
# ============================================================================

VERSION = "2.0.0-alpha"
PHASE = "Phase 1: Core Engine + First Module"
AUTHOR = "Eric - Strasbourg, France"


# ============================================================================
# AVAILABLE MODULES (Phase 1)
# ============================================================================

AVAILABLE_MODULES = {
    'osint': {
        'whois_lookup': {
            'name': 'WHOIS Lookup',
            'description': 'Domain registration information',
            'requires': [],
            'status': 'active'
        }
    },
    'pentest': {},
    'redteam': {},
    'forensics': {},
    'ml_threat': {},
    'fuzzing': {},
    'deception': {},
    'continuous': {}
}


def list_modules(section: Optional[str] = None):
    """
    List available modules.
    
    Args:
        section: Specific section to list (osint, pentest, etc.)
    """
    print_section("Available Modules")
    
    sections = [section] if section else AVAILABLE_MODULES.keys()
    
    for sec in sections:
        modules = AVAILABLE_MODULES.get(sec, {})
        
        if not modules:
            print(f"\n{sec.upper()}: No modules available yet")
            continue
        
        print(f"\n{sec.upper()} ({len(modules)} modules):")
        for module_id, info in modules.items():
            status_icon = "✓" if info['status'] == 'active' else "✗"
            print(f"  {status_icon} {module_id:20} - {info['description']}")


def get_module_path(section: str, module: str) -> Optional[Path]:
    """
    Get module file path.
    
    Args:
        section: Module section (osint, pentest, etc.)
        module: Module name
        
    Returns:
        Path to module file or None if not found
    """
    module_file = PROJECT_ROOT / section / "modules" / f"{module}.py"
    
    if module_file.exists():
        return module_file
    
    return None


async def execute_module(section: str, module: str, target: str, 
                        consent_hash: str, config: Dict) -> Dict:
    """
    Execute a single module.
    
    Args:
        section: Module section
        module: Module name
        target: Target to scan
        consent_hash: Valid consent hash
        config: Module configuration
        
    Returns:
        Module execution result
    """
    # Verify module exists
    if section not in AVAILABLE_MODULES:
        raise ModuleNotFoundError(f"{section}/{module}")
    
    if module not in AVAILABLE_MODULES[section]:
        raise ModuleNotFoundError(f"{section}/{module}")
    
    # Verify consent
    consent_manager = config.get('consent_manager')
    if consent_manager:
        consent_manager.verify_consent(consent_hash)
    
    print_info(f"Executing module: {section}/{module}")
    print_info(f"Target: {target}")
    print_info(f"Consent: {consent_hash[:16]}...")
    
    # Dynamic module import
    try:
        if section == 'osint' and module == 'whois_lookup':
            from osint.modules.whois_lookup import execute as module_execute
            result = await module_execute(target, config)
            return result
        else:
            raise ModuleNotFoundError(f"{section}/{module}")
            
    except ImportError as e:
        raise ModuleNotFoundError(f"{section}/{module} - Import failed: {e}")


def main():
    """Main CLI entry point"""
    
    parser = argparse.ArgumentParser(
        prog="ats-toolkit",
        description="ATS-Toolkit v2.0 - Professional Red Team Cyber Suite",
        epilog="⚠️  EDUCATIONAL USE ONLY - AUTHORIZED SYSTEMS ONLY ⚠️",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Version and info
    parser.add_argument("--version", action="version",
                       version=f"ATS-Toolkit {VERSION} - {PHASE}")
    
    # Legal
    parser.add_argument("--accept-legal", action="store_true",
                       help="Accept legal disclaimer (required first time)")
    parser.add_argument("--show-legal", action="store_true",
                       help="Show legal disclaimer")
    
    # Module listing
    parser.add_argument("--list-modules", nargs="?", const="all", metavar="SECTION",
                       help="List available modules (optionally by section)")
    
    # Module execution
    parser.add_argument("--section", choices=list(AVAILABLE_MODULES.keys()),
                       help="Module section (osint, pentest, etc.)")
    parser.add_argument("--module", type=str,
                       help="Module to execute (e.g., whois_lookup)")
    parser.add_argument("--target", type=str,
                       help="Target to scan (domain, IP, URL, etc.)")
    
    # Consent
    parser.add_argument("--generate-consent", action="store_true",
                       help="Generate new consent hash")
    parser.add_argument("--consent", type=str,
                       help="Consent hash for authorization")
    parser.add_argument("--user-id", type=str, default="default",
                       help="User identifier for consent (email, username)")
    
    # Cache management
    parser.add_argument("--no-cache", action="store_true",
                       help="Disable result caching")
    parser.add_argument("--cache-stats", action="store_true",
                       help="Show cache statistics")
    parser.add_argument("--clear-cache", action="store_true",
                       help="Clear cache database")
    
    # Consent management
    parser.add_argument("--consent-stats", action="store_true",
                       help="Show consent blockchain statistics")
    parser.add_argument("--verify-consent", type=str, metavar="HASH",
                       help="Verify consent hash validity")
    
    # Output
    parser.add_argument("--output", type=str,
                       help="Output file path (JSON)")
    parser.add_argument("--verbose", "-v", action="store_true",
                       help="Verbose output")
    parser.add_argument("--debug", action="store_true",
                       help="Debug mode (full tracebacks)")
    
    args = parser.parse_args()
    
    # Show banner
    if not any([args.cache_stats, args.consent_stats, args.clear_cache, args.list_modules]):
        print_banner()
    
    try:
        # ====================================================================
        # LEGAL DISCLAIMER
        # ====================================================================
        
        if args.show_legal or args.accept_legal:
            show_disclaimer(language="en")
            if not args.accept_legal:
                sys.exit(0)
        
        # Check if legal was accepted (unless running info commands)
        info_commands = [
            args.list_modules, args.cache_stats, args.consent_stats,
            args.show_legal, args.version
        ]
        
        if not any(info_commands) and not check_acceptance_log():
            if not args.accept_legal:
                raise ConsentNotGivenError(
                    "Legal disclaimer not accepted. Run with --accept-legal first."
                )
        
        # ====================================================================
        # CACHE MANAGEMENT
        # ====================================================================
        
        if args.cache_stats:
            cache = CacheManager()
            cache.display_stats()
            sys.exit(0)
        
        if args.clear_cache:
            cache = CacheManager()
            response = input("⚠ Clear ALL cache data? (yes/no): ")
            if response.lower() == 'yes':
                deleted = cache.clear_all()
                print_success(f"✓ Cleared {deleted} cache entries")
            else:
                print_info("Operation cancelled")
            sys.exit(0)
        
        # ====================================================================
        # CONSENT MANAGEMENT
        # ====================================================================
        
        if args.consent_stats:
            consent = ConsentManager()
            consent.display_stats()
            sys.exit(0)
        
        if args.verify_consent:
            consent = ConsentManager()
            try:
                valid = consent.verify_consent(args.verify_consent)
                print_success(f"✓ Consent hash is VALID: {args.verify_consent}")
                details = consent.get_consent_details(args.verify_consent)
                if details:
                    print(f"Target: {details.target}")
                    print(f"Modules: {', '.join(details.modules_list)}")
                    print(f"Timestamp: {details.timestamp}")
            except Exception as e:
                print_error(f"✗ {e}")
                sys.exit(1)
            sys.exit(0)
        
        # ====================================================================
        # MODULE LISTING
        # ====================================================================
        
        if args.list_modules:
            section = None if args.list_modules == "all" else args.list_modules
            list_modules(section)
            sys.exit(0)
        
        # ====================================================================
        # GENERATE CONSENT
        # ====================================================================
        
        if args.generate_consent:
            if not args.target or not args.module:
                print_error("--target and --module required for consent generation")
                sys.exit(1)
            
            consent = ConsentManager()
            modules_list = [args.module]
            
            consent_hash = consent.generate_consent_hash(
                target=args.target,
                modules=modules_list,
                user_id=args.user_id
            )
            
            print_success(f"✓ Consent hash generated:")
            print(f"\n  {consent_hash}\n")
            print(f"Target:  {args.target}")
            print(f"Modules: {', '.join(modules_list)}")
            print(f"User:    {args.user_id}")
            print(f"\nUse with: --consent {consent_hash}")
            sys.exit(0)
        
        # ====================================================================
        # MODULE EXECUTION
        # ====================================================================
        
        if args.module:
            # Validate required arguments
            if not args.section:
                print_error("--section required (e.g., --section osint)")
                sys.exit(1)
            
            if not args.target:
                print_error("--target required (e.g., --target example.com)")
                sys.exit(1)
            
            if not args.consent:
                print_error("--consent required. Generate with --generate-consent")
                print_info("Quick start: Run with --generate-consent first")
                sys.exit(1)
            
            # Initialize managers
            consent_manager = ConsentManager()
            cache_manager = None if args.no_cache else CacheManager()
            
            # Configuration
            config = {
                'consent_manager': consent_manager,
                'cache_manager': cache_manager,
                'verbose': args.verbose,
                'debug': args.debug
            }
            
            # Execute module
            result = asyncio.run(
                execute_module(
                    section=args.section,
                    module=args.module,
                    target=args.target,
                    consent_hash=args.consent,
                    config=config
                )
            )
            
            # Display results
            if result.get('success'):
                print_success(f"\n✓ Module {args.module} completed successfully")
                
                # Pretty print based on module
                if args.section == 'osint' and args.module == 'whois_lookup':
                    from osint.modules.whois_lookup import display_whois_results
                    display_whois_results(result)
                else:
                    import json
                    print(json.dumps(result, indent=2))
                
                # Save output if requested
                if args.output:
                    import json
                    output_path = Path(args.output)
                    with open(output_path, 'w') as f:
                        json.dump(result, f, indent=2)
                    print_success(f"✓ Results saved to: {output_path}")
                    
            else:
                print_error(f"\n✗ Module {args.module} failed")
                print_error(f"Error: {result.get('error', 'Unknown error')}")
                sys.exit(1)
        
        else:
            # No command specified - show help
            parser.print_help()
    
    except ATSToolkitError as e:
        handle_exception(e, debug=args.debug if 'debug' in args else False)
        sys.exit(1)
    
    except KeyboardInterrupt:
        print_warning("\n\n⚠ Operation cancelled by user")
        sys.exit(130)
    
    except Exception as e:
        print_error(f"\n✗ Unexpected error: {e}")
        if args.debug if 'debug' in args else False:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
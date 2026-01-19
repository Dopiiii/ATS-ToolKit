#!/usr/bin/env python3
"""
ATS-Toolkit v2.0 - Main CLI Interface
Professional Security & Intelligence Framework

⚠️  EDUCATIONAL USE ONLY - AUTHORIZED SYSTEMS ONLY ⚠️

Author: ATS Team
Version: 2.0.0-alpha
"""

import sys
import argparse
import asyncio
from pathlib import Path
from typing import Dict, Optional, List
import json

# Add project root to Python path
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

from core.module_registry import ModuleRegistry, ModuleStatus
from core.pipeline_engine import PipelineEngine
from core.consent_manager import ConsentManager
from core.cache_manager import CacheManager
from core.utils import (
    print_banner, print_success, print_error, print_info,
    print_warning, print_section, get_timestamp
)
from core.exceptions import (
    ATSToolkitError, ConsentNotGivenError, ModuleNotFoundError,
    InvalidTargetError, handle_exception
)
from legal.disclaimer import show_disclaimer, check_acceptance_log


# ============================================================================
# VERSION & METADATA
# ============================================================================

VERSION = "2.0.0-alpha"
PHASE = "Phase 1: Core Architecture + Module System"
AUTHOR = "ATS Team"


# ============================================================================
# CORE FUNCTIONS
# ============================================================================

def list_modules_command(registry: ModuleRegistry, section: Optional[str] = None,
                        verbose: bool = False):
    """
    Display available modules.

    Args:
        registry: Module registry instance
        section: Specific section to list (None for all)
        verbose: Show detailed info
    """
    print_section("Available Modules")

    modules_by_section = registry.list_modules(section=section)

    if not modules_by_section:
        print_warning("No modules found. Have you run module discovery?")
        return

    total_modules = 0

    for sec, modules in sorted(modules_by_section.items()):
        # Count active modules
        active_count = sum(1 for m in modules if m.status == ModuleStatus.ACTIVE)
        error_count = sum(1 for m in modules if m.status == ModuleStatus.ERROR)

        print(f"\n{sec.upper():15} | {active_count} active | {error_count} error")
        print("-" * 60)

        for module in sorted(modules, key=lambda x: x.id):
            # Status icon
            if module.status == ModuleStatus.ACTIVE:
                icon = "[+]"
            elif module.status == ModuleStatus.ERROR:
                icon = "[x]"
            else:
                icon = "[ ]"

            print(f"  {icon} {module.id:20} | {module.description[:35]}")

            if verbose:
                print(f"       Version: {module.version} | Author: {module.author}")

                if module.requires:
                    print(f"       Requires: {', '.join(module.requires)}")

                if module.requires_api_keys:
                    print(f"       API Keys: {', '.join(module.requires_api_keys)}")

                if module.status == ModuleStatus.ERROR:
                    print(f"       Error: {module.error_message}")

                print()

            total_modules += 1

    print(f"\n{'-' * 60}")
    print(f"Total: {total_modules} modules")


async def execute_single_module(registry: ModuleRegistry, section: str, module_id: str,
                                target: str, config: Dict, consent_hash: Optional[str] = None):
    """
    Execute a single module.

    Args:
        registry: Module registry
        section: Module section
        module_id: Module ID
        target: Target to scan
        config: Configuration
        consent_hash: Optional consent hash

    Returns:
        Execution result
    """
    # Get module info
    module_info = registry.get_module(section, module_id)

    if not module_info:
        raise ModuleNotFoundError(f"{section}/{module_id}")

    print_info(f"Executing: {section}/{module_id}")
    print_info(f"Target: {target}")

    # Initialize pipeline engine
    consent_manager = config.get('consent_manager')
    cache_manager = config.get('cache_manager')

    engine = PipelineEngine(
        registry=registry,
        consent_manager=consent_manager,
        cache_manager=cache_manager,
        config=config
    )

    # Execute module
    result = await engine.execute_module(
        section=section,
        module_id=module_id,
        target=target,
        config=config
    )

    return result


async def execute_multiple_modules(registry: ModuleRegistry, target: str,
                                   modules: List[tuple[str, str]], config: Dict):
    """
    Execute multiple modules via pipeline.

    Args:
        registry: Module registry
        target: Target to scan
        modules: List of (section, module_id) tuples
        config: Configuration

    Returns:
        Pipeline result
    """
    print_section(f"Executing Pipeline on {target}")
    print_info(f"Modules: {len(modules)}")

    # Initialize pipeline engine
    consent_manager = config.get('consent_manager')
    cache_manager = config.get('cache_manager')

    engine = PipelineEngine(
        registry=registry,
        consent_manager=consent_manager,
        cache_manager=cache_manager,
        config=config
    )

    # Execute pipeline
    result = await engine.execute_pipeline(
        target=target,
        modules=modules,
        config=config
    )

    return result


def display_module_result(section: str, module_id: str, result: Dict):
    """
    Display module result using module's display function.

    Args:
        section: Module section
        module_id: Module ID
        result: Execution result
    """
    # Try to import module's display function
    try:
        if section == 'osint':
            if module_id == 'dns_enum':
                from osint.modules.dns_enum import display_results
                display_results(result.data)
            elif module_id == 'subdomain_enum':
                from osint.modules.subdomain_enum import display_results
                display_results(result.data)
            elif module_id == 'ip_geolocate':
                from osint.modules.ip_geolocate import display_results
                display_results(result.data)
            elif module_id == 'whois_lookup':
                from osint.modules.whois_lookup import display_whois_results
                display_whois_results(result.data)
            else:
                # Generic display
                print(json.dumps(result.to_dict(), indent=2))
        else:
            # Generic display for other sections
            print(json.dumps(result.to_dict(), indent=2))

    except ImportError:
        # Fallback to generic JSON display
        print(json.dumps(result.to_dict(), indent=2))


# ============================================================================
# MAIN CLI
# ============================================================================

def main():
    """Main CLI entry point"""

    parser = argparse.ArgumentParser(
        prog="ats-toolkit",
        description="ATS-Toolkit v2.0 - Professional Security & Intelligence Framework",
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

    # Module management
    parser.add_argument("--discover", action="store_true",
                       help="Discover and register available modules")
    parser.add_argument("--list-modules", nargs="?", const="all", metavar="SECTION",
                       help="List available modules (optionally by section)")
    parser.add_argument("--module-info", metavar="SECTION/MODULE",
                       help="Show detailed module information")

    # Module execution
    parser.add_argument("--section", type=str,
                       help="Module section (osint, pentest, etc.)")
    parser.add_argument("--module", type=str,
                       help="Module to execute (e.g., dns_enum)")
    parser.add_argument("--modules", type=str,
                       help="Multiple modules (comma-separated: dns_enum,subdomain_enum)")
    parser.add_argument("--target", type=str,
                       help="Target to scan (domain, IP, URL, etc.)")

    # Pipeline options
    parser.add_argument("--parallel", action="store_true",
                       help="Execute modules in parallel (default: sequential)")

    # Consent
    parser.add_argument("--generate-consent", action="store_true",
                       help="Generate new consent hash")
    parser.add_argument("--consent", type=str,
                       help="Consent hash for authorization")
    parser.add_argument("--user-id", type=str, default="default",
                       help="User identifier for consent")

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
    info_commands = [args.cache_stats, args.consent_stats, args.clear_cache,
                    args.list_modules, args.show_legal]

    if not any(info_commands):
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
        if not any(info_commands) and not check_acceptance_log():
            if not args.accept_legal:
                raise ConsentNotGivenError(
                    "Legal disclaimer not accepted. Run with --accept-legal first."
                )

        # ====================================================================
        # MODULE REGISTRY INITIALIZATION
        # ====================================================================

        registry = ModuleRegistry(PROJECT_ROOT)

        # Auto-discover modules on first run or if requested
        if args.discover or not args.list_modules:
            if args.verbose or args.discover:
                print_info("Discovering modules...")

            discovered = registry.discover_modules(verbose=args.discover)

            if args.discover:
                print_success(f"[+] Discovered {discovered} modules")
                sys.exit(0)

        # ====================================================================
        # CACHE MANAGEMENT
        # ====================================================================

        if args.cache_stats:
            cache = CacheManager()
            cache.display_stats()
            sys.exit(0)

        if args.clear_cache:
            cache = CacheManager()
            response = input("⚠  Clear ALL cache data? (yes/no): ")
            if response.lower() == 'yes':
                deleted = cache.clear_all()
                print_success(f"[+] Cleared {deleted} cache entries")
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
                print_success(f"[+] Consent hash is VALID: {args.verify_consent}")
            except Exception as e:
                print_error(f"[x] {e}")
                sys.exit(1)
            sys.exit(0)

        # ====================================================================
        # MODULE LISTING
        # ====================================================================

        if args.list_modules:
            registry.discover_modules(verbose=False)
            section = None if args.list_modules == "all" else args.list_modules
            list_modules_command(registry, section=section, verbose=args.verbose)
            sys.exit(0)

        # ====================================================================
        # GENERATE CONSENT
        # ====================================================================

        if args.generate_consent:
            if not args.target:
                print_error("--target required for consent generation")
                sys.exit(1)

            if not args.module and not args.modules:
                print_error("--module or --modules required for consent generation")
                sys.exit(1)

            consent = ConsentManager()

            # Parse modules
            if args.modules:
                modules_list = args.modules.split(',')
            else:
                modules_list = [args.module]

            consent_hash = consent.generate_consent_hash(
                target=args.target,
                modules=modules_list,
                user_id=args.user_id
            )

            print_success(f"[+] Consent hash generated:")
            print(f"\n  {consent_hash}\n")
            print(f"Target:  {args.target}")
            print(f"Modules: {', '.join(modules_list)}")
            print(f"User:    {args.user_id}")
            print(f"\nUse with: --consent {consent_hash}")
            sys.exit(0)

        # ====================================================================
        # MODULE EXECUTION
        # ====================================================================

        if args.module or args.modules:
            # Validate required arguments
            if not args.section:
                print_error("--section required (e.g., --section osint)")
                sys.exit(1)

            if not args.target:
                print_error("--target required (e.g., --target example.com)")
                sys.exit(1)

            # Initialize managers
            consent_manager = ConsentManager()
            cache_manager = None if args.no_cache else CacheManager()

            # Discover modules
            registry.discover_modules(verbose=False)

            # Configuration
            config = {
                'consent_manager': consent_manager,
                'cache_manager': cache_manager,
                'verbose': args.verbose,
                'debug': args.debug,
                'execution_mode': 'parallel' if args.parallel else 'sequential',
                'no_cache': args.no_cache
            }

            # Single module execution
            if args.module:
                result = asyncio.run(
                    execute_single_module(
                        registry=registry,
                        section=args.section,
                        module_id=args.module,
                        target=args.target,
                        config=config,
                        consent_hash=args.consent
                    )
                )

                # Display results
                if result.status.value == "success":
                    print_success(f"\n[+] Module {args.module} completed successfully")
                    display_module_result(args.section, args.module, result)
                else:
                    print_error(f"\n[x] Module {args.module} failed")
                    if result.error:
                        print_error(f"Error: {result.error}")
                    sys.exit(1)

                # Save output if requested
                if args.output:
                    output_path = Path(args.output)
                    with open(output_path, 'w') as f:
                        json.dump(result.to_dict(), f, indent=2)
                    print_success(f"[+] Results saved to: {output_path}")

            # Multiple modules execution
            elif args.modules:
                module_ids = [m.strip() for m in args.modules.split(',')]
                modules_list = [(args.section, mid) for mid in module_ids]

                pipeline_result = asyncio.run(
                    execute_multiple_modules(
                        registry=registry,
                        target=args.target,
                        modules=modules_list,
                        config=config
                    )
                )

                # Display summary
                print_section("\nPipeline Execution Summary")
                print(f"  Target:         {args.target}")
                print(f"  Modules Run:    {pipeline_result.modules_executed}")
                print(f"  Succeeded:      {pipeline_result.modules_succeeded}")
                print(f"  Failed:         {pipeline_result.modules_failed}")
                print(f"  Total Time:     {pipeline_result.total_time:.2f}s")

                # Display individual results
                for result in pipeline_result.results:
                    print(f"\n{'-' * 60}")
                    if result.status.value == "success":
                        print_success(f"[+] {result.module_id}")
                        display_module_result(result.section, result.module_id, result)
                    else:
                        print_error(f"[x] {result.module_id}: {result.error}")

                # Save output if requested
                if args.output:
                    output_path = Path(args.output)
                    with open(output_path, 'w') as f:
                        json.dump(pipeline_result.to_dict(), f, indent=2)
                    print_success(f"\n[+] Results saved to: {output_path}")

        else:
            # No command specified - show help
            parser.print_help()

    except ATSToolkitError as e:
        handle_exception(e, debug=args.debug if hasattr(args, 'debug') else False)
        sys.exit(1)

    except KeyboardInterrupt:
        print_warning("\n\n⚠  Operation cancelled by user")
        sys.exit(130)

    except Exception as e:
        print_error(f"\n[x] Unexpected error: {e}")
        if args.debug if hasattr(args, 'debug') else False:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

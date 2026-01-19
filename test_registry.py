"""Test script for ModuleRegistry."""

import asyncio
from src.modules.registry import get_registry


async def main():
    """Test the module registry."""
    print("=" * 70)
    print("Testing ModuleRegistry")
    print("=" * 70)

    # Get registry instance
    registry = get_registry()

    # Show summary
    print(f"\nTotal modules discovered: {registry.get_module_count()}")
    print(f"Categories: {', '.join(registry.list_categories())}")

    # List all modules
    print("\n" + "=" * 70)
    print("All Modules:")
    print("=" * 70)
    all_modules = registry.list_modules()
    for spec in all_modules:
        print(f"  - {spec.name} [{spec.category.value}] v{spec.version}")
        print(f"    {spec.description}")

    # List by category
    print("\n" + "=" * 70)
    print("OSINT Modules:")
    print("=" * 70)
    osint_modules = registry.list_modules(category="osint")
    for spec in osint_modules:
        print(f"  - {spec.name}: {spec.description}")

    print("\n" + "=" * 70)
    print("Pentest Modules:")
    print("=" * 70)
    pentest_modules = registry.list_modules(category="pentest")
    for spec in pentest_modules:
        print(f"  - {spec.name}: {spec.description}")

    # Search modules
    print("\n" + "=" * 70)
    print("Search for 'scan':")
    print("=" * 70)
    search_results = registry.search("scan")
    for spec in search_results:
        print(f"  - {spec.name}: {spec.description}")

    # Get specific module spec
    print("\n" + "=" * 70)
    print("Module Details: whois_lookup")
    print("=" * 70)
    spec = registry.get_spec("whois_lookup")
    if spec:
        print(f"Name: {spec.name}")
        print(f"Category: {spec.category.value}")
        print(f"Description: {spec.description}")
        print(f"Version: {spec.version}")
        print(f"Author: {spec.author}")
        print(f"Tags: {', '.join(spec.tags)}")
        print(f"Parameters:")
        for param in spec.parameters:
            print(f"  - {param.name} ({param.type.value}): {param.description}")
            if not param.required:
                print(f"    Default: {param.default}")

    # Test execution
    print("\n" + "=" * 70)
    print("Testing Module Execution: whois_lookup")
    print("=" * 70)
    try:
        result = await registry.execute(
            "whois_lookup",
            {"target": "example.com", "follow_referral": False},
            timeout=30
        )
        print(f"Success: {result['success']}")
        print(f"Duration: {result['duration_ms']}ms")
        if result['success']:
            print(f"Registrar: {result['data'].get('registrar', 'N/A')}")
        else:
            print(f"Errors: {', '.join(result['errors'])}")
    except Exception as e:
        print(f"Execution failed: {e}")

    print("\n" + "=" * 70)
    print("Tests Complete!")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())

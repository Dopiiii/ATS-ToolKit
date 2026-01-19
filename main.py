#!/usr/bin/env python3
"""ATS-Toolkit - Modular Cybersecurity Framework.

Entry point for all execution modes:
- TUI: python main.py --tui
- API: python main.py --api
- Streamlit: python main.py --web
- Module CLI: python main.py run <module> [--config key=value]
"""

import argparse
import asyncio
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))


def run_api(host: str = "127.0.0.1", port: int = 8000, reload: bool = False):
    """Start FastAPI server."""
    import uvicorn

    uvicorn.run(
        "src.api.main:app",
        host=host,
        port=port,
        reload=reload,
        log_level="info"
    )


def run_tui():
    """Start Textual TUI."""
    try:
        from src.tui.app import AtsApp
        app = AtsApp()
        app.run()
    except ImportError:
        print("TUI not yet implemented. Use --api for now.")
        print("TUI will be available in Phase 1.")
        sys.exit(1)


def run_streamlit():
    """Start Streamlit web UI."""
    import subprocess
    subprocess.run([
        sys.executable, "-m", "streamlit", "run",
        "src/streamlit_ui/app.py",
        "--server.port", "8501"
    ])


async def run_module(module_name: str, config: dict):
    """Run a single module from CLI."""
    from src.core.config_manager import init_config
    from src.core.logger import setup_logging, get_logger
    from src.modules.registry import get_registry

    # Initialize
    cfg = init_config()
    setup_logging(level=cfg.config.log_level)
    logger = get_logger("cli")

    # Discover modules
    registry = get_registry()
    registry.discover()

    # Check if module exists
    if module_name not in registry:
        logger.error("module_not_found", module=module_name)
        print(f"\nModule '{module_name}' not found.")
        print("\nAvailable modules:")
        for spec in registry.list_modules():
            print(f"  - {spec.name}: {spec.description}")
        sys.exit(1)

    # Run module
    print(f"\nRunning module: {module_name}")
    print(f"Config: {config}\n")

    result = await registry.execute(module_name, config)

    if result.success:
        print("\n[SUCCESS]")
        print(f"Duration: {result.duration_ms}ms")
        print("\nResults:")
        import json
        print(json.dumps(result.data, indent=2))
    else:
        print("\n[FAILED]")
        print(f"Duration: {result.duration_ms}ms")
        print("\nErrors:")
        for error in result.errors:
            print(f"  - {error}")


def list_modules():
    """List all available modules."""
    from src.core.config_manager import init_config
    from src.core.logger import setup_logging
    from src.modules.registry import get_registry

    init_config()
    setup_logging(console=True)

    registry = get_registry()
    registry.discover()

    categories = registry.list_categories()

    print("\n=== ATS-Toolkit Modules ===\n")

    for category, count in sorted(categories.items(), key=lambda x: -x[1]):
        print(f"\n{category.value.upper()} ({count} modules)")
        print("-" * 40)

        for spec in registry.list_modules(category=category):
            api_indicator = " [API]" if spec.requires_api_key else ""
            print(f"  {spec.name}{api_indicator}")
            print(f"    {spec.description}")

    print(f"\nTotal: {registry.count} modules")


def parse_config(config_args: list) -> dict:
    """Parse key=value config arguments."""
    config = {}
    for arg in config_args:
        if "=" in arg:
            key, value = arg.split("=", 1)
            # Try to parse as JSON for complex values
            try:
                import json
                value = json.loads(value)
            except json.JSONDecodeError:
                pass
            config[key] = value
    return config


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="ATS-Toolkit - Modular Cybersecurity Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --tui              Start TUI interface
  python main.py --api              Start API server
  python main.py --web              Start Streamlit web UI
  python main.py list               List all modules
  python main.py run username_enum --config username=john_doe
        """
    )

    # Mode selection
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--tui",
        action="store_true",
        help="Start Textual TUI interface"
    )
    mode_group.add_argument(
        "--api",
        action="store_true",
        help="Start FastAPI server"
    )
    mode_group.add_argument(
        "--web",
        action="store_true",
        help="Start Streamlit web interface"
    )

    # API options
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="API host (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="API port (default: 8000)"
    )
    parser.add_argument(
        "--reload",
        action="store_true",
        help="Enable auto-reload for development"
    )

    # Subcommands
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # List command
    subparsers.add_parser("list", help="List all available modules")

    # Run command
    run_parser = subparsers.add_parser("run", help="Run a module")
    run_parser.add_argument("module", help="Module name to run")
    run_parser.add_argument(
        "--config", "-c",
        nargs="*",
        default=[],
        help="Config as key=value pairs"
    )

    args = parser.parse_args()

    # Execute based on mode
    if args.tui:
        run_tui()
    elif args.api:
        run_api(host=args.host, port=args.port, reload=args.reload)
    elif args.web:
        run_streamlit()
    elif args.command == "list":
        list_modules()
    elif args.command == "run":
        config = parse_config(args.config)
        asyncio.run(run_module(args.module, config))
    else:
        # Default: show help
        parser.print_help()


if __name__ == "__main__":
    main()

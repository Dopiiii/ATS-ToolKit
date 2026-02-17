"""ATS-Toolkit - Entry Point.

Provides CLI access to the modular cybersecurity framework via
argparse.  Supports TUI, web, and API launch modes as well as
direct module listing and execution from the command line.
"""

import argparse
import asyncio
import subprocess
import sys
from dataclasses import asdict

from src.core.config_manager import get_config_manager
from src.core.logger import setup_logging
from src.modules.registry import get_registry


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        prog="ats-toolkit",
        description="ATS-Toolkit v2.0 - Modular Cybersecurity Framework",
    )

    # Launch-mode flags (mutually exclusive)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--tui", action="store_true", help="Launch the Textual TUI")
    mode.add_argument("--web", action="store_true", help="Launch the Streamlit web UI")
    mode.add_argument("--api", action="store_true", help="Launch the FastAPI REST API")

    # Subcommands
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("list", help="List all available modules")

    run_parser = sub.add_parser("run", help="Run a specific module")
    run_parser.add_argument("module_name", help="Name of the module to run")
    run_parser.add_argument(
        "--param",
        "-p",
        action="append",
        default=[],
        help="Module parameter as key=value (repeatable)",
    )

    return parser


def cmd_list() -> None:
    """List all registered modules."""
    registry = get_registry()
    registry.discover()

    modules = registry.list_modules()
    if not modules:
        print("No modules found.")
        return

    print(f"\n{'Name':<35} {'Category':<18} {'Description'}")
    print("-" * 90)
    for spec in modules:
        print(f"{spec.name:<35} {spec.category.value:<18} {spec.description}")
    print(f"\nTotal: {len(modules)} modules")


def cmd_run(module_name: str, params: list[str]) -> None:
    """Run a module by name."""
    registry = get_registry()
    registry.discover()

    # Parse key=value params
    config: dict[str, str] = {}
    for param in params:
        if "=" not in param:
            print(f"Error: invalid parameter format '{param}' (expected key=value)")
            sys.exit(1)
        key, value = param.split("=", 1)
        config[key] = value

    try:
        result = asyncio.run(registry.execute(module_name, config))
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

    if result.success:
        print(f"\n[OK] {module_name} completed in {result.duration_ms}ms")
        for key, value in result.data.items():
            print(f"  {key}: {value}")
    else:
        print(f"\n[FAIL] {module_name} failed in {result.duration_ms}ms")
        for err in result.errors:
            print(f"  ERROR: {err}")
        sys.exit(1)


def main() -> None:
    """Main entry point."""
    parser = build_parser()
    args = parser.parse_args()

    # Initialise config and logging
    cfg = get_config_manager()
    setup_logging(
        log_level=cfg.config.log_level,
        log_format=cfg.config.log_format,
    )

    # Launch-mode flags
    if args.tui:
        from src.tui.app import AtsApp

        AtsApp().run()
        return

    if args.web:
        subprocess.run(
            [sys.executable, "-m", "streamlit", "run", "src/streamlit_ui/app.py"],
            check=True,
        )
        return

    if args.api:
        import uvicorn

        uvicorn.run("src.api.main:app", host="0.0.0.0", port=8000, reload=True)
        return

    # Subcommands
    if args.command == "list":
        cmd_list()
        return

    if args.command == "run":
        cmd_run(args.module_name, args.param)
        return

    # Default: show help
    parser.print_help()


if __name__ == "__main__":
    main()

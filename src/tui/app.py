"""ATS-Toolkit Textual TUI Application.

A full-featured terminal user interface for browsing, configuring,
and executing ATS-Toolkit security modules.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime
from typing import Any, Optional

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, ScrollableContainer
from textual.widgets import Header, Footer, Tree, Static, Input, Button, RichLog, Label
from textual.screen import ModalScreen

from src.modules.registry import get_registry, ModuleRegistry
from src.core.base_module import ModuleSpec, ModuleCategory, Parameter, ParameterType


# ---------------------------------------------------------------------------
# Category display helpers
# ---------------------------------------------------------------------------

CATEGORY_ICONS: dict[ModuleCategory, str] = {
    ModuleCategory.OSINT: "[bold cyan]OSINT[/]",
    ModuleCategory.PENTEST: "[bold red]PENTEST[/]",
    ModuleCategory.RECON: "[bold green]RECON[/]",
    ModuleCategory.EXPLOIT: "[bold magenta]EXPLOIT[/]",
    ModuleCategory.POST_EXPLOIT: "[bold yellow]POST-EXPLOIT[/]",
    ModuleCategory.DEFENSE: "[bold blue]DEFENSE[/]",
    ModuleCategory.FORENSICS: "[bold white]FORENSICS[/]",
    ModuleCategory.CRYPTO: "[bold cyan]CRYPTO[/]",
    ModuleCategory.SOCIAL: "[bold magenta]SOCIAL[/]",
    ModuleCategory.WEB: "[bold green]WEB[/]",
    ModuleCategory.NETWORK: "[bold yellow]NETWORK[/]",
    ModuleCategory.WIRELESS: "[bold red]WIRELESS[/]",
    ModuleCategory.CLOUD: "[bold blue]CLOUD[/]",
    ModuleCategory.MOBILE: "[bold cyan]MOBILE[/]",
    ModuleCategory.RED_TEAM: "[bold red]RED-TEAM[/]",
    ModuleCategory.FUZZING: "[bold magenta]FUZZING[/]",
    ModuleCategory.ML_DETECTION: "[bold green]ML-DETECT[/]",
    ModuleCategory.MALWARE: "[bold red]MALWARE[/]",
    ModuleCategory.DECEPTION: "[bold yellow]DECEPTION[/]",
    ModuleCategory.CONTINUOUS_PENTEST: "[bold red]CONT-PENTEST[/]",
    ModuleCategory.ADVANCED: "[bold white]ADVANCED[/]",
    ModuleCategory.MISC: "[dim]MISC[/]",
}


def _category_label(cat: ModuleCategory, count: int) -> str:
    """Return a rich-text label for a category tree node."""
    icon = CATEGORY_ICONS.get(cat, cat.value.upper())
    return f"{icon}  ({count})"


# ---------------------------------------------------------------------------
# Modal screens
# ---------------------------------------------------------------------------

class HelpScreen(ModalScreen):
    """Overlay screen showing usage information."""

    BINDINGS = [
        Binding("escape", "dismiss", "Close"),
        Binding("f1", "dismiss", "Close"),
    ]

    DEFAULT_CSS = """
    HelpScreen {
        align: center middle;
    }
    #help-dialog {
        width: 72;
        height: auto;
        max-height: 80%;
        border: thick $accent;
        background: $surface;
        padding: 1 2;
    }
    #help-dialog Label {
        width: 100%;
        margin-bottom: 1;
    }
    #help-title {
        text-style: bold;
        color: $accent;
        text-align: center;
        width: 100%;
        margin-bottom: 1;
    }
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="help-dialog"):
            yield Label("ATS-Toolkit v2.0 -- Help", id="help-title")
            yield Label(
                "[bold]Navigation[/]\n"
                "  Up/Down        Browse module tree\n"
                "  Enter          Expand/collapse category or select module\n"
                "  Tab            Move focus between panels\n\n"
                "[bold]Actions[/]\n"
                "  Enter / Run    Execute the selected module\n"
                "  F1             Show this help screen\n"
                "  F2             Open settings screen\n"
                "  Ctrl+Q         Quit the application\n\n"
                "[bold]Module Configuration[/]\n"
                "  Select a module from the tree on the left.\n"
                "  Fill in the parameter fields in the config panel.\n"
                "  Press the [bold green]Run Module[/] button or Enter to execute.\n\n"
                "[bold]Results[/]\n"
                "  Execution output appears in the log panel at the bottom right.\n"
                "  Errors and warnings are highlighted.\n\n"
                "Press [bold]Escape[/] to close.",
            )
            yield Button("Close", variant="primary", id="help-close-btn")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "help-close-btn":
            self.dismiss()


class SettingsScreen(ModalScreen):
    """Overlay screen showing application settings and registry info."""

    BINDINGS = [
        Binding("escape", "dismiss", "Close"),
        Binding("f2", "dismiss", "Close"),
    ]

    DEFAULT_CSS = """
    SettingsScreen {
        align: center middle;
    }
    #settings-dialog {
        width: 72;
        height: auto;
        max-height: 80%;
        border: thick $accent;
        background: $surface;
        padding: 1 2;
    }
    #settings-title {
        text-style: bold;
        color: $accent;
        text-align: center;
        width: 100%;
        margin-bottom: 1;
    }
    """

    def __init__(self, registry: ModuleRegistry) -> None:
        super().__init__()
        self._registry = registry

    def compose(self) -> ComposeResult:
        categories = self._registry.list_categories()
        total = self._registry.count
        cat_lines = "\n".join(
            f"  {cat.value:<20s} {count} module(s)"
            for cat, count in sorted(categories.items(), key=lambda x: x[0].value)
        )
        with Vertical(id="settings-dialog"):
            yield Label("ATS-Toolkit v2.0 -- Settings", id="settings-title")
            yield Label(
                f"[bold]Registry Status[/]\n"
                f"  Total modules loaded: {total}\n"
                f"  Categories active:    {len(categories)}\n\n"
                f"[bold]Modules per Category[/]\n{cat_lines}\n\n"
                f"[bold]Environment[/]\n"
                f"  Application:  ATS-Toolkit v2.0\n"
                f"  Interface:    Textual TUI\n"
            )
            yield Button("Close", variant="primary", id="settings-close-btn")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "settings-close-btn":
            self.dismiss()


# ---------------------------------------------------------------------------
# Custom widgets
# ---------------------------------------------------------------------------

class ModuleConfigPanel(Static):
    """Panel that displays module spec details and parameter input fields."""

    DEFAULT_CSS = """
    ModuleConfigPanel {
        height: auto;
        padding: 1 2;
    }
    .config-section-title {
        text-style: bold;
        color: $accent;
        margin-bottom: 1;
    }
    .param-label {
        margin-top: 1;
        color: $text;
    }
    .param-hint {
        color: $text-muted;
        text-style: italic;
    }
    """

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._current_spec: Optional[ModuleSpec] = None
        self._param_inputs: dict[str, Input] = {}

    @property
    def current_spec(self) -> Optional[ModuleSpec]:
        return self._current_spec

    def get_param_values(self) -> dict[str, Any]:
        """Collect current parameter values from the input fields."""
        values: dict[str, Any] = {}
        if not self._current_spec:
            return values
        for param in self._current_spec.parameters:
            input_widget = self._param_inputs.get(param.name)
            if input_widget is None:
                continue
            raw = input_widget.value.strip()
            if not raw:
                if param.default is not None:
                    values[param.name] = param.default
                continue
            values[param.name] = self._cast_value(raw, param)
        return values

    @staticmethod
    def _cast_value(raw: str, param: Parameter) -> Any:
        """Attempt to cast a raw string to the parameter's declared type."""
        try:
            if param.type == ParameterType.INTEGER:
                return int(raw)
            elif param.type == ParameterType.FLOAT:
                return float(raw)
            elif param.type == ParameterType.BOOLEAN:
                return raw.lower() in ("true", "1", "yes", "on")
            elif param.type == ParameterType.LIST:
                if raw.startswith("["):
                    return json.loads(raw)
                return [s.strip() for s in raw.split(",") if s.strip()]
            elif param.type == ParameterType.DICT:
                return json.loads(raw)
            else:
                return raw
        except (ValueError, json.JSONDecodeError):
            return raw

    async def show_spec(self, spec: ModuleSpec) -> None:
        """Render the config form for a given module spec."""
        self._current_spec = spec
        self._param_inputs.clear()
        await self.remove_children()

        # Module header
        await self.mount(
            Label(
                f"[bold]{spec.name}[/]  [dim]v{spec.version}[/]"
                + (f"  [bold red]DANGEROUS[/]" if spec.dangerous else ""),
                classes="config-section-title",
            )
        )
        await self.mount(Label(spec.description))

        if spec.requires_api_key:
            await self.mount(
                Label(
                    f"[bold yellow]Requires API key:[/] {spec.api_key_service or 'unknown'}",
                    classes="param-hint",
                )
            )

        if spec.tags:
            await self.mount(
                Label(f"[dim]Tags: {', '.join(spec.tags)}[/]", classes="param-hint")
            )

        # Parameters section
        if spec.parameters:
            await self.mount(
                Label("\n[bold]Parameters[/]", classes="config-section-title")
            )
            for param in spec.parameters:
                req_marker = "[bold red]*[/] " if param.required else ""
                type_hint = param.type.value
                if param.choices:
                    type_hint += f" ({', '.join(param.choices)})"
                await self.mount(
                    Label(
                        f"{req_marker}{param.name}  [dim]{type_hint}[/]",
                        classes="param-label",
                    )
                )
                if param.description:
                    await self.mount(
                        Label(f"  {param.description}", classes="param-hint")
                    )
                placeholder = ""
                if param.default is not None:
                    placeholder = str(param.default)
                elif param.choices:
                    placeholder = " | ".join(param.choices)
                input_widget = Input(
                    placeholder=placeholder or f"Enter {param.type.value}",
                    id=f"param-{param.name}",
                )
                self._param_inputs[param.name] = input_widget
                await self.mount(input_widget)
        else:
            await self.mount(
                Label("[dim]This module has no configurable parameters.[/]")
            )

        # Run button
        await self.mount(
            Button(
                "Run Module",
                variant="success",
                id="run-module-btn",
            )
        )

    async def show_empty(self) -> None:
        """Show placeholder when no module is selected."""
        self._current_spec = None
        self._param_inputs.clear()
        await self.remove_children()
        await self.mount(
            Label(
                "[dim]Select a module from the tree to view its configuration.[/]",
                classes="config-section-title",
            )
        )


# ---------------------------------------------------------------------------
# Main application
# ---------------------------------------------------------------------------

class AtsApp(App):
    """ATS-Toolkit Terminal User Interface."""

    TITLE = "ATS-Toolkit v2.0"
    SUB_TITLE = "Security Toolkit TUI"

    CSS = """
    /* ---- Layout ---- */
    #main-container {
        width: 100%;
        height: 100%;
    }

    #sidebar {
        width: 34;
        min-width: 28;
        height: 100%;
        border-right: thick $accent;
        overflow-y: auto;
    }

    #sidebar-title {
        text-style: bold;
        color: $accent;
        text-align: center;
        width: 100%;
        padding: 1 0;
    }

    #module-tree {
        width: 100%;
        height: 1fr;
        scrollbar-gutter: stable;
    }

    #right-panel {
        width: 1fr;
        height: 100%;
    }

    #config-scroll {
        height: 1fr;
        min-height: 12;
        border-bottom: thick $accent;
    }

    #config-panel {
        width: 100%;
        height: auto;
    }

    #log-panel-header {
        text-style: bold;
        color: $accent;
        padding: 0 2;
        height: 1;
        dock: top;
    }

    #result-log {
        height: 1fr;
        min-height: 8;
        padding: 0 1;
    }

    /* ---- Misc ---- */
    Button {
        margin: 1 2;
    }
    """

    BINDINGS = [
        Binding("f1", "show_help", "Help", show=True),
        Binding("f2", "show_settings", "Settings", show=True),
        Binding("ctrl+q", "quit", "Quit", show=True),
        Binding("enter", "run_selected", "Run", show=True, priority=False),
    ]

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._mod_registry: ModuleRegistry = get_registry()
        self._selected_module: Optional[str] = None
        self._executing: bool = False

    # -- Compose ---------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="main-container"):
            with Vertical(id="sidebar"):
                yield Label("Modules", id="sidebar-title")
                yield Tree("ATS-Toolkit", id="module-tree")
            with Vertical(id="right-panel"):
                with ScrollableContainer(id="config-scroll"):
                    yield ModuleConfigPanel(id="config-panel")
                yield Label("Execution Log", id="log-panel-header")
                yield RichLog(id="result-log", highlight=True, markup=True)
        yield Footer()

    # -- Lifecycle -------------------------------------------------------------

    async def on_mount(self) -> None:
        """Discover modules and populate the tree on startup."""
        log: RichLog = self.query_one("#result-log", RichLog)
        log.write("[bold cyan]ATS-Toolkit v2.0[/] -- TUI started")
        log.write(f"[dim]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/]")
        log.write("")

        # Discover modules
        try:
            count = self._mod_registry.discover()
            log.write(f"[green]Registry discovery complete:[/] {count} module(s) loaded.")
        except Exception as exc:
            log.write(f"[bold red]Discovery error:[/] {exc}")
            count = 0

        # Build tree
        self._build_module_tree()

        if count == 0:
            log.write(
                "[yellow]No modules found. "
                "Ensure module files exist under src/modules/<category>/.[/]"
            )

        # Show empty config
        config_panel: ModuleConfigPanel = self.query_one("#config-panel", ModuleConfigPanel)
        await config_panel.show_empty()

    def _build_module_tree(self) -> None:
        """Populate the sidebar tree with categories and modules."""
        tree: Tree = self.query_one("#module-tree", Tree)
        tree.clear()
        tree.root.expand()

        categories = self._mod_registry.list_categories()
        for cat in sorted(categories, key=lambda c: c.value):
            count = categories[cat]
            label = _category_label(cat, count)
            cat_node = tree.root.add(label, expand=False)
            cat_node.data = {"type": "category", "category": cat}

            modules = self._mod_registry.list_modules(category=cat)
            for mod_spec in modules:
                danger_mark = " [bold red]![/]" if mod_spec.dangerous else ""
                leaf = cat_node.add_leaf(f"{mod_spec.name}{danger_mark}")
                leaf.data = {"type": "module", "name": mod_spec.name}

    # -- Tree selection --------------------------------------------------------

    async def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        """Handle module selection in the tree."""
        node_data = event.node.data
        if node_data is None:
            return

        if node_data.get("type") == "module":
            module_name = node_data["name"]
            await self._select_module(module_name)

    async def _select_module(self, name: str) -> None:
        """Display the selected module's configuration form."""
        self._selected_module = name
        config_panel: ModuleConfigPanel = self.query_one("#config-panel", ModuleConfigPanel)
        log: RichLog = self.query_one("#result-log", RichLog)
        try:
            spec = self._mod_registry.get_spec(name)
            await config_panel.show_spec(spec)
            log.write(f"[cyan]Selected module:[/] {spec.name} v{spec.version}")
        except Exception as exc:
            log.write(f"[bold red]Error loading module spec:[/] {exc}")
            await config_panel.show_empty()
            self._selected_module = None

    # -- Execution -------------------------------------------------------------

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses (Run Module)."""
        if event.button.id == "run-module-btn":
            await self._execute_selected_module()

    async def action_run_selected(self) -> None:
        """Action triggered by Enter key binding."""
        # Only run if a module is selected and focus is not on an Input
        focused = self.focused
        if isinstance(focused, Input):
            return  # let the Input handle Enter normally
        await self._execute_selected_module()

    async def _execute_selected_module(self) -> None:
        """Execute the currently selected module with parameters from the form."""
        if self._executing:
            return
        if not self._selected_module:
            self._log_message("[yellow]No module selected. Pick one from the tree first.[/]")
            return

        config_panel: ModuleConfigPanel = self.query_one("#config-panel", ModuleConfigPanel)
        log: RichLog = self.query_one("#result-log", RichLog)
        module_name = self._selected_module

        # Gather parameters
        params = config_panel.get_param_values()

        # Visual feedback
        self._executing = True
        log.write("")
        log.write(f"[bold]{'=' * 60}[/]")
        log.write(
            f"[bold green]Executing:[/] {module_name}  "
            f"[dim]{datetime.now().strftime('%H:%M:%S')}[/]"
        )
        if params:
            log.write(f"[dim]Parameters: {json.dumps(params, default=str)}[/]")
        log.write("")

        try:
            result = await self._mod_registry.execute(module_name, params, timeout=120)

            if result.success:
                log.write(f"[bold green]SUCCESS[/]  ({result.duration_ms} ms)")
            else:
                log.write(f"[bold red]FAILED[/]  ({result.duration_ms} ms)")

            # Errors
            for err in result.errors:
                log.write(f"  [red]ERROR:[/] {err}")

            # Warnings
            for warn in result.warnings:
                log.write(f"  [yellow]WARN:[/] {warn}")

            # Data
            if result.data:
                log.write("[bold]Result data:[/]")
                self._write_data_to_log(log, result.data)

        except Exception as exc:
            log.write(f"[bold red]Execution exception:[/] {type(exc).__name__}: {exc}")

        finally:
            self._executing = False
            log.write(f"[bold]{'=' * 60}[/]")
            log.write("")

    def _write_data_to_log(self, log: RichLog, data: dict[str, Any], indent: int = 2) -> None:
        """Pretty-print result data dict into the log widget."""
        prefix = " " * indent
        for key, value in data.items():
            if isinstance(value, dict):
                log.write(f"{prefix}[bold]{key}:[/]")
                self._write_data_to_log(log, value, indent + 2)
            elif isinstance(value, list):
                log.write(f"{prefix}[bold]{key}:[/] ({len(value)} items)")
                for i, item in enumerate(value[:20]):  # cap at 20 items
                    if isinstance(item, dict):
                        log.write(f"{prefix}  [{i}]:")
                        self._write_data_to_log(log, item, indent + 4)
                    else:
                        log.write(f"{prefix}  - {item}")
                if len(value) > 20:
                    log.write(f"{prefix}  ... and {len(value) - 20} more")
            else:
                log.write(f"{prefix}[bold]{key}:[/] {value}")

    def _log_message(self, message: str) -> None:
        """Write a single message to the result log."""
        try:
            log: RichLog = self.query_one("#result-log", RichLog)
            log.write(message)
        except Exception:
            pass

    # -- Actions ---------------------------------------------------------------

    def action_show_help(self) -> None:
        """Open the help overlay screen."""
        self.push_screen(HelpScreen())

    def action_show_settings(self) -> None:
        """Open the settings overlay screen."""
        self.push_screen(SettingsScreen(self._mod_registry))


# ---------------------------------------------------------------------------
# Entry-point
# ---------------------------------------------------------------------------

def run_tui() -> None:
    """Launch the ATS-Toolkit TUI application."""
    app = AtsApp()
    app.run()


if __name__ == "__main__":
    run_tui()

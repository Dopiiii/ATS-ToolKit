"""ATS-Toolkit Streamlit Web Dashboard.

Run with:
    streamlit run src/streamlit_ui/app.py
"""

import streamlit as st
import asyncio
import json
import csv
import io
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Ensure project root is on sys.path so `src.*` imports resolve when running
# with  `streamlit run src/streamlit_ui/app.py`  from the project root.
# ---------------------------------------------------------------------------
_PROJECT_ROOT = str(Path(__file__).resolve().parents[2])
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from src.modules.registry import get_registry, ModuleRegistry
from src.core.base_module import (
    ModuleSpec,
    ModuleCategory,
    ParameterType,
    Parameter,
    ExecutionResult,
)

# ---------------------------------------------------------------------------
# Page configuration
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="ATS-Toolkit",
    page_icon="\U0001f512",  # lock emoji
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Custom CSS
# ---------------------------------------------------------------------------
st.markdown(
    """
    <style>
    /* Sidebar header styling */
    .sidebar-title {
        font-size: 1.6rem;
        font-weight: 700;
        padding-bottom: 0.4rem;
        border-bottom: 2px solid #4e8cff;
        margin-bottom: 1rem;
    }
    /* Danger badge */
    .danger-badge {
        background-color: #ff4b4b;
        color: white;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 0.8rem;
        font-weight: 600;
    }
    /* Tag chip */
    .tag-chip {
        display: inline-block;
        background-color: #262730;
        color: #fafafa;
        padding: 2px 10px;
        border-radius: 12px;
        font-size: 0.75rem;
        margin: 2px 2px;
        border: 1px solid #4e8cff;
    }
    /* Status indicators */
    .status-success {
        color: #09ab3b;
        font-weight: 600;
    }
    .status-failure {
        color: #ff4b4b;
        font-weight: 600;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Registry initialisation (cached so discovery only happens once)
# ---------------------------------------------------------------------------


@st.cache_resource(show_spinner="Discovering modules ...")
def init_registry() -> ModuleRegistry:
    """Create the module registry and run discovery once."""
    registry = get_registry()
    registry.discover()
    return registry


registry = init_registry()

# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------


def _categories_with_modules(reg: ModuleRegistry) -> List[ModuleCategory]:
    """Return only categories that actually contain registered modules."""
    cat_counts = reg.list_categories()
    return sorted(cat_counts.keys(), key=lambda c: c.value)


def _run_async(coro):
    """Run an async coroutine from synchronous Streamlit context."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # Inside an already-running loop (e.g. Jupyter / some Streamlit
            # deployments). Create a new loop in a thread to avoid nesting.
            import concurrent.futures

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                return pool.submit(asyncio.run, coro).result()
        else:
            return loop.run_until_complete(coro)
    except RuntimeError:
        return asyncio.run(coro)


def _render_tags(tags: List[str]) -> str:
    """Return HTML for a list of tag chips."""
    if not tags:
        return ""
    chips = "".join(f'<span class="tag-chip">{t}</span>' for t in tags)
    return chips


def _result_to_flat_rows(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Best-effort conversion of result data to a flat list of dicts for CSV."""
    # If data already contains a list of dicts, use that directly
    for value in data.values():
        if isinstance(value, list) and value and isinstance(value[0], dict):
            return value
    # Fallback: single row with top-level keys
    return [data]


def _build_csv_bytes(rows: List[Dict[str, Any]]) -> bytes:
    """Convert a list of flat dicts to CSV bytes."""
    if not rows:
        return b""
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    for row in rows:
        writer.writerow({k: json.dumps(v) if isinstance(v, (dict, list)) else v for k, v in row.items()})
    return buf.getvalue().encode("utf-8")


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------
with st.sidebar:
    st.markdown('<div class="sidebar-title">\U0001f512 ATS-Toolkit</div>', unsafe_allow_html=True)
    st.caption(f"{registry.count} modules loaded")

    # --- Search -----------------------------------------------------------
    search_query = st.text_input("Search modules", placeholder="e.g. nmap, phishing, osint ...")
    if search_query:
        search_results = registry.search(search_query)
        if search_results:
            search_names = [s.name for s in search_results]
            selected_module_name = st.selectbox(
                "Search results",
                search_names,
                key="search_select",
            )
        else:
            st.info("No modules match your search.")
            selected_module_name = None
    else:
        # --- Category selector ------------------------------------------------
        categories = _categories_with_modules(registry)

        if not categories:
            st.warning("No modules discovered. Check the modules directory.")
            st.stop()

        category_labels = {c: f"{c.value.replace('_', ' ').title()} ({len(registry.list_modules(category=c))})" for c in categories}
        selected_category = st.selectbox(
            "Category",
            categories,
            format_func=lambda c: category_labels[c],
        )

        # --- Module selector --------------------------------------------------
        modules_in_cat = registry.list_modules(category=selected_category)
        module_names = [m.name for m in modules_in_cat]

        if not module_names:
            st.info("No modules in this category.")
            st.stop()

        selected_module_name = st.selectbox("Module", module_names)

    if selected_module_name is None:
        st.stop()

    # --- Module info card -----------------------------------------------------
    spec: ModuleSpec = registry.get_spec(selected_module_name)

    st.divider()
    st.markdown(f"**Version:** `{spec.version}`")
    st.markdown(f"**Author:** {spec.author}")

    if spec.dangerous:
        st.markdown('<span class="danger-badge">DANGEROUS</span>', unsafe_allow_html=True)

    if spec.requires_api_key:
        st.markdown(f"**Requires API key:** `{spec.api_key_service or 'yes'}`")

    if spec.tags:
        st.markdown("**Tags:**")
        st.markdown(_render_tags(spec.tags), unsafe_allow_html=True)

    if spec.outputs:
        with st.expander("Output fields"):
            for out in spec.outputs:
                st.markdown(f"- **{out.name}** (*{out.type}*) -- {out.description}")

# ---------------------------------------------------------------------------
# Main area -- header
# ---------------------------------------------------------------------------
st.title(f"{spec.name}")
st.markdown(spec.description)

if spec.dangerous:
    st.warning(
        "This module is marked as **dangerous**. It may perform intrusive or "
        "destructive actions. Use responsibly and only on systems you own or "
        "have explicit permission to test."
    )

st.divider()

# ---------------------------------------------------------------------------
# Dynamic parameter form
# ---------------------------------------------------------------------------
st.subheader("Parameters")

param_values: Dict[str, Any] = {}

if not spec.parameters:
    st.info("This module does not require any parameters.")
else:
    # Use a two-column layout for parameters
    col_left, col_right = st.columns(2)
    columns = [col_left, col_right]

    for idx, param in enumerate(spec.parameters):
        col = columns[idx % 2]
        with col:
            label = param.name.replace("_", " ").title()
            if param.required:
                label += " *"
            help_text = param.description or None

            if param.type == ParameterType.BOOLEAN:
                default_bool = bool(param.default) if param.default is not None else False
                param_values[param.name] = st.checkbox(
                    label,
                    value=default_bool,
                    help=help_text,
                    key=f"param_{spec.name}_{param.name}",
                )

            elif param.type == ParameterType.INTEGER:
                default_int = int(param.default) if param.default is not None else 0
                kwargs: Dict[str, Any] = {"label": label, "value": default_int, "help": help_text, "key": f"param_{spec.name}_{param.name}"}
                if param.min_value is not None:
                    kwargs["min_value"] = int(param.min_value)
                if param.max_value is not None:
                    kwargs["max_value"] = int(param.max_value)
                param_values[param.name] = st.number_input(**kwargs)

            elif param.type == ParameterType.FLOAT:
                default_float = float(param.default) if param.default is not None else 0.0
                kwargs = {"label": label, "value": default_float, "step": 0.1, "help": help_text, "key": f"param_{spec.name}_{param.name}"}
                if param.min_value is not None:
                    kwargs["min_value"] = float(param.min_value)
                if param.max_value is not None:
                    kwargs["max_value"] = float(param.max_value)
                param_values[param.name] = st.number_input(**kwargs)

            elif param.type == ParameterType.CHOICE:
                choices = param.choices or []
                default_idx = 0
                if param.default and param.default in choices:
                    default_idx = choices.index(param.default)
                param_values[param.name] = st.selectbox(
                    label,
                    options=choices,
                    index=default_idx,
                    help=help_text,
                    key=f"param_{spec.name}_{param.name}",
                )

            elif param.type == ParameterType.FILE:
                uploaded = st.file_uploader(
                    label,
                    help=help_text,
                    key=f"param_{spec.name}_{param.name}",
                )
                param_values[param.name] = uploaded.name if uploaded else (param.default or "")

            elif param.type == ParameterType.LIST:
                raw = st.text_area(
                    label,
                    value=", ".join(param.default) if isinstance(param.default, list) else (param.default or ""),
                    help=(help_text or "") + " (comma-separated values)",
                    key=f"param_{spec.name}_{param.name}",
                )
                param_values[param.name] = [v.strip() for v in raw.split(",") if v.strip()] if raw else []

            elif param.type == ParameterType.DICT:
                raw_json = st.text_area(
                    label,
                    value=json.dumps(param.default) if isinstance(param.default, dict) else (param.default or "{}"),
                    help=(help_text or "") + " (JSON object)",
                    key=f"param_{spec.name}_{param.name}",
                )
                try:
                    param_values[param.name] = json.loads(raw_json) if raw_json else {}
                except json.JSONDecodeError:
                    st.error(f"Invalid JSON for **{param.name}**")
                    param_values[param.name] = {}

            else:
                # STRING, URL, DOMAIN, IP, EMAIL -- all rendered as text input
                placeholder_map = {
                    ParameterType.URL: "https://example.com",
                    ParameterType.DOMAIN: "example.com",
                    ParameterType.IP: "192.168.1.1",
                    ParameterType.EMAIL: "user@example.com",
                    ParameterType.STRING: "",
                }
                placeholder = placeholder_map.get(param.type, "")
                default_str = str(param.default) if param.default is not None else ""
                param_values[param.name] = st.text_input(
                    label,
                    value=default_str,
                    placeholder=placeholder,
                    help=help_text,
                    key=f"param_{spec.name}_{param.name}",
                )

# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------
st.divider()

run_col, timeout_col, _ = st.columns([2, 2, 6])
with timeout_col:
    timeout = st.number_input("Timeout (s)", min_value=5, max_value=600, value=60, step=5)
with run_col:
    execute_clicked = st.button(
        "Execute Module",
        type="primary",
        use_container_width=True,
    )

if execute_clicked:
    # Check required parameters are filled
    missing = []
    for param in spec.parameters:
        if param.required:
            val = param_values.get(param.name)
            if val is None or val == "" or val == [] or val == {}:
                missing.append(param.name)

    if missing:
        st.error(f"Missing required parameters: **{', '.join(missing)}**")
    else:
        with st.spinner(f"Running {spec.name} ..."):
            result: ExecutionResult = _run_async(
                registry.execute(selected_module_name, param_values, timeout=int(timeout))
            )

        # Store result in session state for export
        st.session_state["last_result"] = result
        st.session_state["last_module"] = spec.name

# ---------------------------------------------------------------------------
# Results display
# ---------------------------------------------------------------------------
if "last_result" in st.session_state and st.session_state.get("last_module") == spec.name:
    result: ExecutionResult = st.session_state["last_result"]

    st.divider()
    st.subheader("Results")

    # Status row
    status_col, duration_col, ts_col = st.columns(3)
    with status_col:
        if result.success:
            st.markdown(':green[**SUCCESS**]')
        else:
            st.markdown(':red[**FAILURE**]')
    with duration_col:
        st.metric("Duration", f"{result.duration_ms} ms")
    with ts_col:
        st.metric("Timestamp", result.timestamp[:19] if result.timestamp else "N/A")

    # Errors
    if result.errors:
        st.subheader("Errors")
        for err in result.errors:
            st.error(err)

    # Warnings
    if result.warnings:
        st.subheader("Warnings")
        for warn in result.warnings:
            st.warning(warn)

    # Data
    if result.data:
        tab_json, tab_table, tab_raw = st.tabs(["JSON", "Table", "Raw"])

        with tab_json:
            st.json(result.data, expanded=True)

        with tab_table:
            try:
                rows = _result_to_flat_rows(result.data)
                st.dataframe(rows, use_container_width=True)
            except Exception:
                st.info("Data could not be displayed as a table.")

        with tab_raw:
            st.code(json.dumps(result.data, indent=2, default=str), language="json")

        # ------------------------------------------------------------------
        # Export options
        # ------------------------------------------------------------------
        st.subheader("Export")
        export_col_json, export_col_csv = st.columns(2)

        json_bytes = json.dumps(
            {
                "module": result.module_name,
                "success": result.success,
                "duration_ms": result.duration_ms,
                "timestamp": result.timestamp,
                "data": result.data,
                "errors": result.errors,
                "warnings": result.warnings,
            },
            indent=2,
            default=str,
        ).encode("utf-8")

        with export_col_json:
            st.download_button(
                "Download JSON",
                data=json_bytes,
                file_name=f"{result.module_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json",
                use_container_width=True,
            )

        with export_col_csv:
            try:
                csv_bytes = _build_csv_bytes(_result_to_flat_rows(result.data))
                st.download_button(
                    "Download CSV",
                    data=csv_bytes,
                    file_name=f"{result.module_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv",
                    use_container_width=True,
                )
            except Exception:
                st.download_button(
                    "Download CSV",
                    data=b"",
                    file_name="empty.csv",
                    mime="text/csv",
                    disabled=True,
                    use_container_width=True,
                )
                st.caption("CSV export not available for this data shape.")
    else:
        st.info("Module returned no data.")

# ---------------------------------------------------------------------------
# Footer
# ---------------------------------------------------------------------------
st.divider()
st.caption("ATS-Toolkit -- Security Testing Dashboard")

"""ATS-Toolkit Streamlit Web Interface.

Modern web UI for ATS-Toolkit with real-time execution and results visualization.
"""

import streamlit as st
import asyncio
import json
import pandas as pd
from datetime import datetime
from pathlib import Path
import sys

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.core.config_manager import get_config, init_config
from src.core.logger import setup_logging, get_logger
from src.core.base_module import ModuleCategory
from src.modules.registry import get_registry


# Page config
st.set_page_config(
    page_title="ATS-Toolkit v2.0",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        margin-bottom: 0.5rem;
    }
    .sub-header {
        font-size: 1.2rem;
        color: #666;
        margin-bottom: 2rem;
    }
    .module-card {
        padding: 1rem;
        border-radius: 0.5rem;
        border: 1px solid #ddd;
        margin-bottom: 1rem;
    }
    .success-box {
        padding: 1rem;
        background-color: #d4edda;
        border-left: 4px solid #28a745;
        border-radius: 0.25rem;
        margin: 1rem 0;
    }
    .error-box {
        padding: 1rem;
        background-color: #f8d7da;
        border-left: 4px solid #dc3545;
        border-radius: 0.25rem;
        margin: 1rem 0;
    }
    .info-box {
        padding: 1rem;
        background-color: #d1ecf1;
        border-left: 4px solid #17a2b8;
        border-radius: 0.25rem;
        margin: 1rem 0;
    }
    .metric-card {
        background-color: #f8f9fa;
        padding: 1rem;
        border-radius: 0.5rem;
        text-align: center;
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 2rem;
    }
</style>
""", unsafe_allow_html=True)


# Initialize
@st.cache_resource
def init_app():
    """Initialize application resources."""
    init_config()
    setup_logging(level="INFO", console=False)
    registry = get_registry()
    registry.discover()
    return registry


def render_sidebar():
    """Render sidebar with module selection."""
    st.sidebar.markdown("### 🛡️ ATS-Toolkit v2.0")
    st.sidebar.markdown("**Modular Cybersecurity Framework**")
    st.sidebar.markdown("---")

    registry = st.session_state.registry

    # Search
    search_query = st.sidebar.text_input("🔍 Search modules", "")

    # Category filter
    categories = registry.list_categories()
    category_options = ["All"] + [cat.value.upper() for cat in categories.keys()]
    selected_category = st.sidebar.selectbox(
        "Category",
        category_options,
        key="category_filter"
    )

    # Get modules
    if search_query:
        modules = registry.search(search_query)
    elif selected_category == "All":
        modules = registry.list_modules()
    else:
        cat = ModuleCategory(selected_category.lower())
        modules = registry.list_modules(category=cat)

    # Display modules
    st.sidebar.markdown("---")
    st.sidebar.markdown(f"**Modules ({len(modules)})**")

    for spec in modules:
        api_indicator = " 🔑" if spec.requires_api_key else ""
        if st.sidebar.button(
            f"{spec.name}{api_indicator}",
            key=f"select_{spec.name}",
            help=spec.description
        ):
            st.session_state.selected_module = spec.name

    # Settings
    st.sidebar.markdown("---")
    if st.sidebar.button("⚙️ Settings"):
        st.session_state.show_settings = True

    # Stats
    st.sidebar.markdown("---")
    st.sidebar.markdown("**Statistics**")
    st.sidebar.metric("Total Modules", registry.count)
    for cat, count in sorted(categories.items(), key=lambda x: -x[1])[:5]:
        st.sidebar.metric(cat.value.upper(), count)


def render_settings():
    """Render settings page."""
    st.markdown('<div class="main-header">⚙️ Settings</div>', unsafe_allow_html=True)

    config = get_config()

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("### General Settings")

        log_level = st.selectbox(
            "Log Level",
            ["DEBUG", "INFO", "WARNING", "ERROR"],
            index=["DEBUG", "INFO", "WARNING", "ERROR"].index(config.config.log_level)
        )

        threads = st.number_input(
            "Concurrent Threads",
            min_value=1,
            max_value=100,
            value=config.config.threads
        )

        timeout = st.number_input(
            "Default Timeout (seconds)",
            min_value=10,
            max_value=300,
            value=config.config.timeout
        )

    with col2:
        st.markdown("### API Keys")

        shodan_key = st.text_input(
            "Shodan API Key",
            value=config.get_api_key("shodan") or "",
            type="password"
        )

        hunter_key = st.text_input(
            "Hunter.io API Key",
            value=config.get_api_key("hunter") or "",
            type="password"
        )

        virustotal_key = st.text_input(
            "VirusTotal API Key",
            value=config.get_api_key("virustotal") or "",
            type="password"
        )

        hibp_key = st.text_input(
            "HIBP API Key",
            value=config.get_api_key("hibp") or "",
            type="password"
        )

    if st.button("💾 Save Settings", type="primary"):
        config.set("log_level", log_level, persist=True)
        config.set("threads", threads, persist=True)
        config.set("timeout", timeout, persist=True)

        if shodan_key:
            config.set_api_key("shodan", shodan_key)
        if hunter_key:
            config.set_api_key("hunter", hunter_key)
        if virustotal_key:
            config.set_api_key("virustotal", virustotal_key)
        if hibp_key:
            config.set_api_key("hibp", hibp_key)

        st.success("✅ Settings saved successfully!")
        st.session_state.show_settings = False
        st.rerun()

    if st.button("← Back"):
        st.session_state.show_settings = False
        st.rerun()


def render_module_config(spec):
    """Render module configuration form."""
    st.markdown(f'<div class="main-header">{spec.name}</div>', unsafe_allow_html=True)
    st.markdown(f'<div class="sub-header">{spec.description}</div>', unsafe_allow_html=True)

    # Module info
    with st.expander("ℹ️ Module Information", expanded=False):
        col1, col2, col3 = st.columns(3)
        col1.metric("Category", spec.category.value.upper())
        col2.metric("Version", spec.version)
        col3.metric("Parameters", len(spec.parameters))

        if spec.requires_api_key:
            st.warning(f"🔑 This module requires API key: **{spec.requires_api_key}**")

        if spec.external_tools:
            st.info(f"🔧 External tools: {', '.join(spec.external_tools)}")

        if spec.tags:
            st.markdown(f"**Tags:** {', '.join(spec.tags)}")

    # Configuration form
    st.markdown("### Configuration")

    config = {}

    for param in spec.parameters:
        label = f"{param.name}"
        if param.required:
            label += " *"

        help_text = param.description
        if param.default:
            help_text += f" (Default: {param.default})"

        if param.type == ParameterType.CHOICE:
            value = st.selectbox(
                label,
                param.choices,
                index=param.choices.index(param.default) if param.default in param.choices else 0,
                help=help_text,
                key=f"param_{param.name}"
            )
        elif param.type == ParameterType.BOOLEAN:
            value = st.checkbox(
                label,
                value=param.default or False,
                help=help_text,
                key=f"param_{param.name}"
            )
        elif param.type == ParameterType.INTEGER:
            value = st.number_input(
                label,
                min_value=int(param.min_value) if param.min_value else None,
                max_value=int(param.max_value) if param.max_value else None,
                value=int(param.default) if param.default else 0,
                help=help_text,
                key=f"param_{param.name}"
            )
        else:
            value = st.text_input(
                label,
                value=str(param.default) if param.default else "",
                help=help_text,
                key=f"param_{param.name}"
            )

        if value:
            config[param.name] = value

    return config


def render_results(result):
    """Render module execution results."""
    st.markdown("### 📊 Results")

    if result.success:
        st.markdown(
            f'<div class="success-box">✅ Module executed successfully in {result.duration_ms}ms</div>',
            unsafe_allow_html=True
        )

        # Tabs for different views
        tab1, tab2, tab3 = st.tabs(["📋 Summary", "🔍 Detailed", "📥 Export"])

        with tab1:
            # Render summary
            render_summary(result.data)

        with tab2:
            # Detailed JSON view
            st.json(result.data)

        with tab3:
            # Export options
            col1, col2 = st.columns(2)

            with col1:
                json_str = json.dumps(result.data, indent=2)
                st.download_button(
                    "📥 Download JSON",
                    json_str,
                    file_name=f"ats_result_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json"
                )

            with col2:
                # Convert to DataFrame if possible
                try:
                    df = pd.json_normalize(result.data)
                    csv = df.to_csv(index=False)
                    st.download_button(
                        "📥 Download CSV",
                        csv,
                        file_name=f"ats_result_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                        mime="text/csv"
                    )
                except:
                    st.info("CSV export not available for this result format")

    else:
        st.markdown(
            f'<div class="error-box">❌ Module execution failed</div>',
            unsafe_allow_html=True
        )

        st.markdown("**Errors:**")
        for error in result.errors:
            st.error(error)

        if result.warnings:
            st.markdown("**Warnings:**")
            for warning in result.warnings:
                st.warning(warning)


def render_summary(data):
    """Render smart summary of results."""
    # Try to extract key metrics
    if isinstance(data, dict):
        # Look for common patterns
        if "summary" in data:
            st.markdown("#### Summary")
            summary = data["summary"]
            if isinstance(summary, dict):
                cols = st.columns(min(len(summary), 4))
                for i, (key, value) in enumerate(summary.items()):
                    cols[i % 4].metric(key.replace("_", " ").title(), value)

        # Look for lists of findings
        for key in ["findings", "results", "breaches", "snapshots", "records", "vulnerabilities"]:
            if key in data and isinstance(data[key], list):
                st.markdown(f"#### {key.title()} ({len(data[key])})")
                if data[key]:
                    df = pd.DataFrame(data[key])
                    st.dataframe(df, use_container_width=True)

        # Look for nested data
        for key, value in data.items():
            if isinstance(value, dict) and key not in ["summary"]:
                with st.expander(f"📁 {key.replace('_', ' ').title()}"):
                    st.json(value)

    else:
        st.write(data)


def main():
    """Main application."""
    # Initialize session state
    if "registry" not in st.session_state:
        st.session_state.registry = init_app()

    if "selected_module" not in st.session_state:
        st.session_state.selected_module = None

    if "show_settings" not in st.session_state:
        st.session_state.show_settings = False

    if "last_result" not in st.session_state:
        st.session_state.last_result = None

    # Render sidebar
    render_sidebar()

    # Main content
    if st.session_state.show_settings:
        render_settings()
        return

    if st.session_state.selected_module:
        registry = st.session_state.registry

        try:
            spec = registry.get_spec(st.session_state.selected_module)

            # Render module configuration
            config = render_module_config(spec)

            # Execute button
            col1, col2 = st.columns([1, 5])
            with col1:
                execute = st.button("▶️ Execute", type="primary", use_container_width=True)
            with col2:
                clear = st.button("🗑️ Clear", use_container_width=True)

            if clear:
                st.session_state.selected_module = None
                st.session_state.last_result = None
                st.rerun()

            if execute:
                with st.spinner(f"Executing {spec.name}..."):
                    # Execute module
                    result = asyncio.run(registry.execute(spec.name, config))
                    st.session_state.last_result = result

            # Show results if available
            if st.session_state.last_result:
                render_results(st.session_state.last_result)

        except Exception as e:
            st.error(f"Error loading module: {e}")

    else:
        # Welcome page
        st.markdown('<div class="main-header">🛡️ ATS-Toolkit v2.0</div>', unsafe_allow_html=True)
        st.markdown(
            '<div class="sub-header">Modular Cybersecurity Framework - 144 Tools</div>',
            unsafe_allow_html=True
        )

        st.markdown("---")

        # Quick stats
        registry = st.session_state.registry
        categories = registry.list_categories()

        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total Modules", registry.count)
        col2.metric("Categories", len(categories))
        col3.metric("OSINT Modules", categories.get(ModuleCategory.OSINT, 0))
        col4.metric("Pentest Modules", categories.get(ModuleCategory.PENTEST, 0))

        st.markdown("---")

        # Getting started
        st.markdown("### 🚀 Getting Started")

        st.markdown("""
        1. **Select a module** from the sidebar
        2. **Configure parameters** as needed
        3. **Execute** and view results
        4. **Export** results in JSON or CSV format

        **Categories:**
        - 🔍 **OSINT**: Reconnaissance and information gathering
        - 🎯 **Pentest**: Web application security testing
        - 🔴 **Red Team**: Advanced offensive security
        - 🔬 **Forensics**: Digital forensics and analysis
        - 🧪 **Fuzzing**: Automated vulnerability discovery
        - 🤖 **ML Detection**: Machine learning threat detection
        """)

        st.markdown("---")

        # Recent modules
        st.markdown("### 📌 Featured Modules")

        featured = [
            "domain_recon",
            "sql_injection_scanner",
            "breach_check",
            "port_scanner",
        ]

        cols = st.columns(2)
        for i, module_name in enumerate(featured):
            try:
                spec = registry.get_spec(module_name)
                with cols[i % 2]:
                    with st.container():
                        st.markdown(f"**{spec.name}**")
                        st.markdown(spec.description)
                        if st.button(f"Open →", key=f"featured_{module_name}"):
                            st.session_state.selected_module = module_name
                            st.rerun()
            except:
                pass


if __name__ == "__main__":
    # Import required for parameter types
    from src.core.base_module import ParameterType
    main()

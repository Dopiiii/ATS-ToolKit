#!/usr/bin/env python3
"""
ATS-Toolkit - Phase 0: Project Structure Generator
Creates complete folder structure for ATS-Toolkit v2.0

Run this script to initialize the project structure.
"""

import os
from pathlib import Path

def create_structure():
    """Create complete ATS-Toolkit directory structure"""
    
    structure = {
        # Root files (will be created separately)
        ".": [
            "README.md",
            "LICENSE",
            "requirements.txt",
            "requirements-dev.txt",
            ".gitignore",
            "toolkit.py",
            "setup.py",
            "CONTRIBUTING.md",
            "CHANGELOG.md"
        ],
        
        # Legal documentation
        "legal": [
            "__init__.py",
            "disclaimer.py",
            "consent.py",
            "legal.pdf"  # Will be placeholder
        ],
        
        # Core engine
        "core": [
            "__init__.py",
            "consent_manager.py",
            "cache_manager.py",
            "pipeline_engine.py",
            "report_gen.py",
            "loot_manager.py",
            "stealth_utils.py",
            "api_manager.py",
            "utils.py",
            "exceptions.py",
            "websocket_server.py"
        ],
        
        # OSINT modules
        "osint": [
            "__init__.py",
            "README.md"
        ],
        "osint/core": [
            "__init__.py",
            "engine.py",
            "db_cache.py",
            "graph_builder.py"
        ],
        "osint/modules": [
            "__init__.py",
            ".gitkeep"  # Empty for now, modules added in Phase 2+
        ],
        
        # Pentest modules
        "pentest": [
            "__init__.py",
            "README.md"
        ],
        "pentest/core": [
            "__init__.py",
            "pentest_pipeline.py"
        ],
        "pentest/modules": [
            "__init__.py",
            ".gitkeep"
        ],
        
        # Red Team modules
        "redteam": [
            "__init__.py",
            "README.md"
        ],
        "redteam/modules": [
            "__init__.py",
            ".gitkeep"
        ],
        
        # Forensics modules
        "forensics": [
            "__init__.py",
            "README.md"
        ],
        "forensics/modules": [
            "__init__.py",
            ".gitkeep"
        ],
        
        # Fuzzing modules
        "fuzzing": [
            "__init__.py",
            "README.md"
        ],
        "fuzzing/modules": [
            "__init__.py",
            ".gitkeep"
        ],
        
        # ML Threat Detection
        "ml_threat": [
            "__init__.py",
            "README.md"
        ],
        "ml_threat/modules": [
            "__init__.py",
            ".gitkeep"
        ],
        
        # Deception Technology
        "deception": [
            "__init__.py",
            "README.md"
        ],
        "deception/modules": [
            "__init__.py",
            ".gitkeep"
        ],
        
        # Continuous Monitoring
        "continuous": [
            "__init__.py",
            "README.md"
        ],
        "continuous/modules": [
            "__init__.py",
            ".gitkeep"
        ],
        
        # Configuration files
        "config": [
            "api_keys.env.example",
            "pipelines_osint.yaml",
            "pipelines_pentest.yaml",
            "pipelines_redteam.yaml",
            "pipelines_forensics.yaml",
            "pipelines_continuous.yaml"
        ],
        "config/wordlists": [
            "subdomains.txt",
            "webpaths.txt",
            "params.txt",
            "usernames.txt"
        ],
        "config/payloads": [
            "revshells.yaml",
            "obfuscators.yaml"
        ],
        
        # Web Dashboard
        "ATS-UI": [
            "streamlit_app.py",
            "index.html",
            "dashboard.html"
        ],
        "ATS-UI/static": [],
        "ATS-UI/static/css": [
            "style.css",
            "ats_brand.css",
            "animations.css"
        ],
        "ATS-UI/static/js": [
            "dashboard.js",
            "charts.js",
            "alerts.js"
        ],
        "ATS-UI/static/img": [
            ".gitkeep"
        ],
        "ATS-UI/static/fonts": [
            ".gitkeep"
        ],
        "ATS-UI/pages": [
            "__init__.py",
            "osint_page.py",
            "pentest_page.py",
            "redteam_page.py",
            "forensics_page.py",
            "reports_page.py"
        ],
        "ATS-UI/components": [
            "__init__.py",
            "navbar.py",
            "sidebar.py",
            "modals.py"
        ],
        
        # Installers
        "installers": [
            "linux.sh",
            "windows.ps1",
            "docker.Dockerfile"
        ],
        
        # Docker
        "docker": [
            "Dockerfile",
            "docker-compose.yml",
            "docker-compose.test.yml",
            ".dockerignore"
        ],
        
        # Tests
        "tests": [
            "__init__.py",
            "conftest.py",
            "test_consent.py",
            "test_cache.py",
            "test_pipeline.py",
            "test_osint.py",
            "test_pentest.py",
            "docker-compose.yml"
        ],
        "tests/fixtures": [
            ".gitkeep"
        ],
        
        # Documentation
        "docs": [
            "index.md",
            "installation.md",
            "usage.md",
            "modules.md",
            "api_reference.md",
            "architecture.md",
            "contributing.md",
            "legal.md",
            "faq.md"
        ],
        "docs/examples": [
            "osint_domain.md",
            "pentest_webapp.md",
            "forensics_memory.md"
        ],
        "docs/images": [
            ".gitkeep"
        ],
        
        # Reports output directory
        "reports": [
            ".gitkeep"
        ],
        
        # Database storage
        "data": [
            ".gitkeep",
            "README.md"
        ],
        
        # Logs
        "logs": [
            ".gitkeep"
        ],
        
        # GitHub workflows
        ".github": [],
        ".github/workflows": [
            "test_linux.yml",
            "test_windows.yml",
            "test_docker.yml",
            "release.yml"
        ],
        ".github/ISSUE_TEMPLATE": [
            "bug_report.md",
            "feature_request.md"
        ]
    }
    
    print("🚀 Creating ATS-Toolkit project structure...\n")
    
    # Create all directories and files
    for directory, files in structure.items():
        # Create directory
        dir_path = Path(directory)
        dir_path.mkdir(parents=True, exist_ok=True)
        print(f"📁 Created: {directory}/")
        
        # Create files in directory
        for file in files:
            file_path = dir_path / file
            if not file_path.exists():
                file_path.touch()
                print(f"   ✓ {file}")
    
    print("\n✅ Structure created successfully!")
    print("\n📊 Summary:")
    print(f"   - Root files: {len(structure['.'])} files")
    print(f"   - Core modules: {len(structure['core'])} files")
    print(f"   - Module categories: 8 (OSINT, Pentest, RedTeam, Forensics, etc.)")
    print(f"   - Total directories: {len(structure)} directories")
    
    return True

if __name__ == "__main__":
    create_structure()
    print("\n🎯 Next steps:")
    print("   1. Review .gitignore")
    print("   2. Read LICENSE")
    print("   3. Check legal/disclaimer.py")
    print("   4. Ready for Phase 1! 🚀")
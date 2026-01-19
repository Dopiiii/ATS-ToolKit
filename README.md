# ATS-Toolkit v2.0

**Modular Cybersecurity Framework - 144 Tools**

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Phase](https://img.shields.io/badge/Phase-2%2F5-orange.svg)](#roadmap)

> Professional-grade cybersecurity toolkit with 30+ modules (144 planned) covering OSINT, Pentest, Red Team, Forensics, and more.

## Features

- **🎯 30+ Modules** (15 OSINT + 15 Pentest) - 144 total planned
- **🖥️ Dual Interface** - TUI (Textual) + Web UI (Streamlit)
- **⚡ Async Architecture** - High-performance concurrent execution
- **📊 REST API** - FastAPI backend with WebSocket logs
- **🔒 Secure** - API key management, audit logging, encrypted config
- **🐳 Docker Ready** - One-command deployment
- **🧪 100% Tested** - Comprehensive test coverage

## Quick Start

### Installation

```bash
# Clone repository
git clone https://github.com/Dopiiii/ATS-Toolkit
cd ATS-Toolkit

# Install dependencies
poetry install

# Configure
cp .env.example .env
# Edit .env with your API keys
```

### Usage

```bash
# Start TUI
python main.py --tui

# Start Streamlit Web UI
python main.py --web

# Start API Server
python main.py --api

# List all modules
python main.py list

# Run a module from CLI
python main.py run domain_recon --config domain=example.com
```

### Docker

```bash
docker-compose up
# API: http://localhost:8000
# Streamlit: http://localhost:8501
```

## Interfaces

### 🖥️ TUI (Textual)

Modern terminal interface with:
- Module browser by category
- Dynamic configuration panel
- Real-time log streaming
- Results visualization
- Settings management (F2)
- Keyboard shortcuts

```bash
python main.py --tui
```

**Shortcuts:**
- `Tab` - Navigate panels
- `F1` - Help
- `F2` - Settings (API keys)
- `Ctrl+K` - Launch Streamlit
- `Ctrl+Q` - Quit

### 🌐 Web UI (Streamlit)

Beautiful web interface with:
- Visual module selection
- Interactive configuration forms
- Real-time execution
- Results export (JSON/CSV)
- Metrics dashboard

```bash
python main.py --web
# Opens on http://localhost:8501
```

### 🔌 API (FastAPI)

REST API + WebSocket:

```bash
# Start server
python main.py --api

# API docs
http://localhost:8000/docs

# Examples
curl http://localhost:8000/modules
curl http://localhost:8000/modules/domain_recon/spec
curl -X POST http://localhost:8000/modules/domain_recon/run \
  -H "Content-Type: application/json" \
  -d '{"config": {"domain": "example.com"}}'

# WebSocket logs
ws://localhost:8000/ws/logs/all
```

## Modules

### 📡 OSINT (15 modules)

| Module | Description | API Key |
|--------|-------------|---------|
| `username_enum` | Username enumeration across 20+ platforms | - |
| `email_hunter` | Email discovery with Hunter.io integration | 🔑 Hunter |
| `domain_recon` | Comprehensive domain reconnaissance | - |
| `subdomain_enum` | Subdomain enumeration (bruteforce + CT logs) | - |
| `whois_lookup` | WHOIS information lookup | - |
| `dns_records` | DNS records enumeration + SPF/DMARC analysis | - |
| `ip_geolocation` | IP geolocation and ASN info | - |
| `shodan_search` | Shodan API search | 🔑 Shodan |
| `google_dorks` | Google dork query generator | - |
| `social_analyzer` | Social media profile analysis | - |
| `metadata_extractor` | Web page metadata extraction | - |
| `breach_check` | Data breach check (HIBP) | 🔑 HIBP |
| `certificate_search` | SSL certificate transparency search | - |
| `tech_detector` | Technology stack detection | - |
| `wayback_machine` | Internet Archive snapshot search | - |

### 🎯 Pentest (15 modules)

| Module | Description | Risk |
|--------|-------------|------|
| `sql_injection_scanner` | SQL injection vulnerability scanner | HIGH |
| `xss_scanner` | Cross-Site Scripting (XSS) scanner | HIGH |
| `port_scanner` | Fast async port scanner | MEDIUM |
| `directory_fuzzer` | Directory and file fuzzing | MEDIUM |
| `nuclei_wrapper` | Nuclei vulnerability scanner wrapper | MEDIUM |
| `cms_scanner` | CMS detection and vulnerability check | MEDIUM |
| `ssl_tls_scanner` | SSL/TLS configuration analyzer | LOW |
| `cors_tester` | CORS misconfiguration tester | MEDIUM |
| `header_security` | HTTP security headers analyzer | LOW |
| `api_fuzzer` | API endpoint fuzzer | MEDIUM |
| `jwt_analyzer` | JWT token analyzer | MEDIUM |
| `sensitive_data_scanner` | Sensitive data exposure scanner | MEDIUM |
| `csrf_tester` | CSRF vulnerability tester | HIGH |
| `lfi_rfi_scanner` | Local/Remote File Inclusion scanner | HIGH |
| `xxe_tester` | XML External Entity (XXE) tester | HIGH |

## Architecture

```
┌─────────────────────┐
│   TUI / Streamlit   │  Frontend Layer
├─────────────────────┤
│   FastAPI + WS      │  Application Layer
├─────────────────────┤
│   Core Engine       │  Business Logic
│  - AtsModule        │
│  - ConfigManager    │
│  - Logger           │
│  - ErrorHandler     │
├─────────────────────┤
│   144 Modules       │  Module Layer
│  OSINT | Pentest    │
│  RedTeam | Forensics│
├─────────────────────┤
│ SQLite │ Redis      │  Persistence
└─────────────────────┘
```

## Configuration

Edit `.env` file:

```bash
# Environment
ATS_ENV=production
ATS_LOG_LEVEL=INFO

# Performance
ATS_THREADS=50
ATS_TIMEOUT=60

# API Keys (get from providers)
ATS_API_SHODAN=your_shodan_key
ATS_API_HUNTER=your_hunter_key
ATS_API_VIRUSTOTAL=your_vt_key
ATS_API_HIBP=your_hibp_key

# Proxy (optional)
ATS_PROXY_ENABLED=false
ATS_PROXY_HOST=
```

Or use Settings UI (F2 in TUI, sidebar in Web).

## Development

### Add a Module

Create a file in `src/modules/<category>/my_module.py`:

```python
from src.core.base_module import AtsModule, ModuleSpec, ModuleCategory, Parameter, ParameterType, OutputField

class MyModule(AtsModule):
    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="my_module",
            category=ModuleCategory.OSINT,
            description="My awesome module",
            parameters=[
                Parameter(name="target", type=ParameterType.STRING, description="Target", required=True)
            ],
            outputs=[OutputField(name="results", type="list", description="Results")]
        )

    def validate_inputs(self, config) -> Tuple[bool, str]:
        return True, ""

    async def execute(self, config) -> Dict[str, Any]:
        target = config["target"]
        # Your logic here
        return {"results": [...]}
```

The module will be auto-discovered on next run!

### Run Tests

```bash
poetry run pytest
poetry run pytest --cov=src
```

### Code Quality

```bash
poetry run black src/
poetry run isort src/
poetry run mypy src/
poetry run ruff check src/
```

## Roadmap

### ✅ Phase 0 - Foundation (DONE)
- Core engine (AtsModule, Config, Logger, Errors)
- FastAPI backend
- Docker setup
- Module registry

### ✅ Phase 1 - TUI + OSINT (DONE)
- Textual TUI interface
- 15 OSINT modules
- Real-time logging
- Settings management

### ✅ Phase 2 - Streamlit + Pentest (DONE)
- Streamlit web UI
- 15 Pentest modules
- Results export (JSON/CSV)
- Visual dashboard

### 🔄 Phase 3 - Advanced (IN PROGRESS)
- 10 Red Team modules
- 8 Forensics modules
- 6 Fuzzing modules
- 5 ML Threat Detection modules

### 📅 Phase 4 - Production
- 4 Malware Development modules (authorized use only)
- 5 Deception modules
- 3 Continuous Pentest modules
- PyInstaller packaging
- Complete documentation

### 📅 Phase 5 - Future (2026)
- 64 Advanced modules (AI, Web3, ICS, Cloud)
- Machine learning integration
- Automated reporting
- Team collaboration features

**Total: 144 modules planned**

## Security Considerations

⚠️ **IMPORTANT**: This tool is for authorized security testing only.

- **Pentest modules** require explicit permission
- **Red Team modules** are restricted by default
- **Malware modules** require authorization context
- All actions are logged to audit trail
- Comply with local laws and regulations

## API Keys

Some modules require API keys:

| Service | Module | Get Key |
|---------|--------|---------|
| Shodan | `shodan_search` | https://shodan.io |
| Hunter.io | `email_hunter` | https://hunter.io |
| VirusTotal | (future) | https://virustotal.com |
| Have I Been Pwned | `breach_check` | https://haveibeenpwned.com/API/Key |

Configure in `.env` or Settings UI.

## Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new modules
4. Ensure code quality (black, isort, mypy)
5. Submit a pull request

## License

MIT License - see [LICENSE](LICENSE) file.

## Credits

**Author**: Eric Dopi
**Repository**: https://github.com/Dopiiii/ATS-Toolkit
**Version**: 2.0.0 (Phase 2)

## Support

- 📖 Documentation: `python main.py --help`
- 🐛 Issues: https://github.com/Dopiiii/ATS-Toolkit/issues
- 💬 Discussions: GitHub Discussions

---

**⚡ Built with FastAPI, Textual, Streamlit, and Python 3.11+**

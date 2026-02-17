# ATS-Toolkit v2.0

Modular cybersecurity framework with 144 modules across 10 categories. Features TUI (Textual), Web UI (Streamlit), and REST API (FastAPI) interfaces.

## Features

- **144 Security Modules** across 10 categories
- **TUI Interface** - Terminal UI built with Textual
- **Web Interface** - Streamlit-based dashboard
- **REST API** - FastAPI with WebSocket support
- **Module Auto-Discovery** - Drop-in module architecture
- **Structured Logging** - JSON logging with SQLite audit trail
- **Docker Support** - Full containerized deployment

## Module Categories

| Category | Modules | Description |
|----------|---------|-------------|
| OSINT | 15 | Open Source Intelligence gathering |
| Pentest | 15 | Penetration testing tools |
| Red Team | 10 | Offensive security operations |
| Forensics | 8 | Digital forensics analysis |
| Fuzzing | 6 | Fuzz testing and input mutation |
| ML Detection | 5 | Machine learning threat detection |
| Malware | 4 | Malware analysis tools |
| Deception | 5 | Honeypots and deception tech |
| Continuous Pentest | 3 | Automated continuous testing |
| Advanced | 73 | AI, Crypto, Web3, Network, Mobile, Social Engineering |

## Quick Start (Windows)

```batch
:: Install dependencies
install.bat

:: Launch the toolkit
start.bat
```

## Quick Start (Manual)

### Prerequisites

- Python 3.11+
- Poetry (recommended) or pip

### Installation

```bash
# Create virtual environment
python -m venv .venv

# Activate (Windows)
.venv\Scripts\activate

# Activate (Linux/macOS)
source .venv/bin/activate

# Install with Poetry
poetry install

# Or with pip
pip install -e .

# Copy environment config
cp .env.example .env
```

### Launch Options

```bash
# TUI Mode (Terminal Interface)
python main.py --tui

# Web UI Mode (Streamlit)
python main.py --web

# API Mode (FastAPI)
python main.py --api

# List all modules
python main.py list

# Run a specific module
python main.py run <module_name>
```

## Docker Deployment

```bash
cd docker
docker-compose up -d
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/modules` | List all modules |
| GET | `/modules/{name}` | Get module spec |
| POST | `/modules/{name}/run` | Execute a module |
| GET | `/config` | Get current config |
| WS | `/ws/logs/{module}` | Live log streaming |

## Project Structure

```
ATS-ToolKit/
├── src/
│   ├── core/               # Core engine
│   │   ├── base_module.py  # Abstract base class
│   │   ├── config_manager.py
│   │   ├── logger.py
│   │   └── error_handler.py
│   ├── modules/            # 144 security modules
│   │   ├── registry.py     # Auto-discovery registry
│   │   ├── osint/          # 15 OSINT modules
│   │   ├── pentest/        # 15 Pentest modules
│   │   ├── red_team/       # 10 Red Team modules
│   │   ├── forensics/      # 8 Forensics modules
│   │   ├── fuzzing/        # 6 Fuzzing modules
│   │   ├── ml_detection/   # 5 ML Detection modules
│   │   ├── malware/        # 4 Malware modules
│   │   ├── deception/      # 5 Deception modules
│   │   ├── continuous_pentest/ # 3 Continuous Pentest
│   │   └── advanced/       # 73 Advanced modules
│   ├── api/                # FastAPI REST API
│   ├── tui/                # Textual TUI
│   └── streamlit_ui/       # Streamlit Web UI
├── docker/                 # Docker deployment
├── tests/                  # Test suite
├── main.py                 # Entry point
├── start.bat               # Windows launcher
├── install.bat             # Windows installer
├── pyproject.toml          # Dependencies
└── .env.example            # Configuration template
```

## Configuration

See `.env.example` for all available settings including API keys for external services (Shodan, VirusTotal, HIBP, etc.).

## Author

Eric Dopi - ATS-Toolkit Team

## License

MIT

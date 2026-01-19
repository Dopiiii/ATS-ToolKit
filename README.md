<div align="center">

# ATS-Toolkit v2.0

**Professional Security & Intelligence Framework**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey.svg)](https://github.com/ATS-strasbourg/ATS-toolkit)
[![Status](https://img.shields.io/badge/status-active-success.svg)](https://github.com/ATS-strasbourg/ATS-toolkit)

</div>

---

**CRITICAL LEGAL NOTICE**: ATS-Toolkit is strictly for educational and authorized use only. Unauthorized access to computer systems is illegal. Users assume full responsibility for compliance with applicable laws. See [Legal Disclaimer](#legal-disclaimer) below.

---

## Table of Contents

- [Overview](#overview)
- [Legal Disclaimer](#legal-disclaimer)
- [Features](#features)
- [Project Structure](#project-structure)
- [Platform Support](#platform-support)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Module Reference](#module-reference)
- [CLI Usage](#cli-usage)
- [Dashboard Interface](#dashboard-interface)
- [Configuration](#configuration)
- [Testing Environment](#testing-environment)
- [Development](#development)
- [Contributing](#contributing)
- [FAQ](#faq)
- [Support](#support)
- [License](#license)

---

## Overview

ATS-Toolkit v2.0 is a comprehensive, modular cybersecurity framework designed for authorized security professionals and educators. The platform integrates OSINT reconnaissance, penetration testing, red team operations, digital forensics, vulnerability fuzzing, machine learning threat detection, and deception technology within a unified architecture.

The framework implements blockchain-inspired consent tracking to ensure ethical usage, with cryptographic verification and immutable logging of all authorization events.

### Design Principles

- **Modularity**: 124 independent modules organized by security domain
- **Education First**: Built for learning cybersecurity concepts and techniques
- **Legal Compliance**: Immutable consent system requiring explicit authorization
- **Professional Quality**: Enterprise-grade code standards and error handling
- **Cross-Platform**: Seamless operation on Windows, Linux, macOS, and Docker
- **Modern Architecture**: Async/await patterns, encrypted caching, real-time dashboards

### Target Audience

- **Security Professionals**: Penetration testers conducting authorized security assessments
- **Bug Bounty Researchers**: Ethical hackers performing reconnaissance on authorized targets
- **SOC Analysts**: Security operations personnel practicing threat hunting and incident response
- **Cybersecurity Students**: Learners developing practical skills in OSINT, pentesting, and red team tactics
- **Academic Researchers**: Security researchers conducting studies in isolated laboratory environments

---

## Legal Disclaimer

### Authorized Use Only

ATS-Toolkit v2.0 is STRICTLY for educational and authorized testing only.

**Authorized Activities:**
- Testing your own systems and applications
- Authorized penetration testing with written contracts
- Bug bounty programs where explicitly permitted
- Educational lab exercises (DVWA, Metasploitable, bWAPP)
- Academic research with proper ethics approval
- Internal security assessments with management approval

**Prohibited Activities:**
- Unauthorized access to any computer system
- Testing systems without explicit written permission
- Corporate networks without formal pentest contracts
- Public infrastructure or third-party websites
- Creating or deploying actual malware
- Harvesting personal data without consent
- Active attacks against production systems

### Legal Consequences

Unauthorized computer access is a criminal offense with severe penalties:

- **France**: Articles 323-1 to 323-7 (Code Pénal) - Up to 5 years imprisonment + €75,000 fine
- **United States**: Computer Fraud & Abuse Act (CFAA) - Up to 10 years imprisonment + federal fines
- **United Kingdom**: Computer Misuse Act 1990 - Up to 10 years imprisonment + unlimited fine
- **European Union**: GDPR violations - Up to €20 million or 4% of annual revenue
- **International**: Cybercrime conventions and extradition treaties apply globally

### Liability and Acknowledgment

By using ATS-Toolkit, you acknowledge and accept the following terms:

1. You have thoroughly reviewed and understand all provisions of this disclaimer
2. You will exclusively use this toolkit on systems you own or have explicit written authorization to test
3. You assume complete legal and criminal responsibility for all actions taken with this software
4. The authors and contributors disclaim all liability for misuse, damages, or legal consequences
5. You will maintain full compliance with all applicable laws and regulations in your jurisdiction

---

## Features

### OSINT Intelligence Engine (35 Modules)

Comprehensive reconnaissance capabilities for target profiling:

**Identity & Username Reconnaissance**
- Multi-platform username enumeration (50+ social networks via Maigret)
- Email discovery and breach correlation (HIBP, Dehashed, LeakCheck)
- Phone number reverse lookup and carrier identification
- Social media profile aggregation (Twitter, Instagram, TikTok, LinkedIn, Discord, Twitch, Reddit)
- GitHub user intelligence (repositories, commits, exposed emails)
- Company employee directory scraping

**Domain & Network Intelligence**
- Subdomain enumeration (certificate transparency logs, DNS brute force)
- SSL/TLS certificate analysis and historical data
- WHOIS registration information and DNS records
- Nameserver enumeration and zone transfer attempts
- IP geolocation and ASN lookup
- Reverse DNS and IP ownership identification

**Breach & Credential Intelligence**
- Multi-database breach correlation
- Credential leak detection (API keys, passwords, tokens)
- Data exposure monitoring (paste sites, GitHub commits)
- Historical breach analysis and timeline

**Threat Intelligence Integration**
- Malware hash classification (VirusTotal, YARA)
- CVE vulnerability mapping and severity scoring
- IoC (Indicator of Compromise) checking
- Threat actor attribution and campaign tracking

**Advanced Reconnaissance**
- Reverse image search (Google Images, TinEye, SauceNAO)
- NSFW content detection (TensorFlow classifier)
- Blockchain address analysis (Etherscan, Bitcoin)
- Dark web monitoring (Tor hidden services, OnionSearch)
- Custom data source integration

### Penetration Testing Suite (25 Modules)

Vulnerability identification and exploitation for authorized assessments:

**Web Application Security**
- Directory and file enumeration (Gobuster, ffuf integration)
- SQL injection detection (SQLMap wrapper with safety mechanisms)
- Cross-Site Scripting (XSS) fuzzing and discovery
- CORS misconfiguration detection
- Cookie security analysis (HttpOnly, Secure, SameSite flags)
- JWT token weakness detection
- CSRF protection validation
- XXE (XML External Entity) payload testing
- SSRF and LFI vulnerability detection
- API endpoint fuzzing (REST, GraphQL, SOAP)

**Network Security**
- Async port scanning (Nmap with SYN/UDP/service detection)
- Service enumeration and banner grabbing
- SSL/TLS vulnerability assessment
- DNS zone transfer attempts
- WebSocket security testing
- Network segmentation analysis

**CMS & Framework Testing**
- WordPress security scanning (WPScan integration)
- Drupal and Joomla vulnerability detection
- Plugin and theme vulnerability correlation
- Custom framework detection and exploitation

**Authentication & Session**
- Brute force automation (Hydra: HTTP, SSH, FTP, SMB)
- Session fixation and hijacking tests
- Password policy analysis
- Multi-factor authentication bypass detection

### Red Team Operations (10 Modules)

Advanced post-exploitation and evasion techniques for authorized testing:

**Command & Control Framework**
- Lightweight C2 implementation (HTTP/3, WebSocket, DNS tunneling)
- Multi-protocol beacon support
- Beacon jitter and sleep obfuscation
- Multi-agent management interface

**Payload Development**
- Reverse shell generation (Bash, Python, PowerShell, C#, JavaScript, VBScript)
- AES-256 and XOR payload obfuscation
- AMSI bypass templates (PowerShell, .NET)
- AV evasion techniques (signature polymorphism, code caves)
- Shellcode encoding and decoding

**Post-Exploitation**
- Process injection templates (DLL, shellcode)
- Credential dumping methods (pass-the-hash simulation)
- Lateral movement frameworks
- Persistence mechanism library (Registry, cron, Task Scheduler)
- Data exfiltration channels (DNS, ICMP, HTTP, S3)

**Important**: All Red Team modules are educational templates designed exclusively for isolated laboratory testing. Production deployment is strictly prohibited.

### Digital Forensics Suite (8 Modules)

Incident response and forensic analysis capabilities:

**Memory Analysis**
- Volatility3 integration for memory dump analysis
- Process list enumeration and hidden process detection
- Network connection tracking
- Malware behavior identification

**Disk Forensics**
- Super-timeline generation (Plaso/log2timeline)
- File carving and artifact extraction
- Windows registry hive parsing (SAM, SYSTEM, SOFTWARE)
- Event log analysis (Security, Application, System)

**Recovery & Reconstruction**
- Browser history recovery (Chrome, Firefox, Edge, Safari)
- Deleted file recovery
- Windows prefetch file analysis (execution history)
- Temporary file examination

**Correlation & Reporting**
- Artifact correlation engine
- Mermaid timeline visualization
- Forensic report generation (PDF, HTML, Markdown)
- Chain of custody logging

### Vulnerability Fuzzing (6 Modules)

Automated vulnerability discovery through fuzzing:

- Distributed AFL++ cluster (Docker Swarm coordination)
- Coverage-guided feedback loop optimization
- Custom mutation engine (Radamsa-inspired transformations)
- Protocol fuzzing (DNS, HTTP, TLS)
- Binary fuzzing with crash analysis
- PoC (Proof of Concept) generation

### Machine Learning Threat Detection (5 Modules)

Intelligent threat identification using ML:

- YARA + TensorFlow malware classification
- Network traffic anomaly detection
- Process behavior analysis
- Malware family clustering
- Threat likelihood scoring

### Deception Technology (5 Modules)

Honeypot and canary trap deployment:

- Honeypot deployment (Cowrie SSH, Dionaea multi-protocol)
- Canary token generation (URLs, files, DNS records)
- Real-time attack monitoring and alerts
- Decoy file deployment
- Network bait systems

### Continuous Monitoring (3 Modules)

Ongoing security monitoring and alerting:

- URL watchdog (continuous re-scanning with change detection)
- GitHub CI/CD security hooks (automated vulnerability scanning)
- Multi-platform alerting (Slack, Discord, Telegram, Email)
- Scheduled scanning via APScheduler

---

## Project Structure

```
ATS-toolkit/
├── ATS-UI/                                    # Web Dashboard (Streamlit)
│   ├── index.html                             # Landing page
│   ├── dashboard.html                         # Main interface
│   ├── auth.html                              # Authentication
│   ├── streamlit_app.py                       # Backend server
│   ├── pages/
│   │   ├── osint_page.py                      # OSINT UI
│   │   ├── pentest_page.py                    # Pentest UI
│   │   ├── redteam_page.py                    # Red Team UI
│   │   ├── forensics_page.py                  # Forensics UI
│   │   ├── ml_threat_page.py                  # ML Threat UI
│   │   └── reports_page.py                    # Reports UI
│   ├── components/
│   │   ├── navbar.py
│   │   ├── sidebar.py
│   │   ├── modals.py
│   │   └── charts.py
│   └── static/
│       ├── css/
│       │   ├── style.css                      # Main styles
│       │   ├── ats_brand.css                  # Red/black theme
│       │   └── animations.css                 # Effects
│       ├── js/
│       │   ├── dashboard.js
│       │   ├── pipeline_builder.js
│       │   └── charts.js
│       └── img/
│           ├── ats_logo.svg
│           ├── favicon.ico
│           └── backgrounds/
│
├── core/                                      # Shared Components
│   ├── pipeline_engine.py                     # Async orchestrator (400+ lines)
│   ├── consent_manager.py                     # Legal consent tracking
│   ├── cache_manager.py                       # Encrypted SQLite cache
│   ├── loot_manager.py                        # Credential storage
│   ├── stealth_utils.py                       # Rate limit, proxies, UA rotation
│   ├── report_gen.py                          # PDF/JSON/MD/Mermaid generation
│   ├── websocket_server.py                    # Real-time updates
│   ├── exceptions.py                          # Custom exceptions
│   └── utils.py                               # Helper functions
│
├── osint/                                     # OSINT Modules (35)
│   ├── core/
│   │   ├── engine.py                          # OSINT pipeline
│   │   ├── api_manager.py                     # API integrations
│   │   └── graph_builder.py                   # Relationship graphs
│   └── modules/
│       ├── username_enum.py                   # Maigret + WhatsMyName
│       ├── email_recon.py                     # Email + breaches
│       ├── domain_recon.py                    # Domain intelligence
│       ├── phone_reverse.py                   # Phone lookup
│       ├── github_user.py                     # GitHub OSINT
│       ├── breach_check.py                    # Breach databases
│       ├── social_profiles.py                 # Social media
│       ├── cloud_enum.py                      # Cloud storage
│       ├── darkweb_search.py                  # Tor/hidden services
│       ├── image_reverse.py                   # Image search
│       ├── nsfw_detect.py                     # NSFW classifier
│       ├── blockchain_recon.py                # Crypto analysis
│       ├── discord_recon.py                   # Discord OSINT
│       ├── shodan_scan.py                     # Shodan API
│       ├── censys_enum.py                     # Censys API
│       ├── fofa_scan.py                       # FOFA search
│       ├── dns_enum.py                        # DNS enumeration
│       ├── whois_lookup.py                    # WHOIS data
│       ├── ip_geolocate.py                    # IP geolocation
│       ├── email_finder.py                    # Email discovery
│       ├── company_enum.py                    # Corporate data
│       ├── credential_leak.py                 # Credential APIs
│       ├── certificate_search.py              # SSL certificates
│       ├── hosting_detect.py                  # Hosting provider
│       ├── cms_detect.py                      # CMS detection
│       ├── screenshot_take.py                 # Site screenshots
│       ├── pdf_metadata.py                    # PDF EXIF
│       ├── mobile_recon.py                    # Mobile app OSINT
│       ├── ioc_check.py                       # Indicator checking
│       ├── cve_check.py                       # CVE correlation
│       ├── twitter_osint.py                   # Twitter data
│       ├── linkedin_enum.py                   # LinkedIn scraping
│       └── custom_connector.py                # User data sources
│
├── pentest/                                   # Pentest Modules (25)
│   ├── core/
│   │   └── pentest_pipeline.py                # Pentest orchestrator
│   └── modules/
│       ├── subdomain_enum.py                  # crt.sh + Sublist3r
│       ├── portscan.py                        # Async nmap
│       ├── service_enum.py                    # whatweb + banners
│       ├── sqlmap_wrapper.py                  # SQL injection
│       ├── nuclei_scanner.py                  # Nuclei 10k+ CVEs
│       ├── gobuster_dirfuzz.py                # Directory fuzzing
│       ├── nikto_scanner.py                   # Web server scan
│       ├── dalfox_xss.py                      # XSS detection
│       ├── cve_scanner.py                     # CVE lookup
│       ├── wordpress_scan.py                  # WPScan wrapper
│       ├── api_fuzzer.py                      # REST/GraphQL
│       ├── burp_proxy.py                      # Interception proxy
│       ├── ssl_test.py                        # SSL/TLS testing
│       ├── jwt_analyzer.py                    # JWT weakness
│       ├── websocket_fuzz.py                  # WebSocket testing
│       ├── cors_checker.py                    # CORS detection
│       ├── cookie_analyzer.py                 # Cookie security
│       ├── redirect_test.py                   # Open redirects
│       ├── csrf_detector.py                   # CSRF detection
│       ├── xml_entity.py                      # XXE testing
│       ├── dos_tester.py                      # DoS simulation
│       ├── brute_force.py                     # Hydra wrapper
│       ├── phishing_cloner.py                 # httrack + hooks
│       └── wireless_audit.py                  # WiFi testing
│
├── redteam/                                   # Red Team Modules (10)
│   └── modules/
│       ├── c2_framework.py                    # C2 beacons
│       ├── payload_generator.py               # Reverse shells
│       ├── obfuscation.py                     # AES/XOR encoding
│       ├── amsi_bypass.py                     # AMSI evasion
│       ├── av_evasion.py                      # AV bypass techniques
│       ├── process_injection.py               # DLL injection
│       ├── lateral_movement.py                # Pass-the-hash
│       ├── persistence.py                     # Backdoor methods
│       ├── exfiltration.py                    # Data channels
│       └── command_control.py                 # C2 protocols
│
├── forensics/                                 # Forensics Modules (8)
│   └── modules/
│       ├── volatility_wrapper.py              # Memory analysis
│       ├── timeline_generator.py              # Plaso timeline
│       ├── disk_artifact.py                   # File carving
│       ├── registry_parser.py                 # Registry hives
│       ├── event_log_parse.py                 # Event logs
│       ├── browser_history.py                 # Browser recovery
│       ├── prefetch_analysis.py               # Prefetch files
│       └── artifact_correlate.py              # Correlation
│
├── fuzzing/                                   # Fuzzing Modules (6)
│   └── modules/
│       ├── cluster_fuzz.py                    # AFL++ cluster
│       ├── api_fuzzer_adv.py                  # API mutations
│       ├── protocol_fuzzer.py                 # Protocol fuzzing
│       ├── input_mutation.py                  # Radamsa engine
│       ├── feedback_engine.py                 # Coverage guidance
│       └── crash_analyzer.py                  # Crash triage
│
├── ml_threat/                                 # ML Modules (5)
│   └── modules/
│       ├── yara_classifier.py                 # YARA + ML
│       ├── anomaly_detector.py                # IDS anomalies
│       ├── malware_behavior.py                # Behavior analysis
│       ├── traffic_analyzer.py                # Network ML
│       └── threat_predict.py                  # Scoring
│
├── malware_dev/                               # Malware Dev Kit (4)
│   └── modules/
│       ├── trojan_template.py                 # Keylogger/RAT
│       ├── ransomware_demo.py                 # Ransomware sim
│       ├── sandbox_tester.py                  # Cuckoo deploy
│       └── crypter_payloads.py                # Obfuscation
│
├── deception/                                 # Deception Modules (5)
│   └── modules/
│       ├── honeypot_deploy.py                 # Cowrie/Dionaea
│       ├── canary_tokens.py                   # Canary tokens
│       ├── honeypot_monitor.py                # Monitoring
│       ├── decoy_files.py                     # Decoy deployment
│       └── bait_deployment.py                 # Network baits
│
├── continuous/                                # Continuous Modules (3)
│   └── modules/
│       ├── watchdog_scanner.py                # URL monitoring
│       ├── github_ci_hook.py                  # CI/CD integration
│       └── alerting_system.py                 # Multi-platform alerts
│
├── config/                                    # Configuration Files
│   ├── pipelines_osint.yaml                   # OSINT presets
│   ├── pipelines_pentest.yaml                 # Pentest presets
│   ├── pipelines_redteam.yaml                 # Red Team presets
│   ├── pipelines_forensics.yaml               # Forensics presets
│   ├── api_keys.env.example                   # API credentials template
│   ├── wordlists/
│   │   ├── subdomains.txt                     # Top 1M subdomains
│   │   ├── webpaths.txt                       # Common URIs
│   │   └── params.txt                         # API parameters
│   └── payloads/
│       ├── revshells.yaml                     # Reverse shell templates
│       └── obfuscators.yaml                   # Encoding templates
│
├── tests/                                     # Test Suite
│   ├── docker-compose.yml                     # DVWA + Metasploitable
│   ├── test_suite_full.sh                     # Complete test runner
│   ├── test_osint.sh                          # OSINT tests
│   ├── test_pentest.sh                        # Pentest tests
│   ├── test_redteam.sh                        # Red Team tests
│   ├── test_forensics.sh                      # Forensics tests
│   └── test_ml.sh                             # ML tests
│
├── docs/                                      # Documentation
│   ├── legal.pdf                              # Full legal disclaimer
│   ├── usage.md                               # Module usage guide
│   ├── architecture.md                        # Design documentation
│   ├── api_reference.md                       # API documentation
│   ├── redteam_guide.md                       # Red Team workflows
│   ├── forensics_guide.md                     # Forensics procedures
│   └── examples/
│       ├── osint_workflow.md                  # OSINT scenario
│       ├── pentest_workflow.md                # Pentest scenario
│       ├── incident_response.md               # IR scenario
│       └── lab_setup.md                       # Lab guide
│
├── installers/
│   ├── linux.sh                               # Arch/Ubuntu installer
│   ├── windows.ps1                            # Windows installer
│   ├── docker.Dockerfile                      # Docker build
│   └── docker-compose-test.yml                # Test environment
│
├── toolkit.py                                 # Main CLI (500+ lines)
├── setup.py                                   # Installation script
├── requirements.txt                           # Python dependencies
├── requirements-dev.txt                       # Dev dependencies
├── setup.sh                                   # Linux quick install
├── setup.bat                                  # Windows quick install
├── start-ats.sh                               # Linux launcher
├── start-ats.bat                              # Windows launcher
├── Dockerfile                                 # Container build
├── docker-compose.yml                         # Services stack
├── README.md                                  # This file
├── LICENSE                                    # MIT License
├── CONTRIBUTING.md                            # Contribution guide
├── CODE_OF_CONDUCT.md                         # Community standards
└── .github/
    └── workflows/
        ├── test_linux.yml                     # Linux CI
        ├── test_windows.yml                   # Windows CI
        ├── test_docker.yml                    # Docker CI
        └── publish.yml                        # Release workflow
```

---

## Platform Support

| Platform | Status | Notes |
|----------|--------|-------|
| **Linux (Arch)** | Fully Supported | Primary development platform |
| **Linux (Ubuntu/Debian)** | Fully Supported | Via apt package manager |
| **Windows 10/11** | Fully Supported | Via WSL2 Kali or native (limited) |
| **macOS 12+** | Supported | Via Homebrew package manager |
| **Docker** | Fully Supported | Multi-arch (ARM/x86-64) |
| **Kubernetes** | Experimental | Helm charts coming soon |

---

## Installation

### Method 1: Automated Install (Linux/macOS)

```bash
# Clone repository
git clone https://github.com/ATS-strasbourg/ATS-toolkit.git
cd ATS-toolkit

# Run automatic installer
chmod +x setup.sh
./setup.sh
```

The installer will:
- Detect your OS and package manager
- Install system dependencies
- Create Python virtual environment
- Install Python packages
- Setup configuration files
- Run initial tests
- Display legal disclaimer

### Method 2: Docker (Recommended for Isolation)

```bash
# Build multi-arch image
docker build -t ATS-toolkit:latest .

# Run with Docker Compose (includes test environments)
docker-compose up -d

# Access services
# CLI: docker exec -it ATS-toolkit python toolkit.py
# Web: http://localhost:8501
# Honeypot SSH: localhost:2222
```

### Method 3: Manual Installation

**Arch Linux**
```bash
# Install system dependencies
sudo pacman -S python python-pip nmap sqlmap nuclei gobuster \
               hydra hashcat volatility3 docker docker-compose \
               tor torsocks aircrack-ng wireshark-cli git

# Clone and setup
git clone https://github.com/ATS-strasbourg/ATS-toolkit.git
cd ATS-toolkit

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install Python packages
pip install -r requirements.txt

# Initialize
python toolkit.py --initialize
```

**Ubuntu/Debian**
```bash
# Install system dependencies
sudo apt update
sudo apt install python3.12 python3-pip nmap sqlmap nuclei \
                 gobuster hydra hashcat docker.io docker-compose \
                 tor torsocks aircrack-ng git

# Clone and setup
git clone https://github.com/ATS-strasbourg/ATS-toolkit.git
cd ATS-toolkit

# Create virtual environment
python3.12 -m venv venv
source venv/bin/activate

# Install Python packages
pip install -r requirements.txt

# Initialize
python3 toolkit.py --initialize
```

**Windows 10/11**
```powershell
# Install via Windows Package Manager
winget install Python.Python.3.12
winget install Docker.DockerDesktop
winget install Nmap.Nmap
winget install Git.Git

# Clone and setup
git clone https://github.com/ATS-strasbourg/ATS-toolkit.git
cd ATS-toolkit

# Create virtual environment
python -m venv venv
venv\Scripts\activate

# Install Python packages
pip install -r requirements.txt

# Initialize
python toolkit.py --initialize
```

### Method 4: PyPI (Coming Soon)

```bash
pip install ATS-toolkit
ATS-toolkit --help
```

---

## Quick Start

### 1. Legal Compliance

```bash
python toolkit.py --mode web
```

On initial launch, complete the following steps:
1. Review the complete legal disclaimer
2. Accept terms and generate consent hash
3. Securely store your consent hash for authorization verification

### 2. Run Your First OSINT Scan

**Simple username search:**
```bash
python toolkit.py --section osint \
                  --input "username:ATS" \
                  --modules username_enum,social_profiles \
                  --output json
```

**Full domain intelligence:**
```bash
python toolkit.py --section osint \
                  --target example.com \
                  --pipeline domain_full \
                  --output pdf
```

**Breach database check:**
```bash
python toolkit.py --section osint \
                  --input "email:test@example.com" \
                  --modules breach_check,email_recon \
                  --consent YOUR_CONSENT_HASH
```

### 3. Launch Web Dashboard

```bash
python toolkit.py --mode web
# Opens http://localhost:8501
```

**Workflow Overview:**
1. Complete legal compliance and accept terms
2. Select operational module section (OSINT/Pentest/RedTeam/Forensics)
3. Configure target information and scope
4. Choose specific modules or utilize pipeline presets
5. Monitor real-time execution progress
6. Generate and export reports in multiple formats (PDF/JSON/Markdown)

### 4. Run Test Environment

```bash
# Start vulnerable test systems
docker-compose -f tests/docker-compose.yml up -d

# Test against DVWA
python toolkit.py --section pentest \
                  --target http://localhost:8080 \
                  --pipeline web_full

# Access test systems
# DVWA: http://localhost:8080 (admin/password)
# Metasploitable: http://localhost:3000
# Honeypot SSH: localhost:2222
```

---

## Module Reference

### OSINT Modules (35)

| Module | Function | Input | Output |
|--------|----------|-------|--------|
| username_enum | Multi-platform search | Username | Accounts (50+ sites) |
| email_recon | Email intelligence | Email | Breaches, services |
| domain_recon | Domain analysis | Domain | Subdomains, DNS, tech |
| phone_reverse | Phone lookup | Phone | Carrier, location |
| github_user | GitHub profile | Username | Repos, emails |
| breach_check | Breach database | Email | Breaches, passwords |
| social_profiles | Social media | Username | 20+ platform profiles |
| cloud_enum | Cloud storage | Domain | S3, Azure, GCP |
| darkweb_search | Hidden services | Keywords | .onion sites |
| image_reverse | Image search | Image URL | Similar images |
| nsfw_detect | Content classifier | Image | Probability score |
| blockchain_recon | Crypto analysis | Address | Transactions, balance |
| discord_recon | Discord OSINT | User ID | User, guilds, activity |
| shodan_scan | Device search | IP/Domain | Open ports, services |
| censys_enum | Host data | IP/Domain | Certificates, services |
| fofa_scan | Protocol search | Protocol | Hosts, indicators |
| dns_enum | DNS records | Domain | All DNS records |
| whois_lookup | WHOIS data | Domain | Registrar, dates |
| ip_geolocate | IP location | IP | City, ISP, coordinates |
| email_finder | Email discovery | Company | Employee emails |
| company_enum | Corporate data | Company | Employees, info |
| credential_leak | Credential API | Email | Leaked credentials |
| certificate_search | SSL certificates | Domain | Certificate chain |
| hosting_detect | Hosting provider | Domain | Provider, CDN |
| cms_detect | CMS detection | URL | WordPress, Drupal, etc |
| screenshot_take | Site screenshot | URL | PNG image |
| pdf_metadata | PDF extraction | PDF URL | Metadata, author |
| mobile_recon | Mobile app OSINT | App name | Store data, reviews |
| ioc_check | Indicator check | Hash/IP | Malware rating |
| cve_check | CVE correlation | Service | Related CVEs |
| twitter_osint | Twitter data | Handle | Tweets, followers |
| linkedin_enum | LinkedIn scraping | Company | Employees, jobs |
| strava_recon | Fitness leaks | User | Activities, routes |
| custom_connector | User datasource | Custom | User data |

### Pentest Modules (25)

| Module | Function | Target | Findings |
|--------|----------|--------|----------|
| subdomain_enum | Find subdomains | Domain | Subdomain list |
| portscan | Port scanning | IP/Domain | Open ports |
| service_enum | Service detection | IP/Domain | Software versions |
| sqlmap_wrapper | SQL injection | URL | SQLi vulnerabilities |
| nuclei_scanner | CVE scanner | URL | Known vulnerabilities |
| gobuster_dirfuzz | Directory fuzzing | URL | Hidden paths |
| nikto_scanner | Web server scan | URL | Misconfigurations |
| dalfox_xss | XSS detection | URL | Injection points |
| cve_scanner | CVE mapping | Service | Related CVEs |
| wordpress_scan | WordPress audit | URL | Vulnerabilities |
| api_fuzzer | API testing | URL | Parameter issues |
| burp_proxy | Interception | Local traffic | Requests/responses |
| ssl_test | SSL/TLS audit | Domain | Cipher weaknesses |
| jwt_analyzer | JWT testing | Token | Weak keys, bypass |
| websocket_fuzz | WebSocket test | URL | Protocol issues |
| cors_checker | CORS detection | URL | Misconfigurations |
| cookie_analyzer | Cookie security | URL | Weak flags |
| redirect_test | Open redirects | URL | Redirect chains |
| csrf_detector | CSRF detection | URL | Token weakness |
| xml_entity | XXE testing | URL | Entity injection |
| dos_tester | DoS simulation | Target | Tolerance levels |
| brute_force | Password brute | Service | Valid credentials |
| phishing_cloner | Site cloner | URL | Local clone |
| wireless_audit | WiFi testing | Interface | WPA2 crack |
| hybrid_scan | Full assessment | Target | All findings |

---

## CLI Usage

### General Syntax

```bash
python toolkit.py --section SECTION \
                  --input INPUT \
                  --pipeline PIPELINE \
                  --modules MODULE1,MODULE2 \
                  --toggle +TOGGLE1 -TOGGLE2 \
                  --output FORMAT \
                  --consent HASH
```

### Common Examples

**OSINT Username Investigation**
```bash
python toolkit.py --section osint \
                  --input "username:ATS" \
                  --pipeline full \
                  --output pdf
```

**Pentest Web Application**
```bash
python toolkit.py --section pentest \
                  --target http://testsite.com \
                  --pipeline web_full \
                  --modules sqlmap,xss,api_fuzzer
```

**Red Team C2 Setup**
```bash
python toolkit.py --section redteam \
                  --pipeline c2_full \
                  --toggle +obfuscation +stealth \
                  --docker deploy
```

**Continuous Monitoring**
```bash
python toolkit.py --section continuous \
                  --watch http://target.com \
                  --cron "0 */6 * * *" \
                  --alerts discord
```

**Forensics Timeline**
```bash
python toolkit.py --section forensics \
                  --target /mnt/evidence/disk.dd \
                  --pipeline timeline_full
```

### Available Options

| Option | Type | Example | Description |
|--------|------|---------|-------------|
| --section | string | osint | Module section |
| --input | string | "username:ATS" | Target data |
| --target | string | example.com | Primary target |
| --pipeline | string | full | Preset pipeline |
| --modules | string | sqlmap,xss | Specific modules |
| --toggle | string | +darkweb -nsfw | Runtime toggles |
| --output | string | pdf,json | Output formats |
| --consent | string | hash123... | Authorization hash |
| --mode | string | web,cli | Execution mode |
| --docker | flag | deploy | Docker operations |
| --help | flag | - | Show help |
| --version | flag | - | Show version |

---

## Dashboard Interface

### Web Dashboard Features

**Navigation Tabs:**
1. **Attack Planner** - Drag-drop module selection, pipeline builder
2. **Live Monitor** - Real-time scan progress, graphs
3. **Reports** - Generated reports, export options
4. **Loot Manager** - Discovered credentials (encrypted)
5. **Settings** - API keys, consent verification

**Design System:**
- Color scheme: Red (#DC143C) and black (#000000)
- Typography: Montserrat (headers), JetBrains Mono (code)
- Animations: Matrix background, neon glows, smooth transitions
- Responsive: Mobile-first design for field testing

**Key Features:**
- Real-time WebSocket updates
- Drag-drop module builder
- One-click report export
- Encrypted credential display
- Consent verification
- Dark mode (default)

---

## Configuration

### API Keys Setup

```bash
# Create environment file
cp config/api_keys.env.example config/api_keys.env

# Edit and add your API keys
SHODAN_API_KEY=your_shodan_key
HIBP_API_KEY=your_hibp_key
DISCORD_WEBHOOK=https://discord.com/api/webhooks/...
SLACK_WEBHOOK=https://hooks.slack.com/services/...
```

### Custom Pipelines

Create custom pipeline in `config/pipelines_osint.yaml`:

```yaml
my_investigation:
  name: "Custom Investigation"
  modules:
    - username_enum
    - email_recon
    - breach_check
    - github_user
    - social_profiles
  chain: sequential
  toggles:
    stealth: true
    cache: true
    timeout: 300
  outputs:
    - json
    - pdf
```

### Wordlist Configuration

Place custom wordlists in `config/wordlists/`:
- `subdomains.txt` - Subdomain list (one per line)
- `webpaths.txt` - Directory/file paths
- `params.txt` - API parameter names

---

## Testing Environment

### Docker Test Stack

```bash
# Start all test services
docker-compose up -d

# Services included:
# - DVWA (Damn Vulnerable Web App) port 8080
# - Metasploitable 3 port 3000
# - Cowrie SSH Honeypot port 2222
# - Cuckoo Sandbox port 8000
```

### Run Test Suite

```bash
# Full test coverage
./tests/test_suite_full.sh

# Individual test suites
./tests/test_osint.sh        # OSINT module tests
./tests/test_pentest.sh      # Pentest module tests
./tests/test_redteam.sh      # Red Team module tests
./tests/test_forensics.sh    # Forensics module tests
./tests/test_ml.sh           # ML module tests
```

### Test Scenarios

Available in `docs/examples/`:
- `osint_workflow.md` - Complete OSINT reconnaissance
- `pentest_workflow.md` - Web application assessment
- `incident_response.md` - Forensics and IR
- `lab_setup.md` - Lab environment configuration

---

## Development

### Setting Up Dev Environment

```bash
# Clone repository
git clone https://github.com/ATS-strasbourg/ATS-toolkit.git
cd ATS-toolkit

# Create virtual environment
python -m venv venv-dev
source venv-dev/bin/activate  # Windows: venv-dev\Scripts\activate

# Install dev dependencies
pip install -r requirements-dev.txt

# Run tests
pytest tests/ --cov=core --cov=osint --cov=pentest -v

# Run linters
black . --check
flake8 . --max-line-length=100
mypy core/ osint/ pentest/

# Build documentation
mkdocs serve
```

### Project Phases

**Phase 1: Foundations** (Week 1-2) ✓
- Architecture design
- Documentation framework
- Legal systems

**Phase 2: Core Engine** (Week 3-4) - In Progress
- Consent Manager
- Cache Manager
- Pipeline Orchestrator

**Phase 3: OSINT Suite** (Week 5-8) - Planned
- 35 OSINT modules
- Multi-platform discovery

**Phase 4: Pentest Tools** (Week 9-11) - Planned
- 25 Pentest modules
- Vulnerability assessment

**Phase 5: Web Dashboard** (Week 12-13) - Planned
- Streamlit backend
- React frontend

**Phase 6: Advanced Modules** (Week 14-16) - Planned
- Red Team, Forensics, ML

**Phase 7: Release** (Week 17-18) - Planned
- CI/CD pipelines
- Docker builds
- PyPI publication

---

## Contributing

### Code Contribution Workflow

1. Fork the repository
2. Create feature branch: `git checkout -b feature/new-module`
3. Make changes and commit: `git commit -am 'Add new module'`
4. Push to branch: `git push origin feature/new-module`
5. Open Pull Request with description

### Module Development

Create new module in appropriate section directory:

```python
# osint/modules/new_module.py
"""
Module Name - Brief description

Authorized use only. Educational platform for cybersecurity professionals.
"""

from typing import Dict, List, Optional
from datetime import datetime
from core.pipeline_engine import ModuleResult, ModuleStatus

async def execute(target: str, config: Dict) -> ModuleResult:
    """
    Execute module reconnaissance.
    
    Args:
        target: Target identifier (domain, email, username, etc)
        config: Module configuration from pipeline
        
    Returns:
        ModuleResult containing findings
    """
    findings = []
    errors = []
    
    try:
        # Your implementation here
        pass
    except Exception as e:
        errors.append(str(e))
    
    return ModuleResult(
        module_name="new_module",
        status=ModuleStatus.SUCCESS if not errors else ModuleStatus.ERROR,
        findings=findings,
        errors=errors,
        execution_time=0.0,
        timestamp=datetime.utcnow().isoformat(),
        metadata={"target": target}
    )
```

### Code Standards

- **Python**: PEP 8, type hints, Google-style docstrings
- **Async**: Use async/await for I/O operations
- **Error Handling**: Try-catch with informative messages
- **Security**: Input validation, sanitization
- **Testing**: Unit tests + integration tests (80%+ coverage)
- **Documentation**: Inline comments, module docstrings

---

## FAQ

### General Questions

**Q: Is ATS-Toolkit legal?**
A: Yes, when used exclusively on authorized systems. Unauthorized access is illegal worldwide.

**Q: Can I use this for bug bounties?**
A: Yes, strictly within authorized programs (HackerOne, Bugcrowd) following program guidelines.

**Q: What's the difference between sections?**
A: OSINT focuses on passive information gathering, Pentest performs active vulnerability testing, and RedTeam simulates adversarial exploitation.

**Q: Do I need programming knowledge?**
A: Basic CLI/dashboard usage requires no programming experience. Module development requires Python proficiency.

### Technical Questions

**Q: Why is consent tracking important?**
A: Consent tracking provides cryptographic proof of authorization for legal compliance and audit trails.

**Q: How does the cache work?**
A: The system uses encrypted SQLite storage with automatic TTL expiration to optimize API usage and reduce redundant requests.

**Q: Can I run this on Windows?**
A: Yes, via WSL2 with Kali Linux (recommended) or natively (with limited functionality).

**Q: What Docker images are included?**
A: The test environment includes DVWA, Metasploitable, Cowrie, and Cuckoo for secure practice environments.

### Module Questions

**Q: Which OSINT modules work without API keys?**
A: Most modules including crt.sh, DNS, and WHOIS operate without API keys. Services like Shodan require free registration for API access.

**Q: Are Red Team modules real malware?**
A: No, these are educational templates designed exclusively for isolated laboratory environments.

**Q: Can I add custom modules?**
A: Yes, refer to CONTRIBUTING.md for module development guidelines and standards.

### Legal Questions

**Q: What if I accidentally scan an unauthorized system?**
A: Cease all activity immediately, document the incident, and notify the system owner. Users bear full legal responsibility for their actions.

**Q: What's required for corporate pentesting?**
A: Corporate penetration testing requires a written contract, explicit management approval, and formal scope authorization.

**Q: How do I handle responsible disclosure?**
A: Follow the industry-standard 90-day coordinated disclosure process with affected vendors.

---

## Support

### Resources

- **Documentation**: [docs.ATS-toolkit.dev](https://docs.ATS-toolkit.dev)
- **Issue Tracker**: [GitHub Issues](https://github.com/ATS-strasbourg/ATS-toolkit/issues)
- **Community Forum**: [GitHub Discussions](https://github.com/ATS-strasbourg/ATS-toolkit/discussions)

### Reporting Issues

```bash
# Include system information
python toolkit.py --debug --version
python toolkit.py --system-info > debug.txt
```

### Security Vulnerabilities

Report security vulnerabilities to: [security@ATS-toolkit.dev](mailto:security@ATS-toolkit.dev)

---

## License

ATS-Toolkit v2.0 is released under the MIT License with an Educational Use Annex.

```
MIT License + Educational Use Annex

Copyright (c) 2026 ATS

Permission is hereby granted to use this software exclusively for educational,
research, and authorized security testing purposes.
```

**Additional Terms:**
1. Commercial use requires explicit written authorization
2. Malicious use is strictly prohibited and may result in legal action
3. Users must maintain full compliance with all applicable laws
4. Authors and contributors disclaim all liability for misuse

Refer to the [LICENSE](LICENSE) file for complete terms and conditions.

---

<div align="center">

**ATS-Toolkit v2.0**

*Professional Security & Intelligence Framework*

Designed for authorized cybersecurity professionals and educators worldwide.

**⚠️ LEGAL NOTICE ⚠️**

Always obtain explicit written authorization before testing any system.

Unauthorized access is illegal and carries severe criminal penalties worldwide.

---

© 2026 ATS - All Rights Reserved

</div>

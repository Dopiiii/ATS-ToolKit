#!/usr/bin/env python3
"""
ATS-Toolkit - Core Utilities
Common helper functions used across all modules

⚠️ EDUCATIONAL USE ONLY - AUTHORIZED SYSTEMS ONLY ⚠️
"""

import re
import sys
import hashlib
import socket
from typing import Optional, Dict, Any, List
from datetime import datetime
from pathlib import Path
import json

# ANSI Color codes for terminal output
class Colors:
    """ANSI color codes for beautiful terminal output"""
    # Basic colors
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    
    # Bright colors
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'
    
    # Styles
    BOLD = '\033[1m'
    DIM = '\033[2m'
    UNDERLINE = '\033[4m'
    BLINK = '\033[5m'
    REVERSE = '\033[7m'
    
    # Reset
    RESET = '\033[0m'
    
    # ATS Brand colors (dark red theme)
    ATS_RED = '\033[38;5;88m'        # Dark red
    ATS_CRIMSON = '\033[38;5;160m'   # Crimson
    ATS_BRIGHT_RED = '\033[38;5;196m' # Bright red


def print_banner():
    """Display ATS-Toolkit ASCII banner"""
    banner = f"""
{Colors.ATS_CRIMSON}{Colors.BOLD}
    ___  ___________   ______            __ __   _ __
   /   |/_  __/ ___/  /_  __/___  ____  / // /__(_) /_
  / /| | / /  \\__ \\    / / / __ \\/ __ \\/ // //_/ / __/
 / ___ |/ /  ___/ /   / / / /_/ / /_/ / // ,< / / /_
/_/  |_/_/  /____/   /_/  \\____/\\____/_//_/|_/_/\\__/

{Colors.ATS_RED}ATS-Toolkit v2.0{Colors.RESET}
{Colors.DIM}Professional Security & Intelligence Framework{Colors.RESET}
{Colors.YELLOW}[!] EDUCATIONAL USE ONLY - AUTHORIZED SYSTEMS ONLY [!]{Colors.RESET}
"""
    try:
        print(banner)
    except UnicodeEncodeError:
        # Fallback for Windows console
        simple_banner = """
    ___  ___________   ______            __ __   _ __
   /   |/_  __/ ___/  /_  __/___  ____  / // /__(_) /_
  / /| | / /  \\__ \\    / / / __ \\/ __ \\/ // //_/ / __/
 / ___ |/ /  ___/ /   / / / /_/ / /_/ / // ,< / / /_
/_/  |_/_/  /____/   /_/  \\____/\\____/_//_/|_/_/\\__/

ATS-Toolkit v2.0
Professional Security & Intelligence Framework
[!] EDUCATIONAL USE ONLY - AUTHORIZED SYSTEMS ONLY [!]
"""
        print(simple_banner)


def print_success(message: str):
    """Print success message in green"""
    try:
        print(f"{Colors.BRIGHT_GREEN}[+]{Colors.RESET} {message}")
    except UnicodeEncodeError:
        print(f"[+] {message}")


def print_error(message: str):
    """Print error message in red"""
    try:
        print(f"{Colors.BRIGHT_RED}[x]{Colors.RESET} {message}", file=sys.stderr)
    except UnicodeEncodeError:
        print(f"[x] {message}", file=sys.stderr)


def print_warning(message: str):
    """Print warning message in yellow"""
    try:
        print(f"{Colors.BRIGHT_YELLOW}[!]{Colors.RESET} {message}")
    except UnicodeEncodeError:
        print(f"[!] {message}")


def print_info(message: str):
    """Print info message in cyan"""
    try:
        print(f"{Colors.BRIGHT_CYAN}[*]{Colors.RESET} {message}")
    except UnicodeEncodeError:
        print(f"[*] {message}")


def print_debug(message: str, debug: bool = False):
    """Print debug message in dim white (only if debug=True)"""
    if debug:
        print(f"{Colors.DIM}[DEBUG]{Colors.RESET} {message}")


def print_section(title: str):
    """Print section header"""
    width = 70
    line = "=" * width
    print(f"\n{Colors.BOLD}{Colors.ATS_CRIMSON}{line}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.ATS_CRIMSON}{title.center(width)}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.ATS_CRIMSON}{line}{Colors.RESET}\n")


# ============================================================================
# VALIDATION FUNCTIONS
# ============================================================================

def is_valid_domain(domain: str) -> bool:
    """
    Validate domain name format.
    
    Args:
        domain: Domain to validate
        
    Returns:
        True if valid domain format
        
    Examples:
        >>> is_valid_domain("example.com")
        True
        >>> is_valid_domain("sub.example.co.uk")
        True
        >>> is_valid_domain("invalid..domain")
        False
    """
    # Basic domain regex (simplified)
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))


def is_valid_ip(ip: str) -> bool:
    """
    Validate IPv4 address format.
    
    Args:
        ip: IP address to validate
        
    Returns:
        True if valid IPv4 format
        
    Examples:
        >>> is_valid_ip("192.168.1.1")
        True
        >>> is_valid_ip("999.999.999.999")
        False
    """
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False


def is_valid_url(url: str) -> bool:
    """
    Validate URL format.
    
    Args:
        url: URL to validate
        
    Returns:
        True if valid URL format
    """
    pattern = r'^https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&/=]*)$'
    return bool(re.match(pattern, url))


def is_valid_email(email: str) -> bool:
    """
    Validate email address format.
    
    Args:
        email: Email to validate
        
    Returns:
        True if valid email format
    """
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename by removing dangerous characters.
    
    Args:
        filename: Original filename
        
    Returns:
        Safe filename
        
    Examples:
        >>> sanitize_filename("report_2024-01-19.pdf")
        'report_2024-01-19.pdf'
        >>> sanitize_filename("../../etc/passwd")
        'etc_passwd'
    """
    # Remove path separators and dangerous chars
    safe = re.sub(r'[^\w\-_\. ]', '_', filename)
    # Remove leading dots (hidden files)
    safe = safe.lstrip('.')
    return safe


# ============================================================================
# HASHING & CRYPTO
# ============================================================================

def generate_hash(data: str, algorithm: str = "sha256") -> str:
    """
    Generate cryptographic hash of data.
    
    Args:
        data: Data to hash
        algorithm: Hash algorithm (md5, sha1, sha256, sha512)
        
    Returns:
        Hexadecimal hash string
        
    Examples:
        >>> generate_hash("test")
        '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'
    """
    if algorithm == "md5":
        return hashlib.md5(data.encode()).hexdigest()
    elif algorithm == "sha1":
        return hashlib.sha1(data.encode()).hexdigest()
    elif algorithm == "sha256":
        return hashlib.sha256(data.encode()).hexdigest()
    elif algorithm == "sha512":
        return hashlib.sha512(data.encode()).hexdigest()
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")


def generate_consent_hash(target: str, modules: List[str], user_id: str) -> str:
    """
    Generate consent hash for blockchain logging.
    
    Args:
        target: Target being scanned
        modules: List of modules to use
        user_id: User identifier
        
    Returns:
        SHA256 hash for consent tracking
    """
    timestamp = datetime.utcnow().isoformat()
    data = f"{timestamp}|{target}|{','.join(modules)}|{user_id}"
    return generate_hash(data, "sha256")


# ============================================================================
# FILE OPERATIONS
# ============================================================================

def ensure_dir(directory: Path) -> Path:
    """
    Ensure directory exists, create if not.
    
    Args:
        directory: Directory path
        
    Returns:
        Path object
    """
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def get_project_root() -> Path:
    """
    Get project root directory.
    
    Returns:
        Path to project root
    """
    # Assume this file is in core/, so parent is root
    return Path(__file__).parent.parent


def get_reports_dir() -> Path:
    """Get reports output directory"""
    return ensure_dir(get_project_root() / "reports")


def get_logs_dir() -> Path:
    """Get logs directory"""
    return ensure_dir(get_project_root() / "logs")


def get_data_dir() -> Path:
    """Get data storage directory"""
    return ensure_dir(get_project_root() / "data")


def save_json(data: Dict[Any, Any], filepath: Path):
    """
    Save dictionary to JSON file.
    
    Args:
        data: Dictionary to save
        filepath: Output file path
    """
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def load_json(filepath: Path) -> Optional[Dict[Any, Any]]:
    """
    Load JSON file to dictionary.
    
    Args:
        filepath: JSON file path
        
    Returns:
        Dictionary or None if file doesn't exist
    """
    if not filepath.exists():
        return None
        
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)


# ============================================================================
# TIMESTAMP & FORMATTING
# ============================================================================

def get_timestamp(format: str = "iso") -> str:
    """
    Get current timestamp in various formats.
    
    Args:
        format: "iso", "filename", "human"
        
    Returns:
        Formatted timestamp string
        
    Examples:
        >>> get_timestamp("iso")
        '2026-01-19T14:30:45.123456'
        >>> get_timestamp("filename")
        '20260119_143045'
        >>> get_timestamp("human")
        '2026-01-19 14:30:45'
    """
    now = datetime.utcnow()
    
    if format == "iso":
        return now.isoformat()
    elif format == "filename":
        return now.strftime("%Y%m%d_%H%M%S")
    elif format == "human":
        return now.strftime("%Y-%m-%d %H:%M:%S")
    else:
        raise ValueError(f"Unknown format: {format}")


def format_bytes(bytes_num: int) -> str:
    """
    Format bytes to human-readable size.
    
    Args:
        bytes_num: Number of bytes
        
    Returns:
        Formatted string (e.g., "1.5 MB")
        
    Examples:
        >>> format_bytes(1024)
        '1.0 KB'
        >>> format_bytes(1048576)
        '1.0 MB'
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_num < 1024.0:
            return f"{bytes_num:.1f} {unit}"
        bytes_num /= 1024.0
    return f"{bytes_num:.1f} PB"


def format_duration(seconds: float) -> str:
    """
    Format seconds to human-readable duration.
    
    Args:
        seconds: Duration in seconds
        
    Returns:
        Formatted string (e.g., "2m 30s")
        
    Examples:
        >>> format_duration(150)
        '2m 30s'
        >>> format_duration(3665)
        '1h 1m 5s'
    """
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{minutes}m {secs}s"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)
        return f"{hours}h {minutes}m {secs}s"


# ============================================================================
# NETWORK UTILITIES
# ============================================================================

def resolve_domain(domain: str) -> Optional[str]:
    """
    Resolve domain to IP address.
    
    Args:
        domain: Domain name
        
    Returns:
        IP address or None if resolution fails
    """
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


def reverse_dns(ip: str) -> Optional[str]:
    """
    Reverse DNS lookup (IP to hostname).
    
    Args:
        ip: IP address
        
    Returns:
        Hostname or None if lookup fails
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return None


# ============================================================================
# PROGRESS & STATUS
# ============================================================================

class ProgressBar:
    """Simple progress bar for terminal"""
    
    def __init__(self, total: int, prefix: str = "Progress", width: int = 50):
        """
        Initialize progress bar.
        
        Args:
            total: Total number of items
            prefix: Prefix text
            width: Bar width in characters
        """
        self.total = total
        self.prefix = prefix
        self.width = width
        self.current = 0
        
    def update(self, amount: int = 1):
        """Update progress by amount"""
        self.current += amount
        self.display()
        
    def display(self):
        """Display current progress"""
        if self.total == 0:
            return
            
        percent = self.current / self.total
        filled = int(self.width * percent)
        bar = '█' * filled + '░' * (self.width - filled)
        
        print(f'\r{self.prefix}: |{bar}| {percent*100:.1f}%', end='', flush=True)
        
        if self.current >= self.total:
            print()  # New line when complete


# ============================================================================
# TESTING
# ============================================================================

if __name__ == "__main__":
    # Demo/test utilities
    print_banner()
    print_section("Testing Core Utilities")
    
    print_success("Success message test")
    print_error("Error message test")
    print_warning("Warning message test")
    print_info("Info message test")
    print_debug("Debug message test", debug=True)
    
    print("\n--- Validation Tests ---")
    print(f"is_valid_domain('example.com'): {is_valid_domain('example.com')}")
    print(f"is_valid_ip('192.168.1.1'): {is_valid_ip('192.168.1.1')}")
    print(f"is_valid_email('test@example.com'): {is_valid_email('test@example.com')}")
    
    print("\n--- Hash Tests ---")
    print(f"SHA256 of 'test': {generate_hash('test', 'sha256')[:32]}...")
    
    print("\n--- Timestamp Tests ---")
    print(f"ISO: {get_timestamp('iso')}")
    print(f"Filename: {get_timestamp('filename')}")
    print(f"Human: {get_timestamp('human')}")
    
    print("\n--- Format Tests ---")
    print(f"1048576 bytes: {format_bytes(1048576)}")
    print(f"150 seconds: {format_duration(150)}")
    
    print("\n--- Progress Bar Test ---")
    import time
    progress = ProgressBar(10, "Scanning")
    for i in range(10):
        time.sleep(0.1)
        progress.update()
    
    print_success("\nAll utility tests completed!")
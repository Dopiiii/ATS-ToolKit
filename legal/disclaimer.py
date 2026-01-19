#!/usr/bin/env python3
"""
ATS-Toolkit - Legal Disclaimer Display System
Mandatory legal warning display before ANY toolkit operation

⚠️ THIS MODULE MUST BE IMPORTED AND EXECUTED BEFORE ANY SCANNING ⚠️
"""

import sys
import time
from datetime import datetime
from pathlib import Path

# Try to import rich for beautiful output, fallback to basic print
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
    from rich.prompt import Confirm
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


class LegalDisclaimer:
    """
    Legal disclaimer display and acceptance tracking.
    
    Features:
    - Beautiful formatted output (rich) or fallback plain text
    - Multi-language support (English, French)
    - Acceptance tracking with timestamp
    - Screen clearing for visibility
    - Mandatory 3-second read time
    """
    
    DISCLAIMER_EN = """
+========================================================================+
|             [!] ATS-TOOLKIT v2.0 - LEGAL DISCLAIMER [!]                |
|                    Attack & Testing Suite                              |
+========================================================================+
|                                                                        |
|  EDUCATIONAL USE ONLY - NO MALICIOUS ACTIVITY PERMITTED                |
|                                                                        |
|  CONDITIONS:                                                           |
|  [+] Tests ONLY on owned systems (VMs, localhost, isolated labs)       |
|  [+] Written consent REQUIRED for third-party systems                  |
|  [x] Unauthorized access = CRIMINAL OFFENSE (prison + fines)           |
|  [x] Author assumes ZERO liability - YOU assume ALL risks              |
|                                                                        |
|  AUTHORIZED USE:                                                       |
|  * Your personal VMs/Docker containers                                 |
|  * DVWA, Metasploitable, WebGoat, bWAPP (educational labs)             |
|  * Bug bounty programs within scope (HackerOne, Bugcrowd)              |
|  * Pentests with signed contracts + legal authorization                |
|                                                                        |
|  PROHIBITED USE:                                                       |
|  * Any system without WRITTEN permission                               |
|  * Companies without pentest contracts                                 |
|  * Public networks (WiFi, cloud, third-party infrastructure)           |
|  * Real data harvesting without consent                                |
|  * Creating/deploying actual malware                                   |
|                                                                        |
|  CRIMINAL PENALTIES:                                                   |
|  - France: Up to 5 years prison + 75,000 EUR fine                      |
|  - USA: Up to 10 years prison + $250,000 fine (CFAA)                   |
|  - UK: Up to 10 years prison + unlimited fine                          |
|  - EU: GDPR violations up to 20M EUR or 4% global revenue              |
|                                                                        |
|  BLOCKCHAIN CONSENT:                                                   |
|  Every scan requires cryptographic consent hash (SHA256)               |
|  Immutable audit trail stored locally for legal protection             |
|                                                                        |
|  BY USING ATS-TOOLKIT YOU ACCEPT:                                      |
|  * Full legal responsibility for your actions                          |
|  * Compliance with all applicable laws                                 |
|  * To obtain proper authorization before testing                       |
|  * That author has ZERO liability for misuse                           |
|                                                                        |
+========================================================================+

IF YOU DO NOT AGREE, EXIT NOW AND DO NOT USE THIS SOFTWARE.
Unauthorized computer access is ILLEGAL and IMMORAL.

See LICENSE file for complete legal terms (MIT + Educational Annex).
"""

    DISCLAIMER_FR = """
+========================================================================+
|            [!] ATS-TOOLKIT v2.0 - AVERTISSEMENT LEGAL [!]              |
|                    Attack & Testing Suite                              |
+========================================================================+
|                                                                        |
|  USAGE EDUCATIF UNIQUEMENT - AUCUNE ACTIVITE MALVEILLANTE              |
|                                                                        |
|  CONDITIONS :                                                          |
|  [+] Tests UNIQUEMENT sur vos propres systemes (VMs, localhost)        |
|  [+] Consentement ECRIT OBLIGATOIRE pour systemes tiers                |
|  [x] Acces non-autorise = DELIT PENAL (prison + amendes)               |
|  [x] Auteur = ZERO responsabilite - VOUS assumez TOUS les risques      |
|                                                                        |
|  SANCTIONS PENALES :                                                   |
|  Articles 323-1 a 323-7 Code Penal                                     |
|  Jusqu'a 5 ans de prison + 75 000 EUR d'amende                         |
|                                                                        |
|  EN UTILISANT ATS-TOOLKIT VOUS ACCEPTEZ :                              |
|  * Responsabilite legale totale de vos actions                         |
|  * Conformite avec toutes les lois applicables                         |
|  * D'obtenir une autorisation avant tout test                          |
|  * Que l'auteur n'a AUCUNE responsabilite en cas d'abus                |
|                                                                        |
+========================================================================+

SI VOUS N'ACCEPTEZ PAS, QUITTEZ MAINTENANT.
L'acces non-autorise aux systemes informatiques est ILLEGAL.

Voir fichier LICENSE pour les termes legaux complets.
"""
    
    def __init__(self, language: str = "en"):
        """
        Initialize disclaimer display.
        
        Args:
            language: "en" (English) or "fr" (French)
        """
        self.language = language
        self.disclaimer_text = self.DISCLAIMER_EN if language == "en" else self.DISCLAIMER_FR
        self.console = Console() if RICH_AVAILABLE else None
        self.accepted = False
        self.acceptance_timestamp = None
        
    def clear_screen(self):
        """Clear terminal screen (cross-platform)"""
        import os
        os.system('cls' if os.name == 'nt' else 'clear')
        
    def display_rich(self):
        """Display disclaimer using rich library (beautiful output)"""
        self.clear_screen()

        # Create styled text
        disclaimer = Text(self.disclaimer_text)
        disclaimer.stylize("bold red")

        # Create panel with red border
        panel = Panel(
            disclaimer,
            border_style="bold red",
            title="[!] LEGAL DISCLAIMER [!]",
            title_align="center"
        )

        self.console.print(panel)
        self.console.print()
        
    def display_plain(self):
        """Display disclaimer using plain text (fallback)"""
        self.clear_screen()
        print(self.disclaimer_text)
        print()
        
    def display(self):
        """Display disclaimer (auto-detect best method)"""
        if RICH_AVAILABLE and self.console:
            self.display_rich()
        else:
            self.display_plain()
            
    def enforce_read_time(self, seconds: int = 3):
        """
        Enforce minimum read time before acceptance.

        Args:
            seconds: Minimum seconds user must wait
        """
        print(f"[*] Please read carefully... ({seconds} seconds minimum)")
        for i in range(seconds, 0, -1):
            print(f"    Continuing in {i}...", end='\r')
            time.sleep(1)
        print("    " + " " * 50)  # Clear countdown line
        
    def prompt_acceptance(self) -> bool:
        """
        Prompt user to accept legal terms.
        
        Returns:
            True if accepted, False otherwise
        """
        if RICH_AVAILABLE:
            accepted = Confirm.ask(
                "\n[bold red]Do you accept these terms and conditions?[/bold red]",
                default=False
            )
        else:
            response = input("\nDo you accept these terms and conditions? (yes/no): ").strip().lower()
            accepted = response in ['yes', 'y', 'oui', 'o']
            
        if accepted:
            self.accepted = True
            self.acceptance_timestamp = datetime.utcnow().isoformat()
            self._log_acceptance()

            if RICH_AVAILABLE:
                self.console.print("\n[+] [bold green]Legal terms accepted[/bold green]")
                self.console.print(f"[*] Timestamp: {self.acceptance_timestamp}")
            else:
                print("\n[+] Legal terms accepted")
                print(f"[*] Timestamp: {self.acceptance_timestamp}")
        else:
            if RICH_AVAILABLE:
                self.console.print("\n[x] [bold red]Legal terms NOT accepted - Exiting[/bold red]")
            else:
                print("\n[x] Legal terms NOT accepted - Exiting")
                
        return accepted
        
    def _log_acceptance(self):
        """Log acceptance to file for audit trail"""
        log_dir = Path(__file__).parent.parent / "logs"
        log_dir.mkdir(exist_ok=True)
        
        log_file = log_dir / "legal_acceptance.log"
        
        with open(log_file, "a") as f:
            f.write(f"{self.acceptance_timestamp} - Legal disclaimer accepted\n")
            
    def require_acceptance(self) -> bool:
        """
        Complete flow: display disclaimer, enforce read time, prompt acceptance.
        
        Returns:
            True if accepted, exits program if declined
        """
        self.display()
        self.enforce_read_time(seconds=3)
        
        accepted = self.prompt_acceptance()
        
        if not accepted:
            print("\n[!] Exiting ATS-Toolkit. Use responsibly.")
            sys.exit(0)
            
        return True


def show_disclaimer(language: str = "en", auto_exit: bool = True) -> bool:
    """
    Convenience function to show disclaimer and get acceptance.
    
    Args:
        language: "en" or "fr"
        auto_exit: Exit program if not accepted (default: True)
        
    Returns:
        True if accepted
        
    Example:
        >>> from legal.disclaimer import show_disclaimer
        >>> show_disclaimer()
        # Displays disclaimer, returns True if accepted or exits if declined
    """
    disclaimer = LegalDisclaimer(language=language)
    return disclaimer.require_acceptance()


def check_acceptance_log() -> bool:
    """
    Check if user has previously accepted disclaimer (today).
    
    Returns:
        True if already accepted today, False otherwise
    """
    log_file = Path(__file__).parent.parent / "logs" / "legal_acceptance.log"
    
    if not log_file.exists():
        return False
        
    today = datetime.utcnow().date().isoformat()
    
    with open(log_file, "r") as f:
        for line in f:
            if today in line:
                return True
                
    return False


# ============================================================================
# AUTO-DISPLAY ON IMPORT (if run as main)
# ============================================================================

if __name__ == "__main__":
    # Demo/test mode
    print("ATS-Toolkit Legal Disclaimer - Demo Mode\n")
    show_disclaimer(language="en")
    print("\n✅ Demo completed successfully!")
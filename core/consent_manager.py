#!/usr/bin/env python3
"""
ATS-Toolkit - Consent Manager with Blockchain-Inspired Tracking
Immutable audit trail for legal authorization tracking

⚠️ EDUCATIONAL USE ONLY - AUTHORIZED SYSTEMS ONLY ⚠️
"""

import sqlite3
import hashlib
import json
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Tuple
from pathlib import Path
from dataclasses import dataclass, asdict

from core.utils import get_data_dir, print_success, print_error, print_info
from core.exceptions import InvalidConsentHashError


@dataclass
class ConsentRecord:
    """Single consent record in the blockchain"""
    id: int
    timestamp: str
    consent_hash: str
    target: str
    modules: str  # JSON string
    user_signature: str
    prev_hash: str
    block_hash: str
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return asdict(self)
    
    @property
    def modules_list(self) -> List[str]:
        """Parse modules JSON string to list"""
        return json.loads(self.modules)


class ConsentManager:
    """
    Blockchain-inspired consent tracking system.
    
    Features:
    - SHA256 cryptographic hashing
    - Immutable chain with previous block hash
    - Chain integrity verification
    - Timestamp-based audit trail
    - Tamper detection
    
    Each scan requires a valid consent hash proving authorization.
    """
    
    def __init__(self, db_path: Optional[Path] = None):
        """
        Initialize Consent Manager.
        
        Args:
            db_path: Path to SQLite database (default: data/consent.db)
        """
        if db_path is None:
            db_path = get_data_dir() / "consent.db"
        
        self.db_path = Path(db_path)
        self.init_database()
        
    def init_database(self):
        """Initialize consent blockchain database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS consent_chain (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                consent_hash TEXT UNIQUE NOT NULL,
                target TEXT NOT NULL,
                modules TEXT NOT NULL,
                user_signature TEXT NOT NULL,
                prev_hash TEXT,
                block_hash TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Index for fast hash lookups
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_consent_hash 
            ON consent_chain(consent_hash)
        """)
        
        # Index for timestamp queries
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_timestamp 
            ON consent_chain(timestamp)
        """)
        
        conn.commit()
        conn.close()
        
    def generate_consent_hash(self, 
                             target: str, 
                             modules: List[str], 
                             user_id: str = "default") -> str:
        """
        Generate cryptographic consent hash and store in blockchain.
        
        Args:
            target: Target being scanned (domain, IP, etc.)
            modules: List of modules to be used
            user_id: User identifier (email, username, etc.)
            
        Returns:
            Consent hash (SHA256) for this authorization
            
        Example:
            >>> cm = ConsentManager()
            >>> hash = cm.generate_consent_hash("example.com", ["whois", "dns"], "eric@test.com")
            >>> print(hash)
            'a3f5c9d7e2b8f1a6c4e9d2b7f5a3c8e1...'
        """
        # Generate timestamp
        timestamp = datetime.utcnow().isoformat()
        
        # Create consent data string
        consent_data = f"{timestamp}|{target}|{','.join(sorted(modules))}|{user_id}"
        
        # Generate consent hash
        consent_hash = hashlib.sha256(consent_data.encode()).hexdigest()
        
        # Get previous block hash for chain integrity
        prev_hash = self._get_last_block_hash()
        
        # Create block hash (consent + previous)
        block_data = f"{consent_hash}|{prev_hash}"
        block_hash = hashlib.sha256(block_data.encode()).hexdigest()
        
        # Store in blockchain
        self._store_consent(
            timestamp=timestamp,
            consent_hash=consent_hash,
            target=target,
            modules=modules,
            user_signature=user_id,
            prev_hash=prev_hash,
            block_hash=block_hash
        )
        
        return consent_hash
    
    def _get_last_block_hash(self) -> str:
        """
        Get hash of last block in chain.
        
        Returns:
            Block hash or "genesis" for first block
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT block_hash FROM consent_chain ORDER BY id DESC LIMIT 1")
        result = cursor.fetchone()
        
        conn.close()
        
        return result[0] if result else "genesis"
    
    def _store_consent(self, 
                      timestamp: str,
                      consent_hash: str,
                      target: str,
                      modules: List[str],
                      user_signature: str,
                      prev_hash: str,
                      block_hash: str):
        """Store consent record in blockchain"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        modules_json = json.dumps(modules)
        
        try:
            cursor.execute("""
                INSERT INTO consent_chain 
                (timestamp, consent_hash, target, modules, user_signature, prev_hash, block_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (timestamp, consent_hash, target, modules_json, user_signature, prev_hash, block_hash))
            
            conn.commit()
            
        except sqlite3.IntegrityError:
            # Consent hash already exists (duplicate)
            conn.close()
            raise ValueError(f"Consent hash already exists: {consent_hash}")
            
        conn.close()
        
    def verify_consent(self, consent_hash: str, max_age_hours: int = 24) -> bool:
        """
        Verify consent hash exists and is not expired.
        
        Args:
            consent_hash: Consent hash to verify
            max_age_hours: Maximum age in hours (default: 24h)
            
        Returns:
            True if valid and not expired
            
        Raises:
            InvalidConsentHashError: If hash is invalid or expired
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT timestamp, target, modules 
            FROM consent_chain 
            WHERE consent_hash = ?
        """, (consent_hash,))
        
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            raise InvalidConsentHashError(consent_hash)
        
        timestamp_str, target, modules_json = result
        
        # Check expiration
        timestamp = datetime.fromisoformat(timestamp_str)
        age = datetime.utcnow() - timestamp
        
        if age > timedelta(hours=max_age_hours):
            raise InvalidConsentHashError(f"{consent_hash} (expired after {max_age_hours}h)")
        
        return True
    
    def get_consent_details(self, consent_hash: str) -> Optional[ConsentRecord]:
        """
        Get detailed information about a consent record.
        
        Args:
            consent_hash: Consent hash
            
        Returns:
            ConsentRecord or None if not found
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, timestamp, consent_hash, target, modules, 
                   user_signature, prev_hash, block_hash
            FROM consent_chain 
            WHERE consent_hash = ?
        """, (consent_hash,))
        
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return None
        
        return ConsentRecord(*result)
    
    def list_recent_consents(self, limit: int = 10) -> List[ConsentRecord]:
        """
        List recent consent records.
        
        Args:
            limit: Maximum number of records to return
            
        Returns:
            List of ConsentRecord objects
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, timestamp, consent_hash, target, modules, 
                   user_signature, prev_hash, block_hash
            FROM consent_chain 
            ORDER BY id DESC 
            LIMIT ?
        """, (limit,))
        
        results = cursor.fetchall()
        conn.close()
        
        return [ConsentRecord(*row) for row in results]
    
    def verify_chain_integrity(self) -> Tuple[bool, Optional[str]]:
        """
        Verify entire blockchain integrity.
        
        Returns:
            (is_valid, error_message)
            
        Example:
            >>> cm = ConsentManager()
            >>> valid, error = cm.verify_chain_integrity()
            >>> if valid:
            >>>     print("[+] Chain integrity verified")
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, consent_hash, prev_hash, block_hash 
            FROM consent_chain 
            ORDER BY id
        """)
        
        blocks = cursor.fetchall()
        conn.close()
        
        if not blocks:
            return True, None  # Empty chain is valid
        
        # Verify each block
        for i, (block_id, consent_hash, prev_hash, block_hash) in enumerate(blocks):
            # Verify block hash calculation
            expected_block = hashlib.sha256(f"{consent_hash}|{prev_hash}".encode()).hexdigest()
            
            if expected_block != block_hash:
                return False, f"Block {block_id} has invalid hash"
            
            # Verify chain linkage (except genesis block)
            if i > 0:
                prev_block_hash = blocks[i-1][3]  # Previous block's block_hash
                if prev_hash != prev_block_hash:
                    return False, f"Block {block_id} has broken chain link"
        
        return True, None
    
    def get_stats(self) -> Dict:
        """
        Get blockchain statistics.
        
        Returns:
            Dictionary with stats (total_blocks, first_timestamp, last_timestamp, etc.)
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM consent_chain")
        total_blocks = cursor.fetchone()[0]
        
        cursor.execute("SELECT timestamp FROM consent_chain ORDER BY id ASC LIMIT 1")
        first = cursor.fetchone()
        first_timestamp = first[0] if first else None
        
        cursor.execute("SELECT timestamp FROM consent_chain ORDER BY id DESC LIMIT 1")
        last = cursor.fetchone()
        last_timestamp = last[0] if last else None
        
        cursor.execute("SELECT COUNT(DISTINCT target) FROM consent_chain")
        unique_targets = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            "total_blocks": total_blocks,
            "first_timestamp": first_timestamp,
            "last_timestamp": last_timestamp,
            "unique_targets": unique_targets,
            "database_path": str(self.db_path)
        }
    
    def display_stats(self):
        """Display blockchain statistics in terminal"""
        stats = self.get_stats()
        
        print_info("Consent Blockchain Statistics:")
        print(f"  Total Consents: {stats['total_blocks']}")
        print(f"  Unique Targets: {stats['unique_targets']}")
        print(f"  First Consent:  {stats['first_timestamp'] or 'None'}")
        print(f"  Last Consent:   {stats['last_timestamp'] or 'None'}")
        print(f"  Database:       {stats['database_path']}")
        
        # Verify integrity
        valid, error = self.verify_chain_integrity()
        if valid:
            print_success("  Chain Integrity: [+] VALID")
        else:
            print_error(f"  Chain Integrity: [x] INVALID - {error}")


# ============================================================================
# CLI INTERFACE
# ============================================================================

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="ATS-Toolkit Consent Manager")
    parser.add_argument("--generate", nargs=3, metavar=("TARGET", "MODULES", "USER"),
                       help="Generate consent hash")
    parser.add_argument("--verify", metavar="HASH",
                       help="Verify consent hash")
    parser.add_argument("--list", type=int, metavar="N", default=10,
                       help="List N recent consents")
    parser.add_argument("--stats", action="store_true",
                       help="Show blockchain statistics")
    parser.add_argument("--check-integrity", action="store_true",
                       help="Verify blockchain integrity")
    
    args = parser.parse_args()
    
    cm = ConsentManager()
    
    if args.generate:
        target, modules, user = args.generate
        modules_list = modules.split(',')
        consent_hash = cm.generate_consent_hash(target, modules_list, user)
        print_success(f"Consent hash generated: {consent_hash}")
        print(f"Target: {target}")
        print(f"Modules: {', '.join(modules_list)}")
        print(f"User: {user}")
        
    elif args.verify:
        try:
            valid = cm.verify_consent(args.verify)
            if valid:
                print_success(f"[+] Consent hash is VALID: {args.verify}")
                details = cm.get_consent_details(args.verify)
                if details:
                    print(f"Target: {details.target}")
                    print(f"Modules: {', '.join(details.modules_list)}")
                    print(f"Timestamp: {details.timestamp}")
        except InvalidConsentHashError as e:
            print_error(f"[x] {e}")
            
    elif args.stats:
        cm.display_stats()
        
    elif args.check_integrity:
        valid, error = cm.verify_chain_integrity()
        if valid:
            print_success("[+] Blockchain integrity verified - No tampering detected")
        else:
            print_error(f"[x] Blockchain integrity check FAILED: {error}")
            
    else:
        # Default: list recent consents
        print_info(f"Recent consent records (last {args.list}):")
        consents = cm.list_recent_consents(args.list)
        
        if not consents:
            print("  No consent records found.")
        else:
            for consent in consents:
                print(f"\n  Hash: {consent.consent_hash[:16]}...")
                print(f"  Target: {consent.target}")
                print(f"  Modules: {', '.join(consent.modules_list)}")
                print(f"  Time: {consent.timestamp}")
#!/usr/bin/env python3
"""
ATS-Toolkit - Cache Manager with Encryption
SQLite cache with Fernet encryption and TTL support

⚠️ EDUCATIONAL USE ONLY - AUTHORIZED SYSTEMS ONLY ⚠️
"""

import sqlite3
import json
import time
from typing import Any, Optional, Dict
from pathlib import Path
from cryptography.fernet import Fernet

from core.utils import get_data_dir, print_success, print_info, print_warning
from core.exceptions import CacheCorruptedError, CacheEncryptionError


class CacheManager:
    """
    Encrypted cache manager using SQLite + Fernet.
    
    Features:
    - Fernet symmetric encryption (AES-128)
    - TTL (Time To Live) support
    - Automatic expiration cleanup
    - Fast key-based lookups
    - Encrypted at rest
    
    Use cases:
    - Cache OSINT results (avoid rate limits)
    - Store API responses
    - Temporary data storage with auto-expiration
    """
    
    DEFAULT_TTL = 604800  # 7 days in seconds
    
    def __init__(self, 
                 db_path: Optional[Path] = None,
                 encryption_key: Optional[bytes] = None,
                 auto_cleanup: bool = True):
        """
        Initialize Cache Manager.
        
        Args:
            db_path: Path to SQLite database (default: data/cache.db)
            encryption_key: Fernet encryption key (generates new if None)
            auto_cleanup: Automatically cleanup expired entries on init
        """
        if db_path is None:
            db_path = get_data_dir() / "cache.db"
        
        self.db_path = Path(db_path)
        
        # Handle encryption key
        key_file = self.db_path.parent / ".cache_key"
        
        if encryption_key:
            self.key = encryption_key
        elif key_file.exists():
            # Load existing key
            with open(key_file, 'rb') as f:
                self.key = f.read()
        else:
            # Generate new key and save
            self.key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(self.key)
            # Secure file permissions
            key_file.chmod(0o600)
        
        self.cipher = Fernet(self.key)
        self.init_database()
        
        if auto_cleanup:
            self.cleanup_expired()
    
    def init_database(self):
        """Initialize cache database schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cache (
                key TEXT PRIMARY KEY,
                encrypted_value BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                hits INTEGER DEFAULT 0,
                last_accessed INTEGER
            )
        """)
        
        # Index for expiration queries
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_expires_at 
            ON cache(expires_at)
        """)
        
        # Index for creation time
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_created_at 
            ON cache(created_at)
        """)
        
        conn.commit()
        conn.close()
    
    def set(self, key: str, value: Any, ttl: int = DEFAULT_TTL) -> bool:
        """
        Store encrypted value with TTL.
        
        Args:
            key: Cache key (unique identifier)
            value: Value to cache (must be JSON serializable)
            ttl: Time to live in seconds (default: 7 days)
            
        Returns:
            True if stored successfully
            
        Example:
            >>> cache = CacheManager()
            >>> cache.set("whois:example.com", {"registrar": "ACME Inc"}, ttl=3600)
            True
        """
        now = int(time.time())
        expires = now + ttl
        
        try:
            # Serialize to JSON
            json_value = json.dumps(value)
            
            # Encrypt
            encrypted = self.cipher.encrypt(json_value.encode())
            
        except Exception as e:
            raise CacheEncryptionError(f"Failed to encrypt value: {e}")
        
        # Store in database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT OR REPLACE INTO cache 
                (key, encrypted_value, created_at, expires_at, hits, last_accessed)
                VALUES (?, ?, ?, ?, 0, ?)
            """, (key, encrypted, now, expires, now))
            
            conn.commit()
            success = True
            
        except Exception as e:
            conn.rollback()
            raise CacheCorruptedError(str(self.db_path))
            
        finally:
            conn.close()
        
        return success
    
    def get(self, key: str) -> Optional[Any]:
        """
        Retrieve and decrypt cached value.
        
        Args:
            key: Cache key
            
        Returns:
            Cached value or None if not found/expired
            
        Example:
            >>> cache = CacheManager()
            >>> result = cache.get("whois:example.com")
            >>> if result:
            >>>     print(result['registrar'])
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT encrypted_value, expires_at, hits 
            FROM cache 
            WHERE key = ?
        """, (key,))
        
        result = cursor.fetchone()
        
        if not result:
            conn.close()
            return None
        
        encrypted_value, expires_at, hits = result
        now = int(time.time())
        
        # Check expiration
        if now > expires_at:
            # Expired - delete and return None
            cursor.execute("DELETE FROM cache WHERE key = ?", (key,))
            conn.commit()
            conn.close()
            return None
        
        # Update hit counter and last accessed
        cursor.execute("""
            UPDATE cache 
            SET hits = ?, last_accessed = ? 
            WHERE key = ?
        """, (hits + 1, now, key))
        
        conn.commit()
        conn.close()
        
        # Decrypt
        try:
            decrypted = self.cipher.decrypt(encrypted_value)
            return json.loads(decrypted.decode())
        except Exception as e:
            raise CacheEncryptionError(f"Failed to decrypt value: {e}")
    
    def delete(self, key: str) -> bool:
        """
        Delete cached entry.
        
        Args:
            key: Cache key
            
        Returns:
            True if deleted, False if not found
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("DELETE FROM cache WHERE key = ?", (key,))
        deleted = cursor.rowcount > 0
        
        conn.commit()
        conn.close()
        
        return deleted
    
    def exists(self, key: str) -> bool:
        """
        Check if key exists and is not expired.
        
        Args:
            key: Cache key
            
        Returns:
            True if exists and valid
        """
        now = int(time.time())
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT expires_at 
            FROM cache 
            WHERE key = ? AND expires_at > ?
        """, (key, now))
        
        result = cursor.fetchone()
        conn.close()
        
        return result is not None
    
    def cleanup_expired(self) -> int:
        """
        Remove all expired entries.
        
        Returns:
            Number of entries deleted
        """
        now = int(time.time())
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("DELETE FROM cache WHERE expires_at < ?", (now,))
        deleted = cursor.rowcount
        
        conn.commit()
        conn.close()
        
        return deleted
    
    def clear_all(self) -> int:
        """
        Clear entire cache (use with caution).
        
        Returns:
            Number of entries deleted
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("DELETE FROM cache")
        deleted = cursor.rowcount
        
        conn.commit()
        conn.close()
        
        return deleted
    
    def get_stats(self) -> Dict:
        """
        Get cache statistics.
        
        Returns:
            Dictionary with stats (total_entries, expired_entries, size, etc.)
        """
        now = int(time.time())
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Total entries
        cursor.execute("SELECT COUNT(*) FROM cache")
        total = cursor.fetchone()[0]
        
        # Valid (non-expired) entries
        cursor.execute("SELECT COUNT(*) FROM cache WHERE expires_at > ?", (now,))
        valid = cursor.fetchone()[0]
        
        # Expired entries
        expired = total - valid
        
        # Total hits
        cursor.execute("SELECT SUM(hits) FROM cache")
        hits_result = cursor.fetchone()[0]
        total_hits = hits_result if hits_result else 0
        
        # Most accessed key
        cursor.execute("""
            SELECT key, hits 
            FROM cache 
            WHERE expires_at > ?
            ORDER BY hits DESC 
            LIMIT 1
        """, (now,))
        most_accessed = cursor.fetchone()
        
        # Database size
        cursor.execute("SELECT page_count * page_size as size FROM pragma_page_count(), pragma_page_size()")
        db_size = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            "total_entries": total,
            "valid_entries": valid,
            "expired_entries": expired,
            "total_hits": total_hits,
            "most_accessed_key": most_accessed[0] if most_accessed else None,
            "most_accessed_hits": most_accessed[1] if most_accessed else 0,
            "database_size_bytes": db_size,
            "database_path": str(self.db_path)
        }
    
    def display_stats(self):
        """Display cache statistics in terminal"""
        stats = self.get_stats()
        
        print_info("Cache Statistics:")
        print(f"  Total Entries:   {stats['total_entries']}")
        print(f"  Valid Entries:   {stats['valid_entries']}")
        print(f"  Expired Entries: {stats['expired_entries']}")
        print(f"  Total Hits:      {stats['total_hits']}")
        
        if stats['most_accessed_key']:
            print(f"  Most Accessed:   {stats['most_accessed_key']} ({stats['most_accessed_hits']} hits)")
        
        # Format database size
        size_mb = stats['database_size_bytes'] / (1024 * 1024)
        print(f"  Database Size:   {size_mb:.2f} MB")
        print(f"  Database Path:   {stats['database_path']}")
        
        if stats['expired_entries'] > 0:
            print_warning(f"  ⚠ {stats['expired_entries']} expired entries can be cleaned up")
    
    def list_keys(self, prefix: Optional[str] = None, limit: int = 10) -> list:
        """
        List cache keys (optionally filtered by prefix).
        
        Args:
            prefix: Key prefix filter (e.g., "whois:")
            limit: Maximum number of keys to return
            
        Returns:
            List of cache keys
        """
        now = int(time.time())
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if prefix:
            cursor.execute("""
                SELECT key, created_at, expires_at, hits 
                FROM cache 
                WHERE key LIKE ? AND expires_at > ?
                ORDER BY created_at DESC
                LIMIT ?
            """, (f"{prefix}%", now, limit))
        else:
            cursor.execute("""
                SELECT key, created_at, expires_at, hits 
                FROM cache 
                WHERE expires_at > ?
                ORDER BY created_at DESC
                LIMIT ?
            """, (now, limit))
        
        results = cursor.fetchall()
        conn.close()
        
        return results


# ============================================================================
# CLI INTERFACE
# ============================================================================

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="ATS-Toolkit Cache Manager")
    parser.add_argument("--stats", action="store_true",
                       help="Show cache statistics")
    parser.add_argument("--cleanup", action="store_true",
                       help="Cleanup expired entries")
    parser.add_argument("--clear", action="store_true",
                       help="Clear entire cache (WARNING)")
    parser.add_argument("--list", metavar="PREFIX",
                       help="List cache keys (optionally with prefix)")
    parser.add_argument("--get", metavar="KEY",
                       help="Get cached value")
    parser.add_argument("--delete", metavar="KEY",
                       help="Delete cached entry")
    
    args = parser.parse_args()
    
    cache = CacheManager()
    
    if args.stats:
        cache.display_stats()
        
    elif args.cleanup:
        deleted = cache.cleanup_expired()
        print_success(f"✓ Cleaned up {deleted} expired entries")
        
    elif args.clear:
        response = input("⚠ WARNING: This will delete ALL cached data. Continue? (yes/no): ")
        if response.lower() == 'yes':
            deleted = cache.clear_all()
            print_success(f"✓ Cleared {deleted} cache entries")
        else:
            print_info("Operation cancelled")
            
    elif args.list is not None:
        prefix = args.list if args.list else None
        keys = cache.list_keys(prefix=prefix, limit=20)
        
        if not keys:
            print_info("No cache entries found")
        else:
            print_info(f"Cache keys{' (prefix: ' + prefix + ')' if prefix else ''}:")
            for key, created, expires, hits in keys:
                from datetime import datetime
                created_dt = datetime.fromtimestamp(created).strftime("%Y-%m-%d %H:%M")
                print(f"  {key}")
                print(f"    Created: {created_dt} | Hits: {hits}")
                
    elif args.get:
        value = cache.get(args.get)
        if value:
            print_success(f"✓ Cached value for '{args.get}':")
            print(json.dumps(value, indent=2))
        else:
            print_warning(f"No cached value found for '{args.get}'")
            
    elif args.delete:
        if cache.delete(args.delete):
            print_success(f"✓ Deleted cache entry '{args.delete}'")
        else:
            print_warning(f"Cache entry '{args.delete}' not found")
            
    else:
        # Default: show stats
        cache.display_stats()
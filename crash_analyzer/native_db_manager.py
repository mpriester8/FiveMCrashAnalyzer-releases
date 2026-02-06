"""
FiveM Native Database Manager

Downloads and manages GTA V/FiveM native function hash databases.
Provides automatic fetching of comprehensive native mappings for crash analysis.
"""

import json
import sys
from pathlib import Path
from typing import Dict, Optional
import traceback

try:
    import requests
except ImportError:
    requests = None


class NativeDBManager:
    """Manages downloading and caching of FiveM native databases."""
    
    # Primary sources for native databases (ordered by preference)
    SOURCES = {
        "alloc8or": {
            "url": "https://raw.githubusercontent.com/alloc8or/gta5-nativedb-data/master/natives.json",
            "name": "alloc8or GTA5 NativeDB (6,673 natives)",
            "format": "namespace -> hash -> entry",
        },
        "fivem_community": {
            "url": "https://raw.githubusercontent.com/MrTigerST/fivem-natives-list/main/all_natives.json",
            "name": "FiveM Community Natives",
            "format": "hash -> entry",
        },
    }
    
    # Fallback hardcoded natives (for offline use)
    FALLBACK_NATIVES = {
        "0x2b9d4f50": "CREATE_VEHICLE",
        "0x3c3dfc19": "SET_ENTITY_COORDS",
        "0x4746fc30": "GET_ENTITY_COORDS",
        "0x70a9e6e4": "DELETE_ENTITY",
        "0x75aaacf2": "IS_ENTITY_DEAD",
        "0x0b74e1e7": "GET_ENTITY_TYPE",
        "0xa96c87a9": "SET_ENTITY_VELOCITY",
        "0x206d948f": "GET_ENTITY_VELOCITY",
        "0x61e1e1f0": "IS_ENTITY_IN_WATER",
        "0xbfd8b56c": "GET_ENTITY_MODEL",
        "0xc4b3a50c083da006": "CLEAR_PED_TASKS",
        "0x83a169eaddaa49ba": "REQUEST_ANIM_DICT",
    }
    
    def __init__(self, cache_dir: Optional[str] = None):
        """
        Initialize native database manager.
        
        Args:
            cache_dir: Directory to cache downloaded databases. Defaults to temp_output/.
        """
        if cache_dir:
            self.cache_dir = Path(cache_dir)
        else:
            # Use temp_output directory relative to crash_analyzer package
            self.cache_dir = Path(__file__).parent.parent / "temp_output"
        
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cached_db: Optional[Dict[str, str]] = None
    
    def get_cache_path(self, source_name: str) -> Path:
        """Get cache file path for a given source."""
        safe_name = source_name.replace("/", "_").replace(":", "")
        return self.cache_dir / f"fivem_natives_{safe_name}.json"
    
    def download_and_parse(self, source_name: str = "alloc8or", verbose: bool = True) -> Optional[Dict[str, str]]:
        """
        Download and parse native database from a source.
        
        Args:
            source_name: Key from SOURCES dict
            verbose: Print status messages
            
        Returns:
            Dict mapping hash -> name, or None if failed
        """
        if source_name not in self.SOURCES:
            if verbose:
                print(f"[-] Unknown source: {source_name}")
            return None
        
        source = self.SOURCES[source_name]
        url = source["url"]
        cache_path = self.get_cache_path(source_name)
        
        if verbose:
            print(f"[*] Fetching native database from {source['name']}...")
            print(f"    URL: {url}")
        
        # Try to fetch if requests available
        if requests:
            try:
                resp = requests.get(url, timeout=30, headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                })
                resp.raise_for_status()
                
                if verbose:
                    print(f"[+] Downloaded {len(resp.content) / 1024 / 1024:.2f} MB")
                
                # Parse JSON
                raw_data = resp.json()
                native_dict = self._parse_native_data(raw_data, source_name)
                
                if native_dict:
                    # Cache it
                    with open(cache_path, 'w') as f:
                        json.dump(native_dict, f, indent=2)
                    
                    if verbose:
                        print(f"[+] Parsed {len(native_dict)} native mappings")
                        print(f"[+] Cached to: {cache_path}")
                    
                    self.cached_db = native_dict
                    return native_dict
                else:
                    if verbose:
                        print(f"[-] Failed to parse native data")
                    return None
                    
            except Exception as e:
                if verbose:
                    print(f"[-] Download failed: {type(e).__name__}: {e}")
                return None
        else:
            if verbose:
                print(f"[-] requests library not available for downloading")
            return None
    
    def _parse_native_data(self, raw_data: dict, source_name: str) -> Optional[Dict[str, str]]:
        """
        Parse raw native database into hash -> name format.
        
        Args:
            raw_data: Raw JSON data from source
            source_name: Source identifier for format detection
            
        Returns:
            Dict mapping hash (lowercase) -> function name
        """
        natives = {}
        
        if source_name == "alloc8or":
            # Format: namespace -> 64bit_hash -> {name, jhash, params, ...}
            for namespace, ns_data in raw_data.items():
                if isinstance(ns_data, dict):
                    for hash_64bit, entry_data in ns_data.items():
                        if isinstance(entry_data, dict):
                            name = entry_data.get("name", "")
                            if name and hash_64bit.startswith("0x"):
                                natives[hash_64bit.lower()] = name
                                
                                # Also add 32-bit variant
                                jhash = entry_data.get("jhash", "").lower()
                                if jhash and jhash.startswith("0x"):
                                    natives[jhash] = name
        
        elif source_name == "fivem_community":
            # Different format - check structure
            if isinstance(raw_data, list):
                # Array format
                for entry in raw_data:
                    if isinstance(entry, dict):
                        hash_val = entry.get("hash", entry.get("jhash", "")).lower()
                        name = entry.get("name", "")
                        if hash_val.startswith("0x") and name:
                            natives[hash_val] = name
            elif isinstance(raw_data, dict):
                # Direct hash -> name
                for hash_val, name in raw_data.items():
                    if hash_val.startswith("0x"):
                        natives[hash_val.lower()] = name
        
        return natives if natives else None
    
    def load_or_fetch(self, source_name: str = "alloc8or", verbose: bool = True) -> Dict[str, str]:
        """
        Load cached database or fetch from source.
        
        Args:
            source_name: Which source to use
            verbose: Print status messages
            
        Returns:
            Dict mapping hash -> name. Falls back to hardcoded natives if needed.
        """
        # Return cached if available
        if self.cached_db:
            return self.cached_db
        
        # Try to load from cache
        cache_path = self.get_cache_path(source_name)
        if cache_path.exists():
            if verbose:
                print(f"[*] Loading cached native database from: {cache_path}")
            
            try:
                with open(cache_path) as f:
                    self.cached_db = json.load(f)
                
                if verbose:
                    print(f"[+] Loaded {len(self.cached_db)} cached native mappings")
                
                return self.cached_db
            except Exception as e:
                if verbose:
                    print(f"[-] Failed to load cache: {e}")
        
        # Try to fetch from source
        native_dict = self.download_and_parse(source_name, verbose=verbose)
        if native_dict:
            self.cached_db = native_dict
            return native_dict
        
        # Fallback to hardcoded
        if verbose:
            print(f"[*] Falling back to {len(self.FALLBACK_NATIVES)} hardcoded native mappings")
        
        return self.FALLBACK_NATIVES
    
    def get_sources_info(self) -> str:
        """Get readable info about available sources."""
        lines = ["Available native database sources:\n"]
        for key, source in self.SOURCES.items():
            lines.append(f"  {key:20} - {source['name']}")
        return "\n".join(lines)


def fetch_and_cache_comprehensive_natives(verbose: bool = True) -> Dict[str, str]:
    """
    Convenience function to fetch and cache the comprehensive native database.
    
    Args:
        verbose: Print status messages
        
    Returns:
        Dict of native mappings (hash -> name)
    """
    manager = NativeDBManager()
    return manager.load_or_fetch(source_name="alloc8or", verbose=verbose)


if __name__ == "__main__":
    # CLI for testing/updating
    manager = NativeDBManager()
    
    if len(sys.argv) > 1 and sys.argv[1] == "fetch":
        print("=" * 70)
        print("FiveM Native Database Fetcher")
        print("=" * 70)
        
        source = sys.argv[2] if len(sys.argv) > 2 else "alloc8or"
        
        print(f"\nFetching from: {source}")
        print(manager.get_sources_info())
        print()
        
        natives = manager.load_or_fetch(source_name=source, verbose=True)
        print(f"\nFinal result: {len(natives)} native mappings available")
        
    else:
        print("Usage: python -m crash_analyzer.native_db_manager fetch [source]")
        print("\n" + manager.get_sources_info())

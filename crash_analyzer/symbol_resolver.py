"""Symbol Resolution Module for FiveM Crash Analyzer.

This module handles automatic PDB symbol downloading from FiveM's symbol server
and Microsoft's public symbol server, with symbol resolution for crash analysis.
"""
from __future__ import annotations

import os
import re
import struct
import tempfile
import hashlib
import shutil
import threading
import time
import uuid
import sys
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple, Callable
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# Optional dependencies
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    requests = None
    HAS_REQUESTS = False


def safe_print(msg: str):
    """Print message safely, handling unicode encoding issues on Windows."""
    try:
        print(msg)
    except UnicodeEncodeError:
        # Fallback: try with errors='replace'
        print(msg.encode(sys.stdout.encoding or 'utf-8', errors='replace').decode(sys.stdout.encoding or 'utf-8', errors='replace'))


@dataclass
class SymbolInfo:
    """Information about a resolved symbol."""
    module_name: str
    function_name: str
    offset: int  # Offset from function start
    source_file: Optional[str] = None
    line_number: Optional[int] = None
    rva: int = 0  # Relative Virtual Address within module


@dataclass
class ModuleSymbolInfo:
    """Symbol information for a loaded module."""
    name: str
    base_address: int
    size: int
    pdb_name: str = ""
    pdb_guid: str = ""
    pdb_age: int = 0
    pdb_path: Optional[str] = None  # Local path to downloaded PDB
    symbols_loaded: bool = False
    # Symbol table: RVA -> (function_name, function_size)
    symbols: Dict[int, Tuple[str, int]] = field(default_factory=dict)
    # Public symbols from PDB
    publics: Dict[int, str] = field(default_factory=dict)


@dataclass
class LastMemoryOperation:
    """Details about the last memory operation before crash."""
    operation_type: str  # "read", "write", "execute", "unknown"
    target_address: int  # The address being accessed
    instruction_address: int  # The instruction that caused the crash

    # Resolved symbol info for the faulting instruction
    faulting_function: Optional[str] = None
    faulting_module: Optional[str] = None
    function_offset: int = 0

    # What the operation was trying to do
    description: str = ""

    # Additional context
    is_null_pointer: bool = False
    is_stack_address: bool = False
    is_heap_address: bool = False
    is_code_address: bool = False

    # Register values at crash time (for context)
    registers: Dict[str, int] = field(default_factory=dict)

    # Nearby memory content if available
    nearby_memory: Optional[bytes] = None

    # Potential cause analysis
    likely_cause: str = ""
    recommendations: List[str] = field(default_factory=list)


class SymbolResolver:
    """
    Automatic symbol resolver for FiveM crash dumps.

    Downloads PDB symbols from multiple symbol servers and resolves
    addresses to function names for better crash analysis.
    """

    # FiveM symbol server (primary)
    FIVEM_SYMBOL_SERVER = "https://runtime.fivem.net/client/symbols/"
    
    # GitHub PDB repository (X3P0/fivem-pdbs) - community-maintained collection
    # These are static PDB files from December 2021, useful for older builds
    GITHUB_PDB_REPO = "https://raw.githubusercontent.com/X3P0/fivem-pdbs/main/"

    # Microsoft public symbol server (fallback)
    MICROSOFT_SYMBOL_SERVER = "https://msdl.microsoft.com/download/symbols/"

    # Alternative symbol servers
    ALT_SYMBOL_SERVERS = [
        "https://symbols.nuget.org/download/symbols/",
        "https://chromium-browser-symsrv.commondatastorage.googleapis.com/",
    ]

    # Enable verbose logging for debugging symbol downloads
    VERBOSE = True

    # Common FiveM modules that have symbols
    FIVEM_MODULES = {
        'fivem.exe', 'fivem_b2802_gtalauncher.exe', 'fivem_b2699_gtalauncher.exe',
        'citizengame.dll', 'citizen-resources-core.dll', 'citizen-scripting-core.dll',
        'citizen-scripting-lua.dll', 'citizen-scripting-v8.dll', 'citizen-scripting-mono.dll',
        'gta-core-five.dll', 'gta-game-five.dll', 'gta-net-five.dll',
        'gta5.exe', 'gta5_b2802.exe', 'gta5_b2699.exe',
        'rage-allocator-five.dll', 'rage-device-five.dll', 'rage-graphics-five.dll',
        'rage-input-five.dll', 'rage-nutsnbolts-five.dll', 'gta-streaming-five.dll',
    }

    def __init__(self, cache_dir: Optional[str] = None,
                 progress_callback: Optional[Callable[[str, int, int], None]] = None):
        """
        Initialize the symbol resolver.

        Args:
            cache_dir: Directory to cache downloaded symbols. Defaults to temp directory.
            progress_callback: Callback for progress updates (message, current, total)
        """
        if cache_dir:
            self.cache_dir = Path(cache_dir)
        else:
            self.cache_dir = Path(tempfile.gettempdir()) / "fivem_symbols"

        self.cache_dir.mkdir(parents=True, exist_ok=True)

        self.progress_callback = progress_callback
        self._modules: Dict[int, ModuleSymbolInfo] = {}  # base_address -> ModuleSymbolInfo
        self._download_lock = threading.Lock()
        self._session: Optional[requests.Session] = None

        # Statistics
        self.stats = {
            'symbols_downloaded': 0,
            'symbols_cached': 0,
            'symbols_failed': 0,
            'addresses_resolved': 0,
        }

    def _get_session(self) -> 'requests.Session':
        """Get or create HTTP session with retry configuration."""
        if self._session is None and HAS_REQUESTS:
            self._session = requests.Session()
            # Configure retries
            from requests.adapters import HTTPAdapter
            from urllib3.util.retry import Retry

            retry_strategy = Retry(
                total=3,
                backoff_factor=0.5,
                status_forcelist=[429, 500, 502, 503, 504],
            )
            adapter = HTTPAdapter(max_retries=retry_strategy)
            self._session.mount("http://", adapter)
            self._session.mount("https://", adapter)
            self._session.headers.update({
                'User-Agent': 'FiveMCrashAnalyzer/1.0 (Symbol Download)'
            })
        return self._session

    def _report_progress(self, message: str, current: int = 0, total: int = 0):
        """Report progress to callback if available."""
        if self.progress_callback:
            try:
                self.progress_callback(message, current, total)
            except Exception:
                pass

    def register_module(self, name: str, base_address: int, size: int,
                       pdb_name: str = "", pdb_guid: str = "", pdb_age: int = 0) -> ModuleSymbolInfo:
        """
        Register a module for symbol resolution.

        Args:
            name: Module name (e.g., "citizen-scripting-lua.dll")
            base_address: Base address where module is loaded
            size: Size of the module in memory
            pdb_name: PDB file name
            pdb_guid: PDB GUID for symbol server lookup
            pdb_age: PDB age for symbol server lookup

        Returns:
            ModuleSymbolInfo object for the registered module
        """
        mod_info = ModuleSymbolInfo(
            name=name,
            base_address=base_address,
            size=size,
            pdb_name=pdb_name or os.path.splitext(os.path.basename(name))[0] + ".pdb",
            pdb_guid=pdb_guid,
            pdb_age=pdb_age,
        )
        self._modules[base_address] = mod_info
        return mod_info

    def _extract_pdb_info_from_pe(self, pe_path: str) -> Optional[Tuple[str, str, int]]:
        """Extract PDB info (name, GUID, age) from a PE file's CodeView (RSDS) debug record."""
        if not pe_path or not os.path.exists(pe_path):
            return None

        try:
            with open(pe_path, "rb") as f:
                data = f.read()

            if len(data) < 0x100:
                return None

            # DOS header e_lfanew
            e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
            if e_lfanew <= 0 or e_lfanew + 4 > len(data):
                return None

            # PE signature
            if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
                return None

            # File header
            file_header_off = e_lfanew + 4
            machine, num_sections, _, _, _, size_opt_header, _ = struct.unpack_from("<HHIIIHH", data, file_header_off)

            # Optional header
            opt_off = file_header_off + 20
            if opt_off + size_opt_header > len(data):
                return None

            magic = struct.unpack_from("<H", data, opt_off)[0]
            is_pe64 = magic == 0x20B

            # Data directory offset
            if is_pe64:
                data_dir_off = opt_off + 112
            else:
                data_dir_off = opt_off + 96

            if data_dir_off + 8 * 7 > len(data):
                return None

            # IMAGE_DIRECTORY_ENTRY_DEBUG = index 6
            debug_rva, debug_size = struct.unpack_from("<II", data, data_dir_off + 8 * 6)
            if debug_rva == 0 or debug_size == 0:
                return None

            # Section table
            sections_off = opt_off + size_opt_header
            sections = []
            for i in range(num_sections):
                sec_off = sections_off + i * 40
                if sec_off + 40 > len(data):
                    break
                name = data[sec_off:sec_off + 8].rstrip(b"\x00").decode("ascii", errors="ignore")
                virtual_size, virtual_address, size_raw, ptr_raw = struct.unpack_from("<IIII", data, sec_off + 8)
                sections.append((virtual_address, max(virtual_size, size_raw), ptr_raw, size_raw, name))

            def rva_to_file_offset(rva: int) -> Optional[int]:
                for va, vsz, ptr, rawsz, _ in sections:
                    if va <= rva < va + vsz:
                        delta = rva - va
                        if delta < rawsz:
                            return ptr + delta
                return None

            debug_off = rva_to_file_offset(debug_rva)
            if debug_off is None:
                return None

            # Parse IMAGE_DEBUG_DIRECTORY entries (28 bytes each)
            entry_size = 28
            count = debug_size // entry_size
            for i in range(count):
                off = debug_off + i * entry_size
                if off + entry_size > len(data):
                    break
                _, _, _, _, debug_type, size_of_data, addr_raw, ptr_raw = struct.unpack_from("<IIHHIIII", data, off)

                # CodeView debug info = 2
                if debug_type != 2:
                    continue

                # Prefer pointer to raw data if available
                cv_off = ptr_raw if ptr_raw != 0 else rva_to_file_offset(addr_raw)
                if cv_off is None or cv_off + 24 > len(data):
                    continue

                sig = data[cv_off:cv_off + 4]
                if sig != b"RSDS":
                    continue

                guid_bytes = data[cv_off + 4:cv_off + 20]
                age = struct.unpack_from("<I", data, cv_off + 20)[0]

                # PDB path is null-terminated string
                pdb_path_bytes = data[cv_off + 24:cv_off + 24 + 260]
                pdb_path = pdb_path_bytes.split(b"\x00", 1)[0].decode("utf-8", errors="ignore")
                pdb_name = os.path.basename(pdb_path) if pdb_path else ""

                guid = str(uuid.UUID(bytes_le=guid_bytes)).upper()
                if pdb_name and guid:
                    return (pdb_name, guid, age)

            return None
        except Exception:
            return None

    def ensure_pdb_info(self, mod: ModuleSymbolInfo) -> bool:
        """Ensure a module has PDB name/GUID/age by reading its PE file if needed."""
        if mod.pdb_name and mod.pdb_guid:
            return True

        # Check if module name is actually a valid file path
        if not mod.name or not os.path.exists(mod.name):
            resolved = self._resolve_module_path(mod.name or "")
            if resolved and os.path.exists(resolved):
                mod.name = resolved
            else:
                print(f"[SYMBOL] Cannot extract PDB info: file not found at {mod.name}")
                return False

        print(f"[SYMBOL] Extracting PDB info from PE file: {mod.name}")
        info = self._extract_pdb_info_from_pe(mod.name)
        if not info:
            print(f"[SYMBOL] - Could not extract RSDS data from {mod.name}")
            return False

        pdb_name, pdb_guid, pdb_age = info
        print(f"[SYMBOL] + Found: {pdb_name} (GUID={pdb_guid}, age={pdb_age})")
        if pdb_name:
            mod.pdb_name = pdb_name
        if pdb_guid:
            mod.pdb_guid = pdb_guid
        if pdb_age:
            mod.pdb_age = pdb_age
        return bool(mod.pdb_name and mod.pdb_guid)

    def _build_symbol_path(self, pdb_name: str, guid: str, age: int) -> str:
        """
        Build the symbol server path for a PDB file.

        Microsoft symbol server format: {pdb_name}/{GUID}{age}/{pdb_name}
        Example: ntdll.pdb/1234567890ABCDEF1234567890ABCDEF1/ntdll.pdb
        
        CRITICAL FIX: Age format must be DECIMAL, not hex
        """
        # Clean up GUID - remove dashes and ensure uppercase
        guid_clean = guid.replace('-', '').upper()

        # Combine GUID and age as DECIMAL (critical fix)
        age_value = int(age) if age else 0
        signature = f"{guid_clean}{age_value:d}"

        return f"{pdb_name}/{signature}/{pdb_name}"

    def _get_cached_path(self, pdb_name: str, guid: str, age: int) -> Path:
        """Get the local cache path for a symbol file."""
        guid_clean = guid.replace('-', '').upper()
        age_value = int(age) if age else 0
        signature = f"{guid_clean}{age_value:d}"
        return self.cache_dir / pdb_name / signature / pdb_name

    def _log(self, message: str):
        """Log a message if verbose mode is enabled."""
        if self.VERBOSE:
            print(f"[SYMBOL] {message}")

    def _resolve_module_path(self, module_path: str) -> Optional[str]:
        """Try to resolve a module path from a dump to a local file on disk."""
        if not module_path:
            return None
        if os.path.exists(module_path):
            return module_path

        # Replace user profile (e.g., C:\Users\Other\...) with current user home
        try:
            m = re.match(r"^[A-Za-z]:\\Users\\[^\\]+\\(.+)$", module_path)
            if m:
                candidate = os.path.join(str(Path.home()), m.group(1))
                if os.path.exists(candidate):
                    return candidate
        except Exception:
            pass

        # Resolve within local FiveM.app folder
        try:
            home = Path.home()
            default_fivem = home / "AppData" / "Local" / "FiveM" / "FiveM.app"
            fivem_root = Path(os.environ.get("FIVEM_APP_PATH", "")) if os.environ.get("FIVEM_APP_PATH") else default_fivem
            if fivem_root and fivem_root.exists():
                marker = "\\FiveM.app\\"
                if marker in module_path:
                    sub = module_path.split(marker, 1)[1]
                    candidate = fivem_root / sub
                    if candidate.exists():
                        return str(candidate)
        except Exception:
            pass

        return None

    def download_symbol(self, pdb_name: str, guid: str, age: int,
                       is_fivem_module: bool = False) -> Optional[str]:
        """
        Download a PDB symbol file from symbol servers.

        Tries FiveM symbol server first for FiveM modules, then falls back
        to Microsoft's public symbol server.

        Args:
            pdb_name: Name of the PDB file
            guid: PDB GUID
            age: PDB age
            is_fivem_module: Whether this is a known FiveM module

        Returns:
            Local path to downloaded PDB file, or None if download failed
        """
        if not HAS_REQUESTS:
            return None

        if not pdb_name or not guid:
            safe_print(f"[SYMBOL] - Cannot download {pdb_name}: missing pdb_name or guid")
            return None

        # CRITICAL: Skip Chrome/Chromium/Blink PDBs entirely - they're massive and cause hangs
        pdb_name_lower = pdb_name.lower()
        if any(skip in pdb_name_lower for skip in ['chrome', 'chromium', 'blink', 'cef', 'libcef', 'fivemchrome']):
            safe_print(f"[SYMBOL] - Skipping {pdb_name} (Chrome-based module - known to hang)")
            return None

        # Check cache first
        cached_path = self._get_cached_path(pdb_name, guid, age)
        if cached_path.exists():
            safe_print(f"[SYMBOL] + {pdb_name} (cached)")
            self.stats['symbols_cached'] += 1
            self._log(f"Cache hit: {pdb_name}")
            return str(cached_path)

        # Build symbol paths (decimal age is preferred, but try fallbacks)
        symbol_path = self._build_symbol_path(pdb_name, guid, age)
        guid_clean = guid.replace('-', '').upper() if guid else ''
        age_int = int(age) if age else 0
        diagnostic_sig = f"{guid_clean}{age_int:d}"
        hex_sig = f"{guid_clean}{age_int:X}"
        symbol_path_hex = f"{pdb_name}/{hex_sig}/{pdb_name}"
        symbol_path_guid_only = f"{pdb_name}/{guid_clean}/{pdb_name}"
        path_variants = [symbol_path]
        if symbol_path_hex not in path_variants:
            path_variants.append(symbol_path_hex)
        if guid_clean and symbol_path_guid_only not in path_variants:
            path_variants.append(symbol_path_guid_only)
        
        print(f"[SYMBOL] Attempting download: {pdb_name}")
        print(f"[SYMBOL]   GUID: {guid_clean}")
        print(f"[SYMBOL]   Age (decimal): {age_int}")
        print(f"[SYMBOL]   Signature: {diagnostic_sig}")
        print(f"[SYMBOL]   Symbol path: {symbol_path}")

        # Determine server order based on module type
        servers = []
        if is_fivem_module or self._is_fivem_module(pdb_name):
            # For FiveM modules, try in this order:
            # 1. Official FiveM symbol server (latest builds)
            servers.append(self.FIVEM_SYMBOL_SERVER)
            # 2. GitHub community repo (older builds, direct file access)
            servers.append(self.GITHUB_PDB_REPO)
        # 3. Microsoft symbol server (system DLLs)
        servers.append(self.MICROSOFT_SYMBOL_SERVER)
        servers.extend(self.ALT_SYMBOL_SERVERS)

        session = self._get_session()
        if not session:
            print(f"[SYMBOL] ✗ No HTTP session available")
            return None

        # Try each server
        download_attempts = []
        for server_idx, server in enumerate(servers, 1):
            # GitHub repo uses direct file access, not symbol server protocol
            if server == self.GITHUB_PDB_REPO:
                url = f"{server.rstrip('/')}/{pdb_name}"
                try:
                    self._report_progress(f"Trying {server.split('/')[2]}...", 0, 1)
                    print(f"[SYMBOL]   Try {server_idx}/{len(servers)}: {url[:100]}...")

                    response = session.get(url, stream=True, timeout=30)
                    download_attempts.append((url[:100], response.status_code))
                    
                    print(f"[SYMBOL]     → HTTP {response.status_code}")
                    self._log(f"    → HTTP {response.status_code}")

                    if response.status_code == 200:
                        # Download to cache
                        cached_path.parent.mkdir(parents=True, exist_ok=True)
                        with open(cached_path, 'wb') as f:
                            for chunk in response.iter_content(chunk_size=8192):
                                if chunk:
                                    f.write(chunk)

                        self.stats['symbols_downloaded'] += 1
                        print(f"[SYMBOL] + Downloaded {pdb_name} ({cached_path.stat().st_size} bytes)")
                        self._report_progress(f"Downloaded {pdb_name}", 1, 1)
                        return str(cached_path)

                except Exception as e:
                    error_msg = str(e)[:60]
                    download_attempts.append((url[:100], f"Exception: {error_msg}"))
                    print(f"[SYMBOL]     -> Exception: {error_msg}")
                    continue
            else:
                for variant_idx, variant in enumerate(path_variants, 1):
                    # Standard symbol server protocol: {pdb}/{GUID+age}/{pdb}
                    url = f"{server.rstrip('/')}/{variant}"

                    try:
                        self._report_progress(f"Trying {server.split('/')[2]} ({variant_idx}/{len(path_variants)})...", 0, 1)
                        print(f"[SYMBOL]   Try {server_idx}/{len(servers)} ({variant_idx}/{len(path_variants)}): {url[:100]}...")

                        response = session.get(url, stream=True, timeout=30)
                        download_attempts.append((url[:100], response.status_code))
                        
                        print(f"[SYMBOL]     -> HTTP {response.status_code}")
                        self._log(f"    -> HTTP {response.status_code}")

                        if response.status_code == 200:
                            # Download to cache
                            cached_path.parent.mkdir(parents=True, exist_ok=True)
                            with open(cached_path, 'wb') as f:
                                for chunk in response.iter_content(chunk_size=8192):
                                    if chunk:
                                        f.write(chunk)

                            self.stats['symbols_downloaded'] += 1
                            print(f"[SYMBOL] + Downloaded {pdb_name} ({cached_path.stat().st_size} bytes)")
                            self._report_progress(f"Downloaded {pdb_name}", 1, 1)
                            return str(cached_path)

                    except Exception as e:
                        error_msg = str(e)[:60]
                        download_attempts.append((url[:100], f"Exception: {error_msg}"))
                        print(f"[SYMBOL]     -> Exception: {error_msg}")
                        continue

        # Try compressed variants (.pd_ which uncompresses to .pdb)
        compressed_name = pdb_name[:-1] + '_'  # e.g., ntdll.pd_
        self._log(f"  Trying compressed variant: {compressed_name}")

        for server in servers:
            for symbol_path in path_variants:
                # Replace .pdb with .pd_ in the path
                compressed_path = symbol_path.replace(pdb_name, compressed_name)
                url = f"{server.rstrip('/')}/{compressed_path}"

                try:
                    response = session.get(url, stream=True, timeout=30)

                    if response.status_code == 200:
                        # Download compressed file
                        temp_path = cached_path.parent / compressed_name
                        temp_path.parent.mkdir(parents=True, exist_ok=True)

                        with open(temp_path, 'wb') as f:
                            for chunk in response.iter_content(chunk_size=8192):
                                f.write(chunk)

                        # Try to decompress using expand.exe (Windows) or cabextract
                        if self._decompress_cab(str(temp_path), str(cached_path)):
                            temp_path.unlink()
                            self.stats['symbols_downloaded'] += 1
                            self._log(f"  ✓ Downloaded (compressed): {pdb_name}")
                            return str(cached_path)
                        else:
                            temp_path.unlink()

                except Exception:
                    continue

        self.stats['symbols_failed'] += 1
        print(f"[SYMBOL] - Failed to download {pdb_name}")
        print(f"[SYMBOL]   Attempts: {download_attempts}")
        print(f"[SYMBOL]   Statistics: {self.stats}")
        return None

    def _is_fivem_module(self, name: str) -> bool:
        """Check if a module is a known FiveM module."""
        name_lower = name.lower()
        for fivem_mod in self.FIVEM_MODULES:
            if fivem_mod.lower() in name_lower:
                return True
        # Also check for citizen- or gta- prefixes
        if any(name_lower.startswith(prefix) for prefix in ['citizen', 'gta-', 'rage-', 'fivem']):
            return True
        return False

    def _decompress_cab(self, cab_path: str, output_path: str) -> bool:
        """Decompress a CAB file (compressed PDB)."""
        import subprocess
        import platform

        try:
            if platform.system() == 'Windows':
                # Use expand.exe on Windows
                # CREATE_NO_WINDOW flag prevents console window from appearing
                result = subprocess.run(
                    ['expand', cab_path, output_path],
                    capture_output=True,
                    timeout=30,
                    creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                )
                return result.returncode == 0
            else:
                # Try cabextract on Linux/Mac
                result = subprocess.run(
                    ['cabextract', '-d', os.path.dirname(output_path), cab_path],
                    capture_output=True,
                    timeout=30
                )
                return result.returncode == 0
        except Exception:
            return False

    def download_all_symbols(self, max_workers: int = 4) -> Dict[str, bool]:
        """
        Download symbols for all registered modules in parallel.

        Args:
            max_workers: Maximum number of concurrent downloads

        Returns:
            Dictionary mapping module names to download success status
        """
        results = {}
        modules_to_download = []

        # First pass: ensure all modules have PDB info
        for base, mod_info in self._modules.items():
            if not mod_info.pdb_guid:
                # Try to extract PDB info from PE header
                if self.ensure_pdb_info(mod_info):
                    print(f"[SYMBOL] Extracted PDB info from {mod_info.name}: {mod_info.pdb_name}")
                else:
                    print(f"[SYMBOL] ✗ Cannot extract PDB info from {mod_info.name} (no PE file or path)")

        # Second pass: collect modules ready for download
        for base, mod_info in self._modules.items():
            if mod_info.pdb_guid and not mod_info.symbols_loaded:
                modules_to_download.append(mod_info)
                print(f"[SYMBOL] Will download: {mod_info.name}")

        if not modules_to_download:
            print(f"[SYMBOL] ✗ No modules ready for symbol download")
            return results

        total = len(modules_to_download)
        completed = 0

        print(f"[SYMBOL] ========================================")
        print(f"[SYMBOL] Starting download of {total} modules")
        print(f"[SYMBOL] ========================================")
        self._report_progress(f"Downloading symbols for {total} modules...", 0, total)

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_mod = {
                executor.submit(
                    self.download_symbol,
                    mod.pdb_name,
                    mod.pdb_guid,
                    mod.pdb_age,
                    self._is_fivem_module(mod.name)
                ): mod
                for mod in modules_to_download
            }

            for future in as_completed(future_to_mod):
                mod = future_to_mod[future]
                try:
                    pdb_path = future.result()
                    if pdb_path:
                        mod.pdb_path = pdb_path
                        results[mod.name] = True
                        
                        # Skip parsing symbols for problematic large modules
                        # Chrome/Chromium PDBs are massive (100k+ symbols) and enumeration hangs for 5-15 minutes
                        mod_name_lower = mod.name.lower()
                        skip_keywords = ['chrome', 'chromium', 'blink', 'cef', 'webkit', 'fivemchrome']
                        skip_symbol_parse = any(skip in mod_name_lower for skip in skip_keywords)
                        
                        # Additional size check - skip PDBs over 200MB regardless of name
                        if not skip_symbol_parse and pdb_path and os.path.exists(pdb_path):
                            pdb_size = os.path.getsize(pdb_path)
                            if pdb_size > 200 * 1024 * 1024:
                                skip_symbol_parse = True
                                print(f"[SYMBOL] - Skipping {mod.name} due to large PDB size ({pdb_size/(1024*1024):.1f}MB)")
                        
                        if skip_symbol_parse:
                            print(f"[SYMBOL] - Skipping symbol parsing for {mod.name} (known to cause hangs)")
                            mod.symbols_loaded = True  # Mark as loaded even though we skipped
                        else:
                            # Parse symbols from PDB using DbgHelp
                            parsed_ok = self._parse_pdb_symbols(mod)
                            if parsed_ok and len(mod.symbols) > 0:
                                print(f"[SYMBOL] + Parsed {len(mod.symbols)} symbols for {mod.name}")
                                mod.symbols_loaded = True
                            else:
                                # DbgHelp failed or returned 0 symbols - try string extraction fallback
                                if not parsed_ok:
                                    print(f"[SYMBOL] - DbgHelp failed for {mod.name}, trying string extraction fallback")
                                else:
                                    print(f"[SYMBOL] - PDB stripped for {mod.name}, trying string extraction fallback")
                                
                                # Attempt to extract symbols from raw PDB data
                                if pdb_path and os.path.exists(pdb_path):
                                    try:
                                        with open(pdb_path, 'rb') as pdb_file:
                                            pdb_data = pdb_file.read(min(50 * 1024 * 1024, os.path.getsize(pdb_path)))  # Read up to 50MB
                                        self._extract_symbol_strings(pdb_data, mod)
                                        if len(mod.publics) > 0:
                                            print(f"[SYMBOL] + Extracted {len(mod.publics)} symbol strings from {mod.name}")
                                            mod.symbols_loaded = True
                                        else:
                                            print(f"[SYMBOL] - No symbols found via string extraction for {mod.name}")
                                    except Exception as extract_err:
                                        print(f"[SYMBOL] - String extraction failed for {mod.name}: {str(extract_err)[:80]}")
                                else:
                                    print(f"[SYMBOL] - PDB file not accessible for string extraction")
                    else:
                        results[mod.name] = False
                except Exception as e:
                    print(f"[SYMBOL] - Exception downloading {mod.name}: {str(e)[:80]}")
                    results[mod.name] = False

                completed += 1
                self._report_progress(
                    f"Downloaded {completed}/{total}: {mod.name}",
                    completed, total
                )

        # Final statistics
        downloaded_count = sum(1 for success in results.values() if success)
        print(f"[SYMBOL] ========================================")
        print(f"[SYMBOL] Download complete: {downloaded_count}/{total} succeeded")
        # Suppress verbose stats, just show key info
        if self.stats['symbols_downloaded'] > 0 or self.stats['symbols_failed'] > 0:
            print(f"[SYMBOL] Statistics: downloaded={self.stats['symbols_downloaded']}, cached={self.stats['symbols_cached']}, failed={self.stats['symbols_failed']}")
        print(f"[SYMBOL] ========================================")

        return results

    def _parse_pdb_symbols(self, mod: ModuleSymbolInfo) -> bool:
        """Parse public symbols from a PDB file using dbghelp.dll (Windows only).
        
        This uses Windows' native symbol loading to extract RVA -> function name mappings.
        Falls back to basic string extraction on non-Windows or if dbghelp fails.
        """
        if not mod.pdb_path or not os.path.exists(mod.pdb_path):
            return False

        # Try Windows dbghelp first (proper symbol loading)
        import sys
        if sys.platform == 'win32':
            if self._parse_pdb_with_dbghelp(mod):
                mod.symbols_loaded = True
                return True
        
        # Fallback: basic string extraction (less accurate)
        try:
            with open(mod.pdb_path, 'rb') as f:
                data = f.read()

            # Check for PDB signature
            if not data.startswith(b'Microsoft C/C++ MSF 7.00'):
                return False

            # Extract string references that look like function names
            # This is a heuristic approach - full PDB parsing is complex
            self._extract_symbol_strings(data, mod)

            mod.symbols_loaded = True
            return True

        except Exception:
            return False
    
    def _parse_pdb_with_dbghelp(self, mod: ModuleSymbolInfo) -> bool:
        """Parse PDB using Windows dbghelp.dll for proper symbol->RVA mapping.
        
        Uses a timeout wrapper to prevent hangs on massive PDB files.
        """
        
        # OPTIMIZATION: Skip large PDBs that would take too long to parse
        # Large PDBs (like Chromium) have thousands of symbols and enum takes minutes
        if mod.pdb_path and os.path.exists(mod.pdb_path):
            pdb_size = os.path.getsize(mod.pdb_path)
            # Skip PDBs larger than 200MB - they're not critical for crash analysis
            if pdb_size > 200 * 1024 * 1024:
                print(f"[SYMBOL] - Skipping PDB parsing for {mod.name} ({pdb_size/(1024*1024):.1f}MB) - would take 5-15 minutes")
                self._log(f"DbgHelp skipping large PDB {mod.name} ({pdb_size/(1024*1024):.1f}MB) - would take too long")
                return False
        
        print(f"[SYMBOL] - Parsing symbols from PDB for {mod.name}...")
        
        # Wrap the actual parsing in a timeout (max 15 seconds per PDB)
        # Reduced from 30s to prevent extended hangs on large dumps
        result_container = {'result': False}
        
        def timeout_parse():
            result_container['result'] = self._do_parse_pdb_with_dbghelp(mod)
        
        thread = threading.Thread(target=timeout_parse, daemon=True)
        thread.start()
        thread.join(timeout=15)  # Wait max 15 seconds (reduced to prevent hangs)
        
        if thread.is_alive():
            self._log(f"DbgHelp symbol enumeration timeout for {mod.name} - likely massive PDB")
            safe_print(f"[SYMBOL] - Timeout parsing {mod.name} after 15s - skipping")
            return False
        
        return result_container['result']
    
    def _do_parse_pdb_with_dbghelp(self, mod: ModuleSymbolInfo) -> bool:
        """Actually parse PDB using Windows dbghelp.dll.
        
        This is called in a timeout wrapper to prevent hangs.
        """
        try:
            import ctypes
            from ctypes import wintypes
            
            kernel32 = ctypes.windll.kernel32
            
            # Load dbghelp.dll
            dbghelp = ctypes.windll.dbghelp
            
            # Initialize symbol handler
            kernel32.GetCurrentProcess.argtypes = []
            kernel32.GetCurrentProcess.restype = wintypes.HANDLE
            hProcess = kernel32.GetCurrentProcess()

            dbghelp.SymInitializeW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.BOOL]
            dbghelp.SymInitializeW.restype = wintypes.BOOL
            dbghelp.SymLoadModuleExW.argtypes = [
                wintypes.HANDLE,
                wintypes.HANDLE,
                wintypes.LPCWSTR,
                wintypes.LPCWSTR,
                ctypes.c_ulonglong,
                wintypes.DWORD,
                ctypes.c_void_p,
                wintypes.DWORD,
            ]
            dbghelp.SymLoadModuleExW.restype = ctypes.c_ulonglong
            dbghelp.SymUnloadModule64.argtypes = [wintypes.HANDLE, ctypes.c_ulonglong]
            dbghelp.SymUnloadModule64.restype = wintypes.BOOL
            dbghelp.SymCleanup.argtypes = [wintypes.HANDLE]
            dbghelp.SymCleanup.restype = wintypes.BOOL
            dbghelp.SymEnumSymbolsW.argtypes = [wintypes.HANDLE, ctypes.c_ulonglong, wintypes.LPCWSTR, ctypes.c_void_p, ctypes.c_void_p]
            dbghelp.SymEnumSymbolsW.restype = wintypes.BOOL
            dbghelp.SymGetLastError.restype = wintypes.DWORD

            # Configure symbol options
            SYMOPT_UNDNAME = 0x00000002
            SYMOPT_DEFERRED_LOADS = 0x00000004
            SYMOPT_LOAD_LINES = 0x00000010
            SYMOPT_FAIL_CRITICAL_ERRORS = 0x00000200
            dbghelp.SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES | SYMOPT_FAIL_CRITICAL_ERRORS)

            # Build symbol search path (cache dir + pdb directory if available)
            search_paths = []
            if self.cache_dir:
                cache_root = str(self.cache_dir)
                search_paths.append(cache_root)
                search_paths.append(f"srv*{cache_root}")
            if mod.pdb_path:
                pdb_dir = os.path.dirname(mod.pdb_path)
                if pdb_dir and pdb_dir not in search_paths:
                    search_paths.append(pdb_dir)
            sym_path = ";".join(search_paths) if search_paths else None

            # SymInitialize
            if not dbghelp.SymInitializeW(hProcess, sym_path, False):
                self._log(f"DbgHelp SymInitializeW failed (path={sym_path})")
                return False
            
            try:
                # Load module symbols
                # Use a fake base address for symbol loading
                baseAddr = mod.base_address if mod.base_address else 0x10000000
                image_size = mod.size if mod.size else 0x100000

                def _get_last_error() -> int:
                    return kernel32.GetLastError()

                def _get_sym_error() -> int:
                    try:
                        return dbghelp.SymGetLastError()
                    except Exception:
                        return _get_last_error()

                def _load_module(image_path: Optional[str], module_name: Optional[str], flags: int) -> int:
                    return dbghelp.SymLoadModuleExW(
                        hProcess,
                        None,
                        ctypes.c_wchar_p(image_path) if image_path else None,
                        ctypes.c_wchar_p(module_name) if module_name else None,
                        baseAddr,
                        image_size,
                        None,
                        flags,
                    )

                # First try: load using module image path if it exists
                loadedBase = 0
                image_path = mod.name if mod.name and os.path.exists(mod.name) else None
                if image_path:
                    loadedBase = _load_module(image_path, os.path.basename(image_path), 0)
                    if not loadedBase:
                        err_code = _get_sym_error()
                        if err_code != 0:
                            self._log(f"DbgHelp SymLoadModuleExW failed for image {image_path}")
                            self._log(f"  Error code: 0x{err_code:X}")
                            self._log(f"  Possible causes: PDB not found in search path, mismatched PDB GUID, or corrupted PE file")

                # Second try: load using PDB path as a virtual module
                if not loadedBase and mod.pdb_path:
                    SLMFLAG_VIRTUAL = 0x1
                    loadedBase = _load_module(mod.pdb_path, mod.pdb_name or os.path.basename(mod.pdb_path), SLMFLAG_VIRTUAL)
                    if not loadedBase:
                        err_code = _get_sym_error()
                        if err_code != 0:
                            self._log(f"DbgHelp SymLoadModuleExW failed for PDB {mod.pdb_path}")
                            self._log(f"  Error code: 0x{err_code:X}")
                            if err_code == 0x000003F0:  # ERROR_DBG_NO_SYMBOLS
                                self._log(f"  Diagnosis: PDB has no public symbols (stripped/private PDB)")
                            elif err_code == 0x00000002:  # ERROR_FILE_NOT_FOUND
                                self._log(f"  Diagnosis: PDB file not found at path")
                            elif err_code == 0x00000571:  # ERROR_IMAGE_CHECKSUM_MISMATCH
                                self._log(f"  Diagnosis: PDB GUID/Age mismatch with module")
                            else:
                                self._log(f"  Diagnosis: Unknown error loading PDB")
                        else:
                            self._log(f"DbgHelp SymLoadModuleExW failed for PDB {mod.pdb_path} (no error code)")

                if not loadedBase:
                    self._log(f"Failed to load module {mod.name} into DbgHelp")
                    return False
                
                # Enumerate symbols
                class SYMBOL_INFOW(ctypes.Structure):
                    _fields_ = [
                        ("SizeOfStruct", wintypes.DWORD),
                        ("TypeIndex", wintypes.DWORD),
                        ("Reserved", wintypes.ULARGE_INTEGER * 2),
                        ("Index", wintypes.DWORD),
                        ("Size", wintypes.DWORD),
                        ("ModBase", ctypes.c_ulonglong),
                        ("Flags", wintypes.DWORD),
                        ("Value", ctypes.c_ulonglong),
                        ("Address", ctypes.c_ulonglong),
                        ("Register", wintypes.DWORD),
                        ("Scope", wintypes.DWORD),
                        ("Tag", wintypes.DWORD),
                        ("NameLen", wintypes.DWORD),
                        ("MaxNameLen", wintypes.DWORD),
                        ("Name", ctypes.c_wchar * 1),
                    ]

                max_name_len = 2000
                symbol_info = ctypes.create_string_buffer(ctypes.sizeof(SYMBOL_INFOW) + (max_name_len * ctypes.sizeof(ctypes.c_wchar)))
                sym_info_ptr = ctypes.cast(symbol_info, ctypes.POINTER(SYMBOL_INFOW))
                sym_info_ptr.contents.SizeOfStruct = ctypes.sizeof(SYMBOL_INFOW)
                sym_info_ptr.contents.MaxNameLen = max_name_len
                
                # Callback to collect symbols
                symbols_collected = []
                max_symbols_to_collect = 10000  # Cap collection to avoid hangs
                
                @ctypes.WINFUNCTYPE(wintypes.BOOL, ctypes.POINTER(SYMBOL_INFOW), wintypes.DWORD, ctypes.c_void_p)
                def enum_callback(pSymInfo, SymbolSize, UserContext):
                    try:
                        # Stop after collecting enough symbols to avoid infinite hangs
                        if len(symbols_collected) >= max_symbols_to_collect:
                            return False  # Signal enumeration to stop
                        
                        name_len = pSymInfo.contents.NameLen
                        if name_len > 0:
                            name_ptr = ctypes.addressof(pSymInfo.contents.Name)
                            name = ctypes.wstring_at(name_ptr, name_len)
                        else:
                            name = ""
                        rva = pSymInfo.contents.Address - loadedBase
                        size = pSymInfo.contents.Size
                        
                        if name and rva >= 0:
                            symbols_collected.append((rva, name, size))
                        
                        return True  # Continue enumeration
                    except Exception:
                        # Failed to process symbol; continue enumeration
                        return True
                
                # Enumerate all symbols (with timeout protection)
                enum_ok = dbghelp.SymEnumSymbolsW(
                    hProcess,
                    loadedBase,
                    ctypes.c_wchar_p("*"),
                    enum_callback,
                    None,
                )
                if not enum_ok:
                    err_code = _get_sym_error()
                    self._log(f"DbgHelp SymEnumSymbols failed")
                    self._log(f"  Error code: 0x{err_code:X}")
                    if err_code == 0x000003F0:  # ERROR_DBG_NO_SYMBOLS
                        self._log(f"  Diagnosis: PDB contains no public symbols (private/stripped PDB)")
                    else:
                        self._log(f"  Diagnosis: Symbol enumeration failed")
                
                # Store symbols in module
                for rva, name, size in symbols_collected:
                    mod.symbols[rva] = (name, size)
                
                # Unload module
                dbghelp.SymUnloadModule64(hProcess, loadedBase)
                
                symbols_loaded = len(mod.symbols) > 0
                if symbols_loaded:
                    self._log(f"Successfully loaded {len(mod.symbols)} symbols from PDB for {mod.name}")
                else:
                    self._log(f"Warning: PDB loaded but 0 symbols extracted for {mod.name}")
                    self._log(f"  This usually means the PDB is stripped/private. Will fall back to string extraction.")
                
                return symbols_loaded
                
            finally:
                # Cleanup
                dbghelp.SymCleanup(hProcess)
                
        except Exception as e:
            # Log the exception and fall back to string extraction
            self._log(f"Exception during PDB parsing via DbgHelp: {type(e).__name__}: {str(e)[:200]}")
            self._log(f"  Will attempt fallback string extraction method")
            return False

    def _extract_symbol_strings(self, data: bytes, mod: ModuleSymbolInfo):
        """
        Extract potential symbol names from PDB data.

        This uses heuristics to find function names. Not as accurate as
        full PDB parsing but works for basic symbol resolution.
        """
        # Look for patterns that indicate function names
        # Common patterns: ?FunctionName@@... (C++ mangled) or _FunctionName

        # C++ mangled names
        cpp_pattern = re.compile(rb'\?([A-Za-z_][A-Za-z0-9_]*(?:@@[A-Z0-9@]+)?)')

        # C-style names
        c_pattern = re.compile(rb'(?:^|[^A-Za-z0-9_])_?([A-Z][a-z]+[A-Za-z0-9_]{2,})')

        # Extract and store potential symbol names
        found_names = set()

        for match in cpp_pattern.finditer(data):
            name = match.group(1).decode('utf-8', errors='ignore')
            if 3 < len(name) < 200:
                found_names.add(name)

        for match in c_pattern.finditer(data):
            name = match.group(1).decode('utf-8', errors='ignore')
            if 3 < len(name) < 100:
                found_names.add(name)

        # Store as potential symbols (we don't have RVAs from this method)
        for name in found_names:
            mod.publics[hash(name) & 0xFFFFFFFF] = name

    def resolve_address(self, address: int) -> Optional[SymbolInfo]:
        """
        Resolve an address to a symbol.

        Args:
            address: Virtual address to resolve

        Returns:
            SymbolInfo if resolved, None otherwise
        """
        # Find which module contains this address
        mod = self._find_module_for_address(address)
        if not mod:
            return None

        # Calculate RVA (Relative Virtual Address)
        rva = address - mod.base_address

        # Try to find symbol at or before this RVA
        symbol_name = None
        symbol_offset = rva  # Default to RVA as offset if no symbol found

        if mod.symbols:
            # Find closest symbol at or before the RVA from proper symbols dict
            closest_rva = 0
            for sym_rva, (name, size) in mod.symbols.items():
                if sym_rva <= rva and sym_rva > closest_rva:
                    closest_rva = sym_rva
                    symbol_name = name
                    symbol_offset = rva - sym_rva
        elif mod.publics:
            # Fallback: search publics dict (from string extraction)
            # Publics dict is {hash(name): name} so we can't get RVA, but we can find matching names
            # This is less accurate but better than nothing
            for pub_rva, pub_name in mod.publics.items():
                if pub_rva <= rva and pub_rva > (closest_rva if symbol_name else 0):
                    closest_rva = pub_rva
                    symbol_name = pub_name
                    symbol_offset = rva - pub_rva

        if symbol_name:
            self.stats['addresses_resolved'] += 1
            return SymbolInfo(
                module_name=mod.name,
                function_name=symbol_name,
                offset=symbol_offset,
                rva=rva
            )

        # Fall back to module + offset format
        self.stats['addresses_resolved'] += 1
        return SymbolInfo(
            module_name=mod.name,
            function_name=f"<unknown>",
            offset=rva,
            rva=rva
        )

    def _find_module_for_address(self, address: int) -> Optional[ModuleSymbolInfo]:
        """Find which module contains the given address."""
        for base, mod in self._modules.items():
            if base <= address < base + mod.size:
                return mod
        return None

    def get_module_for_address(self, address: int) -> Optional[Tuple[str, int]]:
        """
        Get module name and offset for an address.

        Returns:
            Tuple of (module_name, offset) or None
        """
        mod = self._find_module_for_address(address)
        if mod:
            return (mod.name, address - mod.base_address)
        return None

    def format_address(self, address: int) -> str:
        """
        Format an address with module and offset information.

        Example: "citizen-scripting-lua.dll+0x12345" or "0x7FF812345678"
        """
        mod = self._find_module_for_address(address)
        if mod:
            offset = address - mod.base_address
            return f"{os.path.basename(mod.name)}+0x{offset:X}"
        return f"0x{address:016X}"

    def analyze_last_memory_operation(self, exception_code: int,
                                       exception_address: int,
                                       access_type: str,
                                       target_address: int,
                                       context: Dict[str, int],
                                       memory_regions: List[Any] = None) -> LastMemoryOperation:
        """
        Analyze the last memory operation before the crash.

        Args:
            exception_code: Windows exception code (e.g., 0xC0000005)
            exception_address: Address of the faulting instruction
            access_type: Type of access ("read", "write", "execute")
            target_address: Address that was being accessed
            context: CPU register values
            memory_regions: List of memory region info for context

        Returns:
            LastMemoryOperation with detailed analysis
        """
        op = LastMemoryOperation(
            operation_type=access_type or "unknown",
            target_address=target_address,
            instruction_address=exception_address,
            registers=context.copy() if context else {}
        )

        # Resolve the faulting address to a symbol
        symbol = self.resolve_address(exception_address)
        if symbol:
            op.faulting_function = symbol.function_name
            op.faulting_module = symbol.module_name
            op.function_offset = symbol.offset
        else:
            # Fall back to module + offset
            mod_info = self.get_module_for_address(exception_address)
            if mod_info:
                op.faulting_module = mod_info[0]
                op.function_offset = mod_info[1]

        # Analyze the target address
        op.is_null_pointer = target_address < 0x10000

        # Check if it's a stack address (typically high addresses on Windows x64)
        if context:
            rsp = context.get('Rsp', context.get('RSP', context.get('rsp', 0)))
            if rsp and abs(target_address - rsp) < 0x100000:  # Within 1MB of stack
                op.is_stack_address = True

        # Check if it's in a code region
        if memory_regions:
            for region in memory_regions:
                if hasattr(region, 'start_address') and hasattr(region, 'size'):
                    if region.start_address <= target_address < region.start_address + region.size:
                        if hasattr(region, 'contains_code') and region.contains_code:
                            op.is_code_address = True
                        break

        # Build description
        op.description = self._build_operation_description(op, exception_code)

        # Analyze likely cause and provide recommendations
        op.likely_cause, op.recommendations = self._analyze_crash_cause(
            op, exception_code, context
        )

        return op

    def _build_operation_description(self, op: LastMemoryOperation,
                                     exception_code: int) -> str:
        """Build a human-readable description of the memory operation."""
        parts = []

        # Operation type
        if op.operation_type == "read":
            parts.append("Attempted to READ from")
        elif op.operation_type == "write":
            parts.append("Attempted to WRITE to")
        elif op.operation_type == "execute" or "execute" in op.operation_type.lower():
            parts.append("Attempted to EXECUTE code at")
        else:
            parts.append("Invalid access to")

        # Target address description
        if op.is_null_pointer:
            if op.target_address == 0:
                parts.append("NULL pointer (address 0x0)")
            else:
                parts.append(f"near-NULL address 0x{op.target_address:X} (likely NULL + offset)")
        elif op.is_stack_address:
            parts.append(f"stack address 0x{op.target_address:016X}")
        elif op.is_code_address:
            parts.append(f"code region 0x{op.target_address:016X}")
        else:
            parts.append(f"address 0x{op.target_address:016X}")

        # Faulting location
        if op.faulting_function and op.faulting_function != "<unknown>":
            parts.append(f"\nFaulting function: {op.faulting_module}!{op.faulting_function}+0x{op.function_offset:X}")
        elif op.faulting_module:
            parts.append(f"\nFaulting location: {op.faulting_module}+0x{op.function_offset:X}")

        return " ".join(parts)

    def _analyze_crash_cause(self, op: LastMemoryOperation,
                            exception_code: int,
                            context: Dict[str, int]) -> Tuple[str, List[str]]:
        """Analyze the likely cause of the crash and provide recommendations."""
        likely_cause = ""
        recommendations = []

        # Access Violation analysis
        if exception_code == 0xC0000005:
            if op.is_null_pointer:
                likely_cause = "NULL pointer dereference"
                recommendations = [
                    "Check for uninitialized variables or handles",
                    "Verify entity/player handles are valid before use",
                    "Add nil checks in Lua scripts before accessing object properties",
                    "Check if async callbacks received valid data",
                    "Ensure GetPlayerPed() and similar natives return valid handles"
                ]
            elif op.operation_type == "write" and op.is_code_address:
                likely_cause = "Write to code/read-only memory (possible buffer overflow)"
                recommendations = [
                    "Check for buffer overflows in native calls",
                    "Verify string lengths before passing to natives",
                    "Check for array out-of-bounds access"
                ]
            elif "execute" in op.operation_type.lower():
                likely_cause = "DEP violation - attempted to execute non-executable memory"
                recommendations = [
                    "This may indicate a corrupted function pointer",
                    "Check for use-after-free scenarios",
                    "Verify callback function pointers are valid"
                ]
            elif op.is_stack_address:
                likely_cause = "Stack corruption or overflow"
                recommendations = [
                    "Check for infinite recursion in scripts",
                    "Reduce deeply nested function calls",
                    "Check for large local arrays that might overflow stack"
                ]
            else:
                likely_cause = "Invalid memory access (freed/unmapped memory)"
                recommendations = [
                    "Check for use-after-free scenarios",
                    "Verify pointers/handles are still valid",
                    "Check for race conditions in async code"
                ]

        # Stack overflow
        elif exception_code == 0xC00000FD:
            likely_cause = "Stack overflow (infinite recursion or deep call stack)"
            recommendations = [
                "Check for recursive functions without proper exit conditions",
                "Look for circular event triggers",
                "Reduce nested function call depth",
                "Check for infinite loops with function calls"
            ]

        # Heap corruption
        elif exception_code == 0xC0000374:
            likely_cause = "Heap corruption (memory management error)"
            recommendations = [
                "Check for double-free scenarios",
                "Verify all memory allocations are properly freed",
                "Check for writes past allocated buffer boundaries",
                "Look for race conditions in memory management"
            ]

        # Check for FiveM-specific patterns
        if op.faulting_module:
            mod_lower = op.faulting_module.lower()
            if 'citizen-scripting-lua' in mod_lower:
                recommendations.insert(0, "Crash in Lua runtime - check Lua scripts for errors")
            elif 'citizen-scripting-v8' in mod_lower:
                recommendations.insert(0, "Crash in JavaScript runtime - check JS scripts for errors")
            elif 'gta-' in mod_lower or 'rage-' in mod_lower:
                recommendations.insert(0, "Crash in game engine - may be caused by invalid native calls")
            elif 'nvwgf2umx' in mod_lower or 'atikmdag' in mod_lower:
                recommendations.insert(0, "Crash in graphics driver - try updating GPU drivers")

        return likely_cause, recommendations

    def get_statistics(self) -> Dict[str, Any]:
        """Get symbol resolution statistics."""
        return {
            'modules_registered': len(self._modules),
            'modules_with_symbols': sum(1 for m in self._modules.values() if m.symbols_loaded),
            **self.stats
        }

    def clear_cache(self):
        """Clear the symbol cache directory."""
        try:
            shutil.rmtree(self.cache_dir)
            self.cache_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

    def get_cache_size(self) -> int:
        """Get the total size of cached symbols in bytes."""
        total = 0
        try:
            for path in self.cache_dir.rglob('*'):
                if path.is_file():
                    total += path.stat().st_size
        except Exception:
            pass
        return total

"""Core crash analysis logic for FiveM Crash Analyzer.

This module provides comprehensive crash analysis including deep memory analysis,
script/resource pinpointing, and detailed error attribution.
"""
from __future__ import annotations

import json
import os
import re
import sys
import struct
import tempfile
import urllib.parse
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple, Set

# #region agent log
_DEBUG_LOG = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".cursor", "debug.log")
def _dlog(hypothesis_id: str, location: str, message: str, data: dict) -> None:
    try:
        os.makedirs(os.path.dirname(_DEBUG_LOG), exist_ok=True)
        with open(_DEBUG_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps({"hypothesisId": hypothesis_id, "location": location, "message": message, "data": data, "timestamp": __import__("time").time()}) + "\n")
    except Exception:
        pass

def _dlog2(
    hypothesis_id: str,
    location: str,
    message: str,
    data: Dict[str, Any],
    run_id: str = "run1",
) -> None:
    """Debug-mode log writer with required NDJSON fields."""
    try:
        os.makedirs(os.path.dirname(_DEBUG_LOG), exist_ok=True)
        ts_ms = int(__import__("time").time() * 1000)
        with open(_DEBUG_LOG, "a", encoding="utf-8") as f:
            f.write(
                json.dumps(
                    {
                        "sessionId": "debug-session",
                        "runId": run_id,
                        "hypothesisId": hypothesis_id,
                        "location": location,
                        "message": message,
                        "data": data,
                        "timestamp": ts_ms,
                    }
                )
                + "\n"
            )
    except Exception:
        pass
# #endregion

# Optional dependencies
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    requests = None
    HAS_REQUESTS = False

try:
    from minidump.minidumpfile import MinidumpFile
    HAS_MINIDUMP = True
except ImportError:
    MinidumpFile = None
    HAS_MINIDUMP = False

try:
    import ctypes
    HAS_CTYPES = True
except ImportError:
    ctypes = None
    HAS_CTYPES = False

# Import the deep memory analyzer
from .memory_analyzer import (
    MemoryAnalyzer,
    DeepAnalysisResult,
    ScriptEvidence,
    EvidenceType,
    ResourceInfo,
    ScriptError,
    LuaStackFrame,
    # NEW: Additional data classes for extended extraction
    HandleInfo,
    ThreadExtendedInfo,
    ModuleVersionInfo,
    ExceptionParams,
    ProcessStatistics,
    MemoryRegionInfo,
)


@dataclass
class PatternMatch:
    """Represents a matched crash pattern."""
    issue: str
    explanation: str
    solutions: List[str]


@dataclass
class CrashReport:
    """Complete crash analysis report."""
    # Basic info
    dump_file: Optional[str] = None
    log_files: List[str] = field(default_factory=list)

    # Exception details
    exception_code: Optional[int] = None
    exception_address: Optional[int] = None
    exception_module: Optional[str] = None

    # Primary suspects
    primary_suspects: List[ResourceInfo] = field(default_factory=list)

    # All resources identified (from memory scan); used to show names near native stack
    resources: Dict[str, ResourceInfo] = field(default_factory=dict)

    # Script errors
    script_errors: List[ScriptError] = field(default_factory=list)

    # Stack traces
    lua_stacks: List[List[LuaStackFrame]] = field(default_factory=list)
    lua_stack_resources: List[List[str]] = field(default_factory=list)  # resources involved per Lua stack
    js_stacks: List[str] = field(default_factory=list)
    js_stack_resources: List[List[str]] = field(default_factory=list)  # resources involved per JS stack
    native_stacks: List[str] = field(default_factory=list)
    # Symbolicated native stack (function names when PDB available); same length as native_stacks
    native_stacks_symbolicated: List[str] = field(default_factory=list)
    # True if FIVEM_SYMBOL_CACHE (or local_symbol_path) was set when symbolication ran (for message wording)
    symbolication_had_local_path: bool = False
    # Diagnostic when symbols failed: first modules we tried and paths checked (for troubleshooting)
    symbolication_diagnostic: Optional[str] = None

    # Pattern matches
    crash_patterns: List[PatternMatch] = field(default_factory=list)

    # Modules
    modules: List[Dict[str, Any]] = field(default_factory=list)
    identified_modules: List[Dict[str, str]] = field(default_factory=list)

    # Resources from logs
    log_resources: List[str] = field(default_factory=list)
    log_errors: List[Dict[str, Any]] = field(default_factory=list)

    # Tie-breaking / confidence (from memory_analyzer)
    primary_suspect_secondary: Optional[str] = None
    primary_suspect_confidence: str = "medium"

    # All evidence
    all_evidence: List[ScriptEvidence] = field(default_factory=list)

    # Analysis metadata
    analysis_errors: List[str] = field(default_factory=list)

    # Standard Minidump Data
    system_info: Dict[str, Any] = field(default_factory=dict)
    misc_info: Dict[str, Any] = field(default_factory=dict)
    crash_time: Optional[int] = None
    exception_context: Dict[str, Any] = field(default_factory=dict)
    unloaded_modules: List[str] = field(default_factory=list)

    # NEW: Extended minidump data
    # Detailed exception parameters (access violation details, etc.)
    exception_params: Optional[ExceptionParams] = None

    # Handle data - open files, mutexes, registry keys at crash
    handles: List[HandleInfo] = field(default_factory=list)

    # Extended thread information
    threads_extended: List[ThreadExtendedInfo] = field(default_factory=list)

    # Module version/PDB info for symbol resolution
    module_versions: List[ModuleVersionInfo] = field(default_factory=list)

    # Memory info list with detailed permissions
    memory_info: List[MemoryRegionInfo] = field(default_factory=list)

    # Process statistics (memory usage, handle counts, etc.)
    process_stats: Optional[ProcessStatistics] = None

    # Function table entries count
    function_table_entries: int = 0

    # Comment streams
    comment_stream_a: str = ""
    comment_stream_w: str = ""

    # Assertion info
    assertion_info: Dict[str, str] = field(default_factory=dict)

    # JavaScriptData stream (20) - V8/JS context when present
    javascript_data: Optional[Dict[str, Any]] = None
    # ProcessVmCounters stream (22) - VM usage at crash
    process_vm_counters: Optional[Dict[str, Any]] = None

    # ===== MEMORY LEAK ANALYSIS DATA =====
    # Entity creation/deletion tracking
    entity_creations: List[Tuple[str, int]] = field(default_factory=list)
    entity_deletions: List[Tuple[str, int]] = field(default_factory=list)
    
    # Timer tracking
    timers_created: List[Tuple[str, int]] = field(default_factory=list)
    
    # Event handler tracking
    event_handlers_registered: List[Tuple[str, int]] = field(default_factory=list)
    event_handlers_removed: List[Tuple[str, int]] = field(default_factory=list)
    
    # Memory allocation tracking
    memory_allocations: List[Tuple[str, int]] = field(default_factory=list)
    memory_frees: List[Tuple[str, int]] = field(default_factory=list)
    
    # Memory leak indicators
    memory_leak_indicators: List[Tuple[str, str, int]] = field(default_factory=list)
    
    # Pool exhaustion indicators
    pool_exhaustion_indicators: List[Tuple[str, int]] = field(default_factory=list)
    
    # Database patterns
    database_patterns: List[Tuple[str, int]] = field(default_factory=list)
    
    # NUI/CEF patterns
    nui_patterns: List[Tuple[str, int]] = field(default_factory=list)
    
    # Network patterns
    network_patterns: List[Tuple[str, int]] = field(default_factory=list)
    
    # State bag patterns
    statebag_patterns: List[Tuple[str, int]] = field(default_factory=list)


class Symbolicator:
    """Symbol downloader and address resolver for Windows minidumps.

    Local symbol cache: set FIVEM_SYMBOL_CACHE to a folder path (e.g. D:\\symbolcache)
    to load PDBs from disk when the server returns 404. Layout: cache/pdb_name/GUIDage/pdb_name
    or cache/pdb_name/GUID/pdb_name or cache/pdb_name (flat).
    """

    # Timeout (seconds) for symbol server requests; increase if you see timeout errors
    SYMBOL_DOWNLOAD_TIMEOUT = 30

    # Fallback paths to check when FIVEM_SYMBOL_CACHE env var is not set
    _DEFAULT_CACHE_PATHS = ("D:\\symbolcache", "C:\\symbolcache")

    def __init__(
        self,
        symbol_server: str = "https://runtime.fivem.net/client/symbols/",
        local_symbol_path: Optional[str] = None,
    ):
        self.server = symbol_server
        raw_path = (local_symbol_path or os.environ.get("FIVEM_SYMBOL_CACHE", "").strip()) or None
        # Fallback: if env var not set, use first existing default path (e.g. when run from IDE, not run_analyzer.bat)
        if not raw_path and sys.platform == "win32":
            for p in self._DEFAULT_CACHE_PATHS:
                if os.path.isdir(p):
                    raw_path = p
                    break
        self._local_symbol_path = os.path.normpath(raw_path) if raw_path else None
        # #region agent log
        _dlog("local_cache", "core.Symbolicator.__init__", "local symbol path", {
            "local_symbol_path": self._local_symbol_path,
            "from_env": os.environ.get("FIVEM_SYMBOL_CACHE", "").strip() or None,
        })
        # #endregion
        self.process = None
        self.dbghelp = None
        self._initialized = False
        self._symbol_cache: Dict[str, str] = {}

        if sys.platform == 'win32' and HAS_CTYPES:
            self._init_dbghelp()

    def _init_dbghelp(self) -> None:
        """Initialize Windows debug help library."""
        try:
            self.dbghelp = ctypes.windll.dbghelp
            kernel32 = ctypes.windll.kernel32
            self.process = kernel32.GetCurrentProcess()

            # Initialize symbol handler
            self.dbghelp.SymSetOptions(0x10)  # SYMOPT_LOAD_LINES
            result = self.dbghelp.SymInitializeW(
                self.process,
                ctypes.c_wchar_p(self.server),
                ctypes.c_bool(False)
            )
            self._initialized = bool(result)
        except Exception:
            self._initialized = False

    def download_symbol(self, module_name: str) -> Optional[str]:
        """Download symbol file for a module."""
        if not HAS_REQUESTS:
            return None

        base = os.path.basename(module_name)
        candidates = [base, base + '.pdb', base + '.sym', base + '.zip']

        for cand in candidates:
            if cand in self._symbol_cache:
                return self._symbol_cache[cand]

            url = urllib.parse.urljoin(self.server, cand)
            try:
                r = requests.get(url, stream=True, timeout=Symbolicator.SYMBOL_DOWNLOAD_TIMEOUT)
                if r.status_code == 200:
                    fd, path = tempfile.mkstemp(suffix='_' + cand)
                    with os.fdopen(fd, 'wb') as f:
                        for chunk in r.iter_content(8192):
                            f.write(chunk)
                    self._symbol_cache[cand] = path
                    return path
            except Exception:
                continue
        return None

    def _try_local_cache(
        self, pdb_name: str, guid_str: str, combined: str, cache_key: str
    ) -> Optional[str]:
        """Try to find PDB in local cache. Tries exact GUID match first, then GUID-agnostic fallback (FiveM builds often compatible)."""
        # #region agent log
        _dlog2("H1", "core._try_local_cache.entry", "local cache lookup start", {
            "pdb_name": pdb_name,
            "guid_str": guid_str[:20] if guid_str else "",
            "combined": combined[:20] if combined else "",
            "local_path": self._local_symbol_path,
        })
        # #endregion
        if not self._local_symbol_path or not os.path.isdir(self._local_symbol_path):
            return None
        pdb_basename = os.path.basename(pdb_name)
        # Normalize: ensure we have .pdb for file matching
        pdb_file = pdb_name if pdb_name.lower().endswith(".pdb") else pdb_name + ".pdb"
        # Folder name variants (cache may use "citizen-game-main.pdb" or "citizen-game-main")
        folder_variants = [pdb_name, pdb_file]
        if pdb_name.lower().endswith(".pdb"):
            folder_variants.append(pdb_name[:-4])  # without .pdb
        folder_variants = list(dict.fromkeys(folder_variants))  # dedup

        # 1. Exact paths: pdb_name/GUID+age/pdb, pdb_name/GUID/pdb, pdb_name/pdb
        candidates = []
        if combined:
            candidates.append(os.path.join(self._local_symbol_path, pdb_name, combined, pdb_file))
            candidates.append(os.path.join(self._local_symbol_path, pdb_name, combined, pdb_name))
        if guid_str:
            candidates.append(os.path.join(self._local_symbol_path, pdb_name, guid_str, pdb_file))
            candidates.append(os.path.join(self._local_symbol_path, pdb_name, guid_str, pdb_name))
        for folder in folder_variants:
            candidates.append(os.path.join(self._local_symbol_path, folder, pdb_file))
            candidates.append(os.path.join(self._local_symbol_path, folder, pdb_name))
        # #region agent log
        _dlog2("H1", "core._try_local_cache.exact_candidates", "exact path candidates", {
            "pdb_name": pdb_name,
            "folder_variants": folder_variants,
            "candidates_count": len(candidates),
            "candidates_sample": [c for c in candidates[:4]],
        })
        # #endregion
        for c in candidates:
            if c and os.path.isfile(c):
                self._symbol_cache[cache_key] = c
                # #region agent log
                _dlog2("H1", "core._try_local_cache.found_exact", "found via exact path", {"path": c})
                # #endregion
                return c

        # 2. Flexible scan: folder matching pdb_name (any variant), any subfolder with pdb file
        try:
            matched_folders = []
            for sub in os.listdir(self._local_symbol_path):
                if sub.lower() not in {v.lower() for v in folder_variants}:
                    continue
                matched_folders.append(sub)
                subpath = os.path.join(self._local_symbol_path, sub)
                if not os.path.isdir(subpath):
                    continue
                for fname in (pdb_file, pdb_name, pdb_basename):
                    flat = os.path.join(subpath, fname)
                    if os.path.isfile(flat):
                        self._symbol_cache[cache_key] = flat
                        # #region agent log
                        _dlog2("H4", "core._try_local_cache.found_flat", "found via flat scan", {"path": flat})
                        # #endregion
                        return flat
                for sub2 in os.listdir(subpath):
                    for fname in (pdb_file, pdb_name, pdb_basename):
                        candidate = os.path.join(subpath, sub2, fname)
                        if os.path.isfile(candidate):
                            self._symbol_cache[cache_key] = candidate
                            # #region agent log
                            _dlog2("H4", "core._try_local_cache.found_subfolder", "found via subfolder scan", {"path": candidate})
                            # #endregion
                            return candidate
            # #region agent log
            if matched_folders:
                _dlog2("H4", "core._try_local_cache.matched_folders", "folders matched but no pdb file", {
                    "pdb_name": pdb_name,
                    "matched_folders": matched_folders[:5],
                })
            # #endregion
        except OSError:
            pass

        # 3. GUID-agnostic walk: find any .pdb with matching name (FiveM PDBs often work across builds)
        try:
            found_any: List[str] = []
            for root, _dirs, files in os.walk(self._local_symbol_path, topdown=True):
                if len(found_any) > 50:
                    break
                for f in files:
                    if (f == pdb_basename or f.lower() == pdb_basename.lower()
                            or f == pdb_file or f.lower() == pdb_file.lower()):
                        path = os.path.join(root, f)
                        if os.path.isfile(path) and path.lower().endswith(".pdb"):
                            found_any.append(path)
                            if guid_str and len(guid_str) >= 8 and guid_str.upper() in path.upper():
                                self._symbol_cache[cache_key] = path
                                # #region agent log
                                _dlog2("H4", "core._try_local_cache.found_walk_guid", "found via walk with GUID match", {"path": path})
                                # #endregion
                                return path
            if found_any:
                self._symbol_cache[cache_key] = found_any[0]
                # #region agent log
                _dlog2("H4", "core._try_local_cache.found_walk_any", "found via walk (any match)", {"path": found_any[0], "total_found": len(found_any)})
                # #endregion
                return found_any[0]
            # #region agent log
            _dlog2("H4", "core._try_local_cache.walk_not_found", "walk completed, no match", {
                "pdb_name": pdb_name,
                "pdb_basename": pdb_basename,
                "pdb_file": pdb_file,
            })
            # #endregion
        except OSError:
            pass
        return None

    def download_symbol_by_pdb(self, pdb_name: str, guid: str, age: int) -> Optional[str]:
        """Download symbol file using PDB name and GUID."""
        if not pdb_name:
            return None

        cache_key = f"{pdb_name}_{guid}_{age}"
        if cache_key in self._symbol_cache:
            return self._symbol_cache[cache_key]

        guid_str = str(guid).upper().replace('-', '') if guid else ''
        age_str = str(int(age)) if age is not None else '0'
        combined = guid_str + age_str

        # Try local symbol cache FIRST (user has PDBs locally; FiveM builds are often compatible)
        if self._local_symbol_path:
            found = self._try_local_cache(pdb_name, guid_str, combined, cache_key)
            if found:
                return found

        # Try symbol server (only if requests available)
        if HAS_REQUESTS and guid:
            path = f"{pdb_name}/{combined}/{pdb_name}"
            url = urllib.parse.urljoin(self.server, path)
            try:
                r = requests.get(url, stream=True, timeout=Symbolicator.SYMBOL_DOWNLOAD_TIMEOUT)
                # #region agent log
                _dlog("H3", "core.Symbolicator.download_symbol_by_pdb", "pdb download primary", {
                    "url": url[:120],
                    "status_code": r.status_code,
                    "pdb_name": pdb_name,
                })
                # #endregion
                if r.status_code == 200:
                    fd, tmp = tempfile.mkstemp(suffix='_' + pdb_name)
                    with os.fdopen(fd, 'wb') as f:
                        for chunk in r.iter_content(8192):
                            f.write(chunk)
                    self._symbol_cache[cache_key] = tmp
                    return tmp
            except Exception as e:
                # #region agent log
                _dlog("H3", "core.Symbolicator.download_symbol_by_pdb", "pdb download primary exception", {"error": str(e)[:80], "pdb_name": pdb_name})
                # #endregion
                pass

            # Try fallback path
            try:
                url2 = urllib.parse.urljoin(self.server, f"{pdb_name}/{guid_str}/{pdb_name}")
                r2 = requests.get(url2, stream=True, timeout=Symbolicator.SYMBOL_DOWNLOAD_TIMEOUT)
                # #region agent log
                _dlog("H3", "core.Symbolicator.download_symbol_by_pdb_fallback", "pdb download fallback", {"url": url2[:120], "status_code": r2.status_code})
                # #endregion
                if r2.status_code == 200:
                    fd, tmp2 = tempfile.mkstemp(suffix='_' + pdb_name)
                    with os.fdopen(fd, 'wb') as f:
                        for chunk in r2.iter_content(8192):
                            f.write(chunk)
                    self._symbol_cache[cache_key] = tmp2
                    return tmp2
            except Exception:
                pass

        # #region agent log
        if self._local_symbol_path and pdb_name:
            _dlog("local_cache", "core.Symbolicator.download_symbol_by_pdb.local", "local cache not found", {
                "local_path": self._local_symbol_path,
                "pdb_name": pdb_name,
                "combined": combined,
            })
        elif not self._local_symbol_path:
            _dlog("local_cache", "core.Symbolicator.download_symbol_by_pdb.no_local", "no local path set", {"pdb_name": pdb_name})
        # #endregion

        return None

    def load_module(self, base_addr: int, module_path: str,
                   module_name: Optional[str] = None, module_size: int = 0) -> int:
        """Load a module for symbol resolution."""
        if not self._initialized or not self.dbghelp:
            return 0
        try:
            ImageName = ctypes.c_wchar_p(module_path)
            ModuleName = ctypes.c_wchar_p(module_name or os.path.basename(module_path))
            self.dbghelp.SymLoadModuleExW.restype = ctypes.c_ulonglong
            loaded = self.dbghelp.SymLoadModuleExW(
                self.process, 0, ImageName, ModuleName,
                ctypes.c_ulonglong(base_addr or 0),
                ctypes.c_ulong(module_size or 0), 0, 0
            )
            return int(loaded)
        except Exception:
            return 0

    def symbolicate_address(self, address: int) -> Tuple[Optional[str], Optional[int]]:
        """Resolve an address to a symbol name."""
        if not self._initialized or not self.dbghelp:
            return (None, None)

        class SYMBOL_INFO(ctypes.Structure):
            _fields_ = [
                ("SizeOfStruct", ctypes.c_uint32),
                ("TypeIndex", ctypes.c_uint32),
                ("Reserved", ctypes.c_uint64 * 2),
                ("Index", ctypes.c_uint32),
                ("Size", ctypes.c_uint32),
                ("ModBase", ctypes.c_uint64),
                ("Flags", ctypes.c_uint32),
                ("Value", ctypes.c_uint64),
                ("Address", ctypes.c_uint64),
                ("Register", ctypes.c_uint32),
                ("Scope", ctypes.c_uint32),
                ("Tag", ctypes.c_uint32),
                ("NameLen", ctypes.c_uint32),
                ("MaxNameLen", ctypes.c_uint32),
                ("Name", ctypes.c_char * 1024)
            ]

        sym = SYMBOL_INFO()
        sym.SizeOfStruct = ctypes.sizeof(SYMBOL_INFO)
        sym.MaxNameLen = 1024
        displacement = ctypes.c_ulonglong(0)

        try:
            addr = ctypes.c_ulonglong(address)
            res = self.dbghelp.SymFromAddrW(
                self.process, addr, ctypes.byref(displacement), ctypes.byref(sym)
            )
            if res:
                name = bytes(sym.Name).split(b"\x00", 1)[0].decode(errors='replace')
                return (name, int(displacement.value))
        except Exception:
            pass
        return (None, None)


class CrashAnalyzer:
    """FiveM Crash Analyzer with deep memory analysis capabilities."""

    # Comprehensive crash patterns for FiveM
    CRASH_PATTERNS: Dict[str, Dict[str, Any]] = {
        # Memory issues
        r'out\s*of\s*memory|memory\s*allocation\s*fail': {
            'issue': 'Out of Memory',
            'explanation': 'The game ran out of available RAM. This often occurs with resource-heavy scripts or excessive streaming assets.',
            'solutions': [
                'Reduce the number of active resources',
                'Optimize scripts to reduce memory usage',
                'Increase system RAM or reduce other applications',
                'Check for memory leaks in scripts (e.g., tables not being cleared)'
            ]
        },
        r'entity\s*pool\s*exhaust': {
            'issue': 'Entity Pool Exhaustion',
            'explanation': 'The server/client ran out of available entity slots. FiveM has limits on concurrent entities.',
            'solutions': [
                'Reduce the number of spawned entities (vehicles, peds, objects)',
                'Implement entity cleanup in your scripts',
                'Use OneSync Infinity for higher entity limits',
                'Check for scripts that spawn entities without cleanup'
            ]
        },
        r'heap\s*corrupt|exception\s*code\s*0xc0000374': {
            'issue': 'Heap Corruption',
            'explanation': 'Memory heap corruption detected. This is often caused by buggy native calls or memory overwrites.',
            'solutions': [
                'Check for invalid native call parameters',
                'Update to the latest FiveM build',
                'Disable recently added scripts to isolate the issue',
                'Check for buffer overflows in native calls'
            ]
        },
        r'access\s*violation|exception\s*code\s*0xc0000005': {
            'issue': 'Access Violation',
            'explanation': 'Invalid memory access occurred. A script or native call tried to access protected memory.',
            'solutions': [
                'Check for null/invalid entity handles in scripts',
                'Validate all native call parameters',
                'Check for use-after-delete scenarios',
                'Look for invalid pointer dereferences'
            ]
        },
        r'stack\s*overflow|exception\s*code\s*0xc00000fd': {
            'issue': 'Stack Overflow',
            'explanation': 'Call stack overflow, usually caused by infinite recursion in scripts.',
            'solutions': [
                'Check for recursive function calls without proper exit conditions',
                'Look for circular event triggers',
                'Reduce deeply nested function calls',
                'Check for infinite loops with function calls'
            ]
        },

        # Script errors
        r'lua\s*error|script\s*error|citizen\s*error': {
            'issue': 'Script Error',
            'explanation': 'A Lua script crashed or threw an unhandled error.',
            'solutions': [
                'Check the server/client console for the full error message',
                'Add proper error handling (pcall/xpcall) to your scripts',
                'Validate all inputs before using them',
                'Check the CitizenFX.log for stack traces'
            ]
        },
        r'attempt\s*to\s*(?:call|index|perform|compare|concatenate)': {
            'issue': 'Lua Runtime Error',
            'explanation': 'A Lua operation was attempted on an invalid value (nil, wrong type, etc.).',
            'solutions': [
                'Check for nil values before operations',
                'Validate function parameters',
                'Use type checking before operations',
                'Add nil guards: value and value.property'
            ]
        },

        # Streaming issues
        r'streaming\s*fail|failed\s*to\s*stream|streaming\s*memory': {
            'issue': 'Streaming Failure',
            'explanation': 'Failed to load game assets into memory. This can be caused by corrupted assets or memory limits.',
            'solutions': [
                'Verify integrity of streaming assets (.ytyp, .ymap, etc.)',
                'Reduce the number of streaming assets',
                'Check for malformed or oversized assets',
                'Ensure assets are properly formatted'
            ]
        },

        # Network issues
        r'network\s*timeout|connection\s*lost|sync\s*fail': {
            'issue': 'Network/Sync Issue',
            'explanation': 'Connection or synchronization failed. Can be caused by network issues or server overload.',
            'solutions': [
                'Check network connectivity',
                'Verify server is not overloaded',
                'Reduce network-heavy operations',
                'Check for excessive TriggerServerEvent/TriggerClientEvent calls'
            ]
        },

        # Graphics issues
        r'gpu\s*crash|d3d.*error|directx|nvwgf2umx|atikmdag|dxgi': {
            'issue': 'Graphics Driver Crash',
            'explanation': 'The graphics driver crashed. This can be caused by driver issues or GPU overload.',
            'solutions': [
                'Update graphics drivers',
                'Reduce graphics settings',
                'Check for overheating GPU',
                'Disable GPU-intensive mods/shaders'
            ]
        },

        # Game data issues
        r'vehicle\s*spawn|cvehicle|handling\.meta|vehicles\.meta': {
            'issue': 'Vehicle-Related Crash',
            'explanation': 'Crash related to vehicle data or spawning.',
            'solutions': [
                'Verify vehicle addon files are correct',
                'Check handling.meta and vehicles.meta syntax',
                'Ensure vehicle models exist before spawning',
                'Validate vehicle spawn coordinates'
            ]
        },
        r'audio\s*error|sound\s*fail|rage\s*audio': {
            'issue': 'Audio System Crash',
            'explanation': 'The audio system encountered an error.',
            'solutions': [
                'Verify audio file formats (should be .wav or .ogg)',
                'Check for missing audio files',
                'Reduce concurrent audio streams',
                'Verify audio bank references'
            ]
        },
        r'weapon\s*crash|cweapon|weaponcomponents': {
            'issue': 'Weapon-Related Crash',
            'explanation': 'Crash related to weapon data or components.',
            'solutions': [
                'Verify weapon addon files',
                'Check weapon components.meta',
                'Ensure weapon models exist',
                'Validate weapon attachments'
            ]
        },
        r'ped\s*pool|population|ambient\s*peds|cpedmodel': {
            'issue': 'Ped/Population Crash',
            'explanation': 'Crash related to pedestrian spawning or population systems.',
            'solutions': [
                'Reduce ambient ped density',
                'Check for ped model streaming issues',
                'Verify ped spawn scripts',
                'Implement ped cleanup routines'
            ]
        },

        # FiveM-specific
        r'citizen.*unhandled|cfx.*exception': {
            'issue': 'CitizenFX Unhandled Exception',
            'explanation': 'An unhandled exception occurred in the CitizenFX framework.',
            'solutions': [
                'Check the crash dump for specific error details',
                'Report the issue on the FiveM forums with the dump',
                'Try updating to the latest FiveM version',
                'Disable custom scripts to isolate the issue'
            ]
        },
        r'mono\s*exception|clr\s*error|\.net\s*error': {
            'issue': 'C#/.NET Script Error',
            'explanation': 'An error occurred in a C# script.',
            'solutions': [
                'Check the exception message in logs',
                'Verify C# script compilation',
                'Check for null reference exceptions',
                'Ensure proper async/await usage'
            ]
        },
    }

    # Known modules and their descriptions
    KNOWN_MODULES: Dict[str, str] = {
        'nvwgf2umx.dll': 'NVIDIA Graphics Driver',
        'nvlddmkm.sys': 'NVIDIA Kernel Mode Driver',
        'atikmdag.sys': 'AMD Graphics Driver',
        'amdkmdap': 'AMD Kernel Mode Driver',
        'ntdll.dll': 'Windows NT Layer',
        'kernelbase.dll': 'Windows Kernel Base',
        'kernel32.dll': 'Windows Kernel',
        'd3d11.dll': 'DirectX 11',
        'd3d10.dll': 'DirectX 10',
        'dxgi.dll': 'DirectX Graphics Infrastructure',
        'citizen': 'FiveM/CitizenFX Core',
        'rage': 'RAGE Game Engine',
        'gta5.exe': 'GTA V Executable',
        'fivem': 'FiveM Client',
        'cfx': 'CitizenFX Framework',
        'v8.dll': 'V8 JavaScript Engine',
        'lua51.dll': 'Lua 5.1 Runtime',
        'steam_api64.dll': 'Steam API',
        'dinput8.dll': 'DirectInput (often ScriptHook)',
    }

    # Pre-compiled regex patterns for log analysis and string extraction
    _LUA_ERROR_PATTERN = re.compile(
        r'([A-Za-z0-9_\-/\\]+\.lua):(\d+):\s*(.+)',
        re.IGNORECASE
    )
    _RESOURCE_PATTERN = re.compile(
        # Match common FiveM lifecycle lines, while avoiding false positives from unrelated
        # "Started <something>" phrases.
        # - Started resource myresource
        # - Started 'myresource'
        r'(?:Starting|Started|Stopping|Stopped|Loading|Loaded|Ensuring|Ensured)\s+'
        r'(?:resource\s+([A-Za-z0-9_\-]{2,64})|[\'"]([A-Za-z0-9_\-]{2,64})[\'"])',
        re.IGNORECASE
    )
    _CITIZEN_ERROR_PATTERN = re.compile(
        r'(?:SCRIPT\s*ERROR|Error\s*running|error\s*in).*?(?:@?([A-Za-z0-9_\-]+))?',
        re.IGNORECASE
    )
    _CAMEL_CASE_PATTERN = re.compile(r'[A-Z][a-z]+(?:[A-Z][a-z]+)+')
    # Extract resource name from log error content for log-based boost
    _LOG_ERROR_RESOURCE_PATTERN = re.compile(
        r'(?:resources[/\\]([A-Za-z0-9_\-]{2,64})(?:[/\\]|$)|'
        # Only treat @<name>/... as a resource if it looks like a code path reference.
        # This avoids noise from other @-prefixed strings in logs.
        r'@([A-Za-z0-9_\-]{2,64})[/\\][^\s\r\n]{1,260}\.(?:lua|js|ts|cs)|'
        # "Error running ... for resource <name>" or "error in resource <name>"
        r'(?:\bfor\b|\bin\b)\s+resource\s+[\'\"]?([A-Za-z0-9_\-]{2,64})[\'\"]?)',
        re.IGNORECASE
    )

    _RESOURCE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{1,63}$")
    _LOG_RESOURCE_STOPWORDS: Set[str] = {
        # Common error-message words accidentally captured as "resources"
        "no",
        "bad",
        "string",
        "number",
        "nil",
        "table",
        "function",
        "userdata",
        "boolean",
        "true",
        "false",
        "error",
        "script",
        "resource",
        "resources",
        "loaded",
        "loading",
        "initialization",
        "environments",
        "api",
        "id",
        "attempt",
        "expected",
        "got",
    }

    def __init__(self, progress_callback=None):
        """Initialize the crash analyzer.
        
        Args:
            progress_callback: Optional callable(stage: str, progress: float, message: str)
                             for receiving progress updates during analysis.
        """
        self._has_minidump = HAS_MINIDUMP
        self._progress_callback = progress_callback
        self.memory_analyzer = MemoryAnalyzer(progress_callback=progress_callback)

        # Initialize symbolicator (Windows only)
        try:
            self.symbolicator = Symbolicator()
        except Exception:
            self.symbolicator = None

        # Pre-compile crash patterns
        self._compiled_crash_patterns = []
        for pattern, details in self.CRASH_PATTERNS.items():
            try:
                compiled = re.compile(pattern, re.IGNORECASE)
                self._compiled_crash_patterns.append((compiled, details))
            except re.error:
                continue

    def _is_plausible_resource_name(self, name: Optional[str]) -> bool:
        """Heuristic validation for resource names extracted from logs.

        Goal: avoid promoting generic error-message words (e.g. "string", "bad") as resources.
        """
        if not name:
            return False
        s = str(name).strip().strip('"').strip("'")
        if not s:
            return False
        sl = s.lower()
        if len(sl) < 2 or len(sl) > 64:
            return False
        # Must contain at least one letter; reject pure numbers like "16" or "254".
        if not any(c.isalpha() for c in sl):
            return False
        if sl in self._LOG_RESOURCE_STOPWORDS:
            return False
        if "." in sl or "/" in sl or "\\" in sl or ":" in sl:
            return False
        # Internal/runtime markers (not user resources)
        if sl.startswith(("citizen-scripting-", "citizen-resources-", "cfx-fivem-", "cfx-fxserver-")):
            return False
        return bool(self._RESOURCE_NAME_RE.fullmatch(s))
    
    def set_progress_callback(self, callback) -> None:
        """Set or update the progress callback.
        
        Args:
            callback: callable(stage: str, progress: float, message: str) or None
        """
        self._progress_callback = callback
        self.memory_analyzer._progress_callback = callback

    def set_abort_check(self, abort_check) -> None:
        """Set a callable that returns True when analysis should stop (e.g. user cancel).
        
        Args:
            abort_check: callable() -> bool, or None to disable
        """
        self.memory_analyzer._abort_check = abort_check

    def _extract_strings(self, data: bytes, min_length: int = 4) -> List[str]:
        """Extract printable ASCII strings from binary data."""
        results: List[str] = []
        current_chars: List[str] = []

        for b in data:
            if 32 <= b <= 126:
                current_chars.append(chr(b))
            else:
                if len(current_chars) >= min_length:
                    results.append(''.join(current_chars))
                current_chars = []

        if len(current_chars) >= min_length:
            results.append(''.join(current_chars))

        # Post-process to extract useful tokens
        seen: Set[str] = set()
        final: List[str] = []

        pattern_generic = re.compile(r'[A-Za-z0-9_]{%d,}' % min_length)

        def _trim_repeated(s: str) -> str:
            if not s or len(s) < 4:
                return s
            # Leading repeated chars
            i = 1
            while i < len(s) and s[i] == s[0]:
                i += 1
            if i >= 3:
                s = s[i:]
            if not s:
                return s
            # Trailing repeated chars
            j = len(s) - 2
            while j >= 0 and s[j] == s[-1]:
                j -= 1
            tail_run = len(s) - (j + 1)
            if tail_run >= 3:
                s = s[:j+1]
            return s

        for s in results:
            # CamelCase tokens
            for m in self._CAMEL_CASE_PATTERN.finditer(s):
                token = _trim_repeated(m.group(0))
                if token and token not in seen:
                    seen.add(token)
                    final.append(token)
            # Generic alphanumeric tokens
            for m in pattern_generic.finditer(s):
                token = _trim_repeated(m.group(0))
                if token and token not in seen:
                    seen.add(token)
                    final.append(token)

        return final[:500]  # Limit to prevent memory issues

    def match_patterns(self, all_text: str) -> List[PatternMatch]:
        """Match crash patterns against text."""
        if not all_text:
            return []

        found: List[PatternMatch] = []

        for compiled, details in self._compiled_crash_patterns:
            if compiled.search(all_text):
                found.append(PatternMatch(
                    issue=details['issue'],
                    explanation=details['explanation'],
                    solutions=details.get('solutions', [])
                ))

        return found

    def identify_modules(self, modules: List[str]) -> List[Dict[str, str]]:
        """Identify known modules from a list of module names."""
        identified: List[Dict[str, str]] = []

        for module in modules:
            module_lower = module.lower()
            for known, desc in self.KNOWN_MODULES.items():
                if known in module_lower:
                    identified.append({'module': module, 'description': desc})
                    break

        return identified

    # Regex to parse native stack frame: "ModuleName.exe + 0xOFFSET"
    _NATIVE_FRAME_RE = re.compile(r'^(.+?)\s*\+\s*0x([0-9A-Fa-f]+)$', re.IGNORECASE)

    def _derive_pdb_names_from_module(self, mod_name: str) -> List[str]:
        """Derive possible PDB names when dump has no CvRecord. FiveM-specific mappings."""
        base = os.path.basename(mod_name)
        names: List[str] = []
        if not base:
            return names
        # Direct: module.dll -> module.pdb
        if "." in base:
            stem = base.rsplit(".", 1)[0]
            names.append(stem + ".pdb")
        else:
            names.append(base + ".pdb")
        # FiveM main process exe -> CitizenGame.pdb, CitizenFX_SubProcess_game_3570_aslr.pdb
        if "FiveM" in base and "GTAProcess" in base:
            names.extend(["CitizenGame.pdb", "CitizenFX_SubProcess_game_3570_aslr.pdb"])
        # citizen-* -> citizen-*.pdb (already added above)
        return names

    def _symbolicate_native_stack(self, report: 'Report') -> None:
        """Resolve native stack frames to function names using PDBs when available.

        Populates report.native_stacks_symbolicated. Each entry is either
        '  module + 0xOFFSET  ->  function_name + 0xdisp' or the raw frame if resolution fails.
        """
        report.native_stacks_symbolicated = []
        report.symbolication_had_local_path = bool(
            getattr(self.symbolicator, '_local_symbol_path', None)
        )
        # #region agent log
        _dlog("H1", "core._symbolicate_native_stack.entry", "symbolicate entry", {
            "native_stacks_len": len(report.native_stacks) if report.native_stacks else 0,
            "module_versions_len": len(report.module_versions) if report.module_versions else 0,
            "symbolicator_is_none": self.symbolicator is None,
        })
        # #endregion
        if not report.native_stacks or not self.symbolicator or not report.module_versions:
            # #region agent log
            _dlog("H1", "core._symbolicate_native_stack.early_return", "early return", {
                "reason": "no_stacks" if not report.native_stacks else "no_symbolicator" if not self.symbolicator else "no_module_versions",
            })
            # #endregion
            return

        # Build module name -> (base_address, size, pdb_name, pdb_guid, pdb_age)
        # Use both full name and basename so "FiveM_b3570_GTAProcess.exe" matches even when
        # module_versions has a full path (e.g. C:\...\FiveM_b3570_GTAProcess.exe).
        mod_map: Dict[str, Tuple[int, int, str, str, int]] = {}
        for m in report.module_versions:
            name = (m.name or '').strip()
            if name:
                entry = (
                    getattr(m, 'base_address', 0) or 0,
                    getattr(m, 'size', 0) or 0,
                    getattr(m, 'pdb_name', '') or '',
                    getattr(m, 'pdb_guid', '') or '',
                    getattr(m, 'pdb_age', 0) or 0,
                )
                mod_map[name] = entry
                basename = os.path.basename(name)
                if basename and basename != name:
                    mod_map[basename] = entry

        # #region agent log
        _dlog("H2", "core._symbolicate_native_stack.mod_map", "mod_map built", {
            "mod_map_len": len(mod_map),
            "sample_keys": list(mod_map.keys())[:5],
        })
        # #endregion

        # Parse frames and collect unique modules
        parsed: List[Tuple[str, int, int]] = []  # (module_name, base, offset)
        for raw in report.native_stacks:
            m = self._NATIVE_FRAME_RE.match((raw or '').strip())
            if m:
                mod_name = m.group(1).strip()
                try:
                    offset = int(m.group(2), 16)
                except ValueError:
                    report.native_stacks_symbolicated.append(raw)
                    continue
                info = mod_map.get(mod_name) or (mod_map.get(os.path.basename(mod_name)) if os.path.basename(mod_name) != mod_name else None)
                if info:
                    base, size, pdb_name, pdb_guid, pdb_age = info
                    parsed.append((mod_name, base, offset))
                else:
                    parsed.append((mod_name, 0, offset))
            else:
                parsed.append(('', 0, 0))

        # #region agent log
        first_parsed = parsed[0] if parsed else None
        first_mod_in_map = first_parsed and mod_map.get(first_parsed[0]) is not None if first_parsed else False
        _dlog("H2", "core._symbolicate_native_stack.parsed", "first frame parsed", {
            "first_parsed": first_parsed,
            "first_mod_in_map": first_mod_in_map,
            "parsed_with_base_count": sum(1 for p in parsed if len(p) >= 2 and p[1] != 0),
        })
        # #endregion

        # Load PDBs for each unique module that appears in the stack
        loaded_bases: Set[int] = set()
        seen_bases: Set[int] = set()
        failed_lookups: List[Tuple[str, str, str, int]] = []  # (mod_name, pdb_name, guid, age)
        for mod_name, base, _ in parsed:
            if not mod_name or base == 0 or base in seen_bases:
                continue
            seen_bases.add(base)
            first_module = len(seen_bases) == 1  # Define at start of iteration
            info = mod_map.get(mod_name) or (mod_map.get(os.path.basename(mod_name)) if os.path.basename(mod_name) != mod_name else None)
            if not info:
                continue
            _, size, pdb_name, pdb_guid, pdb_age = info
            pdb_path = None
            if pdb_name and pdb_guid:
                pdb_path = self.symbolicator.download_symbol_by_pdb(pdb_name, pdb_guid, pdb_age)
            # Fallback: dump may point to internal PDB (e.g. CitizenFX_SubProcess_game_3570_aslr.pdb) which
            # returns 404; try same GUID/age with module exe name (e.g. FiveM_b3570_GTAProcess.pdb).
            if not pdb_path and pdb_guid and pdb_age is not None:
                module_pdb = mod_name if mod_name.lower().endswith(".pdb") else (mod_name.rsplit(".", 1)[0] + ".pdb" if "." in mod_name else mod_name + ".pdb")
                if module_pdb != pdb_name:
                    pdb_path = self.symbolicator.download_symbol_by_pdb(module_pdb, pdb_guid, pdb_age)
                    # #region agent log
                    if len(seen_bases) <= 1:
                        _dlog("H3", "core._symbolicate_native_stack.fallback_pdb", "tried module-named PDB", {"module_pdb": module_pdb, "pdb_path_got": pdb_path is not None})
                    # #endregion
            # Fallback: dump has no PDB info (CvRecord empty) - derive PDB name from module and try local cache.
            # FiveM modules often lack PDB info in minidumps; local cache lookup by name usually works.
            if not pdb_path and self.symbolicator._local_symbol_path:
                derived_names = self._derive_pdb_names_from_module(mod_name)
                # #region agent log
                if first_module:
                    _dlog("H5", "core._symbolicate_native_stack.derive_fallback", "trying derived PDB names", {
                        "mod_name": mod_name,
                        "derived_names": derived_names,
                        "pdb_name_was_empty": not pdb_name,
                        "pdb_guid_was_empty": not pdb_guid,
                    })
                # #endregion
                for try_pdb in derived_names:
                    pdb_path = self.symbolicator.download_symbol_by_pdb(try_pdb, "", 0)
                    if pdb_path:
                        # #region agent log
                        _dlog("H5", "core._symbolicate_native_stack.derived_success", "found via derived name", {"try_pdb": try_pdb, "pdb_path": pdb_path})
                        # #endregion
                        break
            if not pdb_path:
                pdb_path = self.symbolicator.download_symbol(mod_name)
            if pdb_path:
                load_ret = self.symbolicator.load_module(base, pdb_path, mod_name, size)
                # #region agent log
                if first_module:
                    _dlog("H3,H4,H5", "core._symbolicate_native_stack.load_attempt", "first module load", {
                        "mod_name": mod_name,
                        "base": base,
                        "pdb_name": pdb_name or "",
                        "pdb_guid_len": len(pdb_guid) if pdb_guid else 0,
                        "pdb_path_got": True,
                        "load_module_return": load_ret,
                    })
                # #endregion
                loaded_bases.add(base)
            else:
                if pdb_name and pdb_guid and len(failed_lookups) < 5:
                    failed_lookups.append((mod_name, pdb_name, pdb_guid, pdb_age or 0))
            if not pdb_path and first_module:
                # #region agent log
                _dlog("H3", "core._symbolicate_native_stack.download_failed", "first module no pdb path", {
                    "mod_name": mod_name,
                    "base": base,
                    "pdb_name": pdb_name or "",
                    "pdb_guid_len": len(pdb_guid) if pdb_guid else 0,
                })
                # #endregion

        # #region agent log
        _dlog("H4,H5", "core._symbolicate_native_stack.after_load", "after load loop", {"loaded_bases_count": len(loaded_bases)})
        # #endregion

        # Build diagnostic when no symbols loaded (helps user troubleshoot GUID mismatch, wrong build, etc.)
        if not loaded_bases and failed_lookups and getattr(self.symbolicator, "_local_symbol_path", None):
            cache_path = self.symbolicator._local_symbol_path
            lines = [
                "Symbolication diagnostic (PDBs not found in cache):",
                f"  Cache path: {cache_path}",
                "  First modules we looked for:",
            ]
            for mod_name, pdb_name, guid, age in failed_lookups[:3]:
                guid_clean = str(guid).upper().replace("-", "")
                combined = f"{guid_clean}{age}"
                path1 = os.path.join(cache_path, pdb_name, combined, pdb_name)
                path2 = os.path.join(cache_path, pdb_name, guid_clean, pdb_name)
                lines.append(f"    - {mod_name} (PDB: {pdb_name}, GUID: {guid_clean}, age: {age})")
                lines.append(f"      Checked: {path1}")
                lines.append(f"      Checked: {path2}")
            lines.append("  Your crash may be from a different FiveM build than your PDBs. Each build has unique GUIDs.")
            lines.append("  Ensure PDBs in your cache match the exact build that produced this dump.")
            report.symbolication_diagnostic = "\n".join(lines)

        # Symbolicate each frame
        for i, raw in enumerate(report.native_stacks):
            if i >= len(parsed):
                report.native_stacks_symbolicated.append(raw)
                continue
            mod_name, base, offset = parsed[i]
            full_addr = base + offset if base else 0
            if full_addr and loaded_bases:
                sym_name, disp = self.symbolicator.symbolicate_address(full_addr)
                if sym_name:
                    report.native_stacks_symbolicated.append(
                        f"  {raw}  ->  {sym_name} + 0x{disp:X}"
                    )
                    continue
            report.native_stacks_symbolicated.append(raw)

    def analyze_log(self, log_path: str) -> Dict[str, Any]:
        """Analyze a log file for errors and resource information."""
        info: Dict[str, Any] = {
            'file': os.path.basename(log_path),
            'errors': [],
            'warnings': [],
            'resources': [],
            'crash_indicators': [],
            'script_errors': [],
            'lua_errors': [],
        }

        content = None
        used_encoding: Optional[str] = None
        for encoding in ['utf-8', 'utf-16', 'latin-1', 'cp1252']:
            try:
                with open(log_path, 'r', encoding=encoding) as f:
                    content = f.read()
                used_encoding = encoding
                break
            except Exception:
                continue

        if content is None:
            info['error'] = 'Could not read log file'
            return info

        lines = content.splitlines()

        for i, line in enumerate(lines):
            l = line.strip()
            lower = l.lower()

            # Detect errors
            if 'error' in lower or 'exception' in lower or 'crash' in lower:
                info['errors'].append({'line': i + 1, 'content': l[:300]})

                # Check for Lua errors
                lua_match = self._LUA_ERROR_PATTERN.search(l)
                if lua_match:
                    info['lua_errors'].append({
                        'file': lua_match.group(1),
                        'line': int(lua_match.group(2)),
                        'message': lua_match.group(3)[:200],
                        'log_line': i + 1
                    })

                # Check for Citizen/FiveM errors
                citizen_match = self._CITIZEN_ERROR_PATTERN.search(l)
                if citizen_match:
                    resource = citizen_match.group(1)
                    info['script_errors'].append({
                        'resource': resource,
                        'message': l[:200],
                        'log_line': i + 1
                    })

            # Detect warnings
            if 'warning' in lower or 'warn' in lower:
                info['warnings'].append({'line': i + 1, 'content': l[:200]})

            # Detect resources
            resource_match = self._RESOURCE_PATTERN.search(l)
            if resource_match:
                res = resource_match.group(1) or resource_match.group(2)
                if self._is_plausible_resource_name(res) and res not in info['resources']:
                    info['resources'].append(res)

            # Also extract resources from common error/path formats (e.g. "@res/path.lua")
            for m in self._LOG_ERROR_RESOURCE_PATTERN.finditer(l):
                for g in (m.group(1), m.group(2), m.group(3)):
                    if self._is_plausible_resource_name(g) and g not in info['resources']:
                        info['resources'].append(g)

            # Detect stack traces
            if 'stack trace' in lower or 'call stack' in lower or 'traceback' in lower:
                context = '\n'.join(lines[i:i+10])
                info['crash_indicators'].append({
                    'line': i + 1,
                    'context': context
                })

        # #region agent log
        _dlog2(
            "H7",
            "core.CrashAnalyzer.analyze_log",
            "log summary",
            {
                "file": os.path.basename(log_path),
                "encoding": used_encoding,
                "lines": len(lines),
                "errors": len(info.get("errors", [])),
                "warnings": len(info.get("warnings", [])),
                "resources": len(info.get("resources", [])),
                "lua_errors": len(info.get("lua_errors", [])),
                "script_errors": len(info.get("script_errors", [])),
                "resources_sample": list(info.get("resources", [])[:20]),
                "lua_error_files_sample": [e.get("file") for e in info.get("lua_errors", [])[:3]],
                "script_error_resources_sample": [
                    e.get("resource") for e in info.get("script_errors", [])[:5] if e.get("resource")
                ],
            },
        )
        # #endregion

        return info

    def analyze_dump(self, dump_path: str) -> Dict[str, Any]:
        """Basic dump analysis with string extraction."""
        info: Dict[str, Any] = {
            'file': os.path.basename(dump_path),
            'size': os.path.getsize(dump_path),
            'exception': None,
            'modules': [],
            'threads': 0,
            'raw_data': []
        }

        try:
            with open(dump_path, 'rb') as f:
                # Verify minidump header
                magic = f.read(4)
                if magic != b'MDMP':
                    info['error'] = 'Not a valid minidump file'
                    return info

                f.seek(0)
                raw = f.read()

            strings = self._extract_strings(raw, min_length=6)
            info['raw_data'] = strings

            for s in strings:
                lower = s.lower()
                if '.dll' in lower or '.exe' in lower:
                    info['modules'].append(s)

        except Exception as e:
            info['error'] = str(e)

        return info

    def analyze_dump_deep(self, dump_path: str) -> DeepAnalysisResult:
        """Perform deep memory analysis to pinpoint error sources.

        This is the primary method for identifying exactly which script
        or resource caused a crash.
        """
        return self.memory_analyzer.analyze_dump_deep(dump_path)

    def full_analysis(self, dump_path: Optional[str] = None,
                     log_paths: Optional[List[str]] = None) -> CrashReport:
        """Perform comprehensive crash analysis.

        Args:
            dump_path: Path to the minidump file (.dmp)
            log_paths: List of log file paths to analyze

        Returns:
            CrashReport with all analysis results
        """
        report = CrashReport()

        # Analyze dump file
        if dump_path and os.path.exists(dump_path):
            report.dump_file = dump_path

            # Deep memory analysis
            deep_result = self.analyze_dump_deep(dump_path)

            report.exception_code = deep_result.exception_code
            report.exception_address = deep_result.exception_address
            report.exception_module = deep_result.exception_module
            report.primary_suspects = deep_result.primary_suspects
            report.resources = getattr(deep_result, 'resources', {}) or {}
            report.primary_suspect_secondary = getattr(deep_result, 'primary_suspect_secondary', None)
            report.primary_suspect_confidence = getattr(deep_result, 'primary_suspect_confidence', 'medium')
            report.script_errors = deep_result.script_errors
            report.lua_stacks = deep_result.lua_stacks
            report.lua_stack_resources = getattr(deep_result, 'lua_stack_resources', [])
            report.js_stacks = deep_result.js_stacks
            report.js_stack_resources = getattr(deep_result, 'js_stack_resources', [])
            report.native_stacks = deep_result.native_stack
            report.all_evidence = deep_result.all_evidence
            report.analysis_errors.extend(deep_result.errors)

            # Standard Minidump Data
            report.system_info = deep_result.system_info
            report.misc_info = deep_result.misc_info
            report.crash_time = deep_result.crash_time
            report.exception_context = deep_result.exception_context
            report.unloaded_modules = deep_result.unloaded_modules

            # NEW: Extended minidump data
            report.exception_params = deep_result.exception_params
            report.handles = deep_result.handles
            report.threads_extended = deep_result.threads_extended
            report.module_versions = deep_result.module_versions
            # Symbolicate native stack when PDBs available (Windows)
            self._symbolicate_native_stack(report)
            report.memory_info = deep_result.memory_info
            report.process_stats = deep_result.process_stats
            report.function_table_entries = deep_result.function_table_entries
            report.comment_stream_a = deep_result.comment_stream_a
            report.comment_stream_w = deep_result.comment_stream_w
            report.assertion_info = deep_result.assertion_info
            report.javascript_data = deep_result.javascript_data
            report.process_vm_counters = deep_result.process_vm_counters

            # ===== MEMORY LEAK ANALYSIS DATA =====
            report.entity_creations = deep_result.entity_creations
            report.entity_deletions = deep_result.entity_deletions
            report.timers_created = deep_result.timers_created
            report.event_handlers_registered = deep_result.event_handlers_registered
            report.event_handlers_removed = deep_result.event_handlers_removed
            report.memory_allocations = deep_result.memory_allocations
            report.memory_frees = deep_result.memory_frees
            report.memory_leak_indicators = deep_result.memory_leak_indicators
            report.pool_exhaustion_indicators = deep_result.pool_exhaustion_indicators
            report.database_patterns = deep_result.database_patterns
            report.nui_patterns = deep_result.nui_patterns
            report.network_patterns = deep_result.network_patterns
            report.statebag_patterns = deep_result.statebag_patterns

            # Use raw_strings and module_names from deep analysis (avoids re-reading dump)
            if deep_result.raw_strings:
                all_strings = ' '.join(deep_result.raw_strings)
                patterns = self.match_patterns(all_strings)
                report.crash_patterns = patterns
            if deep_result.module_names:
                for name in deep_result.module_names:
                    report.modules.append({'name': name})
            # Identify known modules
            module_names = [m['name'] for m in report.modules if 'name' in m]
            report.identified_modules = self.identify_modules(module_names)

        # Analyze log files
        if log_paths:
            for log_path in log_paths:
                if os.path.exists(log_path):
                    report.log_files.append(log_path)
                    log_info = self.analyze_log(log_path)

                    # Collect resources
                    for res in log_info.get('resources', []):
                        if res not in report.log_resources:
                            report.log_resources.append(res)

                    # Collect errors
                    report.log_errors.extend(log_info.get('errors', []))

                    # Check log patterns
                    all_log_text = ' '.join([e.get('content', '') for e in log_info.get('errors', [])])
                    log_patterns = self.match_patterns(all_log_text)
                    for p in log_patterns:
                        if p not in report.crash_patterns:
                            report.crash_patterns.append(p)

        # Use log data to boost or disambiguate suspects
        self._apply_log_resource_boost(report)

        # #region agent log
        _dlog2(
            "H8",
            "core.CrashAnalyzer.full_analysis",
            "post-boost summary",
            {
                "has_dump": bool(report.dump_file),
                "log_files": len(report.log_files),
                "log_resources": len(report.log_resources),
                "log_errors": len(report.log_errors),
                "primary_suspects_count": len(report.primary_suspects),
                "primary_suspects_top5": [s.name for s in report.primary_suspects[:5]],
                "primary_suspect_confidence": getattr(report, "primary_suspect_confidence", None),
            },
        )
        # #endregion

        return report

    def _apply_log_resource_boost(self, report: CrashReport) -> None:
        """Merge log resources into the picture and boost suspects that appear in logs."""
        # Ensure resources that appear only in logs are in report.resources
        for res in report.log_resources:
            res = (res or '').strip()
            if not self._is_plausible_resource_name(res):
                continue
            if res not in report.resources:
                report.resources[res] = ResourceInfo(name=res)

        # Extract resource names mentioned in log error content
        resources_mentioned_in_errors: Set[str] = set()
        error_resource_hits: Dict[str, int] = {}
        for err in report.log_errors:
            content = err.get('content', '') or ''
            for m in self._LOG_ERROR_RESOURCE_PATTERN.finditer(content):
                for g in (m.group(1), m.group(2), m.group(3)):
                    if self._is_plausible_resource_name(g):
                        resources_mentioned_in_errors.add(g)
                        error_resource_hits[g] = error_resource_hits.get(g, 0) + 1

        # Treat resources mentioned in log error content as strong evidence (even if they didn't appear
        # in start/stop lines). This helps minimal dumps where the .dmp lacks Lua/JS stacks.
        for res in sorted(resources_mentioned_in_errors):
            if res not in report.resources:
                report.resources[res] = ResourceInfo(name=res)
            info = report.resources[res]
            # Add minimal evidence signal so these can rank above "presence-only" resources.
            try:
                info.evidence_types.add(EvidenceType.ERROR_MESSAGE)
            except Exception:
                pass
            try:
                info.evidence_count += 2 + min(3, error_resource_hits.get(res, 0))
            except Exception:
                pass
            # Add a small note (no full log line to avoid leaking sensitive details)
            try:
                note = f"[LOG_ERROR] Mentioned in {error_resource_hits.get(res, 0)} error line(s)"
                if note not in info.context_details and len(info.context_details) < 10:
                    info.context_details.append(note)
            except Exception:
                pass

        # Reorder primary_suspects: put resources that appear in logs first
        log_boost_names = set(report.log_resources) | resources_mentioned_in_errors
        if log_boost_names and report.primary_suspects:
            # Prioritize error-mentioned resources above generic log resources.
            error_infos = [report.resources[r] for r in resources_mentioned_in_errors if r in report.resources]
            # Rank error resources by number of hits in error lines first.
            error_infos_sorted = sorted(
                error_infos,
                key=lambda x: (error_resource_hits.get(x.name, 0), getattr(x, "evidence_count", 0), x.name),
                reverse=True,
            )
            error_names = {i.name for i in error_infos_sorted}
            rest = [s for s in report.primary_suspects if s.name not in error_names]
            # Keep log-start/stop resources next, then everything else.
            in_logs = [s for s in rest if s.name in report.log_resources]
            not_in_logs = [s for s in rest if s not in in_logs]
            report.primary_suspects = error_infos_sorted + in_logs + not_in_logs

        # Add log-only resources as additional suspects (up to 5) if not already in list
        primary_names = {s.name for s in report.primary_suspects}
        added = 0
        # Consider both "log resources" and "error-mentioned resources" for addition.
        add_candidates = list(report.log_resources) + sorted(resources_mentioned_in_errors)
        for res in add_candidates:
            if added >= 5:
                break
            if res in report.resources and res not in primary_names:
                report.primary_suspects.append(report.resources[res])
                primary_names.add(res)
                added += 1

        # #region agent log
        _dlog2(
            "H9",
            "core.CrashAnalyzer._apply_log_resource_boost",
            "log boost details",
            {
                "log_resources_count": len(report.log_resources),
                "log_resources_sample": list(report.log_resources[:15]),
                "error_resources_count": len(resources_mentioned_in_errors),
                "error_resources_sample": sorted(list(resources_mentioned_in_errors))[:15],
                "error_resource_hits_sample": dict(list(error_resource_hits.items())[:10]),
                "primary_suspects_top5": [s.name for s in report.primary_suspects[:5]],
            },
        )
        # #endregion

    def generate_report(self, dump_info: Optional[Dict[str, Any]] = None,
                       log_infos: Optional[List[Dict[str, Any]]] = None) -> str:
        """Generate a text report from analysis results (legacy method)."""
        parts: List[str] = []

        if dump_info:
            parts.append(f"Dump: {dump_info.get('file')}\n")

        if log_infos:
            parts.append(f"Logs: {', '.join([li.get('file', '?') for li in log_infos])}\n")

        if dump_info:
            patterns = self.match_patterns(' '.join(dump_info.get('raw_data', [])))
            if patterns:
                parts.append('\nPatterns Detected:\n')
                for p in patterns:
                    parts.append(f"- {p.issue}: {p.explanation}\n")

        return '\n'.join(parts)

    def generate_full_report(self, report: CrashReport) -> str:
        """Generate a comprehensive text report from a CrashReport."""
        lines = []
        lines.append("=" * 70)
        lines.append("FIVEM CRASH ANALYSIS REPORT")
        lines.append("=" * 70)
        lines.append("")

        # Files analyzed
        if report.dump_file:
            lines.append(f"Dump File: {os.path.basename(report.dump_file)}")
        if report.log_files:
            lines.append(f"Log Files: {', '.join(os.path.basename(f) for f in report.log_files)}")

        if report.crash_time:
            # Basic formatting if it's a timestamp integer
            try:
                import datetime
                dt = datetime.datetime.fromtimestamp(report.crash_time)
                lines.append(f"Crash Time: {dt} (Timestamp: {report.crash_time})")
            except:
                lines.append(f"Crash Time: {report.crash_time}")

        lines.append("")

        # System Information
        if report.system_info:
            lines.append("SYSTEM INFORMATION:")
            lines.append("-" * 40)
            for k, v in report.system_info.items():
                lines.append(f"  {k}: {v}")
            lines.append("")

        # Misc Information
        if report.misc_info:
            lines.append("MISC INFORMATION:")
            lines.append("-" * 40)
            for k, v in report.misc_info.items():
                lines.append(f"  {k}: {v}")
            lines.append("")

        # Exception info
        if report.exception_code or report.exception_address:
            lines.append("EXCEPTION DETAILS:")
            lines.append("-" * 40)
            if report.exception_code:
                lines.append(f"  Code: 0x{report.exception_code:08X}")
                # Explain common exception codes
                exc_explanations = {
                    0xC0000005: "Access Violation - Invalid memory access",
                    0xC00000FD: "Stack Overflow - Infinite recursion likely",
                    0xC0000374: "Heap Corruption - Memory corruption",
                    0xC0000409: "Stack Buffer Overrun",
                    0xC000001D: "Illegal Instruction",
                    0x80000003: "Breakpoint - Debug interrupt",
                }
                if report.exception_code in exc_explanations:
                    lines.append(f"         ({exc_explanations[report.exception_code]})")
            if report.exception_address:
                lines.append(f"  Address: 0x{report.exception_address:016X}")
            if report.exception_module:
                lines.append(f"  Module: {report.exception_module}")

            # NEW: Detailed exception parameters
            if report.exception_params:
                ep = report.exception_params
                lines.append("")
                lines.append("  Detailed Exception Parameters:")
                lines.append(f"    Exception Name: {ep.code_name}")
                if ep.num_parameters > 0:
                    lines.append(f"    Number of Parameters: {ep.num_parameters}")

                # For Access Violations, show the details
                if ep.access_type:
                    lines.append(f"    Access Type: {ep.access_type.upper()}")
                if ep.target_address is not None:
                    lines.append(f"    Target Address: 0x{ep.target_address:016X}")
                    if ep.target_address == 0:
                        lines.append("                    (NULL pointer dereference)")
                    elif ep.target_address < 0x10000:
                        lines.append("                    (Low address - likely NULL + offset)")

                # Show other parameters if present
                if ep.parameters and ep.code != 0xC0000005:
                    lines.append(f"    Parameters: {[hex(p) for p in ep.parameters]}")

                # Nested exception
                if ep.nested_exception:
                    lines.append(f"    Nested Exception: {ep.nested_exception.code_name} (0x{ep.nested_exception.code:08X})")

            # CPU Context
            if report.exception_context:
                lines.append("")
                lines.append("  CPU Registers (Exception Context):")
                # Group registers for readability if possible, or just list
                keys = sorted(report.exception_context.keys())
                for i in range(0, len(keys), 3):
                    chunk = keys[i:i+3]
                    row = []
                    for k in chunk:
                        val = report.exception_context[k]
                        if isinstance(val, int):
                            row.append(f"{k}: 0x{val:X}")
                        else:
                            row.append(f"{k}: {val}")
                    lines.append("    " + "  ".join(row))

            lines.append("")

        # Primary suspects - THE KEY SECTION
        if report.primary_suspects:
            lines.append("=" * 70)
            lines.append("PRIMARY SUSPECTS - MOST LIKELY CRASH CAUSES")
            lines.append("=" * 70)
            sec = getattr(report, 'primary_suspect_secondary', None)
            conf = getattr(report, 'primary_suspect_confidence', 'medium')
            if sec:
                lines.append("  (Top two suspects have close scores; consider both.)")
            if conf == "low":
                lines.append("  (Confidence is low; correlate with stack traces below.)")
            lines.append("")
            for i, suspect in enumerate(report.primary_suspects[:5], 1):
                lines.append("")
                lines.append(f"  #{i} RESOURCE: {suspect.name}")
                if getattr(suspect, 'likely_script', None):
                    lines.append(f"      Likely script: {suspect.likely_script}")
                lines.append(f"      Evidence Score: {suspect.evidence_count}")
                lines.append(f"      Evidence Types: {', '.join(e.name for e in suspect.evidence_types)}")
                if suspect.scripts:
                    lines.append(f"      Scripts Involved: {', '.join(suspect.scripts[:5])}")
                if suspect.path:
                    lines.append(f"      Path: {suspect.path}")
            lines.append("")

        # Script errors
        if report.script_errors:
            lines.append("SCRIPT ERRORS FOUND:")
            lines.append("-" * 40)
            for err in report.script_errors[:10]:
                lines.append(f"\n  Type: {err.error_type}")
                if err.resource_name:
                    lines.append(f"  Resource: {err.resource_name}")
                if err.script_name:
                    lines.append(f"  Script: {err.script_name}")
                if err.line_number:
                    lines.append(f"  Line: {err.line_number}")
                lines.append(f"  Message: {err.message[:200]}")
            lines.append("")

        # Lua stack traces (with resources involved per stack)
        if report.lua_stacks:
            lines.append("LUA STACK TRACES:")
            lines.append("-" * 40)
            for i, stack in enumerate(report.lua_stacks[:3], 1):
                lines.append(f"\n  Stack #{i}:")
                if i - 1 < len(report.lua_stack_resources) and report.lua_stack_resources[i - 1]:
                    lines.append(f"    Resources involved: {', '.join(report.lua_stack_resources[i - 1])}")
                for frame in stack[:8]:
                    func = frame.function_name or '(anonymous)'
                    lines.append(f"    {frame.source}:{frame.line} in {func}")
            lines.append("")

        # JS stack traces (with resources involved per stack)
        if report.js_stacks:
            lines.append("JAVASCRIPT STACK TRACES:")
            lines.append("-" * 40)
            for i, trace in enumerate(report.js_stacks[:10]):
                if i < len(report.js_stack_resources) and report.js_stack_resources[i]:
                    lines.append(f"  Resources involved: {', '.join(report.js_stack_resources[i])}")
                lines.append(f"  {trace}")
            lines.append("")

        # Native stack traces (with symbolication when PDBs available)
        if report.native_stacks:
            lines.append("NATIVE STACK TRACE (Crashing Thread):")
            lines.append("-" * 40)
            # Show resource names right here so user can correlate
            resources_for_stack = []
            if report.primary_suspects:
                resources_for_stack = [s.name for s in report.primary_suspects[:10]]
            elif report.resources:
                by_ev = sorted(
                    report.resources.items(),
                    key=lambda x: (getattr(x[1], 'evidence_count', 0), x[0]),
                    reverse=True
                )
                resources_for_stack = [name for name, _ in by_ev[:10]]
            if resources_for_stack:
                lines.append("Resources identified in this dump (correlate with stack below):")
                lines.append("  " + ", ".join(resources_for_stack))
                lines.append("")
            # How to use this to find the cause
            lines.append("How to use this to find the cause:")
            lines.append("  - Top frames are closest to the crash; the exception address points to the faulting instruction.")
            lines.append("  - When symbols are loaded (PDB), each frame shows:  module + 0xOFFSET  ->  function_name + 0xdisp")
            lines.append("  - Correlate the resources above with the stack to see which script may have triggered this path.")
            lines.append("")
            has_symbolication = report.native_stacks_symbolicated and any("  ->  " in f for f in report.native_stacks_symbolicated)
            if not has_symbolication and report.native_stacks:
                if report.module_versions:
                    if getattr(report, 'symbolication_had_local_path', False):
                        lines.append("  (Symbols not loaded: PDB not found on FiveM symbol server or in local cache. Ensure FIVEM_SYMBOL_CACHE folder has PDBs for this build (e.g. <pdb_name>/<GUID><age>/<pdb_name>). Showing module+offset only.)")
                        diag = getattr(report, 'symbolication_diagnostic', None)
                        if diag:
                            lines.append("")
                            lines.append(diag)
                    else:
                        lines.append("  (Symbols not loaded: PDB not found on FiveM symbol server (404). To use local PDBs, set FIVEM_SYMBOL_CACHE in .env to your symbol folder (e.g. D:\\symbolcache). Showing module+offset only.)")
                else:
                    lines.append("  (Symbols not loaded: PDB download failed or module info missing. Showing module+offset only.)")
                lines.append("")
            elif has_symbolication:
                lines.append("  (Symbols loaded from server or local cache; correlate the function names below with the resources list to identify the crashing resource.)")
                lines.append("")
            display_frames = report.native_stacks_symbolicated if report.native_stacks_symbolicated else report.native_stacks
            for frame in display_frames:
                lines.append(frame if (frame and frame.startswith("  ")) else f"  {frame}")
            lines.append("")

        # Crash patterns
        if report.crash_patterns:
            lines.append("DETECTED CRASH PATTERNS:")
            lines.append("-" * 40)
            for pattern in report.crash_patterns:
                lines.append(f"\n  Issue: {pattern.issue}")
                lines.append(f"  Explanation: {pattern.explanation}")
                if pattern.solutions:
                    lines.append("  Solutions:")
                    for sol in pattern.solutions[:3]:
                        lines.append(f"    - {sol}")
            lines.append("")

        # Identified modules
        if report.identified_modules:
            lines.append("IDENTIFIED MODULES:")
            lines.append("-" * 40)
            for mod in report.identified_modules:
                lines.append(f"  {mod['module']}: {mod['description']}")
            lines.append("")

        # Unloaded modules
        if report.unloaded_modules:
            lines.append("UNLOADED MODULES:")
            lines.append("-" * 40)
            for mod in report.unloaded_modules[:20]:
                lines.append(f"  {mod}")
            if len(report.unloaded_modules) > 20:
                lines.append(f"  ... and {len(report.unloaded_modules) - 20} more")
            lines.append("")

        # NEW: Process Statistics
        if report.process_stats:
            ps = report.process_stats
            lines.append("PROCESS STATISTICS:")
            lines.append("-" * 40)
            lines.append(f"  Process ID: {ps.process_id}")
            if ps.process_integrity_level:
                lines.append(f"  Integrity Level: {ps.process_integrity_level}")
            if ps.protected_process:
                lines.append(f"  Protected Process: Yes")

            # Memory usage
            if ps.peak_working_set_size or ps.working_set_size:
                lines.append("")
                lines.append("  Memory Usage:")
                if ps.working_set_size:
                    lines.append(f"    Working Set: {ps.working_set_size:,} bytes ({ps.working_set_size // (1024*1024)} MB)")
                if ps.peak_working_set_size:
                    lines.append(f"    Peak Working Set: {ps.peak_working_set_size:,} bytes ({ps.peak_working_set_size // (1024*1024)} MB)")
                if ps.private_usage:
                    lines.append(f"    Private Usage: {ps.private_usage:,} bytes ({ps.private_usage // (1024*1024)} MB)")
                if ps.virtual_size:
                    lines.append(f"    Virtual Size: {ps.virtual_size:,} bytes ({ps.virtual_size // (1024*1024)} MB)")
                if ps.peak_virtual_size:
                    lines.append(f"    Peak Virtual Size: {ps.peak_virtual_size:,} bytes ({ps.peak_virtual_size // (1024*1024)} MB)")
                if ps.pagefile_usage:
                    lines.append(f"    Pagefile Usage: {ps.pagefile_usage:,} bytes ({ps.pagefile_usage // (1024*1024)} MB)")
                if ps.page_fault_count:
                    lines.append(f"    Page Faults: {ps.page_fault_count:,}")

            # Handle counts
            if ps.handle_count or ps.gdi_handle_count or ps.user_handle_count:
                lines.append("")
                lines.append("  Handle Counts:")
                if ps.handle_count:
                    lines.append(f"    Total Handles: {ps.handle_count}")
                if ps.gdi_handle_count:
                    lines.append(f"    GDI Handles: {ps.gdi_handle_count}")
                if ps.user_handle_count:
                    lines.append(f"    USER Handles: {ps.user_handle_count}")
            lines.append("")

        # NEW: Open Handles
        if report.handles:
            lines.append("OPEN HANDLES AT CRASH TIME:")
            lines.append("-" * 40)
            # Group handles by type
            by_type: Dict[str, List] = {}
            for h in report.handles:
                if h.type_name not in by_type:
                    by_type[h.type_name] = []
                by_type[h.type_name].append(h)

            for type_name, handles in sorted(by_type.items()):
                lines.append(f"\n  {type_name} ({len(handles)} handles):")
                for h in handles[:10]:  # Show first 10 of each type
                    if h.object_name:
                        lines.append(f"    0x{h.handle_value:04X}: {h.object_name}")
                    else:
                        lines.append(f"    0x{h.handle_value:04X}: (unnamed)")
                if len(handles) > 10:
                    lines.append(f"    ... and {len(handles) - 10} more")
            lines.append("")

        # NEW: Thread Extended Information
        if report.threads_extended:
            lines.append("THREAD INFORMATION:")
            lines.append("-" * 40)
            for t in report.threads_extended[:20]:
                name_str = f" \"{t.thread_name}\"" if t.thread_name else ""
                state_str = f" [{t.state}]" if t.state else ""
                lines.append(f"  Thread {t.thread_id}{name_str}{state_str}")
                if t.priority:
                    lines.append(f"    Priority: {t.priority}")
                if t.stack_base:
                    size = (t.stack_limit - t.stack_base) if t.stack_limit else 0
                    lines.append(f"    Stack: 0x{t.stack_base:016X} ({size:,} bytes)")
                if t.teb_address:
                    lines.append(f"    TEB: 0x{t.teb_address:016X}")
            if len(report.threads_extended) > 20:
                lines.append(f"  ... and {len(report.threads_extended) - 20} more threads")
            lines.append("")

        # NEW: Module Versions with PDB Info
        if report.module_versions:
            # Filter to show only modules with interesting info
            interesting_modules = [m for m in report.module_versions
                                   if m.pdb_name or m.file_version or m.checksum]
            if interesting_modules:
                lines.append("MODULE VERSION INFORMATION:")
                lines.append("-" * 40)
                for m in interesting_modules[:30]:
                    lines.append(f"\n  {os.path.basename(m.name)}")
                    lines.append(f"    Base: 0x{m.base_address:016X}, Size: {m.size:,} bytes")
                    if m.file_version:
                        lines.append(f"    Version: {m.file_version}")
                    if m.checksum:
                        lines.append(f"    Checksum: 0x{m.checksum:08X}")
                    if m.timestamp:
                        try:
                            import datetime
                            dt = datetime.datetime.fromtimestamp(m.timestamp)
                            lines.append(f"    Timestamp: {dt}")
                        except:
                            lines.append(f"    Timestamp: {m.timestamp}")
                    if m.pdb_name:
                        lines.append(f"    PDB: {m.pdb_name}")
                    if m.pdb_guid:
                        lines.append(f"    PDB GUID: {m.pdb_guid}")
                    if m.pdb_age:
                        lines.append(f"    PDB Age: {m.pdb_age}")
                if len(interesting_modules) > 30:
                    lines.append(f"\n  ... and {len(interesting_modules) - 30} more modules with version info")
                lines.append("")

        # NEW: Memory Regions (show executable regions and regions near exception)
        if report.memory_info:
            lines.append("MEMORY REGIONS:")
            lines.append("-" * 40)
            # Show executable regions
            exec_regions = [r for r in report.memory_info if r.contains_code and r.state == "MEM_COMMIT"]
            if exec_regions:
                lines.append("  Executable Regions:")
                for r in exec_regions[:20]:
                    mod_str = f" ({r.module_name})" if r.module_name else ""
                    lines.append(f"    0x{r.start_address:016X} - Size: {r.size:,} bytes{mod_str}")
                    lines.append(f"      Protection: {r.protection}")
                if len(exec_regions) > 20:
                    lines.append(f"    ... and {len(exec_regions) - 20} more")

            # If we have an exception address, show nearby regions
            if report.exception_address:
                lines.append("")
                lines.append("  Regions near exception address:")
                for r in report.memory_info:
                    if r.start_address <= report.exception_address < r.start_address + r.size:
                        lines.append(f"    FAULTING REGION: 0x{r.start_address:016X}")
                        lines.append(f"      Size: {r.size:,} bytes")
                        lines.append(f"      Protection: {r.protection}")
                        lines.append(f"      State: {r.state}")
                        lines.append(f"      Type: {r.type_str}")
                        if r.module_name:
                            lines.append(f"      Module: {r.module_name}")
                        break
            lines.append("")

        # NEW: Assertion Info
        if report.assertion_info:
            lines.append("ASSERTION FAILURE:")
            lines.append("-" * 40)
            if 'expression' in report.assertion_info:
                lines.append(f"  Expression: {report.assertion_info['expression']}")
            if 'function' in report.assertion_info:
                lines.append(f"  Function: {report.assertion_info['function']}")
            if 'file' in report.assertion_info:
                lines.append(f"  File: {report.assertion_info['file']}")
            if 'line' in report.assertion_info:
                lines.append(f"  Line: {report.assertion_info['line']}")
            lines.append("")

        # NEW: Comment Streams
        if report.comment_stream_a or report.comment_stream_w:
            lines.append("DUMP COMMENTS:")
            lines.append("-" * 40)
            if report.comment_stream_a:
                lines.append(f"  ASCII: {report.comment_stream_a[:500]}")
            if report.comment_stream_w:
                lines.append(f"  Unicode: {report.comment_stream_w[:500]}")
            lines.append("")

        # Resources from logs
        if report.log_resources:
            lines.append("RESOURCES FOUND IN LOGS:")
            lines.append("-" * 40)
            lines.append(f"  {', '.join(report.log_resources[:20])}")
            lines.append("")

        # Log errors
        if report.log_errors:
            lines.append("ERRORS FROM LOG FILES:")
            lines.append("-" * 40)
            for err in report.log_errors[:10]:
                lines.append(f"  Line {err.get('line', '?')}: {err.get('content', '')[:100]}")
            lines.append("")

        # Summary
        lines.append("ANALYSIS SUMMARY:")
        lines.append("-" * 40)
        lines.append(f"  Primary Suspects: {len(report.primary_suspects)}")
        lines.append(f"  Script Errors: {len(report.script_errors)}")
        lines.append(f"  Lua Stacks: {len(report.lua_stacks)}")
        lines.append(f"  Crash Patterns: {len(report.crash_patterns)}")
        lines.append(f"  Evidence Items: {len(report.all_evidence)}")
        lines.append("")
        lines.append("  Extended Data Extracted:")
        lines.append(f"    Threads: {len(report.threads_extended)}")
        lines.append(f"    Modules with Version Info: {len([m for m in report.module_versions if m.pdb_name or m.file_version])}")
        lines.append(f"    Open Handles: {len(report.handles)}")
        lines.append(f"    Memory Regions: {len(report.memory_info)}")
        if report.function_table_entries:
            lines.append(f"    Function Table Entries: {report.function_table_entries}")

        if report.analysis_errors:
            lines.append("\n  Warnings:")
            for err in report.analysis_errors:
                lines.append(f"    - {err}")

        lines.append("")
        lines.append("=" * 70)

        return "\n".join(lines)

    def get_diagnostic_info(self, dump_path: str) -> str:
        """Get diagnostic information about dump reading.

        Use this to verify the dump is being read correctly.
        """
        result = self.analyze_dump_deep(dump_path)
        return self.memory_analyzer.get_diagnostic_info()

    def get_pinpoint_summary(self, report: CrashReport) -> str:
        """Get a concise summary pinpointing the likely cause."""
        lines = []

        if report.primary_suspects:
            top = report.primary_suspects[0]
            sec = getattr(report, 'primary_suspect_secondary', None)
            conf = getattr(report, 'primary_suspect_confidence', 'medium')
            if sec:
                lines.append(f"MOST LIKELY CAUSE: Resource '{top.name}' (or '{sec}' if evidence is ambiguous)")
            else:
                lines.append(f"MOST LIKELY CAUSE: Resource '{top.name}'")
            if getattr(top, 'likely_script', None):
                lines.append(f"  Likely script: {top.likely_script}")
            if top.scripts:
                lines.append(f"  Scripts: {', '.join(top.scripts[:3])}")
            lines.append(f"  Evidence: {top.evidence_count} items")
            lines.append(f"  Types: {', '.join(e.name for e in list(top.evidence_types)[:3])}")
            if conf == "low":
                lines.append("  (Consider investigating the resources listed below; confidence is low.)")
        elif report.script_errors:
            err = report.script_errors[0]
            lines.append(f"SCRIPT ERROR DETECTED:")
            lines.append(f"  {err.message[:100]}")
            if err.resource_name:
                lines.append(f"  Resource: {err.resource_name}")
        elif report.crash_patterns:
            pattern = report.crash_patterns[0]
            lines.append(f"CRASH TYPE: {pattern.issue}")
            lines.append(f"  {pattern.explanation}")
        else:
            lines.append("Unable to pinpoint specific cause.")
            lines.append("Check the full report for more details.")

        return "\n".join(lines)

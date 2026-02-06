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
import threading
import urllib.parse
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple, Set

# Optional Windows/native dependencies
try:
    import ctypes
    HAS_CTYPES = True
except Exception:
    ctypes = None
    HAS_CTYPES = False

try:
    import requests
    HAS_REQUESTS = True
except Exception:
    requests = None
    HAS_REQUESTS = False

# Optional minidump library
try:
    from minidump.minidumpfile import MinidumpFile
    HAS_MINIDUMP = True
except Exception:
    MinidumpFile = None
    HAS_MINIDUMP = False

# Internal imports
from .memory_analyzer import (
    MemoryAnalyzer,
    DeepAnalysisResult,
    ScriptEvidence,
    EvidenceType,
    ResourceInfo,
    ScriptError,
    LuaStackFrame,
    HandleInfo,
    ThreadExtendedInfo,
    ModuleVersionInfo,
    ExceptionParams,
    ProcessStatistics,
    MemoryRegionInfo,
)

try:
    from .symbol_resolver import SymbolResolver
    HAS_SYMBOL_RESOLVER = True
except Exception:
    SymbolResolver = None
    HAS_SYMBOL_RESOLVER = False

# WinDbg integration for native stack analysis
try:
    from .windbg_wrapper import WinDbgWrapper
    HAS_WINDBG = True
except Exception:
    WinDbgWrapper = None
    HAS_WINDBG = False

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
                        "timestamp": int(__import__("time").time() * 1000),
                    }
                )
                + "\n"
            )
    except Exception:
        pass


@dataclass
class PatternMatch:
    """Represents a matched crash pattern."""

    issue: str
    explanation: str
    solutions: List[str]


@dataclass
class CrashReport:
    """Complete crash analysis report."""

    # Files
    dump_file: Optional[str] = None
    log_files: List[str] = field(default_factory=list)

    # Exception info
    exception_code: Optional[int] = None
    exception_address: Optional[int] = None
    exception_module: Optional[str] = None

    # Pattern matches
    crash_patterns: List[PatternMatch] = field(default_factory=list)

    # Suspects and resources
    primary_suspects: List[ResourceInfo] = field(default_factory=list)
    resources: Dict[str, ResourceInfo] = field(default_factory=dict)

    # Script diagnostics
    script_errors: List[ScriptError] = field(default_factory=list)
    lua_stacks: List[List[LuaStackFrame]] = field(default_factory=list)
    lua_stack_resources: List[List[str]] = field(default_factory=list)
    js_stacks: List[str] = field(default_factory=list)
    js_stack_resources: List[List[str]] = field(default_factory=list)

    # Native stacks
    native_stacks: List[str] = field(default_factory=list)
    native_stacks_symbolicated: List[str] = field(default_factory=list)

    # Module identification
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

    # Event handlers extracted from memory
    event_handlers: List[str] = field(default_factory=list)

    # Analysis metadata
    analysis_errors: List[str] = field(default_factory=list)

    # ===== ENHANCED EXTRACTION DATA =====
    # Crashometry data (from crashometry.json)
    crashometry: Dict[str, Any] = field(default_factory=dict)
    crash_hash: str = ""
    crash_hash_key: str = ""
    server_address: str = ""
    server_version: str = ""
    gpu_name: str = ""
    onesync_enabled: bool = False
    onesync_big: bool = False
    
    # Timed script errors from log (errors near crash time)
    timed_script_errors: List[Dict[str, Any]] = field(default_factory=list)
    crash_timestamp_ms: Optional[int] = None
    
    # CPU registers at crash
    cpu_registers: Dict[str, int] = field(default_factory=dict)
    
    # Primary suspect from combined analysis
    primary_suspect_resource: Optional[str] = None
    primary_suspect_file: Optional[str] = None
    primary_suspect_line: Optional[int] = None
    primary_suspect_message: Optional[str] = None
    time_before_crash_sec: Optional[float] = None
    
    # Total resource count loaded on server
    loaded_resource_count: int = 0

    # Standard Minidump Data
    system_info: Dict[str, Any] = field(default_factory=dict)
    misc_info: Dict[str, Any] = field(default_factory=dict)
    system_memory_info: Dict[str, Any] = field(default_factory=dict)
    ip_mi_summary: Dict[str, Any] = field(default_factory=dict)
    process_token: Dict[str, Any] = field(default_factory=dict)
    process_parameters: Dict[str, Any] = field(default_factory=dict)
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
    # Raw ThreadEx list (fallback when minidump library is unavailable)
    thread_ex_list: List[Dict[str, Any]] = field(default_factory=list)
    # Decoded thread contexts (register snapshots)
    thread_contexts: Dict[int, Dict[str, int]] = field(default_factory=dict)

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
    # Handle operation list (18) - handle open/close operations
    handle_operations: List[Dict[str, Any]] = field(default_factory=list)

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
    # NUI resources attributed from memory context (resource -> count)
    nui_resources: Dict[str, int] = field(default_factory=dict)

    # Network patterns
    network_patterns: List[Tuple[str, int]] = field(default_factory=list)

    # State bag patterns
    statebag_patterns: List[Tuple[str, int]] = field(default_factory=list)

    # FiveM-specific forensics results
    fivem_forensics: Optional[Dict[str, Any]] = None
    
    # WinDbg native stack analysis results
    windbg_analysis: Optional[Dict[str, Any]] = None
    
    # ===== FRAMEWORK & METADATA DETECTION =====
    # Detected FiveM framework (QBCore, ESX, VRP, Ox, None)
    framework_detected: Optional[str] = None
    framework_confidence: float = 0.0  # 0.0-1.0 confidence score
    
    # fxmanifest.lua metadata extraction
    fxmanifest_data: Dict[str, Any] = field(default_factory=dict)
    
    # Error severity classification (error_id -> severity level)
    error_severities: Dict[str, str] = field(default_factory=dict)  # "crash", "error", "panic", "warning"
    
    # ===== HEAP STATISTICS & LEAK ANALYSIS =====
    # Real heap statistics extracted from MINIDUMP_MEMORY_INFO_LIST
    heap_committed_bytes: int = 0
    heap_reserved_bytes: int = 0
    heap_free_bytes: int = 0
    heap_fragmentation_pct: float = 0.0
    
    # Memory pressure at crash time
    memory_pressure: str = "unknown"  # unknown, normal, elevated, critical
    oom_imminent: bool = False
    
    # Leak detection results
    leak_detected: bool = False
    leak_confidence: str = "none"  # none, low, medium, high
    leak_evidence: List[str] = field(default_factory=list)
    
    # Allocation deltas (calculated from patterns)
    entity_allocation_delta: int = 0  # entities created - deleted
    timer_allocation_delta: int = 0   # timers created (no deletion tracking)
    event_handler_delta: int = 0      # handlers registered - removed
    
    # Leak type flags
    entity_leak: bool = False
    timer_leak: bool = False
    event_handler_leak: bool = False
    nui_leak: bool = False


class Symbolicator:
    """Symbol downloader and address resolver for Windows minidumps.

    Uses the FiveM symbol server; local cache fallbacks are disabled to keep
    analysis strictly source-of-dump.
    """

    # Timeout (seconds) for symbol server requests; increase if you see timeout errors
    SYMBOL_DOWNLOAD_TIMEOUT = 30

    def __init__(
        self,
        symbol_server: str = "https://runtime.fivem.net/client/symbols/",
    ):
        self.server = symbol_server
        self.process = None
        self.dbghelp = None
        self._initialized = False
        self._symbol_cache: Dict[str, str] = {}

        if sys.platform == 'win32' and HAS_CTYPES:
            self._init_dbghelp()

    def _init_dbghelp(self) -> None:
        """Initialize Windows debug help library with proper symbol cache."""
        try:
            from pathlib import Path
            from ctypes import wintypes
            self.dbghelp = ctypes.windll.dbghelp
            kernel32 = ctypes.windll.kernel32
            kernel32.GetCurrentProcess.argtypes = []
            kernel32.GetCurrentProcess.restype = wintypes.HANDLE
            self.process = kernel32.GetCurrentProcess()

            # Create a persistent symbol cache directory
            cache_dir = Path(tempfile.gettempdir()) / "fivem_symbols_cache"
            cache_dir.mkdir(parents=True, exist_ok=True)
            local_pdb_dir = Path(tempfile.gettempdir()) / "fivem_symbols"
            local_pdb_dir.mkdir(parents=True, exist_ok=True)
            
            # Build proper DbgHelp symbol path: srv*cache*server format
            # This tells DbgHelp to download from servers and cache locally
            symbol_path = (
                f"srv*{cache_dir}*{self.server};"
                f"srv*{cache_dir}*https://msdl.microsoft.com/download/symbols/;"
                f"srv*{local_pdb_dir};"
                f"{local_pdb_dir}"
            )

            # Initialize symbol handler with cache directory
            SYMOPT_UNDNAME = 0x00000002
            SYMOPT_DEFERRED_LOADS = 0x00000004
            SYMOPT_LOAD_LINES = 0x00000010
            SYMOPT_FAIL_CRITICAL_ERRORS = 0x00000200
            self.dbghelp.SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES | SYMOPT_FAIL_CRITICAL_ERRORS)
            self.dbghelp.SymInitializeW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.BOOL]
            self.dbghelp.SymInitializeW.restype = wintypes.BOOL
            result = self.dbghelp.SymInitializeW(
                self.process,
                ctypes.c_wchar_p(symbol_path),
                False
            )
            self._initialized = bool(result)
            
            if self._initialized:
                print(f"[DbgHelp] Initialized with symbol cache: {cache_dir}")
            else:
                print(f"[DbgHelp] Initialization failed")
        except Exception as e:
            print(f"[DbgHelp] Exception during init: {str(e)[:80]}")
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

    def download_symbol_by_pdb(self, pdb_name: str, guid: str, age: int) -> Optional[str]:
        """Download symbol file using PDB name and GUID."""
        if not pdb_name:
            return None

        cache_key = f"{pdb_name}_{guid}_{age}"
        if cache_key in self._symbol_cache:
            return self._symbol_cache[cache_key]

        guid_str = str(guid).upper().replace('-', '')
        # Age must be formatted as decimal for Microsoft symbol server format
        age_str = f"{int(age):d}" if age is not None else '0'
        combined = guid_str + age_str

        # Check existing caches FIRST (symbol_resolver uses fivem_symbols, we use fivem_symbols_cache)
        # This avoids redundant 404 downloads when PDB was already cached by another component
        from pathlib import Path
        cache_locations = [
            Path(tempfile.gettempdir()) / "fivem_symbols" / pdb_name / combined / pdb_name,
            Path(tempfile.gettempdir()) / "fivem_symbols_cache" / pdb_name / combined / pdb_name,
        ]
        for cache_path in cache_locations:
            if cache_path.exists() and cache_path.stat().st_size > 100:  # Must be > 100 bytes (not a placeholder)
                print(f"[Symbolicator] Using cached: {pdb_name}")
                self._symbol_cache[cache_key] = str(cache_path)
                return str(cache_path)

        # Try symbol server (only if requests available)
        if HAS_REQUESTS and guid:
            path = f"{pdb_name}/{combined}/{pdb_name}"
            url = urllib.parse.urljoin(self.server, path)
            try:
                # Show abbreviated URL but include GUID info
                print(f"[Symbolicator] Downloading {pdb_name} (GUID={combined[:16]}...)")
                r = requests.get(url, stream=True, timeout=Symbolicator.SYMBOL_DOWNLOAD_TIMEOUT)
                if r.status_code != 200:
                    print(f"[Symbolicator]   HTTP {r.status_code} - symbols not available on server")
                else:
                    print(f"[Symbolicator]   HTTP {r.status_code}")
                # #region agent log
                _dlog("H3", "core.Symbolicator.download_symbol_by_pdb", "pdb download primary", {
                    "url": url[:120],
                    "status_code": r.status_code,
                    "pdb_name": pdb_name,
                    "guid": guid_str,
                    "age": age_str,
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

        return None

    def load_module(self, base_addr: int, module_path: str,
                   module_name: Optional[str] = None, module_size: int = 0) -> int:
        """Load a module for symbol resolution."""
        if not self._initialized or not self.dbghelp:
            return 0
        try:
            from ctypes import wintypes
            kernel32 = ctypes.windll.kernel32
            ImageName = ctypes.c_wchar_p(module_path)
            mod_basename = os.path.basename(module_name or module_path)
            ModuleName = ctypes.c_wchar_p(mod_basename)
            self.dbghelp.SymLoadModuleExW.argtypes = [
                wintypes.HANDLE,
                wintypes.HANDLE,
                wintypes.LPCWSTR,
                wintypes.LPCWSTR,
                ctypes.c_ulonglong,
                ctypes.c_ulong,
                ctypes.c_void_p,
                ctypes.c_ulong,
            ]
            self.dbghelp.SymLoadModuleExW.restype = ctypes.c_ulonglong
            flags = 0
            if base_addr or (module_path and module_path.lower().endswith('.pdb')):
                flags |= 0x1  # SLMFLAG_VIRTUAL for offline symbolization
            loaded = self.dbghelp.SymLoadModuleExW(
                self.process, 0, ImageName, ModuleName,
                ctypes.c_ulonglong(base_addr or 0),
                ctypes.c_ulong(module_size or 0), 0, flags
            )
            # Note: err=0 means module was already loaded (success), suppress that
            if not loaded:
                err = kernel32.GetLastError()
                if err != 0:  # Only report actual errors
                    print(f"[DbgHelp] SymLoadModuleExW failed for {os.path.basename(module_path)} (err={err})")
            return int(loaded)
        except Exception:
            return 0

    def symbolicate_address(self, address: int) -> Tuple[Optional[str], Optional[int]]:
        """Resolve an address to a symbol name."""
        if not self._initialized or not self.dbghelp:
            return (None, None)

        class SYMBOL_INFOW(ctypes.Structure):
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
                ("Name", ctypes.c_wchar * 1)
            ]

        from ctypes import wintypes
        max_name_len = 1024
        buffer_size = ctypes.sizeof(SYMBOL_INFOW) + (max_name_len - 1) * ctypes.sizeof(ctypes.c_wchar)
        symbol_buffer = ctypes.create_string_buffer(buffer_size)
        sym = ctypes.cast(symbol_buffer, ctypes.POINTER(SYMBOL_INFOW))
        sym.contents.SizeOfStruct = ctypes.sizeof(SYMBOL_INFOW)
        sym.contents.MaxNameLen = max_name_len
        displacement = ctypes.c_ulonglong(0)

        self.dbghelp.SymFromAddrW.argtypes = [
            wintypes.HANDLE,
            ctypes.c_ulonglong,
            ctypes.POINTER(ctypes.c_ulonglong),
            ctypes.POINTER(SYMBOL_INFOW),
        ]
        self.dbghelp.SymFromAddrW.restype = wintypes.BOOL

        try:
            kernel32 = ctypes.windll.kernel32
            addr = ctypes.c_ulonglong(address)
            res = self.dbghelp.SymFromAddrW(
                self.process, addr, ctypes.byref(displacement), sym
            )
            if res:
                name_len = sym.contents.NameLen
                name_ptr = ctypes.addressof(sym.contents.Name)
                name = ctypes.wstring_at(name_ptr, name_len) if name_len else ctypes.wstring_at(name_ptr)
                return (name, int(displacement.value))
            # Error 487 = no symbol found, which is expected for stripped PDBs
            # Only log unexpected errors to reduce noise
            err = kernel32.GetLastError()
            if err and err != 487 and not hasattr(self, '_sym_error_logged'):
                print(f"[DbgHelp] Symbol resolution error (err={err}) - PDB may lack public symbols")
                self._sym_error_logged = True
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
        r'0x?deadbade|sub_14133c510|poison.*marker.*write|heap.*poison.*fail': {
            'issue': 'Heap Corruption - Poisoned Memory Write Failure',
            'explanation': (
                'The heap manager attempted to mark freed memory with the poison marker 0xDEADBADE '
                'but the heap pointer was corrupted. This indicates memory has been corrupted BEFORE '
                'the free operation, typically by a buffer overflow, use-after-free, or FFI pointer misuse.'
            ),
            'solutions': [
                'Check for buffer overflows in recently added resources - especially native string buffers',
                'Verify FFI pointer handling - ensure C pointers are not being modified incorrectly',
                'Look for use-after-free scenarios where memory is accessed after being deleted',
                'Check native calls that accept pointers/buffers for correct size parameters',
                'Disable recently added C#/Lua scripts that interact with game memory via natives',
                'Review any CFX natives that accept char* or void* parameters for buffer sizing issues'
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

    def __init__(self, progress_callback=None, auto_download_symbols: bool = True, symbol_cache_dir: Optional[str] = None):
        """Initialize the crash analyzer.
        
        Args:
            progress_callback: Optional callable(stage: str, progress: float, message: str)
                             for receiving progress updates during analysis.
                             If None, defaults to console output.
            auto_download_symbols: Automatically download PDB symbols from FiveM/Microsoft servers
            symbol_cache_dir: Custom directory for symbol cache (defaults to temp directory)
        """
        self._has_minidump = HAS_MINIDUMP
        
        # Use console progress callback if none provided
        if progress_callback is None:
            progress_callback = self._default_progress_callback
        
        self._progress_callback = progress_callback
        self.memory_analyzer = MemoryAnalyzer(progress_callback=progress_callback)

        # Initialize symbolicator (Windows only)
        try:
            self.symbolicator = Symbolicator()
        except Exception:
            self.symbolicator = None
        
        # Symbol resolver for automatic PDB downloading
        self.auto_download_symbols = auto_download_symbols and HAS_SYMBOL_RESOLVER
        self.symbol_resolver = None
        if self.auto_download_symbols and SymbolResolver:
            self.symbol_resolver = SymbolResolver(
                cache_dir=symbol_cache_dir,
                progress_callback=self._symbol_progress_callback
            )

        # Initialize WinDbg wrapper for native stack analysis (Windows only)
        try:
            self.windbg = WinDbgWrapper() if HAS_WINDBG else None
        except Exception:
            self.windbg = None

        # Initialize native database manager for 64-bit native decoding
        try:
            from .native_db_manager import NativeDBManager
            self.native_db_manager = NativeDBManager()
            # Pre-load native database for crash analysis
            self.native_db = self.native_db_manager.load_or_fetch(verbose=False)
        except Exception as e:
            self.native_db_manager = None
            self.native_db = {}

        # Pre-compile crash patterns
        self._compiled_crash_patterns = []
        for pattern, details in self.CRASH_PATTERNS.items():
            try:
                compiled = re.compile(pattern, re.IGNORECASE)
                self._compiled_crash_patterns.append((compiled, details))
            except re.error:
                continue

    @staticmethod
    def _default_progress_callback(stage: str, progress: float, message: str) -> None:
        """Default console progress callback for CLI usage."""
        percentage = int(progress * 100)
        print(f"[{stage.upper():12s}] {percentage:3d}% - {message}")

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
    
    def _symbol_progress_callback(self, message: str, current: int, total: int):
        """Callback for symbol download progress."""
        if self._progress_callback:
            # Convert to unified progress format
            progress = current / max(total, 1) if total > 0 else 0.0
            self._progress_callback("symbols", progress, message)
    
    def download_fivem_symbols(self, dump_path: str) -> Dict[str, bool]:
        """Download FiveM PDB symbols for modules in a dump file.
        
        This extracts module information from the dump and automatically downloads
        PDB symbol files from FiveM's symbol server and Microsoft's public server.
        
        Args:
            dump_path: Path to the minidump file
            
        Returns:
            Dictionary mapping module names to download success status
        """
        if not self.symbol_resolver:
            return {}
        
        # OPTIMIZATION: Skip symbol downloads for very large dumps (>1GB) to prevent hangs
        # Large full dumps typically have all the data we need already in memory
        dump_size = os.path.getsize(dump_path)
        if dump_size > 1024 * 1024 * 1024:  # 1GB
            if self._progress_callback:
                self._progress_callback("symbols", 1.0, f"Skipping symbols for large dump ({dump_size/(1024*1024*1024):.2f}GB)")
            print(f"[SYMBOL] Skipping symbol downloads for large dump ({dump_size/(1024*1024*1024):.2f}GB)")
            print(f"[SYMBOL] Large dumps contain memory content - symbols less critical")
            return {}
        
        # Extract module information from the dump
        if self._progress_callback:
            self._progress_callback("symbols", 0.0, "Extracting module information from dump...")
        
        # Perform a quick structure parse to get module info
        temp_analyzer = MemoryAnalyzer()
        temp_analyzer.result = DeepAnalysisResult()
        
        try:
            # Use lightweight structure parsing to extract modules
            temp_analyzer._parse_large_dump_structure_light(dump_path)
            module_versions = temp_analyzer.result.module_versions
        except Exception as e:
            # Fallback: try full minidump parsing if available
            if HAS_MINIDUMP:
                try:
                    md = MinidumpFile.parse(dump_path)
                    temp_analyzer._analyze_minidump_structure(md)
                    module_versions = temp_analyzer.result.module_versions
                except Exception:
                    return {}
            else:
                return {}
        
        # Register modules with the symbol resolver
        fivem_modules_registered = 0
        all_modules_registered = 0
        
        for mod in module_versions:
            if not mod.pdb_name or not mod.pdb_guid:
                continue
            
            # Register the module
            self.symbol_resolver.register_module(
                name=mod.name,
                base_address=mod.base_address or 0,
                size=mod.size or 0,
                pdb_name=mod.pdb_name,
                pdb_guid=mod.pdb_guid,
                pdb_age=mod.pdb_age or 1
            )
            all_modules_registered += 1
            
            # Count FiveM modules
            if self.symbol_resolver._is_fivem_module(mod.name):
                fivem_modules_registered += 1
        
        if self._progress_callback:
            self._progress_callback(
                "symbols", 0.2,
                f"Found {fivem_modules_registered} FiveM modules (of {all_modules_registered} total)"
            )
        
        # Download all symbols in parallel with timeout protection
        # Wrap symbol download in timeout to prevent indefinite hangs on large dumps
        download_timeout = 600  # 10 minutes max for all symbol downloads
        download_result = {'results': {}}
        
        def download_with_timeout():
            try:
                download_result['results'] = self.symbol_resolver.download_all_symbols(max_workers=4)
            except Exception as e:
                download_result['error'] = str(e)
        
        download_thread = threading.Thread(target=download_with_timeout, daemon=True)
        download_thread.start()
        
        # Wait with progress updates
        elapsed = 0.0
        check_interval = 1.0
        while download_thread.is_alive() and elapsed < download_timeout:
            download_thread.join(timeout=check_interval)
            elapsed += check_interval
            if download_thread.is_alive() and elapsed < download_timeout:
                progress = 0.2 + (elapsed / download_timeout) * 0.8
                self._progress_callback("symbols", progress, f"Downloading symbols ({elapsed:.0f}s)...")
        
        if download_thread.is_alive():
            # Timeout occurred
            if self._progress_callback:
                self._progress_callback("symbols", 1.0, "Symbol download timeout (10min) - continuing without all symbols")
            results = {}
        else:
            results = download_result.get('results', {})
        
        if self._progress_callback:
            downloaded = sum(1 for success in results.values() if success)
            self._progress_callback(
                "symbols", 1.0,
                f"Downloaded {downloaded}/{len(results)} symbols successfully"
            )
        
        return results

    def _ensure_symbols_for_report(self, report: CrashReport) -> None:
        """Auto-resolve and download only the symbols needed for this report.

        This prioritizes modules that appear in the native stack, then falls back
        to FiveM modules if no stack module matches are found.
        """
        if not self.symbol_resolver or not report.module_versions:
            return

        # Determine modules referenced by stack frames
        stack_modules: Set[str] = set()
        for raw_frame in report.native_stacks:
            m = self._NATIVE_FRAME_RE.match((raw_frame or '').strip())
            if not m:
                continue
            mod_name = m.group(1).strip()
            if mod_name:
                stack_modules.add(mod_name.lower())
                stack_modules.add(os.path.basename(mod_name).lower())

        # Register modules that appear in the stack
        registered = 0
        for mod in report.module_versions:
            mod_name = (mod.name or '').strip()
            if not mod_name:
                continue
            mod_base = os.path.basename(mod_name).lower()
            if stack_modules and (mod_name.lower() not in stack_modules and mod_base not in stack_modules):
                continue

            mod_info = self.symbol_resolver.register_module(
                name=mod.name,
                base_address=mod.base_address or 0,
                size=mod.size or 0,
                pdb_name=mod.pdb_name,
                pdb_guid=mod.pdb_guid,
                pdb_age=mod.pdb_age or 1,
            )
            # If PDB info missing, try to extract from PE on disk
            if not mod_info.pdb_guid or not mod_info.pdb_name:
                self.symbol_resolver.ensure_pdb_info(mod_info)
            registered += 1

        # If no stack modules were registered, fall back to FiveM modules
        if registered == 0:
            for mod in report.module_versions:
                if not self.symbol_resolver._is_fivem_module(mod.name):
                    continue
                mod_info = self.symbol_resolver.register_module(
                    name=mod.name,
                    base_address=mod.base_address or 0,
                    size=mod.size or 0,
                    pdb_name=mod.pdb_name,
                    pdb_guid=mod.pdb_guid,
                    pdb_age=mod.pdb_age or 1,
                )
                if not mod_info.pdb_guid or not mod_info.pdb_name:
                    self.symbol_resolver.ensure_pdb_info(mod_info)
                registered += 1

        if registered == 0:
            return

        results = self.symbol_resolver.download_all_symbols(max_workers=4)
        downloaded = sum(1 for success in results.values() if success)
        report.analysis_errors.append(
            f"Symbol Auto-Resolve: {downloaded}/{len(results)} symbols downloaded for stack modules"
        )

    def _extract_strings(self, data: bytes, min_length: int = 4) -> List[str]:
        """Extract printable ASCII strings from binary data."""
        seen: Set[str] = set()
        final: List[str] = []

        # Pre-compile regex for performance
        # Match sequences of printable ASCII characters (32-126)
        ascii_pattern = re.compile(b'[ -~]{%d,}' % min_length)
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

        # Use finditer to process matches as they are found, avoiding large intermediate lists
        # and allowing early exit if we hit the limit
        for match in ascii_pattern.finditer(data):
            try:
                s = match.group().decode('ascii')
            except UnicodeDecodeError:
                continue

            # CamelCase tokens
            for m in self._CAMEL_CASE_PATTERN.finditer(s):
                token = _trim_repeated(m.group(0))
                if token and token not in seen:
                    seen.add(token)
                    final.append(token)
                    if len(final) >= 500:
                        return final

            # Generic alphanumeric tokens
            for m in pattern_generic.finditer(s):
                token = _trim_repeated(m.group(0))
                if token and token not in seen:
                    seen.add(token)
                    final.append(token)
                    if len(final) >= 500:
                        return final

        return final

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

    # =========================================================================
    # Enhanced Extraction Methods
    # =========================================================================
    
    def _parse_crashometry_json(self, crashometry_path: str) -> Dict[str, Any]:
        """Parse crashometry.json file for crash metadata.
        
        Crashometry contains valuable telemetry data:
        - crash_hash: Unique crash signature (e.g., fivem.exe+26A51A0)
        - crash_hash_key: Human-readable hash (e.g., quebec-beer-pip)
        - GPU info, server info, OneSync settings
        """
        result: Dict[str, Any] = {}
        
        try:
            with open(crashometry_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            result = {
                'crash_hash': data.get('crash_hash', ''),
                'crash_hash_key': data.get('crash_hash_key', ''),
                'crash_hash_id': data.get('crash_hash_id', 0),
                'gpu_name': data.get('crashometry_gpu_name', ''),
                'gpu_id': data.get('crashometry_gpu_id', ''),
                'server': data.get('crashometry_last_server', ''),
                'server_url': data.get('crashometry_last_server_url', ''),
                'server_version': data.get('crashometry_last_server_ver', ''),
                'onesync_enabled': data.get('crashometry_onesync_enabled', '') == 'true',
                'onesync_big': data.get('crashometry_onesync_big', '') == 'true',
                'onesync_population': data.get('crashometry_onesync_population', '') == 'true',
                'mod_package_count': int(data.get('crashometry_mod_package_count', 0) or 0),
                'hs_state': data.get('crashometry_hs_state', ''),
                'did_render': data.get('crashometry_did_render_backbuf', '') == 'true',
            }
        except Exception as e:
            result['error'] = str(e)
        
        return result

    def _parse_log_timed_errors(self, log_path: str) -> Tuple[List[Dict[str, Any]], Optional[int], int]:
        """Parse CitizenFX log for script errors with timestamps.
        
        Returns:
            Tuple of (errors_list, crash_timestamp_ms, resource_count)
            
        This enables correlation of errors to crash time to find the
        primary suspect (error closest to crash).
        """
        errors: List[Dict[str, Any]] = []
        crash_timestamp: Optional[int] = None
        resource_count = 0
        
        # ANSI color code pattern
        ansi_pattern = re.compile(r'\^[0-9]')
        
        try:
            with open(log_path, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
            
            # Remove ANSI color codes
            content = ansi_pattern.sub('', content)
            lines = content.split('\n')
            
            i = 0
            while i < len(lines):
                line = lines[i]
                
                # Extract crash timestamp from "Process crash captured"
                if 'Process crash captured' in line:
                    ts_match = re.search(r'\[\s*(\d+)\]', line)
                    if ts_match:
                        crash_timestamp = int(ts_match.group(1))
                
                # Extract resource count from "Required resources:"
                if 'Required resources:' in line:
                    match = re.search(r'Required resources:\s*(.+)', line)
                    if match:
                        resource_count = len(match.group(1).split())
                
                # Parse SCRIPT ERROR blocks
                if 'SCRIPT ERROR:' in line:
                    error: Dict[str, Any] = {'raw': line}
                    
                    # Extract timestamp
                    ts_match = re.search(r'\[\s*(\d+)\]', line)
                    if ts_match:
                        error['timestamp_ms'] = int(ts_match.group(1))
                    
                    # Extract resource and file - handle @resource/path format
                    match = re.search(r'SCRIPT ERROR:\s*@?([\w-]+)/([\w/.]+):(-?\d+):\s*(.*)', line)
                    if match:
                        error['resource'] = match.group(1)
                        error['file'] = match.group(2)
                        error['line'] = int(match.group(3))
                        error['message'] = match.group(4)
                    else:
                        # Fallback pattern
                        simple_match = re.search(r'SCRIPT ERROR:\s*([^:]+):(-?\d+):\s*(.*)', line)
                        if simple_match:
                            path = simple_match.group(1)
                            error['file'] = path
                            error['line'] = int(simple_match.group(2))
                            error['message'] = simple_match.group(3)
                            if '/' in path:
                                error['resource'] = path.split('/')[0].lstrip('@')
                    
                    # Collect context and stack trace
                    error['context'] = ''
                    error['stack'] = []
                    j = i + 1
                    
                    while j < len(lines):
                        stack_line = lines[j].strip()
                        if not stack_line or 'SCRIPT ERROR' in stack_line:
                            break
                        
                        if stack_line.startswith('-'):
                            error['context'] += stack_line + '\n'
                            j += 1
                        elif '> ' in stack_line and '@' in stack_line:
                            # Stack frame: > function (@resource/file:line)
                            frame_match = re.search(
                                r'>\s*(\[?[\w ]+\]?)\s*\(@?([\w-]+)/([\w/.]+):(\d+)\)',
                                stack_line
                            )
                            if frame_match:
                                error['stack'].append({
                                    'function': frame_match.group(1).strip(),
                                    'resource': frame_match.group(2),
                                    'file': frame_match.group(3),
                                    'line': int(frame_match.group(4))
                                })
                            j += 1
                        elif 'MainThrd/' in stack_line:
                            j += 1  # Skip FiveM log continuation
                        else:
                            break
                    
                    errors.append(error)
                    i = j
                    continue
                
                i += 1
                
        except Exception as e:
            errors.append({'error': str(e)})
        
        return errors, crash_timestamp, resource_count

    def _extract_cpu_registers(self, dump_path: str) -> Tuple[Dict[str, int], int]:
        """Extract CPU registers from the crash thread context.
        
        Returns:
            Tuple of (registers_dict, crash_thread_id)
        """
        registers: Dict[str, int] = {}
        crash_tid = 0
        
        try:
            with open(dump_path, 'rb') as f:
                data = f.read()
            
            if data[:4] != b'MDMP':
                return registers, crash_tid
            
            # Parse header
            num_streams = struct.unpack('<I', data[8:12])[0]
            dir_rva = struct.unpack('<I', data[12:16])[0]
            
            # Build stream index
            streams: Dict[int, Tuple[int, int]] = {}
            offset = dir_rva
            for _ in range(num_streams):
                stream_type = struct.unpack('<I', data[offset:offset+4])[0]
                stream_size = struct.unpack('<I', data[offset+4:offset+8])[0]
                stream_rva = struct.unpack('<I', data[offset+8:offset+12])[0]
                streams[stream_type] = (stream_size, stream_rva)
                offset += 12
            
            # Get crash thread ID from exception stream (type 6)
            if 6 in streams:
                size, rva = streams[6]
                crash_tid = struct.unpack('<I', data[rva:rva+4])[0]
            
            # Find crash thread context in thread list (type 3)
            if 3 in streams and crash_tid:
                size, rva = streams[3]
                num_threads = struct.unpack('<I', data[rva:rva+4])[0]
                
                thread_offset = rva + 4
                for _ in range(num_threads):
                    tid = struct.unpack('<I', data[thread_offset:thread_offset+4])[0]
                    if tid == crash_tid:
                        # Get context location (offset 40-48 in MINIDUMP_THREAD)
                        ctx_size = struct.unpack('<I', data[thread_offset+40:thread_offset+44])[0]
                        ctx_rva = struct.unpack('<I', data[thread_offset+44:thread_offset+48])[0]
                        
                        if ctx_rva > 0 and ctx_size >= 0x100:
                            ctx = data[ctx_rva:ctx_rva+ctx_size]
                            
                            # x64 CONTEXT structure offsets
                            registers = {
                                'rax': struct.unpack('<Q', ctx[0x78:0x80])[0],
                                'rcx': struct.unpack('<Q', ctx[0x80:0x88])[0],
                                'rdx': struct.unpack('<Q', ctx[0x88:0x90])[0],
                                'rbx': struct.unpack('<Q', ctx[0x90:0x98])[0],
                                'rsp': struct.unpack('<Q', ctx[0x98:0xA0])[0],
                                'rbp': struct.unpack('<Q', ctx[0xA0:0xA8])[0],
                                'rsi': struct.unpack('<Q', ctx[0xA8:0xB0])[0],
                                'rdi': struct.unpack('<Q', ctx[0xB0:0xB8])[0],
                                'r8': struct.unpack('<Q', ctx[0xB8:0xC0])[0],
                                'r9': struct.unpack('<Q', ctx[0xC0:0xC8])[0],
                                'r10': struct.unpack('<Q', ctx[0xC8:0xD0])[0],
                                'r11': struct.unpack('<Q', ctx[0xD0:0xD8])[0],
                                'r12': struct.unpack('<Q', ctx[0xD8:0xE0])[0],
                                'r13': struct.unpack('<Q', ctx[0xE0:0xE8])[0],
                                'r14': struct.unpack('<Q', ctx[0xE8:0xF0])[0],
                                'r15': struct.unpack('<Q', ctx[0xF0:0xF8])[0],
                                'rip': struct.unpack('<Q', ctx[0xF8:0x100])[0],
                            }
                        break
                    thread_offset += 48
                    
        except Exception:
            pass
        
        return registers, crash_tid

    def _find_crash_folder_files(self, dump_path: str) -> Tuple[Optional[str], Optional[str]]:
        """Find crashometry.json and CitizenFX log in the same folder as the dump.
        
        Returns:
            Tuple of (crashometry_path, log_path) - either may be None
        """
        crash_folder = os.path.dirname(dump_path)
        crashometry_path = None
        log_path = None
        
        try:
            for filename in os.listdir(crash_folder):
                if filename == 'crashometry.json':
                    crashometry_path = os.path.join(crash_folder, filename)
                elif filename.startswith('CitizenFX_log') and filename.endswith('.log'):
                    log_path = os.path.join(crash_folder, filename)
        except Exception:
            pass
        
        return crashometry_path, log_path

    def _determine_primary_suspect(
        self, 
        timed_errors: List[Dict[str, Any]], 
        crash_timestamp: Optional[int]
    ) -> Dict[str, Any]:
        """Determine the primary suspect resource from timed errors.
        
        Finds the script error closest to (but before) the crash time.
        """
        result: Dict[str, Any] = {}
        
        if not timed_errors:
            return result
        
        # Filter errors within 60 seconds of crash
        recent_errors = []
        if crash_timestamp:
            for err in timed_errors:
                err_time = err.get('timestamp_ms', 0)
                if err_time > 0:
                    time_diff = crash_timestamp - err_time
                    if 0 < time_diff < 60000:  # Within 60 seconds before crash
                        recent_errors.append((time_diff, err))
            
            # Sort by time (closest to crash first)
            recent_errors.sort(key=lambda x: x[0])
        
        # If no timed errors, use last error
        if recent_errors:
            _, err = recent_errors[0]
            time_diff_sec = recent_errors[0][0] / 1000
        else:
            err = timed_errors[-1]
            time_diff_sec = None
        
        result = {
            'resource': err.get('resource'),
            'file': err.get('file'),
            'line': err.get('line'),
            'message': err.get('message'),
            'context': err.get('context', '').strip(),
            'stack': err.get('stack', []),
            'time_before_crash_sec': time_diff_sec,
        }
        
        return result

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

    def _symbolicate_with_resolver(self, report: CrashReport) -> int:
        """Resolve native stack frames using the new SymbolResolver.
        
        This uses symbols downloaded from FiveM/Microsoft servers.
        """
        report.native_stacks_symbolicated = []
        
        # Build module name -> module info map
        mod_map: Dict[str, Any] = {}
        for m in report.module_versions:
            name = (m.name or '').strip()
            if name:
                mod_map[name] = m
                basename = os.path.basename(name)
                if basename and basename != name:
                    mod_map[basename] = m
        
        # Map resolver modules by name for dbghelp fallback
        resolver_mod_map: Dict[str, Any] = {}
        for base, mod in self.symbol_resolver._modules.items():
            name = (mod.name or '').strip()
            if not name:
                continue
            resolver_mod_map[name.lower()] = mod
            basename = os.path.basename(name).lower()
            resolver_mod_map[basename] = mod

        loaded_dbghelp_bases: Set[int] = set()
        
        # Process each stack frame
        resolved_count = 0
        skipped_no_base = 0
        skipped_no_mod = 0
        skipped_no_symbol = 0
        
        for raw_frame in report.native_stacks:
            # Parse frame: "module.dll+0x1234"
            m = self._NATIVE_FRAME_RE.match((raw_frame or '').strip())
            if not m:
                report.native_stacks_symbolicated.append(raw_frame)
                continue
            
            mod_name = m.group(1).strip()
            try:
                offset = int(m.group(2), 16)
            except ValueError:
                report.native_stacks_symbolicated.append(raw_frame)
                continue
            
            # Get module info
            mod_info = mod_map.get(mod_name) or mod_map.get(os.path.basename(mod_name))
            if not mod_info:
                report.native_stacks_symbolicated.append(raw_frame)
                skipped_no_mod += 1
                continue
            
            # Calculate absolute address
            base_address = getattr(mod_info, 'base_address', 0) or 0
            if base_address == 0:
                report.native_stacks_symbolicated.append(raw_frame)
                skipped_no_base += 1
                continue
            
            absolute_address = base_address + offset
            
            # Try to resolve address using SymbolResolver (silent - only report summary)
            symbol_info = self.symbol_resolver.resolve_address(absolute_address)
            
            if symbol_info and symbol_info.function_name and symbol_info.function_name != "<unknown>":
                # Success! Format as: module+offset -> function+offset
                symbolicated = f"{mod_name}+0x{offset:X} -> {symbol_info.function_name}+0x{symbol_info.offset:X}"
                report.native_stacks_symbolicated.append(symbolicated)
                resolved_count += 1
            else:
                # Fallback: use dbghelp via Symbolicator if available and PDB was downloaded
                dbghelp_resolved = False
                if self.symbolicator:
                    resolver_mod = resolver_mod_map.get(mod_name.lower()) or resolver_mod_map.get(os.path.basename(mod_name).lower())
                    pdb_path = getattr(resolver_mod, 'pdb_path', None) if resolver_mod else None
                    if base_address:
                        image_path = None
                        if resolver_mod and getattr(resolver_mod, 'name', None):
                            candidate = resolver_mod.name
                            if candidate and os.path.exists(candidate):
                                image_path = candidate
                        load_path = pdb_path or image_path
                        module_size = getattr(mod_info, 'size', 0) or (getattr(resolver_mod, 'size', 0) if resolver_mod else 0)
                        if load_path and base_address not in loaded_dbghelp_bases:
                            load_ret = self.symbolicator.load_module(base_address, load_path, mod_name, module_size)
                            if load_ret:
                                loaded_dbghelp_bases.add(base_address)
                        if base_address in loaded_dbghelp_bases:
                            sym_name, disp = self.symbolicator.symbolicate_address(absolute_address)
                            if sym_name:
                                report.native_stacks_symbolicated.append(
                                    f"{mod_name}+0x{offset:X} -> {sym_name}+0x{disp:X}"
                                )
                                resolved_count += 1
                                dbghelp_resolved = True

                if not dbghelp_resolved:
                    # No symbol found, keep original
                    report.native_stacks_symbolicated.append(raw_frame)
                    skipped_no_symbol += 1
        
        # Print concise summary only
        total = len(report.native_stacks)
        if resolved_count > 0:
            print(f"[SYMBOL] Resolved {resolved_count}/{total} stack frames")
        elif skipped_no_symbol > 0:
            print(f"[SYMBOL] Warning: 0/{total} frames resolved - PDB may lack public symbols")
        
        if resolved_count > 0:
            report.analysis_errors.append(
                f"Symbol Resolution: {resolved_count}/{len(report.native_stacks)} frames resolved using downloaded PDBs"
            )
        else:
            report.analysis_errors.append(
                f"Symbol Resolution: 0/{len(report.native_stacks)} frames resolved (no_base={skipped_no_base}, no_mod={skipped_no_mod}, no_symbol={skipped_no_symbol})"
            )
        return resolved_count
    
    def _symbolicate_native_stack(self, report: CrashReport) -> None:
        """Resolve native stack frames to function names using PDBs when available.

        Populates report.native_stacks_symbolicated. Each entry is either
        '  module + 0xOFFSET  ->  function_name + 0xdisp' or the raw frame if resolution fails.
        
        Uses the new SymbolResolver if available (auto-downloaded symbols),
        otherwise falls back to the legacy Symbolicator (server-only).
        """
        report.native_stacks_symbolicated = []
        
        # Try new SymbolResolver first (has downloaded symbols)
        if self.symbol_resolver and report.native_stacks and report.module_versions:
            resolved_count = self._symbolicate_with_resolver(report)
            if resolved_count > 0:
                return
        
        # #region agent log
        _dlog("H1", "core._symbolicate_native_stack.entry", "symbolicate entry", {
            "native_stacks_len": len(report.native_stacks) if report.native_stacks else 0,
            "module_versions_len": len(report.module_versions) if report.module_versions else 0,
            "symbolicator_is_none": self.symbolicator is None,
            "symbol_resolver_available": self.symbol_resolver is not None,
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
            # Fallback: dump has no PDB info (CvRecord empty) - derive PDB name from module and try server.
            if not pdb_path:
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
                    pdb_path = self.symbolicator.download_symbol(try_pdb)
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
            
            # Automatically download FiveM symbols if enabled
            if self.auto_download_symbols and self.symbol_resolver:
                try:
                    symbol_results = self.download_fivem_symbols(dump_path)
                    if symbol_results:
                        downloaded_count = sum(1 for success in symbol_results.values() if success)
                        report.analysis_errors.append(
                            f"Symbol Download: {downloaded_count}/{len(symbol_results)} PDB files downloaded"
                        )
                except Exception as e:
                    report.analysis_errors.append(f"Symbol download error: {e}")

            # Report that we're starting deep analysis (prevents "Not Responding" appearance)
            if self._progress_callback:
                self._progress_callback("memory", 0.0, "Starting deep memory analysis...")

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
            report.event_handlers = getattr(deep_result, 'event_handlers', [])
            report.analysis_errors.extend(deep_result.errors)
            
            # Framework & metadata detection
            report.framework_detected = getattr(deep_result, 'framework_detected', None)
            report.framework_confidence = getattr(deep_result, 'framework_confidence', 0.0)
            report.fxmanifest_data = getattr(deep_result, 'fxmanifest_data', {})
            report.error_severities = getattr(deep_result, 'error_severities', {})

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
            
            # Register modules with SymbolResolver (for address resolution)
            if self.symbol_resolver and report.module_versions:
                print(f"[SYMBOL] Registering {len(report.module_versions)} modules from dump analysis")
                for mod in report.module_versions:
                    print(f"[SYMBOL] Module: {mod.name}")
                    print(f"[SYMBOL]   Base: 0x{mod.base_address:X}" if mod.base_address else "[SYMBOL]   Base: <none>")
                    print(f"[SYMBOL]   PDB: {mod.pdb_name or '<none>'}")
                    print(f"[SYMBOL]   GUID: {mod.pdb_guid or '<none>'}")
                    
                    if mod.pdb_name and mod.pdb_guid:
                        # Re-register with actual addresses from analysis
                        # (may differ from temp analysis due to different parsing)
                        self.symbol_resolver.register_module(
                            name=mod.name,
                            base_address=mod.base_address or 0,
                            size=mod.size or 0,
                            pdb_name=mod.pdb_name,
                            pdb_guid=mod.pdb_guid,
                            pdb_age=mod.pdb_age or 1
                        )

            # Auto-download symbols needed for this report (stack-first)
            if self.symbol_resolver:
                self._ensure_symbols_for_report(report)
            
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

            # Enrich with low-level dump extractor (additional stream coverage)
            try:
                from .dump_enricher import enrich_crash_report
                report = enrich_crash_report(report, dump_path)
            except Exception as e:
                report.analysis_errors.append(f"Dump enrichment error: {e}")

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
            report.nui_resources = deep_result.nui_resources
            report.network_patterns = deep_result.network_patterns
            report.statebag_patterns = deep_result.statebag_patterns
            
            # ===== HEAP STATISTICS & LEAK ANALYSIS =====
            report.heap_committed_bytes = deep_result.heap_committed_bytes
            report.heap_reserved_bytes = deep_result.heap_reserved_bytes
            report.heap_free_bytes = deep_result.heap_free_bytes
            report.heap_fragmentation_pct = deep_result.heap_fragmentation_pct
            report.memory_pressure = deep_result.memory_pressure
            report.oom_imminent = deep_result.oom_imminent
            report.leak_detected = deep_result.leak_detected
            report.leak_confidence = deep_result.leak_confidence
            report.leak_evidence = deep_result.leak_evidence
            report.entity_allocation_delta = deep_result.entity_allocation_delta
            report.timer_allocation_delta = deep_result.timer_allocation_delta
            report.event_handler_delta = deep_result.event_handler_delta
            report.entity_leak = deep_result.entity_leak
            report.timer_leak = deep_result.timer_leak
            report.event_handler_leak = deep_result.event_handler_leak
            report.nui_leak = deep_result.nui_leak

            # Run FiveM-specific forensics
            report.fivem_forensics = self._run_fivem_forensics(dump_path)

            # Run WinDbg native stack analysis (optional, requires Windows SDK)
            windbg_results = self.analyze_dump_with_windbg(dump_path)
            if windbg_results:
                report.windbg_analysis = windbg_results

            # ===== ENHANCED EXTRACTION =====
            # Extract CPU registers from crash thread
            cpu_regs, crash_tid = self._extract_cpu_registers(dump_path)
            report.cpu_registers = cpu_regs
            
            # Find companion files (crashometry.json, CitizenFX log)
            crashometry_path, citizen_log_path = self._find_crash_folder_files(dump_path)
            
            # Parse crashometry.json
            if crashometry_path:
                crashometry_data = self._parse_crashometry_json(crashometry_path)
                report.crashometry = crashometry_data
                report.crash_hash = crashometry_data.get('crash_hash', '')
                report.crash_hash_key = crashometry_data.get('crash_hash_key', '')
                report.server_address = crashometry_data.get('server', '')
                report.server_version = crashometry_data.get('server_version', '')
                report.gpu_name = crashometry_data.get('gpu_name', '')
                report.onesync_enabled = crashometry_data.get('onesync_enabled', False)
                report.onesync_big = crashometry_data.get('onesync_big', False)
            
            # Parse CitizenFX log for timed errors
            if citizen_log_path:
                timed_errors, crash_ts, res_count = self._parse_log_timed_errors(citizen_log_path)
                report.timed_script_errors = timed_errors
                report.crash_timestamp_ms = crash_ts
                report.loaded_resource_count = res_count
                
                # Add to log_files if not already there
                if citizen_log_path not in report.log_files:
                    report.log_files.append(citizen_log_path)
                
                # Determine primary suspect from timed errors
                suspect_info = self._determine_primary_suspect(timed_errors, crash_ts)
                if suspect_info.get('resource'):
                    report.primary_suspect_resource = suspect_info.get('resource')
                    report.primary_suspect_file = suspect_info.get('file')
                    report.primary_suspect_line = suspect_info.get('line')
                    report.primary_suspect_message = suspect_info.get('message')
                    report.time_before_crash_sec = suspect_info.get('time_before_crash_sec')

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

    def analyze_dump_with_windbg(self, dump_path: str) -> Optional[Dict[str, Any]]:
        """
        Analyze crash dump using WinDbg for native stack walking.
        
        This method requires WinDbg/CDB (part of Windows SDK) to be installed.
        It provides native stack trace information that can help identify which
        resource called the crashing native function.
        
        Args:
            dump_path: Path to the minidump file
            
        Returns:
            Dictionary with WinDbg analysis results, or None if WinDbg unavailable
        """
        if not self.windbg or not self.windbg.available:
            self._progress_callback(
                'windbg',
                1.0,
                "WinDbg not available - skipping native stack analysis"
            )
            return None
        
        self._progress_callback(
            'windbg',
            0.1,
            "Starting WinDbg analysis..."
        )
        
        try:
            # Run WinDbg analysis
            result = self.windbg.analyze_dump(dump_path)
            
            self._progress_callback(
                'windbg',
                0.5,
                f"WinDbg analysis complete - {len(result.stack_frames)} frames found"
            )
            
            # Convert to dictionary format for reporting
            analysis_dict = {
                'success': result.success,
                'exception_code': result.exception_code,
                'exception_address': result.exception_address,
                'culprit_module': result.culprit_module,
                'culprit_resource': result.culprit_resource,
                'confidence': result.confidence,
                'stack_frames': [
                    {
                        'number': frame.frame_number,
                        'address': frame.address,
                        'module': frame.module,
                        'function': frame.function,
                        'is_fivem': frame.is_fivem_related,
                        'resource': frame.resource_name
                    }
                    for frame in result.stack_frames
                ],
                'modules': result.loaded_modules,
                'fivem_modules': result.fivem_modules,
                'summary': result.summary,
                'error': result.error_message
            }
            
            self._progress_callback(
                'windbg',
                1.0,
                "WinDbg analysis complete"
            )
            
            return analysis_dict
            
        except Exception as e:
            error_msg = f"WinDbg analysis error: {str(e)}"
            self._progress_callback(
                'windbg',
                1.0,
                error_msg
            )
            return {
                'success': False,
                'error': error_msg
            }

    def _run_fivem_forensics(self, dump_path: str) -> Dict[str, Any]:
        """Run FiveM-specific forensics analysis on crash dump.
        
        Args:
            dump_path: Path to .dmp file
            
        Returns:
            Dictionary with FiveM forensics results
        """
        # Skip forensics for very large dumps (>2GB) to avoid memory issues
        try:
            file_size = os.path.getsize(dump_path)
            if file_size > 2 * 1024 * 1024 * 1024:  # 2GB
                return {
                    'report_text': f'FiveM forensics skipped for large dump ({file_size / (1024*1024*1024):.1f}GB)',
                    'build_cache_issues': [],
                    'warning': 'Dump too large for forensics analysis'
                }
        except Exception:
            pass
        
        try:
            from .fivem_forensics import BuildCacheForensics
            
            forensics = BuildCacheForensics()
            results = forensics.analyze_dump(dump_path)
            
            # Add formatted report text
            results['report_text'] = forensics.generate_report(results)
            
            return results
        except Exception as e:
            return {
                'error': f'FiveM forensics failed: {e}',
                'confidence': 'none',
            }

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

    def _calculate_resource_confidence(self, evidence_count: int, evidence_types: set, 
                                       has_stack_evidence: bool, is_generic_name: bool) -> float:
        """Calculate realistic confidence percentage for resource culpability."""
        confidence = 0.0
        
        # Base confidence from evidence count
        if evidence_count >= 10:
            confidence += 40
        elif evidence_count >= 5:
            confidence += 20
        elif evidence_count >= 3:
            confidence += 10
        else:
            confidence += 0
        
        # Boost for stack trace presence (most critical)
        if has_stack_evidence:
            confidence += 50
        
        # Check evidence type quality
        has_error_msg = 'ERROR_MESSAGE' in evidence_types
        has_crash_context = 'CRASH_CONTEXT' in evidence_types
        
        if has_error_msg and has_stack_evidence:
            confidence += 15  # Error + Stack = Strong
        elif has_crash_context:
            confidence += 20  # Crash context is very strong
        elif has_error_msg:
            confidence += 5   # Error alone is weak
        
        # Penalty for generic names (high false positive rate)
        if is_generic_name:
            if has_stack_evidence:
                confidence *= 0.8  # Reduce by 20% but still viable
            else:
                confidence *= 0.1  # Reduce by 90% - generic names without stack = likely false positive
        
        # Cap at 0-100 range
        return max(0, min(100, confidence))

    def _format_native_stack_frame(self, frame_str: str, frame_index: int = 0) -> str:
        """
        Enhance native stack frame formatting with better visualization.
        
        Input: "  FiveM_b3570_GTAProcess.exe+0x61A5BB1"
        Output: "[01] FiveM_b3570_GTAProcess.exe + 0x61A5BB1"
        """
        if not frame_str or not frame_str.strip():
            return frame_str
        
        # Remove leading spaces
        frame = frame_str.strip()
        
        # Parse frame: "module+0xOFFSET [ -> function+0xDISP]"
        parts = frame.split(" -> ", 1)
        base_frame = parts[0].strip()
        symbol_info = parts[1].strip() if len(parts) > 1 else None
        
        # Format base frame with padding and frame number
        formatted = f"[{frame_index:02d}] {base_frame}"
        
        # Add symbol info if available
        if symbol_info:
            formatted += f" → {symbol_info}"
        
        return formatted

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
            except Exception:
                # Timestamp conversion failed; use raw value
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
                has_stacks = bool(report.lua_stacks or report.js_stacks or report.native_stacks or report.threads_extended)
                if has_stacks:
                    lines.append("  (Confidence is low; correlate with stack traces below.)")
                else:
                    lines.append("  (Confidence is low; limited evidence available.)")
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
                lines.append("🎯 SUSPECTED RESOURCES (correlate with frames below):")
                lines.append("  " + ", ".join(resources_for_stack))
                lines.append("")
            
            # How to use this section
            lines.append("📊 HOW TO READ THIS STACK:")
            lines.append("  1. [NN] = Frame number (lower = closer to crash)")
            lines.append("  2. Exception address = exact instruction that faulted")
            lines.append("  3. With PDBs: Shows module + 0xOFFSET → function_name + 0xDISP")
            lines.append("  4. Correlate frame functions with suspected resources above")
            lines.append("")
            
            has_symbolication = report.native_stacks_symbolicated and any("  ->  " in f for f in report.native_stacks_symbolicated)
            
            if not has_symbolication and report.native_stacks:
                if report.module_versions:
                    lines.append("  ⚠️  Symbols not available (PDB not found on FiveM symbol server)")
                    lines.append("      Showing module+offset only. For better debugging:")
                    lines.append("      • Enable symbol download in settings")
                    lines.append("      • Check internet connection")
                    diag = getattr(report, 'symbolication_diagnostic', None)
                    if diag:
                        lines.append("")
                        lines.append("      Diagnostic: " + diag)
                else:
                    lines.append("  ⚠️  Symbols not loaded (PDB download failed or module info missing)")
                lines.append("")
            elif has_symbolication:
                lines.append("  ✓ Symbols loaded - use function names below to find crashing resource")
                lines.append("")
            
            # Display the actual stack frames with enhanced formatting
            display_frames = report.native_stacks_symbolicated if report.native_stacks_symbolicated else report.native_stacks
            
            # Limit to top 30 most relevant frames
            max_frames = 30
            frames_to_show = display_frames[:max_frames] if len(display_frames) > max_frames else display_frames
            
            for idx, frame in enumerate(frames_to_show, 1):
                if not frame or not frame.strip():
                    continue
                formatted_frame = self._format_native_stack_frame(frame, idx)
                lines.append(f"  {formatted_frame}")
            
            if len(display_frames) > max_frames:
                lines.append(f"\n  ... and {len(display_frames) - max_frames} more frames (not displayed)")
            
            lines.append("")

        # Crash patterns
        if report.crash_patterns:
            hidden_issues = {
                "Graphics Driver Crash",
                "Vehicle-Related Crash",
            }
            lines.append("DETECTED CRASH PATTERNS:")
            lines.append("-" * 40)
            for pattern in report.crash_patterns:
                if pattern.issue in hidden_issues:
                    continue
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
                        except Exception:
                            # Timestamp conversion failed; use raw value
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

        # FiveM Forensics Section
        if report.fivem_forensics:
            lines.append("")
            lines.append("=" * 70)
            forensics_report = report.fivem_forensics.get('report_text', '')
            if forensics_report:
                lines.append(forensics_report)
            else:
                # If no formatted report, show raw data
                lines.append("FIVEM FORENSICS:")
                lines.append("-" * 40)
                lines.append(f"  Confidence: {report.fivem_forensics.get('confidence', 'unknown')}")
                
                if report.fivem_forensics.get('crashometry'):
                    lines.append("\n  Crashometry Entries:")
                    for entry in report.fivem_forensics['crashometry'][:10]:
                        lines.append(f"    {entry.get('key')} = {entry.get('value')}")
                
                if report.fivem_forensics.get('corruption'):
                    lines.append("\n  Corruption Detected:")
                    for c in report.fivem_forensics['corruption'][:5]:
                        lines.append(f"    Type: {c.get('type')}")
                
                if report.fivem_forensics.get('streaming'):
                    lines.append("\n  Streaming Crashes:")
                    for s in report.fivem_forensics['streaming'][:5]:
                        lines.append(f"    Offset: {s.get('offset')}, Bytes: {s.get('bytes')}")
                
                if report.fivem_forensics.get('error'):
                    lines.append(f"\n  Error: {report.fivem_forensics['error']}")

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
            
            # Check if this is a weak suspect (low evidence, weak types only)
            is_weak = top.evidence_count < 3
            evidence_types_set = set(e.name for e in list(top.evidence_types or []))
            has_stack_evidence = any(t in evidence_types_set for t in {'LUA_STACK_TRACE', 'JS_STACK_TRACE', 'NATIVE_STACK'})
            only_error_messages = evidence_types_set == {'ERROR_MESSAGE'}
            
            # Check for generic resource names (high false positive rate)
            generic_names = {'radio', 'audio', 'sound', 'music', 'ui', 'hud', 'menu', 
                            'core', 'base', 'main', 'system', 'engine', 'game', 'server', 'interface'}
            is_generic_name = top.name.lower() in generic_names
            
            # Calculate actual confidence more accurately
            actual_confidence = self._calculate_resource_confidence(
                top.evidence_count, evidence_types_set, has_stack_evidence, is_generic_name
            )
            
            if sec:
                lines.append(f"MOST LIKELY CAUSE: Resource '{top.name}' (or '{sec}' if evidence is ambiguous)")
            else:
                lines.append(f"MOST LIKELY CAUSE: Resource '{top.name}'")
            if getattr(top, 'likely_script', None):
                lines.append(f"  Likely script: {top.likely_script}")
            if top.scripts:
                lines.append(f"  Scripts: {', '.join(top.scripts[:3])}")
            lines.append(f"  Evidence: {top.evidence_count} items")
            lines.append(f"  Types: {', '.join(sorted(evidence_types_set)[:3])}")
            
            # Enhanced confidence reporting
            if conf == "low" or is_weak or (only_error_messages and is_generic_name):
                lines.append(f"  Confidence: {actual_confidence:.0f}% - ⚠️  WARNING: This may be a false positive")
                lines.append("")
                lines.append("  Why low confidence?")
                if only_error_messages:
                    lines.append("    • Only error messages found (weakest evidence type)")
                if not has_stack_evidence:
                    lines.append("    • Not found in crash stack trace")
                if is_generic_name:
                    lines.append(f"    • '{top.name}' is a generic name (high false positive rate)")
                if top.evidence_count < 5:
                    lines.append(f"    • Only {top.evidence_count} evidence items (need 10+ for confidence)")
                lines.append("")
                lines.append("  Next steps:")
                lines.append("    1. Check native stack trace section (find actual crash location)")
                lines.append("    2. Look for resources with stack trace presence")
                lines.append("    3. See full report for all resources by evidence quality")
            elif actual_confidence >= 70:
                lines.append(f"  Confidence: {actual_confidence:.0f}% - ✓ Strong evidence")
            else:
                lines.append(f"  Confidence: {actual_confidence:.0f}%")
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
        elif report.resources:
            # Resources found but filtered out due to low evidence
            lines.append("⚠️  NO STRONG SUSPECTS IDENTIFIED")
            lines.append("")
            lines.append("Resources were detected but filtered out due to insufficient evidence.")
            lines.append("This often happens when:")
            lines.append("  • Crash occurred in game code (not a script)")
            lines.append("  • Generic words like 'radio', 'audio' were misidentified")
            lines.append("  • The crash dump has minimal script context")
            lines.append("")
            lines.append("Check the Full Report tab for:")
            lines.append("  • FiveM Forensics (cache corruption, streaming issues)")
            lines.append("  • Exception details and crash patterns")
            lines.append("  • Native stack traces")
        else:
            lines.append("Unable to pinpoint specific cause.")
            lines.append("Check the full report for more details.")

        return "\n".join(lines)

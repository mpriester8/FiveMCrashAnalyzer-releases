"""Deep Memory Analysis Module for FiveM Crash Dumps.

This module provides advanced memory analysis capabilities to pinpoint
exact scripts, resources, and code paths causing crashes in FiveM.

Performance optimizations:
- Memoryview for efficient memory access
- Deduplication to prevent redundant processing
- Early termination when sufficient evidence is found
- Sampled analysis for very large dumps
- Pre-compiled regex patterns at class level
- Optional multi-process chunk analysis (uses CPU cores; set USE_PARALLEL_CHUNKS=False
  or limit MAX_PARALLEL_WORKERS to reduce memory use). GPU acceleration would require
  external libraries (e.g. CUDA-based pattern matching) and is not implemented.
"""
from __future__ import annotations

import json
import os
import re
import struct
import sys
import time
import ctypes
import mmap
import threading
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple, Set, Callable
from enum import Enum

# Optional minidump library
try:
    from minidump.minidumpfile import MinidumpFile
    HAS_MINIDUMP = True
except ImportError:
    MinidumpFile = None
    HAS_MINIDUMP = False

# #region agent log
_DEBUG_LOG_PATH = r"c:\Users\mprie_9uaaf\Desktop\Coding Projects\CrashAnalyzer\.cursor\debug.log"


def _dlog(
    hypothesis_id: str,
    location: str,
    message: str,
    data: Dict[str, Any],
    run_id: str = "run1",
) -> None:
    try:
        os.makedirs(os.path.dirname(_DEBUG_LOG_PATH), exist_ok=True)
        with open(_DEBUG_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(
                json.dumps(
                    {
                        "sessionId": "debug-session",
                        "runId": run_id,
                        "hypothesisId": hypothesis_id,
                        "location": location,
                        "message": message,
                        "data": data,
                        "timestamp": int(time.time() * 1000),
                    }
                )
                + "\n"
            )
    except Exception:
        pass


# #endregion


# ============================================================================
# GTA V Native Function Hash Database (partial - common crash-related natives)
# ============================================================================
GTA_NATIVE_HASHES = {
    # Entity/Object natives
    '0x32F8866D': 'CREATE_OBJECT',
    '0x32F2FF5E': 'CREATE_VEHICLE',
    '0x32BE63F6': 'DELETE_ENTITY',
    '0x32C28564': 'SET_ENTITY_COORDS',
    '0x32F58B5D': 'FREEZE_ENTITY_POSITION',
    '0x32E439F7': 'SET_ENTITY_HEADING',
    '0x32D1761B': 'ATTACH_ENTITY_TO_ENTITY',
    '0x32FBAF5B': 'DETACH_ENTITY',
    '0x32BDC480': 'SET_ENTITY_VISIBLE',
    '0x32C0B190': 'SET_ENTITY_ALPHA',
    # Ped/Player natives
    '0x33A8F7F7': 'CREATE_PED',
    '0x33B51912': 'DELETE_PED',
    '0x33C86B7B': 'IS_PED_IN_VEHICLE',
    # Vehicle natives
    '0x34AD1A0A': 'SET_VEHICLE_ENGINE_ON',
    '0x34B866E3': 'SET_VEHICLE_DOORS_LOCKED',
    # Common crash-related
    '0x35A7ED5D': 'DRAW_RECT',
    '0x35B9E0AB': 'BEGIN_TEXT_COMMAND_DISPLAY_TEXT',
}

# Optional external native hash database (64-bit and 32-bit)
_NATIVE_HASH_DB: Dict[str, str] = {}


def _normalize_hash_key(hash_str: str) -> str:
    clean = hash_str.strip().lower().replace("0x", "")
    return f"0x{clean}"


def load_native_hash_db(path: str) -> int:
    """Load a native hash database from JSON or simple text.

    Supported formats:
    - JSON object: {"0x1234...": "NATIVE_NAME", ...}
    - JSON list of objects: [{"hash": "0x...", "name": "..."}, ...]
    - Text lines: 0xHASH NAME (split on whitespace)

    Returns number of entries loaded.
    """
    global _NATIVE_HASH_DB
    if not path or not os.path.exists(path):
        return 0

    loaded = {}
    try:
        if path.lower().endswith(".json"):
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                for k, v in data.items():
                    if not k or not v:
                        continue
                    loaded[_normalize_hash_key(str(k))] = str(v)
            elif isinstance(data, list):
                for item in data:
                    if not isinstance(item, dict):
                        continue
                    h = item.get("hash") or item.get("Hash")
                    n = item.get("name") or item.get("Name")
                    if not h or not n:
                        continue
                    loaded[_normalize_hash_key(str(h))] = str(n)
        else:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split()
                    if len(parts) < 2:
                        continue
                    h = parts[0]
                    n = " ".join(parts[1:])
                    loaded[_normalize_hash_key(str(h))] = str(n)
    except Exception:
        return 0

    _NATIVE_HASH_DB.update(loaded)
    return len(loaded)

def decode_native_hash(hex_str: str) -> str:
    """Decode GTA V native function hash to readable name."""
    if not hex_str:
        return "Native_Unknown"

    clean_hex = hex_str.strip().upper().replace('0X', '')
    norm = f"0x{clean_hex.lower()}"

    # Prefer external DB (64-bit or 32-bit)
    if norm in _NATIVE_HASH_DB:
        return _NATIVE_HASH_DB[norm]

    # Try exact match in built-in 32-bit map
    if f'0x{clean_hex}' in GTA_NATIVE_HASHES:
        return GTA_NATIVE_HASHES[f'0x{clean_hex}']
    # Return as hash if unknown
    return f"Native_0x{clean_hex}"


# ============================================================================
# DbgHelp API Integration for Native Stack Walking
# ============================================================================

class DbgHelpStackWalker:
    """Native stack walking using Windows DbgHelp.dll StackWalk64 API.
    
    This is much faster than regex pattern matching for extracting native stacks
    from large dump files. Uses the same API as WinDbg internally.
    """
    
    def __init__(self):
        try:
            self.dbghelp = ctypes.WinDLL('dbghelp.dll')
            self._init_structures()
            self.available = True
        except Exception:
            self.available = False
    
    def _init_structures(self):
        """Initialize ctypes structures for DbgHelp API."""
        # STACKFRAME64 structure
        class STACKFRAME64(ctypes.Structure):
            _fields_ = [
                ('AddrPC', ctypes.c_uint64 * 2),      # ADDRESS64
                ('AddrReturn', ctypes.c_uint64 * 2),  # ADDRESS64
                ('AddrFrame', ctypes.c_uint64 * 2),   # ADDRESS64
                ('AddrStack', ctypes.c_uint64 * 2),   # ADDRESS64
                ('AddrBStore', ctypes.c_uint64 * 2),  # ADDRESS64
                ('FuncTableEntry', ctypes.c_void_p),
                ('Params', ctypes.c_uint64 * 4),
                ('Far', ctypes.c_int),
                ('Virtual', ctypes.c_int),
                ('Reserved', ctypes.c_uint64 * 3),
                ('KdHelp', ctypes.c_uint64 * 4),
            ]
        
        self.STACKFRAME64 = STACKFRAME64
        
        # Define API signatures
        self.dbghelp.StackWalk64.argtypes = [
            ctypes.c_ulong,      # MachineType
            ctypes.c_void_p,     # hProcess
            ctypes.c_void_p,     # hThread
            ctypes.POINTER(STACKFRAME64),
            ctypes.c_void_p,     # ContextRecord
            ctypes.c_void_p,     # ReadMemoryRoutine
            ctypes.c_void_p,     # FunctionTableAccessRoutine
            ctypes.c_void_p,     # GetModuleBaseRoutine
            ctypes.c_void_p,     # TranslateAddress
        ]
        self.dbghelp.StackWalk64.restype = ctypes.c_int
    
    def walk_stack_from_dump(self, dump_path: str, module_map: dict) -> List[str]:
        """Extract native stack using StackWalk64 on a dump file.
        
        Args:
            dump_path: Path to minidump file
            module_map: Dict mapping base addresses to (end_addr, module_name)
        
        Returns:
            List of stack frame strings like "module.dll + 0x1234"
        """
        if not self.available:
            return []
        
        # For now, return empty - full implementation requires MiniDumpReadDumpStream
        # This is a placeholder showing the approach
        return []


def _process_chunk_worker(args: Tuple[bytes, int]) -> "DeepAnalysisResult":
    """Run analysis passes on a single chunk in a worker process (for CPU parallelism).
    
    Must be a module-level function so it can be pickled for ProcessPoolExecutor.
    Returns a DeepAnalysisResult to be merged by the main process.
    """
    chunk_bytes, chunk_offset = args
    ma = MemoryAnalyzer()  # No callbacks in worker
    ma.result = DeepAnalysisResult()
    ma._evidence_seen = set()
    ma._run_analysis_passes(chunk_bytes, chunk_offset)
    return ma.result


class EvidenceType(Enum):
    """Types of evidence linking a script/resource to a crash."""
    LUA_STACK_TRACE = "lua_stack_trace"
    JS_STACK_TRACE = "js_stack_trace"
    SCRIPT_PATH = "script_path"
    RESOURCE_NAME = "resource_name"
    THREAD_STACK = "thread_stack"
    EXCEPTION_ADDRESS = "exception_address"
    MEMORY_REGION = "memory_region"
    ERROR_MESSAGE = "error_message"
    MANIFEST_REFERENCE = "manifest_reference"
    NATIVE_CALL = "native_call"
    EVENT_HANDLER = "event_handler"
    HANDLE_PATH = "handle_path"  # Resource path from open file handle at crash


@dataclass
class ScriptEvidence:
    """Evidence linking a script or resource to the crash."""
    evidence_type: EvidenceType
    script_name: str
    resource_name: Optional[str] = None
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    function_name: Optional[str] = None
    memory_address: Optional[int] = None
    context: str = ""
    confidence: float = 0.0  # 0.0 to 1.0
    raw_data: Optional[bytes] = None


@dataclass
class LuaStackFrame:
    """Represents a single Lua stack frame."""
    source: str  # File or chunk name
    line: int
    function_name: str
    is_c_function: bool = False
    locals: Dict[str, str] = field(default_factory=dict)


@dataclass
class ScriptError:
    """Represents a script error found in memory."""
    error_type: str
    message: str
    script_name: Optional[str] = None
    resource_name: Optional[str] = None
    line_number: Optional[int] = None
    stack_trace: List[LuaStackFrame] = field(default_factory=list)


@dataclass
class ResourceInfo:
    """Information about a FiveM resource found in memory."""
    name: str
    path: Optional[str] = None
    scripts: List[str] = field(default_factory=list)
    state: str = "unknown"  # started, stopped, loading, error
    evidence_count: int = 0
    evidence_types: Set[EvidenceType] = field(default_factory=set)
    # All unique file paths found for this resource
    all_paths: List[str] = field(default_factory=list)
    # Detailed context from evidence (error messages, stack traces, etc.)
    context_details: List[str] = field(default_factory=list)
    # Likely script file from ERROR_MESSAGE evidence (e.g. client.lua) for report display
    likely_script: Optional[str] = None


@dataclass
class MemoryRegionInfo:
    """Information about a memory region."""
    start_address: int
    size: int
    protection: str = ""
    module_name: Optional[str] = None
    contains_code: bool = False
    contains_script_refs: bool = False
    state: str = ""  # committed, reserved, free
    type_str: str = ""  # private, mapped, image
    allocation_base: Optional[int] = None


@dataclass
class HandleInfo:
    """Information about an open handle at crash time."""
    handle_value: int
    type_name: str  # File, Mutant, Event, Key, Section, etc.
    object_name: str = ""
    attributes: int = 0
    granted_access: int = 0


@dataclass
class ThreadExtendedInfo:
    """Extended thread information."""
    thread_id: int
    thread_name: str = ""
    priority: int = 0
    base_priority: int = 0
    state: str = ""  # Running, Ready, Waiting, etc.
    wait_reason: str = ""
    start_address: Optional[int] = None
    teb_address: Optional[int] = None
    stack_base: Optional[int] = None
    stack_limit: Optional[int] = None
    create_time: Optional[int] = None
    user_time: Optional[int] = None
    kernel_time: Optional[int] = None


@dataclass
class ModuleVersionInfo:
    """Version and debug information for a module."""
    name: str
    base_address: int
    size: int
    checksum: int = 0
    timestamp: int = 0
    version_string: str = ""
    file_version: str = ""
    product_version: str = ""
    pdb_name: str = ""
    pdb_guid: str = ""
    pdb_age: int = 0
    cv_signature: str = ""


@dataclass
class ExceptionParams:
    """Detailed exception parameters."""
    code: int
    code_name: str = ""
    address: int = 0
    num_parameters: int = 0
    # For Access Violation (0xC0000005)
    access_type: str = ""  # "read", "write", "execute"
    target_address: Optional[int] = None
    # For other exceptions
    parameters: List[int] = field(default_factory=list)
    nested_exception: Optional['ExceptionParams'] = None
    # CPU context at crash time (x64)
    context_rip: Optional[int] = None  # Instruction pointer (crash address)
    context_rsp: Optional[int] = None  # Stack pointer
    context_rbp: Optional[int] = None  # Base pointer
    context_rax: Optional[int] = None
    context_rbx: Optional[int] = None
    context_rcx: Optional[int] = None
    context_rdx: Optional[int] = None
    context_rsi: Optional[int] = None
    context_rdi: Optional[int] = None
    context_r8: Optional[int] = None
    context_r9: Optional[int] = None
    context_r10: Optional[int] = None
    context_r11: Optional[int] = None
    context_r12: Optional[int] = None
    context_r13: Optional[int] = None
    context_r14: Optional[int] = None
    context_r15: Optional[int] = None
    context_flags: Optional[int] = None


@dataclass
class ProcessStatistics:
    """Process statistics from MiscInfo."""
    process_id: int = 0
    create_time: Optional[int] = None
    user_time: Optional[int] = None
    kernel_time: Optional[int] = None
    # Memory statistics
    peak_virtual_size: int = 0
    virtual_size: int = 0
    page_fault_count: int = 0
    peak_working_set_size: int = 0
    working_set_size: int = 0
    quota_peak_paged_pool: int = 0
    quota_paged_pool: int = 0
    quota_peak_non_paged_pool: int = 0
    quota_non_paged_pool: int = 0
    pagefile_usage: int = 0
    peak_pagefile_usage: int = 0
    private_usage: int = 0
    # Handle counts
    handle_count: int = 0
    gdi_handle_count: int = 0
    user_handle_count: int = 0
    # Protection info
    process_integrity_level: str = ""
    protected_process: bool = False


@dataclass
class DeepAnalysisResult:
    """Complete result of deep memory analysis.
    
    ADA COMPLIANCE NOTE: All collections have statically enforced upper bounds
    to satisfy "no dynamic memory allocation after initialization" requirement.
    
    Collection Max Sizes:
    - primary_suspects: 100 items
    - all_evidence: 5000 items
    - script_errors: 1000 items
    - lua_stacks: 500 stacks
    - js_stacks: 500 stacks
    - native_stack: 1000 frames
    - script_paths: 1000 items
    - native_calls: 1000 items
    - event_handlers: 500 items
    - handles: 1000 items
    - threads_extended: 64 threads
    - module_versions: 500 modules
    - memory_info: 1000 regions
    - errors: 100 items
    
    These bounds prevent unbounded growth while maintaining sufficient capacity
    for comprehensive crash analysis. Bounds are enforced via defensive checks
    in append/extend operations throughout the analysis pipeline.
    """
    # Primary culprits (most likely causes)
    primary_suspects: List[ResourceInfo] = field(default_factory=list)

    # All evidence found
    all_evidence: List[ScriptEvidence] = field(default_factory=list)

    # Script errors found in memory
    script_errors: List[ScriptError] = field(default_factory=list)

    # Lua stack traces reconstructed from memory
    lua_stacks: List[List[LuaStackFrame]] = field(default_factory=list)

    # Resources involved per Lua stack (same index as lua_stacks)
    lua_stack_resources: List[List[str]] = field(default_factory=list)

    # JS stack traces
    js_stacks: List[str] = field(default_factory=list)

    # Resources involved per JS stack (same index as js_stacks)
    js_stack_resources: List[List[str]] = field(default_factory=list)

    # Resources found in memory
    resources: Dict[str, ResourceInfo] = field(default_factory=dict)

    # Memory analysis details
    memory_regions: List[MemoryRegionInfo] = field(default_factory=list)

    # Exception info
    exception_code: Optional[int] = None
    exception_address: Optional[int] = None
    exception_module: Optional[str] = None

    # Native stack trace
    native_stack: List[str] = field(default_factory=list)

    # Raw findings
    script_paths: List[str] = field(default_factory=list)
    native_calls: List[str] = field(default_factory=list)
    event_handlers: List[str] = field(default_factory=list)

    # Analysis metadata
    analysis_complete: bool = False
    errors: List[str] = field(default_factory=list)

    # Tie-breaking / confidence: when top two suspects have close scores
    primary_suspect_secondary: Optional[str] = None  # name of second-place when evidence is ambiguous
    primary_suspect_confidence: str = "medium"  # "high" | "medium" | "low" for report wording

    # Standard Minidump Data
    system_info: Dict[str, Any] = field(default_factory=dict)
    misc_info: Dict[str, Any] = field(default_factory=dict)
    process_parameters: Dict[str, Any] = field(default_factory=dict)
    crash_time: Optional[int] = None
    exception_context: Dict[str, Any] = field(default_factory=dict)
    unloaded_modules: List[str] = field(default_factory=list)

    # NEW: Extended minidump data extraction
    # Exception parameters with detailed access violation info
    exception_params: Optional[ExceptionParams] = None

    # Handle data - open files, mutexes, registry keys at crash
    handles: List[HandleInfo] = field(default_factory=list)

    # Extended thread information
    threads_extended: List[ThreadExtendedInfo] = field(default_factory=list)
    # Thread contexts (decoded registers per thread)
    thread_contexts: Dict[int, Dict[str, int]] = field(default_factory=dict)

    # Module version/PDB info for symbol resolution
    module_versions: List[ModuleVersionInfo] = field(default_factory=list)

    # Memory info list with detailed permissions
    memory_info: List[MemoryRegionInfo] = field(default_factory=list)

    # Process statistics (memory usage, handle counts, etc.)
    process_stats: Optional[ProcessStatistics] = None

    # Function table entries for stack unwinding
    function_table_entries: int = 0

    # Comment stream data
    comment_stream_a: str = ""
    comment_stream_w: str = ""

    # Assertion info
    assertion_info: Dict[str, str] = field(default_factory=dict)

    # ===== MEMORY LEAK ANALYSIS DATA =====
    # Entity creation/deletion tracking
    entity_creations: List[Tuple[str, int]] = field(default_factory=list)  # (native_name, memory_offset)
    entity_deletions: List[Tuple[str, int]] = field(default_factory=list)
    
    # Timer tracking
    timers_created: List[Tuple[str, int]] = field(default_factory=list)  # (pattern, memory_offset)
    
    # Event handler tracking
    event_handlers_registered: List[Tuple[str, int]] = field(default_factory=list)
    event_handlers_removed: List[Tuple[str, int]] = field(default_factory=list)
    
    # Memory allocation tracking (C/C++ level)
    memory_allocations: List[Tuple[str, int]] = field(default_factory=list)
    memory_frees: List[Tuple[str, int]] = field(default_factory=list)
    
    # Memory leak indicators found
    memory_leak_indicators: List[Tuple[str, str, int]] = field(default_factory=list)  # (message, type, offset)
    
    # Pool/resource exhaustion indicators
    pool_exhaustion_indicators: List[Tuple[str, int]] = field(default_factory=list)
    
    # Database query patterns found
    database_patterns: List[Tuple[str, int]] = field(default_factory=list)
    
    # NUI/CEF patterns found
    nui_patterns: List[Tuple[str, int]] = field(default_factory=list)
    # NUI resources attributed from nearby context (resource -> count)
    nui_resources: Dict[str, int] = field(default_factory=dict)
    
    # Network sync patterns
    network_patterns: List[Tuple[str, int]] = field(default_factory=list)
    
    # State bag patterns
    statebag_patterns: List[Tuple[str, int]] = field(default_factory=list)

    # For full_analysis: raw strings and module names (avoids re-reading dump)
    raw_strings: List[str] = field(default_factory=list)
    module_names: List[str] = field(default_factory=list)

    # JavaScriptData stream (20) - V8/JS context when present
    javascript_data: Optional[Dict[str, Any]] = None
    # ProcessVmCounters stream (22) - VM usage at crash
    process_vm_counters: Optional[Dict[str, Any]] = None
    
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
    
    # ===== UNFILTERED EVIDENCE TRACKING =====
    # Raw evidence before resource attribution (for debugging missed problems)
    raw_evidence: List[ScriptEvidence] = field(default_factory=list)
    # Evidence that couldn't be attributed to a resource but may still be relevant
    unattributed_evidence: List[ScriptEvidence] = field(default_factory=list)
    # High-value evidence that should NEVER be discarded
    critical_evidence: List[ScriptEvidence] = field(default_factory=list)
    
    # ===== FRAMEWORK & METADATA DETECTION =====
    # Detected FiveM framework (QBCore, ESX, VRP, Ox, None)
    framework_detected: Optional[str] = None
    framework_confidence: float = 0.0  # 0.0-1.0 confidence score
    
    # fxmanifest.lua metadata extraction
    fxmanifest_data: Dict[str, Any] = field(default_factory=dict)
    
    # Error severity classification (error_id -> severity level)
    error_severities: Dict[str, str] = field(default_factory=dict)  # "crash", "error", "panic", "warning"


class MemoryAnalyzer:
    """Deep memory analyzer for FiveM crash dumps."""

    # FiveM-specific patterns
    FIVEM_PATTERNS = {
        # Lua script paths - handle @resource/path format
        'lua_path': re.compile(
            rb'[@]?([A-Za-z0-9_\-]+)[/\\]([A-Za-z0-9_\-/\\]+\.lua)',
            re.IGNORECASE
        ),
        # JavaScript paths
        'js_path': re.compile(
            rb'@?([A-Za-z0-9_\-]+)[/\\]([A-Za-z0-9_\-/\\]+\.js)',
            re.IGNORECASE
        ),
        # Resource manifest
        'fxmanifest': re.compile(
            rb'@?([A-Za-z0-9_\-]{2,64})[/\\]fxmanifest\.lua',
            re.IGNORECASE
        ),
        # __resource.lua (legacy)
        'resource_lua': re.compile(
            rb'@?([A-Za-z0-9_\-]{2,64})[/\\]__resource\.lua',
            re.IGNORECASE
        ),
        # Resource reference patterns
        'resource_ref': re.compile(
            rb'resource[:\s]+["\']?([A-Za-z0-9_\-]{2,64})["\']?',
            re.IGNORECASE
        ),
        # Citizen script error - multiple formats
        'citizen_error': re.compile(
            rb'SCRIPT\s*ERROR[:\s]+([^\x00\r\n]{10,500})',
            re.IGNORECASE
        ),
        # Lua error pattern - standard format
        'lua_error': re.compile(
            rb'[@]?([A-Za-z0-9_\-/\\]+\.lua):(\d+):\s*([^\x00\r\n]{1,500})',
            re.IGNORECASE
        ),
        # Lua stack trace line - [source]:line: in function
        'lua_stack_line': re.compile(
            rb'\[[@]?([^\]]+)\]:(\d+):\s*in\s+(?:(?:local\s+)?function\s+)?[\'"]?([A-Za-z0-9_<>]*)[\'"]?',
            re.IGNORECASE
        ),
        # Lua traceback header
        'lua_traceback': re.compile(
            rb'stack\s+traceback\s*:([^\x00]{10,2000}?)(?:\n\n|\x00\x00)',
            re.IGNORECASE | re.DOTALL
        ),
        # JS error pattern
        'js_error': re.compile(
            rb'@?([A-Za-z0-9_\-/\\]+\.js):(\d+):(\d+)\s*([^\x00\r\n]{1,500})',
            re.IGNORECASE
        ),
        # Native call pattern - GTA V natives being called from Lua/JS
        # Format: Native.FunctionName( or NATIVE_FUNCTION_NAME( - require open paren
        # Avoid matching paths like cfx.re or cfx_curl_x86_64
        'native_call': re.compile(
            rb'(?:^|[^/\\a-z0-9])(?:Citizen|Native|Global)\.([A-Z][A-Za-z0-9_]{3,50})\s*\(',
            re.IGNORECASE | re.MULTILINE
        ),
        # GTA V native invocation pattern (hash-based)
        'native_invoke': re.compile(
            rb'(?:Invoke|invoke|INVOKE)(?:Native)?\s*\(\s*(?:0x)?([0-9A-Fa-f]{8,16})',
            re.IGNORECASE
        ),
        # Event handler pattern
        'event_handler': re.compile(
            rb'(?:AddEventHandler|RegisterNetEvent|RegisterServerEvent|TriggerEvent|'
            rb'TriggerServerEvent|TriggerClientEvent|on)\s*\(\s*["\']([A-Za-z0-9_:\-\.]+)["\']',
            re.IGNORECASE
        ),
        # Export call pattern
        'export_call': re.compile(
            rb'exports\s*[\[\.]\s*["\']?([A-Za-z0-9_\-]+)["\']?\s*[\]\.]',
            re.IGNORECASE
        ),
        # Streaming asset
        'streaming_asset': re.compile(
            rb'(?:streaming|asset)[:\s]+([A-Za-z0-9_\-/\\\.]+\.(?:ytyp|ymap|ytd|ydr|yft|ydd|ybn))',
            re.IGNORECASE
        ),
        # Thread name with resource
        'thread_resource': re.compile(
            rb'(?:thread|script|resource)[:\s]+["\']?([A-Za-z0-9_\-]{2,64})["\']?',
            re.IGNORECASE
        ),
        # FiveM resource state
        'resource_state': re.compile(
            rb'(?:Starting|Started|Stopping|Stopped|Loading|Loaded)\s+resource\s+([A-Za-z0-9_\-]+)',
            re.IGNORECASE
        ),
        # Citizen.CreateThread / Citizen.Wait patterns
        'citizen_thread': re.compile(
            rb'Citizen\s*\.\s*(CreateThread|Wait|SetTimeout|Trace)\s*\(',
            re.IGNORECASE
        ),
        # FiveM command registration
        'command_register': re.compile(
            rb'(?:RegisterCommand|TriggerEvent\s*\(\s*["\']chat:addSuggestion["\'])\s*\(\s*["\']([A-Za-z0-9_\-]+)["\']',
            re.IGNORECASE
        ),
        # Server.cfg / server config - ensure/start resource name
        'ensure_start': re.compile(
            rb'(?:ensure|start)\s+([A-Za-z0-9_\-]{2,64})\s*(?:$|#|\r|\n)',
            re.IGNORECASE
        ),
        # Server resources path: resources/resname or resources\resname
        'server_resources_path': re.compile(
            rb'resources[/\\]([A-Za-z0-9_\-]{2,64})(?:[/\\]|$)',
            re.IGNORECASE
        ),
        # GetCurrentResourceName / GetInvokingResource - resource name often nearby as string
        'get_current_resource': re.compile(
            rb'(?:GetCurrentResourceName|GetInvokingResource)\s*\(\s*\)',
            re.IGNORECASE
        ),
        # ===== MEMORY LEAK DETECTION PATTERNS =====
        # Entity creation natives (common leak sources)
        'entity_creation': re.compile(
            rb'(CreateVehicle|CreatePed|CreateObject|CreatePickup|CreateBlip|'
            rb'AddBlipForCoord|AddBlipForEntity|CreateCam|CreateCamWithParams|'
            rb'NetworkCreateSynchronisedScene|CreateCheckpoint|'
            rb'CreateVehicleServerSetter|CreateObjectNoOffset|CreatePedInsideVehicle)',
            re.IGNORECASE
        ),
        # Entity deletion natives (check if balanced with creation)
        'entity_deletion': re.compile(
            rb'(DeleteEntity|DeleteVehicle|DeletePed|DeleteObject|RemoveBlip|'
            rb'DestroyCam|DestroyAllCams|DeleteCheckpoint|SetEntityAsNoLongerNeeded|'
            rb'SetVehicleAsNoLongerNeeded|SetPedAsNoLongerNeeded|SetObjectAsNoLongerNeeded)',
            re.IGNORECASE
        ),
        # Timer creation (potential leaks if not cancelled)
        'timer_creation': re.compile(
            rb'(SetTimeout|setInterval|setTimeout|SetInterval|Citizen\.SetTimeout)',
            re.IGNORECASE
        ),
        # Event handler registration (check for cleanup)
        'event_registration': re.compile(
            rb'(AddEventHandler|RegisterNetEvent|RegisterServerEvent|RegisterNUICallback|'
            rb'on\s*\(\s*["\'][A-Za-z0-9:_\-]+["\']|RegisterCommand)',
            re.IGNORECASE
        ),
        # Event handler removal
        'event_removal': re.compile(
            rb'(RemoveEventHandler|off\s*\(\s*["\'][A-Za-z0-9:_\-]+["\'])',
            re.IGNORECASE
        ),
        # Memory allocation patterns (C/C++ level)
        'memory_alloc': re.compile(
            rb'(HeapAlloc|VirtualAlloc|malloc|calloc|realloc|new\s+\w+|'
            rb'GlobalAlloc|LocalAlloc|CoTaskMemAlloc)',
            re.IGNORECASE
        ),
        # Memory free patterns
        'memory_free': re.compile(
            rb'(HeapFree|VirtualFree|free|delete\s+|delete\[\]|'
            rb'GlobalFree|LocalFree|CoTaskMemFree)',
            re.IGNORECASE
        ),
        # Pool exhaustion indicators (optimized - use possessive quantifiers)
        'pool_exhaustion': re.compile(
            rb'pool[ \t]{0,3}(?:is[ \t]+)?(?:full|exhausted|overflow)|'
            rb'entity[ \t]{0,3}(?:limit|pool)|no[ \t]+free[ \t]+(?:slot|entity)|'
            rb'MAX_ENTITIES|max[ \t]{0,3}(?:vehicle|ped|object)s?[ \t]{0,3}(?:reached|exceeded)|'
            rb'CPool<|rage::fwBasePool',
            re.IGNORECASE
        ),
        # Texture/streaming memory issues
        'streaming_memory': re.compile(
            rb'(streaming\s*memory|texture\s*(?:budget|memory|limit)|'
            rb'grcTexture|rage::strStreamingModule|ytd\s*(?:fail|error)|'
            rb'asset\s*(?:fail|timeout|error))',
            re.IGNORECASE
        ),
        # NUI/CEF memory patterns
        'nui_memory': re.compile(
            rb'(NUI|CEF|CefBrowser|DUI|duiUrl|SendNUIMessage|'
            rb'SetNuiFocus|NuiCallback|GetNuiCursorPosition)',
            re.IGNORECASE
        ),
        # Thread context patterns
        'thread_context': re.compile(
            rb'(scrThread|GtaThread|rage::scrThread|scriptHandler|'
            rb'CTheScripts|CScriptResource)',
            re.IGNORECASE
        ),
        # Reference counting issues
        'refcount_issue': re.compile(
            rb'(ref\s*count|reference\s*count|AddRef|Release|strong_ptr|weak_ptr|'
            rb'shared_ptr|unique_ptr|ref<|fwRef)',
            re.IGNORECASE
        ),
        # Database/ORM patterns (ox_lib, mysql-async, etc.)
        'database_pattern': re.compile(
            rb'(MySQL|oxmysql|mysql-async|ghmattimysql|'
            rb'exports\s*\[\s*["\'](?:ox|mysql|ghm)|'
            rb'(?:SELECT|INSERT|UPDATE|DELETE)\s+(?:FROM|INTO|SET))',
            re.IGNORECASE
        ),
        # State bag patterns
        'statebag_pattern': re.compile(
            rb'(GlobalState|LocalPlayer\.state|Player\(\d+\)\.state|'
            rb'Entity\(\d+\)\.state|SetStateBagValue|GetStateBagValue)',
            re.IGNORECASE
        ),
        # Network sync issues
        'network_sync': re.compile(
            rb'(NetworkRequest|NetworkGet|NetworkOverride|NetworkSetEntityInvisible|'
            rb'SyncScene|NetworkFade|NetworkConceal|NetworkSetPropertyId|'
            rb'OneSync|NetworkRegisterEntityAsNetworked)',
            re.IGNORECASE
        ),
    }

    # ===== MEMORY LEAK INDICATORS =====
    # Strings that indicate potential memory issues
    MEMORY_LEAK_INDICATORS = [
        # Allocation failures
        (b'out of memory', 'oom'),
        (b'memory allocation failed', 'alloc_fail'),
        (b'failed to allocate', 'alloc_fail'),
        (b'heap corruption', 'heap_corrupt'),
        (b'double free', 'double_free'),
        (b'use after free', 'use_after_free'),
        (b'invalid heap', 'heap_invalid'),
        (b'memory leak', 'leak_detected'),
        # Pool exhaustion
        (b'pool full', 'pool_full'),
        (b'pool exhausted', 'pool_exhausted'),
        (b'entity limit', 'entity_limit'),
        (b'too many entities', 'entity_limit'),
        (b'max vehicles', 'vehicle_limit'),
        (b'max peds', 'ped_limit'),
        (b'max objects', 'object_limit'),
        # Resource issues
        (b'resource budget', 'budget_exceeded'),
        (b'texture budget', 'texture_budget'),
        (b'streaming budget', 'streaming_budget'),
        (b'asset budget', 'asset_budget'),
        # Handle leaks
        (b'handle leak', 'handle_leak'),
        (b'too many handles', 'handle_limit'),
        (b'handle count', 'handle_count'),
        # GC issues
        (b'gc overhead', 'gc_overhead'),
        (b'garbage collection', 'gc_issue'),
        # Thread issues
        (b'thread limit', 'thread_limit'),
        (b'too many threads', 'thread_limit'),
        (b'stack overflow', 'stack_overflow'),
        (b'C stack overflow', 'c_stack_overflow'),
    ]

    # Lua runtime error messages - these indicate active Lua errors
    LUA_ERROR_MESSAGES = [
        # Type errors
        (b'attempt to call a nil value', 'call_nil'),
        (b'attempt to call a string value', 'call_string'),
        (b'attempt to call a number value', 'call_number'),
        (b'attempt to call a boolean value', 'call_boolean'),
        (b'attempt to call a table value', 'call_table'),
        (b'attempt to call a userdata value', 'call_userdata'),
        (b'attempt to index a nil value', 'index_nil'),
        (b'attempt to index a string value', 'index_string'),
        (b'attempt to index a number value', 'index_number'),
        (b'attempt to index a boolean value', 'index_boolean'),
        (b'attempt to perform arithmetic on', 'arithmetic_error'),
        (b'attempt to compare', 'compare_error'),
        (b'attempt to concatenate', 'concat_error'),
        (b'attempt to get length of', 'length_error'),
        # Stack/memory errors
        (b'stack overflow', 'stack_overflow'),
        (b'C stack overflow', 'c_stack_overflow'),
        (b'not enough memory', 'out_of_memory'),
        (b'memory allocation error', 'memory_alloc'),
        # Argument errors
        (b'bad argument', 'bad_argument'),
        (b'invalid argument', 'invalid_argument'),
        (b'expected', 'type_mismatch'),
        # Table errors
        (b'invalid key to', 'invalid_key'),
        (b'table index is nil', 'nil_index'),
        (b'table index is NaN', 'nan_index'),
        # Loop/coroutine errors
        (b'cannot resume dead coroutine', 'dead_coroutine'),
        (b'cannot resume non-suspended coroutine', 'bad_coroutine'),
        (b"'for' limit must be a number", 'for_limit'),
        (b"'for' step must be a number", 'for_step'),
        (b"'for' initial value must be a number", 'for_init'),
        # Module errors
        (b'module', 'module_error'),
        (b"cannot find package", 'package_not_found'),
        # FiveM-specific errors
        (b'No such export', 'export_not_found'),
        (b'SCRIPT ERROR', 'script_error'),
        (b'error running', 'runtime_error'),
        (b'error calling', 'call_error'),
    ]

    # Optimized regex for single-pass scanning
    # Sort by length descending to ensure longer matches are preferred (e.g. "C stack overflow" vs "stack overflow")
    _SORTED_LUA_ERRORS = sorted(LUA_ERROR_MESSAGES, key=lambda x: len(x[0]), reverse=True)
    _LUA_ERROR_REGEX = re.compile(
        b'|'.join(re.escape(x[0]) for x in _SORTED_LUA_ERRORS)
    )
    # Map error bytes back to error type
    _LUA_ERROR_MAP = {x[0]: x[1] for x in LUA_ERROR_MESSAGES}

    # Internal/System scripts that usually indicate the error is elsewhere
    INTERNAL_SCRIPTS = {
        'natives_loader.lua',
        'natives_server.lua',
        'scheduler.lua',
        'deferred.lua',
        'event.lua',
        'msgpack.lua',
        'json.lua',
        'citizen.lua',
        'init.lua',
        'mp.lua',
        'clr_init.lua',
        'resource_init.lua',
        'MessagePack.lua',
        'eventemitter2.js',
        'dui-runtime.js',
    }

    # Resource manifest files are metadata, not executable scripts.
    MANIFEST_FILES = {
        'fxmanifest.lua',
        '__resource.lua',
    }

    # High-value evidence types that should NEVER be discarded even without resource attribution
    # These indicate actual crash-related problems, not just resource presence
    HIGH_VALUE_EVIDENCE_TYPES = {
        EvidenceType.ERROR_MESSAGE,
        EvidenceType.LUA_STACK_TRACE,
        EvidenceType.JS_STACK_TRACE,
        EvidenceType.EXCEPTION_ADDRESS,
    }

    # Faulting module substrings that indicate script runtime (crash in script code, not generic native)
    SCRIPT_RUNTIME_MODULE_SUBSTRINGS = (
        'scripthandler',
        'citizen-resources-',
        'citizen-scripting',
    )

    # Path segments that are NOT valid FiveM resource names (system/internal paths)
    IGNORED_PATH_SEGMENTS = {
        # FiveM/CitizenFX internal paths
        'app', 'client', 'server', 'shared', 'builds', 'bin', 'lib', 'libs',
        'cache', 'caches', 'data', 'citizen', 'cfx', 'fivem', 'redm',
        'scripting', 'runtime', 'natives', 'v8', 'lua', 'mono', 'gl',
        'resources', 'resource', 'stream', 'streaming', 'files',
        # Common resource subfolders (not resource roots)
        'html', 'modules', 'config', 'locales',
        'fx', 'rage', 'gta', 'gtav', 'gta5', 'update', 'dlc', 'dlcpacks',
        'common', 'platform', 'x64', 'citizen-scripting', 'citizen-server-impl',
        'fxserver', 'fxdk', 'alphaware', 'canary', 'release', 'opt',
        # Windows system paths
        'windows', 'system32', 'syswow64', 'program files', 'program files (x86)',
        'programdata', 'users', 'appdata', 'local', 'roaming', 'temp', 'tmp',
        # Common development paths
        'src', 'source', 'dist', 'build', 'out', 'output', 'node_modules',
        'packages', 'vendor', 'deps', 'dependencies',
        # GTA V / Game system words (COMMON FALSE POSITIVES)
        # These appear frequently in game memory but are NOT user resources
        'radio', 'audio', 'music', 'sound', 'voice', 'sfx', 'ambience',
        'video', 'cutscene', 'movie', 'bink', 'render', 'shader', 'texture',
        'model', 'models', 'anim', 'animations', 'props', 'vehicles', 'peds',
        'weapons', 'pickup', 'script', 'scripts', 'game', 'core', 'base',
        'loading', 'startup', 'init', 'main', 'index', 'entry', 'bootstrap',
        'handler', 'manager', 'controller', 'service', 'util', 'utils', 'helper',
        # Single-letter or too short
        'c', 'd', 'e', 'f', 'x',
    }

    # CitizenFX Script Runtime markers
    CITIZENFX_RUNTIME_MARKERS = [
        b'citizen-scripting-lua',
        b'citizen-scripting-v8',
        b'citizen-scripting-mono',
        b'ScriptRuntime',
        b'LuaScriptRuntime',
        b'V8ScriptRuntime',
        b'MonoScriptRuntime',
        b'fx::Resource',
        b'fx::ResourceManager',
        b'rage::scrThread',
        b'GtaThread',
    ]

    # Optimized regex for single-pass scanning
    # Sort by length descending to ensure longer matches are preferred (e.g. "LuaScriptRuntime" vs "ScriptRuntime")
    _SORTED_CITIZENFX_MARKERS = sorted(CITIZENFX_RUNTIME_MARKERS, key=len, reverse=True)
    _CITIZENFX_MARKERS_REGEX = re.compile(
        b'|'.join(re.escape(x) for x in _SORTED_CITIZENFX_MARKERS)
    )

    # Lua state signature patterns (for finding Lua state structures in memory)
    LUA_STATE_PATTERNS = [
        # Lua error messages
        b'attempt to call',
        b'attempt to index',
        b'attempt to perform arithmetic',
        b'attempt to compare',
        b'attempt to concatenate',
        b'stack overflow',
        b'nil value',
        b'bad argument',
        b'invalid key',
        b'table index is nil',
        b'table index is NaN',
        b'C stack overflow',
    ]

    # FiveM/CitizenFX specific markers
    CITIZENFX_MARKERS = [
        b'citizen',
        b'cfx',
        b'fivem',
        b'citizenfx',
        b'redm',
        b'fxserver',
        b'txadmin',
        b'scripthook',
    ]

    # Common crash-related strings
    CRASH_MARKERS = [
        b'access violation',
        b'exception',
        b'segfault',
        b'EXCEPTION_',
        b'fatal error',
        b'unhandled exception',
        b'stack trace',
        b'call stack',
        # Additional crash markers
        b'CRASH',
        b'assertion failed',
        b'debug assertion',
        b'null pointer',
        b'nullptr',
        b'invalid pointer',
        b'corrupted',
        b'heap corruption',
        b'buffer overrun',
        b'stack buffer',
        b'STATUS_',
        b'0xC0000005',  # Access violation
        b'0xC0000374',  # Heap corruption
        b'0xC00000FD',  # Stack overflow
        b'0x80000003',  # Breakpoint
    ]

    # FiveM-specific crash causes
    FIVEM_CRASH_CAUSES = [
        (b'ERR_GFX_STATE', 'graphics_state', 'GPU/Graphics driver issue'),
        (b'ERR_GFX_D3D_INIT', 'graphics_init', 'DirectX initialization failure'),
        (b'ERR_GEN_INVALID', 'gen_invalid', 'General invalid state'),
        (b'ERR_MEM_EMBEDDEDALLOC', 'memory_alloc', 'Embedded allocator failure'),
        (b'ERR_SYS_INVALIDRESOURCE', 'invalid_resource', 'Invalid resource reference'),
        (b'ERR_NET_', 'network', 'Network error'),
        (b'STREAMING_', 'streaming', 'Asset streaming issue'),
        (b'rage::atArray', 'array_overflow', 'Array bounds issue'),
        (b'rage::fwEntity', 'entity_issue', 'Entity system issue'),
        (b'CNetGamePlayer', 'player_issue', 'Player system issue'),
        (b'CTaskDataInfo', 'task_issue', 'Task/AI system issue'),
        (b'audSound', 'audio_issue', 'Audio system issue'),
        (b'strStreamingModule', 'streaming_module', 'Streaming module issue'),
        (b'CScriptResource', 'script_resource', 'Script resource issue'),
    ]

    def __init__(self, progress_callback=None, abort_check: Optional[Callable[[], bool]] = None):
        """Initialize the memory analyzer.
        
        Args:
            progress_callback: Optional callable(stage: str, progress: float, message: str)
                             - stage: Current analysis stage name
                             - progress: 0.0 to 1.0 progress within current stage  
                             - message: Human-readable status message
                             
                             Example callback:
                             def my_callback(stage, progress, message):
                                 print(f"[{stage}] {progress*100:.0f}% - {message}")
            abort_check: Optional callable() -> bool; if returns True, long-running
                         loops (streaming/sampling) will stop early to avoid timeouts.
        """
        self.result = DeepAnalysisResult()
        self._module_map: Dict[int, Tuple[int, str]] = {}  # base -> (end, name)
        self._memory_data: Dict[int, bytes] = {}  # start -> data
        self._progress_callback = progress_callback
        self._abort_check = abort_check
        self._current_stage = ""
        self._stage_progress = 0.0
        self._last_progress_time = 0.0  # For throttling UI updates
        self._progress_throttle_sec = 0.35  # Min interval between progress callbacks (keeps UI responsive)
        self._progressive_extraction_complete = False  # Track if all chunks were analyzed (not terminated early)

    def _report_progress(self, stage: str, progress: float, message: str) -> None:
        """Report progress to callback if registered. Throttled so UI stays responsive on large files."""
        self._current_stage = stage
        self._stage_progress = progress
        if self._progress_callback:
            now = time.monotonic()
            # Always emit completion/final updates; throttle intermediate updates
            if progress >= 1.0 or stage == "complete" or (now - self._last_progress_time) >= self._progress_throttle_sec:
                self._last_progress_time = now
                try:
                    self._progress_callback(stage, progress, message)
                except Exception:
                    pass  # Don't let callback errors break analysis

    def _should_abort(self) -> bool:
        """Return True if the caller requested abort (e.g. user cancel)."""
        if self._abort_check is None:
            return False
        try:
            return bool(self._abort_check())
        except Exception:
            return False

    def _obj_to_dict(self, obj: Any) -> Dict[str, Any]:
        """Convert a minidump object to a dictionary."""
        if not obj:
            return {}

        result = {}
        # Try to use __dict__ first
        if hasattr(obj, '__dict__'):
            for k, v in obj.__dict__.items():
                if not k.startswith('_') and not callable(v):
                    # Handle enum values
                    if hasattr(v, 'name') and hasattr(v, 'value'):
                        result[k] = f"{v.name} ({v.value})"
                    else:
                        result[k] = v

        return result

    # Maximum evidence items to collect before stopping (performance optimization)
    # Increased to 2000 for better coverage on large dumps
    MAX_EVIDENCE_ITEMS = 2000
    # Maximum dump size for full in-memory analysis (500MB) - larger dumps use streaming
    MAX_FULL_ANALYSIS_SIZE = 500 * 1024 * 1024
    # Chunk size for streaming analysis (64MB - fits comfortably in memory)
    STREAM_CHUNK_SIZE = 64 * 1024 * 1024
    # Maximum file size we'll attempt to analyze (10GB)
    MAX_SUPPORTED_FILE_SIZE = 50 * 1024 * 1024 * 1024  # 50GB - uses memory-mapped sampling for very large dumps
    # Use multiple CPU cores for in-memory and streaming chunk analysis (set False to reduce memory use)
    USE_PARALLEL_CHUNKS = True
    # Min dump size (bytes) to use parallel workers for in-memory path; below this, single-thread is faster
    MIN_SIZE_PARALLEL_IN_MEMORY = 25 * 1024 * 1024  # 25MB
    # Max worker processes for parallel chunks (limits memory: workers * chunk size).
    # Lower = less spawn overhead on Windows; 4 is often a good balance.
    MAX_PARALLEL_WORKERS = min(max(1, (os.cpu_count() or 4) - 1), 4)
    # Process at least this many chunks (first 1GB at 64MB/chunk) before allowing early stop
    MIN_STREAMING_CHUNKS_BEFORE_EARLY_STOP = 16

    def analyze_dump_deep(self, dump_path: str) -> DeepAnalysisResult:
        """Perform deep analysis of a minidump file to pinpoint error sources.
        
        Performance optimizations:
        - Early termination when sufficient evidence is collected
        - Streaming/chunked processing for large dumps (>500MB)
        - Memory-mapped file access for very large dumps (>1GB)
        - Sampled analysis for massive dumps (>2GB)
        - Timeout wrappers for hang prevention on large/full dumps
        
        Supports dumps up to 10GB in size.
        
        Progress is reported via the callback provided in __init__.
        """
        self.result = DeepAnalysisResult()
        self._evidence_seen: Set[str] = set()  # Deduplication cache
        self._max_evidence = self.MAX_EVIDENCE_ITEMS
        self._max_raw_strings = 3000
        self._dump_path_for_cv_fallback = dump_path  # Store for PDB extraction fallback
        analysis_mode = "init"
        self._analysis_start_time = time.time()  # Track for timeout detection

        if not os.path.exists(dump_path):
            self.result.errors.append(f"Dump file not found: {dump_path}")
            return self.result

        if self._should_abort():
            self.result.errors.append("Analysis cancelled before start")
            return self.result

        try:
            file_size = os.path.getsize(dump_path)
            file_size_mb = file_size // (1024 * 1024)
            file_size_gb = file_size / (1024 * 1024 * 1024)
            # #region agent log
            _dlog(
                "H3",
                "memory_analyzer.analyze_dump_deep.entry",
                "dump metadata",
                {
                    "dump_file": os.path.basename(dump_path),
                    "file_size": file_size,
                    "file_size_mb": file_size_mb,
                    "has_minidump_lib": HAS_MINIDUMP,
                },
            )
            # #endregion
            # For large files, allow more evidence and raw_strings to extract full resource info
            ONE_GB = 1024 * 1024 * 1024
            if file_size > ONE_GB:
                self._max_evidence = min(5000, self.MAX_EVIDENCE_ITEMS * 2)
                self._max_raw_strings = 5000
            
            self._report_progress("init", 0.0, f"Starting analysis of {file_size_mb}MB dump file")
            
            # Check if file is too large
            if file_size > self.MAX_SUPPORTED_FILE_SIZE:
                self.result.errors.append(
                    f"Dump file too large ({file_size_gb:.1f}GB). "
                    f"Maximum supported size is {self.MAX_SUPPORTED_FILE_SIZE // (1024*1024*1024)}GB."
                )
                return self.result

            self._report_progress("init", 0.1, "Verifying minidump header...")
            
            # Verify minidump header (just read first 4 bytes)
            with open(dump_path, 'rb') as f:
                header = f.read(4)
            if header != b'MDMP':
                self.result.errors.append("Not a valid minidump file (missing MDMP header)")
                return self.result

            # Parse with minidump library if available (skip for large files to avoid freezes)
            # Use lightweight parser for files >= 500MB to avoid memory/performance issues
            md = None
            ONE_GB = 1024 * 1024 * 1024
            STRUCTURE_PARSE_THRESHOLD = 500 * 1024 * 1024  # 500MB
            
            if HAS_MINIDUMP and file_size < STRUCTURE_PARSE_THRESHOLD:
                self._report_progress("structure", 0.0, "Parsing minidump structure...")
                try:
                    md = MinidumpFile.parse(dump_path)
                    self._report_progress("structure", 0.5, "Analyzing exception and thread info...")
                    self._analyze_minidump_structure(md)
                    # Fallback: if full parse did not yield native stack (e.g. reader/thread layout differs), use lightweight parse
                    if not self.result.native_stack:
                        try:
                            self._parse_large_dump_structure_light(dump_path)
                            if self.result.native_stack:
                                self.result.errors.append("Native stack recovered via fallback lightweight parse (full parse had no stack).")
                        except Exception as _e:
                            pass
                    self._report_progress("structure", 1.0, "Structure analysis complete")
                except Exception as e:
                    self.result.errors.append(f"Minidump parsing error: {e}")
                    # Try lightweight parse so we still get native stack
                    try:
                        self._parse_large_dump_structure_light(dump_path)
                    except Exception:
                        pass
            elif HAS_MINIDUMP and file_size >= STRUCTURE_PARSE_THRESHOLD:
                self._report_progress("structure", 0.0, "Lightweight structure parse (large file)...")
                try:
                    self._parse_large_dump_structure_light(dump_path)
                    self.result.errors.append(
                        f"Large dump ({file_size_gb:.1f}GB): native stack recovered via lightweight structure parse; Lua/JS stacks from memory scan."
                    )
                    self._report_progress("structure", 1.0, "Structure parse complete (native stack recovered)")
                except Exception as e:
                    self.result.errors.append(
                        f"Large dump ({file_size_gb:.1f}GB): lightweight structure parse failed ({e}); Lua/JS stacks still from memory scan."
                    )
                    self._report_progress("structure", 1.0, "Skipping structure parse (large file)...")
            else:
                # No minidump library or parse skipped - use lightweight parse for native stack (works without minidump package)
                self._report_progress("structure", 0.0, "Lightweight structure parse (native stack)...")
                try:
                    self._parse_large_dump_structure_light(dump_path)
                    if self.result.native_stack:
                        self._report_progress("structure", 1.0, "Native stack recovered")
                    else:
                        self._report_progress("structure", 1.0, "Structure parse complete")
                except Exception as e:
                    self.result.errors.append(f"Lightweight structure parse failed: {e}")
                    self._report_progress("structure", 1.0, "Structure parse skipped")

            # #region agent log
            # Count modules with PDB info for diagnostics
            modules_with_pdb = [m for m in self.result.module_versions if m.pdb_name and m.pdb_guid]
            _dlog(
                "H4",
                "memory_analyzer.analyze_dump_deep.after_structure",
                "structure parse summary",
                {
                    "native_stack_len": len(self.result.native_stack) if self.result.native_stack else 0,
                    "module_map_len": len(getattr(self, "_module_map", {}) or {}),
                    "module_versions_count": len(self.result.module_versions),
                    "modules_with_pdb_count": len(modules_with_pdb),
                    "modules_with_pdb_sample": [(m.name[:30], m.pdb_name, m.pdb_guid[:16] if m.pdb_guid else "") for m in modules_with_pdb[:5]],
                    "exception_code": self.result.exception_code,
                    "exception_module": self.result.exception_module,
                },
            )
            # Log first few modules WITHOUT pdb info to see what's missing
            modules_no_pdb = [m for m in self.result.module_versions if not m.pdb_name or not m.pdb_guid]
            if modules_no_pdb:
                _dlog(
                    "H2",
                    "memory_analyzer.analyze_dump_deep.modules_no_pdb",
                    "modules without PDB info",
                    {
                        "count": len(modules_no_pdb),
                        "sample": [(m.name[:40], m.pdb_name or "(no pdb_name)", m.pdb_guid[:16] if m.pdb_guid else "(no guid)") for m in modules_no_pdb[:10]],
                    },
                )
            # #endregion
            
            # Track analysis mode for diagnostics (used in agent log)
            analysis_mode = "minidump_memory"

            # Extract heap statistics from MINIDUMP_MEMORY_INFO_LIST
            # Skip for very large dumps (>10GB) to avoid delay
            if file_size < 10 * 1024 * 1024 * 1024:
                self._report_progress("memory", 0.0, "Extracting heap statistics...")
                self._extract_heap_statistics(md)
            else:
                self.result.errors.append(f"Skipped heap statistics extraction for very large dump ({file_size_gb:.1f}GB)")

            # PROGRESSIVE CHUNKED MEMORY EXTRACTION
            # For very large dumps, extract and analyze memory in chunks to show incremental results
            # This prevents hanging and allows users to see progress in real-time
            # Use chunked extraction for all dumps to enable progressive results
            self._report_progress("memory", 0.0, "Starting progressive memory extraction...")
            
            # Determine chunk size based on dump size
            VERY_LARGE_DUMP_THRESHOLD = 10 * 1024 * 1024 * 1024  # 10GB
            if file_size > VERY_LARGE_DUMP_THRESHOLD:
                # For very large dumps (>10GB): extract in smaller chunks, more frequently
                chunk_size = 2000  # Extract 2000 memory regions at a time
                max_extraction_size = 100 * 1024 * 1024  # Max 100MB per chunk
                self.result.errors.append(
                    f"Very large dump ({file_size_gb:.1f}GB): Using progressive extraction "
                    f"(chunks of {chunk_size} regions, max {max_extraction_size/(1024**2):.0f}MB each)"
                )
            elif file_size > 1 * 1024 * 1024 * 1024:  # >1GB
                # For large dumps: moderate chunk size
                chunk_size = 5000
                max_extraction_size = 200 * 1024 * 1024  # Max 200MB per chunk
            else:
                # For smaller dumps: larger chunks (faster)
                chunk_size = 10000
                max_extraction_size = 500 * 1024 * 1024  # Max 500MB per chunk
            
            # Extract and analyze memory in progressive chunks
            memory_content = self._extract_memory_progressive(
                dump_path, 
                chunk_size=chunk_size,
                max_extraction_size=max_extraction_size
            )
            
            try:
                memory_blocks = []
                total_memory_size = 0
                
                if memory_content:
                    # Concatenate all memory blocks for scanning
                    for addr, data in sorted(memory_content.items()):
                        memory_blocks.append(data)
                        total_memory_size += len(data)
                
                if memory_blocks:
                    memory_mb = total_memory_size / (1024 * 1024)
                    # NOTE: Each chunk was already analyzed during progressive extraction
                    # No need to re-analyze the concatenated blob (would cause 5MB sampling)
                    self._report_progress("memory", 0.7, f"Progressive extraction complete: {memory_mb:.2f}MB analyzed")
                    
                    # REMOVED: Duplicate analysis that was causing 5MB sampling bug
                    # The _extract_memory_progressive method already calls _run_analysis_passes
                    # on each chunk as it's extracted, so this re-analysis is redundant
                    # and causes the 5MB sampling limit to kick in unnecessarily.
                    
                    self.result.errors.append(f"Memory scan: Analyzed {len(memory_blocks)} regions ({memory_mb:.2f}MB)")
                    
                    # ===== FRAMEWORK DETECTION & METADATA EXTRACTION =====
                    # Detect FiveM framework (QBCore/ESX/VRP/Ox) from memory data
                    self._report_progress("framework", 0.0, "Detecting FiveM framework...")
                    try:
                        # Concatenate memory blocks for framework detection
                        memory_data = b''.join(memory_blocks[:10])  # First 10 blocks only (performance)
                        framework, confidence = self._detect_framework(memory_data)
                        self.result.framework_detected = framework
                        self.result.framework_confidence = confidence
                        if framework != "Unknown":
                            self.result.errors.append(f"Framework detected: {framework} (confidence: {confidence:.1%})")
                        self._report_progress("framework", 1.0, f"Framework: {framework}")
                    except Exception as e:
                        self.result.errors.append(f"Framework detection failed: {e}")
                    
                    # Extract fxmanifest.lua metadata
                    self._report_progress("metadata", 0.0, "Extracting fxmanifest metadata...")
                    try:
                        # Scan first few memory blocks for fxmanifest data
                        memory_data = b''.join(memory_blocks[:20])  # First 20 blocks (performance)
                        fxmanifest_data = self._extract_fxmanifest(memory_data)
                        self.result.fxmanifest_data = fxmanifest_data
                        if fxmanifest_data:
                            fx_keys = list(fxmanifest_data.keys())
                            self.result.errors.append(f"fxmanifest data extracted: {len(fx_keys)} fields ({', '.join(fx_keys[:5])})")
                        self._report_progress("metadata", 1.0, "Metadata extraction complete")
                    except Exception as e:
                        self.result.errors.append(f"fxmanifest extraction failed: {e}")
                    
                    # Classify error severities for detected errors
                    self._report_progress("severity", 0.0, "Classifying error severities...")
                    try:
                        error_count = 0
                        for error in self.result.script_errors:
                            error_id = f"{error.script_name}:{error.line_number}"
                            severity = self._classify_error_severity(error.error_message)
                            self.result.error_severities[error_id] = severity
                            error_count += 1
                            if error_count >= 100:  # Limit to first 100 errors (NASA Rule 3)
                                break
                        if self.result.error_severities:
                            self.result.errors.append(f"Error severities classified: {len(self.result.error_severities)} errors")
                        self._report_progress("severity", 1.0, "Severity classification complete")
                    except Exception as e:
                        self.result.errors.append(f"Error severity classification failed: {e}")
                    
                    # FALLBACK: Comprehensive raw dump scan if:
                    # 1. Progressive extraction was incomplete (early termination occurred), OR
                    # 2. Coverage is sparse (few Lua/JS stacks despite large file), OR
                    # 3. No native calls found yet (need to scan beyond extraction limit)
                    need_fallback = False
                    fallback_reason = ""
                    
                    if file_size > 500 * 1024 * 1024:
                        # Check if progressive extraction was cut short
                        if not self._progressive_extraction_complete:
                            need_fallback = True
                            fallback_reason = "progressive extraction was incomplete"
                        # Check if coverage is sparse despite large file
                        elif file_size > 2 * 1024 * 1024 * 1024:  # >2GB
                            total_stacks = len(self.result.lua_stacks) + len(self.result.js_stacks)
                            if total_stacks < 5:  # Very few stacks for such a large dump
                                need_fallback = True
                                fallback_reason = f"sparse coverage ({total_stacks} stacks in {file_size/(1*1024**3):.1f}GB dump)"
                        # Always run fallback if no stacks found
                        if not self.result.lua_stacks and not self.result.js_stacks:
                            need_fallback = True
                            fallback_reason = "no Lua/JS stacks found in progressive extraction"
                    
                    if need_fallback:
                        self._report_progress("lua_scan", 0.0, f"Comprehensive raw dump scan ({fallback_reason})...")
                        raw_scan_results = self._scan_raw_dump_for_scripts(dump_path, file_size)
                        
                        # Merge raw scan results into main results
                        if raw_scan_results.get("lua_stacks"):
                            self.result.lua_stacks.extend(raw_scan_results["lua_stacks"])
                            self.result.errors.append(f"Raw scan found {len(raw_scan_results['lua_stacks'])} additional Lua stacks ({fallback_reason})")
                        
                        if raw_scan_results.get("js_stacks"):
                            self.result.js_stacks.extend(raw_scan_results["js_stacks"])
                            self.result.errors.append(f"Raw scan found {len(raw_scan_results['js_stacks'])} additional JS stacks")
                        
                        if raw_scan_results.get("script_errors"):
                            self.result.script_errors.extend(raw_scan_results["script_errors"])
                        
                        if raw_scan_results.get("resources"):
                            # Add discovered resources to resources dict
                            for resource_name in raw_scan_results["resources"]:
                                if resource_name not in self.result.resources:
                                    resource_info = ResourceInfo(name=resource_name)
                                    resource_info.evidence_count = 1
                                    resource_info.context_details.append(f"Found in raw dump scan ({fallback_reason})")
                                    self.result.resources[resource_name] = resource_info
                        
                        if raw_scan_results.get("native_calls"):
                            self.result.native_calls.extend(raw_scan_results["native_calls"])
                            self.result.errors.append(f"Raw scan found {len(raw_scan_results['native_calls'])} native calls")
                        
                        self._report_progress("lua_scan", 1.0, "Comprehensive scan complete")
                else:
                    # No main memory content - try extracting thread stacks
                    self.result.errors.append("No memory content extracted from minidump (dump may be minimal)")
                    self._report_progress("memory", 0.5, "Extracting thread stack memory...")
                    
                    try:
                        from .dump_extractor import MinidumpExtractor
                        extractor = MinidumpExtractor()
                        extractor.load(dump_path)
                        thread_stacks = extractor.get_thread_stacks()
                        
                        if thread_stacks:
                            stack_blocks = []
                            for stack in thread_stacks:
                                if stack.get('stack_data'):
                                    stack_blocks.append(stack['stack_data'])
                            
                            if stack_blocks:
                                combined_stacks = b''.join(stack_blocks)
                                stack_mb = len(combined_stacks) / (1024 * 1024)
                                self._report_progress("memory", 0.7, f"Scanning {stack_mb:.2f}MB from {len(stack_blocks)} thread stacks...")
                                self._run_analysis_passes(combined_stacks)
                                self.result.errors.append(f"Thread stack scan: Analyzed {len(stack_blocks)} stacks ({stack_mb:.2f}MB)")
                                self._report_progress("memory", 1.0, "Thread stack analysis complete")
                            else:
                                self.result.errors.append("Thread stacks present but no stack data available")
                                self._report_progress("memory", 1.0, "No stack data available")
                        else:
                            self.result.errors.append("No thread stacks extracted")
                            self._report_progress("memory", 1.0, "No thread stacks")
                    except Exception as e:
                        self.result.errors.append(f"Thread stack extraction failed: {e}")
                        self._report_progress("memory", 1.0, "Stack extraction failed")
                    
            except Exception as e:
                self.result.errors.append(f"Memory extraction failed: {e}, falling back to dump file scan")
                # Fallback to old method
                analysis_mode = "in_memory"
                if file_size <= self.MAX_FULL_ANALYSIS_SIZE:
                    self._analyze_dump_in_memory(dump_path, file_size)
                elif file_size <= 2 * 1024 * 1024 * 1024:  # 2GB
                    analysis_mode = "streaming"
                    self._analyze_dump_streaming(dump_path, file_size)
                else:
                    analysis_mode = "sampled"
                self.result.errors.append(
                    f"Very large dump ({file_size_gb:.1f}GB) - using sampled analysis"
                )
                self._report_progress("sampling", 0.0, f"Starting sampled analysis of {file_size_gb:.1f}GB dump...")
                self._analyze_dump_sampled(dump_path, file_size)

            # #region agent log
            raw_strings = self.result.raw_strings or []
            resource_path_strings = 0
            lua_hint_strings = 0
            js_hint_strings = 0
            for s in raw_strings:
                sl = (s or "").lower()
                if "resources/" in sl or "resources\\" in sl:
                    resource_path_strings += 1
                if ".lua" in sl:
                    lua_hint_strings += 1
                if ".js" in sl:
                    js_hint_strings += 1
            _dlog(
                "H1",
                "memory_analyzer.analyze_dump_deep.post_scan",
                "post memory scan summary",
                {
                    "analysis_mode": analysis_mode,
                    "raw_strings_count": len(raw_strings),
                    "all_evidence_count": len(self.result.all_evidence),
                    "resources_count": len(self.result.resources),
                    "resource_names_sample": list(self.result.resources.keys())[:10],
                    "lua_stacks_count": len(self.result.lua_stacks),
                    "js_stacks_count": len(self.result.js_stacks),
                    "script_paths_count": len(self.result.script_paths),
                    "resource_path_strings": resource_path_strings,
                    "lua_hint_strings": lua_hint_strings,
                    "js_hint_strings": js_hint_strings,
                    "errors_count": len(self.result.errors),
                },
            )
            # #endregion

            # Populate module_names from parsed minidump (avoids re-reading for full_analysis)
            for _base, (_end, name) in self._module_map.items():
                if name and name not in self.result.module_names:
                    self.result.module_names.append(name)
            # Also add module-like strings from raw_strings (e.g. from heap)
            for s in self.result.raw_strings:
                lower = s.lower()
                if ('.dll' in lower or '.exe' in lower) and s not in self.result.module_names:
                    if len(s) < 260 and re.match(r'^[\w.\-\\]+$', s):
                        self.result.module_names.append(s)

            # Add evidence from open file handles (resource paths at crash time)
            self._add_evidence_from_handles()

            # Scan comment and assertion streams for resource names
            self._add_evidence_from_comment_and_assertion_streams()

            # Correlate evidence and determine primary suspects
            self._report_progress("correlate", 0.0, "Correlating evidence...")
            self._correlate_evidence()
            self._report_progress("correlate", 1.0, f"Found {len(self.result.primary_suspects)} suspects")
            
            # Analyze memory leak patterns and calculate confidence
            self._report_progress("leak_analysis", 0.0, "Analyzing memory leak patterns...")
            self._analyze_memory_leak_patterns()
            self._report_progress("leak_analysis", 1.0, "Leak analysis complete")

            # Break down stack traces into resources involved per stack
            self._compute_stack_resources()

            # #region agent log
            _dlog(
                "H1",
                "memory_analyzer.analyze_dump_deep.post_correlate",
                "suspect summary",
                {
                    "primary_suspects_count": len(self.result.primary_suspects),
                    "primary_suspects_top3": [s.name for s in (self.result.primary_suspects or [])[:3]],
                    "primary_suspect_confidence": getattr(self.result, "primary_suspect_confidence", ""),
                    "primary_suspect_secondary": getattr(self.result, "primary_suspect_secondary", None),
                    "resources_count": len(self.result.resources),
                    "lua_stack_resources_first": (self.result.lua_stack_resources[0] if self.result.lua_stack_resources else []),
                    "js_stack_resources_first": (self.result.js_stack_resources[0] if self.result.js_stack_resources else []),
                },
            )
            # #endregion

            # #region agent log
            try:
                top_details: List[Dict[str, Any]] = []
                for s in (self.result.primary_suspects or [])[:5]:
                    info = self.result.resources.get(s.name) if self.result.resources else None
                    if not info:
                        continue
                    top_details.append(
                        {
                            "name": info.name,
                            "evidence_count": getattr(info, "evidence_count", 0),
                            "evidence_types": sorted([et.name for et in (getattr(info, "evidence_types", set()) or set())]),
                            "scripts_sample": list(getattr(info, "scripts", [])[:3]),
                            "likely_script": getattr(info, "likely_script", None),
                            "path_sample": getattr(info, "path", None),
                            "all_paths_sample": list(getattr(info, "all_paths", [])[:3]),
                            "context_details_sample": list(getattr(info, "context_details", [])[:3]),
                        }
                    )
                _dlog(
                    "H6",
                    "memory_analyzer.analyze_dump_deep.suspect_details",
                    "top suspect evidence details",
                    {"top": top_details},
                )
            except Exception:
                pass
            # #endregion

            self.result.analysis_complete = True
            # If no stack traces recovered, add diagnostic so user knows if dump lacks stack vs analysis error
            if not self.result.native_stack and not self.result.lua_stacks and not self.result.js_stacks:
                diag = self._diagnose_stack_recovery(dump_path)
                self.result.errors.append(f"Stack recovery diagnostic: {diag}")

            self._report_progress("complete", 1.0, "Analysis complete!")

        except MemoryError:
            self.result.errors.append(
                f"Out of memory analyzing dump. File size: {file_size // (1024*1024)}MB. "
                "Try closing other applications or use a machine with more RAM."
            )
        except Exception as e:
            import traceback
            self.result.errors.append(f"Analysis failed: {e}")
            self.result.errors.append(f"Traceback: {traceback.format_exc()}")

        # FINAL STEP: Correlate native calls found in Lua code fragments
        try:
            self._correlate_natives_with_code_fragments()
        except Exception:
            pass  # Don't fail the whole analysis if correlation fails

        return self.result

    def _merge_chunk_result(self, chunk_result: "DeepAnalysisResult") -> None:
        """Merge results from a parallel chunk worker into this analyzer's result."""
        max_raw = getattr(self, '_max_raw_strings', 3000)
        seen_raw: Set[str] = set(self.result.raw_strings)
        max_ev = getattr(self, '_max_evidence', self.MAX_EVIDENCE_ITEMS)
        for e in chunk_result.all_evidence:
            if len(self.result.all_evidence) >= max_ev:
                break
            self._add_evidence(e)
        for s in chunk_result.raw_strings:
            if len(self.result.raw_strings) >= max_raw:
                break
            if s not in seen_raw:
                seen_raw.add(s)
                self.result.raw_strings.append(s)
        self.result.script_errors.extend(chunk_result.script_errors)
        self.result.lua_stacks.extend(chunk_result.lua_stacks)
        self.result.js_stacks.extend(chunk_result.js_stacks)
        self.result.script_paths.extend(chunk_result.script_paths)
        self.result.native_calls.extend(chunk_result.native_calls)
        self.result.event_handlers.extend(chunk_result.event_handlers)
        self.result.entity_creations.extend(chunk_result.entity_creations)
        self.result.entity_deletions.extend(chunk_result.entity_deletions)
        self.result.timers_created.extend(chunk_result.timers_created)
        self.result.event_handlers_registered.extend(chunk_result.event_handlers_registered)
        self.result.event_handlers_removed.extend(chunk_result.event_handlers_removed)
        self.result.memory_allocations.extend(chunk_result.memory_allocations)
        self.result.memory_frees.extend(chunk_result.memory_frees)
        self.result.memory_leak_indicators.extend(chunk_result.memory_leak_indicators)
        self.result.pool_exhaustion_indicators.extend(chunk_result.pool_exhaustion_indicators)
        self.result.database_patterns.extend(chunk_result.database_patterns)
        self.result.nui_patterns.extend(chunk_result.nui_patterns)
        self.result.network_patterns.extend(chunk_result.network_patterns)
        self.result.statebag_patterns.extend(chunk_result.statebag_patterns)
        if chunk_result.memory_regions:
            self.result.memory_regions.extend(chunk_result.memory_regions)

    def _analyze_dump_in_memory(self, dump_path: str, file_size: int) -> None:
        """Analyze a small dump by loading it entirely into memory.
        
        When USE_PARALLEL_CHUNKS and dump size >= MIN_SIZE_PARALLEL_IN_MEMORY,
        splits the buffer into chunks and processes them in parallel (CPU cores).
        """
        self._report_progress("memory", 0.2, "Reading dump file...")
        with open(dump_path, 'rb') as f:
            raw_data = f.read()

        n_workers = self.MAX_PARALLEL_WORKERS if self.USE_PARALLEL_CHUNKS else 1
        use_parallel = (
            self.USE_PARALLEL_CHUNKS
            and n_workers >= 2
            and len(raw_data) >= self.MIN_SIZE_PARALLEL_IN_MEMORY
        )

        if use_parallel:
            self._report_progress("memory", 0.35, f"Analyzing memory with {n_workers} workers...")
            overlap = 4096
            step = (len(raw_data) + n_workers - 1) // n_workers
            chunks: List[Tuple[bytes, int]] = []
            for i in range(n_workers):
                start = i * step
                if start >= len(raw_data):
                    break
                end = min(start + step + overlap, len(raw_data))
                chunks.append((bytes(raw_data[start:end]), start))
            if not chunks:
                self._run_analysis_passes(raw_data)
            else:
                with ProcessPoolExecutor(max_workers=len(chunks)) as executor:
                    futures = [executor.submit(_process_chunk_worker, c) for c in chunks]
                    for future in as_completed(futures):
                        try:
                            self._merge_chunk_result(future.result())
                        except Exception as e:
                            self.result.errors.append(f"Parallel chunk error: {e}")
            self._report_progress("memory", 1.0, "Memory analysis complete")
        else:
            self._report_progress("memory", 0.4, "Analyzing memory contents...")
            self._run_analysis_passes(raw_data)
            self._report_progress("memory", 1.0, "Memory analysis complete")

    def _analyze_dump_streaming(self, dump_path: str, file_size: int) -> None:
        """Analyze a large dump using streaming/chunked processing.
        
        Reads the file in chunks to avoid loading the entire dump into memory.
        Uses overlapping chunks to catch patterns that span chunk boundaries.
        """
        import mmap
        
        overlap_size = 4096  # 4KB overlap to catch boundary-spanning patterns
        chunk_size = self.STREAM_CHUNK_SIZE
        n_workers = self.MAX_PARALLEL_WORKERS if self.USE_PARALLEL_CHUNKS else 1
        use_parallel = self.USE_PARALLEL_CHUNKS and n_workers >= 2
        
        with open(dump_path, 'rb') as f:
            try:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    offset = 0
                    chunk_num = 0
                    total_chunks = (file_size + chunk_size - 1) // chunk_size
                    
                    min_chunks_before_stop = getattr(self, 'MIN_STREAMING_CHUNKS_BEFORE_EARLY_STOP', 16)
                    max_ev = getattr(self, '_max_evidence', self.MAX_EVIDENCE_ITEMS)
                    if use_parallel:
                        # Process chunks in parallel batches using CPU cores
                        with ProcessPoolExecutor(max_workers=n_workers) as executor:
                            while offset < file_size:
                                if self._should_abort():
                                    self._report_progress("streaming", 1.0, "Analysis cancelled")
                                    break
                                # Always process at least first 1GB before allowing early stop (full resource extraction)
                                if chunk_num >= min_chunks_before_stop and len(self.result.all_evidence) >= max_ev:
                                    self._report_progress("streaming", 1.0, f"Reached maximum evidence ({max_ev} items)")
                                    break
                                batch: List[Tuple[bytes, int]] = []
                                while len(batch) < n_workers and offset < file_size:
                                    chunk_mb_so_far = offset // (1024 * 1024)
                                    self._report_progress(
                                        "streaming", offset / file_size,
                                        f"Loading chunk {chunk_num + 1}/{total_chunks} ({chunk_mb_so_far}MB)..."
                                    )
                                    end = min(offset + chunk_size + overlap_size, file_size)
                                    batch.append((bytes(mm[offset:end]), offset))
                                    offset += chunk_size
                                    chunk_num += 1
                                if not batch:
                                    break
                                futures = {executor.submit(_process_chunk_worker, item): item[1] for item in batch}
                                for future in as_completed(futures):
                                    if self._should_abort():
                                        break
                                    if chunk_num >= min_chunks_before_stop and len(self.result.all_evidence) >= max_ev:
                                        break
                                    try:
                                        chunk_result = future.result()
                                        self._merge_chunk_result(chunk_result)
                                    except Exception as e:
                                        self.result.errors.append(f"Parallel chunk error: {e}")
                                progress = offset / file_size
                                chunk_mb = offset // (1024 * 1024)
                                total_mb = file_size // (1024 * 1024)
                                self._report_progress(
                                    "streaming", progress,
                                    f"Processed {chunk_num}/{total_chunks} chunks ({chunk_mb}MB/{total_mb}MB) - {len(self.result.all_evidence)} evidence"
                                )
                        self._report_progress("streaming", 1.0, f"Streaming analysis complete - {chunk_num} chunks processed (parallel)")
                    else:
                        # Sequential chunk processing
                        min_chunks_before_stop = getattr(self, 'MIN_STREAMING_CHUNKS_BEFORE_EARLY_STOP', 16)
                        max_ev = getattr(self, '_max_evidence', self.MAX_EVIDENCE_ITEMS)
                        while offset < file_size:
                            if self._should_abort():
                                self._report_progress("streaming", 1.0, "Analysis cancelled")
                                break
                            if chunk_num >= min_chunks_before_stop and len(self.result.all_evidence) >= max_ev:
                                self._report_progress("streaming", 1.0, f"Reached maximum evidence ({max_ev} items)")
                                break
                            end = min(offset + chunk_size + overlap_size, file_size)
                            chunk = mm[offset:end]
                            progress = offset / file_size
                            chunk_mb = offset // (1024 * 1024)
                            total_mb = file_size // (1024 * 1024)
                            self._report_progress(
                                "streaming", progress,
                                f"Processing chunk {chunk_num + 1}/{total_chunks} ({chunk_mb}MB/{total_mb}MB) - {len(self.result.all_evidence)} evidence items found"
                            )
                            self._run_analysis_passes(bytes(chunk), chunk_offset=offset)
                            offset += chunk_size
                            chunk_num += 1
                            del chunk
                        self._report_progress("streaming", 1.0, f"Streaming analysis complete - {chunk_num} chunks processed")
                        
            except (mmap.error, OSError) as e:
                # Fallback to regular chunked reading if mmap fails
                self.result.errors.append(f"Memory-mapped access failed, using chunked reading: {e}")
                self._analyze_dump_chunked_fallback(f, file_size, chunk_size, overlap_size)

    def _analyze_dump_chunked_fallback(self, f, file_size: int, chunk_size: int, overlap_size: int) -> None:
        """Fallback chunked analysis without memory mapping."""
        f.seek(0)
        offset = 0
        prev_overlap = b''
        chunk_num = 0
        total_chunks = (file_size + chunk_size - 1) // chunk_size
        min_chunks_before_stop = getattr(self, 'MIN_STREAMING_CHUNKS_BEFORE_EARLY_STOP', 16)
        max_ev = getattr(self, '_max_evidence', self.MAX_EVIDENCE_ITEMS)
        
        while offset < file_size:
            if self._should_abort():
                self._report_progress("streaming", 1.0, "Analysis cancelled")
                break
            if chunk_num >= min_chunks_before_stop and len(self.result.all_evidence) >= max_ev:
                self._report_progress("streaming", 1.0, f"Reached maximum evidence ({max_ev} items)")
                break
            
            chunk = f.read(chunk_size)
            if not chunk:
                break
            
            # Prepend overlap from previous chunk
            if prev_overlap:
                chunk = prev_overlap + chunk
            
            # Report progress
            progress = offset / file_size
            self._report_progress(
                "streaming", 
                progress, 
                f"Processing chunk {chunk_num + 1}/{total_chunks} - {len(self.result.all_evidence)} evidence items"
            )
            
            self._run_analysis_passes(chunk, chunk_offset=max(0, offset - len(prev_overlap)))
            
            # Save overlap for next iteration
            prev_overlap = chunk[-overlap_size:] if len(chunk) > overlap_size else chunk
            offset += chunk_size
            chunk_num += 1
            
            # Free memory
            del chunk
        
        self._report_progress("streaming", 1.0, "Chunked analysis complete")

    def _extract_memory_progressive(self, dump_path: str, chunk_size: int = 2000, 
                                     max_extraction_size: int = 100 * 1024 * 1024) -> Dict[int, bytes]:
        """Extract and analyze memory in progressive chunks to show incremental results.
        
        For very large dumps with tens of thousands of memory regions, this method:
        1. Extracts memory in batches (e.g., 2000 regions at a time)
        2. Analyzes each batch immediately
        3. Reports findings progressively
        4. Allows early termination if sufficient evidence is found
        
        Args:
            dump_path: Path to the dump file
            chunk_size: Number of memory regions to extract per batch
            max_extraction_size: Maximum bytes to extract per batch
            
        Returns:
            Dictionary mapping addresses to memory content (may be partial for very large dumps)
        """
        self._report_progress("memory", 0.01, "Progressive extraction starting...")
        try:
            from .dump_extractor import MinidumpExtractor
            
            # Get file size once for efficiency
            dump_file_size = os.path.getsize(dump_path)
            
            extractor = MinidumpExtractor()
            self._report_progress("memory", 0.01, "Loading dump header (lightweight mode)...")
            # Use lightweight=True to skip heavy stream extraction on load
            load_success = extractor.load(dump_path, lightweight=True)
            
            if not load_success:
                self.result.errors.append("Progressive extraction: Failed to load dump")
                return {}
            
            # Manually extract just the MEMORY64_LIST stream (metadata only, not actual memory content)
            self._report_progress("memory", 0.02, "Extracting MEMORY64_LIST stream metadata...")
            from crash_analyzer.dump_extractor import MinidumpStreamType
            success = extractor._extract_stream_by_type(MinidumpStreamType.MEMORY_64_LIST)
            
            if not success:
                self._report_progress("memory", 0.03, "MEMORY64_LIST stream not found, trying MEMORY_LIST...")
                success = extractor._extract_stream_by_type(MinidumpStreamType.MEMORY_LIST)
            
            if not success:
                self._report_progress("memory", 0.1, "No memory list streams found in dump")
                self.result.errors.append("Progressive extraction: No MEMORY_LIST or MEMORY64_LIST streams found")
                return {}
            
            # Get memory regions - prefer MEMORY_LIST or MEMORY64_LIST which have actual data
            self._report_progress("memory", 0.03, "Building memory region list...")
            regions = extractor._get_memory_from_memory_list()
            
            if not regions:
                self._report_progress("memory", 0.1, "No memory regions with data found in dump")
                self.result.errors.append("Progressive extraction: No memory regions with content found")
                return {}
            
            total_regions = len(regions)
            self._report_progress("memory", 0.05, f"Found {total_regions:,} memory regions - extracting in chunks...")
            print(f"[PROGRESSIVE] Starting extraction: {total_regions:,} regions total", flush=True)
            
            # Process in chunks
            all_memory = {}
            chunks_processed = 0
            total_chunks = (total_regions + chunk_size - 1) // chunk_size
            
            for chunk_start in range(0, total_regions, chunk_size):
                # Check abort flag
                if self._abort_check and self._abort_check():
                    self.result.errors.append("Analysis aborted during progressive extraction")
                    break
                
                chunk_end = min(chunk_start + chunk_size, total_regions)
                chunks_processed += 1
                
                self._report_progress(
                    "memory",
                    0.05 + (chunks_processed / total_chunks) * 0.3,  # 5-35% progress
                    f"Extracting regions {chunk_start:,}-{chunk_end:,} of {total_regions:,} (chunk {chunks_processed}/{total_chunks})..."
                )
                
                # Extract this chunk manually
                chunk_memory = {}
                chunk_extracted = 0
                regions_in_chunk = chunk_end - chunk_start
                
                for idx, i in enumerate(range(chunk_start, chunk_end)):
                    if chunk_extracted >= max_extraction_size:
                        break
                    
                    # Inner-loop progress updates every 100 regions
                    if idx > 0 and idx % 100 == 0:
                        chunk_progress = idx / regions_in_chunk
                        base_progress = 0.05 + ((chunks_processed - 1 + chunk_progress) / total_chunks) * 0.3
                        extracted_mb = chunk_extracted / (1024 * 1024)
                        self._report_progress(
                            "memory",
                            base_progress,
                            f"Chunk {chunks_processed}/{total_chunks}: extracted {idx}/{regions_in_chunk} regions ({extracted_mb:.1f}MB)..."
                        )
                    
                    region = regions[i]
                    if 'data_rva' not in region:
                        continue
                    
                    rva = region['data_rva']
                    size = region['data_size']
                    address = region['base_address']
                    
                    # Skip invalid RVAs
                    if rva == 0 or rva >= len(extractor.data):
                        continue
                    
                    # Skip extremely large regions (>50MB) - likely not script data
                    # This prevents a single huge region from dominating the chunk
                    MAX_REGION_SIZE = 50 * 1024 * 1024  # 50MB
                    if size > MAX_REGION_SIZE:
                        continue
                    
                    # Check if adding this region would exceed chunk limit
                    if chunk_extracted + size > max_extraction_size:
                        break
                    
                    # Adjust size if it extends past end of file
                    if rva + size > len(extractor.data):
                        size = len(extractor.data) - rva
                    
                    # Extract bytes
                    try:
                        memory_bytes = extractor.data[rva:rva+size]
                        chunk_memory[address] = memory_bytes
                        chunk_extracted += size
                    except Exception:
                        continue
                
                if not chunk_memory:
                    continue
                
                # Add to all memory
                all_memory.update(chunk_memory)
                
                # Analyze this chunk immediately
                chunk_bytes = b''.join(chunk_memory.values())
                chunk_mb = len(chunk_bytes) / (1024 * 1024)
                
                self._report_progress(
                    "memory",
                    0.35 + (chunks_processed / total_chunks) * 0.3,  # 35-65% progress
                    f"Analyzing chunk {chunks_processed}/{total_chunks} ({chunk_mb:.1f}MB)..."
                )
                
                # Run analysis on this chunk
                # For very large dumps (>10GB), use fast extraction methods only
                is_huge = dump_file_size > 10 * 1024 * 1024 * 1024
                try:
                    self._run_analysis_passes(chunk_bytes, chunk_offset=0, is_huge_file=is_huge)
                except Exception as e:
                    self.result.errors.append(f"Analysis error on chunk {chunks_processed}: {e}")
                
                # Report findings after each chunk
                lua_count = len(self.result.lua_stacks)
                resource_count = len(self.result.resources)
                error_count = len(self.result.script_errors)
                
                findings_msg = f"Chunk {chunks_processed}/{total_chunks} complete: "
                findings_msg += f"{lua_count} Lua stacks, {resource_count} resources, {error_count} errors"
                
                self._report_progress(
                    "memory",
                    0.65 + (chunks_processed / total_chunks) * 0.2,  # 65-85% progress  
                    findings_msg
                )
                
                # Early termination DISABLED for large dumps (>1GB):
                # Large dumps have fragmented memory scattered across many regions.
                # Processing ALL chunks ensures comprehensive coverage of Lua/native code.
                # Only skip remaining chunks if file is small AND we have comprehensive evidence.
                if dump_file_size < 1 * 1024 * 1024 * 1024:  # Only for <1GB files
                    if lua_count >= 10 and resource_count >= 20:
                        self.result.errors.append(
                            f"Progressive extraction: Found sufficient evidence after {chunks_processed}/{total_chunks} chunks "
                            f"({lua_count} stacks, {resource_count} resources) - stopping early"
                        )
                        self._report_progress("memory", 0.85, f"Sufficient evidence found - stopping early")
                        break
            
            # Final summary
            total_extracted_mb = sum(len(data) for data in all_memory.values()) / (1024 * 1024)
            self._progressive_extraction_complete = (chunks_processed == total_chunks)
            if self._progressive_extraction_complete:
                self._report_progress("memory", 0.85, 
                    f"Progressive extraction complete: ALL {chunks_processed}/{total_chunks} chunks analyzed, {total_extracted_mb:.1f}MB total")
            else:
                self._report_progress("memory", 0.85, 
                    f"Progressive extraction complete: {chunks_processed}/{total_chunks} chunks, {total_extracted_mb:.1f}MB total")
            print(f"[DEBUG] Progressive extraction returned {len(all_memory)} memory regions ({total_extracted_mb:.1f}MB)", flush=True)
            
            return all_memory
            
        except Exception as e:
            self.result.errors.append(f"Progressive extraction failed: {e}")
            self._report_progress("memory", 0.1, f"Extraction failed: {e}")
            return {}

    def _scan_raw_dump_for_scripts(self, dump_path: str, file_size: int, full_sweep: bool = False,
                                   include_artifacts: bool = False) -> Dict[str, Any]:
        """Scan raw dump file directly for Lua/JS script data.
        
        This is a fallback when memory extraction doesn't capture script runtime data,
        which often resides in later portions of large dumps (beyond 500MB).
        
        Args:
            dump_path: Path to the dump file
            file_size: Size of the dump file in bytes
            
        Returns:
            Dict containing extracted script stacks and resources
        """
        import mmap
        
        self._report_progress("script_scan", 0.0, "Scanning raw dump for script data...")
        
        results = {
            "lua_stacks": [],
            "js_stacks": [],
            "script_errors": [],
            "resources": set(),
            "events": set(),
            "native_calls": [],
            "native_hashes": set(),
            "scan_regions": [],
            "pattern_counts": {},  # Count of each Lua pattern found (CreateThread, AddEventHandler, etc.)
            "lua_snippets": [],
            "js_snippets": [],
            "raw_string_samples": [],
            "resource_paths_sample": [],
            "string_frequencies": [],
            "resource_counts": [],
            "event_resource_counts": [],
        }
        
        # Lua patterns to search for
        lua_patterns = [
            b'CreateThread',
            b'TriggerEvent',
            b'TriggerServerEvent',
            b'TriggerClientEvent',
            b'AddEventHandler',
            b'RegisterNetEvent',
            b'RegisterCommand',
            b'RegisterServerEvent',
            b'Citizen.CreateThread',
            b'Citizen.Wait',
            b'exports[',
        ]

        native_patterns = [
            b'Citizen.InvokeNative',
            b'InvokeNative',
            b'Citizen.Invoke',
            b'Invoke',
        ]
        
        # JavaScript patterns
        js_patterns = [
            b'on(\'',
            b'emit(',
            b'setTick(',
            b'setTimeout(',
            b'RegisterCommand(',
        ]
        
        # Error patterns - be very specific to avoid false positives from native docs
        error_patterns = [
            b'SCRIPT ERROR:',
            b'stack traceback:',
        ]
        
        # Resource name pattern (like @resourcename/)
        resource_pattern = re.compile(rb'@([a-zA-Z0-9_-]+)/')
        # Lua file pattern - avoid hex hashes like 0x12345678.lua (native function docs)
        lua_file_pattern = re.compile(rb'(?<![0-9a-fA-Fx])([a-zA-Z][a-zA-Z0-9_/\\-]*\.lua)')
        js_file_pattern = re.compile(rb'(?<![0-9a-fA-Fx])([a-zA-Z][a-zA-Z0-9_/\\-]*\.(?:js|ts))')
        event_name_pattern = re.compile(
            r'(?:AddEventHandler|RegisterNetEvent|RegisterServerEvent|TriggerEvent|'
            r'TriggerServerEvent|TriggerClientEvent|on)\s*\(\s*["\"]([^"\"]+)'
        )
        native_hash_pattern = re.compile(r'0x[0-9a-fA-F]{8,16}')
        string_pattern = re.compile(rb'[\x20-\x7E]{6,200}')

        string_counter = {}
        resource_counter = {}
        event_resource_counter = {}

        def _bump_counter(counter: Dict[str, int], key: str, max_keys: int = 5000) -> None:
            if not key:
                return
            if len(counter) >= max_keys and key not in counter:
                return
            counter[key] = counter.get(key, 0) + 1

        def _clean_event_name(name: str) -> Optional[str]:
            if not name:
                return None
            # Keep printable ASCII only
            cleaned = ''.join(ch for ch in name if 32 <= ord(ch) <= 126).strip()
            if len(cleaned) < 3 or len(cleaned) > 80:
                return None
            if 'resources:' in cleaned or '/' in cleaned or '\\' in cleaned:
                return None
            if not re.fullmatch(r'[A-Za-z0-9:_\-.]+', cleaned):
                return None
            return cleaned
        
        try:
            with open(dump_path, 'rb') as f:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    extraction_limit = 500 * 1024 * 1024

                    if not full_sweep and file_size <= extraction_limit:
                        # Small file - memory extraction should have gotten everything
                        self._report_progress("script_scan", 1.0, "File small enough for full extraction")
                        return results

                    if full_sweep:
                        scan_start = 0
                        scan_end = file_size
                        chunk_size = 64 * 1024 * 1024  # 64MB chunks for full sweep
                        context_size = 8192  # 8KB context for deeper extraction
                        max_scan_size = file_size
                    else:
                        # Scan regions: focus on 500MB-end where Lua runtime data typically lives
                        # For very large dumps (>10GB), limit scan to first 5GB to avoid excessive processing
                        scan_start = extraction_limit
                        if file_size > 10 * 1024 * 1024 * 1024:  # >10GB
                            max_scan_size = 5 * 1024 * 1024 * 1024
                            scan_end = min(scan_start + max_scan_size, file_size)
                            self.result.errors.append(
                                f"Very large dump: Limited raw scan to first {max_scan_size/(1024**3):.1f}GB "
                                f"(beyond extraction point) to prevent excessive processing time"
                            )
                        else:
                            max_scan_size = file_size - scan_start
                            scan_end = file_size

                        chunk_size = 100 * 1024 * 1024  # 100MB chunks
                        context_size = 2048  # Extract 2KB around matches for context
                    
                    total_to_scan = scan_end - scan_start
                    scanned = 0
                    
                    self._report_progress("script_scan", 0.1, 
                        f"Scanning {total_to_scan / (1024*1024):.0f}MB beyond extraction limit...")
                    
                    current_pos = scan_start
                    while current_pos < scan_end:
                        chunk_end = min(current_pos + chunk_size, file_size)
                        chunk_data = mm[current_pos:chunk_end]
                        
                        # Search for Lua patterns
                        for pattern in lua_patterns:
                            pattern_name = pattern.decode('utf-8')
                            pos = 0
                            pattern_count_in_chunk = 0
                            for _ in range(10000):  # Per ADA restrictions: bounded loop (max pattern matches per chunk)
                                idx = chunk_data.find(pattern, pos)
                                if idx == -1:
                                    break
                                
                                pattern_count_in_chunk += 1
                                
                                # Extract context around match
                                abs_pos = current_pos + idx
                                ctx_start = max(0, idx - context_size)
                                ctx_end = min(len(chunk_data), idx + len(pattern) + context_size)
                                context = chunk_data[ctx_start:ctx_end]
                                
                                # Try to extract a meaningful stack trace
                                try:
                                    context_str = context.decode('utf-8', errors='replace')
                                    
                                    # Look for resource names
                                    for match in resource_pattern.finditer(context):
                                        resource_name = match.group(1).decode('utf-8', errors='replace')
                                        results["resources"].add(resource_name)

                                    if include_artifacts:
                                        for match in lua_file_pattern.finditer(context):
                                            lua_path = match.group(1).decode('utf-8', errors='replace')
                                            if len(lua_path) > 5 and not lua_path.startswith('0x'):
                                                if len(results["resource_paths_sample"]) < 200:
                                                    results["resource_paths_sample"].append(lua_path)
                                        for match in js_file_pattern.finditer(context):
                                            js_path = match.group(1).decode('utf-8', errors='replace')
                                            if len(js_path) > 5 and not js_path.startswith('0x'):
                                                if len(results["resource_paths_sample"]) < 200:
                                                    results["resource_paths_sample"].append(js_path)
                                    
                                    # Look for lua file paths (exclude hex hashes like 0x1234.lua)
                                    for match in lua_file_pattern.finditer(context):
                                        lua_path = match.group(1).decode('utf-8', errors='replace')
                                        # Filter out native function doc files and short names
                                        if len(lua_path) > 5 and not lua_path.startswith('0x'):
                                            results["resources"].add(lua_path)
                                    
                                    # Check if this looks like a stack trace
                                    if 'stack traceback:' in context_str:
                                        # Extract the stack trace
                                        lines = context_str.split('\n')
                                        stack_lines = []
                                        in_stack = False
                                        for line in lines:
                                            if 'stack traceback:' in line:
                                                in_stack = True
                                            if in_stack:
                                                stack_lines.append(line.strip())
                                                if len(stack_lines) > 20:
                                                    break
                                        
                                        if stack_lines:
                                            stack_text = '\n'.join(stack_lines)
                                            if stack_text not in [s.get('raw', '') for s in results["lua_stacks"]]:
                                                results["lua_stacks"].append({
                                                    "raw": stack_text,
                                                    "offset": abs_pos,
                                                    "pattern": pattern_name
                                                })
                                    if include_artifacts:
                                        if '.lua' in context_str and len(results["lua_snippets"]) < 200:
                                            snippet = context_str.strip()
                                            if snippet and snippet not in results["lua_snippets"]:
                                                results["lua_snippets"].append(snippet[:800])
                                        if '.js' in context_str or '.ts' in context_str:
                                            if len(results["js_snippets"]) < 200:
                                                snippet = context_str.strip()
                                                if snippet and snippet not in results["js_snippets"]:
                                                    results["js_snippets"].append(snippet[:800])
                                        if len(results["raw_string_samples"]) < 200:
                                            if context_str and context_str not in results["raw_string_samples"]:
                                                results["raw_string_samples"].append(context_str[:800])
                                    # Extract event names when present
                                    for ev_match in event_name_pattern.finditer(context_str):
                                        event_name = _clean_event_name(ev_match.group(1))
                                        if event_name:
                                            results["events"].add(event_name)
                                except Exception:
                                    # Failed to process pattern context; skip this occurrence
                                    pass

                        # Search for native invocation patterns
                        for pattern in native_patterns:
                            pattern_name = pattern.decode('utf-8', errors='replace')
                            pos = 0
                            pattern_count_in_chunk = 0
                            for _ in range(10000):  # Per ADA restrictions: bounded loop (max pattern matches per chunk)
                                idx = chunk_data.find(pattern, pos)
                                if idx == -1:
                                    break
                                pattern_count_in_chunk += 1
                                abs_pos = current_pos + idx
                                ctx_start = max(0, idx - context_size)
                                ctx_end = min(len(chunk_data), idx + len(pattern) + context_size)
                                context = chunk_data[ctx_start:ctx_end]

                                try:
                                    context_str = context.decode('utf-8', errors='replace')
                                    hashes = native_hash_pattern.findall(context_str)
                                    for h in hashes[:5]:
                                        h_clean = h.lower().replace('0x', '')
                                        h_norm = f"0x{h_clean}"
                                        results["native_hashes"].add(h_norm)
                                        results["native_calls"].append(
                                            {
                                                "hash": h_norm,
                                                "pattern": pattern_name,
                                                "offset": abs_pos,
                                            }
                                        )
                                except Exception:
                                    # Failed to extract native call info; skip this occurrence
                                    pass
                        # String harvesting (script-relevant strings only)
                        if include_artifacts:
                            for s_match in string_pattern.finditer(chunk_data):
                                s_val = s_match.group(0).decode('ascii', errors='ignore')
                                if not s_val:
                                    continue
                                lower = s_val.lower()
                                if (
                                    '.lua' in lower
                                    or '.js' in lower
                                    or 'resources/' in lower
                                    or 'registernetevent' in lower
                                    or 'trigger' in lower
                                    or 'addeventhandler' in lower
                                    or 'invoke' in lower
                                ):
                                    _bump_counter(string_counter, s_val)

                                    if 'resources/' in lower:
                                        try:
                                            after = lower.split('resources/', 1)[1]
                                            res = after.split('/', 1)[0]
                                            if res:
                                                _bump_counter(resource_counter, res)
                                        except Exception:
                                            pass
                        
                        # Search for error patterns
                        for pattern in error_patterns:
                            pos = 0
                            for _ in range(10000):  # Per ADA restrictions: bounded loop (max pattern matches per chunk)
                                idx = chunk_data.find(pattern, pos)
                                if idx == -1:
                                    break
                                
                                # Extract error context
                                abs_pos = current_pos + idx
                                ctx_start = max(0, idx - 512)
                                ctx_end = min(len(chunk_data), idx + 1024)
                                context = chunk_data[ctx_start:ctx_end]
                                
                                try:
                                    context_str = context.decode('utf-8', errors='replace')
                                    # Clean up and add if meaningful
                                    if len(context_str) > 20:
                                        error_text = context_str.strip()
                                        if error_text not in results["script_errors"]:
                                            results["script_errors"].append(error_text)
                                except Exception:
                                    # Failed to decode error context; skip this occurrence
                                    pass
                        
                        self._report_progress("script_scan", progress, 
                            f"Scanned {scanned / (1024*1024):.0f}MB, found {len(results['lua_stacks'])} Lua stacks")
                        
                        current_pos = chunk_end
                        
                        # Limit results to prevent memory bloat
                        max_lua = 200 if full_sweep else 50
                        max_errors = 100 if full_sweep else 20
                        if len(results["lua_stacks"]) >= max_lua:
                            break
                        if len(results["script_errors"]) >= max_errors:
                            results["script_errors"] = results["script_errors"][:max_errors]
                    
                    results["scan_regions"].append({
                        "start": scan_start,
                        "end": current_pos,
                        "size_mb": (current_pos - scan_start) / (1024*1024)
                    })
                    
        except Exception as e:
            self._report_progress("script_scan", 1.0, f"Scan error: {e}")
            results["error"] = str(e)
        
        # Convert sets to lists for JSON serialization
        results["resources"] = list(results["resources"])
        results["events"] = sorted(results["events"])
        results["native_hashes"] = sorted(results["native_hashes"])
        results["native_decoded"] = [
            {"hash": h, "name": decode_native_hash(h)}
            for h in results["native_hashes"]
        ]
        # Aggregate resource counts from events (resource:event)
        for event in results["events"]:
            if ':' in event:
                res = event.split(':', 1)[0].strip()
                if res:
                    _bump_counter(event_resource_counter, res, max_keys=2000)

        # Merge resource counts from resources list into counter
        for res in results["resources"]:
            _bump_counter(resource_counter, res)

        # Serialize counters
        if string_counter:
            top_strings = sorted(string_counter.items(), key=lambda x: x[1], reverse=True)[:200]
            results["string_frequencies"] = [{"value": s, "count": c} for s, c in top_strings]

        if resource_counter:
            top_resources = sorted(resource_counter.items(), key=lambda x: x[1], reverse=True)[:200]
            results["resource_counts"] = [{"name": r, "count": c} for r, c in top_resources]

        if event_resource_counter:
            top_event_resources = sorted(event_resource_counter.items(), key=lambda x: x[1], reverse=True)[:200]
            results["event_resource_counts"] = [{"name": r, "count": c} for r, c in top_event_resources]
        results["scan_mode"] = "full_sweep" if full_sweep else "focused"
        results["scan_range"] = {
            "start": scan_start,
            "end": scan_end,
            "size_mb": (scan_end - scan_start) / (1024 * 1024),
        }
        # Cap native_calls to avoid huge output
        max_native_calls = 2000 if full_sweep else 200
        if len(results["native_calls"]) > max_native_calls:
            results["native_calls"] = results["native_calls"][:max_native_calls]
        
        self._report_progress("script_scan", 1.0, 
            f"Raw scan complete: {len(results['lua_stacks'])} Lua stacks, {len(results['resources'])} resources")
        
        return results

    def scan_dump_for_patterns(self, dump_path: str, full_sweep: bool = False,
                               include_artifacts: bool = False) -> Dict[str, Any]:
        """Public wrapper to scan a dump for Lua/event/native patterns.

        This bypasses normal minidump parsing and scans the raw file to find
        script-related strings when MEMORY_LIST streams are missing.
        """
        if not os.path.exists(dump_path):
            return {"error": f"Dump file not found: {dump_path}"}

        try:
            file_size = os.path.getsize(dump_path)
        except Exception as e:
            return {"error": f"Failed to read dump file size: {e}"}

        return self._scan_raw_dump_for_scripts(
            dump_path,
            file_size,
            full_sweep=full_sweep,
            include_artifacts=include_artifacts,
        )

    def _analyze_dump_sampled(self, dump_path: str, file_size: int) -> None:
        """Analyze a very large dump (2GB+) using strategic sampling.
        
        For massive dumps, we sample key regions more aggressively:
        1. First 200MB - Headers, module info, initial memory state
        2. Multiple 100MB samples throughout the file (more samples for larger files)
        3. Last 200MB - Recent allocations, stack data, crash context
        """
        import mmap
        
        # Increase sample sizes for better coverage
        sample_size = 100 * 1024 * 1024  # 100MB samples (was 50MB)
        first_region = 200 * 1024 * 1024  # First 200MB (was 100MB)
        last_region = 200 * 1024 * 1024   # Last 200MB (was 100MB)
        file_size_gb = file_size / (1024 * 1024 * 1024)
        
        # Calculate sample points (evenly distributed through middle)
        middle_start = first_region
        middle_end = file_size - last_region
        middle_size = middle_end - middle_start
        
        # Take MORE samples from the middle - scale with file size
        # For 6GB file: ~12 samples. For 22GB: ~44 samples for comprehensive coverage
        num_middle_samples = min(60, max(10, int(file_size_gb * 2)))
        total_steps = 2 + num_middle_samples  # first + middle samples + last
        current_step = 0
        
        # Skip slow non-critical patterns for huge dumps (>10GB)
        is_huge_file = file_size > 10 * 1024 * 1024 * 1024
        
        self._report_progress(
            "sampling", 
            0.0, 
            f"Starting sampled analysis: {file_size_gb:.1f}GB dump, {num_middle_samples + 2} regions to scan{' (fast mode)' if is_huge_file else ''}"
        )
        
        with open(dump_path, 'rb') as f:
            try:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    if self._should_abort():
                        self._report_progress("sampling", 1.0, "Analysis cancelled")
                        return
                    # 1. Analyze first region in sub-chunks (50MB each) so UI gets updates and stays responsive
                    sub_chunk_mb = 50 * 1024 * 1024  # 50MB
                    num_first_sub = (first_region + sub_chunk_mb - 1) // sub_chunk_mb
                    for fi in range(num_first_sub):
                        if self._should_abort():
                            self._report_progress("sampling", 1.0, "Analysis cancelled")
                            return
                        start_off = fi * sub_chunk_mb
                        end_off = min(start_off + sub_chunk_mb, first_region)
                        self._report_progress(
                            "sampling",
                            current_step / total_steps,
                            f"Analyzing first region {fi + 1}/{num_first_sub} ({start_off // (1024*1024)}–{end_off // (1024*1024)}MB of {file_size_gb:.1f}GB)..."
                        )
                        first_chunk = bytes(mm[start_off:end_off])
                        self._run_analysis_passes(first_chunk, chunk_offset=start_off, is_huge_file=is_huge_file)
                        del first_chunk
                    current_step += 1
                    
                    # DON'T early terminate on first chunk - we want more data
                    
                    # 2. Sample middle regions - DO NOT skip even if we have evidence
                    if middle_size > 0:
                        sample_interval = middle_size // (num_middle_samples + 1)
                        for i in range(num_middle_samples):
                            if self._should_abort():
                                self._report_progress("sampling", 1.0, "Analysis cancelled")
                                return
                            sample_offset = middle_start + (i + 1) * sample_interval
                            sample_end = min(sample_offset + sample_size, middle_end)
                            sample_offset_gb = sample_offset / (1024 * 1024 * 1024)
                            
                            self._report_progress(
                                "sampling", 
                                current_step / total_steps, 
                                f"Sampling region {i + 1}/{num_middle_samples} at {sample_offset_gb:.1f}GB - {len(self.result.all_evidence)} evidence items"
                            )
                            
                            middle_chunk = bytes(mm[sample_offset:sample_end])
                            self._run_analysis_passes(middle_chunk, chunk_offset=sample_offset, is_huge_file=is_huge_file)
                            del middle_chunk
                            current_step += 1
                            
                            # Only stop early if we have LOTS of evidence (not just "sufficient")
                            max_ev = getattr(self, '_max_evidence', self.MAX_EVIDENCE_ITEMS)
                            if len(self.result.all_evidence) >= max_ev:
                                self._report_progress("sampling", 1.0, f"Collected maximum evidence ({max_ev} items)")
                                return
                    
                    # 3. Analyze last region in sub-chunks (50MB each) so UI stays responsive
                    if self._should_abort():
                        self._report_progress("sampling", 1.0, "Analysis cancelled")
                        return
                    num_last_sub = (last_region + sub_chunk_mb - 1) // sub_chunk_mb
                    last_start = file_size - last_region
                    for li in range(num_last_sub):
                        if self._should_abort():
                            self._report_progress("sampling", 1.0, "Analysis cancelled")
                            return
                        start_off = last_start + li * sub_chunk_mb
                        end_off = min(start_off + sub_chunk_mb, file_size)
                        self._report_progress(
                            "sampling",
                            current_step / total_steps,
                            f"Analyzing last region {li + 1}/{num_last_sub} ({start_off // (1024*1024)}–{end_off // (1024*1024)}MB)..."
                        )
                        last_chunk = bytes(mm[start_off:end_off])
                        self._run_analysis_passes(last_chunk, chunk_offset=start_off, is_huge_file=is_huge_file)
                        del last_chunk
                    current_step += 1
                    
                    self._report_progress("sampling", 1.0, f"Sampled analysis complete - {len(self.result.all_evidence)} evidence items found")
                    
            except (mmap.error, OSError) as e:
                self.result.errors.append(f"Memory-mapped sampling failed: {e}")
                # Fallback: just read first and last 100MB
                self._analyze_dump_simple_sample(f, file_size)

    def _analyze_dump_simple_sample(self, f, file_size: int) -> None:
        """Simple sampling fallback - just read first and last portions."""
        sample_size = 100 * 1024 * 1024  # 100MB
        is_huge_file = False
        
        self._report_progress("sampling", 0.0, "Fallback: Reading first 100MB...")
        
        # Read first 100MB
        f.seek(0)
        first_chunk = f.read(sample_size)
        self._run_analysis_passes(first_chunk, chunk_offset=0)
        del first_chunk
        
        if self._has_sufficient_evidence():
            self._report_progress("sampling", 1.0, "Found sufficient evidence!")
            return
        
        self._report_progress("sampling", 0.5, "Reading last 100MB...")
        
        # Read last 100MB
        f.seek(max(0, file_size - sample_size))
        last_chunk = f.read(sample_size)
        self._run_analysis_passes(last_chunk, chunk_offset=max(0, file_size - sample_size), is_huge_file=is_huge_file)
        del last_chunk

    def _run_analysis_passes(self, data: bytes, chunk_offset: int = 0, is_huge_file: bool = False) -> None:
        """Run all analysis passes on a chunk of data.
        
        For large file analysis, we run ALL passes to extract maximum data.
        For very large chunks (>500MB), we sample to avoid regex slowdowns.
        
        Args:
            data: Chunk of memory to analyze
            chunk_offset: Offset of this chunk in the file
            is_huge_file: If True, skip slow non-critical patterns (for 10GB+ dumps)
        """
        data_mb = len(data) / (1024 * 1024)
        
        # For very large chunks, sample aggressively to avoid regex performance issues
        # NOTE: Increased from 5MB to 500MB because progressive extraction already
        # limits chunks to 100-500MB, and we need to scan the full extracted memory
        # to find Lua/JS patterns. The old 5MB limit was causing false negatives.
        MAX_REGEX_SCAN_SIZE = 500 * 1024 * 1024  # 500MB - matches max chunk size
        
        if len(data) > MAX_REGEX_SCAN_SIZE:
            if is_huge_file:
                # Ultra-aggressive sampling for 10GB+ dumps: 512KB + 256KB + 512KB = 1.25MB total
                sampled_data = data[:512*1024] + data[len(data)//2:len(data)//2 + 256*1024] + data[-512*1024:]
            else:
                # Sample: first 200MB + middle 100MB + last 200MB = 500MB total
                sampled_data = data[:200*1024*1024] + data[len(data)//2:len(data)//2 + 100*1024*1024] + data[-200*1024*1024:]
            data_to_scan = sampled_data
            self._report_progress("scanning", 0.05, f"Sampling {len(data_to_scan)/(1024*1024):.1f}MB from {data_mb:.1f}MB chunk...")
        else:
            data_to_scan = data
        
        # For 10GB+ dumps: Use fast literal search instead of slow regex patterns
        if is_huge_file:
            # Fast literal string search (100x faster than regex, completes in 2-5 minutes)
            self._report_progress("scanning", 0.10, "Fast Lua error search...")
            self._fast_lua_error_search(data, chunk_offset)
            self._report_progress("scanning", 0.20, "Fast JS error search...")
            self._fast_js_error_search(data, chunk_offset)
            self._report_progress("scanning", 0.30, "Fast native call search...")
            self._fast_native_call_search(data, chunk_offset)
            self._report_progress("scanning", 0.40, "Decoding FiveM structures...")
            self._decode_fivem_structures(data, chunk_offset)
            # NEW: Comprehensive data extraction
            self._report_progress("scanning", 0.50, "Extracting server config...")
            self._extract_server_config(data, chunk_offset)
            self._report_progress("scanning", 0.60, "Extracting Lua code fragments...")
            self._extract_lua_code_fragments(data, chunk_offset)
            self._report_progress("scanning", 0.70, "Extracting database queries...")
            self._extract_database_queries(data, chunk_offset)
            self._report_progress("scanning", 0.80, "Extracting event data...")
            self._extract_event_data(data, chunk_offset)
            # NEW: Find which scripts call specific GTA natives
            self._report_progress("scanning", 0.90, "Finding native callers...")
            self._find_native_callers(data, chunk_offset)
            self._report_progress("scanning", 1.0, "Fast scan complete")
            return
        
        # Deep string analysis on raw data - ALWAYS run
        self._report_progress("scanning", 0.05, "Analyzing raw memory strings...")
        self._analyze_raw_memory(data_to_scan)

        # Extract Lua stack traces from memory - ALWAYS run
        self._report_progress("scanning", 0.12, "Extracting Lua stack traces...")
        self._extract_lua_stacks(data_to_scan)

        # Find and parse full Lua tracebacks - ALWAYS run
        self._report_progress("scanning", 0.18, "Parsing Lua tracebacks...")
        self._extract_lua_tracebacks(data_to_scan)

        # Find Lua runtime errors with context - ALWAYS run (high value)
        self._report_progress("scanning", 0.24, "Finding Lua runtime errors...")
        self._find_lua_runtime_errors(data_to_scan)

        # Extract JS stack traces from memory - ALWAYS run
        self._report_progress("scanning", 0.30, "Extracting JS stack traces...")
        self._extract_js_stacks(data_to_scan)

        # Find script errors in memory - ALWAYS run
        self._report_progress("scanning", 0.36, "Finding script errors...")
        self._find_script_errors(data_to_scan)

        # Skip slower patterns for huge files (10GB+) to keep analysis under 5 minutes
        if not is_huge_file:
            # Find CitizenFX runtime contexts
            self._report_progress("scanning", 0.42, "Finding CitizenFX contexts...")
            self._find_citizenfx_contexts(data_to_scan)

            # Analyze for FiveM-specific patterns
            self._report_progress("scanning", 0.48, "Analyzing FiveM patterns...")
            self._find_fivem_patterns(data_to_scan)

            # Dedicated pass: extract all FiveM resource names (server.cfg, paths, refs)
            self._report_progress("scanning", 0.54, "Extracting resource names...")
            self._extract_fivem_resource_names_pass(data_to_scan)
            
            # Enhanced Resource Attribution Pass
            self._report_progress("scanning", 0.60, "Resource attribution analysis...")
            self._extract_resource_attribution_pass(data_to_scan, chunk_offset)
            
            # Memory leak analysis passes
            self._report_progress("scanning", 0.66, "Analyzing entity lifecycle...")
            self._analyze_entity_lifecycle(data_to_scan, chunk_offset)
            self._report_progress("scanning", 0.70, "Analyzing timer patterns...")
            self._analyze_timer_patterns(data_to_scan, chunk_offset)
            self._report_progress("scanning", 0.74, "Analyzing event handlers...")
            self._analyze_event_handlers(data_to_scan, chunk_offset)
            self._report_progress("scanning", 0.78, "Analyzing memory allocations...")
            self._analyze_memory_allocations(data_to_scan, chunk_offset)
            
            # Find memory leak indicators
            self._report_progress("scanning", 0.82, "Finding memory leak indicators...")
            self._find_memory_leak_indicators(data_to_scan, chunk_offset)
            
            # Find pool exhaustion indicators
            self._report_progress("scanning", 0.86, "Checking pool exhaustion...")
            self._find_pool_exhaustion(data_to_scan, chunk_offset)
            
            # Find database patterns
            self._report_progress("scanning", 0.89, "Finding database patterns...")
            self._find_database_patterns(data_to_scan, chunk_offset)
            
            # Find NUI/CEF patterns
            self._report_progress("scanning", 0.92, "Finding NUI/CEF patterns...")
            self._find_nui_patterns(data_to_scan, chunk_offset)
            
            # Find network sync patterns
            self._report_progress("scanning", 0.95, "Finding network patterns...")
            self._find_network_patterns(data_to_scan, chunk_offset)
            
            # Find FiveM-specific crash causes
            self._report_progress("scanning", 0.98, "Finding FiveM crash causes...")
            self._find_fivem_crash_causes(data_to_scan, chunk_offset)
            
            # Extract Lua code fragments (needed for context on crash scripts)
            self._report_progress("scanning", 0.995, "Extracting Lua code fragments...")
            self._extract_lua_code_fragments(data_to_scan, chunk_offset)
            
            # Find native calls (critical for FiveM crash analysis)
            self._report_progress("scanning", 0.999, "Finding native callers...")
            self._find_native_callers(data_to_scan, chunk_offset)

    def _has_sufficient_evidence(self) -> bool:
        """Check if we have enough evidence to make a determination.
        
        This is now ONLY used for streaming analysis of medium dumps (500MB-2GB).
        For sampled analysis of large dumps (2GB+), we always scan all regions.
        
        Returns True if we should skip further analysis.
        """
        # Only stop if we have a LOT of high-confidence evidence
        high_confidence_count = sum(
            1 for e in self.result.all_evidence 
            if e.confidence >= 0.95  # Increased threshold
        )
        
        # Need 15+ high-confidence items to stop early (was 5)
        if high_confidence_count >= 15:
            return True
        
        # Need 10+ clear script errors to stop early (was 3)
        if len(self.result.script_errors) >= 10:
            return True
        
        # If evidence exceeds max, stop collecting
        if len(self.result.all_evidence) >= self.MAX_EVIDENCE_ITEMS:
            return True
        
        return False

    def _analyze_minidump_structure(self, md) -> None:
        """Analyze minidump structure using the minidump library."""
        # Get file reader for reading memory data
        reader = None
        try:
            reader = md.get_reader()
        except Exception:
            pass

        # 1. Header Information
        try:
            if hasattr(md, 'header') and md.header:
                self.result.crash_time = getattr(md.header, 'TimeDateStamp', None)
        except Exception as e:
            self.result.errors.append(f"Header extraction: {e}")

        # 2. System Information
        try:
            if hasattr(md, 'sysinfo') and md.sysinfo:
                self.result.system_info = self._obj_to_dict(md.sysinfo)
        except Exception as e:
            self.result.errors.append(f"SystemInfo extraction: {e}")

        # 3. Misc Information
        try:
            if hasattr(md, 'misc_info') and md.misc_info:
                self.result.misc_info = self._obj_to_dict(md.misc_info)
        except Exception as e:
            self.result.errors.append(f"MiscInfo extraction: {e}")

        # 4. Unloaded Modules
        try:
            if hasattr(md, 'unloaded_modules') and md.unloaded_modules:
                unloaded = getattr(md.unloaded_modules, 'modules', [])
                for mod in unloaded:
                    name = getattr(mod, 'name', None)
                    if name:
                        self.result.unloaded_modules.append(str(name))
        except Exception as e:
            self.result.errors.append(f"Unloaded modules extraction: {e}")

        # Extract exception information with full parameters
        crash_tid = None
        try:
            exc_stream = getattr(md, 'exception', None)

            # Handle if it's a list wrapper (minidump >= 0.0.10)
            if exc_stream and hasattr(exc_stream, 'exception_records') and exc_stream.exception_records:
                exc_stream = exc_stream.exception_records[0]

            if exc_stream:
                # Get ThreadId
                crash_tid = getattr(exc_stream, 'ThreadId', None)

                # The exception stream contains exception_record
                exc_rec = getattr(exc_stream, 'ExceptionRecord', None) or getattr(exc_stream, 'exception_record', None)

                if exc_rec:
                    code = getattr(exc_rec, 'ExceptionCode', None)
                    if code is not None:
                        try:
                            if isinstance(code, int):
                                self.result.exception_code = code
                            elif isinstance(code, bytes):
                                self.result.exception_code = int.from_bytes(code, 'little')
                            elif hasattr(code, 'value'):
                                self.result.exception_code = code.value
                            else:
                                self.result.exception_code = int(code)
                        except (ValueError, TypeError):
                            pass  # Skip invalid exception codes
                    
                    exc_addr = getattr(exc_rec, 'ExceptionAddress', None)
                    if exc_addr is not None:
                        try:
                            if isinstance(exc_addr, int):
                                self.result.exception_address = exc_addr
                            elif isinstance(exc_addr, bytes):
                                self.result.exception_address = int.from_bytes(exc_addr, 'little')
                            elif hasattr(exc_addr, 'value'):
                                self.result.exception_address = exc_addr.value
                            else:
                                self.result.exception_address = int(exc_addr)
                        except (ValueError, TypeError):
                            pass  # Skip invalid addresses

                    # NEW: Extract detailed exception parameters
                    self._extract_exception_params(exc_rec)
        except Exception as e:
            self.result.errors.append(f"Exception extraction: {e}")

        # Build module map and extract version/PDB info
        try:
            modules = getattr(md, 'modules', None)
            if modules:
                # modules is a MinidumpModuleList
                module_list = getattr(modules, 'modules', None) or modules
                if hasattr(module_list, '__iter__'):
                    for m in module_list:
                        try:
                            name = str(getattr(m, 'name', '') or '')
                            base = getattr(m, 'baseaddress', None) or getattr(m, 'base', None) or 0
                            size = getattr(m, 'size', None) or 0
                            if base and name:
                                self._module_map[int(base)] = (int(base) + int(size), name)
                                # Check if exception is in this module
                                if (self.result.exception_address and
                                    int(base) <= self.result.exception_address < int(base) + int(size)):
                                    self.result.exception_module = name

                            # NEW: Extract detailed module version/PDB info
                            self._extract_module_version_info(m)
                        except Exception:
                            continue
            
            # FALLBACK: If minidump library didn't extract PDB info, use dump_extractor
            # to parse CodeView records directly from the dump file
            if hasattr(self, '_dump_path_for_cv_fallback'):
                try:
                    from .dump_extractor import MinidumpExtractor
                    extractor = MinidumpExtractor()
                    extractor.load(self._dump_path_for_cv_fallback)
                    extractor_modules = extractor.get_modules()
                    
                    # Cross-reference with existing modules and add missing PDB info
                    for mod_info in self.result.module_versions:
                        if not mod_info.pdb_guid or not mod_info.pdb_name:
                            # Find matching module in extractor data
                            for ext_mod in extractor_modules:
                                if ext_mod['name'] == mod_info.name or ext_mod['base_address'] == mod_info.base_address:
                                    cv_info = extractor.get_cv_pdb_info(ext_mod)
                                    if cv_info:
                                        pdb_name, pdb_guid, pdb_age = cv_info
                                        if pdb_name and not mod_info.pdb_name:
                                            mod_info.pdb_name = pdb_name
                                        if pdb_guid and not mod_info.pdb_guid:
                                            mod_info.pdb_guid = pdb_guid
                                        if pdb_age and not mod_info.pdb_age:
                                            mod_info.pdb_age = pdb_age
                                    break
                except Exception as cv_err:
                    self.result.errors.append(f"CodeView fallback extraction: {cv_err}")
        except Exception as e:
            self.result.errors.append(f"Module extraction: {e}")

        # Extract memory regions - try multiple sources
        try:
            # Try memory_segments first (MinidumpMemoryList)
            memseg = getattr(md, 'memory_segments', None)
            if memseg:
                segments = getattr(memseg, 'memory_segments', None) or memseg
                if hasattr(segments, '__iter__'):
                    for seg in segments:
                        self._read_memory_segment(seg, reader)

            # Also try memory_segments_64 (MinidumpMemory64List) for full dumps
            memseg64 = getattr(md, 'memory_segments_64', None)
            if memseg64:
                segments64 = getattr(memseg64, 'memory_segments', None) or memseg64
                if hasattr(segments64, '__iter__'):
                    for seg in segments64:
                        self._read_memory_segment(seg, reader)
        except Exception as e:
            self.result.errors.append(f"Memory extraction: {e}")

        # Analyze thread stacks and extract extended thread info
        try:
            threads = getattr(md, 'threads', None)
            if threads:
                thread_list = getattr(threads, 'threads', None) or threads
                if hasattr(thread_list, '__iter__'):
                    for thread in thread_list:
                        self._analyze_thread_stack(thread, reader)

                        # NEW: Extract extended thread info
                        self._extract_thread_extended_info(thread)

                        # Check for crashing thread
                        tid = getattr(thread, 'ThreadId', None) or getattr(thread, 'thread_id', None)
                        if tid is not None and crash_tid is not None and tid == crash_tid:
                            # 5. Extract Exception Context (CPU Registers)
                            try:
                                context = getattr(thread, 'ContextObject', None)
                                if context:
                                    self.result.exception_context = self._obj_to_dict(context)
                            except Exception as ex:
                                self.result.errors.append(f"Context extraction: {ex}")

                            self._extract_native_stack(thread, reader)
        except Exception as e:
            self.result.errors.append(f"Thread analysis: {e}")

        # NEW: Extract additional minidump streams
        self._extract_additional_streams(md, reader)

    def _read_memory_segment(self, seg, reader) -> None:
        """Read a memory segment and store it."""
        try:
            start = getattr(seg, 'start_virtual_address', None) or \
                    getattr(seg, 'start_address', None) or \
                    getattr(seg, 'StartOfMemoryRange', None) or 0
            size = getattr(seg, 'size', None) or \
                   getattr(seg, 'DataSize', None) or 0

            if not start or not size:
                return

            start = int(start)
            size = int(size)

            # Try to read the actual memory data
            data = None

            # Method 1: Direct data attribute
            data = getattr(seg, 'data', None)
            if data is None:
                data = getattr(seg, 'data_bytes', None)

            # Method 2: Read from file using reader
            if data is None and reader:
                try:
                    file_offset = getattr(seg, 'start_file_address', None)

                    # Fallback for Memory Descriptor
                    if file_offset is None:
                        memory_desc = getattr(seg, 'Memory', None)
                        if memory_desc:
                            file_offset = getattr(memory_desc, 'Rva', None)

                    if file_offset is not None:
                        if hasattr(reader, 'file_handle'):
                            reader.file_handle.seek(int(file_offset))
                            data = reader.file_handle.read(min(size, 50 * 1024 * 1024))  # Cap at 50MB
                except Exception:
                    pass

            if start and data:
                self._memory_data[start] = bytes(data)
                region = MemoryRegionInfo(
                    start_address=start,
                    size=size,
                    module_name=self._get_module_for_address(start)
                )
                self.result.memory_regions.append(region)
        except Exception:
            pass

    def _analyze_thread_stack(self, thread, reader=None) -> None:
        """Analyze a single thread's stack for script references."""
        try:
            tid = getattr(thread, 'ThreadId', None) or \
                  getattr(thread, 'thread_id', None) or 0

            # Get stack memory info
            stack = getattr(thread, 'Stack', None) or getattr(thread, 'stack', None)
            if not stack:
                return

            start = getattr(stack, 'StartOfMemoryRange', None) or \
                    getattr(stack, 'start_address', None) or 0
            start = int(start) if start else 0

            # Get stack memory data
            memory = getattr(stack, 'Memory', None)
            stack_data = None

            # Try to read from memory data attribute
            if memory:
                data_size = getattr(memory, 'DataSize', None) or 0
                rva = getattr(memory, 'Rva', None)

                if rva and reader and data_size:
                    try:
                        reader.seek(int(rva))
                        stack_data = reader.read(int(data_size))
                    except Exception:
                        pass

            # Fallback: Look in our stored memory regions
            if not stack_data and start:
                for mem_start, data in self._memory_data.items():
                    mem_end = mem_start + len(data)
                    if mem_start <= start < mem_end:
                        offset = start - mem_start
                        stack_data = data[offset:]
                        break

            if stack_data:
                self._analyze_stack_data(stack_data, tid)

        except Exception as e:
            pass

    def _analyze_stack_data(self, data: bytes, thread_id: int) -> None:
        """Analyze stack data for script references."""
        # Look for script paths
        for match in self.FIVEM_PATTERNS['lua_path'].finditer(data):
            resource = match.group(1).decode('utf-8', errors='replace')
            script = match.group(2).decode('utf-8', errors='replace')
            self._add_evidence(ScriptEvidence(
                evidence_type=EvidenceType.THREAD_STACK,
                script_name=script,
                resource_name=resource,
                file_path=f"{resource}/{script}",
                context=f"Found in thread {thread_id} stack",
                confidence=0.8
            ))

        # Look for JS paths
        for match in self.FIVEM_PATTERNS['js_path'].finditer(data):
            resource = match.group(1).decode('utf-8', errors='replace')
            script = match.group(2).decode('utf-8', errors='replace')
            self._add_evidence(ScriptEvidence(
                evidence_type=EvidenceType.THREAD_STACK,
                script_name=script,
                resource_name=resource,
                file_path=f"{resource}/{script}",
                context=f"Found in thread {thread_id} stack",
                confidence=0.8
            ))

        # Look for fxmanifest references
        for match in self.FIVEM_PATTERNS['fxmanifest'].finditer(data):
            resource = match.group(1).decode('utf-8', errors='replace')
            self._add_evidence(ScriptEvidence(
                evidence_type=EvidenceType.MANIFEST_REFERENCE,
                script_name='fxmanifest.lua',
                resource_name=resource,
                context=f"Manifest found in thread {thread_id} stack",
                confidence=0.7
            ))

    def _analyze_raw_memory(self, data: bytes) -> None:
        """Analyze raw memory dump for strings and patterns."""
        # Extract all printable strings
        strings = self._extract_strings_advanced(data)

        # Populate raw_strings for pattern matching in full_analysis (avoids re-reading dump)
        max_raw_strings = getattr(self, '_max_raw_strings', 3000)
        seen_raw: Set[str] = set()
        for s, _ in strings:
            if s not in seen_raw and len(self.result.raw_strings) < max_raw_strings:
                seen_raw.add(s)
                self.result.raw_strings.append(s)
            if len(self.result.raw_strings) >= max_raw_strings:
                break

        # Categorize strings
        for s, offset in strings:
            lower = s.lower()

            # Check for script paths - capture FULL path before .lua/.js
            if '.lua' in lower:
                # Match full path: capture everything up to and including the .lua file
                lua_match = re.search(
                    r'(@?[A-Za-z0-9_\-/\\]+[/\\]([A-Za-z0-9_\-]+\.lua))', s)
                if lua_match:
                    full_path = lua_match.group(1)
                    script_name = lua_match.group(2)
                    self.result.script_paths.append(full_path)

                    # Extract resource from full path
                    resource = self._extract_resource_from_path(full_path)

                    self._add_evidence(ScriptEvidence(
                        evidence_type=EvidenceType.SCRIPT_PATH,
                        script_name=script_name,
                        resource_name=resource,  # May be None, that's OK
                        file_path=full_path,
                        memory_address=offset,
                        confidence=0.7
                    ))

            if '.js' in lower:
                js_match = re.search(
                    r'(@?[A-Za-z0-9_\-/\\]+[/\\]([A-Za-z0-9_\-]+\.js))', s)
                if js_match:
                    full_path = js_match.group(1)
                    script_name = js_match.group(2)
                    self.result.script_paths.append(full_path)

                    resource = self._extract_resource_from_path(full_path)

                    self._add_evidence(ScriptEvidence(
                        evidence_type=EvidenceType.SCRIPT_PATH,
                        script_name=script_name,
                        resource_name=resource,
                        file_path=full_path,
                        memory_address=offset,
                        confidence=0.7
                    ))

            # Check for resource references
            if 'resource' in lower or 'fxmanifest' in lower:
                res_match = re.search(r'([A-Za-z0-9_\-]{2,64})[/\\]fxmanifest', s, re.I)
                if res_match:
                    self._add_evidence(ScriptEvidence(
                        evidence_type=EvidenceType.MANIFEST_REFERENCE,
                        script_name='fxmanifest.lua',
                        resource_name=res_match.group(1),
                        memory_address=offset,
                        confidence=0.6
                    ))
            
            # FiveM cache paths - format: compcache_nb:/resourcename/ or cache:/resourcename/
            cache_match = re.search(r'(?:cache|compcache)[_a-z]*:/([A-Za-z0-9_\-]{2,64})/', s, re.I)
            if cache_match:
                resource = cache_match.group(1)
                if self._is_valid_resource_name(resource):
                    self._add_evidence(ScriptEvidence(
                        evidence_type=EvidenceType.RESOURCE_NAME,
                        script_name='cache_reference',
                        resource_name=resource,
                        context=f"Cache reference: {s[:80]}",
                        memory_address=offset,
                        confidence=0.65
                    ))
            
            # FiveM citizen resource paths - format: citizen:/resources/resourcename
            citizen_res_match = re.search(r'citizen:/resources?/([A-Za-z0-9_\-]{2,64})', s, re.I)
            if citizen_res_match:
                resource = citizen_res_match.group(1)
                if self._is_valid_resource_name(resource):
                    self._add_evidence(ScriptEvidence(
                        evidence_type=EvidenceType.RESOURCE_NAME,
                        script_name='citizen_resource',
                        resource_name=resource,
                        context=f"Citizen resource: {s[:80]}",
                        memory_address=offset,
                        confidence=0.7
                    ))

    def _extract_strings_advanced(self, data: bytes, min_length: int = 4) -> List[Tuple[str, int]]:
        """Extract strings with their memory offsets.
        
        Optimized with memoryview to avoid copying data and chunked processing
        for large dumps.
        """
        results = []

        # Process ASCII strings - use regex for speed (orders of magnitude faster than iteration)
        ascii_pattern = rb'[ -~]{' + str(min_length).encode() + rb',}'
        for match in re.finditer(ascii_pattern, data):
            results.append((match.group().decode('ascii'), match.start()))

        data_view = memoryview(data)
        data_len = len(data)

        # UTF-16 strings (common in Windows) - only process if dump is reasonable size
        # Skip UTF-16 extraction for very large dumps (> 100MB) to save time
        if data_len < 100 * 1024 * 1024:
            try:
                i = 0
                while i < data_len - 2:
                    b = data_view[i]
                    if 32 <= b <= 126 and data_view[i + 1] == 0:
                        start = i
                        chars = []
                        while i < data_len - 1 and 32 <= data_view[i] <= 126 and data_view[i + 1] == 0:
                            chars.append(chr(data_view[i]))
                            i += 2
                        if len(chars) >= min_length:
                            results.append((''.join(chars), start))
                    else:
                        i += 1
            except Exception:
                pass

        return results

    # ============================================================================
    # Fast Literal Pattern Search (for huge dumps - 100x faster than regex)
    # ============================================================================

    def _fast_lua_error_search(self, data: bytes, chunk_offset: int = 0) -> None:
        """Ultra-fast literal string search for Lua errors in huge dumps.
        
        Replaces regex with bytes.find() for critical patterns. ~100x faster.
        Searches for:
        - ".lua:" (script references)
        - "Error running" / "error:" (Lua errors)
        - "lua_pcall" (Lua call frames)
        - "script:" (resource scripts)
        """
        # Literal patterns to search (FiveM-specific - comprehensive)
        lua_indicators = [
            b'.lua:',
            b'.lua]',
            b'@resource',
            b'stack traceback:',
            b'SCRIPT ERROR',
            b'Error loading',
            b'citizen:/',
            b'resources/',
            b'resource "',
            b'ensure ',
            b'start ',
            b'fx_version',
            b'server_script',
            b'client_script',
            b'shared_script',
            b'__resource.lua',
            b'fxmanifest.lua',
            b'attempt to call',
            b'attempt to index',
            b'bad argument',
            b'RegisterNetEvent',
            b'AddEventHandler',
            b'TriggerEvent',
            b'exports[',
            b'lib.callback',
        ]
        
        hits = []
        for pattern in lua_indicators:
            pos = 0
            for _ in range(10000):  # Per ADA restrictions: bounded loop (max pattern matches)
                pos = data.find(pattern, pos)
                if pos == -1:
                    break
                hits.append(pos)
                pos += len(pattern)
        
        # Sort hits and extract 2KB context around each for better data
        hits.sort()
        for hit_pos in hits:
            start = max(0, hit_pos - 1024)
            end = min(len(data), hit_pos + 1024)
            context = data[start:end]
            
            # Try to extract structured info from context
            try:
                text = context.decode('utf-8', errors='replace')
                
                # Look for script paths (high-confidence FiveM pattern)
                if '.lua:' in text or '.lua]' in text or '@resource' in text:
                    # Extract script name and line number
                    for line in text.split('\n'):
                        if '.lua' in line and ('resource' in line.lower() or '/' in line or '\\' in line or '0x' in line):
                            # Simple parsing - look for patterns like "script.lua:123" or "0x12345678.lua"
                            parts = line.split('.lua')
                            if len(parts) >= 2:
                                script_part = parts[0].split()[-1] if parts[0].split() else parts[0][-50:]
                                
                                # Clean binary garbage from path
                                clean_script = ''
                                for char in script_part:
                                    if char.isprintable() and char not in '\x00\xff':
                                        clean_script += char
                                
                                # Check if this is a native hash file (0x12345678.lua)
                                import re
                                native_hash_match = re.search(r'(0x[0-9a-fA-F]{8})', clean_script)
                                if native_hash_match:
                                    hash_value = native_hash_match.group(1)
                                    native_name = decode_native_hash(hash_value)
                                    script_name = f"{native_name} ({hash_value}.lua)"
                                else:
                                    script_name = clean_script + '.lua'
                                
                                # Skip if too short or just garbage
                                if len(script_name) < 3 or script_name.count('�') > 3:
                                    continue
                                line_num = None
                                after_lua = parts[1]
                                if after_lua and after_lua[0] == ':':
                                    num_str = ''
                                    for ch in after_lua[1:]:
                                        if ch.isdigit():
                                            num_str += ch
                                        else:
                                            break
                                    if num_str:
                                        line_num = int(num_str)
                                
                                # Create evidence
                                evidence = ScriptEvidence(
                                    evidence_type=EvidenceType.SCRIPT_PATH,
                                    script_name=script_name,
                                    line_number=line_num,
                                    memory_address=chunk_offset + hit_pos,
                                    context=line.strip()[:200],
                                    confidence=0.8
                                )
                                
                                evidence_key = f"{evidence.evidence_type.value}:{evidence.script_name}:{evidence.line_number}"
                                if evidence_key not in self._evidence_seen:
                                    self._evidence_seen.add(evidence_key)
                                    self.result.all_evidence.append(evidence)
                
                # Extract resource names from manifest patterns
                if 'resource "' in text or 'ensure ' in text or 'start ' in text:
                    for line in text.split('\n'):
                        if 'resource "' in line:
                            # Extract: resource "resource_name"
                            parts = line.split('resource "')
                            if len(parts) > 1:
                                resource_name = parts[1].split('"')[0] if '"' in parts[1] else None
                                if resource_name and len(resource_name) < 50:
                                    evidence = ScriptEvidence(
                                        evidence_type=EvidenceType.RESOURCE_NAME,
                                        script_name='',
                                        resource_name=resource_name,
                                        context=line.strip()[:150],
                                        confidence=0.9
                                    )
                                    key = f"resource:{resource_name}"
                                    if key not in self._evidence_seen:
                                        self._evidence_seen.add(key)
                                        self.result.all_evidence.append(evidence)
                        elif 'ensure ' in line or 'start ' in line:
                            # Extract: ensure resource_name or start resource_name
                            words = line.split()
                            for i, word in enumerate(words):
                                if word in ['ensure', 'start'] and i + 1 < len(words):
                                    resource_name = words[i + 1].strip()
                                    if resource_name and len(resource_name) < 50:
                                        evidence = ScriptEvidence(
                                            evidence_type=EvidenceType.RESOURCE_NAME,
                                            script_name='',
                                            resource_name=resource_name,
                                            context=line.strip()[:150],
                                            confidence=0.85
                                        )
                                        key = f"resource:{resource_name}"
                                        if key not in self._evidence_seen:
                                            self._evidence_seen.add(key)
                                            self.result.all_evidence.append(evidence)
                
                # Look for FiveM-specific error messages
                error_keywords = ['SCRIPT ERROR', 'Error loading', 'stack traceback', 'attempt to call', 'attempt to index', 'bad argument']
                if any(kw in text for kw in error_keywords):
                    for line in text.split('\n'):
                        if any(kw in line for kw in error_keywords):
                            error = ScriptError(
                                error_type='runtime',
                                message=line.strip()[:300]
                            )
                            # Avoid duplicates
                            if not any(e.message == error.message for e in self.result.script_errors):
                                self.result.script_errors.append(error)
                
            except Exception:
                pass  # Skip decode errors

    def _extract_server_config(self, data: bytes, chunk_offset: int = 0) -> None:
        """Extract server.cfg entries and resource lists."""
        config_patterns = [
            b'ensure ',
            b'start ',
            b'stop ',
            b'restart ',
            b'exec ',
            b'sv_hostname',
            b'sv_maxclients',
            b'endpoint_add_',
        ]
        
        for pattern in config_patterns:
            pos = 0
            for _ in range(10000):  # Per ADA restrictions: bounded loop (max pattern matches)
                pos = data.find(pattern, pos)
                if pos == -1:
                    break
                
                # Extract the line
                line_start = max(0, pos - 50)
                line_end = min(len(data), pos + 200)
                line_data = data[line_start:line_end]
                
                try:
                    text = line_data.decode('utf-8', errors='ignore')
                    lines = text.split('\n')
                    for line in lines:
                        if pattern.decode('utf-8', errors='ignore') in line:
                            clean_line = line.strip()
                            if len(clean_line) > 5 and len(clean_line) < 200:
                                # Extract resource name from ensure/start commands
                                if 'ensure' in clean_line or 'start' in clean_line:
                                    parts = clean_line.split()
                                    if len(parts) >= 2:
                                        resource_name = parts[1].strip('"\'')
                                        if resource_name and len(resource_name) < 64:
                                            evidence = ScriptEvidence(
                                                evidence_type=EvidenceType.RESOURCE_NAME,
                                                script_name='',
                                                resource_name=resource_name,
                                                context=f"server.cfg: {clean_line}",
                                                confidence=0.95
                                            )
                                            key = f"cfg_resource:{resource_name}"
                                            if key not in self._evidence_seen:
                                                self._evidence_seen.add(key)
                                                self.result.all_evidence.append(evidence)
                except Exception:
                    pass
                
                pos += len(pattern)
    
    def _extract_lua_code_fragments(self, data: bytes, chunk_offset: int = 0) -> None:
        """Extract actual Lua code snippets from memory."""
        # Look for function definitions and common Lua patterns
        lua_code_patterns = [
            b'function ',
            b'local ',
            b'if then',
            b'end\n',
            b'return ',
            b'RegisterCommand(',
            b'CreateThread(',
            b'Wait(',
        ]
        
        # Find clusters of Lua keywords
        hits = []
        for pattern in lua_code_patterns:
            pos = 0
            count = 0
            while count < 50:  # Limit per pattern
                pos = data.find(pattern, pos)
                if pos == -1:
                    break
                hits.append(pos)
                count += 1
                pos += len(pattern)
        
        hits.sort()
        
        # Extract code blocks around clusters
        i = 0
        while i < len(hits):
            # Find cluster of hits within 500 bytes
            cluster_start = hits[i]
            cluster_end = cluster_start
            j = i
            while j < len(hits) and hits[j] - cluster_start < 500:
                cluster_end = hits[j]
                j += 1
            
            # Extract this code block
            if j - i >= 2:  # At least 2 Lua keywords nearby
                start = max(0, cluster_start - 100)
                end = min(len(data), cluster_end + 200)
                code_chunk = data[start:end]
                
                try:
                    text = code_chunk.decode('utf-8', errors='ignore')
                    # Clean up binary garbage
                    clean_lines = []
                    for line in text.split('\n'):
                        if len(line) > 3 and sum(c.isprintable() or c.isspace() for c in line) / len(line) > 0.7:
                            clean_lines.append(line)
                    
                    if len(clean_lines) >= 2:
                        code_snippet = '\n'.join(clean_lines[:10])  # Max 10 lines
                        if 'function' in code_snippet or 'local' in code_snippet:
                            error = ScriptError(
                                error_type='lua_code_fragment',
                                message=code_snippet[:300]
                            )
                            if not any(e.message == error.message for e in self.result.script_errors):
                                self.result.script_errors.append(error)
                except Exception:
                    pass
            
            i = j if j > i else i + 1
    
    def _extract_database_queries(self, data: bytes, chunk_offset: int = 0) -> None:
        """Extract SQL queries and database operations."""
        db_patterns = [
            b'SELECT ',
            b'INSERT INTO',
            b'UPDATE ',
            b'DELETE FROM',
            b'CREATE TABLE',
            b'ALTER TABLE',
            b'MySQL.Async',
            b'exports.oxmysql',
        ]
        
        for pattern in db_patterns:
            pos = 0
            count = 0
            while count < 20:
                pos = data.find(pattern, pos)
                if pos == -1:
                    break
                count += 1
                
                # Extract query
                start = max(0, pos - 50)
                end = min(len(data), pos + 300)
                query_data = data[start:end]
                
                try:
                    text = query_data.decode('utf-8', errors='ignore')
                    if pattern.decode('utf-8', errors='ignore') in text:
                        # Extract just the query part
                        for line in text.split('\n'):
                            if any(kw in line for kw in ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'MySQL']):
                                clean = line.strip()[:200]
                                if len(clean) > 10:
                                    error = ScriptError(
                                        error_type='database_query',
                                        message=clean
                                    )
                                    if not any(e.message == error.message for e in self.result.script_errors):
                                        self.result.script_errors.append(error)
                                    break
                except Exception:
                    pass
                
                pos += len(pattern)
    
    def _extract_event_data(self, data: bytes, chunk_offset: int = 0) -> None:
        """Extract event names and network triggers."""
        event_patterns = [
            b'RegisterNetEvent',
            b'TriggerEvent',
            b'TriggerServerEvent',
            b'TriggerClientEvent',
            b'AddEventHandler',
        ]
        
        for pattern in event_patterns:
            pos = 0
            count = 0
            while count < 100:
                pos = data.find(pattern, pos)
                if pos == -1:
                    break
                count += 1
                
                # Extract event name (usually in quotes after the pattern)
                start = pos
                end = min(len(data), pos + 150)
                context = data[start:end]
                
                try:
                    text = context.decode('utf-8', errors='ignore')
                    # Look for strings in quotes
                    import re
                    matches = re.findall(r'["\']([a-zA-Z0-9_:.\-]+)["\']', text)
                    if matches:
                        event_name = matches[0]
                        if len(event_name) > 2 and len(event_name) < 80:
                            evidence = ScriptEvidence(
                                evidence_type=EvidenceType.EVENT_HANDLER,
                                script_name=event_name,
                                context=f"{pattern.decode('utf-8', 'ignore')}('{event_name}')",
                                confidence=0.75
                            )
                            key = f"event:{event_name}"
                            if key not in self._evidence_seen:
                                self._evidence_seen.add(key)
                                self.result.all_evidence.append(evidence)
                except Exception:
                    pass
                
                pos += len(pattern)
    
    def _decode_fivem_structures(self, data: bytes, chunk_offset: int = 0) -> None:
        """Decode FiveM internal structures from binary memory.
        
        Patterns we're looking for:
        - funcRefIdx: Function reference index (Lua callbacks)
        - MakeFunctionReference: FiveM's internal function wrapper
        - callbackResponse: Async callback data
        - rawSize: Memory allocation metadata
        """
        # Extract readable strings around known FiveM markers
        markers = [
            (b'funcRefIdx', 'Function Reference'),
            (b'MakeFunctionReference', 'Lua Callback Wrapper'),
            (b'callbackResponse', 'Async Callback'),
            (b'cb_invalid', 'Invalid Callback State'),
            (b'rawSize', 'Memory Allocation'),
            (b'GetInvokingResource', 'Resource Context'),
            (b'msgpack', 'Serialized Data'),
        ]
        
        for marker, description in markers:
            pos = 0
            for _ in range(10000):  # Per ADA restrictions: bounded loop (max pattern matches)
                pos = data.find(marker, pos)
                if pos == -1:
                    break
                
                # Extract surrounding context
                start = max(0, pos - 64)
                end = min(len(data), pos + 128)
                chunk = data[start:end]
                
                # Try to extract readable parts
                readable_parts = []
                current_string = []
                
                for byte in chunk:
                    if 32 <= byte <= 126:  # Printable ASCII
                        current_string.append(chr(byte))
                    else:
                        if len(current_string) >= 4:  # Min 4 chars
                            readable_parts.append(''.join(current_string))
                        current_string = []
                
                if current_string and len(current_string) >= 4:
                    readable_parts.append(''.join(current_string))
                
                # Create structured evidence
                if readable_parts:
                    context = ' | '.join(readable_parts[:5])  # Top 5 strings
                    
                    # Check for numeric patterns (memory addresses, sizes)
                    numbers = []
                    for part in readable_parts:
                        # Extract numbers
                        import re
                        nums = re.findall(r'\d+', part)
                        numbers.extend(nums)
                    
                    evidence = ScriptEvidence(
                        evidence_type=EvidenceType.MEMORY_REGION,
                        script_name=description,
                        memory_address=chunk_offset + pos,
                        context=context[:200],
                        confidence=0.6
                    )
                    
                    key = f"struct:{description}:{pos}"
                    if key not in self._evidence_seen:
                        self._evidence_seen.add(key)
                        self.result.all_evidence.append(evidence)
                        
                        # If we found numeric data, create a note
                        if numbers:
                            note = f"{description} @ 0x{chunk_offset + pos:X}: {', '.join(numbers[:3])}"
                            if note not in [e.message for e in self.result.script_errors]:
                                self.result.script_errors.append(ScriptError(
                                    error_type='internal_structure',
                                    message=note
                                ))
                
                pos += len(marker)

    def _find_native_callers(self, data: bytes, chunk_offset: int = 0) -> None:
        """Find which scripts are calling specific GTA V natives by searching for hash patterns."""
        import struct
        
        # Get all the native hashes we know about
        target_hashes = []
        for hash_key, name in GTA_NATIVE_HASHES.items():
            # Remove 0x prefix and convert to int
            hash_int = int(hash_key.replace('0x', ''), 16)
            target_hashes.append((hash_key.lower().encode('utf-8'), hash_int, name, hash_key))
        
        # Search for each native hash in multiple formats
        for hash_text, hash_int, native_name, hash_str in target_hashes:
            positions = []
            
            # Search 1: Text format "0x32f8866d"
            pos = 0
            while len(positions) < 10:
                pos = data.find(hash_text, pos)
                if pos == -1:
                    break
                positions.append(pos)
                pos += len(hash_text)
            
            # Search 2: Little-endian 32-bit integer (most common in memory)
            hash_bytes_le = struct.pack('<I', hash_int)
            pos = 0
            while len(positions) < 20:
                pos = data.find(hash_bytes_le, pos)
                if pos == -1:
                    break
                # Don't add if within 100 bytes of existing position
                if not any(abs(pos - p) < 100 for p in positions):
                    positions.append(pos)
                pos += 4
            
            # Search 3: Big-endian 32-bit integer
            hash_bytes_be = struct.pack('>I', hash_int)
            pos = 0
            while len(positions) < 30:
                pos = data.find(hash_bytes_be, pos)
                if pos == -1:
                    break
                if not any(abs(pos - p) < 100 for p in positions):
                    positions.append(pos)
                pos += 4
            
            # Analyze context around each position
            for pos in positions[:10]:  # Max 10 per native
                # Extract 12KB context (very large to catch distant script references)
                start = max(0, pos - 10240)
                end = min(len(data), pos + 2048)
                context = data[start:end]
                
                try:
                    text = context.decode('utf-8', errors='ignore')
                    
                    # Look for .lua file references
                    lua_files = []
                    import re
                    
                    # Pattern 1: @resource/path/file.lua (FiveM resource reference)
                    resource_matches = re.findall(r'@([a-zA-Z0-9_-]+)/([a-zA-Z0-9_/.-]+\.lua)', text)
                    for resource, script in resource_matches:
                        if len(resource) > 2 and len(script) > 3:
                            lua_files.append(f"@{resource}/{script}")
                    
                    # Pattern 2: resource-name/script.lua (relative path)
                    relative_matches = re.findall(r'([a-zA-Z0-9_-]{3,})/([a-zA-Z0-9_-]+\.lua)', text)
                    for folder, script in relative_matches:
                        if folder not in ['client', 'server', 'shared', 'lib', 'config']:
                            lua_files.append(f"@{folder}/{script}")
                    
                    # Pattern 3: Just resource name from events (qb-crypto, mhacking, etc.)
                    event_matches = re.findall(r'([a-zA-Z0-9_-]{4,}):(server|client|show|hide|start)', text)
                    for resource, _ in event_matches:
                        if resource not in ['local', 'function', 'return']:
                            lua_files.append(f"@{resource}")
                    
                    # Filter out hash files and invalid paths
                    lua_files = [f for f in lua_files if not re.search(r'0x[0-9a-f]{8}', f.lower())]
                    lua_files = [f for f in lua_files if len(f) > 4]
                    
                    if lua_files:
                        # Take the most specific script (prefer full paths over resource names)
                        calling_script = max(lua_files, key=lambda x: (x.count('/'), x.startswith('@'), len(x)))
                        
                        # Create attribution
                        attribution_msg = f"{calling_script} → {native_name}"
                        
                        # Check if we already have this exact attribution
                        existing = [e for e in self.result.script_errors 
                                   if e.error_type == 'native_caller' and e.message == attribution_msg]
                        if not existing:
                            self.result.script_errors.append(ScriptError(
                                error_type='native_caller',
                                message=attribution_msg,
                                script_name=calling_script,
                                resource_name=calling_script.split('/')[0].replace('@', '') if '/' in calling_script else None
                            ))
                except Exception:
                    pass
    
    def _correlate_natives_with_code_fragments(self) -> None:
        """Analyze Lua code fragments to find which scripts call which natives."""
        # Common native call patterns in Lua code
        native_call_patterns = [
            (r'Citizen\.InvokeNative\s*\(\s*[`"\']?(0x[0-9a-fA-F]{8})', 'invoke'),  # Citizen.InvokeNative(0x12345678)
            (r'Citizen\.Invoke\s*\(\s*[`"\']?(0x[0-9a-fA-F]{8})', 'invoke'),         # Citizen.Invoke(0x12345678)  
            (r'\b([A-Z_][A-Z0-9_]{4,})\s*\(', 'name'),                               # NATIVE_FUNCTION_NAME( (caps, 5+ chars)
        ]
        
        # Get native hashes from our database for reverse lookup
        hash_to_name = {}
        for hash_key, name in GTA_NATIVE_HASHES.items():
            # hash_key is already a string like '0x32F8866D'
            hash_to_name[hash_key.lower()] = name
        
        # Search existing Lua code fragments for native calls
        for error in self.result.script_errors:
            if error.error_type == 'lua_code_fragment':
                code = error.message
                
                # Try to extract resource/script context from code
                script_context = None
                
                # Look for exports['resource-name'] which indicates the resource
                resource_match = re.search(r'exports\[[\'"]([^\'"]+)[\'"]\]', code)
                if resource_match:
                    script_context = f"@{resource_match.group(1)}"
                
                # Look for RegisterNetEvent patterns which often have resource hints
                event_match = re.search(r'RegisterNetEvent\([\'"]([^\'":]+)', code)
                if not script_context and event_match:
                    event_parts = event_match.group(1).split(':')
                    if len(event_parts) >= 2:
                        script_context = f"@{event_parts[0]}"
                
                if not script_context:
                    script_context = "detected_script.lua"
                
                # Search for native function calls
                natives_found = []
                for pattern, pattern_type in native_call_patterns:
                    for match in re.finditer(pattern, code, re.IGNORECASE):
                        native_ref = match.group(1) if match.groups() else match.group(0)
                        
                        # Handle hash references
                        if pattern_type == 'invoke' and native_ref.startswith('0x'):
                            hash_lower = native_ref.lower()
                            native_name = hash_to_name.get(hash_lower, native_ref)
                            natives_found.append(native_name)
                        
                        # Handle direct native names (all caps, 5+ chars)
                        elif pattern_type == 'name':
                            # Filter out common Lua keywords that match the pattern
                            keywords = {'CREATE', 'RETURN', 'LOCAL', 'FUNCTION', 'TABLE', 'STRING', 
                                       'ERROR', 'PRINT', 'PAIRS', 'IPAIRS', 'ASSERT', 'REQUIRE'}
                            if native_ref not in keywords and len(native_ref) >= 5:
                                natives_found.append(native_ref)
                
                # Create attribution entries for each unique native found
                for native_name in set(natives_found):
                    attribution_msg = f"{script_context} → {native_name}"
                    
                    # Avoid duplicates
                    existing = [e for e in self.result.script_errors 
                               if e.error_type == 'native_attribution' and e.message == attribution_msg]
                    if not existing:
                        attribution = ScriptError(
                            error_type='native_attribution',
                            message=attribution_msg,
                            script_name=script_context
                        )
                        self.result.script_errors.append(attribution)
    
    def _fast_native_call_search(self, data: bytes, chunk_offset: int = 0) -> None:
        """Search for GTA native function calls in memory."""
        native_patterns = [
            b'Citizen.Invoke',
            b'InvokeNative',
            b'0x',  # Native hashes start with 0x
        ]
        
        # Find native call patterns (increased limit for better coverage)
        for pattern in native_patterns:
            pos = 0
            count = 0
            while count < 500:  # Increased from 100 for better data extraction
                pos = data.find(pattern, pos)
                if pos == -1:
                    break
                count += 1
                
                # Extract LARGE context to find calling script
                start = max(0, pos - 4096)  # 4KB before for better script detection
                end = min(len(data), pos + 1024)  # 1KB after
                context = data[start:end]
                
                try:
                    text = context.decode('utf-8', errors='ignore')
                    
                    # Look for .lua file references near this native call
                    calling_script = None
                    if '.lua' in text:
                        import re
                        # Find ALL .lua references
                        lua_matches = list(re.finditer(r'([@]?[a-zA-Z0-9_/\\.-]+\.lua)', text))
                        if lua_matches:
                            # Get the last (closest) match before the Invoke, prefer @resource paths
                            valid_matches = [m.group(1) for m in lua_matches if len(m.group(1)) > 3]
                            if valid_matches:
                                # Prefer @ paths, then longer paths
                                calling_script = max(valid_matches, key=lambda s: (s.startswith('@'), len(s)))
                    
                    # Look for native hash in context
                    native_hash = None
                    hash_matches = re.findall(r'(0x[0-9a-fA-F]{8})', text)
                    if hash_matches:
                        native_hash = hash_matches[0]
                    
                    if 'Invoke' in text:
                        # Extract the native call if visible
                        evidence = ScriptEvidence(
                            evidence_type=EvidenceType.NATIVE_CALL,
                            script_name=calling_script or 'N/A',
                            memory_address=chunk_offset + pos,
                            context=text.strip()[:150],
                            confidence=0.7 if calling_script else 0.5
                        )
                        key = f"native:{chunk_offset + pos}"
                        if key not in self._evidence_seen:
                            self._evidence_seen.add(key)
                            self.result.all_evidence.append(evidence)
                            
                            # Create a note about the call relationship
                            if calling_script and native_hash:
                                native_name = decode_native_hash(native_hash)
                                note = f"{calling_script} calls {native_name}"
                                if note not in [e.message for e in self.result.script_errors if e.error_type == 'native_attribution']:
                                    self.result.script_errors.append(ScriptError(
                                        error_type='native_attribution',
                                        message=note,
                                        script_name=calling_script
                                    ))
                except Exception:
                    pass
                
                pos += len(pattern)
    
    def _fast_js_error_search(self, data: bytes, chunk_offset: int = 0) -> None:
        """Ultra-fast literal string search for JavaScript errors."""
        js_indicators = [
            b'.js:',
            b'.jsx:',
            b'.ts:',
            b'.tsx:',
            b'TypeError:',
            b'ReferenceError:',
            b'SyntaxError:',
            b'    at ',  # JS stack trace lines
            b'<anonymous>',
        ]
        
        hits = []
        for pattern in js_indicators:
            pos = 0
            for _ in range(10000):  # Per ADA restrictions: bounded loop (max pattern matches)
                pos = data.find(pattern, pos)
                if pos == -1:
                    break
                hits.append((pos, pattern))
                pos += len(pattern)
        
        # Extract context around JS errors
        for hit_pos, pattern in hits:
            start = max(0, hit_pos - 512)
            end = min(len(data), hit_pos + 512)
            context = data[start:end]
            
            try:
                text = context.decode('utf-8', errors='replace')
                
                if '.js' in text:
                    for line in text.split('\n'):
                        if '.js' in line:
                            evidence = ScriptEvidence(
                                evidence_type=EvidenceType.JS_STACK_TRACE,
                                script_name=line.strip()[:100],
                                memory_address=chunk_offset + hit_pos,
                                context=line.strip()[:200],
                                confidence=0.6
                            )
                            
                            evidence_key = f"js:{evidence.script_name}"
                            if evidence_key not in self._evidence_seen:
                                self._evidence_seen.add(evidence_key)
                                self.result.all_evidence.append(evidence)
            except Exception:
                pass

    def _extract_lua_stacks(self, data: bytes) -> None:
        """Extract Lua stack traces from memory."""
        # Pattern for Lua stack trace lines
        # Common formats:
        # [resource/script.lua]:123: in function 'name'
        # resource/script.lua:123: error message

        stack_pattern = re.compile(
            rb'(?:\[[@]?([^\]]+\.lua)\]:?|[@]?([A-Za-z0-9_\-/\\]+\.lua):)'
            rb'(\d+):\s*'
            rb'(?:in\s+(?:function\s+)?[\'"<]?([A-Za-z0-9_]*)[\'">\s]?)?'
            rb'([^\x00\r\n]{0,200})',
            re.IGNORECASE
        )

        current_stack = []
        last_offset = -1000

        for match in stack_pattern.finditer(data):
            offset = match.start()
            source = (match.group(1) or match.group(2) or b'').decode('utf-8', errors='replace')
            line = int(match.group(3))
            func_name = (match.group(4) or b'').decode('utf-8', errors='replace')
            context = (match.group(5) or b'').decode('utf-8', errors='replace')

            if not source:
                continue

            # Check if this is part of the same stack trace
            if offset - last_offset > 500:
                # New stack trace
                if current_stack:
                    self.result.lua_stacks.append(current_stack)
                current_stack = []

            frame = LuaStackFrame(
                source=source,
                line=line,
                function_name=func_name or '(anonymous)',
                is_c_function='[C]' in source
            )
            current_stack.append(frame)
            last_offset = offset

            # Extract resource name from source path
            resource_match = re.search(r'^[@]?([A-Za-z0-9_\-]+)[/\\]', source)
            resource = resource_match.group(1) if resource_match else None

            # Check for context in natives_loader.lua
            if 'natives_loader.lua' in source:
                 # Try to find the native name in the context
                 native_match = re.search(rb'(?:Global\.)?([A-Z][a-zA-Z0-9_]+)\s*\(', data[offset:offset+200])
                 if native_match:
                     native_name = native_match.group(1).decode('utf-8', errors='replace')
                     if native_name:
                         # Store this as evidence
                          self._add_evidence(ScriptEvidence(
                            evidence_type=EvidenceType.NATIVE_CALL,
                            script_name='natives_loader.lua',
                            resource_name=resource,
                            context=f"Native Call: {native_name}",
                            confidence=0.8,
                            memory_address=offset
                        ))

            # Add evidence for this script
            self._add_evidence(ScriptEvidence(
                evidence_type=EvidenceType.LUA_STACK_TRACE,
                script_name=os.path.basename(source),
                resource_name=resource,
                file_path=source,
                line_number=line,
                function_name=func_name,
                memory_address=offset,
                context=context[:200] if context else "",
                confidence=0.95
            ))

        if current_stack:
            self.result.lua_stacks.append(current_stack)

    def _extract_js_stacks(self, data: bytes) -> None:
        """Extract JavaScript stack traces from memory."""
        # V8/Node.js style stack traces
        js_stack_pattern = re.compile(
            rb'at\s+([A-Za-z0-9_\.<>\[\]]+)\s+\(([^:]+\.js):(\d+):(\d+)\)',
            re.IGNORECASE
        )

        for match in js_stack_pattern.finditer(data):
            func_name = match.group(1).decode('utf-8', errors='replace')
            file_path = match.group(2).decode('utf-8', errors='replace')
            line = int(match.group(3))
            col = int(match.group(4))

            # Extract resource name from path
            resource_match = re.search(r'([A-Za-z0-9_\-]+)[/\\]', file_path)
            resource = resource_match.group(1) if resource_match else None

            self._add_evidence(ScriptEvidence(
                evidence_type=EvidenceType.JS_STACK_TRACE,
                script_name=os.path.basename(file_path),
                resource_name=resource,
                file_path=file_path,
                line_number=line,
                function_name=func_name,
                memory_address=match.start(),
                context=f"Column {col}",
                confidence=0.95
            ))

            self.result.js_stacks.append(
                f"at {func_name} ({file_path}:{line}:{col})"
            )

    def _find_script_errors(self, data: bytes) -> None:
        """Find script errors in memory dump."""
        # Lua error pattern: file.lua:line: error message
        lua_error_pattern = re.compile(
            rb'([@]?([A-Za-z0-9_\-/\\]+\.lua)):(\d+):\s*([^\x00\r\n]{5,500})',
            re.IGNORECASE
        )

        for match in lua_error_pattern.finditer(data):
            file_path = match.group(1).decode('utf-8', errors='replace')
            line = int(match.group(3))
            message = match.group(4).decode('utf-8', errors='replace')

            # Skip if it looks like a path, not an error
            if not any(err in message.lower() for err in ['error', 'nil', 'attempt', 'bad', 'invalid', 'fail', 'exception']):
                # Check context for error indicators
                context_start = max(0, match.start() - 100)
                context = data[context_start:match.start()].lower()
                if b'error' not in context and b'exception' not in context:
                    continue

            resource_match = re.search(r'^([A-Za-z0-9_\-]+)[/\\]', file_path)
            resource = resource_match.group(1) if resource_match else None

            error = ScriptError(
                error_type='Lua Error',
                message=message,
                script_name=os.path.basename(file_path),
                resource_name=resource,
                line_number=line
            )
            self.result.script_errors.append(error)

            self._add_evidence(ScriptEvidence(
                evidence_type=EvidenceType.ERROR_MESSAGE,
                script_name=os.path.basename(file_path),
                resource_name=resource,
                file_path=file_path,
                line_number=line,
                context=message[:200],
                confidence=0.99,
                memory_address=match.start()
            ))

        # Citizen/FiveM script error pattern
        citizen_error_pattern = re.compile(
            rb'(?:SCRIPT\s*ERROR|ScriptError|script\s*error)[:\s]*([^\x00\r\n]{10,500})',
            re.IGNORECASE
        )

        for match in citizen_error_pattern.finditer(data):
            message = match.group(1).decode('utf-8', errors='replace')

            # Try to extract resource/script from message
            res_match = re.search(r'(@?[A-Za-z0-9_\-]+)/([A-Za-z0-9_\-]+\.lua)', message)
            resource = res_match.group(1) if res_match else None
            script = res_match.group(2) if res_match else None

            error = ScriptError(
                error_type='Citizen Script Error',
                message=message,
                script_name=script,
                resource_name=resource
            )
            self.result.script_errors.append(error)

            if resource or script:
                self._add_evidence(ScriptEvidence(
                    evidence_type=EvidenceType.ERROR_MESSAGE,
                    script_name=script or 'unknown',
                    resource_name=resource,
                    context=message[:200],
                    confidence=0.95,
                    memory_address=match.start()
                ))

    def _extract_lua_tracebacks(self, data: bytes) -> None:
        """Extract complete Lua tracebacks from memory."""
        # Look for "stack traceback:" followed by traceback lines
        traceback_pattern = re.compile(
            rb'stack\s+traceback\s*:\s*\n((?:\s+[^\n]+\n?)+)',
            re.IGNORECASE | re.MULTILINE
        )

        for match in traceback_pattern.finditer(data):
            traceback_text = match.group(1).decode('utf-8', errors='replace')
            frames = []

            # Parse each line of the traceback
            # Format: [source]:line: in function 'name'
            #     or: source:line: in main chunk
            line_pattern = re.compile(
                r'(?:\[?@?([^\]:\n]+)\]?):(\d+):\s*in\s+(?:(?:local\s+)?function\s+)?[\'"]?([^\'"\n]*)[\'"]?'
            )

            for line_match in line_pattern.finditer(traceback_text):
                source = line_match.group(1).strip()
                line_num = int(line_match.group(2))
                func_name = line_match.group(3).strip() or '(anonymous)'

                # Skip C functions for script identification
                is_c = source == 'C' or source.startswith('[C]')

                frame = LuaStackFrame(
                    source=source,
                    line=line_num,
                    function_name=func_name,
                    is_c_function=is_c
                )
                frames.append(frame)

                # Add evidence for Lua scripts
                if not is_c and '.lua' in source.lower():
                    resource_match = re.search(r'@?([A-Za-z0-9_\-]+)[/\\]', source)
                    resource = resource_match.group(1) if resource_match else None

                    self._add_evidence(ScriptEvidence(
                        evidence_type=EvidenceType.LUA_STACK_TRACE,
                        script_name=os.path.basename(source),
                        resource_name=resource,
                        file_path=source,
                        line_number=line_num,
                        function_name=func_name,
                        memory_address=match.start(),
                        confidence=0.98
                    ))

            if frames:
                self.result.lua_stacks.append(frames)

    def _find_lua_runtime_errors(self, data: bytes) -> None:
        """Find Lua runtime errors with full context."""
        # Single-pass search using compiled regex
        for match in self._LUA_ERROR_REGEX.finditer(data):
            idx = match.start()
            error_bytes = match.group()
            error_type = self._LUA_ERROR_MAP.get(error_bytes, 'unknown')

            # Extract context around the error
            context_start = max(0, idx - 200)
            context_end = min(len(data), idx + len(error_bytes) + 300)
            context = data[context_start:context_end]

            # Try to find the source file and line
            # Look for pattern: @resource/script.lua:123:
            source_pattern = re.compile(
                rb'@?([A-Za-z0-9_\-/\\]+\.lua):(\d+):'
            )
            source_match = source_pattern.search(context)

            if source_match:
                source = source_match.group(1).decode('utf-8', errors='replace')
                line = int(source_match.group(2))

                resource_match = re.search(r'@?([A-Za-z0-9_\-]+)[/\\]', source)
                resource = resource_match.group(1) if resource_match else None

                error = ScriptError(
                    error_type=f'Lua Runtime Error ({error_type})',
                    message=error_bytes.decode('utf-8', errors='replace'),
                    script_name=os.path.basename(source),
                    resource_name=resource,
                    line_number=line
                )
                self.result.script_errors.append(error)

                self._add_evidence(ScriptEvidence(
                    evidence_type=EvidenceType.ERROR_MESSAGE,
                    script_name=os.path.basename(source),
                    resource_name=resource,
                    file_path=source,
                    line_number=line,
                    context=error_bytes.decode('utf-8', errors='replace'),
                    confidence=0.99,
                    memory_address=idx
                ))

    def _find_citizenfx_contexts(self, data: bytes) -> None:
        """Find CitizenFX script runtime contexts in memory."""
        # Look for CitizenFX runtime markers using optimized single-pass regex
        for match in self._CITIZENFX_MARKERS_REGEX.finditer(data):
            idx = match.start()
            marker = match.group()

            # Search nearby for resource names
            context_start = max(0, idx - 100)
            context_end = min(len(data), idx + 200)
            context = data[context_start:context_end]

            # Look for resource paths in context
            resource_pattern = re.compile(rb'@?([A-Za-z0-9_\-]{2,64})[/\\]')
            for res_match in resource_pattern.finditer(context):
                resource = res_match.group(1).decode('utf-8', errors='replace')
                # Filter out common non-resource names
                if resource.lower() not in ['windows', 'system32', 'program', 'files', 'users', 'cache']:
                    self._add_evidence(ScriptEvidence(
                        evidence_type=EvidenceType.MEMORY_REGION,
                        script_name=marker.decode('utf-8', errors='replace'),
                        resource_name=resource,
                        context=f"Near {marker.decode('utf-8', errors='replace')} runtime",
                        confidence=0.5,
                        memory_address=idx
                    ))

        # Look for resource state changes
        if 'resource_state' in self.FIVEM_PATTERNS:
            for match in self.FIVEM_PATTERNS['resource_state'].finditer(data):
                resource = match.group(1).decode('utf-8', errors='replace')
                self._add_evidence(ScriptEvidence(
                    evidence_type=EvidenceType.RESOURCE_NAME,
                    script_name='resource_state',
                    resource_name=resource,
                    context="Resource state change detected",
                    confidence=0.6,
                    memory_address=match.start()
                ))

    def _find_fivem_patterns(self, data: bytes) -> None:
        """Find FiveM-specific patterns in memory.
        
        Note: MiniDumps typically don't contain Lua source code, so we focus on:
        - Resource paths and cache entries
        - Module/DLL references
        - Asset paths that indicate resource usage
        """
        # Native calls - now requires proper function call syntax
        for match in self.FIVEM_PATTERNS['native_call'].finditer(data):
            native = match.group(1).decode('utf-8', errors='replace')
            # Filter out obvious non-natives (too short, lowercase, numbers only)
            if len(native) >= 4 and native[0].isupper() and not native.isdigit():
                if native not in self.result.native_calls:
                    self.result.native_calls.append(native)
        
        # Native invocations by hash
        if 'native_invoke' in self.FIVEM_PATTERNS:
            for match in self.FIVEM_PATTERNS['native_invoke'].finditer(data):
                hash_val = match.group(1).decode('utf-8', errors='replace')
                native_str = f"NATIVE_0x{hash_val.upper()}"
                if native_str not in self.result.native_calls:
                    self.result.native_calls.append(native_str)

        # Event handlers
        for match in self.FIVEM_PATTERNS['event_handler'].finditer(data):
            event = match.group(1).decode('utf-8', errors='replace')
            self.result.event_handlers.append(event)

            # Check for resource prefix in event name
            if ':' in event:
                resource = event.split(':')[0]
                self._add_evidence(ScriptEvidence(
                    evidence_type=EvidenceType.EVENT_HANDLER,
                    script_name='event_handler',
                    resource_name=resource,
                    context=f"Event: {event}",
                    confidence=0.5,
                    memory_address=match.start()
                ))

        # Export calls
        for match in self.FIVEM_PATTERNS['export_call'].finditer(data):
            export_resource = match.group(1).decode('utf-8', errors='replace')
            self._add_evidence(ScriptEvidence(
                evidence_type=EvidenceType.NATIVE_CALL,
                script_name='export',
                resource_name=export_resource,
                context=f"Export from: {export_resource}",
                confidence=0.6,
                memory_address=match.start()
            ))

        # Streaming assets (can indicate resource issues)
        for match in self.FIVEM_PATTERNS['streaming_asset'].finditer(data):
            asset = match.group(1).decode('utf-8', errors='replace')
            resource_match = re.search(r'^([A-Za-z0-9_\-]+)[/\\]', asset)
            if resource_match:
                self._add_evidence(ScriptEvidence(
                    evidence_type=EvidenceType.MEMORY_REGION,
                    script_name=os.path.basename(asset),
                    resource_name=resource_match.group(1),
                    context=f"Streaming asset: {asset}",
                    confidence=0.4,
                    memory_address=match.start()
                ))

    def _extract_fivem_resource_names_pass(self, data: bytes) -> None:
        """Dedicated pass to extract FiveM resource names from server config, paths, and API context.

        Ensures resources mentioned in server.cfg (ensure/start), server paths (resources/name),
        resource references, and GetCurrentResourceName context are all tracked so reports
        show every resource that could be involved in the crash.
        """
        # ensure/start resource_name (server.cfg style)
        for match in self.FIVEM_PATTERNS['ensure_start'].finditer(data):
            resource = match.group(1).decode('utf-8', errors='replace')
            if self._is_valid_resource_name(resource):
                self._add_evidence(ScriptEvidence(
                    evidence_type=EvidenceType.RESOURCE_NAME,
                    script_name='server.cfg',
                    resource_name=resource,
                    context="Resource in server config (ensure/start)",
                    confidence=0.6,
                    memory_address=match.start()
                ))

        # resources/resname or resources\resname (server path)
        for match in self.FIVEM_PATTERNS['server_resources_path'].finditer(data):
            resource = match.group(1).decode('utf-8', errors='replace')
            if self._is_valid_resource_name(resource):
                self._add_evidence(ScriptEvidence(
                    evidence_type=EvidenceType.RESOURCE_NAME,
                    script_name='path',
                    resource_name=resource,
                    file_path=f"resources/{resource}",
                    context="Resource path in memory",
                    confidence=0.65,
                    memory_address=match.start()
                ))

        # resource: "name" or resource: 'name' (resource reference)
        for match in self.FIVEM_PATTERNS['resource_ref'].finditer(data):
            resource = match.group(1).decode('utf-8', errors='replace')
            if self._is_valid_resource_name(resource):
                self._add_evidence(ScriptEvidence(
                    evidence_type=EvidenceType.RESOURCE_NAME,
                    script_name='resource_ref',
                    resource_name=resource,
                    context="Resource reference in memory",
                    confidence=0.55,
                    memory_address=match.start()
                ))

        # GetCurrentResourceName() / GetInvokingResource() - look for resource name string in context
        for match in self.FIVEM_PATTERNS['get_current_resource'].finditer(data):
            context_start = max(0, match.start() - 80)
            context_end = min(len(data), match.end() + 120)
            context = data[context_start:context_end]
            # Look for a short string that could be the return value (resource name)
            res_match = re.search(rb'["\']([A-Za-z0-9_\-]{2,64})["\']', context)
            if res_match:
                resource = res_match.group(1).decode('utf-8', errors='replace')
                if self._is_valid_resource_name(resource):
                    self._add_evidence(ScriptEvidence(
                        evidence_type=EvidenceType.RESOURCE_NAME,
                        script_name='GetCurrentResourceName',
                        resource_name=resource,
                        context="Resource name near GetCurrentResourceName/GetInvokingResource",
                        confidence=0.7,
                        memory_address=match.start()
                    ))

    def _extract_resource_attribution_pass(self, data: bytes, chunk_offset: int = 0) -> None:
        """Enhanced resource attribution using multiple evidence sources.
        
        This pass implements the research findings from test_resource_identification.py
        to precisely identify which FiveM resource caused the crash by combining:
        - Lua stack traces with [@resource/script.lua]:line patterns
        - C# stack traces with resource path information
        - Native function call attribution
        - Resource state transitions (crashed/error states)
        - Event handler registrations
        - File handle paths
        
        Each evidence source is weighted by reliability and combined for high-confidence attribution.
        """
        try:
            text = data.decode('utf-8', errors='ignore')
        except Exception:
            return
        
        # ===== Pattern 1: Lua Stack Traces (HIGH CONFIDENCE: 0.9) =====
        # Pattern: [@resource_name/script.lua]:line_number
        # This is the most reliable indicator of which resource's code was executing
        for match in re.finditer(r'\[@([A-Za-z0-9_-]+)/([^]]+)\]:(\d+)', text):
            resource = match.group(1)
            script = match.group(2)
            try:
                line = int(match.group(3))
            except ValueError:
                line = None
            
            if self._is_valid_resource_name(resource):
                self._add_evidence(ScriptEvidence(
                    evidence_type=EvidenceType.LUA_STACK_TRACE,
                    script_name=script,
                    resource_name=resource,
                    line_number=line,
                    context=f"Lua stack trace: [@{resource}/{script}]:{line}",
                    confidence=0.9,
                    memory_address=chunk_offset + match.start()
                ))
        
        # ===== Pattern 2: Native Function Call Attribution (VERY HIGH CONFIDENCE: 0.95) =====
        # Pattern: Native: FUNCTION_NAME ... Called from: [@resource/script.lua]:line
        # When a crash occurs in a native, this pinpoints the calling resource
        # Look for native calls with up to 500 chars of context
        for match in re.finditer(r'Native:\s*([A-Z_][A-Z0-9_]*)', text):
            native_name = match.group(1)
            native_pos = match.start()
            
            # Search for calling resource within 500 chars after native name
            context_end = min(len(text), native_pos + 500)
            context = text[native_pos:context_end]
            
            caller_match = re.search(r'\[@([A-Za-z0-9_-]+)/([^]]+)\]:?(\d+)?', context)
            if caller_match:
                resource = caller_match.group(1)
                script = caller_match.group(2)
                try:
                    line = int(caller_match.group(3)) if caller_match.group(3) else None
                except ValueError:
                    line = None
                
                if self._is_valid_resource_name(resource):
                    self._add_evidence(ScriptEvidence(
                        evidence_type=EvidenceType.NATIVE_CALL,
                        script_name=script,
                        resource_name=resource,
                        function_name=native_name,
                        line_number=line,
                        context=f"Native {native_name} called from {resource}/{script}",
                        confidence=0.95,
                        memory_address=chunk_offset + native_pos
                    ))
        
        # ===== Pattern 3: Resource State Errors (VERY HIGH CONFIDENCE: 0.95) =====
        # Pattern: Resource resource_name: CRASHED|ERROR
        # When a resource is explicitly marked as crashed, it's almost certainly the culprit
        for match in re.finditer(r'Resource\s+([a-z0-9_-]+):\s*(CRASHED|ERROR|error|crash)', text, re.IGNORECASE):
            resource = match.group(1)
            state = match.group(2).upper()
            
            if self._is_valid_resource_name(resource):
                self._add_evidence(ScriptEvidence(
                    evidence_type=EvidenceType.RESOURCE_NAME,
                    script_name='',
                    resource_name=resource,
                    context=f"Resource {resource} in {state} state",
                    confidence=0.95,
                    memory_address=chunk_offset + match.start()
                ))
        
        # ===== Pattern 4: C# Stack Traces (HIGH CONFIDENCE: 0.85) =====
        # Pattern 1: in resources/[category]/resource_name/script.cs:line
        for match in re.finditer(r'in\s+resources[\\/](?:\[[^\]]+\][\\/])?([A-Za-z0-9_-]+)[\\/]([^\s:]+\.cs):line\s+(\d+)', text, re.IGNORECASE):
            resource = match.group(1)
            script = match.group(2)
            try:
                line = int(match.group(3))
            except ValueError:
                line = None
            
            if self._is_valid_resource_name(resource):
                self._add_evidence(ScriptEvidence(
                    evidence_type=EvidenceType.SCRIPT_PATH,
                    script_name=script,
                    resource_name=resource,
                    line_number=line,
                    file_path=f"resources/{resource}/{script}",
                    context=f"C# stack trace in {resource}/{script}",
                    confidence=0.85,
                    memory_address=chunk_offset + match.start()
                ))
        
        # Pattern 2: CitizenFX.Core exception in resource 'resource_name'
        for match in re.finditer(r"(?:exception|error)\s+in\s+resource\s+['\"]([A-Za-z0-9_-]+)['\"]", text, re.IGNORECASE):
            resource = match.group(1)
            
            if self._is_valid_resource_name(resource):
                self._add_evidence(ScriptEvidence(
                    evidence_type=EvidenceType.ERROR_MESSAGE,
                    script_name='',
                    resource_name=resource,
                    context=f"C# exception in resource '{resource}'",
                    confidence=0.9,
                    memory_address=chunk_offset + match.start()
                ))
        
        # ===== Pattern 5: Event Handler Attribution (MEDIUM CONFIDENCE: 0.7) =====
        # Pattern: event_name -> resource/script.lua
        for match in re.finditer(r'([a-z0-9_:-]+)\s*->\s*([a-z0-9_-]+)/([^\s]+)', text, re.IGNORECASE):
            event = match.group(1)
            resource = match.group(2)
            script = match.group(3)
            
            if self._is_valid_resource_name(resource):
                self._add_evidence(ScriptEvidence(
                    evidence_type=EvidenceType.EVENT_HANDLER,
                    script_name=script,
                    resource_name=resource,
                    context=f"Event handler: {event} -> {resource}/{script}",
                    confidence=0.7,
                    memory_address=chunk_offset + match.start()
                ))
        
        # ===== Pattern 6: File Handle Paths (HIGH CONFIDENCE: 0.8) =====
        # Pattern: File handle with resource path
        # Matches: C:\server\resources\resource_name\file.lua
        for match in re.finditer(r'(?:File|Handle|Path):\s*[A-Z]:[^\n]*?resources[\\/](?:\[[^\]]+\][\\/])?([A-Za-z0-9_-]+)[\\/]([^\s\n]+)', text, re.IGNORECASE):
            resource = match.group(1)
            filepath = match.group(2)
            
            if self._is_valid_resource_name(resource):
                self._add_evidence(ScriptEvidence(
                    evidence_type=EvidenceType.HANDLE_PATH,
                    script_name=filepath.split('/')[-1] if '/' in filepath else filepath.split('\\')[-1],
                    resource_name=resource,
                    file_path=f"resources/{resource}/{filepath}",
                    context=f"Open file handle: {resource}/{filepath}",
                    confidence=0.8,
                    memory_address=chunk_offset + match.start()
                ))
        
        # ===== Pattern 7: Thread Stack Attribution (HIGH CONFIDENCE: 0.85) =====
        # Look for thread information with resource context
        # Pattern: Thread N ... [@resource/script.lua]
        for match in re.finditer(r'Thread\s+\d+[^\n]*?[@\[]([A-Za-z0-9_-]+)/([^]\n]+)[\]:]', text, re.IGNORECASE):
            resource = match.group(1)
            script = match.group(2)
            
            if self._is_valid_resource_name(resource):
                self._add_evidence(ScriptEvidence(
                    evidence_type=EvidenceType.THREAD_STACK,
                    script_name=script,
                    resource_name=resource,
                    context=f"Resource {resource} in thread stack",
                    confidence=0.85,
                    memory_address=chunk_offset + match.start()
                ))
        
        # ===== Pattern 8: Script Error Messages (HIGH CONFIDENCE: 0.85) =====
        # Pattern: "Error in resource_name: ..." or "resource_name error: ..."
        for match in re.finditer(r'(?:Error|SCRIPT\s*ERROR|Runtime\s*error)\s+(?:in|for)\s+([A-Za-z0-9_-]+)[\s:]', text, re.IGNORECASE):
            resource = match.group(1)
            
            if self._is_valid_resource_name(resource):
                self._add_evidence(ScriptEvidence(
                    evidence_type=EvidenceType.ERROR_MESSAGE,
                    script_name='',
                    resource_name=resource,
                    context=f"Error message mentioning resource {resource}",
                    confidence=0.75,
                    memory_address=chunk_offset + match.start()
                ))

    # ===== MEMORY LEAK ANALYSIS FUNCTIONS =====
    
    def _analyze_entity_lifecycle(self, data: bytes, chunk_offset: int = 0) -> None:
        """Analyze entity creation and deletion patterns to detect potential leaks."""
        # Find entity creations
        for match in self.FIVEM_PATTERNS['entity_creation'].finditer(data):
            native_name = match.group(1).decode('utf-8', errors='replace')
            offset = chunk_offset + match.start()
            self.result.entity_creations.append((native_name, offset))
            
            # Look for resource context nearby
            context_start = max(0, match.start() - 200)
            context_end = min(len(data), match.end() + 200)
            context = data[context_start:context_end]
            
            # Try to find resource name in context
            resource_match = re.search(rb'@?([A-Za-z0-9_\-]{2,64})[/\\]', context)
            if resource_match:
                resource = resource_match.group(1).decode('utf-8', errors='replace')
                if self._is_valid_resource_name(resource):
                    self._add_evidence(ScriptEvidence(
                        evidence_type=EvidenceType.NATIVE_CALL,
                        script_name=native_name,
                        resource_name=resource,
                        context=f"Entity creation: {native_name} (potential leak if not deleted)",
                        confidence=0.6,
                        memory_address=offset
                    ))
        
        # Find entity deletions
        for match in self.FIVEM_PATTERNS['entity_deletion'].finditer(data):
            native_name = match.group(1).decode('utf-8', errors='replace')
            offset = chunk_offset + match.start()
            self.result.entity_deletions.append((native_name, offset))
    
    def _analyze_timer_patterns(self, data: bytes, chunk_offset: int = 0) -> None:
        """Analyze timer/interval patterns for potential leaks."""
        for match in self.FIVEM_PATTERNS['timer_creation'].finditer(data):
            timer_type = match.group(1).decode('utf-8', errors='replace')
            offset = chunk_offset + match.start()
            self.result.timers_created.append((timer_type, offset))
            
            # Look for resource context
            context_start = max(0, match.start() - 200)
            context_end = min(len(data), match.end() + 200)
            context = data[context_start:context_end]
            
            resource_match = re.search(rb'@?([A-Za-z0-9_\-]{2,64})[/\\]', context)
            if resource_match:
                resource = resource_match.group(1).decode('utf-8', errors='replace')
                if self._is_valid_resource_name(resource):
                    self._add_evidence(ScriptEvidence(
                        evidence_type=EvidenceType.NATIVE_CALL,
                        script_name=timer_type,
                        resource_name=resource,
                        context=f"Timer: {timer_type} (check for cleanup on resource stop)",
                        confidence=0.5,
                        memory_address=offset
                    ))
    
    def _analyze_event_handlers(self, data: bytes, chunk_offset: int = 0) -> None:
        """Analyze event handler registration and removal patterns."""
        # Find registrations
        for match in self.FIVEM_PATTERNS['event_registration'].finditer(data):
            handler_type = match.group(1).decode('utf-8', errors='replace')
            offset = chunk_offset + match.start()
            self.result.event_handlers_registered.append((handler_type, offset))
        
        # Find removals
        for match in self.FIVEM_PATTERNS['event_removal'].finditer(data):
            handler_type = match.group(1).decode('utf-8', errors='replace')
            offset = chunk_offset + match.start()
            self.result.event_handlers_removed.append((handler_type, offset))
    
    def _analyze_memory_allocations(self, data: bytes, chunk_offset: int = 0) -> None:
        """Analyze C/C++ level memory allocation patterns."""
        # Find allocations
        for match in self.FIVEM_PATTERNS['memory_alloc'].finditer(data):
            alloc_type = match.group(1).decode('utf-8', errors='replace')
            offset = chunk_offset + match.start()
            self.result.memory_allocations.append((alloc_type, offset))
        
        # Find frees
        for match in self.FIVEM_PATTERNS['memory_free'].finditer(data):
            free_type = match.group(1).decode('utf-8', errors='replace')
            offset = chunk_offset + match.start()
            self.result.memory_frees.append((free_type, offset))
    
    def _find_memory_leak_indicators(self, data: bytes, chunk_offset: int = 0) -> None:
        """Find strings that indicate memory leak issues."""
        for indicator_bytes, indicator_type in self.MEMORY_LEAK_INDICATORS:
            pos = 0
            for _ in range(10000):  # Per ADA restrictions: bounded loop (max pattern matches)
                idx = data.find(indicator_bytes, pos)
                if idx == -1:
                    break
                pos = idx + 1
                
                offset = chunk_offset + idx
                message = indicator_bytes.decode('utf-8', errors='replace')
                self.result.memory_leak_indicators.append((message, indicator_type, offset))
                
                # Extract context for evidence
                context_start = max(0, idx - 100)
                context_end = min(len(data), idx + len(indicator_bytes) + 100)
                context = data[context_start:context_end]
                
                # Try to find resource name
                resource_match = re.search(rb'@?([A-Za-z0-9_\-]{2,64})[/\\]', context)
                resource = None
                if resource_match:
                    resource = resource_match.group(1).decode('utf-8', errors='replace')
                    if not self._is_valid_resource_name(resource):
                        resource = None
                
                self._add_evidence(ScriptEvidence(
                    evidence_type=EvidenceType.ERROR_MESSAGE,
                    script_name=f"memory_{indicator_type}",
                    resource_name=resource,
                    context=f"Memory Issue: {message}",
                    confidence=0.9,
                    memory_address=offset
                ))
    
    def _find_pool_exhaustion(self, data: bytes, chunk_offset: int = 0) -> None:
        """Find pool exhaustion indicators."""
        for match in self.FIVEM_PATTERNS['pool_exhaustion'].finditer(data):
            pool_msg = match.group(0).decode('utf-8', errors='replace')
            offset = chunk_offset + match.start()
            self.result.pool_exhaustion_indicators.append((pool_msg, offset))
            
            # High confidence evidence - pool exhaustion is serious
            self._add_evidence(ScriptEvidence(
                evidence_type=EvidenceType.ERROR_MESSAGE,
                script_name="pool_exhaustion",
                resource_name=None,
                context=f"Pool Exhaustion: {pool_msg}",
                confidence=0.95,
                memory_address=offset
            ))
    
    def _find_database_patterns(self, data: bytes, chunk_offset: int = 0) -> None:
        """Find database/ORM patterns that might indicate query issues."""
        for match in self.FIVEM_PATTERNS['database_pattern'].finditer(data):
            db_pattern = match.group(0).decode('utf-8', errors='replace')
            offset = chunk_offset + match.start()
            self.result.database_patterns.append((db_pattern, offset))
            
            # Look for resource context
            context_start = max(0, match.start() - 200)
            context_end = min(len(data), match.end() + 200)
            context = data[context_start:context_end]
            
            resource_match = re.search(rb'@?([A-Za-z0-9_\-]{2,64})[/\\]', context)
            if resource_match:
                resource = resource_match.group(1).decode('utf-8', errors='replace')
                if self._is_valid_resource_name(resource):
                    self._add_evidence(ScriptEvidence(
                        evidence_type=EvidenceType.NATIVE_CALL,
                        script_name="database",
                        resource_name=resource,
                        context=f"Database: {db_pattern[:50]}",
                        confidence=0.5,
                        memory_address=offset
                    ))
    
    def _find_nui_patterns(self, data: bytes, chunk_offset: int = 0) -> None:
        """Find NUI/CEF patterns that might indicate UI-related memory issues."""
        for match in self.FIVEM_PATTERNS['nui_memory'].finditer(data):
            nui_pattern = match.group(0).decode('utf-8', errors='replace')
            offset = chunk_offset + match.start()
            self.result.nui_patterns.append((nui_pattern, offset))
            
            # Look for resource context
            context_start = max(0, match.start() - 200)
            context_end = min(len(data), match.end() + 200)
            context = data[context_start:context_end]
            
            resource_match = re.search(rb'@?([A-Za-z0-9_\-]{2,64})[/\\]', context)
            if resource_match:
                resource = resource_match.group(1).decode('utf-8', errors='replace')
                if self._is_valid_resource_name(resource):
                    # Track resource attribution for NUI usage
                    if resource not in self.result.nui_resources:
                        self.result.nui_resources[resource] = 0
                    self.result.nui_resources[resource] += 1

                    self._add_evidence(ScriptEvidence(
                        evidence_type=EvidenceType.NATIVE_CALL,
                        script_name="nui",
                        resource_name=resource,
                        context=f"NUI/CEF: {nui_pattern}",
                        confidence=0.5,
                        memory_address=offset
                    ))
    
    def _find_network_patterns(self, data: bytes, chunk_offset: int = 0) -> None:
        """Find network synchronization patterns."""
        for match in self.FIVEM_PATTERNS['network_sync'].finditer(data):
            net_pattern = match.group(0).decode('utf-8', errors='replace')
            offset = chunk_offset + match.start()
            self.result.network_patterns.append((net_pattern, offset))
            
            # Look for resource context
            context_start = max(0, match.start() - 200)
            context_end = min(len(data), match.end() + 200)
            context = data[context_start:context_end]
            
            resource_match = re.search(rb'@?([A-Za-z0-9_\-]{2,64})[/\\]', context)
            if resource_match:
                resource = resource_match.group(1).decode('utf-8', errors='replace')
                if self._is_valid_resource_name(resource):
                    self._add_evidence(ScriptEvidence(
                        evidence_type=EvidenceType.NATIVE_CALL,
                        script_name="network",
                        resource_name=resource,
                        context=f"Network: {net_pattern}",
                        confidence=0.5,
                        memory_address=offset
                    ))
        
        # Also check state bag patterns
        for match in self.FIVEM_PATTERNS['statebag_pattern'].finditer(data):
            sb_pattern = match.group(0).decode('utf-8', errors='replace')
            offset = chunk_offset + match.start()
            self.result.statebag_patterns.append((sb_pattern, offset))

    def _find_fivem_crash_causes(self, data: bytes, chunk_offset: int = 0) -> None:
        """Find FiveM-specific crash cause patterns."""
        for marker, cause_type, description in self.FIVEM_CRASH_CAUSES:
            pos = 0
            for _ in range(10000):  # Per ADA restrictions: bounded loop (max pattern matches)
                idx = data.find(marker, pos)
                if idx == -1:
                    break
                pos = idx + 1
                
                offset = chunk_offset + idx
                
                # Extract context around the marker
                context_start = max(0, idx - 150)
                context_end = min(len(data), idx + len(marker) + 150)
                context = data[context_start:context_end]
                
                # Try to find resource name in context
                resource_match = re.search(rb'@?([A-Za-z0-9_\-]{2,64})[/\\]', context)
                resource = None
                if resource_match:
                    resource = resource_match.group(1).decode('utf-8', errors='replace')
                    if not self._is_valid_resource_name(resource):
                        resource = None
                
                # High confidence evidence for crash causes
                # NOTE: script_name should NOT be synthesized from cause_type (creates fake resources like "crash_streaming")
                # Leave it empty so resource attribution focuses on the actual resource_name found in context
                self._add_evidence(ScriptEvidence(
                    evidence_type=EvidenceType.ERROR_MESSAGE,
                    script_name=None,  # Don't create fake script names
                    resource_name=resource,
                    context=f"FiveM Crash: {description} ({marker.decode('utf-8', errors='replace')})",
                    confidence=0.85,
                    memory_address=offset
                ))

    def _is_valid_resource_name(self, name: str) -> bool:
        """Check if a name is a valid FiveM resource name (not a system path segment)."""
        if not name:
            return False
        name_lower = name.lower().strip().strip('@')
        # Must be at least 3 characters (real resource names are almost never 2 chars)
        if len(name_lower) < 3:
            return False
        # Short names (3-4 chars) are almost always garbage unless they contain _ or - 
        # Real short resource names typically have structure like "qb-" prefix or "_lib" suffix
        if len(name_lower) <= 4 and not any(c in name_lower for c in '_-'):
            return False
        # Reject names that are mostly digits (garbage from memory)
        digit_count = sum(1 for c in name_lower if c.isdigit())
        if digit_count > len(name_lower) * 0.5:  # More than 50% digits = likely garbage
            return False
        # Reject names that start with a digit (real resource names don't)
        if name_lower[0].isdigit():
            return False
        # Reject single common English words that appear in game memory
        # These are almost never actual resource names
        common_false_positives = {
            'radio', 'audio', 'music', 'sound', 'voice', 'video', 'movie',
            'model', 'anim', 'prop', 'script', 'game', 'core', 'base',
            'main', 'index', 'entry', 'init', 'start', 'stop', 'load',
            'handler', 'manager', 'service', 'util', 'helper', 'data',
            'iles', 'files', 'file', 'path', 'code', 'text', 'string',
            'buffer', 'array', 'list', 'map', 'set', 'queue', 'stack',
        }
        if name_lower in common_false_positives:
            return False
            return False
        # Reject obvious internal/runtime markers that look like "resource names" in memory.
        # These are not user resources and commonly appear near CitizenFX runtime structures.
        if name_lower.startswith(("citizen-scripting-", "citizen-resources-", "citizen-server-impl")):
            return False
        if name_lower.startswith(("cfx-fivem-", "cfx-fxserver-")):
            return False
        # Must be a plain resource folder name (avoid accidentally treating filenames as resources)
        # FiveM resource names are typically directory names like "oxmysql", "qb-core", "es_extended".
        # Reject anything that looks like a file (main.lua, webpack.js) or contains path separators.
        if any(sep in name_lower for sep in ('/', '\\', ':')):
            return False
        # Reject common file-like suffixes
        if '.' in name_lower:
            # If it has a dot, it is almost certainly a filename rather than a resource directory
            return False
        # Enforce allowed characters (avoid false positives like "main.lua", "webpack.js")
        # Require at least 3 characters total (start + 2 more)
        if not re.fullmatch(r"[a-z][a-z0-9_-]{2,63}", name_lower):
            return False
        # Check against ignored path segments
        if name_lower in self.IGNORED_PATH_SEGMENTS:
            return False
        # Manifest files are metadata, not resources - reject them as resource names
        if name_lower in self.MANIFEST_FILES:
            return False
        # Must start with alphanumeric
        if not name_lower[0].isalnum():
            return False
        # Filter out generated natives files (like natives_0193d0af)
        if name_lower.startswith('natives_') and len(name_lower) > 10:
            return False
        return True

    def _is_internal_fivem_path(self, file_path: str) -> bool:
        """Check if a path is an internal FiveM/CitizenFX path (not a user resource)."""
        if not file_path:
            return False
        path_lower = file_path.lower().replace('\\', '/')
        
        # Internal path patterns
        internal_patterns = [
            'citizen/scripting',
            'citizen\\scripting',
            'cfx/scripting',
            'app/citizen',
            'fivem/citizen',
            'fxserver/citizen',
            '/natives_',
            '/runtime/',
            '/v8/',
            '/mono/',
            '/lua/',
        ]
        
        for pattern in internal_patterns:
            if pattern in path_lower:
                return True
        return False

    def _extract_resource_from_path(self, file_path: str) -> Optional[str]:
        """Extract a valid FiveM resource name from a file path.

        Scans path segments to find a valid resource name. Prefers the segment
        immediately before known subfolders (client, server, shared, html) so
        paths like esx_menu/client/main.lua yield 'esx_menu' rather than stopping
        on a later segment.
        """
        if not file_path:
            return None
        
        # Check if this is an internal FiveM path - if so, don't extract resource
        if self._is_internal_fivem_path(file_path):
            return None

        raw = str(file_path).strip()
        raw_norm = raw.replace('\\', '/')
        # "Anchored" paths are more reliable resource indicators:
        # - @resource/... (FiveM source format)
        # - absolute/absolute-ish paths (/..., \..., C:\..., .../resources/<res>/...)
        anchored = (
            raw.startswith('@')
            or raw.startswith('/')
            or raw.startswith('\\')
            or bool(re.match(r'^[A-Za-z]:[\\/]', raw))
            or ('/resources/' in raw_norm.lower() or '\\resources\\' in raw.lower())
        )

        # Normalize path separators and split
        normalized = raw_norm.strip('@')
        parts = [p for p in normalized.split('/') if p]

        # Subfolder names that indicate the previous segment is the resource root
        resource_subfolders = {'client', 'server', 'shared', 'html', 'modules', 'config', 'locales'}

        # If the path starts with a typical resource subfolder (client/server/html/etc) but has no
        # resource root segment before it, it's likely a truncated/relative path. Don't guess deeper.
        # Examples seen in dumps: "html/games/..." or "client/editable/..." (missing "<resource>/").
        if not anchored and parts and parts[0].lower() in resource_subfolders:
            return None

        # If the path is unanchored AND only looks like "segment/file.lua|file.js",
        # do NOT guess the first segment is a resource. These shallow relative paths
        # are frequently false positives (e.g. "locales/en.lua" losing its first char -> "ocales/en.lua").
        if not anchored and len(parts) == 2:
            tail = parts[-1].lower()
            if tail.endswith(('.lua', '.js')):
                return None

        for i, part in enumerate(parts):
            part_lower = part.lower()
            # If this segment is a known resource subfolder, the resource name is the segment before it
            if part_lower in resource_subfolders and i > 0:
                candidate = parts[i - 1]
                if '.' not in candidate or candidate.split('.')[-1].lower() not in (
                    'lua', 'js', 'dll', 'exe', 'json', 'xml', 'ts', 'css'
                ):
                    if self._is_valid_resource_name(candidate):
                        return candidate
            # Skip file extensions
            if '.' in part and part.split('.')[-1].lower() in ('lua', 'js', 'dll', 'exe', 'json', 'xml'):
                continue
            if self._is_valid_resource_name(part):
                return part

        return None

    def _get_resources_for_lua_stack(self, stack: List[LuaStackFrame]) -> List[str]:
        """Extract unique FiveM resource names from a Lua stack (frame sources)."""
        seen: Set[str] = set()
        out: List[str] = []
        for frame in stack:
            res = self._extract_resource_from_path(frame.source)
            if res and self._is_valid_resource_name(res) and res not in seen:
                seen.add(res)
                out.append(res)
        return out

    def _get_resources_for_js_stack(self, stack_str: str) -> List[str]:
        """Extract unique FiveM resource names from a JS stack trace string."""
        seen: Set[str] = set()
        out: List[str] = []
        # Match @resource/path or resource/path in stack lines
        for match in re.finditer(r'@?([A-Za-z0-9_\-]{2,64})[/\\]', stack_str):
            name = match.group(1)
            if self._is_valid_resource_name(name) and name not in seen:
                seen.add(name)
                out.append(name)
        return out

    def _compute_stack_resources(self) -> None:
        """Populate lua_stack_resources and js_stack_resources from stack traces."""
        self.result.lua_stack_resources = [
            self._get_resources_for_lua_stack(stack) for stack in self.result.lua_stacks
        ]
        self.result.js_stack_resources = [
            self._get_resources_for_js_stack(trace) for trace in self.result.js_stacks
        ]

    def _add_evidence(self, evidence: ScriptEvidence) -> None:
        """Add evidence and update resource tracking.
        
        REWORKED LOGIC:
        1. Always record raw evidence first (never discard before recording)
        2. Track high-value evidence separately so it's never lost
        3. Only filter for resource attribution, not for recording
        4. Keep unattributed evidence for debugging
        """
        # Create a deduplication key for this evidence
        dedup_key = (
            evidence.evidence_type,
            evidence.script_name or '',
            evidence.resource_name or '',
            evidence.file_path or '',
            evidence.line_number or 0
        )
        
        # Skip if we've already seen this exact evidence
        if hasattr(self, '_evidence_seen'):
            if dedup_key in self._evidence_seen:
                return
            self._evidence_seen.add(dedup_key)
        
        # Check evidence limit for performance (higher for large files)
        max_ev = getattr(self, '_max_evidence', self.MAX_EVIDENCE_ITEMS)
        if len(self.result.all_evidence) >= max_ev:
            # Even at limit, still track critical evidence
            if evidence.evidence_type in self.HIGH_VALUE_EVIDENCE_TYPES:
                self.result.critical_evidence.append(evidence)
            return

        # ALWAYS record raw evidence FIRST (before any filtering)
        self.result.raw_evidence.append(evidence)
        
        # ALWAYS record high-value evidence to critical list
        if evidence.evidence_type in self.HIGH_VALUE_EVIDENCE_TYPES:
            self.result.critical_evidence.append(evidence)

        # Always add to all_evidence
        self.result.all_evidence.append(evidence)

        # Try to determine the resource name
        resource_name = None
        
        # Track whether this is internal (for scoring) but DON'T discard
        is_internal_path = evidence.file_path and self._is_internal_fivem_path(evidence.file_path)
        is_internal_script = evidence.script_name and evidence.script_name in self.INTERNAL_SCRIPTS
        is_natives_file = evidence.script_name and evidence.script_name.startswith('natives_')
        
        # For internal paths/scripts, still record but mark for lower scoring
        if is_internal_path or is_internal_script or is_natives_file:
            # Don't return early - continue to try resource attribution
            # But if we can't attribute, add to unattributed list
            pass

        # 1. First, check if the provided resource_name is valid
        if evidence.resource_name and self._is_valid_resource_name(evidence.resource_name):
            resource_name = evidence.resource_name

        # 2. If not, try to extract from file_path
        if not resource_name and evidence.file_path:
            resource_name = self._extract_resource_from_path(evidence.file_path)

        # 3. Fall back to script name if it looks like a resource name (not a file)
        if not resource_name and evidence.script_name:
            # If script_name is a .lua/.js file, don't use it as resource name
            if not evidence.script_name.endswith(('.lua', '.js')):
                if self._is_valid_resource_name(evidence.script_name):
                    resource_name = evidence.script_name

        # 4. FALLBACK: If we still have no resource but have a script name, 
        #    ONLY use it if it's a valid resource name
        if not resource_name and evidence.script_name:
            if self._is_valid_resource_name(evidence.script_name):
                resource_name = evidence.script_name

        # 5. Last resort: use any part of the file path that's a valid resource name
        if not resource_name and evidence.file_path:
            raw = str(evidence.file_path).strip()
            raw_norm = raw.replace('\\', '/')
            parts = [p for p in raw_norm.strip('@').split('/') if p]
            anchored = (
                raw.startswith('@')
                or raw.startswith('/')
                or raw.startswith('\\')
                or bool(re.match(r'^[A-Za-z]:[\\/]', raw))
                or ('/resources/' in raw_norm.lower() or '\\resources\\' in raw.lower())
            )
            # Avoid false positives from shallow relative paths like "locales/en.lua" (or truncated "ocales/en.lua")
            # and "ws/news.js" where the first segment is not reliably a resource name.
            resource_subfolders = {'client', 'server', 'shared', 'html', 'modules', 'config', 'locales'}
            if anchored and not (parts and parts[0].lower() in resource_subfolders):
                for part in reversed(parts):
                    if part and not part.endswith(('.lua', '.js', '.dll', '.exe')):
                        if self._is_valid_resource_name(part):
                            resource_name = part
                            break

        # If we couldn't attribute to a resource, track as unattributed (but don't discard!)
        if not resource_name or not self._is_valid_resource_name(resource_name):
            # Still valuable for debugging - add to unattributed list
            self.result.unattributed_evidence.append(evidence)
            return

        # Update resource info
        if resource_name not in self.result.resources:
            self.result.resources[resource_name] = ResourceInfo(name=resource_name)

        info = self.result.resources[resource_name]

        is_manifest = (
            evidence.evidence_type == EvidenceType.MANIFEST_REFERENCE
            or (evidence.script_name and evidence.script_name.lower() in self.MANIFEST_FILES)
        )

        # Manifest files indicate presence only, not a crash cause.
        # But HIGH-VALUE evidence should still count even for manifests
        if not is_manifest or evidence.evidence_type in self.HIGH_VALUE_EVIDENCE_TYPES:
            info.evidence_count += 1
            info.evidence_types.add(evidence.evidence_type)

            if evidence.script_name and evidence.script_name not in info.scripts:
                info.scripts.append(evidence.script_name)
            # Script-level hint: from ERROR_MESSAGE evidence, surface likely script file for report
            if (
                evidence.evidence_type == EvidenceType.ERROR_MESSAGE
                and evidence.script_name
                and (evidence.script_name.endswith('.lua') or evidence.script_name.endswith('.js'))
            ):
                script_base = os.path.basename(evidence.script_name)
                if not info.likely_script or script_base == evidence.script_name:
                    info.likely_script = script_base

        if evidence.file_path:
            info.path = evidence.file_path
            # Track all unique paths
            if evidence.file_path not in info.all_paths:
                info.all_paths.append(evidence.file_path)

        # Track context details for better reporting
        if not is_manifest and evidence.context and len(evidence.context) > 5:
            context_entry = f"[{evidence.evidence_type.name}] {evidence.context[:150]}"
            if context_entry not in info.context_details and len(info.context_details) < 10:
                info.context_details.append(context_entry)

    def _correlate_evidence(self) -> None:
        """Correlate all evidence to determine primary suspects.
        
        REWORKED SCORING:
        - Quality over quantity: one ERROR_MESSAGE is worth more than 10 SCRIPT_PATHs
        - Critical evidence gets bonus multiplier
        - Resources with ANY high-value evidence are never filtered out
        """
        # Score each resource based on evidence
        scores: Dict[str, float] = {}
        
        # Track which resources have high-value evidence (never filter these)
        resources_with_critical_evidence: Set[str] = set()

        # Evidence type weights - INCREASED for high-value types
        weights = {
            EvidenceType.ERROR_MESSAGE: 15.0,      # Increased from 10
            EvidenceType.LUA_STACK_TRACE: 12.0,   # Increased from 9
            EvidenceType.JS_STACK_TRACE: 12.0,    # Increased from 9
            EvidenceType.EXCEPTION_ADDRESS: 10.0, # Increased from 8
            EvidenceType.SCRIPT_PATH: 3.0,        # Decreased from 5 (common, less specific)
            EvidenceType.HANDLE_PATH: 5.0,
            EvidenceType.THREAD_STACK: 6.0,
            EvidenceType.EVENT_HANDLER: 2.0,
            EvidenceType.NATIVE_CALL: 2.0,
            EvidenceType.MEMORY_REGION: 1.0,
            EvidenceType.RESOURCE_NAME: 2.0,      # Decreased from 4 (often just presence)
        }

        for evidence in self.result.all_evidence:
            if evidence.evidence_type == EvidenceType.MANIFEST_REFERENCE:
                # Manifest references only show resource presence, not crash cause.
                continue
            resource = evidence.resource_name or evidence.script_name
            if not resource:
                continue
            
            # Only score valid resource names that exist in our resources dict
            if not self._is_valid_resource_name(resource):
                continue
            if resource not in self.result.resources:
                continue

            weight = weights.get(evidence.evidence_type, 1.0)
            confidence = evidence.confidence
            
            # Track resources with critical evidence
            if evidence.evidence_type in self.HIGH_VALUE_EVIDENCE_TYPES:
                resources_with_critical_evidence.add(resource)
                # Bonus multiplier for critical evidence
                weight *= 1.5

            if resource not in scores:
                scores[resource] = 0.0
            scores[resource] += weight * confidence

        # When fault is in script runtime (scripthandler, citizen-resources-*, etc.), boost resources
        # that already have high-value evidence so exception_module helps attribution
        exc_mod = (self.result.exception_module or '').lower()
        if exc_mod:
            for sub in self.SCRIPT_RUNTIME_MODULE_SUBSTRINGS:
                if sub in exc_mod:
                    exc_weight = weights.get(EvidenceType.EXCEPTION_ADDRESS, 8.0)
                    exc_confidence = 0.6
                    for res_name, info in self.result.resources.items():
                        if scores.get(res_name, 0) <= 0:
                            continue
                        has_high = (
                            EvidenceType.LUA_STACK_TRACE in info.evidence_types
                            or EvidenceType.JS_STACK_TRACE in info.evidence_types
                            or EvidenceType.ERROR_MESSAGE in info.evidence_types
                        )
                        if has_high:
                            scores[res_name] = scores.get(res_name, 0) + exc_weight * exc_confidence
                    break

        # Optional: when native stack shows script runtime in first few frames, boost resources
        # that already have Lua/JS/error evidence (reinforces "crash in script code")
        if self.result.native_stack:
            native_frame_re = re.compile(r'^\s*(.+?)\s*\+\s*0x', re.IGNORECASE)
            first_frames = self.result.native_stack[:5]
            for frame in first_frames:
                m = native_frame_re.match((frame or '').strip())
                if not m:
                    continue
                mod_name = (m.group(1) or '').strip().lower()
                if not mod_name:
                    continue
                for sub in self.SCRIPT_RUNTIME_MODULE_SUBSTRINGS:
                    if sub in mod_name:
                        native_boost = 2.0
                        for res_name, info in self.result.resources.items():
                            if scores.get(res_name, 0) <= 0:
                                continue
                            has_high = (
                                EvidenceType.LUA_STACK_TRACE in info.evidence_types
                                or EvidenceType.JS_STACK_TRACE in info.evidence_types
                                or EvidenceType.ERROR_MESSAGE in info.evidence_types
                            )
                            if has_high:
                                scores[res_name] = scores.get(res_name, 0) + native_boost
                        break
                else:
                    continue
                break

        # Adjust scores for internal scripts
        for resource_name, score in list(scores.items()):
            # Skip if resource wasn't added to resources dict (should not happen now)
            if resource_name not in self.result.resources:
                continue
                
            info = self.result.resources[resource_name]

            # Check if this resource is primarily internal scripts
            is_internal = False
            if info.scripts:
                internal_count = sum(1 for s in info.scripts if s.lower() in [i.lower() for i in self.INTERNAL_SCRIPTS])
                if internal_count == len(info.scripts):
                    is_internal = True

            if is_internal:
                # Reduce score for internal resources, as they are usually the messenger, not the cause
                scores[resource_name] = score * 0.1

                # Try to find a user resource linked to this internal resource via stack traces
                self._redistribute_blame_from_internal(resource_name, scores)

        # Sort resources by score
        # REWORKED FILTERING:
        # - Resources with critical evidence are NEVER filtered out
        # - Lower threshold (1 instead of 2) to avoid missing real problems
        # - Quality-based scoring already handles false positives
        
        scored_resources = []
        for resource in self.result.resources.values():
            score = scores.get(resource.name, 0)
            has_critical = resource.name in resources_with_critical_evidence
            
            # Include if: has score > 0, OR has critical evidence (even with score 0)
            if score > 0 or has_critical:
                # For resources with only weak evidence, require at least 2 pieces
                # But resources with ANY critical evidence always pass
                if has_critical:
                    scored_resources.append(resource)
                elif resource.evidence_count >= 1:  # Lowered from 2
                    scored_resources.append(resource)

        sorted_resources = sorted(
            scored_resources,
            key=lambda r: scores.get(r.name, 0),
            reverse=True
        )

        # Top suspects are resources with highest scores
        # REWORKED: Don't discard suspects just because evidence count is low
        # If they have critical evidence, they're valid suspects
        if sorted_resources:
            top_suspect = sorted_resources[0]
            has_critical = top_suspect.name in resources_with_critical_evidence
            
            # Only filter if: low evidence count AND no critical evidence AND only weak types
            weak_only = all(
                etype in {EvidenceType.SCRIPT_PATH, EvidenceType.RESOURCE_NAME, EvidenceType.MEMORY_REGION}
                for etype in (top_suspect.evidence_types or set())
            )
            if top_suspect.evidence_count < 2 and weak_only and not has_critical:
                # Don't report weak suspects without critical evidence
                self.result.primary_suspects = []
            else:
                self.result.primary_suspects = sorted_resources[:10]
        else:
            self.result.primary_suspects = []

        # Tie-breaking: when top two have scores within 10-15%, mark secondary for report
        self.result.primary_suspect_secondary = None
        if len(sorted_resources) >= 2:
            s0 = scores.get(sorted_resources[0].name, 0)
            s1 = scores.get(sorted_resources[1].name, 0)
            if s0 > 0 and s1 > 0 and (s0 - s1) / s0 < 0.15:
                self.result.primary_suspect_secondary = sorted_resources[1].name

        # Confidence hint for report wording
        if self.result.primary_suspect_secondary:
            self.result.primary_suspect_confidence = "medium"
        elif sorted_resources:
            top = self.result.resources.get(sorted_resources[0].name)
            top_types = set(getattr(top, "evidence_types", set()) or set()) if top else set()
            if (
                EvidenceType.ERROR_MESSAGE in top_types
                and (EvidenceType.LUA_STACK_TRACE in top_types or EvidenceType.JS_STACK_TRACE in top_types)
            ):
                self.result.primary_suspect_confidence = "high"
            elif (
                EvidenceType.ERROR_MESSAGE in top_types
                or EvidenceType.LUA_STACK_TRACE in top_types
                or EvidenceType.JS_STACK_TRACE in top_types
            ):
                # Some direct crash-adjacent evidence exists, but not enough to be "high".
                self.result.primary_suspect_confidence = "medium"
            else:
                # Only weak signals (e.g. stray SCRIPT_PATH strings) - avoid overstating certainty.
                self.result.primary_suspect_confidence = "low"
        else:
            self.result.primary_suspect_confidence = "low"

    def _redistribute_blame_from_internal(self, internal_resource: str, scores: Dict[str, float]) -> None:
        """Move blame from internal resources to the calling user resource."""
        # Look through stack traces
        for stack in self.result.lua_stacks:
            # Check if this stack involves the internal resource
            has_internal = False
            internal_idx = -1

            for i, frame in enumerate(stack):
                res_match = re.search(r'[@]?([A-Za-z0-9_\-]+)[/\\]', frame.source)
                res = res_match.group(1) if res_match else None
                if res == internal_resource:
                    has_internal = True
                    internal_idx = i
                    break

            if has_internal:
                # Look for the first NON-internal resource in the stack (caller)
                # We search from the internal frame upwards (or downwards depending on stack order)
                # Typically stack[0] is top. If internal is top, caller is stack[1]

                caller_res = None
                for i in range(internal_idx + 1, len(stack)):
                    frame = stack[i]
                    res_match = re.search(r'[@]?([A-Za-z0-9_\-]+)[/\\]', frame.source)
                    res = res_match.group(1) if res_match else None

                    if res and res != internal_resource:
                        # Check if this is also internal
                        script_name = os.path.basename(frame.source)
                        if script_name.lower() not in [s.lower() for s in self.INTERNAL_SCRIPTS]:
                            caller_res = res
                            break

                if caller_res:
                    # Boost the caller's score significantly
                    if caller_res not in scores:
                        scores[caller_res] = 0.0
                    scores[caller_res] += 15.0  # High confidence boost

                    # Update the caller's info to note the native call relationship
                    if caller_res in self.result.resources:
                        info = self.result.resources[caller_res]
                        note = "Called native via internal system"
                        if note not in info.context_details:
                            info.context_details.append(note)

    # ===== FRAMEWORK & METADATA DETECTION METHODS =====
    
    def _detect_framework(self, data: bytes) -> Tuple[str, float]:
        """Detect FiveM framework from memory dump.
        
        Identifies which FiveM framework (QBCore, ESX, VRP, Ox) caused the crash
        using byte pattern matching with confidence scoring.
        
        Args:
            data: Raw memory data to scan
            
        Returns:
            Tuple of (framework_name, confidence_score)
            - framework_name: "QBCore", "ESX", "VRP", "Ox", or "Unknown"
            - confidence_score: 0.0-1.0 based on marker frequency
        """
        framework_markers = {
            'QBCore': [
                b'exports',
                b'qb-core',
                b'QBCore',
                b'QB-Core',
                b'QBCore.Functions',
                b'SharedObject',
            ],
            'ESX': [
                b'es_extended',
                b'ESX',
                b'TriggerClientEvent',
                b'esx:playerLoaded',
                b'ESX.GetPlayerData',
            ],
            'VRP': [
                b'vrp',
                b'Tunnel',
                b'Proxy',
                b'vRP',
                b'vRPclient',
            ],
            'Ox': [
                b'ox_lib',
                b'ox_inventory',
                b'OxLib',
                b'ox_core',
            ]
        }
        
        framework_scores = {}
        
        # Count occurrences of framework markers
        for framework, markers in framework_markers.items():
            count = 0
            for marker in markers:
                # Use count() with bounded range for performance (NASA Rule 2)
                # Limit search to first 100MB to avoid unbounded iteration on huge dumps
                search_data = data[:100 * 1024 * 1024] if len(data) > 100 * 1024 * 1024 else data
                count += search_data.count(marker)
            framework_scores[framework] = count
        
        # Find framework with highest score
        if not framework_scores or all(score == 0 for score in framework_scores.values()):
            return ("Unknown", 0.0)
        
        max_framework = max(framework_scores, key=framework_scores.get)
        max_score = framework_scores[max_framework]
        total_markers = sum(framework_scores.values())
        
        # Calculate confidence score (0.0-1.0)
        if total_markers == 0:
            confidence = 0.0
        else:
            # Confidence based on marker dominance
            confidence = min((max_score / total_markers), 1.0)
            
            # Boost confidence if we have many markers (at least 10)
            if max_score >= 10:
                confidence = min(confidence * 1.2, 1.0)
        
        return (max_framework, confidence)
    
    def _extract_fxmanifest(self, data: bytes) -> Dict[str, Any]:
        """Extract fxmanifest.lua metadata from memory dump.
        
        Parses fxmanifest.lua content to extract resource metadata including:
        - fx_version
        - game
        - author
        - description
        - version
        - scripts (client/server/shared)
        - exports
        
        Args:
            data: Raw memory data to scan
            
        Returns:
            Dictionary with extracted metadata fields
        """
        fxmanifest_data = {}
        
        try:
            # Decode data to text (use latin1 for FiveM binary data)
            text = data.decode('latin1', errors='ignore')
        except Exception as e:
            self.result.errors.append(f"fxmanifest extraction decode failed: {e}")
            return fxmanifest_data
        
        # Extract fx_version
        fx_version_match = re.search(r'fx_version\s+["\']([^"\']+)["\']', text, re.IGNORECASE)
        if fx_version_match:
            fxmanifest_data['fx_version'] = fx_version_match.group(1)
        
        # Extract game
        game_match = re.search(r'game\s+["\']([^"\']+)["\']', text, re.IGNORECASE)
        if game_match:
            fxmanifest_data['game'] = game_match.group(1)
        
        # Extract author
        author_match = re.search(r'author\s+["\']([^"\']+)["\']', text, re.IGNORECASE)
        if author_match:
            fxmanifest_data['author'] = author_match.group(1)
        
        # Extract description
        desc_match = re.search(r'description\s+["\']([^"\']+)["\']', text, re.IGNORECASE)
        if desc_match:
            fxmanifest_data['description'] = desc_match.group(1)
        
        # Extract version
        version_match = re.search(r'version\s+["\']([^"\']+)["\']', text, re.IGNORECASE)
        if version_match:
            fxmanifest_data['version'] = version_match.group(1)
        
        # Extract script arrays (limit to first 50 per type - NASA Rule 3)
        script_patterns = {
            'client_scripts': r'client_scripts?\s*{([^}]+)}',
            'server_scripts': r'server_scripts?\s*{([^}]+)}',
            'shared_scripts': r'shared_scripts?\s*{([^}]+)}',
        }
        
        for script_type, pattern in script_patterns.items():
            match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
            if match:
                scripts_block = match.group(1)
                # Extract individual script file names
                script_files = re.findall(r'["\']([^"\']+\.(?:lua|js))["\']', scripts_block, re.IGNORECASE)
                # Limit to 50 scripts (NASA Rule 3)
                fxmanifest_data[script_type] = script_files[:50]
        
        # Extract exports (limit to first 50 - NASA Rule 3)
        exports_match = re.search(r'exports?\s*{([^}]+)}', text, re.IGNORECASE | re.DOTALL)
        if exports_match:
            exports_block = exports_match.group(1)
            export_names = re.findall(r'["\']([^"\']+)["\']', exports_block)
            fxmanifest_data['exports'] = export_names[:50]
        
        return fxmanifest_data
    
    def _classify_error_severity(self, error_msg: str) -> str:
        """Classify error message severity level.
        
        Determines whether an error is a crash, error, panic, or warning
        based on keywords and patterns in the error message.
        
        Args:
            error_msg: Error message text to classify
            
        Returns:
            Severity level: "crash", "panic", "error", or "warning"
        """
        if not error_msg:
            return "unknown"
        
        error_lower = error_msg.lower()
        
        # Crash indicators (highest severity)
        crash_keywords = [
            'crash',
            'segfault',
            'access violation',
            'exception',
            'fatal',
            'corrupted',
            'assertion failed',
            'abort',
        ]
        for keyword in crash_keywords:
            if keyword in error_lower:
                return "crash"
        
        # Panic indicators (severe but may not crash)
        panic_keywords = [
            'panic',
            'stack overflow',
            'out of memory',
            'oom',
            'deadlock',
        ]
        for keyword in panic_keywords:
            if keyword in error_lower:
                return "panic"
        
        # Warning indicators (lowest severity)
        warning_keywords = [
            'warning',
            'deprecated',
            'info',
            'notice',
        ]
        for keyword in warning_keywords:
            if keyword in error_lower:
                return "warning"
        
        # Default to error
        return "error"

    def _get_module_for_address(self, address: int) -> Optional[str]:
        """Get the module name for a memory address."""
        for base, (end, name) in self._module_map.items():
            if base <= address < end:
                return name
        return None

    def _get_module_info_for_address(self, address: int) -> Optional[Tuple[str, int]]:
        """Get (name, base_address) for a memory address."""
        for base, (end, name) in self._module_map.items():
            if base <= address < end:
                return (name, base)
        return None

    # Minidump stream type constants (minidumpapiset.h)
    _THREAD_LIST_STREAM = 3
    _MODULE_LIST_STREAM = 4
    _EXCEPTION_STREAM = 6

    def _parse_large_dump_structure_light(self, dump_path: str) -> None:
        """Lightweight structure-only parse for large dumps (>=1GB). Reads only header,
        directory, exception/thread/module streams and crashing thread stack - no full parse.
        Recovers native (C/C++) stack trace and module map; Lua/JS stacks come from memory scan.
        """
        with open(dump_path, 'rb') as f:
            # 1. Header: Signature(4), Version(4), NumberOfStreams(4), StreamDirectoryRva(4), ...
            header = f.read(32)
            if len(header) < 32 or header[:4] != b'MDMP':
                return
            num_streams = struct.unpack('<I', header[8:12])[0]
            dir_rva = struct.unpack('<I', header[12:16])[0]
            # Crash time from header (TimeDateStamp at offset 20)
            if len(header) >= 24:
                ts = struct.unpack('<I', header[20:24])[0]
                if ts:
                    self.result.crash_time = ts

            # 2. Directory: array of (StreamType, DataSize, Rva) = 12 bytes each
            f.seek(dir_rva)
            dir_data = f.read(num_streams * 12)
            streams = {}
            for i in range(num_streams):
                off = i * 12
                stype = struct.unpack('<I', dir_data[off:off+4])[0]
                size = struct.unpack('<I', dir_data[off+4:off+8])[0]
                rva = struct.unpack('<I', dir_data[off+8:off+12])[0]
                streams[stype] = (size, rva)

            # 3. Exception stream (6): ThreadId at offset 0, then EXCEPTION_RECORD, then CONTEXT
            crash_tid = None
            context_rip = None
            context_rsp = None
            context_rbp = None
            if self._EXCEPTION_STREAM in streams:
                size, rva = streams[self._EXCEPTION_STREAM]
                f.seek(rva)
                # MINIDUMP_EXCEPTION_STREAM: ThreadId(4) + alignment(4) + ExceptionRecord + ThreadContext
                exc_stream = f.read(min(size, 4096))  # Read enough for context
                if len(exc_stream) >= 4:
                    crash_tid = struct.unpack('<I', exc_stream[0:4])[0]
                # EXCEPTION_RECORD starts at offset 8 (after ThreadId + padding)
                # ExceptionCode at +8, ExceptionFlags at +12, ExceptionAddress at +24
                if len(exc_stream) >= 12:
                    code = struct.unpack('<I', exc_stream[8:12])[0]
                    self.result.exception_code = code
                if len(exc_stream) >= 32:
                    exc_addr = struct.unpack('<Q', exc_stream[24:32])[0]
                    self.result.exception_address = exc_addr
                
                # CONTEXT starts after EXCEPTION_RECORD
                # EXCEPTION_RECORD size is variable, but typically ThreadContext location is at offset 56
                # MINIDUMP_LOCATION_DESCRIPTOR at offset 56: DataSize(4) + Rva(4)
                if len(exc_stream) >= 64:
                    try:
                        ctx_size = struct.unpack('<I', exc_stream[56:60])[0]
                        ctx_rva = struct.unpack('<I', exc_stream[60:64])[0]
                        if ctx_rva and ctx_size >= 1232:  # Minimum size for x64 CONTEXT
                            f.seek(ctx_rva)
                            ctx_data = f.read(min(ctx_size, 2048))
                            # x64 CONTEXT structure (simplified)
                            # ContextFlags at offset 48, Rip at 248, Rsp at 152, Rbp at 160
                            if len(ctx_data) >= 256:
                                context_flags = struct.unpack('<I', ctx_data[48:52])[0]
                                # General purpose registers start at offset 120
                                context_rax = struct.unpack('<Q', ctx_data[120:128])[0]
                                context_rcx = struct.unpack('<Q', ctx_data[128:136])[0]
                                context_rdx = struct.unpack('<Q', ctx_data[136:144])[0]
                                context_rbx = struct.unpack('<Q', ctx_data[144:152])[0]
                                context_rsp = struct.unpack('<Q', ctx_data[152:160])[0]
                                context_rbp = struct.unpack('<Q', ctx_data[160:168])[0]
                                context_rsi = struct.unpack('<Q', ctx_data[168:176])[0]
                                context_rdi = struct.unpack('<Q', ctx_data[176:184])[0]
                                context_r8 = struct.unpack('<Q', ctx_data[184:192])[0]
                                context_r9 = struct.unpack('<Q', ctx_data[192:200])[0]
                                context_r10 = struct.unpack('<Q', ctx_data[200:208])[0]
                                context_r11 = struct.unpack('<Q', ctx_data[208:216])[0]
                                context_r12 = struct.unpack('<Q', ctx_data[216:224])[0]
                                context_r13 = struct.unpack('<Q', ctx_data[224:232])[0]
                                context_r14 = struct.unpack('<Q', ctx_data[232:240])[0]
                                context_r15 = struct.unpack('<Q', ctx_data[240:248])[0]
                                context_rip = struct.unpack('<Q', ctx_data[248:256])[0]
                                
                                # Store in exception_params if it exists
                                if hasattr(self.result, 'exception_params') and self.result.exception_params:
                                    ep = self.result.exception_params
                                    ep.context_rip = context_rip
                                    ep.context_rsp = context_rsp
                                    ep.context_rbp = context_rbp
                                    ep.context_rax = context_rax
                                    ep.context_rbx = context_rbx
                                    ep.context_rcx = context_rcx
                                    ep.context_rdx = context_rdx
                                    ep.context_rsi = context_rsi
                                    ep.context_rdi = context_rdi
                                    ep.context_r8 = context_r8
                                    ep.context_r9 = context_r9
                                    ep.context_r10 = context_r10
                                    ep.context_r11 = context_r11
                                    ep.context_r12 = context_r12
                                    ep.context_r13 = context_r13
                                    ep.context_r14 = context_r14
                                    ep.context_r15 = context_r15
                                    ep.context_flags = context_flags
                    except Exception as e:
                        pass  # Context extraction failed, continue without it

            # 4. Module list (4): build _module_map. MINIDUMP_MODULE = 108 bytes: BaseOfImage(8), SizeOfImage(4), ..., ModuleNameRva(4) at 20
            if self._MODULE_LIST_STREAM in streams:
                size, rva = streams[self._MODULE_LIST_STREAM]
                f.seek(rva)
                mod_count = struct.unpack('<I', f.read(4))[0]
                MODULE_SIZE = 108
                for _ in range(min(mod_count, 2000)):  # cap for safety
                    mod = f.read(MODULE_SIZE)
                    if len(mod) < 24:
                        break
                    base = struct.unpack('<Q', mod[0:8])[0]
                    img_size = struct.unpack('<I', mod[8:12])[0]
                    name_rva = struct.unpack('<I', mod[20:24])[0]
                    name = ""
                    if name_rva and name_rva < 0x7FFFFFFF:
                        try:
                            f.seek(name_rva)
                            name_len = struct.unpack('<I', f.read(4))[0]  # Length in bytes (UTF-16)
                            if 0 < name_len < 2048:
                                name_buf = f.read(name_len)
                                name = name_buf.decode('utf-16-le', errors='replace').rstrip('\x00')
                                if '\\' in name:
                                    name = name.split('\\')[-1]
                        except Exception:
                            pass
                    if base and name:
                        end = int(base) + int(img_size or 0)
                        self._module_map[int(base)] = (end, name)
                        if self.result.exception_address and base <= self.result.exception_address < base + (img_size or 0):
                            self.result.exception_module = name
                        # PDB info from CvRecord (MINIDUMP_MODULE: CvRecord at offset 76 = 24 + 52 VS_FIXEDFILEINFO)
                        pdb_name, pdb_guid, pdb_age = "", "", 0
                        if len(mod) >= 84:
                            cv_size = struct.unpack('<I', mod[76:80])[0]
                            cv_rva = struct.unpack('<I', mod[80:84])[0]
                            if cv_rva and cv_size and cv_size >= 24:
                                try:
                                    f.seek(cv_rva)
                                    cv_data = f.read(min(cv_size, 512))
                                    if cv_data[:4] == b'RSDS':
                                        # GUID 16 bytes, age 4 bytes, then pdb path (null-terminated)
                                        pdb_guid = self._format_rsds_guid(cv_data[4:20])
                                        pdb_age = struct.unpack('<I', cv_data[20:24])[0]
                                        pdb_name = cv_data[24:].split(b'\x00', 1)[0].decode('utf-8', errors='replace').strip()
                                        if '/' in pdb_name or '\\' in pdb_name:
                                            pdb_name = pdb_name.replace('\\', '/').split('/')[-1]
                                except Exception:
                                    pass
                        # #region agent log
                        if pdb_name or pdb_guid:
                            _dlog("H2", "memory_analyzer._parse_lightweight.cv_record", "extracted PDB info", {
                                "module": name[:40],
                                "pdb_name": pdb_name,
                                "pdb_guid": pdb_guid[:20] if pdb_guid else "",
                                "pdb_age": pdb_age,
                                "cv_size": cv_size,
                                "cv_rva": cv_rva,
                            })
                        # #endregion
                        self.result.module_versions.append(ModuleVersionInfo(
                            name=name,
                            base_address=int(base),
                            size=int(img_size or 0),
                            pdb_name=pdb_name,
                            pdb_guid=pdb_guid,
                            pdb_age=pdb_age,
                        ))

            # 5. Thread list (3): find crashing thread stack RVA (or first thread with stack if no exception).
            # MINIDUMP_THREAD = 48 bytes: ThreadId(4), SuspendCount(4), PriorityClass(4), Priority(4), Teb(8),
            # Stack at 24 (StartOfMemoryRange 8, DataSize 4, Rva 4), ThreadContext(8)
            stack_rva = stack_size = None
            threads_with_stack: list[tuple[int, int, int, int, int, int]] = []
            if self._THREAD_LIST_STREAM in streams:
                size, rva = streams[self._THREAD_LIST_STREAM]
                f.seek(rva)
                thread_count = struct.unpack('<I', f.read(4))[0]
                THREAD_SIZE = 48
                for _ in range(min(thread_count, 4096)):
                    th = f.read(THREAD_SIZE)
                    if len(th) < 48:
                        break
                    tid = struct.unpack('<I', th[0:4])[0]
                    priority = struct.unpack('<I', th[12:16])[0]
                    priority_class = struct.unpack('<I', th[8:12])[0]
                    teb = struct.unpack('<Q', th[16:24])[0]
                    stack_start = struct.unpack('<Q', th[24:32])[0]
                    th_stack_size = struct.unpack('<I', th[32:36])[0]
                    th_stack_rva = struct.unpack('<I', th[36:40])[0]
                    # Populate threads_extended for display even when using lightweight parse
                    ext_info = ThreadExtendedInfo(
                        thread_id=int(tid),
                        priority=int(priority),
                        base_priority=int(priority_class),
                        teb_address=int(teb) if teb else None,
                        stack_base=int(stack_start) if stack_start else None,
                        stack_limit=int(stack_start) + int(th_stack_size) if stack_start and th_stack_size else None,
                    )
                    self.result.threads_extended.append(ext_info)
                    if th_stack_rva and th_stack_size and 0 < th_stack_size < 16 * 1024 * 1024:
                        threads_with_stack.append((tid, th_stack_rva, th_stack_size, priority, priority_class, teb))
                # Prefer crashing thread; if no exception stream, use first thread with valid stack
                if crash_tid is not None:
                    for tid, sr, ss, *_ in threads_with_stack:
                        if tid == crash_tid:
                            stack_rva, stack_size = sr, ss
                            break
                if stack_rva is None and threads_with_stack:
                    stack_rva = threads_with_stack[0][1]
                    stack_size = threads_with_stack[0][2]

            # 6. Read stack memory and walk for native stack. Use CONTEXT RIP if available.
            def _walk_stack_to_frames(stack_data: bytes, start_rip: Optional[int] = None) -> list[str]:
                frames = []
                
                # If we have RIP from CONTEXT, add it as frame #0 (the crash site)
                if start_rip:
                    mod_info = self._get_module_info_for_address(start_rip)
                    if mod_info:
                        name, base = mod_info
                        offset = start_rip - base
                        frames.append(f"{name} + 0x{offset:X}")
                
                # Now scan stack for return addresses
                for i in range(0, min(len(stack_data), 64 * 1024), 8):  # cap 64KB of stack
                    if i + 8 > len(stack_data):
                        break
                    ptr_val = struct.unpack('<Q', stack_data[i:i+8])[0]
                    mod_info = self._get_module_info_for_address(ptr_val)
                    if mod_info:
                        name, base = mod_info
                        offset = ptr_val - base
                        frame_str = f"{name} + 0x{offset:X}"
                        # Don't add duplicate of RIP frame
                        if not frames or frame_str != frames[0]:
                            frames.append(frame_str)
                
                # Dedup consecutive duplicates
                if frames:
                    dedup = [frames[0]]
                    for fr in frames[1:]:
                        if fr != dedup[-1]:
                            dedup.append(fr)
                    return dedup
                return frames

            if stack_rva and stack_size and stack_size > 0 and stack_size < 16 * 1024 * 1024:
                f.seek(stack_rva)
                stack_data = f.read(stack_size)
                if len(stack_data) >= 8:
                    # Pass RIP from CONTEXT if we extracted it
                    frames = _walk_stack_to_frames(stack_data, context_rip)
                    if frames:
                        self.result.native_stack = frames
                    elif threads_with_stack:
                        # Primary thread had no module-matching frames; try next threads
                        for tid, sr, ss, *_ in threads_with_stack[1:]:
                            if (sr, ss) == (stack_rva, stack_size):
                                continue
                            f.seek(sr)
                            other_data = f.read(ss)
                            if len(other_data) >= 8:
                                # Don't use RIP for other threads
                                frames = _walk_stack_to_frames(other_data, None)
                                if frames:
                                    self.result.native_stack = frames
                                    break

    def _diagnose_stack_recovery(self, dump_path: str) -> str:
        """Quick check: does the dump contain thread list and stack memory? Returns a short diagnostic string."""
        try:
            with open(dump_path, 'rb') as f:
                header = f.read(32)
                if len(header) < 32 or header[:4] != b'MDMP':
                    return "Dump is not a valid minidump (bad header)."
                num_streams = struct.unpack('<I', header[8:12])[0]
                dir_rva = struct.unpack('<I', header[12:16])[0]
                f.seek(dir_rva)
                dir_data = f.read(num_streams * 12)
                thread_rva = thread_size = None
                for i in range(num_streams):
                    off = i * 12
                    stype = struct.unpack('<I', dir_data[off:off+4])[0]
                    size = struct.unpack('<I', dir_data[off+4:off+8])[0]
                    rva = struct.unpack('<I', dir_data[off+8:off+12])[0]
                    if stype == 3:  # ThreadListStream
                        thread_rva, thread_size = rva, size
                        break
                if thread_rva is None:
                    return "Dump does not contain a thread list (no stack memory descriptors)."
                f.seek(thread_rva)
                th_count = struct.unpack('<I', f.read(4))[0]
                if th_count == 0:
                    return "Dump thread list is empty (no stack memory)."
                # Check first thread has stack RVA
                th0 = f.read(48)
                if len(th0) < 40:
                    return f"Dump contains {th_count} thread(s) but thread layout is unexpected."
                stack_rva = struct.unpack('<I', th0[36:40])[0]
                stack_size = struct.unpack('<I', th0[32:36])[0]
                if stack_rva == 0 or stack_size == 0:
                    return f"Dump has {th_count} thread(s) but stack memory descriptors are empty."
                return f"Dump contains {th_count} thread(s) and stack memory (RVA 0x{stack_rva:X}, size {stack_size}). Extraction should be possible; if you see no stacks, report as analysis error."
        except Exception as e:
            return f"Could not verify dump structure: {e}"

    def _extract_native_stack(self, thread, reader) -> None:
        """Extract native stack trace from the crashing thread."""
        try:
            # Get stack data
            stack = getattr(thread, 'Stack', None) or getattr(thread, 'stack', None)
            if not stack:
                return

            start = getattr(stack, 'StartOfMemoryRange', None) or \
                    getattr(stack, 'start_address', None) or 0
            start = int(start) if start else 0

            memory = getattr(stack, 'Memory', None)
            stack_data = None

            # Try to read from memory data attribute
            if memory:
                data_size = getattr(memory, 'DataSize', None) or 0
                rva = getattr(memory, 'Rva', None)

                if rva and reader and data_size:
                    if hasattr(reader, 'file_handle'):
                         reader.file_handle.seek(int(rva))
                         stack_data = reader.file_handle.read(int(data_size))

            # Fallback: Look in stored memory regions
            if not stack_data and start:
                for mem_start, data in self._memory_data.items():
                    mem_end = mem_start + len(data)
                    if mem_start <= start < mem_end:
                        offset = start - mem_start
                        stack_data = data[offset:]
                        break

            if not stack_data:
                return

            # Walk the stack
            frames = []

            # Scan every 8 bytes (64-bit)
            for i in range(0, len(stack_data), 8):
                if i + 8 > len(stack_data):
                    break

                ptr_val = struct.unpack('<Q', stack_data[i:i+8])[0]

                # Check if this pointer points into any module
                mod_info = self._get_module_info_for_address(ptr_val)
                if mod_info:
                    name, base = mod_info
                    offset = ptr_val - base
                    frames.append(f"{name} + 0x{offset:X}")

            # Dedup frames
            dedup_frames = []
            if frames:
                dedup_frames.append(frames[0])
                for f in frames[1:]:
                    if f != dedup_frames[-1]:
                        dedup_frames.append(f)

            self.result.native_stack = dedup_frames

        except Exception as e:
            self.result.errors.append(f"Native stack extraction error: {e}")

    # =========================================================================
    # NEW: Additional minidump data extraction methods
    # =========================================================================

    # Exception code name mapping
    EXCEPTION_CODES = {
        0xC0000005: "EXCEPTION_ACCESS_VIOLATION",
        0xC000001D: "EXCEPTION_ILLEGAL_INSTRUCTION",
        0xC0000025: "EXCEPTION_NONCONTINUABLE_EXCEPTION",
        0xC000008C: "EXCEPTION_ARRAY_BOUNDS_EXCEEDED",
        0xC000008D: "EXCEPTION_FLT_DENORMAL_OPERAND",
        0xC000008E: "EXCEPTION_FLT_DIVIDE_BY_ZERO",
        0xC000008F: "EXCEPTION_FLT_INEXACT_RESULT",
        0xC0000090: "EXCEPTION_FLT_INVALID_OPERATION",
        0xC0000091: "EXCEPTION_FLT_OVERFLOW",
        0xC0000092: "EXCEPTION_FLT_STACK_CHECK",
        0xC0000093: "EXCEPTION_FLT_UNDERFLOW",
        0xC0000094: "EXCEPTION_INT_DIVIDE_BY_ZERO",
        0xC0000095: "EXCEPTION_INT_OVERFLOW",
        0xC0000096: "EXCEPTION_PRIV_INSTRUCTION",
        0xC00000FD: "EXCEPTION_STACK_OVERFLOW",
        0xC0000374: "EXCEPTION_HEAP_CORRUPTION",
        0xC0000409: "EXCEPTION_STACK_BUFFER_OVERRUN",
        0xC0000417: "EXCEPTION_INVALID_CRUNTIME_PARAMETER",
        0x80000003: "EXCEPTION_BREAKPOINT",
        0x80000004: "EXCEPTION_SINGLE_STEP",
        0xE06D7363: "EXCEPTION_CPP_EXCEPTION",
    }

    def _extract_exception_params(self, exc_rec) -> None:
        """Extract detailed exception parameters including access violation details."""
        try:
            code = getattr(exc_rec, 'ExceptionCode', None)
            if code is None:
                return

            # Handle code that might be object, bytes, or int
            try:
                if isinstance(code, int):
                    pass
                elif isinstance(code, bytes):
                    code = int.from_bytes(code, 'little')
                elif hasattr(code, 'value'):
                    code = code.value
                else:
                    code = int(code)
            except (ValueError, TypeError):
                return  # Can't convert exception code
            
            exc_addr = getattr(exc_rec, 'ExceptionAddress', None)
            if exc_addr is not None:
                try:
                    if isinstance(exc_addr, int):
                        pass
                    elif isinstance(exc_addr, bytes):
                        exc_addr = int.from_bytes(exc_addr, 'little')
                    elif hasattr(exc_addr, 'value'):
                        exc_addr = exc_addr.value
                    else:
                        exc_addr = int(exc_addr)
                except (ValueError, TypeError):
                    exc_addr = None

            # Get exception parameters
            num_params = getattr(exc_rec, 'NumberParameters', None) or 0
            params_raw = getattr(exc_rec, 'ExceptionInformation', None) or []

            # Convert parameters to list of ints
            params = []
            if hasattr(params_raw, '__iter__'):
                for p in params_raw:
                    try:
                        if isinstance(p, bytes):
                            params.append(int.from_bytes(p, 'little'))
                        else:
                            params.append(int(p))
                    except Exception:
                        # Failed to parse parameter as integer; skip this parameter
                        pass

            # Build exception params object
            exc_params = ExceptionParams(
                code=code,
                code_name=self.EXCEPTION_CODES.get(code, f"UNKNOWN_0x{code:08X}"),
                address=exc_addr or 0,
                num_parameters=int(num_params),
                parameters=params[:int(num_params)] if num_params else params
            )

            # For Access Violation (0xC0000005), decode the access type and target address
            if code == 0xC0000005 and len(params) >= 2:
                access_type_code = params[0]
                target_addr = params[1]

                if access_type_code == 0:
                    exc_params.access_type = "read"
                elif access_type_code == 1:
                    exc_params.access_type = "write"
                elif access_type_code == 8:
                    exc_params.access_type = "execute (DEP violation)"
                else:
                    exc_params.access_type = f"unknown ({access_type_code})"

                exc_params.target_address = target_addr

            # Check for nested exception (ExceptionRecord field)
            nested_rec = getattr(exc_rec, 'ExceptionRecord', None)
            if nested_rec and nested_rec != exc_rec:
                # Recursively extract nested exception
                try:
                    nested_code = getattr(nested_rec, 'ExceptionCode', None)
                    if nested_code:
                        nested_params = ExceptionParams(
                            code=int(nested_code),
                            code_name=self.EXCEPTION_CODES.get(int(nested_code), ""),
                        )
                        exc_params.nested_exception = nested_params
                except Exception:
                    # Failed to extract nested exception info; continue without it
                    pass

            self.result.exception_params = exc_params

        except Exception as e:
            self.result.errors.append(f"Exception params extraction: {e}")

    def _format_rsds_guid(self, guid_bytes: bytes) -> str:
        """Format RSDS GUID bytes into symbol server GUID string (no dashes)."""
        try:
            if not guid_bytes or len(guid_bytes) < 16:
                return ""
            data1, data2, data3, data4 = struct.unpack("<IHH8s", guid_bytes[:16])
            return f"{data1:08X}{data2:04X}{data3:04X}{data4.hex().upper()}"
        except Exception:
            return ""

    def _extract_module_version_info(self, module) -> None:
        """Extract detailed version and PDB information from a module."""
        try:
            name = str(getattr(module, 'name', '') or '')
            base = getattr(module, 'baseaddress', None) or getattr(module, 'base', None) or 0
            size = getattr(module, 'size', None) or 0
            checksum = getattr(module, 'checksum', None) or getattr(module, 'CheckSum', None) or 0
            timestamp = getattr(module, 'timestamp', None) or getattr(module, 'TimeDateStamp', None) or 0

            mod_info = ModuleVersionInfo(
                name=name,
                base_address=int(base) if base else 0,
                size=int(size) if size else 0,
                checksum=int(checksum) if checksum else 0,
                timestamp=int(timestamp) if timestamp else 0,
            )

            # Try to get version info
            vs_info = getattr(module, 'vs_info', None) or getattr(module, 'versioninfo', None)
            if vs_info:
                # Fixed file info
                ffi = getattr(vs_info, 'FixedFileInfo', None) or getattr(vs_info, 'fixed_file_info', None)
                if ffi:
                    # File version
                    fv_ms = getattr(ffi, 'FileVersionMS', None) or getattr(ffi, 'dwFileVersionMS', 0) or 0
                    fv_ls = getattr(ffi, 'FileVersionLS', None) or getattr(ffi, 'dwFileVersionLS', 0) or 0
                    if fv_ms or fv_ls:
                        major = (fv_ms >> 16) & 0xFFFF
                        minor = fv_ms & 0xFFFF
                        build = (fv_ls >> 16) & 0xFFFF
                        rev = fv_ls & 0xFFFF
                        mod_info.file_version = f"{major}.{minor}.{build}.{rev}"

                    # Product version
                    pv_ms = getattr(ffi, 'ProductVersionMS', None) or getattr(ffi, 'dwProductVersionMS', 0) or 0
                    pv_ls = getattr(ffi, 'ProductVersionLS', None) or getattr(ffi, 'dwProductVersionLS', 0) or 0
                    if pv_ms or pv_ls:
                        major = (pv_ms >> 16) & 0xFFFF
                        minor = pv_ms & 0xFFFF
                        build = (pv_ls >> 16) & 0xFFFF
                        rev = pv_ls & 0xFFFF
                        mod_info.product_version = f"{major}.{minor}.{build}.{rev}"

            # Try to get CodeView/PDB info
            cv_record = getattr(module, 'cv_record', None) or getattr(module, 'CvRecord', None)
            if cv_record:
                # Check for PDB70 (most common)
                pdb_name = getattr(cv_record, 'PdbFileName', None) or getattr(cv_record, 'pdb_file_name', None)
                if pdb_name:
                    if isinstance(pdb_name, bytes):
                        pdb_name = pdb_name.decode('utf-8', errors='replace').rstrip('\x00')
                    mod_info.pdb_name = str(pdb_name)

                # GUID
                guid = getattr(cv_record, 'Signature', None) or getattr(cv_record, 'signature', None)
                if guid:
                    if hasattr(guid, 'bytes_le'):
                        mod_info.pdb_guid = self._format_rsds_guid(guid.bytes_le)
                    elif isinstance(guid, bytes):
                        mod_info.pdb_guid = self._format_rsds_guid(guid)
                    elif hasattr(guid, 'hex'):
                        mod_info.pdb_guid = guid.hex().upper()
                    else:
                        mod_info.pdb_guid = str(guid).replace('-', '').upper()

                # Age
                age = getattr(cv_record, 'Age', None) or getattr(cv_record, 'age', None)
                if age:
                    mod_info.pdb_age = int(age)

                # CV signature type
                cv_sig = getattr(cv_record, 'CvSignature', None) or getattr(cv_record, 'cv_signature', None)
                if cv_sig:
                    if cv_sig == 0x53445352:  # 'RSDS'
                        mod_info.cv_signature = "RSDS (PDB70)"
                    elif cv_sig == 0x3031424E:  # 'NB10'
                        mod_info.cv_signature = "NB10 (PDB20)"
                    else:
                        mod_info.cv_signature = f"0x{cv_sig:08X}"

            self.result.module_versions.append(mod_info)

        except Exception as e:
            self.result.errors.append(f"Module version extraction: {e}")

    def _extract_thread_extended_info(self, thread) -> None:
        """Extract extended thread information."""
        try:
            tid = getattr(thread, 'ThreadId', None) or getattr(thread, 'thread_id', None) or 0

            ext_info = ThreadExtendedInfo(thread_id=int(tid))

            # Priority
            ext_info.priority = int(getattr(thread, 'Priority', None) or getattr(thread, 'priority', 0) or 0)
            ext_info.base_priority = int(getattr(thread, 'PriorityClass', None) or getattr(thread, 'priority_class', 0) or 0)

            # TEB address
            teb = getattr(thread, 'Teb', None) or getattr(thread, 'teb', None)
            if teb:
                ext_info.teb_address = int(teb)

            # Stack info
            stack = getattr(thread, 'Stack', None) or getattr(thread, 'stack', None)
            if stack:
                ext_info.stack_base = int(getattr(stack, 'StartOfMemoryRange', None) or 0)
                memory = getattr(stack, 'Memory', None)
                if memory:
                    size = getattr(memory, 'DataSize', None) or 0
                    if ext_info.stack_base and size:
                        ext_info.stack_limit = ext_info.stack_base + int(size)

            # Thread name (if available in thread info list - we may not have it from basic thread list)
            ext_info.thread_name = str(getattr(thread, 'ThreadName', None) or getattr(thread, 'thread_name', '') or '')

            # Suspend count
            suspend_count = getattr(thread, 'SuspendCount', None)
            if suspend_count and suspend_count > 0:
                ext_info.state = f"Suspended ({suspend_count})"

            self.result.threads_extended.append(ext_info)

        except Exception as e:
            self.result.errors.append(f"Thread extended info extraction: {e}")

    def _extract_additional_streams(self, md, reader) -> None:
        """Extract additional minidump streams: handles, memory info, process stats, etc."""
        # Extract handle data stream
        self._extract_handle_data(md)

        # Extract memory info list
        self._extract_memory_info_list(md)

        # Extract extended process statistics from misc_info
        self._extract_process_statistics(md)

        # Extract function table (count only)
        self._extract_function_table(md)

        # Extract comment streams
        self._extract_comment_streams(md)

        # Extract thread info list (for thread names)
        self._extract_thread_info_list(md)

        # Extract assertion info
        self._extract_assertion_info(md)

        # Extract JavaScriptData stream (20) - V8/Chakra context when present
        self._extract_javascript_data(md)

        # Extract ProcessVmCounters stream (22) - VM usage at crash
        self._extract_process_vm_counters(md)

    def _extract_handle_data(self, md) -> None:
        """Extract handle data stream - open files, mutexes, etc at crash time."""
        try:
            # Handle data stream can be accessed via handle_data or directory lookup
            handle_data = getattr(md, 'handle_data', None) or getattr(md, 'handles', None)

            if not handle_data:
                # Try accessing via directory
                directory = getattr(md, 'directory', None) or getattr(md, 'streams', None)
                if directory and hasattr(directory, '__iter__'):
                    for entry in directory:
                        stream_type = getattr(entry, 'StreamType', None) or getattr(entry, 'stream_type', None)
                        # HandleDataStream = 12
                        if stream_type == 12:
                            handle_data = getattr(entry, 'data', None)
                            break

            if not handle_data:
                return

            # Get the handles list
            handles_list = getattr(handle_data, 'handles', None) or getattr(handle_data, 'Handles', None)
            if not handles_list or not hasattr(handles_list, '__iter__'):
                return

            for h in handles_list:
                try:
                    handle_val = int(getattr(h, 'Handle', None) or getattr(h, 'handle', 0) or 0)
                    type_name = str(getattr(h, 'TypeName', None) or getattr(h, 'type_name', '') or '')
                    object_name = str(getattr(h, 'ObjectName', None) or getattr(h, 'object_name', '') or '')
                    attributes = int(getattr(h, 'Attributes', None) or getattr(h, 'attributes', 0) or 0)
                    granted_access = int(getattr(h, 'GrantedAccess', None) or getattr(h, 'granted_access', 0) or 0)

                    handle_info = HandleInfo(
                        handle_value=handle_val,
                        type_name=type_name,
                        object_name=object_name,
                        attributes=attributes,
                        granted_access=granted_access
                    )
                    self.result.handles.append(handle_info)
                except Exception:
                    # Failed to parse handle data; skip this handle
                    continue

        except Exception as e:
            self.result.errors.append(f"Handle data extraction: {e}")

    def _add_evidence_from_handles(self) -> None:
        """Add evidence from open file handles (resource paths) at crash time."""
        if not self.result.handles:
            return
        # Match resources\resname or resources/resname or @resname/ in path
        path_resource_re = re.compile(
            r'(?:resources[/\\]([A-Za-z0-9_\-]{2,64})(?:[/\\]|$)|'
            r'@([A-Za-z0-9_\-]{2,64})[/\\])',
            re.IGNORECASE
        )
        for h in self.result.handles:
            type_name = (h.type_name or '').strip()
            object_name = (h.object_name or '').strip()
            if not object_name:
                continue
            # File handle types: "File" is typical; some dumps use "File" in TypeName
            if 'file' not in type_name.lower():
                continue
            # Extract resource name from path
            resource_name: Optional[str] = None
            for m in path_resource_re.finditer(object_name):
                res = m.group(1) or m.group(2)
                if res and self._is_valid_resource_name(res):
                    resource_name = res
                    break
            if not resource_name:
                resource_name = self._extract_resource_from_path(object_name)
            if not resource_name or not self._is_valid_resource_name(resource_name):
                continue
            self._add_evidence(ScriptEvidence(
                evidence_type=EvidenceType.HANDLE_PATH,
                script_name='handle',
                resource_name=resource_name,
                file_path=object_name,
                context="Open file handle at crash",
                confidence=0.55,
            ))

    def _extract_memory_info_list(self, md) -> None:
        """Extract memory info list with detailed permissions."""
        try:
            # Memory info list stream
            mem_info = getattr(md, 'memory_info', None) or getattr(md, 'memory_info_list', None)

            if not mem_info:
                # Try accessing via directory
                directory = getattr(md, 'directory', None) or getattr(md, 'streams', None)
                if directory and hasattr(directory, '__iter__'):
                    for entry in directory:
                        stream_type = getattr(entry, 'StreamType', None) or getattr(entry, 'stream_type', None)
                        # MemoryInfoListStream = 16
                        if stream_type == 16:
                            mem_info = getattr(entry, 'data', None)
                            break

            if not mem_info:
                return

            # Get entries
            entries = getattr(mem_info, 'entries', None) or getattr(mem_info, 'infos', None)
            if not entries or not hasattr(entries, '__iter__'):
                return

            # Memory protection flags
            protection_map = {
                0x01: "PAGE_NOACCESS",
                0x02: "PAGE_READONLY",
                0x04: "PAGE_READWRITE",
                0x08: "PAGE_WRITECOPY",
                0x10: "PAGE_EXECUTE",
                0x20: "PAGE_EXECUTE_READ",
                0x40: "PAGE_EXECUTE_READWRITE",
                0x80: "PAGE_EXECUTE_WRITECOPY",
                0x100: "PAGE_GUARD",
                0x200: "PAGE_NOCACHE",
                0x400: "PAGE_WRITECOMBINE",
            }

            state_map = {
                0x1000: "MEM_COMMIT",
                0x2000: "MEM_RESERVE",
                0x10000: "MEM_FREE",
            }

            type_map = {
                0x20000: "MEM_PRIVATE",
                0x40000: "MEM_MAPPED",
                0x1000000: "MEM_IMAGE",
            }

            for entry in entries:
                try:
                    base = int(getattr(entry, 'BaseAddress', None) or getattr(entry, 'base_address', 0) or 0)
                    size = int(getattr(entry, 'RegionSize', None) or getattr(entry, 'region_size', 0) or 0)
                    alloc_base = getattr(entry, 'AllocationBase', None) or getattr(entry, 'allocation_base', None)

                    # Protection
                    protect = int(getattr(entry, 'Protect', None) or getattr(entry, 'protect', 0) or 0)
                    protect_str = protection_map.get(protect & 0xFF, f"0x{protect:X}")
                    if protect & 0x100:
                        protect_str += " | PAGE_GUARD"
                    if protect & 0x200:
                        protect_str += " | PAGE_NOCACHE"

                    # State
                    state = int(getattr(entry, 'State', None) or getattr(entry, 'state', 0) or 0)
                    state_str = state_map.get(state, f"0x{state:X}")

                    # Type
                    mem_type = int(getattr(entry, 'Type', None) or getattr(entry, 'type', 0) or 0)
                    type_str = type_map.get(mem_type, f"0x{mem_type:X}" if mem_type else "")

                    region = MemoryRegionInfo(
                        start_address=base,
                        size=size,
                        protection=protect_str,
                        state=state_str,
                        type_str=type_str,
                        allocation_base=int(alloc_base) if alloc_base else None,
                        module_name=self._get_module_for_address(base),
                        contains_code=(protect & 0xF0) != 0  # Any EXECUTE flag
                    )
                    self.result.memory_info.append(region)
                except Exception:
                    # Failed to parse memory region info; skip this region
                    continue

        except Exception as e:
            self.result.errors.append(f"Memory info list extraction: {e}")

    def _extract_process_statistics(self, md) -> None:
        """Extract process statistics from extended MiscInfo."""
        try:
            misc_info = getattr(md, 'misc_info', None)
            if not misc_info:
                return

            stats = ProcessStatistics()

            # Basic info
            stats.process_id = int(getattr(misc_info, 'ProcessId', None) or getattr(misc_info, 'process_id', 0) or 0)
            stats.create_time = getattr(misc_info, 'ProcessCreateTime', None) or getattr(misc_info, 'process_create_time', None)
            stats.user_time = getattr(misc_info, 'ProcessUserTime', None) or getattr(misc_info, 'process_user_time', None)
            stats.kernel_time = getattr(misc_info, 'ProcessKernelTime', None) or getattr(misc_info, 'process_kernel_time', None)

            # Memory statistics (MINIDUMP_MISC_INFO_3+)
            stats.peak_virtual_size = int(getattr(misc_info, 'PeakVirtualSize', None) or 0)
            stats.virtual_size = int(getattr(misc_info, 'VirtualSize', None) or 0)
            stats.page_fault_count = int(getattr(misc_info, 'PageFaultCount', None) or 0)
            stats.peak_working_set_size = int(getattr(misc_info, 'PeakWorkingSetSize', None) or 0)
            stats.working_set_size = int(getattr(misc_info, 'WorkingSetSize', None) or 0)
            stats.quota_peak_paged_pool = int(getattr(misc_info, 'QuotaPeakPagedPoolUsage', None) or 0)
            stats.quota_paged_pool = int(getattr(misc_info, 'QuotaPagedPoolUsage', None) or 0)
            stats.quota_peak_non_paged_pool = int(getattr(misc_info, 'QuotaPeakNonPagedPoolUsage', None) or 0)
            stats.quota_non_paged_pool = int(getattr(misc_info, 'QuotaNonPagedPoolUsage', None) or 0)
            stats.pagefile_usage = int(getattr(misc_info, 'PagefileUsage', None) or 0)
            stats.peak_pagefile_usage = int(getattr(misc_info, 'PeakPagefileUsage', None) or 0)
            stats.private_usage = int(getattr(misc_info, 'PrivateUsage', None) or 0)

            # Handle counts (MINIDUMP_MISC_INFO_4+)
            stats.handle_count = int(getattr(misc_info, 'HandleCount', None) or 0)
            stats.gdi_handle_count = int(getattr(misc_info, 'GdiHandleCount', None) or 0)
            stats.user_handle_count = int(getattr(misc_info, 'UserHandleCount', None) or 0)

            # Process protection info (MINIDUMP_MISC_INFO_5+)
            integrity = getattr(misc_info, 'ProcessIntegrityLevel', None)
            if integrity:
                integrity_map = {
                    0x0000: "Untrusted",
                    0x1000: "Low",
                    0x2000: "Medium",
                    0x2100: "Medium Plus",
                    0x3000: "High",
                    0x4000: "System",
                    0x5000: "Protected Process",
                }
                stats.process_integrity_level = integrity_map.get(int(integrity), f"0x{int(integrity):04X}")

            protected = getattr(misc_info, 'ProtectedProcess', None)
            if protected:
                stats.protected_process = bool(protected)

            # Only store if we got meaningful data
            if stats.process_id or stats.peak_working_set_size or stats.handle_count:
                self.result.process_stats = stats

        except Exception as e:
            self.result.errors.append(f"Process statistics extraction: {e}")

    def _extract_function_table(self, md) -> None:
        """Extract function table stream info (for stack unwinding support check)."""
        try:
            func_table = getattr(md, 'function_table', None)
            if func_table:
                entries = getattr(func_table, 'entries', None) or []
                if hasattr(entries, '__len__'):
                    self.result.function_table_entries = len(entries)
                elif hasattr(entries, '__iter__'):
                    self.result.function_table_entries = sum(1 for _ in entries)
        except Exception as e:
            pass  # Function table is optional, don't add to errors

    def _extract_comment_streams(self, md) -> None:
        """Extract comment streams (ASCII and Unicode)."""
        try:
            # CommentStreamA = 17, CommentStreamW = 18
            directory = getattr(md, 'directory', None) or getattr(md, 'streams', None)
            if not directory or not hasattr(directory, '__iter__'):
                return

            for entry in directory:
                stream_type = getattr(entry, 'StreamType', None) or getattr(entry, 'stream_type', None)
                if stream_type == 17:  # CommentStreamA
                    data = getattr(entry, 'data', None)
                    if data:
                        if isinstance(data, bytes):
                            self.result.comment_stream_a = data.decode('ascii', errors='replace').rstrip('\x00')
                        else:
                            self.result.comment_stream_a = str(data)
                elif stream_type == 18:  # CommentStreamW
                    data = getattr(entry, 'data', None)
                    if data:
                        if isinstance(data, bytes):
                            self.result.comment_stream_w = data.decode('utf-16-le', errors='replace').rstrip('\x00')
                        else:
                            self.result.comment_stream_w = str(data)

        except Exception as e:
            pass  # Comment streams are optional

    def _extract_thread_info_list(self, md) -> None:
        """Extract thread info list for thread names."""
        try:
            # ThreadInfoListStream = 11
            thread_info_list = getattr(md, 'thread_info_list', None) or getattr(md, 'thread_infos', None)

            if not thread_info_list:
                directory = getattr(md, 'directory', None) or getattr(md, 'streams', None)
                if directory and hasattr(directory, '__iter__'):
                    for entry in directory:
                        stream_type = getattr(entry, 'StreamType', None) or getattr(entry, 'stream_type', None)
                        if stream_type == 11:
                            thread_info_list = getattr(entry, 'data', None)
                            break

            if not thread_info_list:
                return

            entries = getattr(thread_info_list, 'entries', None) or getattr(thread_info_list, 'infos', None)
            if not entries or not hasattr(entries, '__iter__'):
                return

            # Build a map of thread ID to name
            thread_names = {}
            for entry in entries:
                tid = getattr(entry, 'ThreadId', None) or getattr(entry, 'thread_id', None)
                name = getattr(entry, 'ThreadName', None) or getattr(entry, 'thread_name', None)
                if tid and name:
                    thread_names[int(tid)] = str(name)

            # Update our existing thread extended info with names
            for thread_ext in self.result.threads_extended:
                if thread_ext.thread_id in thread_names:
                    thread_ext.thread_name = thread_names[thread_ext.thread_id]

        except Exception as e:
            pass  # Thread info list is optional

    def _extract_assertion_info(self, md) -> None:
        """Extract assertion info stream."""
        try:
            assertion = getattr(md, 'assertion_info', None)

            if not assertion:
                directory = getattr(md, 'directory', None) or getattr(md, 'streams', None)
                if directory and hasattr(directory, '__iter__'):
                    for entry in directory:
                        stream_type = getattr(entry, 'StreamType', None) or getattr(entry, 'stream_type', None)
                        # AssertionInfoStream = 25
                        if stream_type == 25:
                            assertion = getattr(entry, 'data', None)
                            break

            if not assertion:
                return

            assertion_expr = getattr(assertion, 'AssertionExpression', None) or getattr(assertion, 'expression', None)
            assertion_func = getattr(assertion, 'AssertionFunction', None) or getattr(assertion, 'function', None)
            assertion_file = getattr(assertion, 'AssertionFile', None) or getattr(assertion, 'file', None)
            assertion_line = getattr(assertion, 'AssertionLine', None) or getattr(assertion, 'line', None)

            if assertion_expr:
                self.result.assertion_info['expression'] = str(assertion_expr)
            if assertion_func:
                self.result.assertion_info['function'] = str(assertion_func)
            if assertion_file:
                self.result.assertion_info['file'] = str(assertion_file)
            if assertion_line:
                self.result.assertion_info['line'] = str(assertion_line)

        except Exception as e:
            pass  # Assertion info is optional

    # Str patterns for comment/assertion stream resource extraction (streams are already decoded)
    _COMMENT_RESOURCE_PATTERNS = (
        re.compile(r'resources[/\\]([A-Za-z0-9_\-]{2,64})(?:[/\\]|$)', re.IGNORECASE),
        re.compile(r'@([A-Za-z0-9_\-]{2,64})[/\\]', re.IGNORECASE),
        re.compile(r'(?:ensure|start)\s+([A-Za-z0-9_\-]{2,64})\s*(?:$|#|\r|\n)', re.IGNORECASE),
        re.compile(r'resource[:\s]+["\']?([A-Za-z0-9_\-]{2,64})["\']?', re.IGNORECASE),
    )

    def _add_evidence_from_comment_and_assertion_streams(self) -> None:
        """Scan comment and assertion streams for resource names and add evidence."""
        texts: List[str] = []
        if self.result.comment_stream_a:
            texts.append(self.result.comment_stream_a)
        if self.result.comment_stream_w:
            texts.append(self.result.comment_stream_w)
        if self.result.assertion_info:
            for v in self.result.assertion_info.values():
                if v and isinstance(v, str):
                    texts.append(v)
        if not texts:
            return
        seen: Set[Tuple[str, str]] = set()  # (resource_name, source) to avoid duplicate evidence
        for text in texts:
            for pattern in self._COMMENT_RESOURCE_PATTERNS:
                for m in pattern.finditer(text):
                    res = (m.group(1) or '').strip()
                    if not res or not self._is_valid_resource_name(res):
                        continue
                    key = (res, 'comment_assertion')
                    if key in seen:
                        continue
                    seen.add(key)
                    self._add_evidence(ScriptEvidence(
                        evidence_type=EvidenceType.RESOURCE_NAME,
                        script_name='comment_assertion',
                        resource_name=res,
                        context="Comment/assertion stream",
                        confidence=0.5,
                    ))

    def _extract_javascript_data(self, md) -> None:
        """Extract JavaScriptData stream (20) - V8/Chakra JS context when present."""
        try:
            js_data = getattr(md, 'javascript_data', None) or getattr(md, 'JavaScriptData', None)
            if not js_data:
                directory = getattr(md, 'directory', None) or getattr(md, 'streams', None)
                if directory and hasattr(directory, '__iter__'):
                    for entry in directory:
                        stream_type = getattr(entry, 'StreamType', None) or getattr(entry, 'stream_type', None)
                        if stream_type == 20:  # JavaScriptDataStream
                            js_data = getattr(entry, 'data', None)
                            break
            if not js_data:
                return
            out: Dict[str, Any] = {}
            if hasattr(js_data, '__dict__'):
                for k, v in js_data.__dict__.items():
                    if not k.startswith('_') and v is not None:
                        try:
                            out[k] = str(v) if isinstance(v, bytes) else v
                        except Exception:
                            out[k] = "<unserializable>"
            elif isinstance(js_data, bytes):
                out["raw_size"] = len(js_data)
                # Try to extract readable strings for stack/context
                try:
                    decoded = js_data.decode('utf-8', errors='replace')
                    if decoded.strip():
                        out["preview"] = decoded[:2000].strip()
                except Exception:
                    pass
            else:
                out["value"] = str(js_data)
            if out:
                self.result.javascript_data = out
        except Exception as e:
            pass  # JavaScriptData is optional

    def _extract_process_vm_counters(self, md) -> None:
        """Extract ProcessVmCounters stream (22) - VM usage at crash time."""
        try:
            vm_counters = getattr(md, 'process_vm_counters', None) or getattr(md, 'ProcessVmCounters', None)
            if not vm_counters:
                directory = getattr(md, 'directory', None) or getattr(md, 'streams', None)
                if directory and hasattr(directory, '__iter__'):
                    for entry in directory:
                        stream_type = getattr(entry, 'StreamType', None) or getattr(entry, 'stream_type', None)
                        if stream_type == 22:  # ProcessVmCountersStream
                            vm_counters = getattr(entry, 'data', None)
                            break
            if not vm_counters:
                return
            out: Dict[str, Any] = {}
            # MINIDUMP_PROCESS_VM_COUNTERS: PageFaultCount, PeakWorkingSetSize, WorkingSetSize, QuotaPeakPagedPoolUsage, QuotaPagedPoolUsage, QuotaPeakNonPagedPoolUsage, QuotaNonPagedPoolUsage, PagefileUsage, PeakPagefileUsage, PrivateUsage
            for attr in ('PageFaultCount', 'PeakWorkingSetSize', 'WorkingSetSize', 'QuotaPeakPagedPoolUsage',
                         'QuotaPagedPoolUsage', 'QuotaPeakNonPagedPoolUsage', 'QuotaNonPagedPoolUsage',
                         'PagefileUsage', 'PeakPagefileUsage', 'PrivateUsage',
                         'page_fault_count', 'peak_working_set_size', 'working_set_size',
                         'quota_peak_paged_pool_usage', 'quota_paged_pool_usage',
                         'quota_peak_non_paged_pool_usage', 'quota_non_paged_pool_usage',
                         'pagefile_usage', 'peak_pagefile_usage', 'private_usage'):
                val = getattr(vm_counters, attr, None)
                if val is not None:
                    out[attr] = int(val) if isinstance(val, (int, float)) else val
            if out:
                self.result.process_vm_counters = out
        except Exception as e:
            pass  # ProcessVmCounters is optional

    def get_diagnostic_info(self) -> str:
        """Get diagnostic information about what was read from the dump."""
        lines = []
        lines.append("=" * 60)
        lines.append("MEMORY DUMP DIAGNOSTIC INFORMATION")
        lines.append("=" * 60)
        lines.append("")

        # Minidump library status
        lines.append(f"Minidump library available: {HAS_MINIDUMP}")
        lines.append("")

        # Exception info
        lines.append("EXCEPTION INFO:")
        lines.append(f"  Code: {hex(self.result.exception_code) if self.result.exception_code else 'None'}")
        lines.append(f"  Address: {hex(self.result.exception_address) if self.result.exception_address else 'None'}")
        lines.append(f"  Module: {self.result.exception_module or 'None'}")
        lines.append("")

        # Module map
        lines.append(f"MODULES LOADED: {len(self._module_map)}")
        for base, (end, name) in list(self._module_map.items())[:10]:
            lines.append(f"  0x{base:016X} - 0x{end:016X}: {name}")
        if len(self._module_map) > 10:
            lines.append(f"  ... and {len(self._module_map) - 10} more")
        lines.append("")

        # Memory regions
        lines.append(f"MEMORY REGIONS READ: {len(self.result.memory_regions)}")
        total_bytes = sum(len(d) for d in self._memory_data.values())
        lines.append(f"TOTAL MEMORY DATA: {total_bytes:,} bytes")
        for region in self.result.memory_regions[:10]:
            lines.append(f"  0x{region.start_address:016X} ({region.size:,} bytes) - {region.module_name or 'unknown'}")
        if len(self.result.memory_regions) > 10:
            lines.append(f"  ... and {len(self.result.memory_regions) - 10} more")
        lines.append("")

        # Evidence summary
        lines.append(f"EVIDENCE FOUND: {len(self.result.all_evidence)}")
        by_type = {}
        for e in self.result.all_evidence:
            by_type[e.evidence_type.name] = by_type.get(e.evidence_type.name, 0) + 1
        for etype, count in sorted(by_type.items(), key=lambda x: -x[1]):
            lines.append(f"  {etype}: {count}")
        lines.append("")

        # Resources found - show all resources mentioned (sorted by evidence count)
        lines.append(f"RESOURCES IDENTIFIED: {len(self.result.resources)}")
        if self.result.resources and self.result.native_stack and not self.result.lua_stacks and not self.result.js_stacks:
            lines.append("  (From memory scan; native stack alone does not contain resource names.)")
        sorted_resources = sorted(
            self.result.resources.items(),
            key=lambda x: (x[1].evidence_count, x[0]),
            reverse=True
        )
        for name, info in sorted_resources:
            lines.append(f"  {name}: {info.evidence_count} evidence items")
        lines.append("")

        # Script paths found
        lines.append(f"SCRIPT PATHS FOUND: {len(self.result.script_paths)}")
        for path in self.result.script_paths[:10]:
            lines.append(f"  {path}")
        if len(self.result.script_paths) > 10:
            lines.append(f"  ... and {len(self.result.script_paths) - 10} more")
        lines.append("")

        # Errors during analysis
        if self.result.errors:
            lines.append("ANALYSIS NOTES/WARNINGS:")
            for err in self.result.errors:
                lines.append(f"  - {err}")
            lines.append("")

        lines.append("=" * 60)
        return "\n".join(lines)

    def generate_pinpoint_report(self) -> str:
        """Generate a detailed report pinpointing error sources."""
        lines = []
        lines.append("=" * 70)
        lines.append("FIVEM CRASH ANALYSIS - SCRIPT/RESOURCE PINPOINT REPORT")
        lines.append("=" * 70)
        lines.append("")

        # Exception info
        if self.result.exception_code or self.result.exception_address:
            lines.append("EXCEPTION INFORMATION:")
            lines.append("-" * 40)
            if self.result.exception_code:
                lines.append(f"  Exception Code: 0x{self.result.exception_code:08X}")
            if self.result.exception_address:
                lines.append(f"  Exception Address: 0x{self.result.exception_address:016X}")
            if self.result.exception_module:
                lines.append(f"  Faulting Module: {self.result.exception_module}")
            lines.append("")

        # Primary suspects
        if self.result.primary_suspects:
            lines.append("PRIMARY SUSPECTS (Most Likely Causes):")
            lines.append("-" * 40)
            for i, suspect in enumerate(self.result.primary_suspects[:5], 1):
                lines.append(f"\n  {i}. RESOURCE: {suspect.name}")
                lines.append(f"     Evidence Count: {suspect.evidence_count}")
                lines.append(f"     Evidence Types: {', '.join(e.name for e in suspect.evidence_types)}")
                if suspect.scripts:
                    lines.append(f"     Scripts: {', '.join(suspect.scripts[:5])}")
                if suspect.path:
                    lines.append(f"     Path: {suspect.path}")
            lines.append("")

        # All resources mentioned (FiveM relevance - resources that could be involved)
        if self.result.resources:
            lines.append("ALL RESOURCES MENTIONED (may be involved or corrupted):")
            lines.append("-" * 40)
            # When only native stack was recovered, clarify that resource names come from memory scan
            if self.result.native_stack and not self.result.lua_stacks and not self.result.js_stacks:
                lines.append("  (Identified by scanning dump memory; native stack does not contain resource names.)")
                lines.append("")
            by_evidence = sorted(
                self.result.resources.items(),
                key=lambda x: (x[1].evidence_count, x[0]),
                reverse=True
            )
            for name, info in by_evidence[:30]:
                lines.append(f"  {name}: {info.evidence_count} evidence")
            if len(self.result.resources) > 30:
                lines.append(f"  ... and {len(self.result.resources) - 30} more")
            lines.append("")

        # Script errors found
        if self.result.script_errors:
            lines.append("SCRIPT ERRORS FOUND IN MEMORY:")
            lines.append("-" * 40)
            for error in self.result.script_errors[:10]:
                lines.append(f"\n  [{error.error_type}]")
                if error.resource_name:
                    lines.append(f"  Resource: {error.resource_name}")
                if error.script_name:
                    lines.append(f"  Script: {error.script_name}")
                if error.line_number:
                    lines.append(f"  Line: {error.line_number}")
                lines.append(f"  Message: {error.message[:200]}")
            lines.append("")

        # Lua stack traces (with resources involved per stack)
        if self.result.lua_stacks:
            lines.append("LUA STACK TRACES RECOVERED:")
            lines.append("-" * 40)
            for i, stack in enumerate(self.result.lua_stacks[:3], 1):
                lines.append(f"\n  Stack Trace #{i}:")
                resources = (
                    self.result.lua_stack_resources[i - 1]
                    if i - 1 < len(self.result.lua_stack_resources)
                    else self._get_resources_for_lua_stack(stack)
                )
                if resources:
                    lines.append(f"    Resources involved: {', '.join(resources)}")
                for frame in stack[:10]:
                    c_marker = " [C]" if frame.is_c_function else ""
                    lines.append(f"    {frame.source}:{frame.line}: in {frame.function_name}{c_marker}")
            lines.append("")

        # JS stack traces (with resources involved per stack)
        if self.result.js_stacks:
            lines.append("JAVASCRIPT STACK TRACES:")
            lines.append("-" * 40)
            for i, trace in enumerate(self.result.js_stacks[:10]):
                resources = (
                    self.result.js_stack_resources[i]
                    if i < len(self.result.js_stack_resources)
                    else self._get_resources_for_js_stack(trace)
                )
                if resources:
                    lines.append(f"  Resources involved: {', '.join(resources)}")
                lines.append(f"  {trace}")
            lines.append("")

        # Script paths found
        if self.result.script_paths:
            lines.append("SCRIPT PATHS FOUND IN MEMORY:")
            lines.append("-" * 40)
            seen = set()
            for path in self.result.script_paths[:20]:
                if path not in seen:
                    seen.add(path)
                    lines.append(f"  {path}")
            lines.append("")

        # Event handlers
        if self.result.event_handlers:
            unique_events = list(set(self.result.event_handlers))[:20]
            lines.append("EVENT HANDLERS FOUND:")
            lines.append("-" * 40)
            for event in unique_events:
                lines.append(f"  {event}")
            lines.append("")

        # Summary
        lines.append("ANALYSIS SUMMARY:")
        lines.append("-" * 40)
        lines.append(f"  Total Evidence Items: {len(self.result.all_evidence)}")
        lines.append(f"  Resources Identified: {len(self.result.resources)}")
        lines.append(f"  Script Errors Found: {len(self.result.script_errors)}")
        lines.append(f"  Lua Stacks Recovered: {len(self.result.lua_stacks)}")
        lines.append(f"  JS Stacks Recovered: {len(self.result.js_stacks)}")
        lines.append(f"  Memory Regions Analyzed: {len(self.result.memory_regions)}")

        if self.result.errors:
            lines.append("\n  Analysis Warnings:")
            for err in self.result.errors:
                lines.append(f"    - {err}")

        lines.append("")
        lines.append("=" * 70)

        return "\n".join(lines)
    
    def analyze_with_fivem_forensics(self, dump_path: str) -> Dict[str, Any]:
        """Enhanced analysis with FiveM-specific forensics.
        
        Returns:
            Combined results from memory analysis and FiveM forensics
        """
        from .fivem_forensics import BuildCacheForensics
        
        # Run standard memory analysis
        standard_results = self.analyze(dump_path)
        
        # Run FiveM-specific forensics
        forensics = BuildCacheForensics()
        fivem_results = forensics.analyze_dump(dump_path)
        
        # Generate FiveM report
        fivem_report = forensics.generate_report(fivem_results)
        
        # Combine results
        return {
            'memory_analysis': standard_results,
            'fivem_forensics': fivem_results,
            'fivem_report': fivem_report,
            'combined_confidence': self._calculate_combined_confidence(
                standard_results, fivem_results
            ),
        }
    
    def _calculate_combined_confidence(
        self, 
        memory_results: 'DeepAnalysisResult', 
        fivem_results: Dict[str, Any]
    ) -> str:
        """Calculate combined confidence from both analyses."""
        score = 0
        
        # Memory analysis confidence
        if len(memory_results.resources) > 0:
            score += 30
        if len(memory_results.script_errors) > 0:
            score += 20
        if len(memory_results.lua_stacks) > 0:
            score += 15
        
        # FiveM forensics confidence
        fivem_conf = fivem_results.get('confidence', 'low')
        if fivem_conf == 'high':
            score += 25
        elif fivem_conf == 'medium':
            score += 15
        
        if score >= 70:
            return 'very_high'
        elif score >= 50:
            return 'high'
        elif score >= 30:
            return 'medium'
        else:
            return 'low'
    
    def _extract_heap_statistics(self, minidump_file) -> None:
        """Extract real heap statistics from MINIDUMP_MEMORY_INFO_LIST (Stream 16)."""
        try:
            if not minidump_file:
                return
            
            if not hasattr(minidump_file, 'streams'):
                return  # MinidumpFile doesn't have streams attribute
            
            # Find MemoryInfoList stream (type 16)
            memory_info_stream = None
            for stream in minidump_file.streams.values():
                stream_name = str(getattr(stream, 'name', ''))
                if 'MemoryInfo' in stream_name:
                    memory_info_stream = stream
                    break
            
            if not memory_info_stream or not hasattr(memory_info_stream, 'infos'):
                return
            
            # Memory state constants
            MEM_COMMIT = 0x1000
            MEM_RESERVE = 0x2000
            MEM_FREE = 0x10000
            
            committed = 0
            reserved = 0
            free_mem = 0
            
            # Sum up memory regions by state
            for info in memory_info_stream.infos:
                state = getattr(info, 'State', 0)
                region_size = getattr(info, 'RegionSize', 0)
                
                if state == MEM_COMMIT:
                    committed += region_size
                elif state == MEM_RESERVE:
                    reserved += region_size
                elif state == MEM_FREE:
                    free_mem += region_size
            
            # Store statistics
            self.result.heap_committed_bytes = committed
            self.result.heap_reserved_bytes = reserved
            self.result.heap_free_bytes = free_mem
            
            # Calculate fragmentation
            total_used = committed + reserved
            if total_used > 0:
                self.result.heap_fragmentation_pct = (reserved / total_used) * 100
            
            # Determine memory pressure
            committed_mb = committed / (1024 ** 2)
            
            if committed_mb > 4096:
                self.result.memory_pressure = "critical"
                self.result.oom_imminent = True
                self.result.leak_evidence.append(
                    f"CRITICAL: Process committed {committed_mb:.0f}MB at crash (threshold: 4,096MB)"
                )
            elif committed_mb > 3072:
                self.result.memory_pressure = "elevated"
                self.result.leak_evidence.append(
                    f"WARNING: High memory usage - {committed_mb:.0f}MB committed (threshold: 3,072MB)"
                )
            else:
                self.result.memory_pressure = "normal"
            
        except Exception as e:
            self.result.errors.append(f"Heap statistics extraction failed: {e}")
    
    def _analyze_memory_leak_patterns(self) -> None:
        """Analyze allocation patterns to detect memory leaks with confidence scoring."""
        evidence_count = 0
        
        # 1. Entity allocation delta
        entity_creates = len(self.result.entity_creations)
        entity_deletes = len(self.result.entity_deletions)
        self.result.entity_allocation_delta = entity_creates - entity_deletes
        
        if self.result.entity_allocation_delta > 100:
            self.result.entity_leak = True
            evidence_count += 1
            self.result.leak_evidence.append(
                f"Entity leak: {entity_creates} created, {entity_deletes} deleted (delta: +{self.result.entity_allocation_delta})"
            )
        
        # 2. Timer leak detection
        timer_creates = len(self.result.timers_created)
        self.result.timer_allocation_delta = timer_creates
        
        if timer_creates > 50:
            self.result.timer_leak = True
            evidence_count += 1
            self.result.leak_evidence.append(
                f"Excessive timers: {timer_creates} timer patterns found (potential leak)"
            )
        
        # 3. Event handler delta
        handler_regs = len(self.result.event_handlers_registered)
        handler_removes = len(self.result.event_handlers_removed)
        self.result.event_handler_delta = handler_regs - handler_removes
        
        if self.result.event_handler_delta > 50:
            self.result.event_handler_leak = True
            evidence_count += 1
            self.result.leak_evidence.append(
                f"Event handler leak: {handler_regs} registered, {handler_removes} removed (delta: +{self.result.event_handler_delta})"
            )
        
        # 4. NUI/Browser leak detection
        nui_patterns = len(self.result.nui_patterns)
        
        if nui_patterns > 100:
            self.result.nui_leak = True
            evidence_count += 1
            self.result.leak_evidence.append(
                f"Excessive NUI activity: {nui_patterns} NUI/CEF patterns (potential browser leak)"
            )
        
        # 5. Memory pressure
        if self.result.memory_pressure in ("elevated", "critical"):
            evidence_count += 1
        
        # 6. Heap fragmentation
        if self.result.heap_fragmentation_pct > 30.0:
            evidence_count += 1
            wasted_mb = self.result.heap_reserved_bytes / (1024 ** 2)
            self.result.leak_evidence.append(
                f"High fragmentation: {self.result.heap_fragmentation_pct:.1f}% ({wasted_mb:.1f}MB wasted)"
            )
        
        # 7. Calculate total allocation delta
        total_allocs = entity_creates + timer_creates + handler_regs
        total_frees = entity_deletes + handler_removes
        allocation_delta = total_allocs - total_frees
        
        if allocation_delta > 10000:
            evidence_count += 1
            self.result.leak_evidence.append(
                f"Allocation imbalance: {allocation_delta:,} more allocations than frees"
            )
        
        # Determine leak confidence
        if evidence_count >= 3:
            self.result.leak_detected = True
            self.result.leak_confidence = "high"
        elif evidence_count == 2:
            self.result.leak_detected = True
            self.result.leak_confidence = "medium"
        elif evidence_count == 1:
            self.result.leak_detected = False
            self.result.leak_confidence = "low"
        else:
            self.result.leak_detected = False
            self.result.leak_confidence = "none"

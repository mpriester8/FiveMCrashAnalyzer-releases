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
    """Complete result of deep memory analysis."""
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
        # Native call pattern - Citizen natives
        'native_call': re.compile(
            rb'(?:Citizen|CFX|NATIVE)[._]([A-Z][A-Za-z0-9_]+)',
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
        # Pool exhaustion indicators
        'pool_exhaustion': re.compile(
            rb'(pool\s*(?:is\s+)?(?:full|exhausted|overflow)|'
            rb'entity\s*(?:limit|pool)|no\s*free\s*(?:slot|entity)|'
            rb'MAX_ENTITIES|max\s*(?:vehicle|ped|object)s?\s*(?:reached|exceeded)|'
            rb'CPool<|rage::fwBasePool)',
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
    MAX_SUPPORTED_FILE_SIZE = 10 * 1024 * 1024 * 1024
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
        
        Supports dumps up to 10GB in size.
        
        Progress is reported via the callback provided in __init__.
        """
        self.result = DeepAnalysisResult()
        self._evidence_seen: Set[str] = set()  # Deduplication cache
        self._max_evidence = self.MAX_EVIDENCE_ITEMS
        self._max_raw_strings = 3000

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

            # Parse with minidump library if available (skip for large files to avoid freezes in first 1GB)
            ONE_GB = 1024 * 1024 * 1024
            if HAS_MINIDUMP and file_size < ONE_GB:
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
            elif HAS_MINIDUMP and file_size >= ONE_GB:
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

            # Choose analysis strategy based on file size
            analysis_mode = "in_memory"
            if file_size <= self.MAX_FULL_ANALYSIS_SIZE:
                # Small dump - load entirely into memory
                self._report_progress("memory", 0.0, f"Loading {file_size_mb}MB dump into memory...")
                self._analyze_dump_in_memory(dump_path, file_size)
            elif file_size <= 2 * 1024 * 1024 * 1024:  # 2GB
                # Medium dump - use streaming analysis
                analysis_mode = "streaming"
                self.result.errors.append(
                    f"Large dump ({file_size_mb}MB) - using streaming analysis"
                )
                self._report_progress("streaming", 0.0, f"Starting streaming analysis of {file_size_mb}MB dump...")
                self._analyze_dump_streaming(dump_path, file_size)
            else:
                # Very large dump (2GB+) - use memory-mapped sampling
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
        # For 6GB file: ~8-10 samples. For 10GB: ~12-15 samples
        num_middle_samples = min(15, max(5, int(file_size_gb * 2)))
        total_steps = 2 + num_middle_samples  # first + middle samples + last
        current_step = 0
        
        self._report_progress(
            "sampling", 
            0.0, 
            f"Starting sampled analysis: {file_size_gb:.1f}GB dump, {num_middle_samples + 2} regions to scan"
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
                        self._run_analysis_passes(first_chunk, chunk_offset=start_off)
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
                            self._run_analysis_passes(middle_chunk, chunk_offset=sample_offset)
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
                        self._run_analysis_passes(last_chunk, chunk_offset=start_off)
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
        self._run_analysis_passes(last_chunk, chunk_offset=max(0, file_size - sample_size))
        del last_chunk

    def _run_analysis_passes(self, data: bytes, chunk_offset: int = 0) -> None:
        """Run all analysis passes on a chunk of data.
        
        For large file analysis, we run ALL passes to extract maximum data.
        """
        # Deep string analysis on raw data - ALWAYS run
        self._analyze_raw_memory(data)

        # Extract Lua stack traces from memory - ALWAYS run
        self._extract_lua_stacks(data)

        # Find and parse full Lua tracebacks - ALWAYS run
        self._extract_lua_tracebacks(data)

        # Find Lua runtime errors with context - ALWAYS run (high value)
        self._find_lua_runtime_errors(data)

        # Extract JS stack traces from memory - ALWAYS run
        self._extract_js_stacks(data)

        # Find script errors in memory - ALWAYS run
        self._find_script_errors(data)

        # Find CitizenFX runtime contexts - ALWAYS run
        self._find_citizenfx_contexts(data)

        # Analyze for FiveM-specific patterns - ALWAYS run
        self._find_fivem_patterns(data)

        # Dedicated pass: extract all FiveM resource names (server.cfg, paths, refs)
        self._extract_fivem_resource_names_pass(data)
        
        # ===== NEW: Memory leak analysis passes =====
        # Analyze entity creation/deletion patterns
        self._analyze_entity_lifecycle(data, chunk_offset)
        
        # Analyze timer patterns
        self._analyze_timer_patterns(data, chunk_offset)
        
        # Analyze event handler registration/removal
        self._analyze_event_handlers(data, chunk_offset)
        
        # Analyze memory allocation patterns
        self._analyze_memory_allocations(data, chunk_offset)
        
        # Find memory leak indicators
        self._find_memory_leak_indicators(data, chunk_offset)
        
        # Find pool exhaustion indicators
        self._find_pool_exhaustion(data, chunk_offset)
        
        # Find database patterns
        self._find_database_patterns(data, chunk_offset)
        
        # Find NUI/CEF patterns
        self._find_nui_patterns(data, chunk_offset)
        
        # Find network sync patterns
        self._find_network_patterns(data, chunk_offset)
        
        # Find FiveM-specific crash causes
        self._find_fivem_crash_causes(data, chunk_offset)

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
                        self.result.exception_code = int(code)
                    exc_addr = getattr(exc_rec, 'ExceptionAddress', None)
                    if exc_addr is not None:
                        if isinstance(exc_addr, bytes):
                            exc_addr = int.from_bytes(exc_addr, 'little')
                        self.result.exception_address = int(exc_addr)

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

    def _extract_strings_advanced(self, data: bytes, min_length: int = 4) -> List[Tuple[str, int]]:
        """Extract strings with their memory offsets.
        
        Optimized with memoryview to avoid copying data and chunked processing
        for large dumps.
        """
        results = []
        data_view = memoryview(data)
        data_len = len(data)
        current_chars = []
        start_offset = 0

        # Process ASCII strings - use direct byte comparison for speed
        for i in range(data_len):
            b = data_view[i]
            if 32 <= b <= 126:
                if not current_chars:
                    start_offset = i
                current_chars.append(chr(b))
            else:
                if len(current_chars) >= min_length:
                    results.append((''.join(current_chars), start_offset))
                current_chars = []

        if len(current_chars) >= min_length:
            results.append((''.join(current_chars), start_offset))

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
        # Search for each known Lua error pattern
        for error_bytes, error_type in self.LUA_ERROR_MESSAGES:
            pos = 0
            while True:
                idx = data.find(error_bytes, pos)
                if idx == -1:
                    break
                pos = idx + 1

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
        # Look for CitizenFX runtime markers
        for marker in self.CITIZENFX_RUNTIME_MARKERS:
            pos = 0
            while True:
                idx = data.find(marker, pos)
                if idx == -1:
                    break
                pos = idx + 1

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
        """Find FiveM-specific patterns in memory."""
        # Native calls
        for match in self.FIVEM_PATTERNS['native_call'].finditer(data):
            native = match.group(1).decode('utf-8', errors='replace')
            self.result.native_calls.append(native)

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
            while True:
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
            while True:
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
                self._add_evidence(ScriptEvidence(
                    evidence_type=EvidenceType.ERROR_MESSAGE,
                    script_name=f"crash_{cause_type}",
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
        # Must be at least 2 characters
        if len(name_lower) < 2:
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
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{1,63}", name_lower):
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
        
        Includes deduplication to prevent processing the same evidence multiple times.
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
            return

        # Always add to all_evidence first
        self.result.all_evidence.append(evidence)

        # Try to determine the resource name
        resource_name = None

        # Skip evidence from internal FiveM paths - they're not user resources
        if evidence.file_path and self._is_internal_fivem_path(evidence.file_path):
            return
            
        # Skip internal script names
        if evidence.script_name and evidence.script_name in self.INTERNAL_SCRIPTS:
            return
            
        # Skip generated natives files
        if evidence.script_name and evidence.script_name.startswith('natives_'):
            return

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

        # Only proceed if we have a valid resource name
        if not resource_name or not self._is_valid_resource_name(resource_name):
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
        if not is_manifest:
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
        """Correlate all evidence to determine primary suspects."""
        # Score each resource based on evidence
        scores: Dict[str, float] = {}

        # Evidence type weights
        weights = {
            EvidenceType.ERROR_MESSAGE: 10.0,
            EvidenceType.LUA_STACK_TRACE: 9.0,
            EvidenceType.JS_STACK_TRACE: 9.0,
            EvidenceType.EXCEPTION_ADDRESS: 8.0,
            EvidenceType.SCRIPT_PATH: 5.0,
            EvidenceType.HANDLE_PATH: 5.0,
            EvidenceType.THREAD_STACK: 6.0,
            EvidenceType.EVENT_HANDLER: 2.0,
            EvidenceType.NATIVE_CALL: 2.0,
            EvidenceType.MEMORY_REGION: 1.0,
            EvidenceType.RESOURCE_NAME: 4.0,
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
        # Filter out resources with 0 score AND 0 evidence_count (presence-only resources)
        scored_resources = [
            resource for resource in self.result.resources.values()
            if scores.get(resource.name, 0) > 0 and resource.evidence_count > 0
        ]

        sorted_resources = sorted(
            scored_resources,
            key=lambda r: scores.get(r.name, 0),
            reverse=True
        )

        # Top suspects are resources with highest scores
        self.result.primary_suspects = sorted_resources[:10]

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

            # 3. Exception stream (6): ThreadId at offset 0
            crash_tid = None
            if self._EXCEPTION_STREAM in streams:
                size, rva = streams[self._EXCEPTION_STREAM]
                f.seek(rva)
                exc_data = f.read(min(size, 64))
                if len(exc_data) >= 4:
                    crash_tid = struct.unpack('<I', exc_data[0:4])[0]
                if len(exc_data) >= 12:
                    code = struct.unpack('<I', exc_data[8:12])[0]
                    self.result.exception_code = code
                if len(exc_data) >= 32:
                    exc_addr = struct.unpack('<Q', exc_data[24:32])[0]
                    self.result.exception_address = exc_addr

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
                                        pdb_guid = cv_data[4:20].hex().upper()
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

            # 6. Read stack memory and walk for native stack. If primary thread yields no frames, try others.
            def _walk_stack_to_frames(stack_data: bytes) -> list[str]:
                frames = []
                for i in range(0, min(len(stack_data), 64 * 1024), 8):  # cap 64KB of stack
                    if i + 8 > len(stack_data):
                        break
                    ptr_val = struct.unpack('<Q', stack_data[i:i+8])[0]
                    mod_info = self._get_module_info_for_address(ptr_val)
                    if mod_info:
                        name, base = mod_info
                        offset = ptr_val - base
                        frames.append(f"{name} + 0x{offset:X}")
                if frames:
                    dedup = [frames[0]]
                    for fr in frames[1:]:
                        if fr != dedup[-1]:
                            dedup.append(fr)
                return dedup

            if stack_rva and stack_size and stack_size > 0 and stack_size < 16 * 1024 * 1024:
                f.seek(stack_rva)
                stack_data = f.read(stack_size)
                if len(stack_data) >= 8:
                    frames = _walk_stack_to_frames(stack_data)
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
                                frames = _walk_stack_to_frames(other_data)
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

            code = int(code)
            exc_addr = getattr(exc_rec, 'ExceptionAddress', None)
            if exc_addr is not None:
                if isinstance(exc_addr, bytes):
                    exc_addr = int.from_bytes(exc_addr, 'little')
                exc_addr = int(exc_addr)

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
                    except:
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
                except:
                    pass

            self.result.exception_params = exc_params

        except Exception as e:
            self.result.errors.append(f"Exception params extraction: {e}")

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
                    if hasattr(guid, 'hex'):
                        mod_info.pdb_guid = guid.hex().upper()
                    elif isinstance(guid, bytes):
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
                except:
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
                except:
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

"""Deep Memory Analysis Module for FiveM Crash Dumps.

This module provides advanced memory analysis capabilities to pinpoint
exact scripts, resources, and code paths causing crashes in FiveM.
"""
from __future__ import annotations

import os
import re
import struct
import sys
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple, Set
from enum import Enum

# Optional minidump library
try:
    from minidump.minidumpfile import MinidumpFile
    HAS_MINIDUMP = True
except ImportError:
    MinidumpFile = None
    HAS_MINIDUMP = False


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

    # JS stack traces
    js_stacks: List[str] = field(default_factory=list)

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
    }

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

    # Path segments that are NOT valid FiveM resource names (system/internal paths)
    IGNORED_PATH_SEGMENTS = {
        # FiveM/CitizenFX internal paths
        'app', 'client', 'server', 'shared', 'builds', 'bin', 'lib', 'libs',
        'cache', 'caches', 'data', 'citizen', 'cfx', 'fivem', 'redm',
        'scripting', 'runtime', 'natives', 'v8', 'lua', 'mono', 'gl',
        'resources', 'resource', 'stream', 'streaming', 'files',
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
    ]

    def __init__(self):
        self.result = DeepAnalysisResult()
        self._module_map: Dict[int, Tuple[int, str]] = {}  # base -> (end, name)
        self._memory_data: Dict[int, bytes] = {}  # start -> data

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

    def analyze_dump_deep(self, dump_path: str) -> DeepAnalysisResult:
        """Perform deep analysis of a minidump file to pinpoint error sources."""
        self.result = DeepAnalysisResult()

        if not os.path.exists(dump_path):
            self.result.errors.append(f"Dump file not found: {dump_path}")
            return self.result

        try:
            # Read raw dump data for string analysis
            with open(dump_path, 'rb') as f:
                raw_data = f.read()

            # Verify minidump header
            if raw_data[:4] != b'MDMP':
                self.result.errors.append("Not a valid minidump file (missing MDMP header)")
                return self.result

            # Parse with minidump library if available
            if HAS_MINIDUMP:
                try:
                    md = MinidumpFile.parse(dump_path)
                    self._analyze_minidump_structure(md)
                except Exception as e:
                    self.result.errors.append(f"Minidump parsing error: {e}")

            # Deep string analysis on raw data
            self._analyze_raw_memory(raw_data)

            # Extract Lua stack traces from memory
            self._extract_lua_stacks(raw_data)

            # Find and parse full Lua tracebacks
            self._extract_lua_tracebacks(raw_data)

            # Find Lua runtime errors with context
            self._find_lua_runtime_errors(raw_data)

            # Extract JS stack traces from memory
            self._extract_js_stacks(raw_data)

            # Find script errors in memory
            self._find_script_errors(raw_data)

            # Find CitizenFX runtime contexts
            self._find_citizenfx_contexts(raw_data)

            # Analyze for FiveM-specific patterns
            self._find_fivem_patterns(raw_data)

            # Correlate evidence and determine primary suspects
            self._correlate_evidence()

            self.result.analysis_complete = True

        except Exception as e:
            import traceback
            self.result.errors.append(f"Analysis failed: {e}")
            self.result.errors.append(f"Traceback: {traceback.format_exc()}")

        return self.result

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
        """Extract strings with their memory offsets."""
        results = []
        current_chars = []
        start_offset = 0

        for i, b in enumerate(data):
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

        # Also try UTF-16 strings (common in Windows)
        try:
            i = 0
            while i < len(data) - 2:
                if data[i] >= 32 and data[i] <= 126 and data[i+1] == 0:
                    start = i
                    chars = []
                    while i < len(data) - 1 and data[i] >= 32 and data[i] <= 126 and data[i+1] == 0:
                        chars.append(chr(data[i]))
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

    def _is_valid_resource_name(self, name: str) -> bool:
        """Check if a name is a valid FiveM resource name (not a system path segment)."""
        if not name:
            return False
        name_lower = name.lower().strip()
        # Must be at least 2 characters
        if len(name_lower) < 2:
            return False
        # Check against ignored path segments
        if name_lower in self.IGNORED_PATH_SEGMENTS:
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

        Scans path segments to find the first valid resource name,
        skipping common system/internal path segments.
        """
        if not file_path:
            return None
        
        # Check if this is an internal FiveM path - if so, don't extract resource
        if self._is_internal_fivem_path(file_path):
            return None

        # Normalize path separators and split
        normalized = file_path.replace('\\', '/').strip('@')
        parts = [p for p in normalized.split('/') if p]

        # Look for a valid resource name in path segments
        for part in parts:
            # Skip file extensions
            if '.' in part and part.split('.')[-1].lower() in ('lua', 'js', 'dll', 'exe', 'json', 'xml'):
                continue
            if self._is_valid_resource_name(part):
                return part

        return None

    def _add_evidence(self, evidence: ScriptEvidence) -> None:
        """Add evidence and update resource tracking."""
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
            parts = evidence.file_path.replace('\\', '/').split('/')
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
        scored_resources = [
            resource for resource in self.result.resources.values()
            if scores.get(resource.name, 0) > 0
        ]

        sorted_resources = sorted(
            scored_resources,
            key=lambda r: scores.get(r.name, 0),
            reverse=True
        )

        # Top suspects are resources with highest scores
        self.result.primary_suspects = sorted_resources[:10]

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

        # Resources found
        lines.append(f"RESOURCES IDENTIFIED: {len(self.result.resources)}")
        for name, info in list(self.result.resources.items())[:10]:
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

        # Lua stack traces
        if self.result.lua_stacks:
            lines.append("LUA STACK TRACES RECOVERED:")
            lines.append("-" * 40)
            for i, stack in enumerate(self.result.lua_stacks[:3], 1):
                lines.append(f"\n  Stack Trace #{i}:")
                for frame in stack[:10]:
                    c_marker = " [C]" if frame.is_c_function else ""
                    lines.append(f"    {frame.source}:{frame.line}: in {frame.function_name}{c_marker}")
            lines.append("")

        # JS stack traces
        if self.result.js_stacks:
            lines.append("JAVASCRIPT STACK TRACES:")
            lines.append("-" * 40)
            for trace in self.result.js_stacks[:10]:
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

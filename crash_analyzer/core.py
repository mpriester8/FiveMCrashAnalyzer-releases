"""Core crash analysis logic for FiveM Crash Analyzer.

This module provides comprehensive crash analysis including deep memory analysis,
script/resource pinpointing, and detailed error attribution.
"""
from __future__ import annotations

import os
import re
import sys
import struct
import tempfile
import urllib.parse
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple, Set

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

    # Script errors
    script_errors: List[ScriptError] = field(default_factory=list)

    # Stack traces
    lua_stacks: List[List[LuaStackFrame]] = field(default_factory=list)
    js_stacks: List[str] = field(default_factory=list)
    native_stacks: List[str] = field(default_factory=list)

    # Pattern matches
    crash_patterns: List[PatternMatch] = field(default_factory=list)

    # Modules
    modules: List[Dict[str, Any]] = field(default_factory=list)
    identified_modules: List[Dict[str, str]] = field(default_factory=list)

    # Resources from logs
    log_resources: List[str] = field(default_factory=list)
    log_errors: List[Dict[str, Any]] = field(default_factory=list)

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


class Symbolicator:
    """Symbol downloader and address resolver for Windows minidumps."""

    def __init__(self, symbol_server: str = "https://runtime.fivem.net/client/symbols/"):
        self.server = symbol_server
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
                r = requests.get(url, stream=True, timeout=10)
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
        if not HAS_REQUESTS or not pdb_name or not guid:
            return None

        cache_key = f"{pdb_name}_{guid}_{age}"
        if cache_key in self._symbol_cache:
            return self._symbol_cache[cache_key]

        guid_str = str(guid).upper().replace('-', '')
        age_str = str(int(age)) if age is not None else '0'
        combined = guid_str + age_str

        # Try primary path
        path = f"{pdb_name}/{combined}/{pdb_name}"
        url = urllib.parse.urljoin(self.server, path)
        try:
            r = requests.get(url, stream=True, timeout=10)
            if r.status_code == 200:
                fd, tmp = tempfile.mkstemp(suffix='_' + pdb_name)
                with os.fdopen(fd, 'wb') as f:
                    for chunk in r.iter_content(8192):
                        f.write(chunk)
                self._symbol_cache[cache_key] = tmp
                return tmp
        except Exception:
            pass

        # Try fallback path
        try:
            url2 = urllib.parse.urljoin(self.server, f"{pdb_name}/{guid_str}/{pdb_name}")
            r2 = requests.get(url2, stream=True, timeout=8)
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

    def __init__(self):
        """Initialize the crash analyzer."""
        self._has_minidump = HAS_MINIDUMP
        self.memory_analyzer = MemoryAnalyzer()

        # Initialize symbolicator (Windows only)
        try:
            self.symbolicator = Symbolicator()
        except Exception:
            self.symbolicator = None

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
        pattern_camel = re.compile(r'[A-Z][a-z]+(?:[A-Z][a-z]+)+')

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
            for m in pattern_camel.finditer(s):
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
        text_lower = all_text.lower()

        for pattern, details in self.CRASH_PATTERNS.items():
            if re.search(pattern, text_lower):
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
        for encoding in ['utf-8', 'utf-16', 'latin-1', 'cp1252']:
            try:
                with open(log_path, 'r', encoding=encoding) as f:
                    content = f.read()
                break
            except Exception:
                continue

        if content is None:
            info['error'] = 'Could not read log file'
            return info

        lines = content.splitlines()

        # Patterns for log analysis
        lua_error_pattern = re.compile(
            r'([A-Za-z0-9_\-/\\]+\.lua):(\d+):\s*(.+)',
            re.IGNORECASE
        )
        resource_pattern = re.compile(
            r'(?:resource|script|started|stopped|Starting|Stopping)\s+[\'\"]?([A-Za-z0-9_\-]+)[\'\"]?',
            re.IGNORECASE
        )
        citizen_error_pattern = re.compile(
            r'(?:SCRIPT\s*ERROR|Error\s*running|error\s*in).*?(?:@?([A-Za-z0-9_\-]+))?',
            re.IGNORECASE
        )

        for i, line in enumerate(lines):
            l = line.strip()
            lower = l.lower()

            # Detect errors
            if 'error' in lower or 'exception' in lower or 'crash' in lower:
                info['errors'].append({'line': i + 1, 'content': l[:300]})

                # Check for Lua errors
                lua_match = lua_error_pattern.search(l)
                if lua_match:
                    info['lua_errors'].append({
                        'file': lua_match.group(1),
                        'line': int(lua_match.group(2)),
                        'message': lua_match.group(3)[:200],
                        'log_line': i + 1
                    })

                # Check for Citizen/FiveM errors
                citizen_match = citizen_error_pattern.search(l)
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
            resource_match = resource_pattern.search(l)
            if resource_match:
                res = resource_match.group(1)
                if res and res not in info['resources'] and len(res) > 1:
                    info['resources'].append(res)

            # Detect stack traces
            if 'stack trace' in lower or 'call stack' in lower or 'traceback' in lower:
                context = '\n'.join(lines[i:i+10])
                info['crash_indicators'].append({
                    'line': i + 1,
                    'context': context
                })

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
            report.script_errors = deep_result.script_errors
            report.lua_stacks = deep_result.lua_stacks
            report.js_stacks = deep_result.js_stacks
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
            report.memory_info = deep_result.memory_info
            report.process_stats = deep_result.process_stats
            report.function_table_entries = deep_result.function_table_entries
            report.comment_stream_a = deep_result.comment_stream_a
            report.comment_stream_w = deep_result.comment_stream_w
            report.assertion_info = deep_result.assertion_info

            # Basic dump analysis for patterns
            basic_dump = self.analyze_dump(dump_path)
            if 'modules' in basic_dump:
                for mod in basic_dump['modules']:
                    report.modules.append({'name': mod})

            # Identify known modules
            module_names = [m['name'] for m in report.modules if 'name' in m]
            report.identified_modules = self.identify_modules(module_names)

            # Match crash patterns
            all_strings = ' '.join(basic_dump.get('raw_data', []))
            patterns = self.match_patterns(all_strings)
            report.crash_patterns = patterns

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

        return report

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
            for i, suspect in enumerate(report.primary_suspects[:5], 1):
                lines.append("")
                lines.append(f"  #{i} RESOURCE: {suspect.name}")
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

        # Lua stack traces
        if report.lua_stacks:
            lines.append("LUA STACK TRACES:")
            lines.append("-" * 40)
            for i, stack in enumerate(report.lua_stacks[:3], 1):
                lines.append(f"\n  Stack #{i}:")
                for frame in stack[:8]:
                    func = frame.function_name or '(anonymous)'
                    lines.append(f"    {frame.source}:{frame.line} in {func}")
            lines.append("")

        # JS stack traces
        if report.js_stacks:
            lines.append("JAVASCRIPT STACK TRACES:")
            lines.append("-" * 40)
            for trace in report.js_stacks[:10]:
                lines.append(f"  {trace}")
            lines.append("")

        # Native stack traces
        if report.native_stacks:
            lines.append("NATIVE STACK TRACE (Crashing Thread):")
            lines.append("-" * 40)
            for frame in report.native_stacks:
                lines.append(f"  {frame}")
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
            lines.append(f"MOST LIKELY CAUSE: Resource '{top.name}'")
            if top.scripts:
                lines.append(f"  Scripts: {', '.join(top.scripts[:3])}")
            lines.append(f"  Evidence: {top.evidence_count} items")
            lines.append(f"  Types: {', '.join(e.name for e in list(top.evidence_types)[:3])}")
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

    def get_diagnostic_recommendations(self, report: CrashReport) -> str:
        """Generate recommendations for gathering additional diagnostic information."""
        lines = []
        lines.append("=" * 70)
        lines.append("ADDITIONAL DIAGNOSTIC INFORMATION THAT WOULD HELP")
        lines.append("=" * 70)
        lines.append("")

        # Check what we already have
        has_logs = bool(report.log_files and report.log_errors)
        has_suspects = bool(report.primary_suspects)
        has_script_errors = bool(report.script_errors)
        has_stacks = bool(report.lua_stacks or report.js_stacks)

        # Determine crash type
        is_graphics_crash = any('Graphics Driver' in p.issue for p in report.crash_patterns)
        is_oom = any('Out of Memory' in p.issue for p in report.crash_patterns)
        is_access_violation = report.exception_code == 0xC0000005 if report.exception_code else False

        lines.append("1. FIVEM LOG FILES (Most Important!):")
        lines.append("-" * 40)
        if not has_logs or not has_script_errors:
            lines.append("  ⚠ MISSING - These provide critical context!")
        else:
            lines.append("  ✓ Provided")
        lines.append("")
        lines.append("  Location: %LocalAppData%\\FiveM\\FiveM.app\\logs\\")
        lines.append("  Files to include:")
        lines.append("    • CitizenFX.log (main client log)")
        lines.append("    • CitizenFX_log_*.txt (previous sessions)")
        lines.append("    • crashes.log (crash history)")
        lines.append("  These contain script errors, resource loading, and detailed stack traces.")
        lines.append("")

        lines.append("2. SERVER CONSOLE LOGS:")
        lines.append("-" * 40)
        lines.append("  If available, server-side logs showing:")
        lines.append("    • Resource loading/errors before crash")
        lines.append("    • Server-side script errors")
        lines.append("    • Player events leading to crash")
        lines.append("  Location: [Server Directory]/console.log or txAdmin logs")
        lines.append("")

        lines.append("3. SYSTEM INFORMATION:")
        lines.append("-" * 40)
        if is_graphics_crash:
            lines.append("  ⚠ IMPORTANT for Graphics Driver crashes!")
        lines.append("  Helpful information:")
        lines.append("    • Graphics card model and driver version")
        lines.append("    • RAM amount (Total/Available)")
        lines.append("    • Windows version")
        lines.append("    • FiveM build number")
        lines.append("  To get: Run 'dxdiag' and save the report")
        lines.append("")

        lines.append("4. FIVEM SETTINGS & CONFIGURATION:")
        lines.append("-" * 40)
        lines.append("  Files to include:")
        lines.append("    • fivem_set.bin (game settings)")
        lines.append("    • caches.xml (resource cache info)")
        lines.append("    • %LocalAppData%\\FiveM\\FiveM.app\\crashes.xml")
        lines.append("")

        lines.append("5. CRASH CONTEXT:")
        lines.append("-" * 40)
        lines.append("  Information that helps:")
        lines.append("    • What were you doing when it crashed?")
        lines.append("    • Does it crash consistently or randomly?")
        lines.append("    • Recent changes (new resources, game update, driver update)?")
        lines.append("    • How long into gameplay does it crash?")
        lines.append("    • Any error messages before crash?")
        lines.append("")

        # Specific recommendations based on crash type
        lines.append("=" * 70)
        lines.append("SPECIFIC RECOMMENDATIONS FOR THIS CRASH:")
        lines.append("=" * 70)
        lines.append("")

        if is_graphics_crash:
            lines.append("This appears to be a GRAPHICS DRIVER CRASH:")
            lines.append("  • Update GPU drivers (NVIDIA/AMD)")
            lines.append("  • Lower graphics settings in-game")
            lines.append("  • Disable ReShade/ENB if installed")
            lines.append("  • Check GPU temperature (might be overheating)")
            lines.append("  • Verify game files integrity")
            lines.append("  • Try running in DX10/DX11 mode instead of Vulkan (or vice versa)")
            lines.append("")

        if is_oom:
            lines.append("This appears to be an OUT OF MEMORY crash:")
            lines.append("  • Check your server's streaming assets (reduce if excessive)")
            lines.append("  • Limit number of active resources")
            lines.append("  • Look for memory leaks in custom scripts")
            lines.append("  • Increase system RAM if <16GB")
            lines.append("  • Check for scripts that don't clean up entities/objects")
            lines.append("")

        if is_access_violation and not has_suspects:
            lines.append("ACCESS VIOLATION with no specific resource identified:")
            lines.append("  • Likely a native code issue or corrupted game files")
            lines.append("  • Verify GTA V game files via Steam/Epic")
            lines.append("  • Update FiveM to latest version")
            lines.append("  • Disable recently added native DLLs/mods")
            lines.append("  • Check CitizenFX.log for script errors leading up to crash")
            lines.append("")

        if not has_stacks and not has_script_errors:
            lines.append("NO SCRIPT CONTEXT FOUND in dumps:")
            lines.append("  • This usually means crash is in native/engine code")
            lines.append("  • CitizenFX.log is CRITICAL to understand what scripts were running")
            lines.append("  • Check if crash happens with ALL resources disabled")
            lines.append("  • Try with minimal resource set to isolate issue")
            lines.append("")

        # How to use logs with analyzer
        lines.append("=" * 70)
        lines.append("HOW TO ANALYZE WITH THESE FILES:")
        lines.append("=" * 70)
        lines.append("")
        lines.append("1. In the analyzer GUI:")
        lines.append("   • Select .dmp files (you've done this)")
        lines.append("   • Click 'Select Log Files' and add:")
        lines.append("      - CitizenFX.log")
        lines.append("      - server console logs (if available)")
        lines.append("   • Click 'Analyze' again")
        lines.append("")
        lines.append("2. The analyzer will extract:")
        lines.append("   • Script errors from logs")
        lines.append("   • Resource loading order")
        lines.append("   • Events before crash")
        lines.append("   • Correlated with memory dump data")
        lines.append("")

        lines.append("=" * 70)
        lines.append("QUICK CHECKLIST:")
        lines.append("=" * 70)
        status = "✓" if has_logs else "☐"
        lines.append(f"  {status} CitizenFX.log included")
        status = "✓" if has_suspects else "☐"
        lines.append(f"  {status} Specific resource identified")
        status = "✓" if has_stacks else "☐"
        lines.append(f"  {status} Stack traces found")
        lines.append("  ☐ GPU driver version checked")
        lines.append("  ☐ Recent changes documented")
        lines.append("  ☐ Crash reproduction steps known")
        lines.append("")

        return "\n".join(lines)

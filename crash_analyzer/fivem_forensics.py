"""FiveM-Specific Crash Forensics Module.

This module implements advanced forensics patterns discovered from the FiveM
(CitizenFX) codebase, including:
- Crashometry telemetry analysis
- RSC7 (RockStar Cache 7) format validation
- Streaming system crash diagnostics
- Resource cache corruption detection
- Build cache integrity validation
- Scripting runtime exception analysis
"""
from __future__ import annotations

import hashlib
import os
import re
import struct
import threading
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, Set


# ============================================================================
# Crashometry System (FiveM Telemetry Breadcrumbs)
# ============================================================================

class CrashometryMarker(Enum):
    """Known crashometry keys used by FiveM for crash forensics."""
    
    # Resource Cache Corruption Markers
    RCD_CORRUPTED_FILE = "rcd_corrupted_file"  # SHA1 hash mismatch
    RCD_CORRUPTED_READ = "rcd_corrupted_read"  # EOF during stream read
    RCD_INVALID_RESOURCE = "rcd_invalid_resource"  # Bad RSC7 header
    
    # Heap Error Markers
    HEAP_ERROR_GENERIC = "heap_error"
    HEAP_ERROR_CORRUPTION = "heap_error_corruption"
    HEAP_ERROR_OOM = "heap_error_oom"  # Out of Memory
    
    # Streaming Markers
    STREAMING_CRASH = "streaming_crash"
    STREAMING_TIMEOUT = "streaming_timeout"
    
    # Script Runtime Markers
    SCRIPT_ERROR_LUA = "script_error_lua"
    SCRIPT_ERROR_JS = "script_error_js"
    SCRIPT_ERROR_MONO = "script_error_mono"
    
    # Cache Loading Markers
    CACHE_LOAD_HOOK = "cache_load_hook"
    CACHE_MOUNT_FAILURE = "cache_mount_failure"


@dataclass
class CrashometryEntry:
    """A single key-value pair from the crashometry file."""
    key: str
    value: str
    marker_type: Optional[CrashometryMarker] = None
    
    def __post_init__(self):
        # Try to match known markers
        for marker in CrashometryMarker:
            if self.key == marker.value or self.key.startswith(marker.value):
                self.marker_type = marker
                break


# ============================================================================
# RSC7 Format (RockStar Cache 7)
# ============================================================================

@dataclass
class RSC7Header:
    """RSC7 file format header (16 bytes).
    
    RSC7 is the binary format used by GTA V for game assets (.ytd, .ydr, .ydd).
    Structure from ResourceCacheDeviceV2.cpp:
        uint32_t magic;      // 0x37435352 ('RSC7' little-endian)
        uint32_t version;    // Format version (typically 0)
        uint32_t virtPages;  // Virtual page count
        uint32_t physPages;  // Physical page count
    """
    magic: int
    version: int
    virt_pages: int
    phys_pages: int
    
    @staticmethod
    def from_bytes(data: bytes) -> Optional['RSC7Header']:
        """Parse RSC7 header from raw bytes."""
        if len(data) < 16:
            return None
        
        try:
            magic, version, virt_pages, phys_pages = struct.unpack('<IIII', data[:16])
            return RSC7Header(magic, version, virt_pages, phys_pages)
        except struct.error:
            return None
    
    def is_valid(self) -> bool:
        """Validate RSC7 magic bytes and basic sanity checks."""
        # Magic must be 0x37435352 ('RSC7')
        if self.magic != 0x37435352:
            return False
        
        # Version should be reasonable (observed: 0-10)
        if self.version > 100:
            return False
        
        # Page counts should be reasonable (< 1 million pages)
        if self.virt_pages > 1_000_000 or self.phys_pages > 1_000_000:
            return False
        
        return True
    
    def get_total_size(self) -> int:
        """Calculate total file size from page counts (4KB pages)."""
        return (self.virt_pages + self.phys_pages) * 4096
    
    def has_page_allocation_error(self) -> bool:
        """Check for page allocation inconsistencies."""
        # Virtual pages should generally be >= physical pages
        if self.phys_pages > self.virt_pages * 2:
            return True
        # Extreme imbalance indicates corruption
        if self.virt_pages > 0 and self.phys_pages == 0:
            return True
        return False
    
    def __str__(self) -> str:
        magic_str = bytes([
            (self.magic >> 0) & 0xFF,
            (self.magic >> 8) & 0xFF,
            (self.magic >> 16) & 0xFF,
            (self.magic >> 24) & 0xFF,
        ]).decode('ascii', errors='replace')
        return f"RSC7[magic={magic_str}(0x{self.magic:08X}), v{self.version}, virt={self.virt_pages}, phys={self.phys_pages}]"


# ============================================================================
# Streaming System Diagnostics
# ============================================================================

@dataclass
class StreamingRequest:
    """Diagnostic data from a streaming crash (pgReadData_pgReadRequest).
    
    From CrashFixes.StreamingForceCrash.cpp - captures exact crash location
    in streaming file operation.
    """
    handle: int  # File handle
    offset: int  # Offset in file where crash occurred
    buffer_index: int  # Index in streaming buffer pool
    count: int  # Number of bytes being read
    
    @staticmethod
    def from_memory(data: bytes, offset: int = 0) -> Optional['StreamingRequest']:
        """Extract streaming request from memory dump (structure size varies by build)."""
        # Attempt to parse 32-byte structure (typical for x64)
        if len(data) < offset + 32:
            return None
        
        try:
            # Assuming: handle(8), offset(8), buffer_idx(4), count(4), padding(8)
            handle = struct.unpack('<Q', data[offset:offset+8])[0]
            file_offset = struct.unpack('<Q', data[offset+8:offset+16])[0]
            buffer_idx = struct.unpack('<I', data[offset+16:offset+20])[0]
            count = struct.unpack('<I', data[offset+20:offset+24])[0]
            
            return StreamingRequest(handle, file_offset, buffer_idx, count)
        except struct.error:
            return None


# ============================================================================
# Cache Metadata Reconstruction
# ============================================================================

@dataclass
class CacheFileMetadata:
    """Reconstructed metadata from cache file paths and patterns."""
    cache_path: str  # e.g., cache:/game_rpf/x64e/...
    original_file: Optional[str] = None
    resource_name: Optional[str] = None
    sha1_hash: Optional[str] = None
    file_size: Optional[int] = None
    asset_type: Optional[str] = None  # Derived from extension
    compression_flag: bool = False
    
    @staticmethod
    def extract_asset_type(path: str) -> Optional[str]:
        """Extract asset type from file extension."""
        ext_map = {
            '.ytd': 'Texture Dictionary',
            '.ydr': 'Drawable',
            '.ydd': 'Drawable Dictionary',
            '.yft': 'Fragment',
            '.ybn': 'Bounds',
            '.ycd': 'Clip Dictionary',
            '.ymap': 'Map File',
            '.ytyp': 'Type Data',
            '.ymf': 'Manifest',
            '.awc': 'Audio Wave Container',
            '.rpf': 'Resource Package File',
        }
        for ext, asset_type in ext_map.items():
            if path.lower().endswith(ext):
                return asset_type
        return None


@dataclass
class TransactionState:
    """Cache transaction/write state at crash time."""
    has_temp_files: bool = False
    has_lock_files: bool = False
    incomplete_writes: List[str] = field(default_factory=list)
    transaction_id: Optional[str] = None
    

@dataclass
class CachePoolDiagnostics:
    """Memory pool allocation diagnostics for cache system."""
    pool_size_limit: Optional[int] = None
    current_allocation: Optional[int] = None
    failed_allocation_size: Optional[int] = None
    fragmentation_detected: bool = False
    allocation_failures: List[Dict[str, Any]] = field(default_factory=list)


# ============================================================================
# Resource Cache Forensics
# ============================================================================

@dataclass
class CacheCorruptionEvidence:
    """Evidence of resource cache corruption."""
    corruption_type: str  # 'sha1_mismatch', 'read_error', 'invalid_rsc7', 'concurrent_access', 'page_allocation_error', 'transaction_incomplete'
    file_path: str
    details: Dict[str, Any] = field(default_factory=dict)
    
    # Enhanced metadata
    asset_type: Optional[str] = None  # YTD, YDR, YDD, YFT, etc.
    expected_size: Optional[int] = None
    actual_size: Optional[int] = None
    sha1_hash: Optional[str] = None
    resource_name: Optional[str] = None  # Extracted from cache path
    severity: str = "medium"  # low, medium, high, critical
    
    def __str__(self) -> str:
        parts = [f"{self.corruption_type}: {self.file_path}"]
        if self.asset_type:
            parts.append(f"({self.asset_type})")
        if self.severity == "critical":
            parts.append("[CRITICAL]")
        return " ".join(parts)


class BuildCacheForensics:
    """FiveM Build Cache Forensics Engine.
    
    Analyzes crash dumps for evidence of:
    1. Crashometry markers (telemetry breadcrumbs)
    2. Resource cache corruption (SHA1, RSC7 validation)
    3. Streaming system crashes
    4. Build cache integrity issues
    """
    
    # Known FiveM marker strings (from various FiveM components)
    FIVEM_MARKERS = [
        b"cache:/",
        b"resource_surrogate:",
        b"RSC7",
        b"rcd_corrupted",
        b"heap_error",
        b"streaming_crash",
        b"script_error",
        b"gta-streaming-five.dll",
        b"citizen-resources-core.dll",
        b"citizen-scripting-lua.dll",
        b"citizen-scripting-mono.dll",
        b"citizen-scripting-v8.dll",
        b"CitizenFX_Dump",
        b"pgReadData",
        b"rage::fiDevice",
        b"LoadCacheHook",
    ]
    
    # Thread names that indicate specific subsystems
    THREAD_NAMES = {
        b"pgReadThread": "Streaming I/O Thread",
        b"ResourceCache": "Cache Loading Thread",
        b"V8 Worker": "JavaScript Runtime",
        b"MonoThread": "C# Script Thread",
        b"LuaThread": "Lua Script Thread",
    }
    
    def __init__(self):
        self.crashometry_entries: List[CrashometryEntry] = []
        self.corruption_evidence: List[CacheCorruptionEvidence] = []
        self.streaming_crashes: List[StreamingRequest] = []
        self.rsc7_headers: List[Tuple[int, RSC7Header, bool]] = []  # (offset, header, is_valid)
        self.fivem_markers_found: Set[str] = set()
        self.thread_names_found: Dict[str, int] = {}  # thread_name -> offset
        
        # Enhanced forensics data
        self.cache_metadata: List[CacheFileMetadata] = []
        self.transaction_state: Optional[TransactionState] = None
        self.pool_diagnostics: Optional[CachePoolDiagnostics] = None
        self.asset_dependencies: List[Tuple[str, str]] = []  # (parent, child) relationships
        self.open_cache_handles: List[Dict[str, Any]] = []  # From minidump handle stream
    
    def analyze_dump(self, dump_path: str) -> Dict[str, Any]:
        """Main analysis entry point - analyzes a crash dump file."""
        results = {
            'crashometry': [],
            'corruption': [],
            'streaming': [],
            'rsc7_issues': [],
            'fivem_markers': [],
            'thread_context': {},
            'cache_metadata': [],
            'transaction_state': None,
            'pool_diagnostics': None,
            'asset_dependencies': [],
            'open_handles': [],
            'confidence': 'low',
        }
        
        # Try to load crashometry file first (if available)
        crashometry_path = self._find_crashometry_file(dump_path)
        if crashometry_path:
            results['crashometry'] = self._parse_crashometry_file(crashometry_path)
        
        # Analyze the dump file itself
        try:
            with open(dump_path, 'rb') as f:
                dump_data = f.read()
            
            # Scan for FiveM markers
            results['fivem_markers'] = self._scan_fivem_markers(dump_data)
            
            # Scan for thread names
            results['thread_context'] = self._scan_thread_names(dump_data)
            
            # Scan for RSC7 headers (indicates cache files in memory)
            results['rsc7_issues'] = self._scan_rsc7_headers(dump_data)
            
            # Scan for streaming crash structures
            results['streaming'] = self._scan_streaming_crashes(dump_data)
            
            # NEW: Extract cache file metadata from paths
            results['cache_metadata'] = self._extract_cache_metadata(dump_data) or []
            
            # NEW: Detect transaction state (temp files, locks)
            results['transaction_state'] = self._detect_transaction_state(dump_data, dump_path) or {}
            
            # NEW: Analyze memory pool diagnostics
            results['pool_diagnostics'] = self._analyze_pool_diagnostics(dump_data) or {}
            
            # NEW: Extract asset dependency chains
            results['asset_dependencies'] = self._extract_asset_dependencies(dump_data) or []
            
            # NEW: Parse open file handles from minidump (if available)
            results['open_handles'] = self._extract_open_handles(dump_path) or []
            
            # Analyze corruption patterns (now with enhanced data)
            results['corruption'] = self._detect_corruption_patterns(dump_data, results['crashometry'])
            
            # NEW: Verify each corruption pattern and add confidence scores
            # Wrapped in timeout to prevent hangs on large dumps
            corruption_verification = []
            verification_complete = {'done': False}
            
            def timeout_verify_corruptions():
                try:
                    for corruption in results['corruption']:
                        verification = self._verify_corruption_type(corruption, dump_data)
                        corruption.update({
                            'confidence': verification['confidence'],
                            'verified': verification['verified'],
                            'verification_reason': verification['reason'],
                            'corroborating_evidence': verification['corroborating_evidence'],
                        })
                        corruption_verification.append(verification)
                    verification_complete['done'] = True
                except Exception as e:
                    # Log but don't block
                    pass
            
            # Run verification with 60-second timeout
            verify_thread = threading.Thread(target=timeout_verify_corruptions, daemon=True)
            verify_thread.start()
            verify_thread.join(timeout=60)
            
            if verify_thread.is_alive():
                # Verification timed out, add marker
                results['corruption_verification_timeout'] = True
                for corruption in results['corruption']:
                    # Add minimal verification data to avoid None errors
                    corruption.update({
                        'confidence': 0.5,
                        'verified': False,
                        'verification_reason': 'Verification timed out',
                        'corroborating_evidence': [],
                    })
            else:
                results['corruption_verification_timeout'] = False
            
            results['corruption_verification'] = corruption_verification
            
            # Calculate confidence level
            results['confidence'] = self._calculate_confidence(results)
            
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def _find_crashometry_file(self, dump_path: str) -> Optional[str]:
        """Locate crashometry file relative to the dump only.

        Crashometry file is typically at:
        - <dump_dir>/crashometry
        - <dump_dir>/data/cache/crashometry
        - <dump_dir>/../data/cache/crashometry
        """
        dump_dir = Path(dump_path).parent
        
        # Search common locations
        search_paths = [
            dump_dir / "crashometry",
            dump_dir / "data" / "cache" / "crashometry",
            dump_dir.parent / "data" / "cache" / "crashometry",
        ]
        
        for path in search_paths:
            if path.exists():
                return str(path)
        
        return None
    
    def _parse_crashometry_file(self, path: str) -> List[Dict[str, Any]]:
        """Parse crashometry file format.
        
        Format (from MiniDump.cpp):
            uint32_t key_length
            uint32_t value_length
            char key_data[key_length]
            char value_data[value_length]
            (repeats)
        """
        entries = []
        
        try:
            with open(path, 'rb') as f:
                data = f.read()
            
            offset = 0
            for _ in range(10000):  # Per NASA Rule 2: bounded loop (max 10K entries)
                if offset + 8 > len(data):
                    break
                # Read lengths
                key_len = struct.unpack('<I', data[offset:offset+4])[0]
                val_len = struct.unpack('<I', data[offset+4:offset+8])[0]
                offset += 8
                
                # Sanity check
                if key_len > 1024 or val_len > 1024 * 1024:
                    break
                
                if offset + key_len + val_len > len(data):
                    break
                
                # Read key and value
                key = data[offset:offset+key_len].decode('utf-8', errors='replace')
                offset += key_len
                value = data[offset:offset+val_len].decode('utf-8', errors='replace')
                offset += val_len
                
                entry = CrashometryEntry(key, value)
                self.crashometry_entries.append(entry)
                
                entries.append({
                    'key': key,
                    'value': value,
                    'marker': entry.marker_type.value if entry.marker_type else None,
                })
        
        except Exception as e:
            entries.append({'error': f'Failed to parse crashometry: {e}'})
        
        return entries
    
    def _scan_fivem_markers(self, data: bytes) -> List[Dict[str, Any]]:
        """Scan for FiveM-specific marker strings in memory."""
        markers_found = []
        
        for marker in self.FIVEM_MARKERS:
            offset = 0
            for _ in range(10000):  # Per ADA restrictions: bounded loop (max marker matches)
                offset = data.find(marker, offset)
                if offset == -1:
                    break
                
                marker_str = marker.decode('utf-8', errors='replace')
                self.fivem_markers_found.add(marker_str)
                
                # Extract context (50 bytes before and after)
                context_start = max(0, offset - 50)
                context_end = min(len(data), offset + len(marker) + 50)
                context = data[context_start:context_end]
                
                markers_found.append({
                    'marker': marker_str,
                    'offset': f'0x{offset:X}',
                    'context': context[:200].decode('utf-8', errors='replace'),
                })
                
                offset += len(marker)
                
                # Limit to 10 instances per marker to avoid spam
                if len([m for m in markers_found if m['marker'] == marker_str]) >= 10:
                    break
        
        return markers_found
    
    def _scan_thread_names(self, data: bytes) -> Dict[str, Any]:
        """Scan for FiveM thread names to identify crash context."""
        thread_info = {}
        
        for thread_name, description in self.THREAD_NAMES.items():
            offset = data.find(thread_name)
            if offset != -1:
                thread_info[description] = {
                    'offset': f'0x{offset:X}',
                    'found': True,
                }
                self.thread_names_found[thread_name.decode('utf-8')] = offset
        
        return thread_info
    
    def _scan_rsc7_headers(self, data: bytes) -> List[Dict[str, Any]]:
        """Scan for RSC7 file headers in memory."""
        rsc7_issues = []
        
        # Search for RSC7 magic (0x37435352 = 'RSC7' little-endian)
        magic_bytes = struct.pack('<I', 0x37435352)
        offset = 0
        
        for _ in range(10000):  # Per ADA restrictions: bounded loop (max RSC7 headers)
            offset = data.find(magic_bytes, offset)
            if offset == -1:
                break
            
            # Try to parse header
            header = RSC7Header.from_bytes(data[offset:offset+16])
            if header:
                is_valid = header.is_valid()
                self.rsc7_headers.append((offset, header, is_valid))
                
                if not is_valid:
                    rsc7_issues.append({
                        'offset': f'0x{offset:X}',
                        'header': str(header),
                        'valid': False,
                        'issue': 'Invalid RSC7 header detected',
                    })
            
            offset += 4
        
        return rsc7_issues
    
    def _scan_streaming_crashes(self, data: bytes) -> List[Dict[str, Any]]:
        """Scan for streaming crash diagnostic structures."""
        streaming_crashes = []
        
        # Look for pgReadData references
        pg_read_pattern = b"pgReadData"
        offset = 0
        
        for _ in range(10000):  # Per ADA restrictions: bounded loop (max streaming references)
            offset = data.find(pg_read_pattern, offset)
            if offset == -1:
                break
            
            # Try to extract streaming request structure nearby
            for search_offset in range(offset - 256, offset + 256, 8):
                if search_offset < 0 or search_offset >= len(data):
                    continue
                
                req = StreamingRequest.from_memory(data, search_offset)
                if req and req.count > 0 and req.count < 100_000_000:  # Sanity check
                    self.streaming_crashes.append(req)
                    streaming_crashes.append({
                        'offset': f'0x{search_offset:X}',
                        'handle': f'0x{req.handle:X}',
                        'file_offset': f'0x{req.offset:X}',
                        'buffer_index': req.buffer_index,
                        'bytes': req.count,
                    })
                    break
            
            offset += len(pg_read_pattern)
        
        return streaming_crashes
    
    def _extract_cache_metadata(self, data: bytes) -> List[Dict[str, Any]]:
        """Extract cache file metadata from memory patterns."""
        metadata_list = []
        
        # Look for cache:/ paths
        cache_path_pattern = rb'cache:/[\w/._-]{10,200}'
        for match in re.finditer(cache_path_pattern, data):
            try:
                cache_path = match.group().decode('utf-8', errors='ignore')
                metadata = CacheFileMetadata(cache_path=cache_path)
                
                # Extract asset type
                metadata.asset_type = CacheFileMetadata.extract_asset_type(cache_path)
                
                # Try to extract resource name from path (cache:/game_rpf/.../resource_name/...)
                path_parts = cache_path.split('/')
                if len(path_parts) >= 3:
                    metadata.resource_name = path_parts[-2] if path_parts[-2] else None
                
                # Look for SHA1 hash in proximity (40 hex chars)
                nearby_data = data[max(0, match.start()-100):match.end()+100]
                sha1_match = re.search(rb'[0-9a-fA-F]{40}', nearby_data)
                if sha1_match:
                    metadata.sha1_hash = sha1_match.group().decode('ascii')
                
                self.cache_metadata.append(metadata)
                metadata_list.append({
                    'cache_path': cache_path,
                    'asset_type': metadata.asset_type,
                    'resource_name': metadata.resource_name,
                    'sha1_hash': metadata.sha1_hash,
                    'offset': f'0x{match.start():X}',
                })
                
                # Limit to avoid spam
                if len(metadata_list) >= 20:
                    break
            except Exception:
                continue
        
        return metadata_list
    
    def _detect_transaction_state(self, data: bytes, dump_path: str) -> Optional[Dict[str, Any]]:
        """Detect incomplete cache transactions."""
        state = TransactionState()
        
        # Look for .tmp file references
        tmp_pattern = rb'\.tmp\x00'
        state.has_temp_files = tmp_pattern in data
        
        # Look for lock file indicators
        lock_patterns = [b'.lock', b'_lock', b'LOCK']
        state.has_lock_files = any(pattern in data for pattern in lock_patterns)
        
        # Look for transaction IDs (GUIDs in crash dumps)
        guid_pattern = rb'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
        guid_matches = re.findall(guid_pattern, data)
        if guid_matches:
            state.transaction_id = guid_matches[0].decode('ascii')
        
        # Look for incomplete write markers
        incomplete_markers = [b'IncompleteWrite', b'PartialDownload', b'WriteError']
        for marker in incomplete_markers:
            if marker in data:
                state.incomplete_writes.append(marker.decode('utf-8', errors='ignore'))
        
        self.transaction_state = state
        
        return {
            'has_temp_files': state.has_temp_files,
            'has_lock_files': state.has_lock_files,
            'incomplete_writes': state.incomplete_writes,
            'transaction_id': state.transaction_id,
        } if (state.has_temp_files or state.has_lock_files or state.incomplete_writes) else None
    
    def _analyze_pool_diagnostics(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Analyze memory pool allocation patterns."""
        diagnostics = CachePoolDiagnostics()
        
        # Look for pool size markers in memory (typically prefixed by pool name)
        pool_patterns = [
            (rb'CachePool.*?(\d{6,12})', 'cache_pool'),
            (rb'StreamingPool.*?(\d{6,12})', 'streaming_pool'),
            (rb'ResourcePool.*?(\d{6,12})', 'resource_pool'),
        ]
        
        for pattern, pool_name in pool_patterns:
            matches = re.finditer(pattern, data, re.IGNORECASE)
            for match in matches:
                try:
                    size = int(match.group(1))
                    if not diagnostics.pool_size_limit or size > diagnostics.pool_size_limit:
                        diagnostics.pool_size_limit = size
                except (ValueError, IndexError):
                    continue
        
        # Look for allocation failure markers
        alloc_fail_patterns = [
            b'allocation failed',
            b'AllocFailed',
            b'OutOfMemory',
            b'NOMEM',
        ]
        
        for pattern in alloc_fail_patterns:
            offset = 0
            for _ in range(10000):  # Per ADA restrictions: bounded loop (max allocation failures)
                offset = data.find(pattern, offset)
                if offset == -1:
                    break
                diagnostics.allocation_failures.append({
                    'pattern': pattern.decode('utf-8', errors='ignore'),
                    'offset': f'0x{offset:X}',
                })
                offset += len(pattern)
                if len(diagnostics.allocation_failures) >= 10:
                    break
            if len(diagnostics.allocation_failures) >= 10:
                break
        
        # Fragmentation heuristic: many small allocations
        if len(diagnostics.allocation_failures) > 5:
            diagnostics.fragmentation_detected = True
        
        self.pool_diagnostics = diagnostics
        
        return {
            'pool_size_limit': diagnostics.pool_size_limit,
            'current_allocation': diagnostics.current_allocation,
            'allocation_failures': len(diagnostics.allocation_failures),
            'fragmentation_detected': diagnostics.fragmentation_detected,
        } if diagnostics.allocation_failures else None
    
    def _extract_asset_dependencies(self, data: bytes) -> List[Dict[str, Any]]:
        """Extract asset loading dependency chains."""
        dependencies = []
        
        # For large dumps, only scan first 50MB to avoid massive slowdown
        # Asset dependencies are usually near the beginning of memory dumps
        sample_size = min(len(data), 50 * 1024 * 1024)
        data_sample = data[:sample_size] if len(data) > sample_size else data
        
        # Look for parent -> child asset references
        # Pattern: parent.rpf contains child.ytd
        parent_child_pattern = rb'([\w_-]+\.rpf).*?([\w_-]+\.(?:ytd|ydr|ydd|yft))'
        
        for match in re.finditer(parent_child_pattern, data_sample):
            try:
                parent = match.group(1).decode('utf-8', errors='ignore')
                child = match.group(2).decode('utf-8', errors='ignore')
                
                dep_entry = {'parent': parent, 'child': child}
                if dep_entry not in dependencies:
                    self.asset_dependencies.append((parent, child))
                    dependencies.append(dep_entry)
                
                if len(dependencies) >= 15:
                    break
            except Exception:
                continue
        
        return dependencies
    
    def _extract_open_handles(self, dump_path: str) -> List[Dict[str, Any]]:
        """Extract open file handles from minidump (if available)."""
        handles = []
        
        try:
            # Try to use minidump library if available
            from minidump.minidumpfile import MinidumpFile
            
            md = MinidumpFile.parse(dump_path)
            
            # Look for handle data stream (stream type 12)
            if hasattr(md, 'handles') and md.handles:
                for handle in md.handles:
                    if hasattr(handle, 'ObjectName'):
                        obj_name = str(handle.ObjectName)
                        # Filter for cache-related handles
                        if 'cache' in obj_name.lower() or '.rpf' in obj_name.lower():
                            self.open_cache_handles.append({
                                'handle': handle.Handle if hasattr(handle, 'Handle') else 0,
                                'type': handle.TypeName if hasattr(handle, 'TypeName') else 'Unknown',
                                'name': obj_name,
                            })
                            handles.append({
                                'type': handle.TypeName if hasattr(handle, 'TypeName') else 'Unknown',
                                'name': obj_name,
                            })
        except Exception:
            # Minidump library not available or handle stream not present
            pass
        
        return handles
    
    def _detect_corruption_patterns(self, data: bytes, crashometry: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect cache corruption patterns from crashometry and memory."""
        corruption_patterns = []
        
        # Check crashometry for corruption markers
        for entry in crashometry:
            marker = entry.get('marker')
            if marker in [m.value for m in CrashometryMarker]:
                corruption_patterns.append({
                    'source': 'crashometry',
                    'type': marker,
                    'key': entry.get('key'),
                    'value': entry.get('value'),
                })
        
        # ===== ENHANCED CACHE CORRUPTION DETECTION =====
        
        # 1. Detect RSC7 header corruption patterns
        rsc7_corruption_markers = [
            (b'RSC7', 'Invalid RSC7 signature'),
            (b'\xFF\xFF\xFF\xFF', 'Corrupted page table (0xFFFFFFFF markers)'),
            (b'\x00\x00\x00\x00' * 4, 'Null page table entries'),
            (b'seek beyond EOF', 'RSC7 seek beyond file bounds'),
        ]
        
        for marker, desc in rsc7_corruption_markers:
            if marker in data:
                corruption_patterns.append({
                    'source': 'memory',
                    'type': 'rsc7_corruption',
                    'description': desc,
                    'marker': marker.hex()[:32],
                })
        
        # 2. Detect hash/CRC mismatch patterns
        hash_mismatch_patterns = [
            (rb'hash.*mismatch', 'Hash mismatch detected'),
            (rb'CRC.*error', 'CRC check failed'),
            (rb'checksum.*fail', 'Checksum validation failed'),
            (rb'SHA1.*mismatch', 'SHA1 hash mismatch'),
            (rb'Expected.*!=.*Got', 'Expected vs actual value mismatch'),
        ]
        
        for pattern, desc in hash_mismatch_patterns:
            if re.search(pattern, data, re.IGNORECASE):
                corruption_patterns.append({
                    'source': 'memory',
                    'type': 'hash_mismatch',
                    'description': desc,
                })
        
        # 3. Detect compression corruption
        compression_patterns = [
            (rb'Decompression.*failed|zlib error', 'Decompression error'),
            (rb'ZLIB.*return code.*-', 'Zlib negative return (error)'),
            (rb'Compressed.*size.*exceeded', 'Compression buffer overflow'),
            (rb'LZSS.*decode error', 'LZSS decode failure'),
        ]
        
        for pattern, desc in compression_patterns:
            if re.search(pattern, data, re.IGNORECASE):
                corruption_patterns.append({
                    'source': 'memory',
                    'type': 'compression_corruption',
                    'description': desc,
                })
        
        # 4. Detect file system I/O errors
        io_error_patterns = [
            (rb'CreateFile.*failed', 'File creation failed'),
            (rb'ReadFile.*failed', 'Read operation failed'),
            (rb'ERROR_IO_DEVICE', 'I/O device error'),
            (rb'ERROR_DISK_FULL', 'Disk full error'),
            (rb'ERROR_INVALID_ACCESS', 'Invalid file access'),
            (rb'file is locked', 'File locked by another process'),
        ]
        
        for pattern, desc in io_error_patterns:
            if re.search(pattern, data, re.IGNORECASE):
                corruption_patterns.append({
                    'source': 'memory',
                    'type': 'io_error',
                    'description': desc,
                })
        
        # 5. Detect cache page fragmentation
        # Look for patterns suggesting non-contiguous page allocation
        fragmentation_patterns = [
            (rb'Non-contiguous page allocation', 'Fragmented page allocation'),
            (rb'fragmented.*cache', 'Fragmented cache detected'),
            (rb'page.*hole|gap in pages', 'Gap in page sequence'),
        ]
        
        for pattern, desc in fragmentation_patterns:
            if re.search(pattern, data, re.IGNORECASE):
                corruption_patterns.append({
                    'source': 'memory',
                    'type': 'cache_fragmentation',
                    'description': desc,
                })
        
        # 6. Detect version/build mismatch
        version_patterns = [
            (rb'cache version mismatch', 'Cache version incompatible'),
            (rb'build.*incompatible', 'Build version incompatible'),
            (rb'RSC7.*version.*\d+.*expected.*\d+', 'RSC7 version mismatch'),
        ]
        
        for pattern, desc in version_patterns:
            if re.search(pattern, data, re.IGNORECASE):
                corruption_patterns.append({
                    'source': 'memory',
                    'type': 'version_mismatch',
                    'description': desc,
                })
        
        # Check for SHA1 hash strings (indicates hash verification)
        # Now cross-reference with cache metadata
        sha1_pattern = re.compile(rb'[0-9a-fA-F]{40}')
        for offset, header, is_valid in self.rsc7_headers:
            if not is_valid or header.has_page_allocation_error():
                # Try to find associated file path
                file_path = "unknown"
                for metadata in self.cache_metadata:
                    # Simple heuristic: if metadata is within 4KB of header
                    meta_offset = int(getattr(metadata, 'offset', '0x0')[2:], 16) if hasattr(metadata, 'offset') else 0
                    if abs(meta_offset - offset) < 4096:
                        file_path = getattr(metadata, 'cache_path', 'unknown')
                        break
                
                evidence = CacheCorruptionEvidence(
                    corruption_type='page_allocation_error',
                    file_path=file_path,
                    severity='high',
                    details={
                        'virt_pages': header.virt_pages,
                        'phys_pages': header.phys_pages,
                        'expected_size': header.get_total_size(),
                        'offset': f'0x{offset:X}',
                    }
                )
                self.corruption_evidence.append(evidence)
                corruption_patterns.append({
                    'source': 'rsc7_header',
                    'type': 'page_allocation_error',
                    'file_path': file_path,
                    'severity': 'high',
                    'details': evidence.details,
                })
        
        # Check for SHA1 hash strings (indicates hash verification)
        # Now cross-reference with cache metadata
        sha1_pattern = re.compile(rb'[0-9a-fA-F]{40}')
        sha1_count = 0
        for match in sha1_pattern.finditer(data):
            hash_str = match.group().decode('ascii')
            # Find associated cache path if available
            associated_path = None
            for metadata in self.cache_metadata:
                if getattr(metadata, 'sha1_hash', None) == hash_str:
                    associated_path = getattr(metadata, 'cache_path', None)
                    break
            
            corruption_patterns.append({
                'source': 'memory',
                'type': 'sha1_hash_found',
                'hash': hash_str,
                'cache_path': associated_path,
                'offset': f'0x{match.start():X}',
            })
            sha1_count += 1
            
            # Limit to first 5 to avoid spam
            if sha1_count >= 5:
                break
        
        # Check for hard link error messages (concurrent cache access)
        hard_link_errors = [
            b"CreateHardLink failed",
            b"ERROR_SHARING_VIOLATION",
            b"ERROR_ACCESS_DENIED",
        ]
        
        for error_msg in hard_link_errors:
            if error_msg in data:
                corruption_patterns.append({
                    'source': 'memory',
                    'type': 'concurrent_cache_access',
                    'message': error_msg.decode('utf-8', errors='replace'),
                })
        
        return corruption_patterns
    
    def _analyze_cache_corruption_severity(self, corruption_patterns: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze cache corruption patterns and determine severity/remediation."""
        analysis = {
            'corruption_types': {},
            'severity': 'low',
            'affected_resources': set(),
            'remediation_steps': [],
            'is_critical': False,
        }
        
        for pattern in corruption_patterns:
            corruption_type = pattern.get('type', 'unknown')
            source = pattern.get('source', 'unknown')
            
            # Count corruption types
            if corruption_type not in analysis['corruption_types']:
                analysis['corruption_types'][corruption_type] = 0
            analysis['corruption_types'][corruption_type] += 1
            
            # Extract resource names if available
            if pattern.get('cache_path'):
                # Extract resource name from path like "compcache_nb:/resource_name/"
                match = re.search(r'compcache[^/]*/([A-Za-z0-9_\-]+)/', pattern['cache_path'])
                if match:
                    analysis['affected_resources'].add(match.group(1))
        
        # Determine overall severity based on corruption types
        critical_types = {'rsc7_corruption', 'compression_corruption', 'hash_mismatch'}
        high_types = {'io_error', 'cache_fragmentation', 'version_mismatch'}
        
        found_critical = any(t in analysis['corruption_types'] for t in critical_types)
        found_high = any(t in analysis['corruption_types'] for t in high_types)
        
        if found_critical:
            analysis['severity'] = 'critical'
            analysis['is_critical'] = True
        elif found_high or len(analysis['corruption_types']) >= 3:
            analysis['severity'] = 'high'
        elif analysis['corruption_types']:
            analysis['severity'] = 'medium'
        
        # Generate remediation steps based on detected corruption
        if 'rsc7_corruption' in analysis['corruption_types']:
            analysis['remediation_steps'].append("1. Delete cache folder: %LocalAppData%\\CitizenFX\\cache")
            analysis['remediation_steps'].append("2. Restart FiveM (cache will rebuild automatically)")
        
        if 'compression_corruption' in analysis['corruption_types']:
            analysis['remediation_steps'].append("1. The cache may have compressed files that are corrupt")
            analysis['remediation_steps'].append("2. Delete the entire cache folder and restart")
        
        if 'io_error' in analysis['corruption_types']:
            analysis['remediation_steps'].append("1. Check disk space and disk health")
            analysis['remediation_steps'].append("2. Run Windows chkdsk to repair filesystem errors")
            analysis['remediation_steps'].append("3. Ensure sufficient NTFS permissions on cache folder")
        
        if 'version_mismatch' in analysis['corruption_types']:
            analysis['remediation_steps'].append("1. Clear cache (incompatible with current FiveM version)")
            analysis['remediation_steps'].append("2. Update FiveM to latest version")
        
        if len(analysis['affected_resources']) > 0:
            analysis['remediation_steps'].append(f"\nAffected resources: {', '.join(sorted(analysis['affected_resources']))}")
        
        return analysis
    
    def _verify_corruption_type(self, corruption: Dict[str, Any], dump_data: bytes) -> Dict[str, Any]:
        """Verify a corruption pattern with confidence scoring and validation.
        
        Returns dict with:
        - confidence: 0.0-1.0 score
        - verified: bool (high confidence)
        - reason: explanation of confidence
        - corroborating_evidence: list of supporting patterns
        """
        corr_type = corruption.get('type', 'unknown')
        source = corruption.get('source', 'unknown')
        
        verification = {
            'type': corr_type,
            'confidence': 0.0,
            'verified': False,
            'reason': 'No corroborating evidence found',
            'corroborating_evidence': [],
        }
        
        # ===== RSC7 CORRUPTION VERIFICATION =====
        if corr_type == 'rsc7_corruption':
            # Check for multiple RSC7 corruption markers
            rsc7_markers = [
                b'RSC7', b'\xFF\xFF\xFF\xFF', b'seek beyond EOF', 
                b'page table', b'invalid header'
            ]
            marker_count = sum(1 for m in rsc7_markers if m in dump_data)
            
            if source == 'crashometry':
                # Crashometry data is high confidence
                verification['confidence'] = 0.95
                verification['verified'] = True
                verification['reason'] = 'Confirmed by crashometry telemetry'
            elif marker_count >= 2:
                verification['confidence'] = 0.80
                verification['verified'] = True
                verification['reason'] = f'Multiple RSC7 markers found ({marker_count})'
                verification['corroborating_evidence'].extend([m.decode('utf-8', errors='replace') for m in rsc7_markers if m in dump_data])
            elif marker_count >= 1:
                verification['confidence'] = 0.60
                verification['reason'] = f'Single RSC7 marker found'
                verification['corroborating_evidence'].extend([m.decode('utf-8', errors='replace') for m in rsc7_markers if m in dump_data])
        
        # ===== HASH MISMATCH VERIFICATION =====
        elif corr_type == 'hash_mismatch':
            # Look for SHA1 patterns and hash-related errors together
            sha1_pattern = re.compile(rb'[0-9a-fA-F]{40}')
            sha1_found = len(list(sha1_pattern.finditer(dump_data))) > 0
            
            hash_error_patterns = [
                b'hash', b'checksum', b'CRC', b'mismatch', b'validation'
            ]
            error_count = sum(1 for p in hash_error_patterns if re.search(p, dump_data, re.I))
            
            if source == 'crashometry':
                verification['confidence'] = 0.92
                verification['verified'] = True
                verification['reason'] = 'Hash mismatch confirmed by crashometry'
            elif sha1_found and error_count >= 2:
                verification['confidence'] = 0.85
                verification['verified'] = True
                verification['reason'] = f'SHA1 hash found + {error_count} hash error patterns'
                verification['corroborating_evidence'].append(f'SHA1 patterns: {sha1_found}')
                verification['corroborating_evidence'].extend([p.decode('utf-8', errors='replace') for p in hash_error_patterns if re.search(p, dump_data, re.I)])
            elif error_count >= 2:
                verification['confidence'] = 0.70
                verification['reason'] = f'Multiple hash error patterns found ({error_count})'
                verification['corroborating_evidence'].extend([p.decode('utf-8', errors='replace') for p in hash_error_patterns if re.search(p, dump_data, re.I)])
            elif sha1_found:
                # SHA1 alone is weak evidence (could be random bytes)
                verification['confidence'] = 0.45
                verification['reason'] = 'SHA1 pattern found (could be random bytes)'
        
        # ===== COMPRESSION CORRUPTION VERIFICATION =====
        elif corr_type == 'compression_corruption':
            # Look for compression-specific error markers
            compression_errors = [
                b'zlib', b'decompress', b'LZSS', b'inflate', b'deflate'
            ]
            error_count = sum(1 for e in compression_errors if re.search(e, dump_data, re.I))
            
            # Look for compressed data signatures (ZLIB header: 0x78 0x9C or similar)
            zlib_header_pattern = re.compile(rb'\x78[\x01\x5E\x9C\xDA\x20\x60\xC1]')
            zlib_found = len(list(zlib_header_pattern.finditer(dump_data))) > 0
            
            if error_count >= 2 and zlib_found:
                verification['confidence'] = 0.88
                verification['verified'] = True
                verification['reason'] = f'Compression errors ({error_count}) + ZLIB data found'
                verification['corroborating_evidence'].append(f'Compression error patterns: {error_count}')
                verification['corroborating_evidence'].append('ZLIB header signatures detected')
            elif error_count >= 2:
                verification['confidence'] = 0.75
                verification['verified'] = True
                verification['reason'] = f'Multiple compression error patterns ({error_count})'
                verification['corroborating_evidence'].extend([e.decode('utf-8', errors='replace') for e in compression_errors if re.search(e, dump_data, re.I)])
            elif error_count >= 1:
                verification['confidence'] = 0.55
                verification['reason'] = f'Single compression error pattern found'
        
        # ===== I/O ERROR VERIFICATION =====
        elif corr_type == 'io_error':
            io_patterns = [
                rb'CreateFile', rb'ReadFile', rb'ERROR_IO', rb'ERROR_DISK',
                rb'file.*lock', rb'permission', rb'access.*denied'
            ]
            pattern_count = sum(1 for p in io_patterns if re.search(p, dump_data, re.I))
            
            # Check for Windows error codes (0xE... or 0xC...)
            error_code_pattern = re.compile(rb'0x[EC][0-9A-Fa-f]{7}')
            error_codes = len(list(error_code_pattern.finditer(dump_data)))
            
            if pattern_count >= 2 and error_codes > 0:
                verification['confidence'] = 0.82
                verification['verified'] = True
                verification['reason'] = f'I/O patterns ({pattern_count}) + error codes ({error_codes})'
                verification['corroborating_evidence'].append(f'I/O error patterns: {pattern_count}')
                verification['corroborating_evidence'].append(f'Windows error codes: {error_codes}')
            elif pattern_count >= 3:
                verification['confidence'] = 0.80
                verification['verified'] = True
                verification['reason'] = f'Multiple I/O error patterns found ({pattern_count})'
            elif pattern_count >= 2:
                verification['confidence'] = 0.65
                verification['reason'] = f'I/O error patterns found ({pattern_count})'
        
        # ===== CACHE FRAGMENTATION VERIFICATION =====
        elif corr_type == 'cache_fragmentation':
            # Look for page table gaps, fragmentation patterns
            fragmentation_markers = [
                rb'fragmented', rb'non-contiguous', rb'gap', rb'hole',
                rb'page.*skip', rb'allocation.*failed'
            ]
            marker_count = sum(1 for m in fragmentation_markers if re.search(m, dump_data, re.I))
            
            if marker_count >= 2:
                verification['confidence'] = 0.75
                verification['verified'] = True
                verification['reason'] = f'Multiple fragmentation indicators ({marker_count})'
            elif marker_count >= 1:
                verification['confidence'] = 0.55
                verification['reason'] = f'Fragmentation indicator found'
        
        # ===== VERSION MISMATCH VERIFICATION =====
        elif corr_type == 'version_mismatch':
            version_patterns = [
                rb'version', rb'build', rb'incompatible', rb'mismatch'
            ]
            pattern_count = sum(1 for p in version_patterns if re.search(p, dump_data, re.I))
            
            # Look for version number patterns (x.y.z)
            version_number_pattern = re.compile(rb'\d+\.\d+(?:\.\d+)?')
            version_numbers = len(list(version_number_pattern.finditer(dump_data)))
            
            if pattern_count >= 2 and version_numbers >= 2:
                verification['confidence'] = 0.80
                verification['verified'] = True
                verification['reason'] = f'Version patterns ({pattern_count}) + version numbers ({version_numbers})'
            elif pattern_count >= 2:
                verification['confidence'] = 0.70
                verification['reason'] = f'Multiple version-related patterns found ({pattern_count})'
            elif pattern_count >= 1:
                verification['confidence'] = 0.50
                verification['reason'] = f'Version-related pattern found'
        
        return verification
    
    def _calculate_confidence(self, results: Dict[str, Any]) -> str:
        """Calculate confidence level based on forensic evidence."""
        score = 0
        
        # Crashometry entries are high confidence
        if results['crashometry']:
            score += 30
        
        # Multiple FiveM markers
        if len(results['fivem_markers']) >= 3:
            score += 20
        
        # Thread context identified
        if results['thread_context']:
            score += 15
        
        # RSC7 issues found
        if results['rsc7_issues']:
            score += 15
        
        # Streaming crashes detected
        if results['streaming']:
            score += 10
        
        # Corruption patterns
        if results['corruption']:
            score += 10
        
        if score >= 60:
            return 'high'
        elif score >= 30:
            return 'medium'
        else:
            return 'low'
    
    def generate_report(self, results: Dict[str, Any]) -> str:
        """Generate human-readable forensics report."""
        lines = []
        lines.append("=" * 80)
        lines.append("FiveM CRASH FORENSICS REPORT")
        lines.append("=" * 80)
        lines.append(f"\nConfidence Level: {results['confidence'].upper()}\n")
        
        # Crashometry Section
        if results['crashometry']:
            lines.append("\n[CRASHOMETRY TELEMETRY]")
            lines.append("-" * 80)
            for entry in results['crashometry']:
                marker = entry.get('marker', 'unknown')
                lines.append(f"  {entry['key']} = {entry['value']}")
                if marker != 'unknown':
                    lines.append(f"    └─ Marker Type: {marker}")
        
        # Cache Metadata Section (NEW)
        if results.get('cache_metadata'):
            lines.append("\n[CACHE FILE METADATA]")
            lines.append("-" * 80)
            for meta in results['cache_metadata'][:10]:  # Limit to top 10
                lines.append(f"  Path: {meta['cache_path']}")
                if getattr(meta, 'asset_type', None):
                    lines.append(f"    Type: {meta['asset_type']}")
                if getattr(meta, 'resource_name', None):
                    lines.append(f"    Resource: {meta['resource_name']}")
                if getattr(meta, 'sha1_hash', None):
                    lines.append(f"    SHA1: {meta['sha1_hash'][:16]}...")
                lines.append("")
        
        # Corruption Section (ENHANCED)
        if results['corruption']:
            lines.append("\n[CACHE CORRUPTION EVIDENCE]")
            lines.append("-" * 80)
            
            # Analyze corruption severity and generate recommendations
            corruption_analysis = self._analyze_cache_corruption_severity(results['corruption'])
            
            # Show corruption summary with verification statistics
            if corruption_analysis['corruption_types']:
                total_corruptions = len(results['corruption'])
                verified_count = sum(1 for c in results['corruption'] if c.get('verified', False))
                avg_confidence = sum(c.get('confidence', 0.0) for c in results['corruption']) / total_corruptions if total_corruptions > 0 else 0.0
                
                lines.append(f"Corruption Severity: {corruption_analysis['severity'].upper()}")
                lines.append(f"Corruption Types Found: {len(corruption_analysis['corruption_types'])}")
                
                # Show verification status
                lines.append(f"\n📊 VERIFICATION STATUS")
                lines.append(f"   Verified: {verified_count}/{total_corruptions} ({verified_count*100//total_corruptions if total_corruptions > 0 else 0}%)")
                lines.append(f"   Avg Confidence: {avg_confidence*100:.0f}%")
                
                lines.append(f"\n🔍 DETECTED TYPES")
                for corr_type, count in corruption_analysis['corruption_types'].items():
                    lines.append(f"   • {corr_type}: {count} instance(s)")
                lines.append("")
            
            # Show detailed corruption patterns with verification
            for corruption in results['corruption']:
                severity = corruption.get('severity', 'medium').upper()
                confidence = corruption.get('confidence', 0.0)
                verified = corruption.get('verified', False)
                
                # Show corruption with confidence indicator
                confidence_bar = '█' * int(confidence * 10) + '░' * (10 - int(confidence * 10))
                confidence_pct = f"{confidence * 100:.0f}%"
                
                lines.append(f"  [{severity}] {corruption['type']}")
                lines.append(f"  Confidence: [{confidence_bar}] {confidence_pct} {'✓ VERIFIED' if verified else '(unverified)'}")
                lines.append(f"  Source: {corruption['source']}")
                
                if 'verification_reason' in corruption:
                    lines.append(f"  Reason: {corruption['verification_reason']}")
                
                if 'corroborating_evidence' in corruption and corruption['corroborating_evidence']:
                    lines.append(f"  Supporting Evidence:")
                    for evidence in corruption['corroborating_evidence'][:5]:  # Limit to 5
                        lines.append(f"    - {evidence}")
                    if len(corruption['corroborating_evidence']) > 5:
                        lines.append(f"    ... and {len(corruption['corroborating_evidence']) - 5} more")
                
                if 'description' in corruption:
                    lines.append(f"  Description: {corruption['description']}")
                    
                for key, value in corruption.items():
                    if key not in ['type', 'source', 'severity', 'description', 'confidence', 'verified', 
                                   'verification_reason', 'corroborating_evidence']:
                        if key == 'details' and isinstance(value, dict):
                            for dk, dv in value.items():
                                lines.append(f"    {dk}: {dv}")
                        else:
                            lines.append(f"    {key}: {value}")
                lines.append("")
            
            # Show remediation steps
            if corruption_analysis['remediation_steps']:
                lines.append("\n[REMEDIATION STEPS]")
                lines.append("-" * 80)
                for step in corruption_analysis['remediation_steps']:
                    lines.append(f"  {step}")
                lines.append("")
        
        # Transaction State (NEW)
        if results.get('transaction_state'):
            lines.append("\n[TRANSACTION STATE]")
            lines.append("-" * 80)
            ts = results['transaction_state']
            if ts.get('has_temp_files'):
                lines.append("  ⚠ Temporary files detected - incomplete write operation")
            if ts.get('has_lock_files'):
                lines.append("  ⚠ Lock files detected - possible concurrent access")
            if ts.get('incomplete_writes'):
                lines.append(f"  Incomplete writes: {', '.join(ts['incomplete_writes'])}")
            if ts.get('transaction_id'):
                lines.append(f"  Transaction ID: {ts['transaction_id']}")
        
        # Pool Diagnostics (NEW)
        if results.get('pool_diagnostics'):
            lines.append("\n[MEMORY POOL DIAGNOSTICS]")
            lines.append("-" * 80)
            pd = results['pool_diagnostics']
            if pd.get('pool_size_limit'):
                lines.append(f"  Pool Size Limit: {pd['pool_size_limit']:,} bytes")
            if pd.get('allocation_failures'):
                lines.append(f"  Allocation Failures: {pd['allocation_failures']}")
            if pd.get('fragmentation_detected'):
                lines.append("  ⚠ Memory fragmentation detected")
        
        # Asset Dependencies (NEW)
        if results.get('asset_dependencies'):
            lines.append("\n[ASSET DEPENDENCY CHAIN]")
            lines.append("-" * 80)
            for dep in results['asset_dependencies'][:10]:  # Top 10
                lines.append(f"  {dep['parent']} ──→ {dep['child']}")
        
        # Open Handles (NEW)
        if results.get('open_handles'):
            lines.append("\n[OPEN CACHE HANDLES AT CRASH]")
            lines.append("-" * 80)
            for handle in results['open_handles'][:10]:
                lines.append(f"  [{handle['type']}] {handle['name']}")
        
        # Streaming Section
        if results['streaming']:
            lines.append("\n[STREAMING SYSTEM CRASHES]")
            lines.append("-" * 80)
            for crash in results['streaming']:
                lines.append(f"  Offset: {crash['offset']}")
                lines.append(f"  File Handle: {crash['handle']}")
                lines.append(f"  File Offset: {crash['file_offset']}")
                lines.append(f"  Bytes: {crash['bytes']}")
        
        # RSC7 Issues
        if results['rsc7_issues']:
            lines.append("\n[RSC7 FORMAT ISSUES]")
            lines.append("-" * 80)
            for issue in results['rsc7_issues']:
                lines.append(f"  {issue['issue']}")
                lines.append(f"  Offset: {issue['offset']}")
                lines.append(f"  Header: {issue['header']}")
        
        # Thread Context
        if results['thread_context']:
            lines.append("\n[THREAD CONTEXT]")
            lines.append("-" * 80)
            for thread_name, info in results['thread_context'].items():
                lines.append(f"  {thread_name}: Found at {info['offset']}")
        
        # FiveM Markers
        if results['fivem_markers']:
            lines.append("\n[FIVEM MARKERS DETECTED]")
            lines.append("-" * 80)
            marker_counts = {}
            for marker in results['fivem_markers']:
                marker_name = marker['marker']
                marker_counts[marker_name] = marker_counts.get(marker_name, 0) + 1
            
            for marker, count in sorted(marker_counts.items()):
                lines.append(f"  {marker}: {count} occurrence(s)")
        
        # Remediation
        lines.append("\n[RECOMMENDED ACTIONS]")
        lines.append("-" * 80)
        
        if any('rcd_corrupted' in str(c) for c in results['corruption']):
            lines.append("  🔴 CRITICAL: Cache corruption detected - DELETE cache folder and restart")
        
        if any(c.get('severity') == 'high' for c in results['corruption']):
            lines.append("  🔴 High severity corruption - Clear cache and verify game files")
        
        if results.get('transaction_state', {}).get('has_lock_files'):
            lines.append("  ⚠ Concurrent cache access detected - Close all FiveM instances before restart")
        
        if results.get('pool_diagnostics', {}).get('fragmentation_detected'):
            lines.append("  ⚠ Memory fragmentation - Restart FiveM client/server to reset allocator")
        
        if results['streaming']:
            lines.append("  • Streaming crash detected - check disk I/O and file integrity")
        
        if results['rsc7_issues']:
            lines.append("  • Invalid RSC7 files - corrupt game assets, verify game files via Steam/Epic")
        
        if any('heap_error' in str(c) for c in results.get('crashometry', [])):
            lines.append("  • Heap corruption - likely memory leak or script error")
        
        if results.get('asset_dependencies') and len(results['asset_dependencies']) > 10:
            lines.append("  • Complex asset dependencies detected - reduce number of addons/resources")
        
        if not any([results['crashometry'], results['corruption'], results['streaming'], results['rsc7_issues']]):
            lines.append("  • No FiveM-specific markers found - may not be a FiveM crash")
        
        lines.append("\n" + "=" * 80)
        return "\n".join(lines)


# ============================================================================
# Integration with Main Analyzer
# ============================================================================

def analyze_fivem_crash(dump_path: str, verbose: bool = True) -> Dict[str, Any]:
    """Standalone function to analyze FiveM crash dumps.
    
    Args:
        dump_path: Path to .dmp file
        verbose: Print detailed report
    
    Returns:
        Dictionary with forensics results
    """
    forensics = BuildCacheForensics()
    results = forensics.analyze_dump(dump_path)
    
    if verbose:
        report = forensics.generate_report(results)
        print(report)
    
    return results

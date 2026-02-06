"""
Direct Minidump Binary Parser for FiveM Crash Analysis

This module provides LOW-LEVEL minidump parsing using binary struct unpacking
and Windows DbgHelp API calls. It extracts ALL minidump streams including:
- Exception records with access violation details
- All thread stacks and register states
- Module information with timestamps
- Handle tables
- Memory info lists with heap stats
- Custom FiveM comment streams
- Process token/VM counter information

This bypasses library limitations and provides complete forensic data.
"""

import struct
import os
import mmap
import ctypes
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, field
from enum import IntEnum


# ============================================================================
# MINIDUMP STRUCTURES
# ============================================================================

class MinidumpStreamType(IntEnum):
    """MINIDUMP_STREAM_TYPE enum"""
    UNUSED = 0
    RESERVED_STREAM_0 = 1
    RESERVED_STREAM_1 = 2
    THREAD_LIST = 3
    MODULE_LIST = 4
    MEMORY_LIST = 5
    EXCEPTION = 6
    SYSTEM_INFO = 7
    THREAD_EX_LIST = 8
    MEMORY_64_LIST = 9
    COMMENT_STREAM_A = 10
    COMMENT_STREAM_W = 11
    HANDLE_DATA = 12
    FUNCTION_TABLE = 13
    UNLOADED_MODULE_LIST = 14
    MISC_INFO = 15
    MEMORY_INFO_LIST = 16
    THREAD_INFO_LIST = 17
    HANDLE_OPERATION_LIST = 18
    TOKEN = 19
    JAVASCRIPT_DATA = 20
    SYSTEM_MEMORY_INFO = 21
    PROCESS_VM_COUNTERS = 22
    IP_MI_SUMMARY = 33


@dataclass
class MinidumpHeader:
    """MINIDUMP_HEADER"""
    signature: int  # 0x504D444D ('PMDM')
    version: int
    num_streams: int
    stream_directory_rva: int
    checksum: int
    time_date_stamp: int
    flags: int


@dataclass
class MinidumpDirectory:
    """MINIDUMP_DIRECTORY entry"""
    stream_type: int
    data_size: int
    rva: int


@dataclass
class MinidumpException:
    """MINIDUMP_EXCEPTION_STREAM"""
    thread_id: int
    alignment: int  # padding
    exception_record: 'MinidumpExceptionRecord'
    thread_context_rva: int


@dataclass
class MinidumpExceptionRecord:
    """MINIDUMP_EXCEPTION_RECORD"""
    exception_code: int
    exception_flags: int
    exception_record: int  # pointer (RVA)
    exception_address: int
    num_parameters: int
    alignment: int
    exception_information: List[int]  # up to 15 params


@dataclass
class MinidumpThread:
    """MINIDUMP_THREAD"""
    thread_id: int
    suspend_count: int
    priority_class: int
    priority: int
    teb: int
    stack: 'MinidumpMemoryDescriptor'
    thread_context: 'MinidumpLocationDescriptor'


@dataclass
class MinidumpModule:
    """MINIDUMP_MODULE"""
    base_of_image: int
    size_of_image: int
    checksum: int
    time_date_stamp: int
    module_name_rva: int
    version_info: 'VS_FIXEDFILEINFO'
    cv_record: 'MinidumpLocationDescriptor'
    misc_record: 'MinidumpLocationDescriptor'
    reserved0: int
    reserved1: int


@dataclass
class MinidumpMemoryDescriptor:
    """MINIDUMP_MEMORY_DESCRIPTOR"""
    start_of_memory_range: int
    memory: 'MinidumpLocationDescriptor'


@dataclass
class MinidumpLocationDescriptor:
    """MINIDUMP_LOCATION_DESCRIPTOR"""
    data_size: int
    rva: int


@dataclass
class VS_FIXEDFILEINFO:
    """VS_FIXEDFILEINFO version structure"""
    signature: int
    struct_version: int
    file_version_ms: int
    file_version_ls: int
    product_version_ms: int
    product_version_ls: int
    mask: int
    flags: int
    os: int
    file_type: int
    file_subtype: int
    date_ms: int
    date_ls: int


@dataclass
class MinidumpMemoryInfo:
    """MINIDUMP_MEMORY_INFO"""
    base_address: int
    allocation_base: int
    allocation_protect: int
    __alignment1: int
    region_size: int
    state: int
    protect: int
    type: int
    __alignment2: int


@dataclass
class MinidumpHandle:
    """MINIDUMP_HANDLE_DESCRIPTOR"""
    handle: int
    type_name_rva: int
    object_name_rva: int
    attributes: int
    granted_access: int
    handle_count: int
    pointer_count: int


@dataclass
class MinidumpThreadInfo:
    """MINIDUMP_THREAD_INFO"""
    thread_id: int
    dump_flags: int
    dump_error: int
    exit_status: int
    creation_time: int
    exit_time: int
    kernel_time: int
    user_time: int


# ============================================================================
# DUMP EXTRACTOR CLASS
# ============================================================================

class MinidumpExtractor:
    """Low-level minidump binary parser using direct struct unpacking."""

    def __init__(self, dump_path: Optional[str] = None):
        self.dump_path = Path(dump_path) if dump_path else None
        self.data: bytes = None
        self._mmap = None  # Memory-mapped file for large dumps
        self._file_handle = None  # Keep file open for mmap
        self.header: Optional[MinidumpHeader] = None
        self.directories: List[MinidumpDirectory] = []
        self.streams: Dict[MinidumpStreamType, bytes] = {}
        
        # Auto-load if path provided
        if dump_path:
            self.load()
    
    def __del__(self):
        """Clean up mmap and file handle."""
        self._cleanup_mmap()
    
    def _cleanup_mmap(self):
        """Release memory-mapped file resources."""
        if self._mmap is not None:
            try:
                self._mmap.close()
            except Exception:
                # Failed to close mmap; resource may be locked
                pass
            self._mmap = None
        if self._file_handle is not None:
            try:
                self._file_handle.close()
            except Exception:
                # Failed to close file handle; resource may be locked
                pass
            self._file_handle = None
        
    def load(self, dump_path: Optional[str] = None, lightweight: bool = False) -> bool:
        """Load and parse minidump file.
        
        Uses memory-mapping for large files (>100MB) to avoid reading
        the entire file into memory, which would cause UI freezes.
        
        Args:
            dump_path: Path to dump file
            lightweight: If True, skip heavy stream extraction (for large dumps)
        """
        if dump_path:
            self.dump_path = Path(dump_path)
        
        if not self.dump_path:
            raise ValueError("No dump_path specified")
        
        # Clean up any previous mmap
        self._cleanup_mmap()
        
        try:
            file_size = os.path.getsize(self.dump_path)
            
            # Use mmap for large files (>100MB) to avoid memory bloat and freezes
            if file_size > 100 * 1024 * 1024:
                self._file_handle = open(self.dump_path, 'rb')
                self._mmap = mmap.mmap(self._file_handle.fileno(), 0, access=mmap.ACCESS_READ)
                self.data = self._mmap  # mmap supports slicing like bytes
            else:
                # Small file - read entirely for faster access
                with open(self.dump_path, 'rb') as f:
                    self.data = f.read()
            
            if len(self.data) < 32:
                return False
            
            # Parse header
            self._parse_header()
            if not self.header:
                return False
            
            # Parse directory
            self._parse_directory()
            
            # Extract streams (skip for lightweight mode on very large files)
            if not lightweight:
                self._extract_streams()
            
            return True
        except Exception as e:
            print(f"Error loading dump: {e}")
            self._cleanup_mmap()
            return False

    def _parse_header(self) -> None:
        """Parse MINIDUMP_HEADER"""
        try:
            # MINIDUMP_HEADER is 32 bytes
            # DWORD Signature (0x504D444D)
            # DWORD Version
            # DWORD NumberOfStreams
            # DWORD StreamDirectoryRva
            # DWORD Checksum
            # DWORD TimeDateStamp
            # QWORD Flags
            if len(self.data) < 32:
                return
                
            sig, ver, streams, stream_dir_rva, checksum, timestamp = struct.unpack(
                '<IIIIII',
                self.data[:24]
            )
            
            flags, = struct.unpack('<Q', self.data[24:32])
            
            # Verify MDMP signature (0x504D444D = 'MDMP' in little-endian)
            if sig != 0x504D444D:
                return
            
            self.header = MinidumpHeader(
                signature=sig,
                version=ver,
                num_streams=streams,
                stream_directory_rva=stream_dir_rva,
                checksum=checksum,
                time_date_stamp=timestamp,
                flags=flags
            )
        except Exception as e:
            pass

    def _parse_directory(self) -> None:
        """Parse MINIDUMP_DIRECTORY array"""
        if not self.header:
            return
        
        rva = self.header.stream_directory_rva
        for i in range(self.header.num_streams):
            try:
                offset = rva + (i * 12)
                stream_type, data_size, data_rva = struct.unpack(
                    '<III',
                    self.data[offset:offset+12]
                )
                
                self.directories.append(MinidumpDirectory(
                    stream_type=stream_type,
                    data_size=data_size,
                    rva=data_rva
                ))
            except Exception:
                pass
        
        # RECOVERY MODE: If all directories are empty/zero, search for streams
        if self._is_directory_corrupted():
            print("WARNING: Stream directory corrupted - attempting recovery...")
            self._recover_streams()

    def _extract_streams(self) -> None:
        """Extract raw stream data"""
        for directory in self.directories:
            try:
                stream_type = MinidumpStreamType(directory.stream_type)
                start = directory.rva
                end = start + directory.data_size
                
                if 0 <= start < len(self.data) and 0 < end <= len(self.data):
                    self.streams[stream_type] = self.data[start:end]
            except Exception:
                pass

    def _extract_stream_by_type(self, target_stream_type: MinidumpStreamType) -> bool:
        """Extract a single stream by type (for selective extraction).
        
        Args:
            target_stream_type: The specific stream type to extract (e.g., MEMORY_64_LIST)
            
        Returns:
            True if stream was found and extracted, False otherwise
        """
        for directory in self.directories:
            try:
                stream_type = MinidumpStreamType(directory.stream_type)
                if stream_type == target_stream_type:
                    start = directory.rva
                    end = start + directory.data_size
                    
                    if 0 <= start < len(self.data) and 0 < end <= len(self.data):
                        self.streams[stream_type] = self.data[start:end]
                        return True
            except Exception:
                pass
        return False

    # ========================================================================
    # RECOVERY METHODS FOR CORRUPTED STREAM DIRECTORIES
    # ========================================================================

    def _is_directory_corrupted(self) -> bool:
        """Check if stream directory is corrupted (all zeros or invalid)."""
        if not self.directories:
            return True
        
        # Check if all entries are zeros
        all_zero = all(
            d.stream_type == 0 and d.data_size == 0 and d.rva == 0
            for d in self.directories
        )
        
        if all_zero:
            return True
        
        # Check if at least one valid stream exists
        valid_count = sum(
            1 for d in self.directories
            if d.stream_type > 0 and d.data_size > 0 and 0 < d.rva < len(self.data)
        )
        
        return valid_count == 0

    def _recover_streams(self) -> None:
        """Attempt to recover streams by searching for known structures."""
        print("  Searching for EXCEPTION stream...")
        exc_offset = self._find_exception_stream()
        if exc_offset:
            print(f"  [OK] Found EXCEPTION at 0x{exc_offset:X}")
            self.directories.append(MinidumpDirectory(
                stream_type=MinidumpStreamType.EXCEPTION.value,
                data_size=168,  # Standard exception stream size
                rva=exc_offset
            ))
        
        print("  Searching for MODULE_LIST stream...")
        mod_offset, mod_count = self._find_module_list_stream()
        if mod_offset:
            print(f"  [OK] Found MODULE_LIST at 0x{mod_offset:X} ({mod_count} modules)")
            mod_size = 4 + (mod_count * 108)  # Count + array of MINIDUMP_MODULE
            self.directories.append(MinidumpDirectory(
                stream_type=MinidumpStreamType.MODULE_LIST.value,
                data_size=mod_size,
                rva=mod_offset
            ))
        
        print("  Searching for MEMORY64_LIST stream...")
        mem64_offset, num_ranges, base_rva = self._find_memory64_list_stream()
        if mem64_offset:
            print(f"  [OK] Found MEMORY64_LIST at 0x{mem64_offset:X} ({num_ranges} ranges)")
            mem64_size = 16 + (num_ranges * 16)  # Header + descriptors
            self.directories.append(MinidumpDirectory(
                stream_type=MinidumpStreamType.MEMORY_64_LIST.value,
                data_size=mem64_size,
                rva=mem64_offset
            ))

    def _find_exception_stream(self) -> Optional[int]:
        """Search for EXCEPTION stream by pattern matching."""
        # Search in first 5MB (streams are typically early)
        search_limit = min(5 * 1024 * 1024, len(self.data))
        data_start = self.header.stream_directory_rva + (self.header.num_streams * 12)
        
        common_exceptions = [0xC0000005, 0xC0000374, 0xC00000FD, 0xE06D7363, 0x80000003]
        
        for i in range(data_start, search_limit - 168, 4):
            try:
                thread_id = struct.unpack('<I', self.data[i:i+4])[0]
                exc_code = struct.unpack('<I', self.data[i+8:i+12])[0]
                
                if exc_code in common_exceptions and 0 < thread_id < 100000:
                    return i
            except Exception:
                # Failed to unpack exception record; continue searching
                pass
        
        return None

    def _find_module_list_stream(self) -> Tuple[Optional[int], int]:
        """Search for MODULE_LIST stream. Returns (offset, module_count)."""
        search_limit = min(10 * 1024 * 1024, len(self.data))
        data_start = self.header.stream_directory_rva + (self.header.num_streams * 12)
        
        for i in range(data_start, search_limit - 500, 4):
            try:
                num_modules = struct.unpack('<I', self.data[i:i+4])[0]
                
                if not (10 <= num_modules <= 1000):
                    continue
                
                # Verify by checking first few module entries
                valid = True
                for m in range(min(3, num_modules)):
                    mod_offset = i + 4 + (m * 108)
                    if mod_offset + 108 > len(self.data):
                        valid = False
                        break
                    
                    # Check BaseOfImage is reasonable (high address)
                    base = struct.unpack('<Q', self.data[mod_offset:mod_offset+8])[0]
                    if base < 0x10000 or base > 0x7FFFFFFFFFFF:
                        valid = False
                        break
                
                if valid:
                    return i, num_modules
            except Exception:
                # Failed to validate module list candidate; continue searching
                pass
        
        return None, 0

    def _find_memory64_list_stream(self) -> Tuple[Optional[int], int, int]:
        """Search for MEMORY64_LIST stream. Returns (offset, num_ranges, base_rva)."""
        search_limit = min(20 * 1024 * 1024, len(self.data))
        data_start = self.header.stream_directory_rva + (self.header.num_streams * 12)
        
        for i in range(data_start, search_limit - 16, 8):
            try:
                num_ranges, base_rva = struct.unpack('<QQ', self.data[i:i+16])
                
                # Heuristics for valid Memory64List
                if not (1000 <= num_ranges <= 100000):
                    continue
                if not (1024*1024 <= base_rva <= len(self.data)):
                    continue
                
                # Verify first descriptor looks reasonable
                if i + 32 < len(self.data):
                    addr, size = struct.unpack('<QQ', self.data[i+16:i+32])
                    if addr > 0x1000 and 0 < size < 10*1024*1024*1024:  # Max 10GB per region
                        return i, num_ranges, base_rva
            except Exception:
                # Failed to validate memory64 candidate; continue searching
                pass
        
        return None, 0, 0

    # ========================================================================
    # EXCEPTION STREAM EXTRACTION
    # ========================================================================

    def get_exception_record(self) -> Optional[Dict[str, Any]]:
        """Extract exception record details."""
        stream_data = self.streams.get(MinidumpStreamType.EXCEPTION)
        if not stream_data or len(stream_data) < 40:
            return None
        
        try:
            # MINIDUMP_EXCEPTION_STREAM structure
            # ULONG32 ThreadId
            # ULONG32 __alignment
            # EXCEPTION_RECORD ExceptionRecord (88 bytes)
            # ULONG32 ThreadContextRva
            
            thread_id, alignment = struct.unpack('<II', stream_data[:8])
            
            # Parse EXCEPTION_RECORD (starting at offset 8)
            # ExceptionCode, ExceptionFlags, ExceptionRecord (ptr), ExceptionAddress, 
            # NumberOfParameters, __unused__alignment, ExceptionInformation[15]
            
            exc_code, exc_flags, exc_record_ptr, exc_addr, num_params = struct.unpack(
                '<IIIII',
                stream_data[8:28]
            )
            
            # Skip alignment and parse parameters
            # Parameters start at offset 32 (skip 8 + 24 for fixed fields)
            params = []
            for i in range(min(num_params, 15)):
                param_offset = 32 + (i * 8)
                if param_offset + 8 <= len(stream_data):
                    param, = struct.unpack('<Q', stream_data[param_offset:param_offset+8])
                    params.append(param)
            
            return {
                'thread_id': thread_id,
                'exception_code': exc_code,
                'exception_code_hex': hex(exc_code),
                'exception_flags': exc_flags,
                'exception_address': exc_addr,
                'exception_address_hex': hex(exc_addr),
                'num_parameters': num_params,
                'parameters': params,
                'exception_name': self._exception_code_name(exc_code)
            }
        except Exception as e:
            return None

    def get_exception_name(self, code: int) -> str:
        """Map exception code to friendly name."""
        names = {
            0xC0000005: 'ACCESS_VIOLATION',
            0xC0000374: 'HEAP_CORRUPTION',
            0xC00000FD: 'STACK_OVERFLOW',
            0xE06D7363: 'CPP_EXCEPTION',
            0xC0000409: 'STACK_BUFFER_OVERRUN',
            0xC000008E: 'FLOAT_INVALID_OPERATION',
            0xC000008C: 'FLOAT_DIVIDE_BY_ZERO',
            0xC000008D: 'FLOAT_OVERFLOW',
            0xC000008B: 'FLOAT_UNDERFLOW',
            0x80000003: 'BREAKPOINT',
            0x80000004: 'SINGLE_STEP',
            0xC0000025: 'NONCONTINUABLE_EXCEPTION',
            0xC0000138: 'CONTROL_C_EXIT',
            0xC0000194: 'PORT_DISCONNECTED',
            0xC0000195: 'INVALID_HANDLE',
            0xC0000417: 'INVALID_CFF_CHECKSUM',
            0xC0000427: 'DRIVER_INTERNAL_ERROR',
            0xC00002C5: 'DATATYPE_MISALIGNMENT',
            0xC0000605: 'ILLEGAL_INSTRUCTION',
        }
        return names.get(code, 'UNKNOWN_EXCEPTION')

    def _exception_code_name(self, code: int) -> str:
        return self.get_exception_name(code)

    # ========================================================================
    # THREAD EXTRACTION
    # ========================================================================

    def get_threads(self) -> List[Dict[str, Any]]:
        """Extract thread list (from THREAD_LIST or THREAD_INFO_LIST)."""
        # Try THREAD_INFO_LIST first (stream 17), then THREAD_LIST (stream 3)
        thread_info_stream = self.streams.get(MinidumpStreamType.THREAD_INFO_LIST)
        thread_list_stream = self.streams.get(MinidumpStreamType.THREAD_LIST)
        
        threads = []
        
        # THREAD_LIST is the basic list
        if thread_list_stream and len(thread_list_stream) >= 4:
            try:
                num_threads, = struct.unpack('<I', thread_list_stream[:4])
                offset = 4
                
                for i in range(min(num_threads, 1000)):  # Safety limit
                    # MINIDUMP_THREAD struct: 48 bytes
                    # ThreadId, SuspendCount, PriorityClass, Priority, Teb,
                    # Stack (MemoryDescriptor), ThreadContext (LocationDescriptor)
                    if offset + 48 > len(thread_list_stream):
                        break
                    
                    thread_id, suspend_count, priority_class, priority, teb = struct.unpack(
                        '<IIIIQ',
                        thread_list_stream[offset:offset+24]
                    )
                    
                    # Skip invalid thread IDs
                    if thread_id == 0 or thread_id > 0x7FFFFFFF:
                        offset += 48
                        continue
                    
                    threads.append({
                        'thread_id': thread_id,
                        'suspend_count': suspend_count,
                        'priority_class': priority_class,
                        'priority': priority,
                        'teb': teb
                    })
                    
                    offset += 48
            except Exception as e:
                pass
        
        return threads

    # ========================================================================
    # MODULE EXTRACTION
    # ========================================================================

    def get_modules(self) -> List[Dict[str, Any]]:
        """Extract module list with details."""
        stream_data = self.streams.get(MinidumpStreamType.MODULE_LIST)
        if not stream_data or len(stream_data) < 4:
            return []
        
        modules = []
        try:
            num_modules, = struct.unpack('<I', stream_data[:4])
            offset = 4
            
            for i in range(min(num_modules, 2000)):  # Safety limit
                # MINIDUMP_MODULE struct: 108 bytes total
                # BaseOfImage (8), SizeOfImage (4), CheckSum (4), TimeDateStamp (4), ModuleNameRva (4) = 24 bytes
                # VS_FIXEDFILEINFO (52 bytes) at offset 24
                # CvRecord (MINIDUMP_LOCATION_DESCRIPTOR: DataSize(4) + RVA(4)) at offset 76
                # MiscRecord (MINIDUMP_LOCATION_DESCRIPTOR: 8 bytes) at offset 84
                # Reserved0 (8), Reserved1 (8) = 16 bytes
                if offset + 108 > len(stream_data):
                    break
                
                # BaseOfImage (ULONG64), SizeOfImage (ULONG32), CheckSum, TimeDateStamp, ModuleNameRva
                base_addr, size, checksum, timestamp, name_rva = struct.unpack(
                    '<QIIII',
                    stream_data[offset:offset+24]
                )
                
                # VS_FIXEDFILEINFO (52 bytes) at offset 24
                file_version = ""
                product_version = ""
                file_flags = 0
                file_os = 0
                file_type = 0
                file_subtype = 0
                if offset + 24 + 52 <= len(stream_data):
                    try:
                        (sig, _struct_ver, file_ver_ms, file_ver_ls,
                         prod_ver_ms, prod_ver_ls, _file_flags_mask,
                         file_flags, file_os, file_type, file_subtype,
                         file_date_ms, file_date_ls) = struct.unpack(
                            '<13I',
                            stream_data[offset+24:offset+24+52]
                        )
                        if sig == 0xFEEF04BD:
                            file_version = self._format_version(file_ver_ms, file_ver_ls)
                            product_version = self._format_version(prod_ver_ms, prod_ver_ls)
                    except Exception:
                        pass

                # CV record location descriptor at offset 76 (after 24 byte header + 52 byte version info)
                # MINIDUMP_LOCATION_DESCRIPTOR: DataSize (ULONG32) then RVA (RVA)
                if offset + 84 <= len(stream_data):
                    cv_size, cv_rva = struct.unpack('<II', stream_data[offset+76:offset+84])
                else:
                    cv_size, cv_rva = 0, 0
                
                # Extract module name from RVA
                module_name = self._extract_string_from_rva(name_rva)
                
                modules.append({
                    'base_address': base_addr,
                    'size': size,
                    'checksum': checksum,
                    'timestamp': timestamp,
                    'name': module_name,
                    'name_rva': name_rva,
                    'cv_data_rva': cv_rva,
                    'cv_data_size': cv_size,
                    'file_version': file_version,
                    'product_version': product_version,
                    'file_flags': file_flags,
                    'file_os': file_os,
                    'file_type': file_type,
                    'file_subtype': file_subtype
                })
                
                offset += 108
        except Exception as e:
            # Debug
            import traceback
            print(f"Module parsing error: {e}")
            traceback.print_exc()
        
        return modules

    @staticmethod
    def _format_version(ms: int, ls: int) -> str:
        """Format MS/LS version parts into a dotted version string."""
        try:
            return f"{(ms >> 16) & 0xFFFF}.{ms & 0xFFFF}.{(ls >> 16) & 0xFFFF}.{ls & 0xFFFF}"
        except Exception:
            return ""

    # ========================================================================
    # THREAD EX LIST EXTRACTION
    # ========================================================================

    def get_thread_ex_list(self) -> List[Dict[str, Any]]:
        """Extract extended thread list (THREAD_EX_LIST)."""
        stream_data = self.streams.get(MinidumpStreamType.THREAD_EX_LIST)
        if not stream_data or len(stream_data) < 4:
            return []

        threads = []
        try:
            num_threads, = struct.unpack('<I', stream_data[:4])
            offset = 4
            entry_size = 56  # MINIDUMP_THREAD_EX = MINIDUMP_THREAD (48) + BackingStore (8)

            for _ in range(min(num_threads, 10000)):
                if offset + entry_size > len(stream_data):
                    break

                thread_id, suspend_count, priority_class, priority, teb = struct.unpack(
                    '<IIIIQ',
                    stream_data[offset:offset+24]
                )

                # Skip invalid thread IDs
                if thread_id == 0 or thread_id > 0x7FFFFFFF:
                    offset += entry_size
                    continue

                stack_start, stack_size, stack_rva = struct.unpack(
                    '<QII',
                    stream_data[offset+24:offset+40]
                )
                context_size, context_rva = struct.unpack(
                    '<II',
                    stream_data[offset+40:offset+48]
                )
                backing_store_size, backing_store_rva = struct.unpack(
                    '<II',
                    stream_data[offset+48:offset+56]
                )

                threads.append({
                    'thread_id': thread_id,
                    'suspend_count': suspend_count,
                    'priority_class': priority_class,
                    'priority': priority,
                    'teb': teb,
                    'stack_start': stack_start,
                    'stack_size': stack_size,
                    'stack_rva': stack_rva,
                    'context_size': context_size,
                    'context_rva': context_rva,
                    'backing_store_size': backing_store_size,
                    'backing_store_rva': backing_store_rva,
                })

                offset += entry_size
        except Exception:
            pass

        return threads

    # ========================================================================
    # UNLOADED MODULE LIST EXTRACTION
    # ========================================================================

    def get_unloaded_modules(self) -> List[Dict[str, Any]]:
        """Extract unloaded module list (UNLOADED_MODULE_LIST)."""
        stream_data = self.streams.get(MinidumpStreamType.UNLOADED_MODULE_LIST)
        if not stream_data or len(stream_data) < 12:
            return []

        modules = []
        try:
            header_size, entry_size, num_entries = struct.unpack('<III', stream_data[:12])
            offset = header_size if 12 <= header_size <= len(stream_data) else 12
            entry_size = entry_size if entry_size >= 24 else 24

            for _ in range(min(num_entries, 10000)):
                if offset + entry_size > len(stream_data):
                    break

                base_addr, size, checksum, timestamp, name_rva = struct.unpack(
                    '<QIIII',
                    stream_data[offset:offset+24]
                )
                module_name = self._extract_string_from_rva(name_rva)

                modules.append({
                    'base_address': base_addr,
                    'size': size,
                    'checksum': checksum,
                    'timestamp': timestamp,
                    'name': module_name,
                    'name_rva': name_rva,
                })

                offset += entry_size
        except Exception:
            pass

        return modules

    # ========================================================================
    # FUNCTION TABLE / HANDLE OPS / TOKEN / IP_MI_SUMMARY
    # ========================================================================

    def get_function_table(self) -> Dict[str, Any]:
        """Extract function table stream metadata (FUNCTION_TABLE)."""
        stream_data = self.streams.get(MinidumpStreamType.FUNCTION_TABLE)
        if not stream_data:
            return {}

        out: Dict[str, Any] = {'raw_size': len(stream_data)}
        try:
            if len(stream_data) >= 12:
                header_size, entry_size, entry_count = struct.unpack('<III', stream_data[:12])
                out.update({
                    'header_size': header_size,
                    'entry_size': entry_size,
                    'entry_count': entry_count,
                })
                if entry_size and (entry_count == 0 or entry_count > 100000):
                    usable = len(stream_data) - max(header_size, 12)
                    if usable > 0:
                        out['entry_count_estimate'] = usable // entry_size
        except Exception:
            pass

        return out

    def get_handle_operation_list(self) -> Dict[str, Any]:
        """Extract handle operation list stream (HANDLE_OPERATION_LIST)."""
        stream_data = self.streams.get(MinidumpStreamType.HANDLE_OPERATION_LIST)
        if not stream_data:
            return {}

        out: Dict[str, Any] = {'raw_size': len(stream_data)}
        try:
            if len(stream_data) >= 12:
                header_size, entry_size, entry_count = struct.unpack('<III', stream_data[:12])
                out.update({
                    'header_size': header_size,
                    'entry_size': entry_size,
                    'entry_count': entry_count,
                })
                offset = header_size if 12 <= header_size <= len(stream_data) else 12
                entry_size = entry_size if entry_size > 0 else 16
                preview = []
                for i in range(min(entry_count, 50)):
                    if offset + entry_size > len(stream_data):
                        break
                    raw = stream_data[offset:offset+entry_size]
                    preview.append({
                        'index': i,
                        'raw_hex': raw[:min(32, len(raw))].hex()
                    })
                    offset += entry_size
                if preview:
                    out['entries_preview'] = preview
        except Exception:
            pass

        return out

    def get_token_info(self) -> Dict[str, Any]:
        """Extract process token stream (TOKEN)."""
        stream_data = self.streams.get(MinidumpStreamType.TOKEN)
        if not stream_data:
            return {}

        out: Dict[str, Any] = {'raw_size': len(stream_data)}
        try:
            if len(stream_data) >= 8:
                token_size, token_id = struct.unpack('<II', stream_data[:8])
                out['header_guess'] = {'token_size': token_size, 'token_id': token_id}
            out['preview_hex'] = stream_data[:64].hex()
        except Exception:
            pass

        return out

    def get_ip_mi_summary(self) -> Dict[str, Any]:
        """Extract IP_MI_SUMMARY stream (summary memory stats)."""
        stream_data = self.streams.get(MinidumpStreamType.IP_MI_SUMMARY)
        if not stream_data:
            return {}

        out: Dict[str, Any] = {'raw_size': len(stream_data)}
        try:
            if len(stream_data) >= 8:
                qword_count = min(12, len(stream_data) // 8)
                values = [struct.unpack('<Q', stream_data[i*8:(i+1)*8])[0] for i in range(qword_count)]
                out['qword_values'] = values
        except Exception:
            pass

        return out

    def _extract_string_from_rva(self, rva: int, debug: bool = False) -> str:
        """Extract null-terminated unicode string from RVA.
        
        Minidump strings are stored as MINIDUMP_STRING which has:
        - ULONG32 Length (in bytes, not including null terminator)
        - WCHAR Buffer[0]
        """
        try:
            if rva >= len(self.data) or rva == 0:
                if debug:
                    print(f"  [DEBUG] RVA {rva} out of bounds or zero (data len: {len(self.data)})")
                return "(unknown)"
            
            # Read length
            if rva + 4 > len(self.data):
                if debug:
                    print(f"  [DEBUG] RVA {rva} + 4 > data len {len(self.data)}")
                return "(error:bounds)"
            
            length, = struct.unpack('<I', self.data[rva:rva+4])
            
            if debug:
                print(f"  [DEBUG] RVA {rva:08X}: length={length} bytes")
            
            # Unicode strings in minidump are UTF-16LE
            # Length is in bytes, so we need length/2 characters
            str_offset = rva + 4
            str_end = str_offset + length
            
            if str_end > len(self.data):
                if debug:
                    print(f"  [DEBUG] String end {str_end} > data len {len(self.data)}")
                return "(error:bounds)"
            
            # Decode UTF-16LE
            try:
                decoded = self.data[str_offset:str_end].decode('utf-16-le')
                if debug:
                    print(f"  [DEBUG] Decoded: {decoded}")
                return decoded
            except Exception as e:
                if debug:
                    raw_bytes = self.data[str_offset:min(str_end, str_offset+32)]
                    print(f"  [DEBUG] Decode error: {e}")
                    print(f"  [DEBUG] Raw bytes: {raw_bytes.hex()}")
                return "(error:decode)"
        except Exception as e:
            if debug:
                print(f"  [DEBUG] Exception: {e}")
            return "(error)"

    def get_cv_pdb_info(self, module: Dict[str, Any]) -> Optional[Tuple[str, str, int]]:
        """Extract PDB name, GUID, and age from module's CodeView (RSDS) record.
        
        Returns:
            Tuple of (pdb_name, pdb_guid, pdb_age) or None if extraction fails
        """
        cv_rva = module.get('cv_data_rva', 0)
        cv_size = module.get('cv_data_size', 0)
        
        if not cv_rva or not cv_size or cv_size < 24:
            return None
        
        try:
            if cv_rva + cv_size > len(self.data):
                return None
            
            cv_data = self.data[cv_rva:cv_rva + cv_size]
            
            # Check for RSDS signature (CodeView 7.0 format)
            if len(cv_data) < 24 or cv_data[:4] != b'RSDS':
                return None
            
            # Parse RSDS structure:
            # DWORD Signature ('RSDS')
            # GUID Guid (16 bytes)
            # DWORD Age (4 bytes)
            # char PdbFileName[] (null-terminated)
            
            import uuid
            guid_bytes = cv_data[4:20]
            age, = struct.unpack('<I', cv_data[20:24])
            
            # PDB filename is null-terminated string starting at offset 24
            pdb_path_bytes = cv_data[24:]
            null_pos = pdb_path_bytes.find(b'\x00')
            if null_pos >= 0:
                pdb_path_bytes = pdb_path_bytes[:null_pos]
            
            pdb_path = pdb_path_bytes.decode('utf-8', errors='ignore')
            pdb_name = os.path.basename(pdb_path) if pdb_path else ""
            
            # Convert GUID bytes (little-endian) to uppercase string WITHOUT hyphens
            # Symbol servers require format: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX (32 hex chars)
            guid_obj = uuid.UUID(bytes_le=guid_bytes)
            guid = guid_obj.hex.upper()  # Remove hyphens and uppercase
            
            return (pdb_name, guid, age)
            
        except Exception as e:
            # Silently fail - not all modules have CV records
            return None

    # ========================================================================
    # MEMORY INFO EXTRACTION (HEAP ANALYSIS)
    # ========================================================================

    def get_memory_info(self) -> List[Dict[str, Any]]:
        """Extract memory info list (MINIDUMP_MEMORY_INFO_LIST).
        
        Note: This stream (16) is only present in full memory dumps.
        Falls back to MEMORY_LIST (5) if not available.
        """
        stream_data = self.streams.get(MinidumpStreamType.MEMORY_INFO_LIST)
        if not stream_data or len(stream_data) < 16:
            # Fallback: Try to get basic info from MEMORY_LIST
            return self._get_memory_from_memory_list()
        
        memory_regions = []
        try:
            header_size, info_size, num_entries = struct.unpack(
                '<III',
                stream_data[:12]
            )
            
            # MINIDUMP_MEMORY_INFO is 48 bytes each
            offset = header_size
            
            for i in range(num_entries):
                if offset + 48 > len(stream_data):
                    break
                
                mem_info = struct.unpack(
                    '<QQIIQIII',
                    stream_data[offset:offset+48]
                )
                
                base_addr, alloc_base, alloc_protect, region_size, \
                    state, protect, mem_type = mem_info[:7]
                
                memory_regions.append({
                    'base_address': base_addr,
                    'allocation_base': alloc_base,
                    'allocation_protect': alloc_protect,
                    'region_size': region_size,
                    'state': self._memory_state_name(state),
                    'state_code': state,
                    'protect': self._memory_protect_name(protect),
                    'protect_code': protect,
                    'type': self._memory_type_name(mem_type),
                    'type_code': mem_type
                })
                
                offset += info_size
        except Exception as e:
            pass
        
        return memory_regions

    def _get_memory_from_memory64_list(self) -> List[Dict[str, Any]]:
        """Extract memory regions from MEMORY_64_LIST stream (9).
        
        This stream is used in full memory dumps and contains the actual
        memory content after the stream directory, not inline RVAs.
        """
        stream_data = self.streams.get(MinidumpStreamType.MEMORY_64_LIST)
        if not stream_data or len(stream_data) < 16:
            return []
        
        memory_regions = []
        try:
            # MINIDUMP_MEMORY64_LIST header:
            # ULONG64 NumberOfMemoryRanges
            # RVA64 BaseRva (where the actual memory content starts)
            num_ranges, base_rva = struct.unpack('<QQ', stream_data[:16])
            
            offset = 16
            current_rva = base_rva
            
            # Each MINIDUMP_MEMORY_DESCRIPTOR64 is 16 bytes:
            # ULONG64 StartOfMemoryRange
            # ULONG64 DataSize
            for i in range(min(num_ranges, 100000)):  # Safety limit
                if offset + 16 > len(stream_data):
                    break
                
                start_addr, data_size = struct.unpack(
                    '<QQ',
                    stream_data[offset:offset+16]
                )
                
                memory_regions.append({
                    'base_address': start_addr,
                    'allocation_base': start_addr,
                    'allocation_protect': 4,
                    'region_size': data_size,
                    'state': 'COMMITTED',
                    'state_code': 0x1000,
                    'protect': 'READWRITE',
                    'protect_code': 4,
                    'type': 'PRIVATE',
                    'type_code': 0x20000,
                    'source': 'MEMORY_64_LIST',
                    'data_rva': current_rva,
                    'data_size': data_size
                })
                
                offset += 16
                current_rva += data_size
        except Exception as e:
            pass
        
        return memory_regions
    
    def _get_memory_from_memory_list(self) -> List[Dict[str, Any]]:
        """Extract basic memory regions from MEMORY_LIST stream (5)."""
        # Try Memory64 first (full dumps)
        mem64_regions = self._get_memory_from_memory64_list()
        if mem64_regions:
            return mem64_regions
        
        # Fallback to regular MemoryList
        stream_data = self.streams.get(MinidumpStreamType.MEMORY_LIST)
        if not stream_data or len(stream_data) < 4:
            return []
        
        memory_regions = []
        try:
            num_ranges, = struct.unpack('<I', stream_data[:4])
            offset = 4
            
            # Each MINIDUMP_MEMORY_DESCRIPTOR is 16 bytes:
            # ULONG64 StartOfMemoryRange
            # ULONG32 DataSize  
            # ULONG32 Rva (pointer to actual memory content in dump)
            for i in range(min(num_ranges, 10000)):  # Safety limit
                if offset + 16 > len(stream_data):
                    break
                
                start_addr, data_size, rva = struct.unpack(
                    '<QII',
                    stream_data[offset:offset+16]
                )
                
                # Assume committed memory with read/write access
                memory_regions.append({
                    'base_address': start_addr,
                    'allocation_base': start_addr,
                    'allocation_protect': 4,  # PAGE_READWRITE
                    'region_size': data_size,
                    'state': 'COMMITTED',
                    'state_code': 0x1000,
                    'protect': 'READWRITE',
                    'protect_code': 4,
                    'type': 'PRIVATE',
                    'type_code': 0x20000,
                    'source': 'MEMORY_LIST',  # Mark as estimated
                    'data_rva': rva,  # NEW: Store RVA to actual content
                    'data_size': data_size  # NEW: Store actual data size
                })
                
                offset += 16
        except Exception as e:
            pass
        
        return memory_regions

    def get_memory_content(self, max_size: int = 100 * 1024 * 1024) -> Dict[int, bytes]:
        """Extract actual memory bytes from MEMORY_LIST.
        
        Args:
            max_size: Maximum total bytes to extract (default 100MB to prevent OOM)
        
        Returns:
            Dict mapping address -> memory bytes
        """
        memory_content = {}
        regions = self.get_memory_info()
        
        total_extracted = 0
        
        for region in regions:
            if total_extracted >= max_size:
                break
            
            # Skip if no RVA (MEMORY_INFO_LIST doesn't have actual data)
            if 'data_rva' not in region:
                continue
            
            rva = region['data_rva']
            size = region['data_size']
            address = region['base_address']
            
            # Skip invalid RVAs or oversized regions
            if rva == 0 or rva >= len(self.data):
                continue
            
            if rva + size > len(self.data):
                size = len(self.data) - rva
            
            # Extract actual bytes
            try:
                memory_bytes = self.data[rva:rva+size]
                memory_content[address] = memory_bytes
                total_extracted += size
            except Exception:
                continue
        
        return memory_content

    def get_memory_content_range(self, start_index: int = 0, end_index: Optional[int] = None,
                                  max_size: int = 100 * 1024 * 1024) -> Dict[int, bytes]:
        """Extract memory bytes for a specific range of memory regions (progressive extraction).
        
        This allows chunked extraction to avoid OOM on very large dumps with tens of thousands
        of memory regions (e.g., 66K regions in a 22GB dump).
        
        Args:
            start_index: Starting region index (0-based)
            end_index: Ending region index (exclusive), or None for all remaining
            max_size: Maximum total bytes to extract for this range
        
        Returns:
            Dict mapping address -> memory bytes for the specified range
        """
        memory_content = {}
        regions = self.get_memory_info()
        
        if not regions:
            return memory_content
        
        # Determine actual end index
        if end_index is None:
            end_index = len(regions)
        else:
            end_index = min(end_index, len(regions))
        
        # Validate range
        if start_index < 0 or start_index >= len(regions):
            return memory_content
        
        total_extracted = 0
        
        for i in range(start_index, end_index):
            if total_extracted >= max_size:
                break
            
            region = regions[i]
            
            # Skip if no RVA (MEMORY_INFO_LIST doesn't have actual data)
            if 'data_rva' not in region:
                continue
            
            rva = region['data_rva']
            size = region['data_size']
            address = region['base_address']
            
            # Skip invalid RVAs or oversized regions
            if rva == 0 or rva >= len(self.data):
                continue
            
            if rva + size > len(self.data):
                size = len(self.data) - rva
            
            # Extract actual bytes
            try:
                memory_bytes = self.data[rva:rva+size]
                memory_content[address] = memory_bytes
                total_extracted += size
            except Exception:
                continue
        
        return memory_content

    def get_heap_statistics(self) -> Dict[str, Any]:
        """Analyze memory regions for heap statistics.
        
        Uses MEMORY_INFO_LIST if available, otherwise estimates from MEMORY_LIST
        and PROCESS_VM_COUNTERS.
        """
        regions = self.get_memory_info()
        
        # If we have regions from MEMORY_INFO_LIST, analyze them
        if regions and 'source' not in regions[0]:
            committed = 0
            reserved = 0
            free = 0
            heap_regions = []
            
            for region in regions:
                size = region['region_size']
                state = region['state_code']
                protect = region['protect_code']
                
                # MEM_COMMITTED = 0x1000
                if state == 0x1000:
                    committed += size
                    if protect & 0x04:  # PAGE_READWRITE
                        heap_regions.append(region)
                # MEM_RESERVED = 0x2000
                elif state == 0x2000:
                    reserved += size
                # MEM_FREE = 0x10000
                elif state == 0x10000:
                    free += size
            
            total_vm = committed + reserved + free
            fragmentation = (free / total_vm * 100) if total_vm > 0 else 0
            
            return {
                'committed_bytes': committed,
                'reserved_bytes': reserved,
                'free_bytes': free,
                'total_virtual_memory': total_vm,
                'fragmentation_percent': fragmentation,
                'heap_regions': len(heap_regions),
                'pressure_level': self._classify_memory_pressure(committed, total_vm),
                'source': 'MEMORY_INFO_LIST'
            }
        
        # Fallback: Estimate from MEMORY_LIST + VM_COUNTERS
        elif regions:
            # Sum up all memory ranges
            committed = sum(r['region_size'] for r in regions)
            
            # Try to get better data from VM_COUNTERS
            vm_counters = self.get_vm_counters()
            if vm_counters:
                total_vm = vm_counters.get('virtual_size', committed)
                working_set = vm_counters.get('working_set', committed)
                pagefile = vm_counters.get('pagefile_usage', 0)
            else:
                total_vm = committed
                working_set = committed
                pagefile = 0
            
            # Estimate fragmentation (rough)
            fragmentation = 0.0  # Can't calculate without full memory map
            
            return {
                'committed_bytes': working_set,  # Use working set as proxy
                'reserved_bytes': total_vm - working_set,
                'free_bytes': 0,
                'total_virtual_memory': total_vm,
                'fragmentation_percent': fragmentation,
                'heap_regions': len(regions),
                'pressure_level': self._classify_memory_pressure(working_set, total_vm),
                'source': 'MEMORY_LIST+VM_COUNTERS (estimated)',
                'memory_ranges_captured': len(regions)
            }
        else:
            # Last resort: VM_COUNTERS only
            vm_counters = self.get_vm_counters()
            if vm_counters:
                total_vm = vm_counters.get('virtual_size', 0)
                working_set = vm_counters.get('working_set', 0)
                
                return {
                    'committed_bytes': working_set,
                    'reserved_bytes': total_vm - working_set,
                    'free_bytes': 0,
                    'total_virtual_memory': total_vm,
                    'fragmentation_percent': 0.0,
                    'heap_regions': 0,
                    'pressure_level': self._classify_memory_pressure(working_set, total_vm),
                    'source': 'VM_COUNTERS only (limited data)',
                    'warning': 'Minidump does not contain MEMORY_INFO_LIST - heap analysis limited'
                }
            
            return {
                'committed_bytes': 0,
                'reserved_bytes': 0,
                'free_bytes': 0,
                'total_virtual_memory': 0,
                'fragmentation_percent': 0.0,
                'heap_regions': 0,
                'pressure_level': 'UNKNOWN',
                'source': 'none',
                'warning': 'No memory information available in dump'
            }

    @staticmethod
    def _memory_state_name(state: int) -> str:
        states = {
            0x1000: 'COMMITTED',
            0x2000: 'RESERVED',
            0x10000: 'FREE'
        }
        return states.get(state, f'UNKNOWN({hex(state)})')

    @staticmethod
    def _memory_protect_name(protect: int) -> str:
        # PAGE_* constants
        if protect & 0x10:
            return 'EXECUTE'
        elif protect & 0x04:
            return 'READWRITE'
        elif protect & 0x02:
            return 'READONLY'
        elif protect & 0x01:
            return 'NOACCESS'
        return 'UNKNOWN'

    @staticmethod
    def _memory_type_name(mem_type: int) -> str:
        types = {
            0x1000: 'IMAGE',
            0x2000: 'MAPPED',
            0x20000: 'PRIVATE'
        }
        return types.get(mem_type, f'UNKNOWN({hex(mem_type)})')

    @staticmethod
    def _classify_memory_pressure(committed: int, total: int) -> str:
        """Classify memory pressure level."""
        if total == 0:
            return 'UNKNOWN'
        ratio = committed / total
        if ratio > 0.95:
            return 'CRITICAL'
        elif ratio > 0.85:
            return 'ELEVATED'
        elif ratio > 0.70:
            return 'NORMAL'
        else:
            return 'LOW'

    # ========================================================================
    # THREAD STACK EXTRACTION
    # ========================================================================
    
    def get_thread_stacks(self) -> List[Dict[str, Any]]:
        """Extract thread stack memory from ThreadList stream.
        
        Returns list of dicts with:
        - thread_id: Thread ID
        - stack_base: Stack base address  
        - stack_size: Stack size in bytes
        - stack_data: Actual stack memory bytes (if available)
        - context_rva: RVA to thread context (registers)
        """
        stream_data = self.streams.get(MinidumpStreamType.THREAD_LIST)
        if not stream_data or len(stream_data) < 4:
            return []
        
        stacks = []
        try:
            num_threads, = struct.unpack('<I', stream_data[:4])
            offset = 4
            
            # Each MINIDUMP_THREAD is 48 bytes:
            # ULONG32 ThreadId
            # ULONG32 SuspendCount
            # ULONG32 PriorityClass
            # ULONG32 Priority
            # ULONG64 Teb
            # MINIDUMP_MEMORY_DESCRIPTOR Stack (16 bytes)
            # MINIDUMP_LOCATION_DESCRIPTOR ThreadContext (8 bytes)
            
            for i in range(min(num_threads, 1000)):  # Safety limit
                if offset + 48 > len(stream_data):
                    break
                
                thread_id = struct.unpack('<I', stream_data[offset:offset+4])[0]
                # Skip to Stack descriptor (offset +20)
                stack_start = struct.unpack('<Q', stream_data[offset+20:offset+28])[0]
                stack_size = struct.unpack('<I', stream_data[offset+28:offset+32])[0]
                stack_rva = struct.unpack('<I', stream_data[offset+32:offset+36])[0]
                
                # ThreadContext location (offset +36)
                context_size = struct.unpack('<I', stream_data[offset+36:offset+40])[0]
                context_rva = struct.unpack('<I', stream_data[offset+40:offset+44])[0]
                
                # Extract stack data if available
                stack_data = None
                if stack_rva > 0 and stack_size > 0 and stack_rva + stack_size <= len(self.data):
                    try:
                        stack_data = self.data[stack_rva:stack_rva+stack_size]
                    except Exception:
                        # Failed to extract stack data; continue without it
                        pass
                
                stacks.append({
                    'thread_id': thread_id,
                    'stack_base': stack_start,
                    'stack_size': stack_size,
                    'stack_rva': stack_rva,
                    'stack_data': stack_data,
                    'context_rva': context_rva,
                    'context_size': context_size
                })
                
                offset += 48
        except Exception as e:
            pass
        
        return stacks
    
    # ========================================================================
    # HANDLE EXTRACTION
    # ========================================================================

    def get_handles(self) -> List[Dict[str, Any]]:
        """Extract handle list with support for extended MINIDUMP_HANDLE_DESCRIPTOR_2."""
        stream_data = self.streams.get(MinidumpStreamType.HANDLE_DATA)
        if not stream_data or len(stream_data) < 16:
            return []
        
        handles = []
        try:
            # MINIDUMP_HANDLE_DATA_STREAM
            header_size, num_descriptors, size_of_handle_descriptor = struct.unpack(
                '<III',
                stream_data[:12]
            )
            
            offset = header_size
            
            for i in range(num_descriptors):
                if offset + size_of_handle_descriptor > len(stream_data):
                    break
                
                descriptor_bytes = stream_data[offset:offset+size_of_handle_descriptor]
                
                # MINIDUMP_HANDLE_DESCRIPTOR_2 format (extended):
                # ULONG64 Handle
                # RVA TypeNameRva
                # RVA ObjectNameRva  
                # ULONG32 Attributes
                # ULONG32 GrantedAccess
                # ULONG32 HandleCount
                # ULONG32 PointerCount
                # ... (potentially extended fields)
                
                # Extract the base fields we need (first 32 bytes minimum)
                if len(descriptor_bytes) >= 32:
                    handle_value = struct.unpack('<Q', descriptor_bytes[0:8])[0]
                    type_name_rva = struct.unpack('<I', descriptor_bytes[8:12])[0]
                    obj_name_rva = struct.unpack('<I', descriptor_bytes[12:16])[0]
                    attributes = struct.unpack('<I', descriptor_bytes[16:20])[0]
                    granted_access = struct.unpack('<I', descriptor_bytes[20:24])[0]
                    handle_count = struct.unpack('<I', descriptor_bytes[24:28])[0]
                else:
                    # Fallback for smaller descriptors (legacy format)
                    handle_value = struct.unpack('<I', descriptor_bytes[0:4])[0]
                    type_name_rva = struct.unpack('<I', descriptor_bytes[4:8])[0]
                    obj_name_rva = struct.unpack('<I', descriptor_bytes[8:12])[0]
                    attributes = struct.unpack('<I', descriptor_bytes[12:16])[0]
                    granted_access = struct.unpack('<I', descriptor_bytes[16:20])[0]
                    handle_count = struct.unpack('<I', descriptor_bytes[20:24])[0] if len(descriptor_bytes) >= 24 else 0
                
                handles.append({
                    'handle': hex(handle_value),
                    'type': self._extract_string_from_rva(type_name_rva),
                    'object_name': self._extract_string_from_rva(obj_name_rva),
                    'attributes': attributes,
                    'granted_access': hex(granted_access),
                    'handle_count': handle_count
                })
                
                offset += size_of_handle_descriptor
        except Exception as e:
            # Return partial results if parsing fails midway
            pass
        
        return handles

    # ========================================================================
    # COMMENT STREAMS (CUSTOM DATA)
    # ========================================================================

    def get_comment_stream(self, wide: bool = False) -> str:
        """Extract comment stream (custom FiveM data)."""
        stream_type = MinidumpStreamType.COMMENT_STREAM_W if wide else MinidumpStreamType.COMMENT_STREAM_A
        stream_data = self.streams.get(stream_type)
        
        if not stream_data:
            return ""
        
        try:
            if wide:
                # UTF-16LE
                return stream_data.decode('utf-16-le', errors='ignore')
            else:
                # ASCII
                return stream_data.decode('ascii', errors='ignore')
        except Exception:
            return ""

    # ========================================================================
    # SYSTEM INFO
    # ========================================================================

    def get_system_info(self) -> Dict[str, Any]:
        """Extract system info."""
        stream_data = self.streams.get(MinidumpStreamType.SYSTEM_INFO)
        if not stream_data or len(stream_data) < 56:
            return {}
        
        try:
            processor_arch, processor_level, processor_revision, \
            num_processors, os_major, os_minor, os_build, \
            platform_id, csd_version_rva, suite_mask, product_type = struct.unpack(
                '<HHHHHHHHIHBB',
                stream_data[:24]
            )
            
            return {
                'processor_arch': processor_arch,
                'processor_level': processor_level,
                'processor_revision': processor_revision,
                'num_processors': num_processors,
                'os_version': f'{os_major}.{os_minor}.{os_build}',
                'platform_id': platform_id,
                'suite_mask': hex(suite_mask),
                'product_type': product_type
            }
        except Exception:
            return {}

    def get_misc_info(self) -> Dict[str, Any]:
        """Extract misc info (timestamps, etc)."""
        stream_data = self.streams.get(MinidumpStreamType.MISC_INFO)
        if not stream_data or len(stream_data) < 4:
            return {}
        
        try:
            size_of_info, flags = struct.unpack('<II', stream_data[:8])
            
            info = {
                'flags': hex(flags),
                'size': size_of_info
            }
            
            # Process creation time (if flag 0x1 set)
            if len(stream_data) >= 20 and flags & 0x1:
                process_create_time, = struct.unpack('<I', stream_data[12:16])
                info['process_create_time'] = process_create_time
            
            return info
        except Exception:
            return {}

    # ========================================================================
    # PROCESS VM COUNTERS
    # ========================================================================

    def get_vm_counters(self) -> Dict[str, Any]:
        """Extract ProcessVmCounters stream (22)."""
        stream_data = self.streams.get(MinidumpStreamType.PROCESS_VM_COUNTERS)
        if not stream_data or len(stream_data) < 88:
            return {}
        
        try:
            # VS_PROCESS_VM_COUNTERS structure varies by OS
            # Common: peak_virtual_size, virtual_size, peak_working_set, working_set
            peak_vsize, vsize, peak_ws, ws, peak_pagefile, pagefile, peak_nonpage, nonpage = \
                struct.unpack('<QQQQQQQQ', stream_data[:64])
            
            return {
                'peak_virtual_size': peak_vsize,
                'virtual_size': vsize,
                'peak_working_set': peak_ws,
                'working_set': ws,
                'peak_pagefile_usage': peak_pagefile,
                'pagefile_usage': pagefile,
                'peak_nonpaged_pool': peak_nonpage,
                'nonpaged_pool_usage': nonpage
            }
        except Exception:
            return {}

    def get_system_memory_info(self) -> Dict[str, Any]:
        """Extract SYSTEM_MEMORY_INFO stream (21)."""
        stream_data = self.streams.get(MinidumpStreamType.SYSTEM_MEMORY_INFO)
        if not stream_data or len(stream_data) < 48:
            return {}
        
        try:
            # MINIDUMP_SYSTEM_MEMORY_INFO_1 structure
            # First attempt: read what we can
            if len(stream_data) >= 524:  # Full structure
                # Structure layout (approximate - varies by Windows version)
                # We know the stream is 524 bytes from directory listing
                
                # Try to extract known offsets
                # Commit limit, commit total, commit peak are typically early in structure
                data_qwords = struct.unpack('<65Q', stream_data[:520])  # 65 QWORDs
                
                # Heuristic: Look for reasonable values
                # Commit values are typically in GB range (billions of bytes)
                reasonable_values = []
                for i, val in enumerate(data_qwords[:20]):  # Check first 20 QWORDs
                    if 0 < val < (1 << 50):  # Less than 1 PB
                        reasonable_values.append((i, val))
                
                if len(reasonable_values) >= 3:
                    # Use first few reasonable values
                    return {
                        'raw_data_size': len(stream_data),
                        'note': 'SYSTEM_MEMORY_INFO structure varies by OS version',
                        'possible_values': {
                            f'offset_{i*8}': val for i, val in reasonable_values[:10]
                        }
                    }
            
            return {
                'raw_data_size': len(stream_data),
                'note': 'Unable to parse - structure format unknown'
            }
        except Exception as e:
            return {
                'error': str(e),
                'raw_data_size': len(stream_data)
            }

    # ========================================================================
    # COMPREHENSIVE EXTRACTION
    # ========================================================================

    def extract_all_forensics(self) -> Dict[str, Any]:
        """Extract all forensic data from dump."""
        return {
            'file': str(self.dump_path),
            'file_size_bytes': len(self.data) if self.data else 0,
            'header': {
                'signature': hex(self.header.signature) if self.header else None,
                'num_streams': self.header.num_streams if self.header else 0,
                'timestamp': self.header.time_date_stamp if self.header else None,
                'flags': hex(self.header.flags) if self.header else None,
            },
            'exception': self.get_exception_record(),
            'threads': self.get_threads(),
            'threads_ex': self.get_thread_ex_list(),
            'modules': self.get_modules(),
            'unloaded_modules': self.get_unloaded_modules(),
            'memory_info': self.get_memory_info(),
            'heap_stats': self.get_heap_statistics(),
            'handles': self.get_handles(),
            'handle_operations': self.get_handle_operation_list(),
            'comment_stream_a': self.get_comment_stream(wide=False),
            'comment_stream_w': self.get_comment_stream(wide=True),
            'system_info': self.get_system_info(),
            'misc_info': self.get_misc_info(),
            'vm_counters': self.get_vm_counters(),
            'system_memory_info': self.get_system_memory_info(),
            'ip_mi_summary': self.get_ip_mi_summary(),
            'token_info': self.get_token_info(),
            'function_table': self.get_function_table(),
        }

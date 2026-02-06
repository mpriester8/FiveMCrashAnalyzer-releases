"""
Integration layer to connect dump_extractor output into core CrashReport

This module bridges the low-level dump extraction with the high-level crash analysis,
populating CrashReport fields that were previously empty or incomplete.
"""

from typing import Dict, Any, Optional
from .dump_extractor import MinidumpExtractor, MinidumpStreamType
from .core import CrashReport, ExceptionParams
from .memory_analyzer import ProcessStatistics, MemoryRegionInfo


class DumpEnricher:
    """Enriches CrashReport with comprehensive dump data."""
    
    def __init__(self, dump_path: str):
        self.extractor = MinidumpExtractor(dump_path)
        self.dump_path = dump_path
    
    def enrich_report(self, report: CrashReport) -> CrashReport:
        """Load dump and populate all available forensic fields."""
        
        if not self.extractor.load():
            report.analysis_errors.append(f"Failed to parse minidump: {self.dump_path}")
            return report
        
        try:
            # Extract exception details
            self._enrich_exception(report)
            
            # Extract thread information
            self._enrich_threads(report)
            
            # Extract module information
            self._enrich_modules(report)
            
            # Extract memory information
            self._enrich_memory(report)
            
            # Extract handle information
            self._enrich_handles(report)
            
            # Extract comment streams
            self._enrich_comments(report)
            
            # Extract system information
            self._enrich_system_info(report)
            
        except Exception as e:
            report.analysis_errors.append(f"Error enriching report: {str(e)}")
        
        return report
    
    def _enrich_exception(self, report: CrashReport) -> None:
        """Populate exception fields."""
        exc = self.extractor.get_exception_record()
        if not exc:
            return
        
        report.exception_code = exc.get('exception_code')
        report.exception_address = exc.get('exception_address')
        
        # Try to find module containing exception address
        modules = self.extractor.get_modules()
        for mod in modules:
            base = mod['base_address']
            size = mod['size']
            if base <= report.exception_address < base + size:
                report.exception_module = mod['name']
                break
        
        # Store detailed exception parameters
        report.exception_params = ExceptionParams(
            exception_code=exc.get('exception_code'),
            exception_flags=exc.get('exception_flags'),
            exception_address=exc.get('exception_address'),
            num_parameters=exc.get('num_parameters', 0),
            parameters=exc.get('parameters', [])
        )
        
        # Store as context
        report.exception_context = {
            'code': exc.get('exception_code_hex'),
            'address': exc.get('exception_address_hex'),
            'name': exc.get('exception_name'),
            'parameters': exc.get('parameters', [])
        }
    
    def _enrich_threads(self, report: CrashReport) -> None:
        """Populate thread information."""
        threads = self.extractor.get_threads()
        for thread in threads:
            # Store raw thread data (can be analyzed further for stack frames)
            report.system_info.setdefault('threads', []).append(thread)

        # Extended thread list (THREAD_EX_LIST)
        report.thread_ex_list = self.extractor.get_thread_ex_list()
    
    def _enrich_modules(self, report: CrashReport) -> None:
        """Populate module list with PDB information extracted from CodeView records."""
        modules = self.extractor.get_modules()
        for mod in modules:
            # Extract PDB info from CodeView record in the dump
            cv_info = self.extractor.get_cv_pdb_info(mod)
            pdb_name, pdb_guid, pdb_age = cv_info if cv_info else ("", "", 0)
            
            report.modules.append({
                'name': mod['name'],
                'base_address': mod['base_address'],
                'base_address_hex': hex(mod['base_address']),
                'size': mod['size'],
                'checksum': mod['checksum'],
                'timestamp': mod['timestamp'],
                'cv_data_rva': mod['cv_data_rva'],
                'file_version': mod.get('file_version', ''),
                'product_version': mod.get('product_version', ''),
                'file_flags': mod.get('file_flags', 0),
                'file_os': mod.get('file_os', 0),
                'file_type': mod.get('file_type', 0),
                'file_subtype': mod.get('file_subtype', 0),
                'pdb_name': pdb_name,
                'pdb_guid': pdb_guid,
                'pdb_age': pdb_age
            })
    
    def _enrich_memory(self, report: CrashReport) -> None:
        """Populate memory and heap information."""
        # Memory info list
        mem_regions = self.extractor.get_memory_info()
        for region in mem_regions:
            report.memory_info.append(MemoryRegionInfo(
                base_address=region['base_address'],
                allocation_base=region['allocation_base'],
                allocation_protect=region['allocation_protect'],
                region_size=region['region_size'],
                state=region['state'],
                protect=region['protect'],
                mem_type=region['type']
            ))
        
        # Heap statistics
        heap_stats = self.extractor.get_heap_statistics()
        report.heap_committed_bytes = heap_stats.get('committed_bytes', 0)
        report.heap_reserved_bytes = heap_stats.get('reserved_bytes', 0)
        report.heap_free_bytes = heap_stats.get('free_bytes', 0)
        report.heap_fragmentation_pct = heap_stats.get('fragmentation_percent', 0.0)
        report.memory_pressure = heap_stats.get('pressure_level', 'unknown')
        report.oom_imminent = heap_stats.get('pressure_level') == 'CRITICAL'
    
    def _enrich_handles(self, report: CrashReport) -> None:
        """Populate handle information."""
        handles = self.extractor.get_handles()
        for handle in handles:
            report.system_info.setdefault('handles', []).append(handle)
    
    def _enrich_comments(self, report: CrashReport) -> None:
        """Populate comment streams."""
        report.comment_stream_a = self.extractor.get_comment_stream(wide=False)
        report.comment_stream_w = self.extractor.get_comment_stream(wide=True)
    
    def _enrich_system_info(self, report: CrashReport) -> None:
        """Populate system information."""
        report.system_info.update(self.extractor.get_system_info())
        report.misc_info.update(self.extractor.get_misc_info())
        report.process_vm_counters = self.extractor.get_vm_counters()
        report.system_memory_info = self.extractor.get_system_memory_info()
        report.ip_mi_summary = self.extractor.get_ip_mi_summary()
        report.process_token = self.extractor.get_token_info()
        report.handle_operations = self.extractor.get_handle_operation_list().get('entries_preview', [])

        # Unloaded modules (fallback if minidump library is unavailable)
        unloaded = self.extractor.get_unloaded_modules()
        if unloaded:
            report.unloaded_modules = [m.get('name', '') for m in unloaded if m.get('name')]

        # Function table entries
        func_table = self.extractor.get_function_table()
        if func_table:
            report.function_table_entries = func_table.get('entry_count', 0) or func_table.get('entry_count_estimate', 0)


def enrich_crash_report(report: CrashReport, dump_path: str) -> CrashReport:
    """Convenience function to enrich a crash report with full dump data."""
    enricher = DumpEnricher(dump_path)
    return enricher.enrich_report(report)

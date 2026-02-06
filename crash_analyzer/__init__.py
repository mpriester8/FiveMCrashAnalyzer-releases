"""FiveM Crash Analyzer package.

This package provides comprehensive crash analysis for FiveM, including:
- Deep memory analysis of minidump files
- Script/resource pinpointing to identify crash causes
- Lua and JavaScript stack trace extraction
- FiveM-specific crash pattern detection
- Extended minidump data extraction (handles, threads, modules, memory info)
- Automatic PDB symbol downloading from FiveM and Microsoft symbol servers
- Last memory operation analysis to identify crash causes
"""
from .core import (
    CrashAnalyzer,
    CrashReport,
    PatternMatch,
    Symbolicator,
)
from .memory_analyzer import (
    MemoryAnalyzer,
    DeepAnalysisResult,
    ScriptEvidence,
    EvidenceType,
    ResourceInfo,
    ScriptError,
    LuaStackFrame,
    # Extended minidump data types
    HandleInfo,
    ThreadExtendedInfo,
    ModuleVersionInfo,
    ExceptionParams,
    ProcessStatistics,
    MemoryRegionInfo,
)

# Symbol resolver imports (optional - may not be available)
try:
    from .symbol_resolver import (
        SymbolResolver,
        LastMemoryOperation,
        SymbolInfo,
        ModuleSymbolInfo,
    )
    HAS_SYMBOL_RESOLVER = True
except ImportError:
    SymbolResolver = None
    LastMemoryOperation = None
    SymbolInfo = None
    ModuleSymbolInfo = None
    HAS_SYMBOL_RESOLVER = False

__all__ = [
    # Core analyzer
    "CrashAnalyzer",
    "CrashReport",
    "PatternMatch",
    "Symbolicator",
    # Memory analyzer
    "MemoryAnalyzer",
    "DeepAnalysisResult",
    "ScriptEvidence",
    "EvidenceType",
    "ResourceInfo",
    "ScriptError",
    "LuaStackFrame",
    # Extended minidump data types
    "HandleInfo",
    "ThreadExtendedInfo",
    "ModuleVersionInfo",
    "ExceptionParams",
    "ProcessStatistics",
    "MemoryRegionInfo",
    # Symbol resolver
    "SymbolResolver",
    "LastMemoryOperation",
    "SymbolInfo",
    "ModuleSymbolInfo",
    "HAS_SYMBOL_RESOLVER",
]

__version__ = "2.2.0"

"""FiveM Crash Analyzer package.

This package provides comprehensive crash analysis for FiveM, including:
- Deep memory analysis of minidump files
- Script/resource pinpointing to identify crash causes
- Lua and JavaScript stack trace extraction
- FiveM-specific crash pattern detection
- Extended minidump data extraction (handles, threads, modules, memory info)
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
]

__version__ = "2.1.0"

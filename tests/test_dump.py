#!/usr/bin/env python3
"""Test script to verify dump file reading.

Usage:
    python test_dump.py path/to/crash.dmp
"""
import sys
import os

# Add the project to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crash_analyzer import CrashAnalyzer


def main():
    if len(sys.argv) < 2:
        print("Usage: python test_dump.py <path_to_dump.dmp>")
        print("\nThis will show diagnostic information about what's being")
        print("read from the memory dump file.")
        sys.exit(1)

    dump_path = sys.argv[1]

    if not os.path.exists(dump_path):
        print(f"Error: File not found: {dump_path}")
        sys.exit(1)

    print(f"Analyzing: {dump_path}")
    print(f"File size: {os.path.getsize(dump_path):,} bytes")
    print()

    analyzer = CrashAnalyzer()

    # Get diagnostic info
    print("=" * 60)
    print("DIAGNOSTIC INFO (what was read from the dump)")
    print("=" * 60)
    diag = analyzer.get_diagnostic_info(dump_path)
    print(diag)

    # Also do full analysis
    print("\n" + "=" * 60)
    print("PINPOINT ANALYSIS RESULTS")
    print("=" * 60 + "\n")

    report = analyzer.full_analysis(dump_path=dump_path)

    # Show primary suspects
    if report.primary_suspects:
        print("PRIMARY SUSPECTS:")
        for i, suspect in enumerate(report.primary_suspects[:5], 1):
            print(f"\n  #{i} {suspect.name}")
            print(f"      Evidence: {suspect.evidence_count} items")
            if suspect.scripts:
                print(f"      Scripts: {', '.join(suspect.scripts[:3])}")
    else:
        print("No primary suspects identified.")

    # Show script errors
    if report.script_errors:
        print("\n\nSCRIPT ERRORS FOUND:")
        for err in report.script_errors[:5]:
            print(f"\n  [{err.error_type}]")
            if err.resource_name:
                print(f"  Resource: {err.resource_name}")
            if err.script_name:
                print(f"  Script: {err.script_name}:{err.line_number or '?'}")
            print(f"  Message: {err.message[:100]}")

    # Show Lua stacks
    if report.lua_stacks:
        print("\n\nLUA STACK TRACES:")
        for i, stack in enumerate(report.lua_stacks[:2], 1):
            print(f"\n  Stack #{i}:")
            for frame in stack[:5]:
                print(f"    {frame.source}:{frame.line} in {frame.function_name}")

    # Show Native stacks
    if hasattr(report, 'native_stacks') and report.native_stacks:
        print("\n\nNATIVE STACK TRACE:")
        for frame in report.native_stacks:
            print(f"  {frame}")
    else:
        print("\n\nNO NATIVE STACK TRACE FOUND")

    # Show crash patterns
    if report.crash_patterns:
        print("\n\nDETECTED CRASH PATTERNS:")
        for pattern in report.crash_patterns[:3]:
            print(f"\n  {pattern.issue}")
            print(f"    {pattern.explanation}")

    print("\n" + "=" * 60)
    print("Analysis complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
FiveM Crash Analyzer - Main Entry Point

Quick launcher for the crash analysis tools.
"""

import sys
import argparse
from pathlib import Path

# Add crash_analyzer to path
sys.path.insert(0, str(Path(__file__).parent))


def main():
    parser = argparse.ArgumentParser(
        description='FiveM Crash Analyzer - Forensic analysis of FiveM crash dumps',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze a single dump
  %(prog)s analyze crash.dmp
  
  # Launch GUI
  %(prog)s gui
  
  # Inspect dump structure
  %(prog)s inspect crash.dmp
  
  # Run forensics analysis
  %(prog)s forensics crash.dmp

  # Raw scan for Lua/event/native patterns
  %(prog)s scan crash.dmp
  
  # Fetch and cache FiveM native database (6,700+ natives)
  %(prog)s fetch-natives
  
For more information, see README.md or docs/
        """
    )
    
    parser.add_argument(
        'command',
        choices=['analyze', 'gui', 'inspect', 'forensics', 'scan', 'test', 'fetch-natives'],
        help='Command to execute'
    )
    
    parser.add_argument(
        'dump_file',
        nargs='?',
        help='Path to crash dump file (.dmp)'
    )
    
    parser.add_argument(
        '--no-symbols',
        action='store_true',
        help='Skip symbol downloading (faster but less detail)'
    )
    
    parser.add_argument(
        '--output',
        '-o',
        help='Output file for results (default: console)'
    )

    parser.add_argument(
        '--full-scan',
        action='store_true',
        help='Scan the entire dump file (slower, maximum extraction)'
    )

    parser.add_argument(
        '--artifacts',
        action='store_true',
        help='Include additional artifacts (snippets, raw strings, paths) in scan output'
    )

    parser.add_argument(
        '--native-db',
        help='Path to native hash database (JSON or text) for 64-bit decoding'
    )
    
    args = parser.parse_args()
    
    # Route to appropriate handler
    if args.command == 'gui':
        print("Launching GUI analyzer...")
        from crash_analyzer.analyzer import main as gui_main
        gui_main()
    
    elif args.command == 'analyze':
        if not args.dump_file:
            parser.error("analyze command requires dump_file argument")
        
        print(f"Analyzing: {args.dump_file}")
        from scripts.analyze_dump import analyze_dump
        sys.exit(analyze_dump(args.dump_file))
    
    elif args.command == 'forensics':
        if not args.dump_file:
            parser.error("forensics command requires dump_file argument")
        
        print(f"Running FiveM forensics on: {args.dump_file}")
        from crash_analyzer.fivem_forensics import BuildCacheForensics
        
        forensics = BuildCacheForensics()
        result = forensics.analyze_dump(args.dump_file)
        
        # Display results
        print("\n" + "="*80)
        print("FORENSICS RESULTS")
        print("="*80)
        
        if result.get('crash_info'):
            info = result['crash_info']
            print(f"\n🔴 Exception: {info.get('exception_code', 'Unknown')}")
            print(f"   Module: {info.get('faulting_module', 'Unknown')}")
            print(f"   Address: {info.get('exception_address', 'Unknown')}")
        
        resources = result.get('resources', [])
        if resources:
            print(f"\n📦 Resources ({len(resources)}):")
            for res in resources[:10]:
                print(f"   - {res}")
        
        evidence = result.get('evidence', [])
        print(f"\n🔍 Evidence items: {len(evidence)}")
        
        if args.output:
            import json
            with open(args.output, 'w') as f:
                json.dump(result, f, indent=2)
            print(f"\n✓ Full results saved to: {args.output}")
    
    elif args.command == 'inspect':
        if not args.dump_file:
            parser.error("inspect command requires dump_file argument")
        
        print(f"Inspecting: {args.dump_file}")
        from tools.dump_inspector import main as inspect_main
        inspect_main([args.dump_file])

    elif args.command == 'scan':
        if not args.dump_file:
            parser.error("scan command requires dump_file argument")

        print(f"Scanning raw dump for Lua/event/native patterns: {args.dump_file}")
        from crash_analyzer.memory_analyzer import MemoryAnalyzer
        from crash_analyzer.native_db_manager import NativeDBManager

        analyzer = MemoryAnalyzer()
        
        # Auto-fetch native database if not provided
        if not args.native_db:
            print("[*] Attempting to load native database...")
            manager = NativeDBManager()
            natives_db = manager.load_or_fetch(source_name='alloc8or', verbose=False)
            if len(natives_db) > 100:
                # Use it by updating the analyzer's native map
                print(f"[+] Loaded {len(natives_db)} native mappings from cache")
                args.native_db = str(manager.get_cache_path('alloc8or'))
        
        if args.native_db:
            from crash_analyzer.memory_analyzer import load_native_hash_db
            loaded = load_native_hash_db(args.native_db)
            print(f"[+] Loaded native hash DB entries: {loaded}")
        
        results = analyzer.scan_dump_for_patterns(
            args.dump_file,
            full_sweep=args.full_scan,
            include_artifacts=args.artifacts,
        )

        if args.output:
            import json
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"\nResults saved to: {args.output}")
        else:
            # Print a compact summary
            lua_count = len(results.get('lua_stacks', []))
            js_count = len(results.get('js_stacks', []))
            err_count = len(results.get('script_errors', []))
            res_count = len(results.get('resources', []))
            evt_count = len(results.get('events', []))
            native_count = len(results.get('native_hashes', []))
            print("\nSCAN SUMMARY")
            print("=" * 60)
            print(f"Lua stacks: {lua_count}")
            print(f"JS stacks: {js_count}")
            print(f"Script errors: {err_count}")
            print(f"Resources: {res_count}")
            print(f"Events: {evt_count}")
            print(f"Native hashes: {native_count}")
            if results.get('scan_mode'):
                print(f"Scan mode: {results.get('scan_mode')}")
            if results.get('scan_range'):
                rng = results.get('scan_range')
                print(f"Scan range (MB): {rng.get('size_mb', 0):.1f}")
            if args.artifacts:
                print(f"Lua snippets: {len(results.get('lua_snippets', []))}")
                print(f"JS snippets: {len(results.get('js_snippets', []))}")
                print(f"Raw strings: {len(results.get('raw_string_samples', []))}")
                print(f"Resource paths: {len(results.get('resource_paths_sample', []))}")

            if results.get('resource_counts'):
                print("\nTOP RESOURCES:")
                for item in results['resource_counts'][:20]:
                    print(f"  - {item.get('name')} ({item.get('count')})")
            elif results.get('resources'):
                print("\nTOP RESOURCES:")
                for name in results['resources'][:20]:
                    print(f"  - {name}")

            if results.get('events'):
                print("\nSample events:")
                for event in results['events'][:20]:
                    print(f"  - {event}")

            if results.get('native_decoded'):
                print("\nSample native hashes (decoded):")
                for item in results['native_decoded'][:20]:
                    print(f"  - {item.get('hash')} -> {item.get('name')}")
            elif results.get('native_hashes'):
                print("\nSample native hashes:")
                for h in results['native_hashes'][:20]:
                    print(f"  - {h}")
    
    elif args.command == 'fetch-natives':
        print("=" * 80)
        print("FiveM Native Database Fetcher")
        print("=" * 80)
        
        from crash_analyzer.native_db_manager import NativeDBManager
        
        manager = NativeDBManager()
        print("\n" + manager.get_sources_info())
        print()
        
        # Try to fetch and cache
        natives = manager.load_or_fetch(source_name='alloc8or', verbose=True)
        print(f"\n[OK] {len(natives)} native mappings ready for crash analysis")
        print(f"     Cache location: {manager.cache_dir}")
        
    elif args.command == 'test':
        print("Running test suite...")
        import pytest
        sys.exit(pytest.main(['tests/', '-v']))


if __name__ == '__main__':
    main()

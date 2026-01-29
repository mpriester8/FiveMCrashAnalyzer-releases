# FiveM Crash Analyzer

A professional crash dump and memory leak analyzer specifically designed for FiveM servers. Identifies resources causing crashes, tracks memory leaks, and provides detailed heap timeline analysis.

![Crash Analyzer](icon.png)

## Features

- **Minidump Analysis**: Parse Windows crash dumps (`.dmp` files) to identify crashing resources
- **Memory Leak Detection**: Analyze V8 heap timeline snapshots to detect memory leaks from specific resources
- **FiveM-Optimized**: Thresholds and patterns tuned specifically for FiveM server environments
- **Rich GUI**: Modern PySide6 interface with separate tabs for crashes and memory analysis
- **Resource Attribution**: Advanced edge traversal algorithm attributes memory usage to specific FiveM resources
- **Severity Classification**: Automatically classifies issues as CRITICAL, HIGH, MEDIUM, or LOW priority

## Installation

### Requirements

- Python 3.10+
- Windows OS (for minidump analysis)
- FiveM Server (for generating crash dumps and heap snapshots)

### Setup

1. Clone the repository:
```bash
git clone https://github.com/mpriester8/FiveMCrashAnalyzer-releases.git
cd FiveM-CrashAnalyzer
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the analyzer:
```bash
python analyzer.py
```

Or use the batch file on Windows:
```bash
run_analyzer.bat
```

## Usage

### Crash Dump Analysis

1. Launch the application
2. Click the **"Crashes"** tab
3. Click **"Select Crash Dump"** and choose your `.dmp` file
4. View identified resources causing crashes
5. Check the **Crash Patterns** section for technical details

### Heap Timeline Analysis (Memory Leaks)

1. Generate heap snapshots in FiveM:
   - Type `set convar_heapdump true` in server console
   - Restart your server
   - Snapshots will be generated in your `cache/heaptimeline/` folder

2. In the analyzer:
   - Click the **"Memory Leaks"** tab
   - Click **"Select Heap Timeline Folder"**
   - Choose the folder containing multiple heap snapshots
   - Wait for analysis (may take 30-60 seconds for large files)

3. Review results:
   - **Leaking Resources**: Resources with sustained memory growth
   - **Severity**: CRITICAL (>200MB), HIGH (>50MB), MEDIUM (>20MB), LOW (<20MB)
   - **Growth Rate**: MB/minute increase
   - **Consistency**: Percentage of snapshots showing growth

## Analysis Details

### Crash Detection

The analyzer examines minidump files for:
- **Resource Paths**: Identifies FiveM resource folders in crash stack traces
- **Module Analysis**: Checks loaded DLLs and memory regions
- **Native Filters**: Removes false positives from system paths

### Memory Leak Detection

Uses V8 heap snapshot analysis with:
- **Edge Traversal**: 5-depth propagation to attribute memory to resources
- **FiveM-Tuned Thresholds**:
  - Minimum growth: 512 KB (filters noise)
  - Consistency requirement: 70% of snapshots must show growth
  - Minimum snapshots: 3 required for leak confirmation

### Severity Levels

**CRITICAL**:
- Memory usage >200 MB, OR
- Growth rate >5 MB/minute

**HIGH**:
- Memory usage >50 MB, OR
- Growth rate >2 MB/minute

**MEDIUM**:
- Memory usage >20 MB, OR
- Growth rate >0.5 MB/minute

**LOW**:
- All other confirmed leaks

## Common Crash Patterns

| Pattern | Likely Cause |
|---------|--------------|
| `scripthandler.dll` | Script runtime crash (usually from resource) |
| `citizen-resources-*.dll` | Resource loading/initialization issue |
| Access Violation | Memory corruption, often from native calls |
| Stack Overflow | Infinite recursion in Lua script |

## Troubleshooting

### No Resources Found in Crash Dump

- Ensure the crash dump is from a FiveM server (not client)
- Verify resources were actually running at crash time
- Check if crash occurred in native code before resource loaded

### Heap Analysis Shows 0 MB

- Ensure heap snapshots are valid V8 format
- Verify you're analyzing multiple snapshots (3+ recommended)
- Check that snapshots were taken at different times (not all at once)

### False Positive Memory Leaks

The analyzer uses FiveM-specific thresholds to minimize false positives:
- Growth must be sustained across 70% of snapshots
- Minimum 512 KB growth filters normal fluctuations
- Resources under 20 MB typically aren't concerning for servers

## Development

### Project Structure

```
CrashAnalyzer/
├── analyzer.py              # Main GUI application
├── crash_analyzer/
│   ├── __init__.py
│   ├── analyzer.py          # Legacy analyzer (kept for compatibility)
│   ├── core.py              # Minidump parsing logic
│   ├── heap_analyzer.py     # V8 heap snapshot parser
│   └── memory_analyzer.py   # Memory pattern analysis
├── tests/
│   ├── test_crash_analyzer.py
│   ├── test_dump.py
│   └── test_minidump_extraction.py
├── requirements.txt
├── pytest.ini
└── README.md
```

### Running Tests

```bash
pytest
```

All tests should pass before committing changes.

### Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Code Standards

- Use type hints for all function signatures
- Follow PEP 8 style guidelines
- Add docstrings to public methods
- Maintain test coverage
- Use async/await for I/O operations

## Technical Details

### V8 Heap Snapshot Format

The analyzer parses Chrome DevTools heap snapshot format:
- **Nodes**: 7 fields per node (type, name, id, self_size, edge_count, trace_node_id, detachedness)
- **Edges**: 3 fields per edge (type, name_or_index, to_node)
- **Strings**: Lookup table for node/edge names

### Edge Traversal Algorithm

Memory attribution uses 5-depth traversal:
1. Identify nodes with FiveM resource paths
2. Follow parent→child edges (depth 5)
3. Accumulate self_size of all reachable nodes
4. Attribute total memory to source resource

This handles complex object graphs where resources create deeply nested structures.

## License

MIT License - feel free to use this for your FiveM server!

## Changelog

### v1.1.0
- Added heap timeline memory leak detection
- Implemented edge traversal for accurate resource attribution
- Added FiveM-tuned leak detection thresholds
- Professional icon system with crash/debug symbol
- Severity classification (CRITICAL/HIGH/MEDIUM/LOW)

### v1.0.0
- Initial release
- Minidump crash analysis
- Resource identification from crash dumps
- Basic GUI with PySide6

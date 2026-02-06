# FiveM Crash Analyzer

Forensic analysis tool for FiveM crash dumps with automatic symbol resolution, memory analysis, and pattern matching.

## Features

- **Automatic Symbol Downloading** - Downloads PDB symbols from FiveM and Microsoft servers
- **Corrupted Dump Recovery** - Recovers data from dumps with zeroed/corrupted stream directories
- **Deep Memory Analysis** - Scans memory for Lua stacks, script references, and resource evidence
- **FiveM-Specific Forensics** - Pattern matching against 20+ known crash signatures
- **Resource Attribution** - Identifies which resource/script caused the crash
- **Cache Corruption Detection** - RSC7 validation and streaming diagnostics
- **GUI & CLI** - Both graphical and command-line interfaces

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/fivem-crash-analyzer.git
cd fivem-crash-analyzer

# Install dependencies
pip install -r requirements.txt
```

### Usage

**GUI Mode:**
```bash
python crash_analyzer/analyzer.py
```

Or on Windows: `run_analyzer.bat`

**CLI Mode:**
```bash
python crash_analyzer_cli.py path/to/crash.dmp
```

## Requirements

- Python 3.8+
- Windows 7+ (for native debugging features)
- Dependencies: `minidump`, `requests`, `pytest`, `PySide6`

## Project Structure

```
crash_analyzer/     # Core analysis library
scripts/            # CLI utilities
tools/              # Diagnostic tools
tests/              # Test suite
examples/           # Usage examples
docs/               # Documentation
```

## How It Works

1. **Dump Extraction** - Parses minidump binary format, recovers corrupted streams
2. **Memory Analysis** - Scans memory regions for patterns and evidence
3. **Symbol Resolution** - Downloads and caches PDB symbols for stack traces
4. **FiveM Forensics** - Applies FiveM-specific heuristics and pattern matching
5. **Resource Attribution** - Identifies which resource caused the crash

## Common Crash Types Detected

| Crash Type | Description |
|------------|-------------|
| Cache Corruption | Corrupt game assets in FiveM cache |
| Entity Pool Exhaustion | Too many spawned entities |
| Out of Memory | RAM exhaustion from too many assets |
| Script Error | Lua/JavaScript runtime errors |
| Graphics Driver | GPU driver crashes |
| Access Violation | Memory access errors |
| Stack Overflow | Infinite recursion or large stack allocation |

## Testing

```bash
# Run all tests
pytest tests/ -v

# Test specific component
pytest tests/test_fivem_forensics.py -v
```

## API Usage

```python
from crash_analyzer.fivem_forensics import BuildCacheForensics

# Create analyzer
forensics = BuildCacheForensics()

# Analyze dump
result = forensics.analyze_dump("crash.dmp")

# Access results
print(f"Exception: {result['crash_info']['exception_code']}")
print(f"Resources: {result['resources']}")
```

## Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

MIT License - see LICENSE file for details

## Acknowledgments

Built for the FiveM community. Special thanks to:
- CitizenFX core team
- FiveM forensics research community

---

**Where to find crash files:**  
`%localappdata%\FiveM\FiveM.app\crashes\`

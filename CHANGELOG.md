# Changelog

All notable changes to FiveM Crash Analyzer are documented here.

---

## [2.1.0]

### Added
- Deep memory analysis with script/resource pinpointing
- Lua and JavaScript stack trace extraction from crash dumps
- Optional native stack symbolication via local PDB cache (`.env` / `FIVEM_SYMBOL_CACHE`)
- Extended minidump data: handles, threads, module versions, memory regions, process statistics
- FiveM-specific crash pattern detection and evidence types

---

## [2.0.0]

### Changed
- Major analysis pipeline refactor; GUI and logic moved into `crash_analyzer` package
- Integrated memory analyzer with deep analysis and progress/abort support
- Top-level `analyzer.py` launcher; run via `python analyzer.py` or `run_analyzer.bat`

---

## [1.1.0]

### Added
- Heap timeline memory leak detection
- Edge traversal for accurate resource attribution
- FiveM-tuned leak detection thresholds
- Professional icon system with crash/debug symbol
- Severity classification (CRITICAL / HIGH / MEDIUM / LOW)

---

## [1.0.0]

### Added
- Initial release
- Minidump crash analysis
- Resource identification from crash dumps
- Basic GUI with PySide6

[2.1.0]: https://github.com/mpriester8/FiveMCrashAnalyzer-releases/releases/tag/v2.1.0
[2.0.0]: https://github.com/mpriester8/FiveMCrashAnalyzer-releases/releases/tag/v2.0.0
[1.1.0]: https://github.com/mpriester8/FiveMCrashAnalyzer-releases/releases/tag/v1.1.0
[1.0.0]: https://github.com/mpriester8/FiveMCrashAnalyzer-releases/releases/tag/v1.0.0

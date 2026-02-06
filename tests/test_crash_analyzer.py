"""Tests for FiveM Crash Analyzer with deep memory analysis."""
import os
import tempfile
from crash_analyzer.core import CrashAnalyzer, CrashReport, PatternMatch
from crash_analyzer.memory_analyzer import (
    MemoryAnalyzer,
    DeepAnalysisResult,
    EvidenceType,
    ScriptEvidence,
    ResourceInfo,
    LuaStackFrame,
    ScriptError,
)


def test_extract_strings():
    """Test basic string extraction from binary data."""
    ca = CrashAnalyzer()
    data = b"xxxHelloWorldyyy\x00\x01AnotherString!!!!\xffEnd"
    res = ca._extract_strings(data, min_length=5)
    assert any(s == 'HelloWorld' for s in res)
    assert any('AnotherString' in s for s in res)


def test_extract_strings_utf16():
    """Test string extraction handles various encodings."""
    ca = CrashAnalyzer()
    # Simple ASCII strings with null terminators
    data = b"test_resource\x00\x00\x00another_script\x00\x00"
    res = ca._extract_strings(data, min_length=4)
    assert any('test' in s.lower() for s in res)


def test_match_patterns():
    """Test crash pattern matching."""
    ca = CrashAnalyzer()
    text = "The process failed with an out of memory error and memory allocation fail"
    found = ca.match_patterns(text)
    assert any(p.issue == 'Out of Memory' for p in found)


def test_match_patterns_multiple():
    """Test matching multiple crash patterns."""
    ca = CrashAnalyzer()
    text = "lua error in script at line 10, then access violation exception code 0xc0000005"
    found = ca.match_patterns(text)
    issues = [p.issue for p in found]
    assert 'Script Error' in issues or 'Access Violation' in issues


def test_match_patterns_graphics():
    """Test graphics driver crash pattern."""
    ca = CrashAnalyzer()
    text = "crash in nvwgf2umx.dll DirectX error"
    found = ca.match_patterns(text)
    assert any(p.issue == 'Graphics Driver Crash' for p in found)


def test_identify_modules():
    """Test known module identification."""
    ca = CrashAnalyzer()
    modules = [
        r"C:\\Windows\\System32\\nvwgf2umx.dll",
        r"C:\\some\\path\\custom.dll",
    ]
    identified = ca.identify_modules(modules)
    assert any('NVIDIA' in i['description'] for i in identified)


def test_identify_modules_fivem():
    """Test FiveM-specific module identification."""
    ca = CrashAnalyzer()
    modules = [
        "citizen-resources-core.dll",
        "rage_audio.dll",
    ]
    identified = ca.identify_modules(modules)
    descs = [i['description'] for i in identified]
    assert any('FiveM' in d or 'CitizenFX' in d for d in descs)


def test_analyze_log(tmp_path):
    """Test log file analysis."""
    log_file = tmp_path / "test.log"
    content = """Warning: be careful
Error: crashed here
Started 'coolresource'
stack trace:
trace line 1
"""
    log_file.write_text(content, encoding='utf-8')

    ca = CrashAnalyzer()
    info = ca.analyze_log(str(log_file))

    # Error detection
    assert len(info.get('errors', [])) >= 1
    # Resource extraction
    assert 'coolresource' in info.get('resources', [])


def test_analyze_log_lua_errors(tmp_path):
    """Test log file detects Lua errors."""
    log_file = tmp_path / "citizenfx.log"
    content = """[script:myresource] SCRIPT ERROR: @myresource/server/main.lua:42: attempt to index nil value
stack traceback:
  @myresource/server/main.lua:42: in function 'doThing'
  @myresource/server/main.lua:10: in main chunk
"""
    log_file.write_text(content, encoding='utf-8')

    ca = CrashAnalyzer()
    info = ca.analyze_log(str(log_file))

    # Should detect errors
    assert len(info.get('errors', [])) >= 1
    # Should detect stack trace
    assert len(info.get('crash_indicators', [])) >= 1


# Memory Analyzer Tests

def test_memory_analyzer_init():
    """Test MemoryAnalyzer initialization."""
    ma = MemoryAnalyzer()
    assert ma.result is not None
    assert isinstance(ma.result, DeepAnalysisResult)


def test_memory_analyzer_extract_strings_advanced():
    """Test advanced string extraction with offsets and confidence scores."""
    ma = MemoryAnalyzer()
    data = b"\x00\x00myresource/client.lua\x00\x00another/script.js\x00"
    strings = ma._extract_strings_advanced(data, min_length=4)

    # Should return tuples of (string, offset, confidence)
    assert len(strings) > 0
    string_values = [s[0] for s in strings]
    assert any('myresource' in s for s in string_values)
    assert any('client.lua' in s for s in string_values)
    # Properly null-terminated strings should have high confidence
    for s, offset, confidence in strings:
        assert 0.0 <= confidence <= 1.0


def test_word_fragment_filtering():
    """Test that word fragments like 'rors' are filtered out or penalized."""
    ma = MemoryAnalyzer()
    
    # Test that word fragments are in the blocklist
    assert 'rors' in ma.WORD_FRAGMENTS
    assert 'rror' in ma.WORD_FRAGMENTS
    assert 'ource' in ma.WORD_FRAGMENTS
    
    # Test that _is_valid_resource_name rejects word fragments
    assert not ma._is_valid_resource_name('rors')
    assert not ma._is_valid_resource_name('rror')
    assert not ma._is_valid_resource_name('ource')
    
    # Test that valid resource names still pass
    assert ma._is_valid_resource_name('qb-core')
    assert ma._is_valid_resource_name('oxmysql')
    assert ma._is_valid_resource_name('es_extended')
    
    # Test that string extraction penalizes word fragments
    data = b"\x00\x00rors\x00\x00myresource\x00\x00"
    strings = ma._extract_strings_advanced(data, min_length=4)
    
    # Find the 'rors' and 'myresource' strings
    rors_confidence = None
    myresource_confidence = None
    for s, offset, confidence in strings:
        if s == 'rors':
            rors_confidence = confidence
        if s == 'myresource':
            myresource_confidence = confidence
    
    # 'rors' should have much lower confidence than 'myresource'
    if rors_confidence is not None and myresource_confidence is not None:
        assert rors_confidence < myresource_confidence


def test_memory_analyzer_lua_stack_extraction():
    """Test Lua stack trace extraction from raw memory."""
    ma = MemoryAnalyzer()

    # Simulate memory containing Lua stack trace
    data = b"""
    some data here
    [myresource/server/main.lua]:42: in function 'processData'
    [myresource/server/main.lua]:10: in main chunk
    more data
    """

    ma.result = DeepAnalysisResult()
    ma._extract_lua_stacks(data)

    assert len(ma.result.lua_stacks) >= 1
    assert len(ma.result.all_evidence) >= 1

    # Check evidence was added
    lua_evidence = [e for e in ma.result.all_evidence
                   if e.evidence_type == EvidenceType.LUA_STACK_TRACE]
    assert len(lua_evidence) >= 1


def test_memory_analyzer_script_error_extraction():
    """Test script error extraction from memory."""
    ma = MemoryAnalyzer()

    data = b"""
    normal memory content
    myresource/client.lua:15: attempt to index nil value 'player'
    more normal content
    SCRIPT ERROR: @otherresource/server.lua:100: bad argument
    """

    ma.result = DeepAnalysisResult()
    ma._find_script_errors(data)

    # Should find at least one error
    assert len(ma.result.script_errors) >= 1

    # Check evidence
    error_evidence = [e for e in ma.result.all_evidence
                     if e.evidence_type == EvidenceType.ERROR_MESSAGE]
    assert len(error_evidence) >= 1


def test_memory_analyzer_fivem_patterns():
    """Test FiveM-specific pattern detection."""
    ma = MemoryAnalyzer()

    data = b"""
    exports['esx_jobs']:getJob('police')
    AddEventHandler('playerConnecting', function)
    Citizen.CreateThread(function()
    resource: testresource
    testresource/fxmanifest.lua
    """

    ma.result = DeepAnalysisResult()
    ma._find_fivem_patterns(data)

    # Should find event handlers
    assert len(ma.result.event_handlers) >= 1
    assert 'playerConnecting' in ma.result.event_handlers


def test_evidence_type_enum():
    """Test EvidenceType enum values."""
    assert EvidenceType.LUA_STACK_TRACE.name == 'LUA_STACK_TRACE'
    assert EvidenceType.SCRIPT_PATH.name == 'SCRIPT_PATH'
    assert EvidenceType.ERROR_MESSAGE.name == 'ERROR_MESSAGE'


def test_script_evidence_dataclass():
    """Test ScriptEvidence dataclass."""
    evidence = ScriptEvidence(
        evidence_type=EvidenceType.LUA_STACK_TRACE,
        script_name='main.lua',
        resource_name='myresource',
        file_path='myresource/main.lua',
        line_number=42,
        function_name='doSomething',
        confidence=0.95
    )

    assert evidence.script_name == 'main.lua'
    assert evidence.resource_name == 'myresource'
    assert evidence.line_number == 42
    assert evidence.confidence == 0.95


def test_resource_info_dataclass():
    """Test ResourceInfo dataclass."""
    info = ResourceInfo(name='myresource')
    info.evidence_count = 5
    info.evidence_types.add(EvidenceType.LUA_STACK_TRACE)
    info.scripts.append('main.lua')

    assert info.name == 'myresource'
    assert info.evidence_count == 5
    assert EvidenceType.LUA_STACK_TRACE in info.evidence_types


def test_crash_report_dataclass():
    """Test CrashReport dataclass."""
    report = CrashReport()

    assert report.dump_file is None
    assert report.log_files == []
    assert report.primary_suspects == []
    assert report.script_errors == []
    assert report.lua_stacks == []
    assert report.all_evidence == []


def test_full_analysis_no_files():
    """Test full analysis with no files."""
    ca = CrashAnalyzer()
    report = ca.full_analysis(dump_path=None, log_paths=None)

    assert isinstance(report, CrashReport)
    assert report.dump_file is None


def test_full_analysis_with_log(tmp_path):
    """Test full analysis with log file."""
    log_file = tmp_path / "test.log"
    log_file.write_text("Error: script crashed\nStarted 'myresource'\n")

    ca = CrashAnalyzer()
    report = ca.full_analysis(log_paths=[str(log_file)])

    assert len(report.log_files) == 1
    assert 'myresource' in report.log_resources


def test_generate_full_report():
    """Test report generation."""
    ca = CrashAnalyzer()
    report = CrashReport()
    report.dump_file = "test.dmp"
    report.exception_code = 0xC0000005
    report.primary_suspects = [
        ResourceInfo(name='badresource')
    ]
    report.primary_suspects[0].evidence_count = 10
    report.primary_suspects[0].evidence_types.add(EvidenceType.ERROR_MESSAGE)

    text = ca.generate_full_report(report)

    assert 'badresource' in text
    assert 'C0000005' in text


def test_get_pinpoint_summary():
    """Test pinpoint summary generation."""
    ca = CrashAnalyzer()
    report = CrashReport()
    report.primary_suspects = [
        ResourceInfo(name='problemscript')
    ]
    report.primary_suspects[0].evidence_count = 5
    report.primary_suspects[0].scripts = ['main.lua', 'client.lua']

    summary = ca.get_pinpoint_summary(report)

    assert 'problemscript' in summary
    assert 'CAUSE' in summary.upper()


def test_get_pinpoint_summary_no_suspects():
    """Test pinpoint summary when no suspects found."""
    ca = CrashAnalyzer()
    report = CrashReport()

    summary = ca.get_pinpoint_summary(report)

    assert 'unable' in summary.lower() or 'pinpoint' in summary.lower()


def test_deep_analysis_result_dataclass():
    """Test DeepAnalysisResult dataclass defaults."""
    result = DeepAnalysisResult()

    assert result.primary_suspects == []
    assert result.all_evidence == []
    assert result.script_errors == []
    assert result.lua_stacks == []
    assert result.js_stacks == []
    assert result.resources == {}
    assert result.analysis_complete is False


def test_lua_stack_frame_dataclass():
    """Test LuaStackFrame dataclass."""
    frame = LuaStackFrame(
        source='myresource/main.lua',
        line=42,
        function_name='update',
        is_c_function=False
    )

    assert frame.source == 'myresource/main.lua'
    assert frame.line == 42
    assert frame.function_name == 'update'
    assert not frame.is_c_function


def test_pattern_match_solutions():
    """Test that crash patterns include solutions."""
    ca = CrashAnalyzer()
    text = "stack overflow exception code 0xc00000fd"
    found = ca.match_patterns(text)

    stack_overflow = [p for p in found if 'Stack Overflow' in p.issue]
    assert len(stack_overflow) > 0
    assert len(stack_overflow[0].solutions) > 0


def test_memory_analyzer_correlate_evidence():
    """Test evidence correlation and scoring."""
    ma = MemoryAnalyzer()
    ma.result = DeepAnalysisResult()

    # Add various evidence for different resources
    ma._add_evidence(ScriptEvidence(
        evidence_type=EvidenceType.ERROR_MESSAGE,
        script_name='main.lua',
        resource_name='badresource',
        confidence=0.95
    ))
    ma._add_evidence(ScriptEvidence(
        evidence_type=EvidenceType.LUA_STACK_TRACE,
        script_name='main.lua',
        resource_name='badresource',
        confidence=0.9
    ))
    ma._add_evidence(ScriptEvidence(
        evidence_type=EvidenceType.SCRIPT_PATH,
        script_name='client.lua',
        resource_name='goodresource',
        confidence=0.5
    ))

    ma._correlate_evidence()

    # badresource should be primary suspect
    assert len(ma.result.primary_suspects) >= 1
    assert ma.result.primary_suspects[0].name == 'badresource'


def test_create_fake_minidump(tmp_path):
    """Test handling of invalid dump file."""
    fake_dump = tmp_path / "fake.dmp"
    fake_dump.write_bytes(b"NOT_A_VALID_DUMP_FILE")

    ca = CrashAnalyzer()
    result = ca.analyze_dump(str(fake_dump))

    assert 'error' in result or result.get('modules') == []


def test_create_minimal_minidump(tmp_path):
    """Test with minimal valid-header minidump."""
    # MDMP header (minimal)
    fake_dump = tmp_path / "minimal.dmp"
    # Write MDMP magic + minimal header
    header = b'MDMP' + b'\x00' * 100 + b'test_resource/script.lua' + b'\x00' * 100
    fake_dump.write_bytes(header)

    ca = CrashAnalyzer()
    result = ca.analyze_dump(str(fake_dump))

    # Should recognize the MDMP header
    assert result.get('error') is None or 'not a valid' not in result.get('error', '').lower()


def test_js_stack_extraction():
    """Test JavaScript stack trace extraction."""
    ma = MemoryAnalyzer()
    ma.result = DeepAnalysisResult()

    data = b"""
    Error: undefined is not a function
    at processPlayer (myresource/client.js:42:15)
    at Object.update (myresource/client.js:10:5)
    """

    ma._extract_js_stacks(data)

    assert len(ma.result.js_stacks) >= 1
    js_evidence = [e for e in ma.result.all_evidence
                  if e.evidence_type == EvidenceType.JS_STACK_TRACE]
    assert len(js_evidence) >= 1


def test_lua_traceback_extraction():
    """Test extraction of full Lua tracebacks."""
    ma = MemoryAnalyzer()
    ma.result = DeepAnalysisResult()

    data = b"""
    some data before
    stack traceback:
        [@myresource/server/main.lua]:42: in function 'processPlayer'
        [@myresource/server/main.lua]:15: in function 'onPlayerConnect'
        [C]: in function 'TriggerEvent'
        [@myresource/server/main.lua]:5: in main chunk
    some data after
    """

    ma._extract_lua_tracebacks(data)

    # Should find the stack trace
    assert len(ma.result.lua_stacks) >= 1
    # Should have multiple frames
    if ma.result.lua_stacks:
        assert len(ma.result.lua_stacks[0]) >= 1


def test_lua_runtime_error_detection():
    """Test detection of Lua runtime errors."""
    ma = MemoryAnalyzer()
    ma.result = DeepAnalysisResult()

    data = b"""
    @myresource/client.lua:55: attempt to index a nil value (global 'player')
    other data
    @otherresource/server.lua:100: attempt to call a nil value (method 'getData')
    """

    ma._find_lua_runtime_errors(data)

    # Should find runtime errors
    assert len(ma.result.script_errors) >= 1
    # Check evidence
    error_evidence = [e for e in ma.result.all_evidence
                     if e.evidence_type == EvidenceType.ERROR_MESSAGE]
    assert len(error_evidence) >= 1


def test_citizenfx_context_detection():
    """Test detection of CitizenFX runtime contexts."""
    ma = MemoryAnalyzer()
    ma.result = DeepAnalysisResult()

    data = b"""
    citizen-scripting-lua runtime initialized
    Loading resource: myresource/fxmanifest.lua
    LuaScriptRuntime executing @myresource/server/main.lua
    """

    ma._find_citizenfx_contexts(data)

    # Should find evidence related to resources
    assert len(ma.result.all_evidence) >= 1


def test_fivem_at_prefix_paths():
    """Test handling of @ prefix in FiveM resource paths."""
    ma = MemoryAnalyzer()
    ma.result = DeepAnalysisResult()

    # FiveM uses @ prefix for resource paths
    data = b"""
    [@myresource/client/main.lua]:25: in function 'init'
    @anotherresource/server/database.lua:100: error here
    """

    ma._extract_lua_stacks(data)
    ma._find_script_errors(data)

    # Should find evidence with proper resource extraction
    resources_found = set()
    for e in ma.result.all_evidence:
        if e.resource_name:
            resources_found.add(e.resource_name)

    # The 'myresource' or 'anotherresource' should be found
    assert len(resources_found) >= 1


def test_lua_error_messages_detection():
    """Test detection of various Lua error message types."""
    ma = MemoryAnalyzer()
    ma.result = DeepAnalysisResult()

    data = b"""
    @resource1/script.lua:10: attempt to call a nil value
    @resource2/script.lua:20: attempt to index a nil value
    @resource3/script.lua:30: bad argument #1 to 'func'
    @resource4/script.lua:40: stack overflow
    """

    ma._find_lua_runtime_errors(data)

    # Should detect multiple error types
    assert len(ma.result.script_errors) >= 1


def test_export_pattern_detection():
    """Test detection of FiveM export patterns."""
    ma = MemoryAnalyzer()
    ma.result = DeepAnalysisResult()

    data = b"""
    local job = exports['esx_jobs']:getCurrentJob()
    exports.myresource:doSomething()
    exports["another_resource"]:call()
    """

    ma._find_fivem_patterns(data)

    # Should find export references
    export_evidence = [e for e in ma.result.all_evidence
                      if 'export' in e.context.lower() or e.script_name == 'export']
    assert len(export_evidence) >= 1

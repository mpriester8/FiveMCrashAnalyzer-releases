
import sys
import os
import unittest
from unittest.mock import MagicMock, Mock, patch
from dataclasses import dataclass

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crash_analyzer.memory_analyzer import MemoryAnalyzer, DeepAnalysisResult
from crash_analyzer.core import CrashAnalyzer, CrashReport

# Mock minidump classes
class MockMinidumpHeader:
    def __init__(self):
        self.TimeDateStamp = 1678886400  # 2023-03-15 16:00:00

class MockSystemInfo:
    def __init__(self):
        self.ProcessorArchitecture = "AMD64 (9)"
        self.ProcessorLevel = 6
        self.NumberOfProcessors = 8
        self.MajorVersion = 10
        self.MinorVersion = 0
        self.BuildNumber = 19045

class MockMiscInfo:
    def __init__(self):
        self.ProcessId = 12345
        self.ProcessCreateTime = 1678880000

class MockUnloadedModule:
    def __init__(self, name):
        self.name = name

class MockUnloadedModules:
    def __init__(self):
        self.modules = [MockUnloadedModule("unloaded.dll"), MockUnloadedModule("old.dll")]

class MockExceptionInner:
    def __init__(self):
        self.ExceptionCode = 0xC0000005
        self.ExceptionAddress = 0x7FF000001234

class MockExceptionRecord:
    def __init__(self):
        self.ThreadId = 1
        self.ExceptionRecord = MockExceptionInner()

class MockExceptionStream:
    def __init__(self):
        self.exception_records = [MockExceptionRecord()]

class MockContext:
    def __init__(self):
        self.Rax = 0xAAAAAAAA
        self.Rbx = 0xBBBBBBBB
        self.Rip = 0x7FF000001234
        self.ContextFlags = 0x1000

class MockThread:
    def __init__(self, tid):
        self.ThreadId = tid
        self.ContextObject = MockContext() if tid == 1 else None
        self.Stack = MagicMock()
        self.Stack.StartOfMemoryRange = 0x1000
        self.Stack.Memory.DataSize = 0

class MockThreadList:
    def __init__(self):
        self.threads = [MockThread(1), MockThread(2)]

class MockMinidumpFile:
    def __init__(self):
        self.header = MockMinidumpHeader()
        self.sysinfo = MockSystemInfo()
        self.misc_info = MockMiscInfo()
        self.unloaded_modules = MockUnloadedModules()
        self.exception = MockExceptionStream()
        self.threads = MockThreadList()
        self.modules = None
        self.memory_segments = None
        self.memory_segments_64 = None

    def get_reader(self):
        return MagicMock()

class TestExtraction(unittest.TestCase):
    def test_deep_analysis_extraction(self):
        analyzer = MemoryAnalyzer()

        # Inject our mock minidump
        md = MockMinidumpFile()

        # Call the structure analysis directly
        analyzer._analyze_minidump_structure(md)

        result = analyzer.result

        # Verify Extractions
        print("Verifying System Info...")
        self.assertEqual(result.system_info['NumberOfProcessors'], 8)
        self.assertEqual(result.system_info['BuildNumber'], 19045)

        print("Verifying Crash Time...")
        self.assertEqual(result.crash_time, 1678886400)

        print("Verifying Misc Info...")
        self.assertEqual(result.misc_info['ProcessId'], 12345)

        print("Verifying Unloaded Modules...")
        self.assertIn("unloaded.dll", result.unloaded_modules)
        self.assertIn("old.dll", result.unloaded_modules)

        print("Verifying Exception Context...")
        self.assertEqual(result.exception_context['Rax'], 0xAAAAAAAA)
        self.assertEqual(result.exception_context['Rip'], 0x7FF000001234)

        print("Verifying Exception Code...")
        self.assertEqual(result.exception_code, 0xC0000005)

    @patch('os.path.exists')
    def test_full_report_generation(self, mock_exists):
        mock_exists.return_value = True

        # Create a populated DeepAnalysisResult
        result = DeepAnalysisResult()
        result.system_info = {'OS': 'Windows 10', 'Cores': 4}
        result.crash_time = 1600000000
        result.misc_info = {'PID': 999}
        result.exception_context = {'RAX': 0x123, 'RBX': 0x456}
        result.unloaded_modules = ['bad.dll']
        result.exception_code = 0xC0000005
        result.exception_address = 0x123456

        # Mock the memory analyzer to return this result
        analyzer = CrashAnalyzer()
        analyzer.memory_analyzer.analyze_dump_deep = MagicMock(return_value=result)
        analyzer.analyze_dump = MagicMock(return_value={'file': 'test.dmp', 'raw_data': []})

        # Run full analysis
        report = analyzer.full_analysis('fake.dmp')

        # Check transfer to CrashReport
        self.assertEqual(report.system_info['OS'], 'Windows 10')
        self.assertEqual(report.crash_time, 1600000000)
        self.assertEqual(report.exception_context['RAX'], 0x123)

        # Generate text report
        text = analyzer.generate_full_report(report)
        print("\nGenerated Report Snippet:")
        print(text[:500]) # Print start of report

        # Verify text presence
        self.assertIn("SYSTEM INFORMATION:", text)
        self.assertIn("OS: Windows 10", text)
        self.assertIn("Crash Time:", text)
        self.assertIn("MISC INFORMATION:", text)
        self.assertIn("PID: 999", text)
        self.assertIn("CPU Registers (Exception Context):", text)
        self.assertIn("RAX: 0x123", text)
        self.assertIn("UNLOADED MODULES:", text)
        self.assertIn("bad.dll", text)

if __name__ == "__main__":
    unittest.main()

"""
WinDbg Wrapper Module - Automates crash dump analysis with WinDbg/CDB
Part of FiveM Crash Analyzer

Handles:
- WinDbg/CDB detection and location
- Script generation
- Dump file analysis
- Output parsing
- Symbol resolution
"""

import subprocess
import os
import re
import json
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field


@dataclass
class WinDbgStackFrame:
    """Represents a single stack frame from WinDbg output"""
    frame_number: int
    address: str
    module: Optional[str] = None
    function: Optional[str] = None
    offset: Optional[str] = None
    source_file: Optional[str] = None
    line_number: Optional[int] = None
    is_fivem_related: bool = False
    resource_name: Optional[str] = None  # Detected FiveM resource if applicable


@dataclass
class WinDbgAnalysisResult:
    """Complete WinDbg analysis result"""
    success: bool
    error_message: Optional[str] = None
    
    # Exception info
    exception_code: Optional[int] = None
    exception_address: Optional[int] = None
    exception_module: Optional[str] = None
    
    # Stack trace
    stack_frames: List[WinDbgStackFrame] = field(default_factory=list)
    
    # Module info
    loaded_modules: Dict[str, Dict] = field(default_factory=dict)
    fivem_modules: List[str] = field(default_factory=list)
    
    # Analysis results
    culprit_module: Optional[str] = None
    culprit_resource: Optional[str] = None
    confidence: float = 0.0  # 0.0-1.0
    
    # Raw output
    raw_output: str = ""
    summary: str = ""


class WinDbgWrapper:
    """Wrapper for WinDbg/CDB crash dump analysis"""
    
    CDB_PATHS = [
        r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe",
        r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\cdb.exe",
        r"C:\Program Files (x86)\Windows Kits\11\Debuggers\x64\cdb.exe",
        r"C:\Program Files (x86)\Windows Kits\11\Debuggers\x86\cdb.exe",
        r"C:\Program Files\Windows Kits\10\Debuggers\x64\cdb.exe",
        r"C:\Program Files\Windows Kits\11\Debuggers\x64\cdb.exe",
    ]
    
    # WinDbg Preview paths (Microsoft Store version)
    WINDBGX_PATHS = [
        os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\WindowsApps\WinDbgX.exe"),
        os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\WinDbg\WinDbgX.exe"),
    ]
    
    FIVEM_MODULE_NAMES = [
        "fivem", "gta5", "rage", "scripthook", "cfx", "NativeUI",
        "RedM", "cerbersus", "adhesive", "fxkernal"
    ]
    
    def __init__(self):
        """Initialize WinDbg wrapper"""
        self.is_windbgx = False  # Set before _find_cdb() so it can be updated
        self.cdb_path = self._find_cdb()
        self.available = self.cdb_path is not None
    
    def _find_cdb(self) -> Optional[str]:
        """Find CDB (console debugger) or WinDbgX executable"""
        # Try CDB first (preferred for automation)
        for path in self.CDB_PATHS:
            if os.path.exists(path):
                return path
        
        # Try to find via PATH
        try:
            # CREATE_NO_WINDOW flag prevents console window from appearing
            result = subprocess.run(
                ['where', 'cdb.exe'], 
                capture_output=True, 
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
            )
            if result.returncode == 0:
                return result.stdout.strip().split('\n')[0]
        except Exception:
            # PATH lookup failed; try WinDbg Preview as fallback
            pass
        
        # Try WinDbg Preview (WinDbgX) as fallback
        for path in self.WINDBGX_PATHS:
            if os.path.exists(path):
                self.is_windbgx = True
                return path
        
        # Try via PATH for WinDbgX
        try:
            # CREATE_NO_WINDOW flag prevents console window from appearing
            result = subprocess.run(
                ['where', 'windbgx.exe'], 
                capture_output=True, 
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
            )
            if result.returncode == 0:
                self.is_windbgx = True
                return result.stdout.strip().split('\n')[0]
        except Exception:
            # WinDbgX PATH lookup failed; return None (not installed)
            pass
        
        return None
    
    def generate_analysis_script(self, output_file: str) -> str:
        """Generated WinDbg command script for crash analysis"""
        commands = [
            ".echo ========== CRASH ANALYSIS ==========",
            ".echo Dump Analysis Started",
            ".echo",
            ".exr -1",  # Get last exception
            ".echo",  
            ".echo Exception Record above",
            ".echo",
            "~.",  # Current thread
            ".echo",
            ".echo ========== STACK TRACE ==========",
            "k 30",  # Stack trace, limit to 30 frames
            ".echo",
            "kn 30",  # Numbered stack trace
            ".echo",
            ".echo ========== MODULES ==========",
            "lmv m fivem*",  # FiveM modules, verbose
            "lmv m gta*",  # GTA modules
            "lmv m cfx*",  # CFX modules
            ".echo",
            ".echo ========== CRASH LOCATION ==========", 
            ".cxr",  # Current context record
            ".echo",
            ".echo ========== END ANALYSIS ==========",
            "q"  # Quit
        ]
        
        return "\n".join(commands)
    
    def analyze_dump(self, dump_path: str) -> WinDbgAnalysisResult:
        """
        Analyze crash dump using WinDbg/CDB
        
        Args:
            dump_path: Path to the minidump file (.dmp)
        
        Returns:
            WinDbgAnalysisResult with full analysis
        """
        if not self.available:
            return WinDbgAnalysisResult(
                success=False,
                error_message="WinDbg/CDB not found. Install 'Debugging Tools for Windows' from Windows SDK"
            )
        
        if not os.path.exists(dump_path):
            return WinDbgAnalysisResult(
                success=False,
                error_message=f"Dump file not found: {dump_path}"
            )
        
        # Generate command script
        script_content = self.generate_analysis_script("")
        
        # Create temp script file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(script_content)
            script_path = f.name
        
        # Create temp log file for output (especially for WinDbgX)
        log_file = tempfile.NamedTemporaryFile(mode='w', suffix='_windbg_output.txt', delete=False)
        log_path = log_file.name
        log_file.close()
        
        try:
            # Calculate timeout based on dump size (minimum 120 seconds, +30s per GB)
            try:
                dump_size_gb = os.path.getsize(dump_path) / (1024**3)
                timeout = max(120, int(120 + (dump_size_gb * 30)))
            except Exception:
                # Could not determine file size; use default timeout
                timeout = 120
            
            # Run CDB or WinDbgX with dump file
            if self.is_windbgx:
                # WinDbgX command-line mode with -logo for output capture
                cmd = [
                    self.cdb_path,
                    "-logo", log_path,  # Redirect output to log file
                    "-z", dump_path,  # Load dump
                    "-c", f"$$>< {script_path}"  # Execute commands from script
                ]
                print(f"[WinDbgX] Running: {os.path.basename(self.cdb_path)} -z {os.path.basename(dump_path)}...")
                print(f"[WinDbgX] Output log: {log_path}")
                print(f"[WinDbgX] Timeout: {timeout}s (dump size: {dump_size_gb:.2f} GB)")
            else:
                # CDB command-line mode
                cmd = [
                    self.cdb_path,
                    "-logo", log_path,  # Redirect output to log file (works for CDB too)
                    "-z", dump_path,  # Load dump
                    "-c", f"$$>< {script_path}",  # Execute commands from script
                ]
                print(f"[CDB] Running: {' '.join(cmd[:3])}...")
                print(f"[CDB] Timeout: {timeout}s")
            
            # CREATE_NO_WINDOW flag prevents console window from appearing during WinDbg execution
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
            )
            
            # Read output from log file (more reliable than stdout/stderr for WinDbgX)
            output = ""
            if os.path.exists(log_path):
                with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                    output = f.read()
            
            # Fallback to stdout/stderr if log file is empty
            if not output:
                output = result.stdout + result.stderr
            
            # Parse output
            return self._parse_output(output, dump_path)
            
        except subprocess.TimeoutExpired:
            # Try to read partial output from log file
            partial_output = ""
            if os.path.exists(log_path):
                try:
                    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                        partial_output = f.read()
                except Exception:
                    # Could not read log file; continue with empty partial output
                    pass
            
            return WinDbgAnalysisResult(
                success=False,
                error_message=f"WinDbg analysis timed out after {timeout} seconds. Partial output may be available in: {log_path}",
                raw_output=partial_output[:5000] if partial_output else ""
            )
        except Exception as e:
            return WinDbgAnalysisResult(
                success=False,
                error_message=f"WinDbg execution error: {str(e)}"
            )
        finally:
            # Cleanup temp files
            try:
                os.unlink(script_path)
            except Exception:
                # Could not delete temporary script file
                pass
            try:
                if os.path.exists(log_path):
                    os.unlink(log_path)
            except Exception:
                # Could not delete temporary log file
                pass
    
    def _parse_output(self, output: str, dump_path: str) -> WinDbgAnalysisResult:
        """Parse WinDbg output and extract useful information"""
        result = WinDbgAnalysisResult(success=True, raw_output=output[:5000])
        
        lines = output.split('\n')
        in_stack_section = False
        in_modules_section = False
        stack_frames = []
        
        for i, line in enumerate(lines):
            line = line.strip()
            
            # Parse exception info
            if "ExceptionCode:" in line or "exception code" in line.lower():
                match = re.search(r'0x[0-9a-fA-F]+', line)
                if match:
                    result.exception_code = int(match.group(), 16)
            
            if "ExceptionAddress:" in line or "exception address" in line.lower():
                match = re.search(r'0x[0-9a-fA-F]+', line)
                if match:
                    result.exception_address = int(match.group(), 16)
            
            # Parse stack trace
            if "STACK TRACE" in line:
                in_stack_section = True
                in_modules_section = False
                continue
            
            if "MODULES" in line:
                in_modules_section = True
                in_stack_section = False
                continue
            
            if "END ANALYSIS" in line:
                in_stack_section = False
                in_modules_section = False
                continue
            
            # Extract stack frames
            if in_stack_section and line and not line.startswith('#') and not line.startswith('*'):
                # WinDbg stack format: "00 0000007c`8157c958 00007ffc`968f2533     ntdll!NtWaitForMultipleObjects+0x14"
                # Pattern: frame# child-SP retAddr module!function
                match = re.match(r'^([0-9a-f]{2,3})\s+([0-9a-f`]+)\s+([0-9a-f`]+)\s+(\S+?)!(.+)', line, re.IGNORECASE)
                if match:
                    frame_num = int(match.group(1), 16)  # Frame number is hex
                    child_sp = match.group(2)
                    ret_addr = match.group(3)
                    module = match.group(4)
                    function = match.group(5).strip()
                    
                    # Check if FiveM-related
                    is_fivem = any(fivem in module.lower() for fivem in self.FIVEM_MODULE_NAMES)
                    
                    # Try to extract resource name from function signature
                    resource = None
                    if "@" in function:
                        parts = function.split("@")
                        if len(parts) > 1:
                            resource = parts[1].split("/")[0]
                    
                    frame = WinDbgStackFrame(
                        frame_number=frame_num,
                        address=ret_addr.replace('`', ''),  # Remove backticks
                        module=module,
                        function=function,
                        is_fivem_related=is_fivem,
                        resource_name=resource
                    )
                    stack_frames.append(frame)
            
            # Extract module info
            if in_modules_section and line and not line.startswith('*'):
                # Match patterns like: "Start             End                 Module name"
                parts = line.split()
                if len(parts) >= 3:
                    try:
                        start = parts[0]
                        end = parts[1]
                        module_name = " ".join(parts[2:])
                        
                        # Store module info
                        result.loaded_modules[module_name] = {
                            'start': start,
                            'end': end
                        }
                        
                        # Track FiveM modules
                        if any(fivem in module_name.lower() for fivem in self.FIVEM_MODULE_NAMES):
                            result.fivem_modules.append(module_name)
                    except Exception:
                        # Could not parse stack frame; continue with next frame
                        pass
        
        result.stack_frames = stack_frames
        
        # Determine culprit
        if stack_frames:
            # Find first FiveM-related frame in stack
            for frame in stack_frames:
                if frame.is_fivem_related or frame.resource_name:
                    result.culprit_module = frame.module
                    result.culprit_resource = frame.resource_name
                    result.confidence = 0.8 if frame.is_fivem_related else 0.6
                    break
            
            # If no FiveM frame, use first frame
            if not result.culprit_module and stack_frames:
                result.culprit_module = stack_frames[0].module
                result.culprit_resource = stack_frames[0].resource_name
                result.confidence = 0.4
        
        # Generate summary
        result.summary = self._generate_summary(result)
        
        return result
    
    def _generate_summary(self, result: WinDbgAnalysisResult) -> str:
        """Generate human-readable summary"""
        lines = []
        
        lines.append("=" * 70)
        lines.append("WinDbg CRASH ANALYSIS SUMMARY")
        lines.append("=" * 70)
        lines.append("")
        
        if result.exception_code:
            lines.append(f"Exception Code:  0x{result.exception_code:08X}")
        if result.exception_address:
            lines.append(f"Exception Address: 0x{result.exception_address:016X}")
        
        lines.append(f"FiveM Modules Found: {len(result.fivem_modules)}")
        if result.fivem_modules:
            for mod in result.fivem_modules[:5]:
                lines.append(f"  - {mod}")
        
        lines.append("")
        lines.append(f"Stack Frames: {len(result.stack_frames)}")
        
        if result.stack_frames:
            lines.append("\nTop 5 Stack Frames:")
            for frame in result.stack_frames[:5]:
                fivem_indicator = " [FiveM]" if frame.is_fivem_related else ""
                lines.append(f"  {frame.frame_number}: {frame.module}!{frame.function}{fivem_indicator}")
        
        if result.culprit_module:
            lines.append("")
            lines.append(f"Likely Culprit Module: {result.culprit_module}")
            lines.append(f"Confidence: {result.confidence:.1%}")
            if result.culprit_resource:
                lines.append(f"Associated Resource: {result.culprit_resource}")
        
        lines.append("")
        lines.append("=" * 70)
        
        return "\n".join(lines)


if __name__ == "__main__":
    # Test
    wrapper = WinDbgWrapper()
    
    print("WinDbg Wrapper Test")
    print(f"CDB available: {wrapper.available}")
    if wrapper.available:
        print(f"CDB path: {wrapper.cdb_path}")
    
    # You can test with: python crash_analyzer/windbg_wrapper.py

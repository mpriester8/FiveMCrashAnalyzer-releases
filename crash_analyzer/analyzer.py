"""PySide6 GUI wrapper for the FiveM Crash Analyzer with deep analysis support."""
from PySide6 import QtWidgets, QtCore, QtGui
from PySide6.QtWidgets import (
    QApplication, QFileDialog, QTextEdit, QPushButton, QLabel,
    QHBoxLayout, QVBoxLayout, QWidget, QProgressBar, QTabWidget,
    QGroupBox, QListWidget, QSplitter, QFrame
)
from PySide6.QtCore import Qt, Signal, QThread
import os
from datetime import datetime
from crash_analyzer.core import CrashAnalyzer, CrashReport
from crash_analyzer.heap_analyzer import HeapTimelineAnalyzer, HeapAnalysisResult


class AnalysisWorker(QThread):
    """Background worker for crash analysis."""
    finished = Signal(object)  # Emits list of (filename, CrashReport) tuples
    progress = Signal(str)  # Emits status messages
    error = Signal(str)

    def __init__(self, analyzer, dump_files, log_files):
        super().__init__()
        self.analyzer = analyzer
        self.dump_files = dump_files if dump_files else []
        self.log_files = log_files

    def run(self):
        try:
            results = []

            if not self.dump_files:
                # No dump files, just analyze logs
                self.progress.emit("Analyzing log files only...")
                report = self.analyzer.full_analysis(
                    dump_path=None,
                    log_paths=self.log_files
                )
                results.append(("logs_only", report))
            else:
                # Analyze each dump file
                total = len(self.dump_files)
                for i, dump_file in enumerate(self.dump_files, 1):
                    filename = os.path.basename(dump_file)
                    self.progress.emit(f"Analyzing dump {i}/{total}: {filename}...")

                    report = self.analyzer.full_analysis(
                        dump_path=dump_file,
                        log_paths=self.log_files if i == 1 else []  # Only include logs with first dump
                    )
                    results.append((filename, report))

            self.progress.emit("Analysis complete!")
            self.finished.emit(results)

        except Exception as e:
            self.error.emit(str(e))


class CrashAnalyzerGUI(QWidget):
    """Main GUI for FiveM Crash Analyzer with deep memory analysis."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle('FiveM Crash Analyzer - Deep Memory Analysis')
        self.resize(1100, 800)
        self._set_window_icon()
        self.analyzer = CrashAnalyzer()
        self.heap_analyzer = HeapTimelineAnalyzer()
        self.dump_files = []  # Changed to list for multiple files
        self.log_files = []
        self.heap_files = []  # Heap timeline files
        self.current_reports = []  # List of (filename, report) tuples
        self.current_heap_results = []  # List of HeapAnalysisResult
        self._build_ui()
    
    def _set_window_icon(self):
        """Set window icon for the application."""
        # Try to load icon from multiple possible locations
        # Prefer .ico for Windows for proper taskbar icon display
        icon_paths = [
            os.path.abspath(os.path.join(os.path.dirname(__file__), 'icon.ico')),
            os.path.abspath(os.path.join(os.path.dirname(__file__), 'icon.png')),
            os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'icon.ico')),
            os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'icon.png')),
        ]
        
        for icon_path in icon_paths:
            if os.path.exists(icon_path):
                icon = QtGui.QIcon(icon_path)
                if not icon.isNull():
                    self.setWindowIcon(icon)
                    return
        
        # If no icon file found, create a simple colored icon programmatically
        self._create_default_icon()
    
    def _create_default_icon(self):
        """Create a professional-looking default icon if no icon file exists."""
        # Create a 64x64 pixmap with a modern crash/debug symbol
        pixmap = QtGui.QPixmap(64, 64)
        pixmap.fill(QtCore.Qt.transparent)
        
        painter = QtGui.QPainter(pixmap)
        painter.setRenderHint(QtGui.QPainter.Antialiasing)
        
        # Draw background circle with gradient
        gradient = QtGui.QRadialGradient(32, 32, 32)
        gradient.setColorAt(0, QtGui.QColor(220, 53, 69))  # Red center (crash/alert color)
        gradient.setColorAt(1, QtGui.QColor(180, 35, 50))  # Darker red edges
        painter.setBrush(gradient)
        painter.setPen(QtGui.QPen(QtGui.QColor(100, 20, 30), 2))
        painter.drawEllipse(2, 2, 60, 60)
        
        # Draw warning/bug symbol
        painter.setPen(QtGui.QPen(QtCore.Qt.white, 3, QtCore.Qt.SolidLine, QtCore.Qt.RoundCap))
        
        # Draw exclamation mark
        painter.drawLine(32, 16, 32, 38)  # Vertical line
        painter.drawPoint(32, 46)  # Dot
        
        # Draw circuit/bug antenna lines
        painter.setPen(QtGui.QPen(QtGui.QColor(255, 255, 255, 180), 2))
        painter.drawLine(22, 20, 18, 12)  # Left antenna
        painter.drawLine(42, 20, 46, 12)  # Right antenna
        
        painter.end()
        
        icon = QtGui.QIcon(pixmap)
        self.setWindowIcon(icon)

    def _build_ui(self):
        main_layout = QVBoxLayout()

        # Header
        header = QLabel("FiveM Crash Analyzer")
        header.setStyleSheet("font-size: 18px; font-weight: bold; padding: 10px;")
        main_layout.addWidget(header)

        # File selection group
        file_group = QGroupBox("File Selection")
        file_layout = QVBoxLayout()

        # Dump file row
        dump_row = QHBoxLayout()
        self.dump_label = QLabel("No dump files selected")
        self.dump_label.setStyleSheet("color: gray;")
        dump_row.addWidget(self.dump_label, 1)
        self.dump_btn = QPushButton('Select .dmp Files')
        self.dump_btn.setToolTip("Select one or more minidump files to analyze")
        self.dump_btn.clicked.connect(self.select_dump)
        dump_row.addWidget(self.dump_btn)
        file_layout.addLayout(dump_row)

        # Log files row
        log_row = QHBoxLayout()
        self.log_label = QLabel("No log files selected")
        self.log_label.setStyleSheet("color: gray;")
        log_row.addWidget(self.log_label, 1)
        self.log_btn = QPushButton('Select Log Files')
        self.log_btn.clicked.connect(self.select_logs)
        log_row.addWidget(self.log_btn)
        file_layout.addLayout(log_row)

        # Heap timeline files row (optional)
        heap_row = QHBoxLayout()
        self.heap_label = QLabel("No heap timeline files (optional)")
        self.heap_label.setStyleSheet("color: gray;")
        heap_row.addWidget(self.heap_label, 1)
        self.heap_btn = QPushButton('Select Heap Timeline')
        self.heap_btn.setToolTip("Optional: Select heap timeline JSON files to analyze for memory leaks")
        self.heap_btn.clicked.connect(self.select_heap_files)
        heap_row.addWidget(self.heap_btn)
        file_layout.addLayout(heap_row)

        file_group.setLayout(file_layout)
        main_layout.addWidget(file_group)

        # Action buttons
        action_layout = QHBoxLayout()
        self.analyze_btn = QPushButton('Analyze Crash (Deep Memory Dive)')
        self.analyze_btn.setStyleSheet("font-weight: bold; padding: 10px;")
        self.analyze_btn.clicked.connect(self.analyze)
        action_layout.addWidget(self.analyze_btn)

        self.clear_btn = QPushButton('Clear All')
        self.clear_btn.clicked.connect(self.clear_files)
        action_layout.addWidget(self.clear_btn)
        main_layout.addLayout(action_layout)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        main_layout.addWidget(self.progress_bar)

        # Status label
        self.status_label = QLabel("")
        self.status_label.setStyleSheet("color: blue;")
        main_layout.addWidget(self.status_label)

        # Results tabs
        self.tabs = QTabWidget()

        # Summary tab
        self.summary_text = QTextEdit()
        self.summary_text.setReadOnly(True)
        self.summary_text.setStyleSheet("font-family: monospace;")
        self.tabs.addTab(self.summary_text, "Summary")

        # Primary Suspects tab
        self.suspects_text = QTextEdit()
        self.suspects_text.setReadOnly(True)
        self.suspects_text.setStyleSheet("font-family: monospace;")
        self.tabs.addTab(self.suspects_text, "Primary Suspects")

        # Script Errors tab
        self.errors_text = QTextEdit()
        self.errors_text.setReadOnly(True)
        self.errors_text.setStyleSheet("font-family: monospace;")
        self.tabs.addTab(self.errors_text, "Script Errors")

        # Stack Traces tab
        self.stacks_text = QTextEdit()
        self.stacks_text.setReadOnly(True)
        self.stacks_text.setStyleSheet("font-family: monospace;")
        self.tabs.addTab(self.stacks_text, "Stack Traces")

        # Full Report tab
        self.full_report_text = QTextEdit()
        self.full_report_text.setReadOnly(True)
        self.full_report_text.setStyleSheet("font-family: monospace;")
        self.tabs.addTab(self.full_report_text, "Full Report")

        # Memory Leaks tab (for heap timeline analysis)
        self.memory_leaks_text = QTextEdit()
        self.memory_leaks_text.setReadOnly(True)
        self.memory_leaks_text.setStyleSheet("font-family: monospace;")
        self.tabs.addTab(self.memory_leaks_text, "Memory Leaks")

        main_layout.addWidget(self.tabs, 1)

        # Bottom buttons
        bottom = QHBoxLayout()
        self.save_btn = QPushButton('Save Report')
        self.save_btn.clicked.connect(self.save_report)
        bottom.addWidget(self.save_btn)

        self.copy_btn = QPushButton('Copy to Clipboard')
        self.copy_btn.clicked.connect(self.copy_report)
        bottom.addWidget(self.copy_btn)

        self.copy_summary_btn = QPushButton('Copy Summary Only')
        self.copy_summary_btn.clicked.connect(self.copy_summary)
        bottom.addWidget(self.copy_summary_btn)

        main_layout.addLayout(bottom)

        self.setLayout(main_layout)

    def select_dump(self):
        paths, _ = QFileDialog.getOpenFileNames(
            self, 'Select .dmp files (can select multiple)',
            filter='Minidump Files (*.dmp);;All Files (*)'
        )
        if paths:
            self.dump_files = paths
            if len(paths) == 1:
                self.dump_label.setText(os.path.basename(paths[0]))
            else:
                self.dump_label.setText(f"{len(paths)} dump files selected")
            self.dump_label.setStyleSheet("color: green; font-weight: bold;")

    def select_logs(self):
        paths, _ = QFileDialog.getOpenFileNames(
            self, 'Select log files',
            filter='Log Files (*.log *.txt);;All Files (*)'
        )
        if paths:
            self.log_files = paths
            self.log_label.setText(f"{len(paths)} file(s) selected")
            self.log_label.setStyleSheet("color: green;")

    def select_heap_files(self):
        paths, _ = QFileDialog.getOpenFileNames(
            self, 'Select heap timeline JSON files',
            filter='Heap Timeline (*.json);;All Files (*)'
        )
        if paths:
            self.heap_files = paths
            if len(paths) == 1:
                self.heap_label.setText(os.path.basename(paths[0]))
            else:
                self.heap_label.setText(f"{len(paths)} heap file(s) selected")
            self.heap_label.setStyleSheet("color: green;")

    def clear_files(self):
        self.dump_files = []
        self.log_files = []
        self.heap_files = []
        self.current_reports = []
        self.current_heap_results = []
        self.dump_label.setText("No dump files selected")
        self.dump_label.setStyleSheet("color: gray;")
        self.log_label.setText("No log files selected")
        self.log_label.setStyleSheet("color: gray;")
        self.heap_label.setText("No heap timeline files (optional)")
        self.heap_label.setStyleSheet("color: gray;")
        self.summary_text.clear()
        self.suspects_text.clear()
        self.errors_text.clear()
        self.stacks_text.clear()
        self.full_report_text.clear()
        self.memory_leaks_text.clear()
        self.status_label.setText("")

    def analyze(self):
        if not self.dump_files and not self.log_files and not self.heap_files:
            self.status_label.setText('Please select at least one file to analyze')
            self.status_label.setStyleSheet("color: red;")
            return

        self.analyze_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate
        self.status_label.setText("Analyzing...")
        self.status_label.setStyleSheet("color: blue;")

        # Clear previous results
        self.summary_text.clear()
        self.suspects_text.clear()
        self.errors_text.clear()
        self.stacks_text.clear()
        self.full_report_text.clear()
        self.memory_leaks_text.clear()

        # Analyze heap timeline files first (synchronous, fast)
        self.current_heap_results = []
        if self.heap_files:
            self.status_label.setText("Analyzing heap timeline files...")
            for heap_file in self.heap_files:
                result = self.heap_analyzer.analyze_file(heap_file)
                self.current_heap_results.append(result)
            self._display_heap_results(self.current_heap_results)

        # If only heap files, we're done
        if not self.dump_files and not self.log_files:
            self.progress_bar.setVisible(False)
            self.analyze_btn.setEnabled(True)
            self.status_label.setText(f"Heap analysis complete! ({len(self.heap_files)} file(s))")
            self.status_label.setStyleSheet("color: green;")
            self.tabs.setCurrentWidget(self.memory_leaks_text)
            return

        # Run crash dump analysis in background thread
        self.worker = AnalysisWorker(
            self.analyzer, self.dump_files, self.log_files
        )
        self.worker.finished.connect(self.on_analysis_complete)
        self.worker.progress.connect(self.on_progress)
        self.worker.error.connect(self.on_error)
        self.worker.start()

    def on_progress(self, message):
        self.status_label.setText(message)

    def on_error(self, error_msg):
        self.progress_bar.setVisible(False)
        self.analyze_btn.setEnabled(True)
        self.status_label.setText(f"Error: {error_msg}")
        self.status_label.setStyleSheet("color: red;")

    def on_analysis_complete(self, results):
        """Handle completion of analysis for one or more dump files.

        Args:
            results: List of (filename, CrashReport) tuples
        """
        self.current_reports = results
        self.progress_bar.setVisible(False)
        self.analyze_btn.setEnabled(True)

        num_dumps = len(results)
        self.status_label.setText(f"Analysis complete! ({num_dumps} dump{'s' if num_dumps != 1 else ''} analyzed)")
        self.status_label.setStyleSheet("color: green;")

        if num_dumps == 1:
            # Single dump - show normal view
            filename, report = results[0]
            self._display_single_report(report)
        else:
            # Multiple dumps - show combined view
            self._display_multiple_reports(results)

        # Switch to Summary tab
        self.tabs.setCurrentIndex(0)

    def _display_single_report(self, report: CrashReport):
        """Display a single report in all tabs."""
        # Populate Summary tab
        summary = self._generate_summary(report)
        self.summary_text.setPlainText(summary)

        # Populate Primary Suspects tab
        suspects = self._generate_suspects_view(report)
        self.suspects_text.setPlainText(suspects)

        # Populate Script Errors tab
        errors = self._generate_errors_view(report)
        self.errors_text.setPlainText(errors)

        # Populate Stack Traces tab
        stacks = self._generate_stacks_view(report)
        self.stacks_text.setPlainText(stacks)

        # Populate Full Report tab
        full_report = self.analyzer.generate_full_report(report)
        self.full_report_text.setPlainText(full_report)

    def _display_multiple_reports(self, results):
        """Display combined view for multiple reports."""
        # Generate combined summary
        summary_lines = []
        summary_lines.append("=" * 70)
        summary_lines.append(f"COMBINED CRASH ANALYSIS - {len(results)} DUMP FILES")
        summary_lines.append("=" * 70)
        summary_lines.append("")

        # Aggregate suspects across all dumps with full details
        all_suspects = {}  # name -> {count, evidence_total, dumps, scripts, paths, evidence_types, context}
        all_patterns = {}  # pattern_issue -> count
        all_exception_codes = {}  # code -> count

        for filename, report in results:
            # Count exception codes
            if report.exception_code:
                code = report.exception_code
                if code not in all_exception_codes:
                    all_exception_codes[code] = []
                all_exception_codes[code].append(filename)

            # Aggregate suspects with full details
            for suspect in report.primary_suspects[:5]:
                name = suspect.name
                if name not in all_suspects:
                    all_suspects[name] = {
                        'count': 0,
                        'evidence_total': 0,
                        'dumps': [],
                        'scripts': set(),
                        'paths': set(),
                        'evidence_types': set(),
                        'context': []
                    }
                data = all_suspects[name]
                data['count'] += 1
                data['evidence_total'] += suspect.evidence_count
                data['dumps'].append(filename)

                # Collect scripts
                for script in suspect.scripts:
                    data['scripts'].add(script)

                # Collect paths
                if suspect.path:
                    data['paths'].add(suspect.path)
                if hasattr(suspect, 'all_paths'):
                    for path in suspect.all_paths:
                        data['paths'].add(path)

                # Collect evidence types
                for etype in suspect.evidence_types:
                    data['evidence_types'].add(etype.name)

                # Collect context details
                if hasattr(suspect, 'context_details'):
                    for ctx in suspect.context_details[:3]:
                        if ctx not in data['context']:
                            data['context'].append(ctx)

            # Aggregate patterns
            for pattern in report.crash_patterns:
                if pattern.issue not in all_patterns:
                    all_patterns[pattern.issue] = 0
                all_patterns[pattern.issue] += 1

        # Show exception code breakdown
        if all_exception_codes:
            summary_lines.append("EXCEPTION CODES ACROSS DUMPS:")
            summary_lines.append("-" * 40)
            for code, filenames in sorted(all_exception_codes.items(), key=lambda x: -len(x[1])):
                summary_lines.append(f"  0x{code:08X}: {len(filenames)} dump(s)")
            summary_lines.append("")

        # Show crashing modules
        all_modules = {}  # module -> count
        for filename, report in results:
            if report.exception_module:
                mod = report.exception_module
                if mod not in all_modules:
                    all_modules[mod] = 0
                all_modules[mod] += 1

        if all_modules:
            summary_lines.append("CRASH MODULES (where exception occurred):")
            summary_lines.append("-" * 40)
            for mod, count in sorted(all_modules.items(), key=lambda x: -x[1]):
                summary_lines.append(f"  {mod}: {count} dump(s)")
            summary_lines.append("")

        # Show most common suspects with detailed info
        if all_suspects:
            summary_lines.append("MOST COMMON SUSPECTS ACROSS ALL DUMPS:")
            summary_lines.append("-" * 40)
            sorted_suspects = sorted(all_suspects.items(), key=lambda x: (-x[1]['count'], -x[1]['evidence_total']))
            for name, data in sorted_suspects[:10]:
                summary_lines.append(f"  {name}:")
                summary_lines.append(f"    Appears in: {data['count']}/{len(results)} dumps")
                summary_lines.append(f"    Total Evidence: {data['evidence_total']}")
                if data['scripts']:
                    scripts_list = list(data['scripts'])[:5]
                    summary_lines.append(f"    Scripts: {', '.join(scripts_list)}")
                if data['paths']:
                    paths_list = list(data['paths'])[:3]
                    for path in paths_list:
                        summary_lines.append(f"    Path: {path}")
            summary_lines.append("")

        # Show crash patterns
        if all_patterns:
            summary_lines.append("CRASH PATTERNS DETECTED:")
            summary_lines.append("-" * 40)
            for issue, count in sorted(all_patterns.items(), key=lambda x: -x[1]):
                summary_lines.append(f"  [{issue}]: {count} dump(s)")
            summary_lines.append("")

        # Individual dump summaries
        summary_lines.append("=" * 70)
        summary_lines.append("INDIVIDUAL DUMP SUMMARIES")
        summary_lines.append("=" * 70)

        for filename, report in results:
            summary_lines.append("")
            summary_lines.append(f"--- {filename} ---")
            if report.exception_code:
                summary_lines.append(f"  Exception: 0x{report.exception_code:08X}")
            if report.exception_module:
                summary_lines.append(f"  Module: {report.exception_module}")
            if report.primary_suspects:
                top = report.primary_suspects[0]
                top_info = f"  Top Suspect: {top.name} (score: {top.evidence_count})"
                if top.scripts:
                    top_info += f" - {top.scripts[0]}"
                summary_lines.append(top_info)
            summary_lines.append(f"  Evidence Items: {len(report.all_evidence)}")

        self.summary_text.setPlainText("\n".join(summary_lines))

        # Combine suspects view with detailed information
        suspects_lines = []
        suspects_lines.append("=" * 70)
        suspects_lines.append("PRIMARY SUSPECTS - AGGREGATED FROM ALL DUMPS")
        suspects_lines.append("=" * 70)
        suspects_lines.append("")
        suspects_lines.append("Note: Resource names are extracted from file paths in memory.")
        suspects_lines.append("      Scripts and paths help identify the exact cause.")
        suspects_lines.append("")

        if all_suspects:
            sorted_suspects = sorted(all_suspects.items(), key=lambda x: (-x[1]['count'], -x[1]['evidence_total']))
            for i, (name, data) in enumerate(sorted_suspects[:15], 1):
                suspects_lines.append(f"#{i} {'='*50}")
                suspects_lines.append(f"   RESOURCE: {name}")
                suspects_lines.append(f"   Frequency: {data['count']}/{len(results)} dumps ({100*data['count']//len(results)}%)")
                suspects_lines.append(f"   Total Evidence Score: {data['evidence_total']}")

                # Show evidence types
                if data['evidence_types']:
                    types_str = ', '.join(sorted(data['evidence_types']))
                    suspects_lines.append(f"   Evidence Types: {types_str}")

                # Show scripts involved
                if data['scripts']:
                    scripts_list = sorted(data['scripts'])[:8]
                    suspects_lines.append(f"   Scripts Involved:")
                    for script in scripts_list:
                        suspects_lines.append(f"      - {script}")

                # Show file paths
                if data['paths']:
                    paths_list = sorted(data['paths'])[:5]
                    suspects_lines.append(f"   File Paths Found:")
                    for path in paths_list:
                        suspects_lines.append(f"      - {path}")

                # Show context details if available
                if data['context']:
                    suspects_lines.append(f"   Context/Errors:")
                    for ctx in data['context'][:3]:
                        # Truncate long context
                        ctx_display = ctx[:100] + "..." if len(ctx) > 100 else ctx
                        suspects_lines.append(f"      {ctx_display}")

                suspects_lines.append(f"   Found in Dumps: {', '.join(data['dumps'][:5])}")
                if len(data['dumps']) > 5:
                    suspects_lines.append(f"                   ... and {len(data['dumps']) - 5} more")
                suspects_lines.append("")
        else:
            # No suspects found - show what resources WERE in memory
            suspects_lines.append("No specific resources identified with high confidence.")
            suspects_lines.append("Showing all resources found in memory:")
            suspects_lines.append("")

            # Collect ALL resources from all reports (not just primary suspects)
            all_resources_found = {}  # resource -> dumps
            all_script_paths_by_resource = {}  # resource -> paths

            for filename, report in results:
                # Get all evidence and extract resource info
                if hasattr(report, 'all_evidence'):
                    for ev in report.all_evidence:
                        # Try to get resource name from evidence
                        res_name = ev.resource_name
                        if not res_name and ev.file_path:
                            # Extract from path
                            parts = ev.file_path.replace('\\', '/').strip('@').split('/')
                            for part in parts:
                                if part and not part.endswith(('.lua', '.js', '.dll', '.exe', '.json')):
                                    if len(part) > 2 and part[0].isalnum():
                                        res_name = part
                                        break
                        
                        if res_name:
                            if res_name not in all_resources_found:
                                all_resources_found[res_name] = []
                                all_script_paths_by_resource[res_name] = set()
                            if filename not in all_resources_found[res_name]:
                                all_resources_found[res_name].append(filename)
                            if ev.file_path:
                                all_script_paths_by_resource[res_name].add(ev.file_path)

            if all_resources_found:
                suspects_lines.append("RESOURCES DETECTED IN MEMORY:")
                suspects_lines.append("-" * 40)
                # Sort by frequency
                sorted_res = sorted(all_resources_found.items(), key=lambda x: -len(x[1]))
                for res_name, dumps in sorted_res[:30]:
                    suspects_lines.append(f"  • {res_name}")
                    suspects_lines.append(f"    Found in: {len(dumps)}/{len(results)} dumps")
                    if res_name in all_script_paths_by_resource:
                        paths = list(all_script_paths_by_resource[res_name])[:3]
                        for path in paths:
                            suspects_lines.append(f"    Path: {path}")
                suspects_lines.append("")

            # Show modules where crashes occurred
            all_modules = set()
            for filename, report in results:
                if report.exception_module:
                    all_modules.add(report.exception_module)

            if all_modules:
                suspects_lines.append("CRASH OCCURRED IN THESE MODULES:")
                suspects_lines.append("-" * 40)
                for mod in sorted(all_modules):
                    suspects_lines.append(f"  • {mod}")
                suspects_lines.append("")
                suspects_lines.append("Note: These are native code modules (drivers/engine),")
                suspects_lines.append("      not FiveM resources. Check Summary tab for patterns.")

        self.suspects_text.setPlainText("\n".join(suspects_lines))

        # Combine errors and stacks from all reports
        errors_lines = []
        stacks_lines = []
        full_lines = []

        for filename, report in results:
            errors_lines.append(f"\n{'='*60}\nERRORS FROM: {filename}\n{'='*60}\n")
            errors_lines.append(self._generate_errors_view(report))

            stacks_lines.append(f"\n{'='*60}\nSTACKS FROM: {filename}\n{'='*60}\n")
            stacks_lines.append(self._generate_stacks_view(report))

            full_lines.append(f"\n{'#'*70}\n# FULL REPORT: {filename}\n{'#'*70}\n")
            full_lines.append(self.analyzer.generate_full_report(report))

        self.errors_text.setPlainText("\n".join(errors_lines))
        self.stacks_text.setPlainText("\n".join(stacks_lines))
        self.full_report_text.setPlainText("\n".join(full_lines))

    def _display_heap_results(self, results: list) -> None:
        """Display heap timeline analysis results in the Memory Leaks tab.

        Args:
            results: List of HeapAnalysisResult objects from heap_analyzer
        """
        if not results:
            self.memory_leaks_text.setPlainText("No heap timeline files analyzed.")
            return

        lines = []
        lines.append("=" * 70)
        lines.append("HEAP TIMELINE MEMORY LEAK ANALYSIS")
        lines.append("=" * 70)
        lines.append("")

        for result in results:
            # Generate report for each file
            report_text = self.heap_analyzer.generate_report(result)
            lines.append(report_text)
            lines.append("")
            lines.append("-" * 70)
            lines.append("")

        # Add summary if multiple files
        if len(results) > 1:
            lines.append("=" * 70)
            lines.append("AGGREGATE SUMMARY")
            lines.append("=" * 70)
            lines.append("")

            # Aggregate leaky resources across all files
            all_leaky = {}  # resource_name -> combined info
            for result in results:
                for resource in result.leaky_resources:
                    name = resource.resource_name
                    if name not in all_leaky:
                        all_leaky[name] = {
                            'files': [],
                            'total_growth': 0,
                            'max_memory': 0,
                            'growth_rates': []
                        }
                    all_leaky[name]['files'].append(result.file_path)
                    all_leaky[name]['total_growth'] += resource.memory_growth
                    all_leaky[name]['max_memory'] = max(
                        all_leaky[name]['max_memory'],
                        resource.peak_memory
                    )
                    if resource.growth_rate > 0:
                        all_leaky[name]['growth_rates'].append(resource.growth_rate)

            if all_leaky:
                lines.append(f"RESOURCES WITH LEAKS DETECTED ({len(all_leaky)} total):")
                lines.append("-" * 50)

                # Sort by total growth
                sorted_leaky = sorted(
                    all_leaky.items(),
                    key=lambda x: x[1]['total_growth'],
                    reverse=True
                )

                for name, info in sorted_leaky:
                    lines.append(f"\n  📛 {name}")
                    lines.append(f"     Found in: {len(info['files'])} heap file(s)")
                    lines.append(f"     Total Growth: {info['total_growth'] / 1024 / 1024:.2f} MB")
                    lines.append(f"     Peak Memory: {info['max_memory'] / 1024 / 1024:.2f} MB")
                    if info['growth_rates']:
                        avg_rate = sum(info['growth_rates']) / len(info['growth_rates'])
                        lines.append(f"     Avg Growth Rate: {avg_rate / 1024:.2f} KB/snapshot")

        self.memory_leaks_text.setPlainText("\n".join(lines))

    def _generate_summary(self, report: CrashReport) -> str:
        """Generate a quick summary for the Summary tab."""
        lines = []
        lines.append("=" * 60)
        lines.append("CRASH ANALYSIS SUMMARY")
        lines.append("=" * 60)
        lines.append("")

        # Quick pinpoint
        pinpoint = self.analyzer.get_pinpoint_summary(report)
        lines.append(pinpoint)
        lines.append("")

        # Exception info with detailed parameters
        if report.exception_code:
            lines.append("-" * 40)
            lines.append("EXCEPTION DETAILS:")
            lines.append(f"  Code: 0x{report.exception_code:08X}")

            # Show exception name from params
            if report.exception_params and report.exception_params.code_name:
                lines.append(f"  Name: {report.exception_params.code_name}")

            if report.exception_address:
                lines.append(f"  Address: 0x{report.exception_address:016X}")
            if report.exception_module:
                lines.append(f"  Module: {report.exception_module}")

            # Detailed exception parameters (access violation details)
            if report.exception_params:
                ep = report.exception_params
                if ep.access_type:
                    lines.append(f"  Access Type: {ep.access_type.upper()}")
                if ep.target_address is not None:
                    lines.append(f"  Target Address: 0x{ep.target_address:016X}")
                    if ep.target_address == 0:
                        lines.append("                  (NULL pointer dereference)")
                    elif ep.target_address < 0x10000:
                        lines.append("                  (Low address - likely NULL + offset)")
            lines.append("")

        # Process Statistics
        if report.process_stats:
            ps = report.process_stats
            lines.append("-" * 40)
            lines.append("PROCESS INFO:")
            lines.append(f"  Process ID: {ps.process_id}")
            if ps.process_integrity_level:
                lines.append(f"  Integrity: {ps.process_integrity_level}")
            if ps.working_set_size:
                lines.append(f"  Memory (Working Set): {ps.working_set_size // (1024*1024)} MB")
            if ps.peak_working_set_size:
                lines.append(f"  Memory (Peak): {ps.peak_working_set_size // (1024*1024)} MB")
            if ps.handle_count:
                lines.append(f"  Handles: {ps.handle_count}")
            lines.append("")

        # Quick stats
        lines.append("-" * 40)
        lines.append("ANALYSIS STATISTICS:")
        lines.append(f"  - Primary Suspects Found: {len(report.primary_suspects)}")
        lines.append(f"  - Script Errors Found: {len(report.script_errors)}")
        lines.append(f"  - Lua Stack Traces: {len(report.lua_stacks)}")
        lines.append(f"  - JS Stack Traces: {len(report.js_stacks)}")
        lines.append(f"  - Crash Patterns Matched: {len(report.crash_patterns)}")
        lines.append(f"  - Total Evidence Items: {len(report.all_evidence)}")
        lines.append("")

        # Extended data stats
        lines.append("-" * 40)
        lines.append("EXTENDED DATA EXTRACTED:")
        lines.append(f"  - Threads: {len(report.threads_extended)}")
        modules_with_info = len([m for m in report.module_versions if m.pdb_name or m.file_version])
        lines.append(f"  - Modules with Version/PDB Info: {modules_with_info}")
        lines.append(f"  - Open Handles: {len(report.handles)}")
        lines.append(f"  - Memory Regions: {len(report.memory_info)}")
        if report.function_table_entries:
            lines.append(f"  - Function Table Entries: {report.function_table_entries}")
        lines.append("")

        # Crash patterns
        if report.crash_patterns:
            lines.append("-" * 40)
            lines.append("DETECTED ISSUES:")
            for pattern in report.crash_patterns[:3]:
                lines.append(f"  [{pattern.issue}]")
                lines.append(f"    {pattern.explanation}")
            lines.append("")

        # Assertion info if present
        if report.assertion_info:
            lines.append("-" * 40)
            lines.append("ASSERTION FAILURE:")
            if 'expression' in report.assertion_info:
                lines.append(f"  Expression: {report.assertion_info['expression']}")
            if 'file' in report.assertion_info:
                lines.append(f"  File: {report.assertion_info['file']}")
            if 'line' in report.assertion_info:
                lines.append(f"  Line: {report.assertion_info['line']}")
            lines.append("")

        if report.analysis_errors:
            lines.append("-" * 40)
            lines.append("ANALYSIS NOTES:")
            for err in report.analysis_errors:
                lines.append(f"  - {err}")

        return "\n".join(lines)

    def _generate_suspects_view(self, report: CrashReport) -> str:
        """Generate detailed view of primary suspects."""
        lines = []
        lines.append("=" * 60)
        lines.append("PRIMARY SUSPECTS - RESOURCES/SCRIPTS LIKELY CAUSING CRASH")
        lines.append("=" * 60)
        lines.append("")

        if not report.primary_suspects:
            lines.append("No specific resource could be identified as the cause.")
            lines.append("Check the Stack Traces and Script Errors tabs for more info.")
            return "\n".join(lines)

        for i, suspect in enumerate(report.primary_suspects[:10], 1):
            lines.append(f"#{i} ========================================")
            lines.append(f"   RESOURCE: {suspect.name}")
            lines.append(f"   Evidence Score: {suspect.evidence_count}")
            lines.append("")
            lines.append(f"   Evidence Types:")
            for etype in suspect.evidence_types:
                lines.append(f"     - {etype.name}")
            lines.append("")
            if suspect.scripts:
                lines.append(f"   Scripts Involved:")
                for script in suspect.scripts[:10]:
                    lines.append(f"     - {script}")
            if suspect.path:
                lines.append(f"   Primary Path: {suspect.path}")
            # Show all paths found
            if hasattr(suspect, 'all_paths') and suspect.all_paths:
                if len(suspect.all_paths) > 1 or (len(suspect.all_paths) == 1 and suspect.all_paths[0] != suspect.path):
                    lines.append(f"   All Paths Found:")
                    for path in suspect.all_paths[:5]:
                        lines.append(f"     - {path}")
            # Show context details
            if hasattr(suspect, 'context_details') and suspect.context_details:
                lines.append(f"   Context/Errors:")
                for ctx in suspect.context_details[:5]:
                    ctx_display = ctx[:120] + "..." if len(ctx) > 120 else ctx
                    lines.append(f"     {ctx_display}")
            lines.append("")

        return "\n".join(lines)

    def _generate_errors_view(self, report: CrashReport) -> str:
        """Generate detailed view of script errors."""
        lines = []
        lines.append("=" * 60)
        lines.append("SCRIPT ERRORS FOUND IN MEMORY")
        lines.append("=" * 60)
        lines.append("")

        if not report.script_errors:
            lines.append("No script errors were found in the dump.")
            return "\n".join(lines)

        for i, err in enumerate(report.script_errors, 1):
            lines.append(f"Error #{i}")
            lines.append("-" * 40)
            lines.append(f"Type: {err.error_type}")
            if err.resource_name:
                lines.append(f"Resource: {err.resource_name}")
            if err.script_name:
                lines.append(f"Script: {err.script_name}")
            if err.line_number:
                lines.append(f"Line: {err.line_number}")
            lines.append(f"Message:")
            lines.append(f"  {err.message}")
            lines.append("")

        # Also show log errors
        if report.log_errors:
            lines.append("=" * 60)
            lines.append("ERRORS FROM LOG FILES")
            lines.append("=" * 60)
            lines.append("")
            for err in report.log_errors[:20]:
                lines.append(f"Line {err.get('line', '?')}: {err.get('content', '')}")
                lines.append("")

        return "\n".join(lines)

    def _generate_stacks_view(self, report: CrashReport) -> str:
        """Generate detailed view of stack traces."""
        lines = []
        lines.append("=" * 60)
        lines.append("STACK TRACES AND THREAD INFORMATION")
        lines.append("=" * 60)
        lines.append("")

        # Thread information
        if report.threads_extended:
            lines.append("THREADS AT CRASH TIME:")
            lines.append("-" * 40)
            for t in report.threads_extended[:30]:
                name_str = f" \"{t.thread_name}\"" if t.thread_name else ""
                state_str = f" [{t.state}]" if t.state else ""
                lines.append(f"  Thread {t.thread_id}{name_str}{state_str}")
                if t.priority:
                    lines.append(f"    Priority: {t.priority}")
                if t.stack_base:
                    size = (t.stack_limit - t.stack_base) if t.stack_limit else 0
                    lines.append(f"    Stack: 0x{t.stack_base:016X} ({size:,} bytes)")
            if len(report.threads_extended) > 30:
                lines.append(f"  ... and {len(report.threads_extended) - 30} more threads")
            lines.append("")

        # Lua stacks
        if report.lua_stacks:
            lines.append("LUA STACK TRACES:")
            lines.append("-" * 40)
            for i, stack in enumerate(report.lua_stacks, 1):
                lines.append(f"\nStack #{i}:")
                for frame in stack:
                    c_marker = " [C]" if frame.is_c_function else ""
                    func = frame.function_name or "(anonymous)"
                    lines.append(f"  {frame.source}:{frame.line}: in {func}{c_marker}")
            lines.append("")

        # JS stacks
        if report.js_stacks:
            lines.append("JAVASCRIPT STACK TRACES:")
            lines.append("-" * 40)
            for trace in report.js_stacks:
                lines.append(f"  {trace}")
            lines.append("")

        # Native stacks
        if report.native_stacks:
            lines.append("NATIVE STACK TRACE (Crashing Thread):")
            lines.append("-" * 40)
            for frame in report.native_stacks:
                lines.append(f"  {frame}")
            lines.append("")

        if not report.lua_stacks and not report.js_stacks and not report.native_stacks and not report.threads_extended:
            lines.append("No stack traces could be recovered from the dump.")
            lines.append("")
            lines.append("This might happen if:")
            lines.append("  - The crash was in native code (not a script)")
            lines.append("  - The dump doesn't contain stack memory")
            lines.append("  - The script runtime state was corrupted")

        return "\n".join(lines)

    def save_report(self):
        if not self.current_reports:
            self.status_label.setText("No analysis to save")
            return

        path, _ = QFileDialog.getSaveFileName(
            self, 'Save Report',
            f'crash_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt',
            filter='Text Files (*.txt);;All Files (*)'
        )
        if path:
            # Get the full report text from the Full Report tab
            full_report = self.full_report_text.toPlainText()
            with open(path, 'w', encoding='utf-8') as f:
                f.write(full_report)
            self.status_label.setText(f"Report saved to {os.path.basename(path)}")

    def copy_report(self):
        if not self.current_reports:
            self.status_label.setText("No analysis to copy")
            return

        # Get the full report text from the Full Report tab
        full_report = self.full_report_text.toPlainText()
        cb = QApplication.clipboard()
        cb.setText(full_report)
        self.status_label.setText("Full report copied to clipboard")

    def copy_summary(self):
        if not self.current_reports:
            self.status_label.setText("No analysis to copy")
            return

        # Get summary text from the Summary tab
        summary = self.summary_text.toPlainText()
        cb = QApplication.clipboard()
        cb.setText(summary)
        self.status_label.setText("Summary copied to clipboard")


def main():
    import ctypes
    
    app = QApplication([])
    app.setApplicationName("FiveM Crash Analyzer")
    app.setOrganizationName("FiveM Tools")
    
    # Set application-wide icon (prefer .ico for Windows taskbar)
    # Use absolute paths for reliability
    script_dir = os.path.dirname(os.path.abspath(__file__))
    icon_paths = [
        os.path.join(script_dir, 'icon.ico'),
        os.path.join(script_dir, 'icon.png'),
        os.path.join(os.path.dirname(script_dir), 'icon.ico'),
        os.path.join(os.path.dirname(script_dir), 'icon.png'),
    ]
    
    app_icon = None
    for icon_path in icon_paths:
        if os.path.exists(icon_path):
            icon = QtGui.QIcon(icon_path)
            if not icon.isNull():
                app.setWindowIcon(icon)
                app_icon = icon
                break
    
    # Windows-specific: Set the AppUserModelID to ensure taskbar icon works
    try:
        if hasattr(ctypes, 'windll'):
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID('FiveM.CrashAnalyzer.1.0')
    except Exception:
        pass
    
    gui = CrashAnalyzerGUI()
    
    # Ensure window icon is set
    if app_icon:
        gui.setWindowIcon(app_icon)
    
    gui.show()
    app.exec()


if __name__ == "__main__":
    main()

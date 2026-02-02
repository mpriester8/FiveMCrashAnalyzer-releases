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
    progress_detail = Signal(str, float, str)  # stage, progress (0-1), message
    error = Signal(str)

    def __init__(self, analyzer, dump_files, log_files):
        super().__init__()
        self.analyzer = analyzer
        self.dump_files = dump_files if dump_files else []
        self.log_files = log_files
        self._cancel_requested = False
        # Set up progress callback to emit signals
        self.analyzer.set_progress_callback(self._on_progress)
        # Abort check so long-running analysis can be cancelled
        self.analyzer.set_abort_check(lambda: self._cancel_requested)

    def request_cancel(self) -> None:
        """Request that the current analysis stop (checked between dumps and in long loops)."""
        self._cancel_requested = True

    def _on_progress(self, stage: str, progress: float, message: str) -> None:
        """Callback from memory analyzer - emit as signal for thread safety."""
        self.progress_detail.emit(stage, progress, message)
        # Also emit simplified message
        self.progress.emit(message)

    def run(self):
        import traceback
        results = []
        try:
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
                    if self._cancel_requested:
                        self.progress.emit("Analysis cancelled.")
                        break
                    filename = os.path.basename(dump_file)
                    self.progress.emit(f"Analyzing dump {i}/{total}: {filename}...")

                    report = self.analyzer.full_analysis(
                        dump_path=dump_file,
                        log_paths=self.log_files if i == 1 else []  # Only include logs with first dump
                    )
                    results.append((filename, report))

            if not self._cancel_requested:
                self.progress.emit("Analysis complete!")
            self.finished.emit(results)

        except BaseException as e:
            # Catch all Python exceptions (including KeyboardInterrupt) so the app
            # never "stopped working" due to an unhandled exception in the worker
            msg = str(e)
            tb = traceback.format_exc()
            if tb and tb.strip() != "NoneType: None":
                self.error.emit(f"{msg}\n\nTraceback:\n{tb}")
            else:
                self.error.emit(msg)
            self.finished.emit(results)  # Emit partial results so UI can reset


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
        action_layout.addWidget(self.analyze_btn, 1)  # stretch so buttons share space equally

        self.cancel_btn = QPushButton('Cancel')
        self.cancel_btn.setToolTip("Stop the current analysis")
        self.cancel_btn.clicked.connect(self._on_cancel_clicked)
        self.cancel_btn.setVisible(False)
        action_layout.addWidget(self.cancel_btn)

        self.clear_btn = QPushButton('Clear All')
        self.clear_btn.setStyleSheet("padding: 10px;")  # same padding as Analyze for equal height
        self.clear_btn.clicked.connect(self.clear_files)
        action_layout.addWidget(self.clear_btn, 1)  # same stretch as Analyze for equal width
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
        self.worker.progress_detail.connect(self.on_progress_detail)
        self.worker.error.connect(self.on_error)
        self.cancel_btn.setVisible(True)
        self.worker.start()

    def _on_cancel_clicked(self):
        """Request that the background analysis stop."""
        if hasattr(self, 'worker') and self.worker is not None and self.worker.isRunning():
            self.worker.request_cancel()
            self.status_label.setText("Cancelling...")
            self.status_label.setStyleSheet("color: orange;")

    def on_progress(self, message):
        self.status_label.setText(message)

    def on_progress_detail(self, stage: str, progress: float, message: str):
        """Handle detailed progress updates from memory analyzer.
        
        Args:
            stage: Current analysis stage (init, structure, streaming, sampling, etc.)
            progress: Progress within stage (0.0 to 1.0)
            message: Human-readable status message
        """
        # Update status label with detailed message
        self.status_label.setText(message)
        # Process pending events so the window repaints and stays responsive (avoids "Not Responding" on large files)
        QApplication.processEvents()
        
        # Update progress bar
        # Map stages to overall progress ranges
        stage_ranges = {
            'init': (0, 5),
            'structure': (5, 15),
            'memory': (15, 90),
            'streaming': (15, 90),
            'sampling': (15, 90),
            'correlate': (90, 98),
            'complete': (98, 100),
        }
        
        if stage in stage_ranges:
            start, end = stage_ranges[stage]
            overall_progress = start + (end - start) * progress
            self.progress_bar.setValue(int(overall_progress))

    def on_error(self, error_msg):
        # Stop the indeterminate animation by resetting to determinate range
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(False)
        self.analyze_btn.setEnabled(True)
        self.cancel_btn.setVisible(False)
        self.status_label.setText(f"Error: {error_msg}")
        self.status_label.setStyleSheet("color: red;")

    def on_analysis_complete(self, results):
        """Handle completion of analysis for one or more dump files.

        Args:
            results: List of (filename, CrashReport) tuples (may be empty if cancelled)
        """
        self.current_reports = results
        # Stop the indeterminate animation by resetting to determinate range
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(100)
        self.progress_bar.setVisible(False)
        self.analyze_btn.setEnabled(True)
        self.cancel_btn.setVisible(False)

        num_dumps = len(results)
        if num_dumps == 0:
            self.status_label.setText("Analysis cancelled or no results.")
            self.status_label.setStyleSheet("color: orange;")
            return
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
                if getattr(top, 'likely_script', None):
                    top_info += f" [Likely script: {top.likely_script}]"
                elif top.scripts:
                    top_info += f" - {top.scripts[0]}"
                summary_lines.append(top_info)
                sec = getattr(report, 'primary_suspect_secondary', None)
                conf = getattr(report, 'primary_suspect_confidence', 'medium')
                if sec:
                    summary_lines.append(f"  Also consider: {sec} (evidence ambiguous)")
                if conf == "low":
                    summary_lines.append("  (Confidence: low - correlate with stack traces)")
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

        # ===== MEMORY LEAK ANALYSIS SECTION =====
        has_leak_data = (
            report.entity_creations or report.entity_deletions or
            report.memory_leak_indicators or report.pool_exhaustion_indicators or
            report.timers_created or report.nui_patterns or report.database_patterns
        )
        
        if has_leak_data:
            lines.append("-" * 40)
            lines.append("MEMORY LEAK ANALYSIS:")
            lines.append("")
            
            # Entity lifecycle analysis
            if report.entity_creations or report.entity_deletions:
                create_count = len(report.entity_creations)
                delete_count = len(report.entity_deletions)
                lines.append(f"  Entity Lifecycle:")
                lines.append(f"    - Creation calls found: {create_count}")
                lines.append(f"    - Deletion calls found: {delete_count}")
                if create_count > delete_count * 2:
                    lines.append(f"    ⚠️  WARNING: Many more creates than deletes - possible entity leak!")
                
                # Show most common creation types
                if report.entity_creations:
                    from collections import Counter
                    creation_types = Counter(c[0] for c in report.entity_creations)
                    lines.append(f"    Most common creations:")
                    for native, count in creation_types.most_common(5):
                        lines.append(f"      - {native}: {count} times")
                lines.append("")
            
            # Memory leak indicators
            if report.memory_leak_indicators:
                lines.append(f"  ⚠️  Memory Leak Indicators Found: {len(report.memory_leak_indicators)}")
                from collections import Counter
                indicator_types = Counter(i[1] for i in report.memory_leak_indicators)
                for itype, count in indicator_types.most_common(5):
                    lines.append(f"    - {itype}: {count} occurrences")
                lines.append("")
            
            # Pool exhaustion
            if report.pool_exhaustion_indicators:
                lines.append(f"  🚨 POOL EXHAUSTION DETECTED: {len(report.pool_exhaustion_indicators)}")
                for msg, _ in report.pool_exhaustion_indicators[:5]:
                    lines.append(f"    - {msg[:60]}")
                lines.append("")
            
            # Timers
            if report.timers_created:
                lines.append(f"  Timer Patterns: {len(report.timers_created)} found")
                lines.append(f"    (Check that timers are cleaned up on resource stop)")
                lines.append("")
            
            # NUI/CEF patterns
            if report.nui_patterns:
                lines.append(f"  NUI/CEF Patterns: {len(report.nui_patterns)} found")
                lines.append(f"    (Check for NUI memory leaks, unclosed browsers)")
                lines.append("")
            
            # Database patterns
            if report.database_patterns:
                lines.append(f"  Database Queries: {len(report.database_patterns)} found")
                lines.append(f"    (Check for unclosed connections, slow queries)")
                lines.append("")
            
            # Event handlers
            if report.event_handlers_registered:
                reg_count = len(report.event_handlers_registered)
                rem_count = len(report.event_handlers_removed)
                lines.append(f"  Event Handlers:")
                lines.append(f"    - Registered: {reg_count}")
                lines.append(f"    - Removed: {rem_count}")
                if reg_count > rem_count * 3:
                    lines.append(f"    ⚠️  Many handlers registered but few removed")
                lines.append("")
            
            # Network patterns
            if report.network_patterns:
                lines.append(f"  Network Sync Calls: {len(report.network_patterns)} found")
                lines.append("")
            
            # State bags
            if report.statebag_patterns:
                lines.append(f"  State Bag Operations: {len(report.statebag_patterns)} found")
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

        sec = getattr(report, 'primary_suspect_secondary', None)
        conf = getattr(report, 'primary_suspect_confidence', 'medium')
        if sec:
            lines.append("Note: Top two suspects have close scores; consider both.")
        if conf == "low":
            lines.append("Confidence is low; correlate with stack traces and script errors.")
        lines.append("")

        for i, suspect in enumerate(report.primary_suspects[:10], 1):
            lines.append(f"#{i} ========================================")
            lines.append(f"   RESOURCE: {suspect.name}")
            if getattr(suspect, 'likely_script', None):
                lines.append(f"   Likely script: {suspect.likely_script}")
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

        # Exception information (show at the top for visibility)
        if report.exception_code or report.exception_params:
            lines.append("EXCEPTION INFORMATION:")
            lines.append("-" * 40)
            
            # Show exception code and name
            if report.exception_params:
                exc_code = report.exception_params.code
                exc_name = report.exception_params.code_name
                lines.append(f"Exception Code: 0x{exc_code:08X} ({exc_name})")
                
                # Show exception address with enhanced information
                if report.exception_params.address:
                    exc_addr = report.exception_params.address
                    lines.append(f"Exception Address: 0x{exc_addr:016X}")
                    
                    # Calculate offset from module base
                    module_offset = None
                    module_base = None
                    if report.exception_module:
                        lines.append(f"Faulting Module: {report.exception_module}")
                        
                        # Find the module base address from module list
                        if report.module_versions:
                            for mod in report.module_versions:
                                if mod.name.lower() == report.exception_module.lower():
                                    module_base = mod.base_address
                                    module_offset = exc_addr - module_base
                                    break
                        elif report.modules:
                            for mod in report.modules:
                                mod_name = mod.get('name', '')
                                if mod_name.lower() == report.exception_module.lower():
                                    module_base = mod.get('base', 0) or mod.get('baseaddress', 0)
                                    if module_base:
                                        module_offset = exc_addr - module_base
                                    break
                        
                        # Show module+offset format (standard for crash analysis)
                        if module_offset is not None:
                            lines.append(f"Module Offset: {report.exception_module} + 0x{module_offset:X}")
                    
                    # Check if this address appears in the symbolicated stack trace
                    if report.native_stacks_symbolicated:
                        exc_addr_hex = f"0x{exc_addr:X}".upper()
                        for frame in report.native_stacks_symbolicated:
                            if exc_addr_hex in frame.upper() or f"+0x{module_offset:X}" in frame.upper() if module_offset else False:
                                # Extract function name if present
                                if "  ->  " in frame:
                                    _, func_part = frame.split("  ->  ", 1)
                                    lines.append(f"Exception Location: {func_part.strip()}")
                                break
                    
                    # If not in symbolicated trace, check raw stack trace for context
                    elif report.native_stacks and module_offset is not None:
                        offset_str = f"0x{module_offset:X}"
                        for i, frame in enumerate(report.native_stacks):
                            if offset_str in frame:
                                stack_position = "top of stack" if i == 0 else f"frame #{i}"
                                lines.append(f"Stack Position: Found at {stack_position} (likely the faulting instruction)")
                                break
                    
                    # Provide interpretation based on offset patterns
                    if module_offset is not None:
                        lines.append("")
                        lines.append("What this means:")
                        # Check if it's in common sections
                        if module_offset < 0x1000:
                            lines.append("  -> Exception in module headers/low memory (unusual, possible corruption)")
                        elif 0x1000 <= module_offset < 0x100000:
                            lines.append("  -> Exception in early code section (startup/initialization code)")
                        else:
                            lines.append("  -> Exception in runtime code")
                            # Check correlation with resources
                            if report.primary_suspects:
                                lines.append(f"  -> Likely triggered by: {', '.join(s.name for s in report.primary_suspects[:3])}")
                            elif report.resources:
                                top_resources = sorted(
                                    report.resources.items(),
                                    key=lambda x: getattr(x[1], 'evidence_count', 0),
                                    reverse=True
                                )[:3]
                                if top_resources:
                                    lines.append(f"  -> Likely triggered by: {', '.join(r[0] for r in top_resources)}")
                
                # For Access Violations, show detailed information
                if exc_code == 0xC0000005 and report.exception_params.access_type:
                    lines.append(f"Access Type: {report.exception_params.access_type}")
                    if report.exception_params.target_address is not None:
                        lines.append(f"Target Address: 0x{report.exception_params.target_address:016X}")
                        # Categorize the target address
                        target = report.exception_params.target_address
                        if target == 0:
                            lines.append("  -> NULL pointer dereference")
                        elif target < 0x10000:
                            lines.append(f"  -> Near-NULL address (likely null/uninitialized pointer + offset)")
                        elif target > 0x7FFFFFFFFFFF:
                            lines.append(f"  -> Invalid high address (likely corrupted pointer)")
                
                # Show any additional exception parameters
                if report.exception_params.num_parameters > 2:
                    lines.append(f"Additional Parameters: {report.exception_params.num_parameters - 2}")
                    for i, param in enumerate(report.exception_params.parameters[2:], start=2):
                        lines.append(f"  Param[{i}]: 0x{param:016X}")
                
                # Nested exception
                if report.exception_params.nested_exception:
                    nested = report.exception_params.nested_exception
                    lines.append(f"Nested Exception: 0x{nested.code:08X} ({nested.code_name})")
                    
            elif report.exception_code:
                # Fallback if we only have basic exception info
                lines.append(f"Exception Code: 0x{report.exception_code:08X}")
                if report.exception_address:
                    exc_addr = report.exception_address
                    lines.append(f"Exception Address: 0x{exc_addr:016X}")
                    
                    # Calculate offset from module base
                    module_offset = None
                    if report.exception_module:
                        lines.append(f"Faulting Module: {report.exception_module}")
                        
                        # Find the module base address
                        if report.module_versions:
                            for mod in report.module_versions:
                                if mod.name.lower() == report.exception_module.lower():
                                    module_offset = exc_addr - mod.base_address
                                    lines.append(f"Module Offset: {report.exception_module} + 0x{module_offset:X}")
                                    break
                        elif report.modules:
                            for mod in report.modules:
                                mod_name = mod.get('name', '')
                                if mod_name.lower() == report.exception_module.lower():
                                    module_base = mod.get('base', 0) or mod.get('baseaddress', 0)
                                    if module_base:
                                        module_offset = exc_addr - module_base
                                        lines.append(f"Module Offset: {report.exception_module} + 0x{module_offset:X}")
                                    break
            
            lines.append("")

        # Register state at crash time
        if report.exception_context:
            lines.append("REGISTERS AT CRASH TIME:")
            lines.append("-" * 40)
            ctx = report.exception_context
            
            # Determine architecture and show relevant registers
            # x64 registers
            if 'Rip' in ctx or 'rip' in ctx:
                rip = ctx.get('Rip') or ctx.get('rip', 0)
                rsp = ctx.get('Rsp') or ctx.get('rsp', 0)
                rbp = ctx.get('Rbp') or ctx.get('rbp', 0)
                
                lines.append(f"RIP (Instruction Pointer): 0x{rip:016X}")
                lines.append(f"RSP (Stack Pointer):       0x{rsp:016X}")
                lines.append(f"RBP (Base Pointer):        0x{rbp:016X}")
                lines.append("")
                
                # General purpose registers
                lines.append("General Purpose Registers:")
                for reg in ['Rax', 'Rbx', 'Rcx', 'Rdx', 'Rsi', 'Rdi']:
                    val = ctx.get(reg) or ctx.get(reg.lower(), 0)
                    lines.append(f"  {reg.upper()}: 0x{val:016X}")
                
                # R8-R15
                lines.append("")
                lines.append("Extended Registers:")
                for i in range(8, 16):
                    reg_name = f'R{i}'
                    val = ctx.get(reg_name) or ctx.get(reg_name.lower(), 0)
                    lines.append(f"  {reg_name}: 0x{val:016X}")
                
            # x86 registers
            elif 'Eip' in ctx or 'eip' in ctx:
                eip = ctx.get('Eip') or ctx.get('eip', 0)
                esp = ctx.get('Esp') or ctx.get('esp', 0)
                ebp = ctx.get('Ebp') or ctx.get('ebp', 0)
                
                lines.append(f"EIP (Instruction Pointer): 0x{eip:08X}")
                lines.append(f"ESP (Stack Pointer):       0x{esp:08X}")
                lines.append(f"EBP (Base Pointer):        0x{ebp:08X}")
                lines.append("")
                
                lines.append("General Purpose Registers:")
                for reg in ['Eax', 'Ebx', 'Ecx', 'Edx', 'Esi', 'Edi']:
                    val = ctx.get(reg) or ctx.get(reg.lower(), 0)
                    lines.append(f"  {reg.upper()}: 0x{val:08X}")
            
            # Flags register
            eflags = ctx.get('EFlags') or ctx.get('eflags') or ctx.get('ContextFlags') or ctx.get('contextflags')
            if eflags:
                lines.append("")
                lines.append(f"Flags: 0x{eflags:08X}")
            
            lines.append("")

        # Thread information
        if report.threads_extended:
            lines.append("THREADS AT CRASH TIME:")
            lines.append("-" * 40)
            
            # Try to identify the crashing thread
            crashing_thread_id = None
            if report.exception_context:
                # Some contexts have thread ID
                crashing_thread_id = report.exception_context.get('ThreadId') or report.exception_context.get('thread_id')
            
            for i, t in enumerate(report.threads_extended[:30]):
                name_str = f" \"{t.thread_name}\"" if t.thread_name else ""
                state_str = f" [{t.state}]" if t.state else ""
                
                # Mark the crashing thread
                crash_marker = ""
                if crashing_thread_id and t.thread_id == crashing_thread_id:
                    crash_marker = " *** CRASHING THREAD ***"
                elif i == 0 and not crashing_thread_id and report.exception_code:
                    # If we can't identify crashing thread, assume it's the first one
                    crash_marker = " *** LIKELY CRASHING THREAD ***"
                
                lines.append(f"  Thread {t.thread_id}{name_str}{state_str}{crash_marker}")
                if t.priority:
                    lines.append(f"    Priority: {t.priority}")
                if t.stack_base:
                    size = (t.stack_limit - t.stack_base) if t.stack_limit else 0
                    lines.append(f"    Stack: 0x{t.stack_base:016X} ({size:,} bytes)")
            if len(report.threads_extended) > 30:
                lines.append(f"  ... and {len(report.threads_extended) - 30} more threads")
            lines.append("")

        # Lua stacks (with resources involved per stack)
        if report.lua_stacks:
            lines.append("LUA STACK TRACES:")
            lines.append("-" * 40)
            for i, stack in enumerate(report.lua_stacks, 1):
                lines.append(f"\nStack #{i}:")
                if i - 1 < len(report.lua_stack_resources) and report.lua_stack_resources[i - 1]:
                    lines.append(f"  Resources involved: {', '.join(report.lua_stack_resources[i - 1])}")
                for frame in stack:
                    c_marker = " [C]" if frame.is_c_function else ""
                    func = frame.function_name or "(anonymous)"
                    lines.append(f"  {frame.source}:{frame.line}: in {func}{c_marker}")
            lines.append("")

        # JS stacks (with resources involved per stack)
        if report.js_stacks:
            lines.append("JAVASCRIPT STACK TRACES:")
            lines.append("-" * 40)
            for i, trace in enumerate(report.js_stacks):
                if i < len(report.js_stack_resources) and report.js_stack_resources[i]:
                    lines.append(f"  Resources involved: {', '.join(report.js_stack_resources[i])}")
                lines.append(f"  {trace}")
            lines.append("")

        # Loaded modules section (for context with stack trace)
        if report.module_versions or report.modules:
            lines.append("LOADED MODULES:")
            lines.append("-" * 40)
            
            # Use module_versions if available (more detailed), otherwise modules
            module_list = []
            if report.module_versions:
                # Sort by base address
                sorted_modules = sorted(report.module_versions, key=lambda m: m.base_address)
                for mod in sorted_modules[:15]:  # Show first 15 modules
                    base = mod.base_address
                    end = base + mod.size - 1 if mod.size else base
                    size_kb = mod.size // 1024 if mod.size else 0
                    
                    # Show version if available
                    version_str = ""
                    if mod.file_version:
                        version_str = f" v{mod.file_version}"
                    elif mod.product_version:
                        version_str = f" v{mod.product_version}"
                    
                    lines.append(f"  {mod.name}{version_str}")
                    lines.append(f"    Base: 0x{base:016X} - 0x{end:016X} ({size_kb:,} KB)")
                    
                    # Show PDB info if available (useful for symbol resolution)
                    if mod.pdb_name:
                        pdb_guid_str = f"{mod.pdb_guid}-{mod.pdb_age}" if mod.pdb_guid and mod.pdb_age else mod.pdb_guid or ""
                        if pdb_guid_str:
                            lines.append(f"    PDB: {mod.pdb_name} ({pdb_guid_str})")
                
                if len(sorted_modules) > 15:
                    lines.append(f"  ... and {len(sorted_modules) - 15} more modules")
            
            elif report.modules:
                # Fallback to basic module info
                for i, mod in enumerate(report.modules[:15]):
                    name = mod.get('name', 'Unknown')
                    base = mod.get('base', 0) or mod.get('baseaddress', 0)
                    size = mod.get('size', 0)
                    
                    if base:
                        end = base + size - 1 if size else base
                        size_kb = size // 1024 if size else 0
                        lines.append(f"  {name}")
                        lines.append(f"    Base: 0x{base:016X} - 0x{end:016X} ({size_kb:,} KB)")
                
                if len(report.modules) > 15:
                    lines.append(f"  ... and {len(report.modules) - 15} more modules")
            
            lines.append("")

        # Native stacks (symbolicated when PDBs available)
        if report.native_stacks:
            lines.append("NATIVE STACK TRACE (Crashing Thread):")
            lines.append("-" * 40)
            # Show resource names right here so user can correlate
            resources_for_stack = []
            if report.primary_suspects:
                resources_for_stack = [s.name for s in report.primary_suspects[:10]]
            elif getattr(report, 'resources', None):
                by_ev = sorted(
                    report.resources.items(),
                    key=lambda x: (getattr(x[1], 'evidence_count', 0), x[0]),
                    reverse=True
                )
                resources_for_stack = [name for name, _ in by_ev[:10]]
            if resources_for_stack:
                lines.append("Resources identified in this dump (correlate with stack below):")
                lines.append("  " + ", ".join(resources_for_stack))
                lines.append("")
            lines.append("How to use this to find the cause:")
            lines.append("  - Top frames are closest to the crash; exception address = faulting instruction.")
            lines.append("  - With PDBs, frames show:  module + 0xOFFSET  ->  function_name + 0xdisp")
            lines.append("  - Correlate the resources above with the stack to see which script triggered this path.")
            lines.append("")
            sym = getattr(report, 'native_stacks_symbolicated', None)
            has_symbolication = sym and any("  ->  " in f for f in sym)
            if not has_symbolication and report.native_stacks:
                if getattr(report, 'module_versions', None):
                    if getattr(report, 'symbolication_had_local_path', False):
                        lines.append("  (Symbols not loaded: PDB not found on FiveM symbol server or in local cache. Ensure FIVEM_SYMBOL_CACHE folder has PDBs for this build (e.g. <pdb_name>/<GUID><age>/<pdb_name>). Showing module+offset only.)")
                        diag = getattr(report, 'symbolication_diagnostic', None)
                        if diag:
                            lines.append("")
                            lines.append(diag)
                    else:
                        lines.append("  (Symbols not loaded: PDB not found on FiveM symbol server (404). To use local PDBs, set FIVEM_SYMBOL_CACHE in .env to your symbol folder (e.g. D:\\symbolcache). Showing module+offset only.)")
                else:
                    lines.append("  (Symbols not loaded: PDB download failed or module info missing. Showing module+offset only.)")
                lines.append("")
            elif has_symbolication:
                lines.append("  (Symbols loaded from server or local cache; correlate the function names below with the resources list to identify the crashing resource.)")
                lines.append("")
            display_frames = sym if (sym and len(sym) == len(report.native_stacks)) else report.native_stacks
            for frame in display_frames:
                lines.append(frame if (frame and frame.startswith("  ")) else f"  {frame}")
            lines.append("")

        if not report.lua_stacks and not report.js_stacks and not report.native_stacks and not report.threads_extended:
            lines.append("No stack traces could be recovered from the dump.")
            lines.append("")
            lines.append("Check ANALYSIS NOTES/WARNINGS below for the stack recovery diagnostic.")
            lines.append("It will state whether the dump contains stack memory or not (analysis error vs. dump content).")
            lines.append("")
            lines.append("Common causes when dump has stack memory:")
            lines.append("  - Extraction fallback may have run; re-run analysis to get native stack")
            lines.append("Common causes when dump lacks stack memory:")
            lines.append("  - The dump doesn't include thread/stack descriptors")
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

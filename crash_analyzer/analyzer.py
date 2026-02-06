"""PySide6 GUI wrapper for the FiveM Crash Analyzer with deep analysis support."""
import sys
import os
from pathlib import Path
from io import StringIO

# Add parent directory to path so crash_analyzer can be imported
parent_dir = Path(__file__).parent.parent
if str(parent_dir) not in sys.path:
    sys.path.insert(0, str(parent_dir))

from PySide6 import QtWidgets, QtCore, QtGui
from PySide6.QtWidgets import (
    QApplication, QFileDialog, QTextEdit, QPushButton, QLabel,
    QHBoxLayout, QVBoxLayout, QWidget, QProgressBar, QTabWidget,
    QGroupBox, QListWidget, QSplitter, QFrame, QScrollArea, QCheckBox
)
from PySide6.QtCore import Qt, Signal, QThread
import os
from datetime import datetime
from crash_analyzer.core import CrashAnalyzer, CrashReport
from crash_analyzer.heap_analyzer import HeapTimelineAnalyzer, HeapAnalysisResult


class OutputRedirector:
    """Redirects stdout/stderr to a QTextEdit widget in a thread-safe manner."""
    
    def __init__(self, text_widget, original_stream):
        self.text_widget = text_widget
        self.original_stream = original_stream
        self._buffer = StringIO()
        
    def write(self, text):
        # Write to original stream (maintains console output for debugging)
        if self.original_stream:
            try:
                self.original_stream.write(text)
                self.original_stream.flush()
            except Exception:
                pass  # Ignore if original stream is closed
        
        # Update GUI widget in a thread-safe way
        if text and text.strip():  # Only update for non-empty content
            try:
                QtCore.QMetaObject.invokeMethod(
                    self.text_widget,
                    "append",
                    Qt.QueuedConnection,
                    QtCore.Q_ARG(str, text.rstrip())
                )
            except RuntimeError:
                pass  # Widget might be deleted
    
    def flush(self):
        if self.original_stream:
            try:
                self.original_stream.flush()
            except Exception:
                pass


class CollapsibleBox(QWidget):
    """A collapsible group box for better organization of UI sections."""
    
    def __init__(self, title="", parent=None):
        super().__init__(parent)
        
        self.toggle_button = QPushButton(title)
        self.toggle_button.setCheckable(True)
        self.toggle_button.setChecked(False)
        self.toggle_button.setStyleSheet(
            "QPushButton { text-align: left; padding: 8px; font-weight: bold; }"
            "QPushButton:checked { background-color: #e0e0e0; }"
        )
        self.toggle_button.clicked.connect(self.on_toggle)
        
        self.content_area = QWidget()
        self.content_layout = QVBoxLayout()
        self.content_layout.setContentsMargins(15, 5, 5, 5)
        self.content_area.setLayout(self.content_layout)
        self.content_area.setVisible(False)
        
        layout = QVBoxLayout()
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.toggle_button)
        layout.addWidget(self.content_area)
        self.setLayout(layout)
    
    def on_toggle(self):
        self.content_area.setVisible(self.toggle_button.isChecked())
        # Update button text with indicator
        title = self.toggle_button.text().replace(' ▼', '').replace(' ▶', '')
        if self.toggle_button.isChecked():
            self.toggle_button.setText(f'{title} ▼')
        else:
            self.toggle_button.setText(f'{title} ▶')
    
    def set_content_layout(self, layout):
        # Clear existing layout
        while self.content_layout.count():
            child = self.content_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()
        # Add new layout
        self.content_layout.addLayout(layout)


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

                    try:
                        report = self.analyzer.full_analysis(
                            dump_path=dump_file,
                            log_paths=self.log_files if i == 1 else []  # Only include logs with first dump
                        )
                        results.append((filename, report))
                    except Exception as e:
                        # If analysis fails, log the error and continue
                        self.error.emit(f"Failed to analyze {filename}: {str(e)}")
                        break

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
            os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'assets', 'icon.ico')),
            os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'assets', 'icon.png')),
            os.path.abspath(os.path.join(os.path.dirname(__file__), 'icon.ico')),
            os.path.abspath(os.path.join(os.path.dirname(__file__), 'icon.png')),
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
    
    def _setup_output_redirection(self):
        """Redirect stdout and stderr to the console tab."""
        self._original_stdout = sys.stdout
        self._original_stderr = sys.stderr
        
        # Create redirectors that write to both console and original streams
        self.stdout_redirector = OutputRedirector(self.console_text, self._original_stdout)
        self.stderr_redirector = OutputRedirector(self.console_text, self._original_stderr)
        
        # Install redirectors
        sys.stdout = self.stdout_redirector
        sys.stderr = self.stderr_redirector
        
        # Print welcome message
        print("="*60)
        print("FiveM Crash Analyzer - Console Output")
        print("="*60)
        print("All analysis output will be displayed here.")
        print("")
    
    def closeEvent(self, event):
        """Restore original stdout/stderr when closing."""
        # Restore original streams
        sys.stdout = self._original_stdout
        sys.stderr = self._original_stderr
        event.accept()

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
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("%p% - %v/%m")
        main_layout.addWidget(self.progress_bar)

        # Status label - Main status message
        self.status_label = QLabel("")
        self.status_label.setStyleSheet("""
            color: white; 
            font-size: 11pt; 
            font-weight: bold;
            padding: 5px;
            background-color: #2a2a2a;
            border-radius: 3px;
        """)
        main_layout.addWidget(self.status_label)
        
        # Process detail label - Shows current subprocess being executed
        self.process_label = QLabel("")
        self.process_label.setStyleSheet("""
            color: #a6e3a1;
            font-size: 9pt;
            padding: 3px 5px;
            background-color: #1a1a1a;
            border-left: 3px solid #0d7377;
            border-radius: 2px;
        """)
        self.process_label.setVisible(False)
        self.process_label.setWordWrap(True)
        main_layout.addWidget(self.process_label)

        # Results tabs - DARK THEME
        self.tabs = QTabWidget()
        self.tabs.setTabPosition(QTabWidget.North)
        self.tabs.setMovable(True)
        self.tabs.setStyleSheet("""
            QTabWidget::pane { 
                border: 1px solid #3a3a3a; 
                background-color: #1e1e1e;
            }
            QTabBar::tab { 
                padding: 8px 16px; 
                margin: 2px; 
                background-color: #2d2d2d;
                color: #cccccc;
                border: 1px solid #3a3a3a;
            }
            QTabBar::tab:selected { 
                background: #0d7377; 
                color: white; 
                font-weight: bold; 
            }
            QTabBar::tab:hover {
                background: #3a3a3a;
            }
        """)

        # Dark theme for all text editors
        dark_style = """
            font-family: 'Consolas', 'Courier New', monospace; 
            background-color: #1e1e1e; 
            color: #d4d4d4; 
            selection-background-color: #264f78;
            selection-color: #ffffff;
        """

        # 1. Quick Summary tab (always first)
        self.summary_text = QTextEdit()
        self.summary_text.setReadOnly(True)
        self.summary_text.setStyleSheet(dark_style + "font-size: 10pt;")
        self.tabs.addTab(self.summary_text, "⭐ Summary")

        # 2. Primary Suspects tab (key findings)
        self.suspects_text = QTextEdit()
        self.suspects_text.setReadOnly(True)
        self.suspects_text.setStyleSheet(dark_style + "font-size: 10pt;")
        self.tabs.addTab(self.suspects_text, "🎯 Suspects")

        # 3. Native Function Calls
        self.native_calls_text = QTextEdit()
        self.native_calls_text.setReadOnly(True)
        self.native_calls_text.setStyleSheet(dark_style + "font-size: 9pt;")
        self.tabs.addTab(self.native_calls_text, "⚡ Native Calls")

        # 4. Lua Code Fragments
        self.lua_code_text = QTextEdit()
        self.lua_code_text.setReadOnly(True)
        self.lua_code_text.setStyleSheet(dark_style + "font-size: 9pt;")
        self.tabs.addTab(self.lua_code_text, "📜 Lua Code")

        # 5. Network Events
        self.events_text = QTextEdit()
        self.events_text.setReadOnly(True)
        self.events_text.setStyleSheet(dark_style + "font-size: 9pt;")
        self.tabs.addTab(self.events_text, "🌐 Events")

        # 6. FiveM Forensics tab
        self.forensics_text = QTextEdit()
        self.forensics_text.setReadOnly(True)
        self.forensics_text.setStyleSheet(dark_style + "font-size: 9pt;")
        self.tabs.addTab(self.forensics_text, "🔧 Forensics")

        # 7. Script Errors tab
        self.errors_text = QTextEdit()
        self.errors_text.setReadOnly(True)
        self.errors_text.setStyleSheet(dark_style + "font-size: 9pt;")
        self.tabs.addTab(self.errors_text, "❌ Errors")

        # 8. Stack Traces tab
        self.stacks_text = QTextEdit()
        self.stacks_text.setReadOnly(True)
        self.stacks_text.setStyleSheet(dark_style + "font-size: 9pt;")
        self.tabs.addTab(self.stacks_text, "📚 Stacks")

        # 9. Memory Analysis tab
        self.memory_leaks_text = QTextEdit()
        self.memory_leaks_text.setReadOnly(True)
        self.memory_leaks_text.setStyleSheet(dark_style + "font-size: 9pt;")
        self.tabs.addTab(self.memory_leaks_text, "💾 Memory")

        # 10. Full Report tab (detailed)
        self.full_report_text = QTextEdit()
        self.full_report_text.setReadOnly(True)
        self.full_report_text.setStyleSheet(dark_style + "font-size: 8pt;")
        self.tabs.addTab(self.full_report_text, "📋 Full Report")

        # 11. Console Output tab (captures stdout/stderr)
        self.console_text = QTextEdit()
        self.console_text.setReadOnly(True)
        self.console_text.setStyleSheet(dark_style + "font-size: 9pt;")
        self.console_text.setLineWrapMode(QTextEdit.NoWrap)  # Better for log output
        self.tabs.addTab(self.console_text, "🖥️ Console")

        # Redirect stdout and stderr to console tab
        self._setup_output_redirection()

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
        self.native_calls_text.clear()
        self.lua_code_text.clear()
        self.events_text.clear()
        self.forensics_text.clear()
        self.errors_text.clear()
        self.stacks_text.clear()
        self.full_report_text.clear()
        self.memory_leaks_text.clear()
        self.status_label.setText("")

    def analyze(self):
        if not self.dump_files and not self.log_files and not self.heap_files:
            self.status_label.setText('Please select at least one file to analyze')
            self.status_label.setStyleSheet("""
                color: #ff6b6b; 
                font-size: 11pt; 
                font-weight: bold;
                padding: 5px;
                background-color: #3a2020;
                border-radius: 3px;
            """)
            return
        
        # Check for extremely large dump files and warn user
        # Most dumps are mini dumps (<20MB) and analyze quickly
        # Warn only when dumps are large enough to take significant time
        huge_files = []
        very_large_files = []
        for dump_file in self.dump_files:
            try:
                size_mb = os.path.getsize(dump_file) / (1024 ** 2)
                size_gb = size_mb / 1024
                # Very large: >2GB (will use progressive chunked extraction)
                if size_gb > 2:
                    huge_files.append((os.path.basename(dump_file), size_gb))
                # Large: 500MB-2GB (will use chunked extraction)
                elif size_mb > 500:
                    very_large_files.append((os.path.basename(dump_file), size_gb))
            except Exception:
                pass
        
        # Show warning for huge files (>2GB)
        if huge_files:
            msg = "⚠️ VERY LARGE DUMP FILE DETECTED\n\n"
            msg += "The following dump file(s) are extremely large:\n\n"
            for name, size in huge_files:
                msg += f"  • {name}: {size:.1f} GB\n"
            msg += "\n⏱️ ANALYSIS WILL TAKE 30-60+ MINUTES\n\n"
            msg += "This analysis will:\n"
            msg += "  • Process memory in multiple chunks\n"
            msg += "  • Use significant CPU and memory resources\n"
            msg += "  • Show progress incrementally\n\n"
            msg += "Continue analysis?"
            
            from PySide6.QtWidgets import QMessageBox
            reply = QMessageBox.warning(self, "Very Large Dump File", msg, QMessageBox.Yes | QMessageBox.No)
            if reply == QMessageBox.No:
                self.status_label.setText("Analysis cancelled by user")
                return
        
        # Show warning for large files (500MB-2GB)
        if very_large_files:
            msg = "⏱️ LARGE DUMP FILE DETECTED\n\n"
            msg += "The following dump file(s) are large:\n\n"
            for name, size in very_large_files:
                msg += f"  • {name}: {size:.2f} GB\n"
            msg += "\nEstimated analysis time: 10-30 minutes\n\n"
            msg += "Continue?"
            
            from PySide6.QtWidgets import QMessageBox
            reply = QMessageBox.information(self, "Large Dump File", msg, QMessageBox.Yes | QMessageBox.No)
            if reply == QMessageBox.No:
                self.status_label.setText("Analysis cancelled by user")
                return

        self.analyze_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate
        self.status_label.setText("🔍 Analyzing...")
        self.status_label.setStyleSheet("""
            color: #74c7ec; 
            font-size: 11pt; 
            font-weight: bold;
            padding: 5px;
            background-color: #1a2a3a;
            border-radius: 3px;
        """)

        # Clear previous results
        self.summary_text.clear()
        self.suspects_text.clear()
        self.native_calls_text.clear()
        self.lua_code_text.clear()
        self.events_text.clear()
        self.forensics_text.clear()
        self.errors_text.clear()
        self.stacks_text.clear()
        self.full_report_text.clear()
        self.memory_leaks_text.clear()
        self.console_text.clear()
        
        # Print analysis start to console
        print("\n" + "="*60)
        print(f"Starting Analysis - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*60)
        if self.dump_files:
            print(f"Dump files: {len(self.dump_files)}")
            for df in self.dump_files:
                print(f"  - {os.path.basename(df)}")
        if self.log_files:
            print(f"Log files: {len(self.log_files)}")
        if self.heap_files:
            print(f"Heap files: {len(self.heap_files)}")
        print("")

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
            self.status_label.setText(f"✅ Heap analysis complete! ({len(self.heap_files)} file(s))")
            self.status_label.setStyleSheet("""
                color: #a6e3a1; 
                font-size: 11pt; 
                font-weight: bold;
                padding: 5px;
                background-color: #1a3a1a;
                border-radius: 3px;
            """)
            self.tabs.setCurrentWidget(self.memory_leaks_text)
            return

        # Run crash dump analysis in background thread
        # Clean up any previous worker first
        if hasattr(self, 'worker') and self.worker is not None:
            try:
                self.worker.finished.disconnect()
                self.worker.progress.disconnect()
                self.worker.progress_detail.disconnect()
                self.worker.error.disconnect()
            except (RuntimeError, TypeError):
                pass  # Signals might already be disconnected
            
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
            self.status_label.setText("⚠️ Cancelling...")
            self.status_label.setStyleSheet("""
                color: #fab387; 
                font-size: 11pt; 
                font-weight: bold;
                padding: 5px;
                background-color: #3a2a1a;
                border-radius: 3px;
            """)

    def on_progress(self, message):
        # Enhanced status display with better formatting
        self.status_label.setText(f"⏳ {message}")
        self.status_label.setStyleSheet("""
            color: white; 
            font-size: 11pt; 
            font-weight: bold;
            padding: 5px;
            background-color: #2a2a2a;
            border-radius: 3px;
        """)
        
        # Hide process_label in simple progress mode (no subprocess detail)
        self.process_label.setVisible(False)

    def on_progress_detail(self, stage: str, progress: float, message: str):
        """Handle detailed progress updates from memory analyzer.
        
        Args:
            stage: Current analysis stage (init, structure, streaming, sampling, etc.)
            progress: Progress within stage (0.0 to 1.0)
            message: Human-readable status message
        """
        # Update status label with detailed message and stage indicator
        stage_icons = {
            'init': '🚀',
            'loading': '📂',
            'extraction': '🔓',
            'structure': '📋',
            'threads': '🧵',
            'modules': '📦',
            'memory': '🧠',
            'streaming': '📊',
            'sampling': '🎯',
            'patterns': '🔍',
            'lua': '📜',
            'native': '⚡',
            'symbols': '🔣',
            'correlate': '🔗',
            'forensics': '🔧',
            'leak_analysis': '💾',
            'finalize': '✨'
        }
        
        stage_descriptions = {
            'init': 'Initializing analyzer',
            'loading': 'Loading crash dump',
            'extraction': 'Extracting dump streams',
            'structure': 'Parsing dump structure',
            'threads': 'Analyzing threads',
            'modules': 'Processing modules',
            'memory': 'Deep memory analysis',
            'streaming': 'Analyzing streaming data',
            'sampling': 'Sampling memory regions',
            'patterns': 'Detecting crash patterns',
            'lua': 'Extracting Lua stacks',
            'native': 'Finding native calls',
            'symbols': 'Downloading symbols',
            'correlate': 'Correlating evidence',
            'forensics': 'FiveM forensics',
            'leak_analysis': 'Memory leak detection',
            'finalize': 'Finalizing report'
        }
        
        icon = stage_icons.get(stage, '⏳')
        stage_desc = stage_descriptions.get(stage, stage.replace('_', ' ').title())
        
        # Update main status
        self.status_label.setText(f"{icon} {stage_desc}")
        self.status_label.setStyleSheet("""
            color: white; 
            font-size: 11pt; 
            font-weight: bold;
            padding: 5px;
            background-color: #2a2a2a;
            border-radius: 3px;
        """)
        
        # Update process detail label ONLY if message provides additional detail beyond stage description
        # This prevents duplicate status displays
        message_lower = message.lower() if message else ""
        stage_desc_lower = stage_desc.lower()
        
        # Check if message is redundant (same as stage description or too similar)
        is_redundant = (
            not message or 
            message_lower == stage_desc_lower or
            message_lower in stage_desc_lower or
            stage_desc_lower in message_lower
        )
        
        if message and not is_redundant:
            # Show subprocess detail only if it adds new information
            self.process_label.setText(f"└─ {message}")
            self.process_label.setVisible(True)
        else:
            # Hide process label to avoid duplicate status
            self.process_label.setVisible(False)
        
        # Process pending events so the window repaints and stays responsive (avoids "Not Responding" on large files)
        QApplication.processEvents()
        
        # Update progress bar with determinate range
        self.progress_bar.setRange(0, 100)
        
        # Map stages to overall progress ranges (updated with more stages)
        stage_ranges = {
            'init': (0, 3),
            'loading': (3, 8),
            'extraction': (8, 15),
            'structure': (15, 20),
            'threads': (20, 25),
            'modules': (25, 30),
            'symbols': (30, 35),
            'memory': (35, 75),
            'streaming': (35, 75),
            'sampling': (35, 75),
            'patterns': (75, 80),
            'lua': (75, 80),
            'native': (80, 85),
            'correlate': (85, 90),
            'forensics': (90, 95),
            'leak_analysis': (95, 97),
            'finalize': (97, 100),
            'complete': (100, 100),
        }
        
        if stage in stage_ranges:
            start, end = stage_ranges[stage]
            overall_progress = start + (end - start) * progress
            self.progress_bar.setValue(int(overall_progress))
            self.progress_bar.setFormat(f"{int(overall_progress)}% - {stage_desc}")
        else:
            # Unknown stage, just show the message
            self.progress_bar.setFormat(f"%p% - {message}")

    def on_error(self, error_msg):
        # Stop the indeterminate animation by resetting to determinate range
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(False)
        self.process_label.setVisible(False)
        self.analyze_btn.setEnabled(True)
        self.cancel_btn.setVisible(False)
        self.status_label.setText(f"❌ Error: {error_msg}")
        self.status_label.setStyleSheet("""
            color: #ff6b6b; 
            font-size: 11pt; 
            font-weight: bold;
            padding: 5px;
            background-color: #3a2020;
            border-radius: 3px;
        """)

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
        self.process_label.setVisible(False)
        self.analyze_btn.setEnabled(True)
        self.cancel_btn.setVisible(False)

        num_dumps = len(results)
        if num_dumps == 0:
            # Check if this was actually cancelled or if it's an error
            if hasattr(self, 'worker') and hasattr(self.worker, '_cancel_requested') and self.worker._cancel_requested:
                self.status_label.setText("Analysis cancelled by user.")
            else:
                self.status_label.setText("Analysis failed - no results generated. Check console for errors.")
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

        # Populate FiveM Forensics tab (NEW)
        forensics = self._generate_forensics_view(report)
        self.forensics_text.setPlainText(forensics)

        # Populate Script Errors tab
        errors = self._generate_errors_view(report)
        self.errors_text.setPlainText(errors)

        # Populate Stack Traces tab
        stacks = self._generate_stacks_view(report)
        self.stacks_text.setPlainText(stacks)

        # Populate Full Report tab
        full_report = self.analyzer.generate_full_report(report)
        self.full_report_text.setPlainText(full_report)

        # Populate Native Calls, Lua Code, and Events tabs
        self._populate_native_calls_tab([("<single>", report)])
        self._populate_lua_code_tab([("<single>", report)])
        self._populate_events_tab([("<single>", report)])

        # Ensure Memory tab has content (heap timeline or placeholder)
        self._ensure_memory_tab()

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
                    has_stacks = bool(report.lua_stacks or report.js_stacks or report.native_stacks or report.threads_extended)
                    if has_stacks:
                        summary_lines.append("  (Confidence: low - correlate with stack traces)")
                    else:
                        summary_lines.append("  (Confidence: low - limited evidence)")
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

        # Populate new tabs: Native Calls, Lua Code, Events
        self._populate_native_calls_tab(results)
        self._populate_lua_code_tab(results)
        self._populate_events_tab(results)

        # Ensure Memory tab has content (heap timeline or placeholder)
        self._ensure_memory_tab()

    def _ensure_memory_tab(self) -> None:
        """Ensure the Memory tab is populated with heap results or a placeholder."""
        if self.current_heap_results:
            self._display_heap_results(self.current_heap_results)
            return

        self.memory_leaks_text.setPlainText(
            "No heap timeline files analyzed.\n"
            "Use 'Select Heap Timeline' to add heap JSON files for leak analysis."
        )

    def _populate_native_calls_tab(self, results: list) -> None:
        """Populate the Native Calls tab with script-to-native attribution."""
        lines = []
        lines.append("=" * 80)
        lines.append("NATIVE FUNCTION CALLS - SCRIPT ATTRIBUTION")
        lines.append("=" * 80)
        lines.append("")
        lines.append("Shows which Lua scripts are calling which GTA V native functions.")
        lines.append("Format: script_name → NATIVE_FUNCTION_NAME")
        lines.append("")

        all_native_calls = []
        all_native_callers = []

        for filename, report in results:
            if hasattr(report, 'script_errors'):
                # Get both native_attribution and native_caller types
                native_attrs = [e for e in report.script_errors if e.error_type == 'native_attribution']
                native_callers = [e for e in report.script_errors if e.error_type == 'native_caller']
                
                all_native_calls.extend(native_attrs)
                all_native_callers.extend(native_callers)

        # Show GTA V Native Calls (CREATE_VEHICLE, CREATE_OBJECT, etc.)
        if all_native_callers:
            lines.append(f"{'='*80}")
            lines.append(f"GTA V NATIVES ({len(all_native_callers)} attributions)")
            lines.append(f"{'='*80}")
            
            # Group by resource
            by_resource = {}
            for caller in all_native_callers:
                msg = caller.message
                if ' → ' in msg:
                    script, native = msg.split(' → ', 1)
                    resource = script.split('/')[0].replace('@', '')
                    if resource not in by_resource:
                        by_resource[resource] = []
                    by_resource[resource].append((script, native))
            
            for resource in sorted(by_resource.keys()):
                lines.append(f"\n@{resource}:")
                for script, native in sorted(set(by_resource[resource])):
                    script_display = script if script != f"@{resource}" else "main script"
                    lines.append(f"  • {script_display} → {native}")
        else:
            lines.append("No GTA V native calls found in memory dump.")
            lines.append("This is normal for dumps without active entity manipulation.") 
        
        lines.append("")
        lines.append("=" * 80)
        lines.append("📋 MINIDUMP LIMITATION")
        lines.append("=" * 80)
        lines.append("Native function calls are typically only found in full memory dumps.")
        lines.append("MiniDumps (like crash reports) capture only:")
        lines.append("  • Thread stacks and CPU registers")
        lines.append("  • Exception information")
        lines.append("  • Selected memory regions")
        lines.append("")
        lines.append("To debug native calls, check the CitizenFX.log for script errors")
        lines.append("and resource timing information in the Summary or Suspects tabs.")
        lines.append("")

        # Show Framework Function Calls
        if all_native_calls:
            lines.append(f"{'='*80}")
            lines.append(f"FRAMEWORK FUNCTIONS ({len(all_native_calls)} attributions)")
            lines.append(f"{'='*80}")
            lines.append("FiveM/QBCore framework function calls detected:")
            lines.append("")
            
            # Group by resource
            by_resource = {}
            for attr in all_native_calls:
                msg = attr.message
                if ' → ' in msg:
                    script, func = msg.split(' → ', 1)
                    resource = script.split('/')[0].replace('@', '')
                    if resource not in by_resource:
                        by_resource[resource] = set()
                    by_resource[resource].add(func)
            
            for resource in sorted(by_resource.keys()):
                lines.append(f"\n@{resource}:")
                for func in sorted(by_resource[resource])[:15]:
                    lines.append(f"  • {func}")
                if len(by_resource[resource]) > 15:
                    lines.append(f"  ... and {len(by_resource[resource]) - 15} more")
        
        if not all_native_calls and not all_native_callers:
            lines.append("")
            lines.append("💡 Tip: Native call attribution requires memory dump analysis.")
            lines.append("   Make sure you've selected a .dmp file, not just logs.")

        self.native_calls_text.setPlainText("\n".join(lines))

    def _populate_lua_code_tab(self, results: list) -> None:
        """Populate the Lua Code tab with extracted code fragments."""
        lines = []
        lines.append("=" * 80)
        lines.append("LUA CODE FRAGMENTS EXTRACTED FROM MEMORY")
        lines.append("=" * 80)
        lines.append("")
        lines.append("Actual Lua code reconstructed from the crash dump memory.")
        lines.append("Can help identify what scripts were executing at crash time.")
        lines.append("")

        all_fragments = []
        for filename, report in results:
            if hasattr(report, 'script_errors'):
                fragments = [e for e in report.script_errors if e.error_type == 'lua_code_fragment']
                all_fragments.extend(fragments)

        if all_fragments:
            lines.append(f"Found {len(all_fragments)} code fragments:\n")
            
            for i, frag in enumerate(all_fragments[:30], 1):
                lines.append(f"{'─'*80}")
                lines.append(f"Fragment #{i}")
                lines.append(f"{'─'*80}")
                
                # Clean up the code display
                code = frag.message
                lines.append(code)
                lines.append("")
                
            if len(all_fragments) > 30:
                lines.append(f"\n... and {len(all_fragments) - 30} more fragments")
                lines.append("(See Full Report for complete list)")
        else:
            lines.append("No Lua code fragments found in memory.")
            lines.append("")
            lines.append("═" * 80)
            lines.append("📋 WHY IS THIS EMPTY?")
            lines.append("═" * 80)
            lines.append("")
            lines.append("Lua source code is typically only found in FULL memory dumps.")
            lines.append("")
            lines.append("MiniDumps (crash reports) only include:")
            lines.append("  • Thread stack traces (which may show Lua frames)")
            lines.append("  • Exception information")
            lines.append("  • Limited memory regions around crash point")
            lines.append("")
            lines.append("Lua source code is in the heap, which is NOT captured in MiniDumps.")
            lines.append("")
            lines.append("ALTERNATIVE SOURCES FOR DEBUGGING:")
            lines.append("  1. CitizenFX.log - Shows script errors with line numbers")
            lines.append("  2. Summary tab - Resource timing and error analysis")
            lines.append("  3. Suspects tab - Top affected resources")
            lines.append("  4. Stack Traces - Shows Lua stack frames at crash time")

        self.lua_code_text.setPlainText("\n".join(lines))

    def _populate_events_tab(self, results: list) -> None:
        """Populate the Events tab with network event data."""
        from crash_analyzer.memory_analyzer import EvidenceType
        from collections import Counter
        
        lines = []
        lines.append("=" * 80)
        lines.append("NETWORK EVENTS & TRIGGERS")
        lines.append("=" * 80)
        lines.append("")
        lines.append("FiveM network events found in memory (TriggerServerEvent, RegisterNetEvent, etc.)")
        lines.append("")

        all_events = set()
        reg_counts = Counter()
        rem_counts = Counter()
        handler_delta = 0

        for filename, report in results:
            if hasattr(report, 'all_evidence'):
                for evidence in report.all_evidence:
                    if evidence.evidence_type == EvidenceType.EVENT_HANDLER:
                        if evidence.context:
                            all_events.add(evidence.context)
                    if evidence.evidence_type == EvidenceType.ERROR_MESSAGE and 'TriggerEvent' in str(evidence.context):
                        if evidence.context:
                            all_events.add(evidence.context)

            # Include direct event handler names extracted from memory
            if hasattr(report, 'event_handlers') and report.event_handlers:
                all_events.update(report.event_handlers)

            # Aggregate registration/removal counts
            for handler_type, _ in getattr(report, 'event_handlers_registered', []):
                reg_counts[handler_type] += 1
            for handler_type, _ in getattr(report, 'event_handlers_removed', []):
                rem_counts[handler_type] += 1
            handler_delta += getattr(report, 'event_handler_delta', 0)

        if all_events:
            lines.append(f"DETECTED EVENTS ({len(all_events)}):")
            lines.append("─" * 80)
            
            # Categorize events
            server_events = [e for e in all_events if 'ServerEvent' in e or ':server:' in e]
            client_events = [e for e in all_events if e not in server_events]
            
            if server_events:
                lines.append("\n🌐 Server Events:")
                for event in sorted(server_events)[:30]:
                    lines.append(f"  • {event}")
                if len(server_events) > 30:
                    lines.append(f"  ... and {len(server_events) - 30} more")
            
            if client_events:
                lines.append("\n💻 Client Events:")
                for event in sorted(client_events)[:30]:
                    lines.append(f"  • {event}")
                if len(client_events) > 30:
                    lines.append(f"  ... and {len(client_events) - 30} more")
        else:
            lines.append("No event names found in memory dump.")

        # Registration/removal summary (useful even if names are missing)
        if reg_counts or rem_counts:
            lines.append("")
            lines.append("REGISTRATION ACTIVITY:")
            lines.append("─" * 80)
            if reg_counts:
                lines.append("Registered handlers:")
                for handler, count in reg_counts.most_common(10):
                    lines.append(f"  • {handler}: {count}")
            if rem_counts:
                lines.append("Removed handlers:")
                for handler, count in rem_counts.most_common(10):
                    lines.append(f"  • {handler}: {count}")
            if handler_delta:
                lines.append(f"Net handler delta: {handler_delta:+d}")

        if not all_events and not reg_counts and not rem_counts:
            lines.append("")
            lines.append("═" * 80)
            lines.append("📋 WHY IS THIS EMPTY?")
            lines.append("═" * 80)
            lines.append("")
            lines.append("Network events are typically only found in FULL memory dumps.")
            lines.append("")
            lines.append("MiniDumps (crash reports) only include:")
            lines.append("  • Thread stack traces")
            lines.append("  • CPU registers at crash time")
            lines.append("  • Exception information")
            lines.append("  • Limited memory snapshots")
            lines.append("")
            lines.append("Event handler tables live in the Lua/V8 heap, which is NOT captured")
            lines.append("in MiniDumps. To find active events, use a full memory dump.")
            lines.append("")
            lines.append("WHAT YOU CAN DO NOW:")
            lines.append("  1. Check Summary tab for Top Suspects (resources most involved)")
            lines.append("  2. Review Stack Traces for which modules were executing")
            lines.append("  3. Check CitizenFX.log for TriggerEvent/RegisterNetEvent errors")
            lines.append("  4. Analyze script errors and timing in Suspects tab")

        self.events_text.setPlainText("\n".join(lines))

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

        # WinDbg Native Stack Analysis (if available)
        if hasattr(report, 'windbg_analysis') and report.windbg_analysis:
            lines.append("-" * 40)
            lines.append("WINDBG NATIVE ANALYSIS:")
            wd = report.windbg_analysis
            if wd.get('success'):
                if wd.get('exception_code'):
                    lines.append(f"  - Exception Code: 0x{wd['exception_code']:08X}")
                if wd.get('exception_address'):
                    lines.append(f"  - Exception Address: 0x{wd['exception_address']:016X}")
                if wd.get('culprit_module'):
                    lines.append(f"  - Culprit Module: {wd['culprit_module']}")
                    if wd.get('confidence'):
                        lines.append(f"  - Confidence: {wd['confidence']*100:.0f}%")
                frames = wd.get('stack_frames', [])
                if frames:
                    lines.append(f"  - Stack Frames: {len(frames)}")
                fivem_mods = wd.get('fivem_modules', [])
                if fivem_mods:
                    lines.append(f"  - FiveM Modules: {len(fivem_mods)}")
            else:
                lines.append(f"  - Analysis Failed: {wd.get('error', 'Unknown error')}")
            lines.append("")

        # FiveM Forensics quick summary (if available)
        lines.append("-" * 40)
        lines.append("FIVEM FORENSICS SUMMARY:")
        if report.fivem_forensics:
            fivem = report.fivem_forensics
            lines.append(f"  - Confidence: {fivem.get('confidence', 'unknown')}")
            lines.append(f"  - Crashometry Entries: {len(fivem.get('crashometry', []) or [])}")
            lines.append(f"  - FiveM Markers: {len(fivem.get('fivem_markers', []) or [])}")
            lines.append(f"  - RSC7 Issues: {len(fivem.get('rsc7_issues', []) or [])}")
            lines.append(f"  - Streaming Crashes: {len(fivem.get('streaming', []) or [])}")
            lines.append(f"  - Corruption Evidence: {len(fivem.get('corruption', []) or [])}")
            if fivem.get('error'):
                lines.append(f"  - Forensics Error: {fivem.get('error')}")
        else:
            lines.append("  - Not available (no dump analyzed or forensics failed)")
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

        # ===== ENHANCED EXTRACTION (CRASHOMETRY + LOG ANALYSIS) =====
        has_enhanced_data = (
            report.crash_hash or report.crash_hash_key or 
            report.primary_suspect_resource or report.timed_script_errors or
            report.cpu_registers
        )
        
        if has_enhanced_data:
            lines.append("-" * 40)
            lines.append("🔬 ENHANCED CRASH FORENSICS:")
            lines.append("")
            
            # Crashometry data (from crashometry.json)
            if report.crash_hash or report.crash_hash_key:
                lines.append("  Crashometry Data:")
                if report.crash_hash:
                    lines.append(f"    Crash Hash: {report.crash_hash}")
                if report.crash_hash_key:
                    lines.append(f"    Crash Key:  {report.crash_hash_key}")
                if report.server_address:
                    lines.append(f"    Server:     {report.server_address}")
                if report.server_version:
                    lines.append(f"    Version:    {report.server_version}")
                if report.gpu_name:
                    lines.append(f"    GPU:        {report.gpu_name}")
                if report.onesync_enabled is not None:
                    onesync_str = "Enabled" if report.onesync_enabled else "Disabled"
                    if report.onesync_big:
                        onesync_str += " (Big Mode)"
                    lines.append(f"    OneSync:    {onesync_str}")
                lines.append("")
            
            # Primary suspect from timed script errors
            if report.primary_suspect_resource:
                lines.append("  🎯 PRIMARY SUSPECT:")
                lines.append(f"    Resource: {report.primary_suspect_resource}")
                if report.primary_suspect_file:
                    loc = report.primary_suspect_file
                    if report.primary_suspect_line:
                        loc += f":{report.primary_suspect_line}"
                    lines.append(f"    Location: {loc}")
                if report.primary_suspect_message:
                    # Truncate long messages
                    msg = report.primary_suspect_message
                    if len(msg) > 80:
                        msg = msg[:77] + "..."
                    lines.append(f"    Error:    {msg}")
                if report.time_before_crash_sec is not None:
                    lines.append(f"    Timing:   {report.time_before_crash_sec:.1f}s before crash")
                lines.append("")
            
            # Timed script errors summary
            if report.timed_script_errors:
                error_count = len(report.timed_script_errors)
                lines.append(f"  Script Errors with Timestamps: {error_count}")
                if report.crash_timestamp_ms:
                    lines.append(f"  Crash Timestamp: {report.crash_timestamp_ms:,} ms ({report.crash_timestamp_ms / 1000:.1f}s uptime)")
                lines.append("")
            
            # Resource count
            if report.loaded_resource_count:
                lines.append(f"  Loaded Resources: {report.loaded_resource_count}")
                lines.append("")
            
            # CPU registers at crash
            if report.cpu_registers:
                lines.append("  CPU Registers at Crash:")
                regs = report.cpu_registers
                # Format in rows of 4
                reg_names = ['RAX', 'RCX', 'RDX', 'RBX', 'RSP', 'RBP', 'RSI', 'RDI',
                             'R8', 'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15', 'RIP']
                for i in range(0, len(reg_names), 4):
                    row_regs = reg_names[i:i+4]
                    row_parts = []
                    for rn in row_regs:
                        if rn in regs:
                            row_parts.append(f"{rn}=0x{regs[rn]:X}")
                    if row_parts:
                        lines.append(f"    {', '.join(row_parts)}")
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
        # Use enhanced leak report if available
        has_leak_data = (
            report.entity_creations or report.entity_deletions or
            report.memory_leak_indicators or report.pool_exhaustion_indicators or
            report.timers_created or report.nui_patterns or report.database_patterns or
            report.heap_committed_bytes > 0  # New: actual heap statistics
        )
        
        if has_leak_data:
            lines.append("-" * 40)
            
            # If we have the new enhanced leak analysis, use that
            if hasattr(report, 'leak_confidence') and report.leak_confidence != "none":
                # Use the new enhanced leak report
                lines.append("MEMORY LEAK ANALYSIS:")
                lines.append("")
                
                # Overall assessment
                if report.leak_detected:
                    icon = "🔴" if report.leak_confidence == "high" else "🟠"
                    lines.append(f"  {icon} MEMORY LEAK DETECTED (Confidence: {report.leak_confidence.upper()})")
                else:
                    confidence_msg = f" (Confidence: {report.leak_confidence})" if report.leak_confidence != "none" else ""
                    lines.append(f"  🟢 No strong evidence of memory leak{confidence_msg}")
                
                lines.append("")
                
                # Memory statistics (if available)
                if report.heap_committed_bytes > 0:
                    lines.append("  Memory Usage at Crash Time:")
                    committed_mb = report.heap_committed_bytes / (1024 ** 2)
                    reserved_mb = report.heap_reserved_bytes / (1024 ** 2)
                    free_mb = report.heap_free_bytes / (1024 ** 2)
                    
                    pressure_icon = "🔴" if report.memory_pressure == "critical" else ("🟠" if report.memory_pressure == "elevated" else "🟢")
                    
                    lines.append(f"    Committed: {committed_mb:,.1f} MB")
                    lines.append(f"    Reserved:  {reserved_mb:,.1f} MB")
                    lines.append(f"    Free:      {free_mb:,.1f} MB")
                    lines.append(f"    Pressure:  {pressure_icon} {report.memory_pressure.upper()}")
                    
                    if report.oom_imminent:
                        lines.append(f"    ⚠️  OUT-OF-MEMORY IMMINENT!")
                    
                    lines.append("")
                
                # Heap fragmentation
                if report.heap_fragmentation_pct > 0:
                    frag_icon = "⚠️" if report.heap_fragmentation_pct > 30.0 else "ℹ️"
                    lines.append(f"  Heap Fragmentation: {frag_icon} {report.heap_fragmentation_pct:.1f}%")
                    if report.heap_fragmentation_pct > 30.0:
                        wasted_mb = report.heap_reserved_bytes / (1024 ** 2)
                        lines.append(f"    {wasted_mb:.1f}MB wasted due to fragmentation")
                    lines.append("")
                
                # Allocation tracking
                if report.entity_allocation_delta != 0 or report.timer_allocation_delta != 0 or report.event_handler_delta != 0:
                    lines.append("  Allocation Tracking:")
                    
                    if report.entity_allocation_delta != 0:
                        entity_creates = len(report.entity_creations)
                        entity_deletes = len(report.entity_deletions)
                        delta_icon = "⚠️" if report.entity_allocation_delta > 100 else "ℹ️"
                        lines.append(f"    {delta_icon} Entities: {entity_creates:,} created, {entity_deletes:,} deleted (delta: +{report.entity_allocation_delta:,})")
                    
                    if report.timer_allocation_delta > 0:
                        timer_icon = "⚠️" if report.timer_allocation_delta > 50 else "ℹ️"
                        lines.append(f"    {timer_icon} Timers: {report.timer_allocation_delta:,} created (no cleanup tracking)")
                    
                    if report.event_handler_delta != 0:
                        handler_regs = len(report.event_handlers_registered)
                        handler_removes = len(report.event_handlers_removed)
                        handler_icon = "⚠️" if report.event_handler_delta > 50 else "ℹ️"
                        lines.append(f"    {handler_icon} Event Handlers: {handler_regs:,} registered, {handler_removes:,} removed (delta: +{report.event_handler_delta:,})")
                    
                    lines.append("")
                
                # Specific leak types
                leak_types = []
                if report.entity_leak:
                    leak_types.append("🚗 Entity Leak (vehicles/peds/objects not cleaned up)")
                if report.timer_leak:
                    leak_types.append("⏱️  Timer Leak (CreateThread/SetTimeout without clearing)")
                if report.event_handler_leak:
                    leak_types.append("📡 Event Handler Leak (RegisterNetEvent without cleanup)")
                if report.nui_leak:
                    nui_count = len(report.nui_patterns)
                    leak_types.append(f"🌐 NUI/Browser Leak ({nui_count} CEF patterns)")
                
                if leak_types:
                    lines.append("  Detected Leak Types:")
                    for leak in leak_types:
                        lines.append(f"    {leak}")
                    lines.append("")
                
                # Evidence
                if hasattr(report, 'leak_evidence') and report.leak_evidence:
                    lines.append("  Evidence:")
                    for evidence in report.leak_evidence[:10]:  # Limit to first 10
                        lines.append(f"    • {evidence}")
                    lines.append("")
                
                # Recommendations
                if report.leak_detected:
                    lines.append("  Recommendations:")
                    if report.entity_leak:
                        lines.append("    1. Check for DeleteEntity() calls in resource cleanup")
                        lines.append("    2. Verify AddEventHandler('onResourceStop', ...) handlers exist")
                    if report.timer_leak:
                        lines.append("    3. Ensure all CreateThread() loops have proper exit conditions")
                        lines.append("    4. Check for SetTimeout/SetInterval without ClearTimeout/ClearInterval")
                    if report.event_handler_leak:
                        lines.append("    5. Verify RemoveEventHandler() calls on resource stop")
                    if report.nui_leak:
                        lines.append("    6. Check NUI resources for SendNUIMessage() spam")
                        lines.append("    7. Ensure CEF browsers are properly destroyed")
                    lines.append("")
                    
            else:
                # Fall back to old pattern-based analysis
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
                    # Show top resources using NUI when available
                    if hasattr(report, 'nui_resources') and report.nui_resources:
                        lines.append("    Top NUI Resources:")
                        for res, count in sorted(report.nui_resources.items(), key=lambda x: x[1], reverse=True)[:5]:
                            lines.append(f"      - {res}: {count} hit(s)")
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

        # ===== ENHANCED SUSPECT FROM TIMED LOG ANALYSIS =====
        if report.primary_suspect_resource:
            lines.append("🎯 TOP SUSPECT (from timestamped log analysis):")
            lines.append("-" * 50)
            lines.append(f"   Resource: {report.primary_suspect_resource}")
            if report.primary_suspect_file:
                loc = report.primary_suspect_file
                if report.primary_suspect_line:
                    loc += f":{report.primary_suspect_line}"
                lines.append(f"   Location: {loc}")
            if report.primary_suspect_message:
                # Show full message, possibly wrapped
                msg = report.primary_suspect_message
                if len(msg) > 100:
                    lines.append(f"   Error: {msg[:100]}")
                    lines.append(f"          {msg[100:]}")
                else:
                    lines.append(f"   Error: {msg}")
            if report.time_before_crash_sec is not None:
                lines.append(f"   Timing: Error occurred {report.time_before_crash_sec:.1f}s before crash")
                if report.time_before_crash_sec < 5.0:
                    lines.append("           ⚠️  VERY CLOSE to crash time - HIGH correlation!")
                elif report.time_before_crash_sec < 30.0:
                    lines.append("           📍 Close to crash time - likely related")
            lines.append("")
            lines.append("   This suspect was identified by correlating script error")
            lines.append("   timestamps with the crash time from crashometry.json.")
            lines.append("")

        if not report.primary_suspects:
            if not report.primary_suspect_resource:
                lines.append("No specific resource could be identified as the cause.")
                lines.append("Check the Stack Traces and Script Errors tabs for more info.")
            return "\n".join(lines)

        sec = getattr(report, 'primary_suspect_secondary', None)
        conf = getattr(report, 'primary_suspect_confidence', 'medium')
        if sec:
            lines.append("Note: Top two suspects have close scores; consider both.")
        if conf == "low":
            has_stacks = bool(report.lua_stacks or report.js_stacks or report.native_stacks or report.threads_extended)
            has_errors = bool(report.script_errors)
            messages = []
            if has_stacks:
                messages.append("stack traces")
            if has_errors:
                messages.append("script errors")
            if messages:
                lines.append(f"Confidence is low; correlate with {' and '.join(messages)}.")
            else:
                lines.append("Confidence is low; limited evidence available.")
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

    def _generate_forensics_view(self, report: CrashReport) -> str:
        """Generate detailed FiveM forensics view with cache, RSC7, and pool diagnostics."""
        lines = []
        lines.append("=" * 80)
        lines.append("FIVEM FORENSICS - CACHE & STREAMING DIAGNOSTICS")
        lines.append("=" * 80)
        lines.append("")
        
        # ===== CRASHOMETRY DATA SECTION =====
        if report.crash_hash or report.crash_hash_key or report.server_address:
            lines.append("┌─ CRASHOMETRY DATA " + "─" * 59)
            lines.append("│")
            if report.crash_hash:
                lines.append(f"│  Crash Hash:    {report.crash_hash}")
            if report.crash_hash_key:
                lines.append(f"│  Crash Key:     {report.crash_hash_key}")
            if report.server_address:
                lines.append(f"│  Server:        {report.server_address}")
            if report.server_version:
                lines.append(f"│  Version:       {report.server_version}")
            if report.gpu_name:
                lines.append(f"│  GPU:           {report.gpu_name}")
            if report.onesync_enabled is not None:
                onesync_str = "✅ Enabled" if report.onesync_enabled else "❌ Disabled"
                if report.onesync_big:
                    onesync_str += " (Big Mode - 1024 entities)"
                lines.append(f"│  OneSync:       {onesync_str}")
            if report.loaded_resource_count:
                lines.append(f"│  Resources:     {report.loaded_resource_count} loaded")
            if report.crash_timestamp_ms:
                uptime_sec = report.crash_timestamp_ms / 1000
                uptime_min = uptime_sec / 60
                lines.append(f"│  Uptime:        {uptime_min:.1f} minutes ({uptime_sec:.1f}s)")
            lines.append("│")
            lines.append("└" + "─" * 78)
            lines.append("")
        
        # ===== FRAMEWORK DETECTION SECTION =====
        # Display detected FiveM framework (QBCore/ESX/VRP/Ox) if available
        if hasattr(report, 'framework_detected') and report.framework_detected:
            lines.append("┌─ FRAMEWORK DETECTION " + "─" * 56)
            lines.append("│")
            framework = report.framework_detected
            confidence = getattr(report, 'framework_confidence', 0.0)
            
            # Choose icon based on confidence level
            if confidence >= 0.8:
                confidence_icon = "🟢"
                confidence_text = "High"
            elif confidence >= 0.5:
                confidence_icon = "🟡"
                confidence_text = "Medium"
            else:
                confidence_icon = "🔴"
                confidence_text = "Low"
            
            lines.append(f"│  {confidence_icon} Framework:   {framework}")
            lines.append(f"│     Confidence:  {confidence_text} ({confidence:.0%})")
            
            # Add helpful context about detected framework
            if framework == "QBCore":
                lines.append("│     Common Issues: qb-core exports, SharedObject conflicts")
            elif framework == "ESX":
                lines.append("│     Common Issues: es_extended events, TriggerClientEvent sync")
            elif framework == "VRP":
                lines.append("│     Common Issues: Tunnel/Proxy timing, vRPclient registration")
            elif framework == "Ox":
                lines.append("│     Common Issues: ox_lib modules, ox_inventory sync")
            
            lines.append("│")
            lines.append("└" + "─" * 78)
            lines.append("")
        
        # ===== FXMANIFEST METADATA SECTION =====
        # Display extracted fxmanifest.lua metadata if available
        if hasattr(report, 'fxmanifest_data') and report.fxmanifest_data:
            lines.append("┌─ FXMANIFEST METADATA " + "─" * 56)
            lines.append("│")
            fxdata = report.fxmanifest_data
            
            if 'fx_version' in fxdata:
                lines.append(f"│  FX Version:     {fxdata['fx_version']}")
            if 'game' in fxdata:
                lines.append(f"│  Game:           {fxdata['game']}")
            if 'author' in fxdata:
                lines.append(f"│  Author:         {fxdata['author']}")
            if 'version' in fxdata:
                lines.append(f"│  Version:        {fxdata['version']}")
            if 'description' in fxdata:
                desc = fxdata['description']
                if len(desc) > 60:
                    lines.append(f"│  Description:    {desc[:60]}...")
                else:
                    lines.append(f"│  Description:    {desc}")
            
            # Display script counts
            script_types = ['client_scripts', 'server_scripts', 'shared_scripts']
            for script_type in script_types:
                if script_type in fxdata and fxdata[script_type]:
                    count = len(fxdata[script_type])
                    lines.append(f"│  {script_type.replace('_', ' ').title()}: {count} files")
                    # Show first few scripts
                    for script in fxdata[script_type][:3]:
                        lines.append(f"│      - {script}")
                    if count > 3:
                        lines.append(f"│      ... and {count - 3} more")
            
            if 'exports' in fxdata and fxdata['exports']:
                count = len(fxdata['exports'])
                lines.append(f"│  Exports:        {count} functions")
                for export in fxdata['exports'][:3]:
                    lines.append(f"│      - {export}")
                if count > 3:
                    lines.append(f"│      ... and {count - 3} more")
            
            lines.append("│")
            lines.append("└" + "─" * 78)
            lines.append("")
        
        # ===== ERROR SEVERITY CLASSIFICATION =====
        # Display error severity statistics if available
        if hasattr(report, 'error_severities') and report.error_severities:
            lines.append("┌─ ERROR SEVERITY CLASSIFICATION " + "─" * 45)
            lines.append("│")
            
            # Count severities
            severities = {}
            for severity in report.error_severities.values():
                severities[severity] = severities.get(severity, 0) + 1
            
            # Display summary
            lines.append(f"│  Total Errors Classified: {len(report.error_severities)}")
            lines.append("│")
            
            # Show breakdown with icons
            severity_icons = {
                'crash': '🔴',
                'panic': '🟠',
                'error': '🟡',
                'warning': '🟢',
            }
            
            for severity in ['crash', 'panic', 'error', 'warning']:
                count = severities.get(severity, 0)
                if count > 0:
                    icon = severity_icons.get(severity, '⚪')
                    lines.append(f"│  {icon} {severity.capitalize()}: {count}")
            
            lines.append("│")
            lines.append("└" + "─" * 78)
            lines.append("")
        
        if not report.fivem_forensics:
            lines.append("No FiveM-specific forensics data available.")
            lines.append("")
            lines.append("This could mean:")
            lines.append("  • The crash is not FiveM-related")
            lines.append("  • Forensics analysis was not run")
            lines.append("  • No cache/streaming markers were found in the dump")
            return "\n".join(lines)
        
        forensics = report.fivem_forensics
        
        # Confidence banner
        confidence = forensics.get('confidence', 'unknown').upper()
        confidence_color = {
            'HIGH': '🟢',
            'MEDIUM': '🟡',
            'LOW': '🔴',
        }.get(confidence, '⚪')
        lines.append(f"{confidence_color} CONFIDENCE LEVEL: {confidence}")
        lines.append("")
        
        # Cache Metadata Section
        if forensics.get('cache_metadata'):
            lines.append("┌─ CACHE FILE METADATA " + "─" * 56)
            lines.append("│")
            metadata = forensics['cache_metadata'][:10]  # Top 10
            for i, meta in enumerate(metadata, 1):
                lines.append(f"│ [{i}] {meta.get('cache_path', 'unknown')}")
                if meta.get('asset_type'):
                    lines.append(f"│     Asset Type: {meta['asset_type']}")
                if meta.get('resource_name'):
                    lines.append(f"│     Resource: {meta['resource_name']}")
                if meta.get('sha1_hash'):
                    lines.append(f"│     SHA1: {meta['sha1_hash'][:16]}...")
                if i < len(metadata):
                    lines.append("│")
            lines.append("└" + "─" * 79)
            lines.append("")
        
        # Cache Corruption Evidence (Enhanced)
        if forensics.get('corruption'):
            lines.append("┌─ CACHE CORRUPTION EVIDENCE " + "─" * 50)
            lines.append("│")
            for i, corruption in enumerate(forensics['corruption'][:10], 1):
                severity = corruption.get('severity', 'medium').upper()
                severity_icon = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(severity, '⚪')
                lines.append(f"│ {severity_icon} [{severity}] {corruption.get('type', 'unknown')}")
                lines.append(f"│   Source: {corruption.get('source', 'unknown')}")
                
                # Display details
                if 'file_path' in corruption:
                    lines.append(f"│   File: {corruption['file_path']}")
                if 'cache_path' in corruption and corruption['cache_path']:
                    lines.append(f"│   Cache Path: {corruption['cache_path']}")
                
                # Show nested details dict
                if 'details' in corruption and isinstance(corruption['details'], dict):
                    for key, value in corruption['details'].items():
                        lines.append(f"│   {key}: {value}")
                
                if i < len(forensics['corruption'][:10]):
                    lines.append("│")
            lines.append("└" + "─" * 79)
            lines.append("")
        
        # Transaction State
        if forensics.get('transaction_state'):
            lines.append("┌─ TRANSACTION STATE " + "─" * 58)
            lines.append("│")
            ts = forensics['transaction_state']
            if ts.get('has_temp_files'):
                lines.append("│ ⚠️  Temporary files detected - incomplete write operation")
            if ts.get('has_lock_files'):
                lines.append("│ ⚠️  Lock files detected - possible concurrent access")
            if ts.get('incomplete_writes'):
                lines.append(f"│ Incomplete Writes: {', '.join(ts['incomplete_writes'])}")
            if ts.get('transaction_id'):
                lines.append(f"│ Transaction ID: {ts['transaction_id']}")
            lines.append("└" + "─" * 79)
            lines.append("")
        
        # Memory Pool Diagnostics
        if forensics.get('pool_diagnostics'):
            lines.append("┌─ MEMORY POOL DIAGNOSTICS " + "─" * 52)
            lines.append("│")
            pd = forensics['pool_diagnostics']
            if pd.get('pool_size_limit'):
                lines.append(f"│ Pool Size Limit: {pd['pool_size_limit']:,} bytes")
            if pd.get('allocation_failures'):
                lines.append(f"│ Allocation Failures: {pd['allocation_failures']}")
            if pd.get('fragmentation_detected'):
                lines.append("│ ⚠️  Memory fragmentation detected")
            lines.append("└" + "─" * 79)
            lines.append("")
        
        # Asset Dependencies
        if forensics.get('asset_dependencies'):
            lines.append("┌─ ASSET DEPENDENCY CHAIN " + "─" * 53)
            lines.append("│")
            deps = forensics['asset_dependencies'][:10]
            for dep in deps:
                lines.append(f"│ {dep['parent']} ──→ {dep['child']}")
            if len(forensics['asset_dependencies']) > 10:
                lines.append(f"│ ... and {len(forensics['asset_dependencies']) - 10} more")
            lines.append("└" + "─" * 79)
            lines.append("")
        
        # Open Cache Handles
        if forensics.get('open_handles'):
            lines.append("┌─ OPEN CACHE HANDLES AT CRASH " + "─" * 47)
            lines.append("│")
            for handle in forensics['open_handles'][:10]:
                lines.append(f"│ [{handle['type']}] {handle['name']}")
            lines.append("└" + "─" * 79)
            lines.append("")
        
        # RSC7 Format Issues
        if forensics.get('rsc7_issues'):
            lines.append("┌─ RSC7 FORMAT VALIDATION " + "─" * 53)
            lines.append("│")
            for issue in forensics['rsc7_issues'][:5]:
                lines.append(f"│ ❌ {issue.get('issue', 'Unknown issue')}")
                lines.append(f"│   Offset: {issue.get('offset', '?')}")
                if 'header' in issue:
                    lines.append(f"│   Header: {issue['header']}")
            lines.append("└" + "─" * 79)
            lines.append("")
        
        # Streaming Crashes
        if forensics.get('streaming'):
            lines.append("┌─ STREAMING SYSTEM CRASHES " + "─" * 51)
            lines.append("│")
            for crash in forensics['streaming'][:5]:
                lines.append(f"│ Crash at offset {crash.get('offset', '?')}")
                lines.append(f"│   File Handle: {crash.get('handle', '?')}")
                lines.append(f"│   File Offset: {crash.get('file_offset', '?')}")
                lines.append(f"│   Bytes Reading: {crash.get('bytes', '?')}")
                lines.append("│")
            lines.append("└" + "─" * 79)
            lines.append("")
        
        # Crashometry Telemetry
        if forensics.get('crashometry'):
            lines.append("┌─ CRASHOMETRY TELEMETRY " + "─" * 54)
            lines.append("│")
            for entry in forensics['crashometry'][:10]:
                marker = entry.get('marker', '')
                marker_display = f" [{marker}]" if marker else ""
                lines.append(f"│ {entry.get('key', '?')}{marker_display}")
                lines.append(f"│   Value: {entry.get('value', '?')}")
                lines.append("│")
            lines.append("└" + "─" * 79)
            lines.append("")
        
        # Recommended Actions
        lines.append("┌─ RECOMMENDED ACTIONS " + "─" * 56)
        lines.append("│")
        
        # Extract recommendations from forensics report
        if forensics.get('corruption'):
            if any('rcd_corrupted' in str(c) for c in forensics['corruption']):
                lines.append("│ 🔴 CRITICAL: DELETE cache folder and restart FiveM")
            if any(c.get('severity') == 'high' for c in forensics['corruption']):
                lines.append("│ 🟠 Clear cache and verify game files via Steam/Epic")
        
        if forensics.get('transaction_state', {}).get('has_lock_files'):
            lines.append("│ ⚠️  Close ALL FiveM instances before restarting")
        
        if forensics.get('pool_diagnostics', {}).get('fragmentation_detected'):
            lines.append("│ 💡 Restart FiveM to reset memory allocator")
        
        if forensics.get('streaming'):
            lines.append("│ 💡 Check disk I/O and file integrity")
        
        if forensics.get('rsc7_issues'):
            lines.append("│ 💡 Verify game files via Steam/Epic launcher")
        
        if not any([
            forensics.get('corruption'),
            forensics.get('streaming'),
            forensics.get('rsc7_issues'),
            forensics.get('crashometry')
        ]):
            lines.append("│ ℹ️  No critical FiveM issues detected")
        
        lines.append("└" + "─" * 79)
        
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
            lines.append("(MiniDumps often miss Lua/V8 heap content.)")
            lines.append("")
        else:
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
        elif not report.script_errors:
            lines.append("No log errors found either. Verify CitizenFX.log was selected.")

        return "\n".join(lines)

    def _format_native_stack_frame(self, frame_str: str, frame_index: int = 0, total_frames: int = 0) -> str:
        """
        Enhance native stack frame formatting with better visualization.
        
        Input: "  FiveM_b3570_GTAProcess.exe+0x61A5BB1"
        Output: "[01] FiveM_b3570_GTAProcess.exe + 0x61A5BB1"
        """
        if not frame_str or not frame_str.strip():
            return frame_str
        
        # Remove leading spaces
        frame = frame_str.strip()
        
        # Parse frame: "module+0xOFFSET [ -> function+0xDISP]"
        parts = frame.split(" -> ", 1)
        base_frame = parts[0].strip()
        symbol_info = parts[1].strip() if len(parts) > 1 else None
        
        # Format base frame with padding and frame number
        formatted = f"[{frame_index:02d}] {base_frame}"
        
        # Add symbol info if available
        if symbol_info:
            formatted += f" → {symbol_info}"
        
        return formatted

    def _format_thread_info(self, thread) -> str:
        """Format thread information compactly for better display."""
        # Create a concise thread summary line
        parts = [f"[TID {thread.thread_id}]"]
        if thread.thread_name:
            parts.append(f"'{thread.thread_name}'")
        if thread.state:
            parts.append(f"[{thread.state}]")
        if thread.priority:
            parts.append(f"[P:{thread.priority}]")
        return " ".join(parts)

    def _generate_stacks_view(self, report: CrashReport) -> str:
        """Generate detailed view of stack traces."""
        lines = []
        lines.append("=" * 60)
        lines.append("STACK TRACES AND THREAD INFORMATION")
        lines.append("=" * 60)
        lines.append("")

        # WinDbg Native Stack Analysis (if available)
        if hasattr(report, 'windbg_analysis') and report.windbg_analysis:
            wd = report.windbg_analysis
            lines.append("🔍 WINDBG NATIVE STACK ANALYSIS")
            lines.append("=" * 60)
            
            if wd.get('success'):
                # Exception info
                if wd.get('exception_code'):
                    lines.append(f"Exception Code: 0x{wd['exception_code']:08X}")
                if wd.get('exception_address'):
                    lines.append(f"Exception Address: 0x{wd['exception_address']:016X}")
                
                # Culprit identification
                if wd.get('culprit_module'):
                    lines.append(f"Culprit Module: {wd['culprit_module']}")
                    if wd.get('confidence'):
                        lines.append(f"Confidence: {wd['confidence']*100:.0f}%")
                
                # Stack frames
                frames = wd.get('stack_frames', [])
                if frames:
                    lines.append(f"\nStack Frames: {len(frames)}")
                    lines.append("-" * 40)
                    
                    # Show top 20 frames
                    for frame in frames[:20]:
                        if hasattr(frame, 'frame_number'):
                            num = frame.frame_number
                            mod = frame.module
                            func = frame.function
                            fivem_marker = ' [FIVEM]' if frame.is_fivem_related else ''
                            lines.append(f"  {num:3d}: {mod}!{func}{fivem_marker}")
                        else:
                            # Dict format
                            num = frame.get('frame_number', 0)
                            mod = frame.get('module', '?')
                            func = frame.get('function', '?')
                            fivem_marker = ' [FIVEM]' if frame.get('is_fivem_related') else ''
                            lines.append(f"  {num:3d}: {mod}!{func}{fivem_marker}")
                    
                    if len(frames) > 20:
                        lines.append(f"  ... and {len(frames) - 20} more frames")
                
                # FiveM modules
                fivem_mods = wd.get('fivem_modules', [])
                if fivem_mods:
                    lines.append(f"\nFiveM Modules Found: {len(fivem_mods)}")
                    lines.append("-" * 40)
                    for mod in fivem_mods[:10]:
                        lines.append(f"  - {mod}")
                    if len(fivem_mods) > 10:
                        lines.append(f"  ... and {len(fivem_mods) - 10} more")
            else:
                error = wd.get('error', 'Unknown error')
                lines.append(f"⚠ WinDbg analysis failed: {error}")
            
            lines.append("")
            lines.append("=" * 60)
            lines.append("")

        # Thread information - show only essential threads
        if report.threads_extended:
            lines.append("THREADS AT CRASH TIME:")
            lines.append("-" * 40)
            
            # Identify crashing thread and a few other active threads
            crashing_tid = None
            if report.exception_context and 'thread_id' in report.exception_context:
                crashing_tid = report.exception_context['thread_id']
            
            # Sort: crashing thread first, then by stack size (larger = more active)
            sorted_threads = sorted(
                report.threads_extended,
                key=lambda t: (
                    t.thread_id != crashing_tid,  # Crashing thread first (False sorts before True)
                    -((t.stack_limit - t.stack_base) if t.stack_limit else 0)  # Then by stack size
                )
            )
            
            # Display top threads with better formatting
            displayed = 0
            for t in sorted_threads:
                if displayed >= 15:  # Reduced from 30
                    break
                
                thread_summary = self._format_thread_info(t)
                if t.thread_id == crashing_tid:
                    lines.append(f"  ⚠ CRASHING THREAD: {thread_summary}")
                else:
                    lines.append(f"  {thread_summary}")
                
                # Add stack info if available
                if t.stack_base and t.stack_limit:
                    size = (t.stack_limit - t.stack_base)
                    lines.append(f"      Stack: 0x{t.stack_base:016X} ({size:,} bytes)")
                
                displayed += 1
            
            remaining = len(report.threads_extended) - displayed
            if remaining > 0:
                lines.append(f"  ... and {remaining} more threads (use full dump analysis for details)")
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
                lines.append("🎯 SUSPECTED RESOURCES (correlate with frames below):")
                lines.append("  " + ", ".join(resources_for_stack))
                lines.append("")
            
            # How to use this section
            lines.append("📊 HOW TO READ THIS STACK:")
            lines.append("  1. [NN] = Frame number (lower = closer to crash)")
            lines.append("  2. Exception address = exact instruction that faulted")
            lines.append("  3. With PDBs: Shows module + 0xOFFSET → function_name + 0xDISP")
            lines.append("  4. Correlate frame functions with suspected resources above")
            lines.append("")
            
            sym = getattr(report, 'native_stacks_symbolicated', None)
            has_symbolication = sym and any("  ->  " in f for f in sym)
            
            if not has_symbolication and report.native_stacks:
                if getattr(report, 'module_versions', None):
                    lines.append("  ⚠️  Symbols not available (PDB not found on FiveM symbol server)")
                    lines.append("      Showing module+offset only. For better debugging:")
                    lines.append("      • Enable symbol download in settings")
                    lines.append("      • Check internet connection")
                    diag = getattr(report, 'symbolication_diagnostic', None)
                    if diag:
                        lines.append("")
                        lines.append("      Diagnostic: " + diag)
                else:
                    lines.append("  ⚠️  Symbols not loaded (PDB download failed or module info missing)")
                lines.append("")
            elif has_symbolication:
                lines.append("  ✓ Symbols loaded - use function names below to find crashing resource")
                lines.append("")
            
            # Display the actual stack frames with enhanced formatting
            display_frames = sym if (sym and len(sym) == len(report.native_stacks)) else report.native_stacks
            
            # Limit to top 30 most relevant frames
            max_frames = 30
            frames_to_show = display_frames[:max_frames] if len(display_frames) > max_frames else display_frames
            
            for idx, frame in enumerate(frames_to_show, 1):
                if not frame or not frame.strip():
                    continue
                formatted_frame = self._format_native_stack_frame(frame, idx, len(frames_to_show))
                lines.append(f"  {formatted_frame}")
            
            if len(display_frames) > max_frames:
                lines.append(f"\n  ... and {len(display_frames) - max_frames} more frames (not displayed)")
            
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
        os.path.join(os.path.dirname(script_dir), 'assets', 'icon.ico'),
        os.path.join(os.path.dirname(script_dir), 'assets', 'icon.png'),
        os.path.join(script_dir, 'icon.ico'),
        os.path.join(script_dir, 'icon.png'),
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

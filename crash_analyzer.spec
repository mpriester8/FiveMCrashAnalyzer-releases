# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec file for FiveM Crash Analyzer
Compiles the GUI into a standalone Windows executable
"""

block_cipher = None

a = Analysis(
    ['crash_analyzer\\analyzer.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('crash_analyzer\\*.py', 'crash_analyzer'),
        ('assets\\*', 'assets'),  # Include icons if they exist
    ],
    hiddenimports=[
        'PySide6.QtCore',
        'PySide6.QtGui',
        'PySide6.QtWidgets',
        'crash_analyzer.core',
        'crash_analyzer.dump_extractor',
        'crash_analyzer.memory_analyzer',
        'crash_analyzer.symbol_resolver',
        'crash_analyzer.fivem_forensics',
        'crash_analyzer.heap_analyzer',
        'crash_analyzer.dump_enricher',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'matplotlib',
        'numpy',
        'scipy',
        'pandas',
        'IPython',
        'jupyter',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='FiveM Crash Analyzer',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # NO CONSOLE WINDOW
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='assets\\icon.ico' if os.path.exists('assets\\icon.ico') else None,
)

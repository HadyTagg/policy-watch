# -*- mode: python ; coding: utf-8 -*-

from PyInstaller.utils.hooks import collect_all, collect_submodules

block_cipher = None

pyside6 = collect_all("PySide6")
win32com_submodules = collect_submodules("win32com")


analysis = Analysis(
    ["main.py"],
    pathex=["."],
    binaries=pyside6.binaries,
    datas=pyside6.datas,
    hiddenimports=["pyodbc", *pyside6.hiddenimports, *win32com_submodules],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(analysis.pure, analysis.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    analysis.scripts,
    analysis.binaries,
    analysis.zipfiles,
    analysis.datas,
    [],
    name="PolicyWatch",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
)

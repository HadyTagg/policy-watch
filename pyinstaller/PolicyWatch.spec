# -*- mode: python ; coding: utf-8 -*-

from PyInstaller.utils.hooks import (
    collect_all,
    collect_data_files,
    collect_dynamic_libs,
    collect_submodules,
)

block_cipher = None

pyside6_datas, pyside6_binaries, pyside6_hiddenimports = collect_all("PySide6")
pyside6_dynamic_libs = collect_dynamic_libs("PySide6")
pyside6_plugins = collect_data_files("PySide6", subdir="Qt/plugins")
pyside6_qml = collect_data_files("PySide6", subdir="Qt/qml")
win32com_submodules = collect_submodules("win32com")
policywatch_hiddenimports = collect_submodules("policywatch")
policywatch_datas = collect_data_files("policywatch")


analysis = Analysis(
    ["main.py"],
    pathex=[".", "src"],
    binaries=[*pyside6_binaries, *pyside6_dynamic_libs],
    datas=[*pyside6_datas, *pyside6_plugins, *pyside6_qml, *policywatch_datas],
    hiddenimports=[
        "pyodbc",
        *pyside6_hiddenimports,
        *win32com_submodules,
        *policywatch_hiddenimports,
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    include_msvcr=True,
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

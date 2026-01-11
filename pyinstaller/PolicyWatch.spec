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
pyside6_bins = collect_data_files("PySide6", subdir="Qt/bin")
pyside6_translations = collect_data_files("PySide6", subdir="Qt/translations")
pyside6_resources = collect_data_files("PySide6", subdir="Qt/resources")
shiboken6_dynamic_libs = collect_dynamic_libs("shiboken6")
shiboken6_datas = collect_data_files("shiboken6")
win32com_submodules = collect_submodules("win32com")
policywatch_hiddenimports = collect_submodules("policywatch")
policywatch_datas = collect_data_files("policywatch")


analysis = Analysis(
    ["main.py"],
    pathex=[".", "src"],
    binaries=[*pyside6_binaries, *pyside6_dynamic_libs, *shiboken6_dynamic_libs],
    datas=[
        *pyside6_datas,
        *pyside6_plugins,
        *pyside6_qml,
        *pyside6_bins,
        *pyside6_translations,
        *pyside6_resources,
        *shiboken6_datas,
        *policywatch_datas,
    ],
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

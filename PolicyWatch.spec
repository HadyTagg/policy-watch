# -*- mode: python ; coding: utf-8 -*-

from PyInstaller.utils.hooks import (
    collect_all,
    collect_data_files,
    collect_dynamic_libs,
    collect_submodules,
)

block_cipher = None

pyqt5_datas, pyqt5_binaries, pyqt5_hiddenimports = collect_all("PyQt5")
pyqt5_dynamic_libs = collect_dynamic_libs("PyQt5")
pyqt5_plugins = collect_data_files("PyQt5", subdir="Qt5/plugins")
pyqt5_qml = collect_data_files("PyQt5", subdir="Qt5/qml")
pyqt5_bins = collect_data_files("PyQt5", subdir="Qt5/bin")
pyqt5_translations = collect_data_files("PyQt5", subdir="Qt5/translations")
pyqt5_resources = collect_data_files("PyQt5", subdir="Qt5/resources")
win32com_submodules = collect_submodules("win32com")
policywatch_hiddenimports = collect_submodules("policywatch")
policywatch_datas = collect_data_files("policywatch")


analysis = Analysis(
    ["src/policywatch/__main__.py"],
    pathex=[".", "src"],
    binaries=[*pyqt5_binaries, *pyqt5_dynamic_libs],
    datas=[
        *pyqt5_datas,
        *pyqt5_plugins,
        *pyqt5_qml,
        *pyqt5_bins,
        *pyqt5_translations,
        *pyqt5_resources,
        *policywatch_datas,
    ],
    hiddenimports=[
        *pyqt5_hiddenimports,
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

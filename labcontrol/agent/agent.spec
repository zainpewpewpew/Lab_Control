# PyInstaller spec for CadenceSec agent. Produces a single `agent.exe`.
# Build (on Windows, Python 3.11 x64):
#   python -m pip install pyinstaller==6.10.0
#   pyinstaller agent.spec --noconfirm
# Output: dist\agent.exe

# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_submodules

hidden = (
    collect_submodules('cryptography')
    + collect_submodules('cryptography.hazmat.primitives.asymmetric')
    + collect_submodules('cryptography.hazmat.backends.openssl')
    + collect_submodules('httpx')
    + collect_submodules('httpcore')
    + collect_submodules('psutil')
)

a = Analysis(
    ['agent.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=hidden,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'tkinter', 'unittest', 'pydoc', 'test', 'doctest', 'xmlrpc',
        'lib2to3', 'IPython', 'notebook', 'matplotlib', 'numpy',
    ],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='agent',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=False,
    manifest=None,
    version=None,
)

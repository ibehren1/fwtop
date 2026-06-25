import os
import importlib

from PyInstaller.utils.hooks import copy_metadata

# Locate installed package paths for data file collection
textual_path = os.path.dirname(importlib.import_module("textual").__file__)
textual_plotext_path = os.path.dirname(importlib.import_module("textual_plotext").__file__)
fwtop_path = os.path.dirname(importlib.import_module("fwtop").__file__)

a = Analysis(
    ["src/fwtop/__main__.py"],
    pathex=[],
    binaries=[],
    datas=[
        # Textual ships CSS and default themes that must be bundled
        (textual_path, "textual"),
        (textual_plotext_path, "textual_plotext"),
        # Our own .tcss stylesheet
        (os.path.join(fwtop_path, "fwtop.tcss"), "fwtop"),
        # Bundle package metadata so importlib.metadata can read __version__
        *copy_metadata("fwtop"),
    ],
    hiddenimports=[
        "fwtop",
        "fwtop.app",
        "fwtop.collector",
        "fwtop.config",
        "fwtop.models",
        "fwtop.stats",
        "fwtop.resolve",
        "fwtop.sources",
        "fwtop.sources.interfaces",
        "fwtop.sources.conntrack",
        "fwtop.sources.firewall",
        "fwtop.sources.demo",
        "fwtop.widgets",
        "fwtop.widgets.summary_panel",
        "fwtop.widgets.throughput_chart",
        "fwtop.widgets.drops_heatmap",
        "fwtop.widgets.interface_table",
        "fwtop.widgets.conntrack_panel",
        "fwtop.widgets.connections_table",
        "fwtop.widgets.firewall_panel",
        "fwtop.widgets.cpu_panel",
        "psutil",
        "textual",
        "textual_plotext",
        "plotext",
        "dns",
        "dns.resolver",
        "dns.reversename",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="fwtop",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    target_arch=None,
)

"""Headless bootstrap: inject a wx stub and initialize PixelFlasher runtime without GUI."""
from __future__ import annotations

import os
import sys
import types
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from config import Config
    from phone import Device


def _install_wx_stub() -> None:
    """Inject a fake wx module into sys.modules before any PixelFlasher import.

    The stub is idempotent: if real wx is already loaded, it is left untouched so
    the plugin can coexist with a running GUI process.
    """
    if "wx" in sys.modules and not getattr(sys.modules["wx"], "_pf_stub", False):
        return  # Real wx already loaded (GUI mode) — don't interfere.

    class _ChainStub:
        """Returns itself for any attribute access or call."""

        def __getattr__(self, name: str) -> object:
            return self

        def __call__(self, *args: object, **kwargs: object) -> object:
            return self

    class _StubWxBase:
        """Generic stand-in for wx classes used as bases or instantiated."""

        def __init__(self, *args: object, **kwargs: object) -> None:
            pass

        def __getattr__(self, name: str) -> object:
            return _ChainStub()

    class _StubSizer(_StubWxBase):
        def Add(self, *a: object, **kw: object) -> object:
            return self

        def AddButton(self, *a: object, **kw: object) -> object:
            return self

        def Realize(self, *a: object, **kw: object) -> object:
            return self

    class _StubListCtrl(_StubWxBase):
        def AppendColumn(self, *a: object, **kw: object) -> int:
            return 0

        def InsertItem(self, *a: object, **kw: object) -> int:
            return 0

        def GetFirstSelected(self, *a: object, **kw: object) -> int:
            return -1

    class _StubDisplay(_StubWxBase):
        def GetGeometry(self) -> object:
            class _Size:
                width = 1920
                height = 1080

                def GetSize(self) -> object:
                    return self

            return _Size()

    _stub_cache: dict[str, type] = {}

    def _make_stub_class(name: str) -> type:
        # Create (or reuse) a _StubWxBase subclass for any unstubbed wx attribute.
        # It's instantiable, callable, and usable as a base class, so module-scope
        # inheritance like `class Foo(wx.Panel):` doesn't raise TypeError.
        if name not in _stub_cache:
            cls = type(name, (_StubWxBase,), {})
            _stub_cache[name] = cls
        return _stub_cache[name]

    class _WxStub(types.ModuleType):
        """Module subclass that provides a catch-all __getattr__ fallback."""

        def __getattr__(self, name: str) -> object:
            return _make_stub_class(name)

    stub = _WxStub("wx")
    stub._pf_stub = True

    # No-op event-loop functions.
    stub.Yield = lambda *a, **kw: None
    stub.YieldIfNeeded = lambda *a, **kw: None
    stub.CallAfter = lambda fn, *a, **kw: None
    stub.SafeYield = lambda *a, **kw: None
    stub.SafeYieldIfNeeded = lambda *a, **kw: None
    stub.Bell = lambda *a, **kw: None
    stub.GetApp = lambda: _StubApp()

    # Dialog functions — return affirmative defaults so code paths proceed.
    stub.MessageBox = lambda *a, **kw: stub.ID_YES
    stub.MessageDialog = lambda *a, **kw: _StubDialog()

    # GUI classes referenced at import time by ksu_asset_selector.py.
    stub.Dialog = _StubWxBase
    stub.BoxSizer = _StubSizer
    stub.StaticText = _StubWxBase
    stub.SearchCtrl = _StubWxBase
    stub.ListCtrl = _StubListCtrl
    stub.StdDialogButtonSizer = _StubSizer
    stub.Button = _StubWxBase
    stub.Display = _StubDisplay

    # Flag constants used for bitwise OR in source.
    stub.YES = 1
    stub.NO = 2
    stub.YES_NO = 3
    stub.OK = 4
    stub.CANCEL = 8
    stub.ID_YES = 5103
    stub.ID_NO = 5104
    stub.ID_OK = 5100
    stub.ID_CANCEL = 5101
    stub.ICON_ERROR = 16
    stub.ICON_QUESTION = 32
    stub.ICON_EXCLAMATION = 48
    stub.ICON_INFORMATION = 64
    stub.BOTH = 0
    stub.VERTICAL = 0
    stub.HORIZONTAL = 0
    stub.DEFAULT_DIALOG_STYLE = 0
    stub.RESIZE_BORDER = 0
    stub.ALL = 0
    stub.EXPAND = 0
    stub.ALIGN_CENTER_VERTICAL = 0
    stub.RIGHT = 0
    stub.LEFT = 0
    stub.BOTTOM = 0
    stub.TE_PROCESS_ENTER = 0
    stub.LC_REPORT = 0
    stub.LC_SINGLE_SEL = 0
    stub.EVT_CLOSE = 0
    stub.EVT_BUTTON = 0
    stub.EVT_LIST_ITEM_ACTIVATED = 0
    stub.EVT_TEXT = 0
    stub.EVT_TEXT_ENTER = 0
    stub.EVT_SEARCHCTRL_CANCEL_BTN = 0

    sys.modules["wx"] = stub


class _StubDialog:
    """Stand-in for wx.MessageDialog / wx.SingleChoiceDialog."""

    def ShowModal(self) -> int:
        return sys.modules["wx"].ID_YES

    def CentreOnParent(self, *a: object, **kw: object) -> None:
        pass

    def SetSize(self, *a: object, **kw: object) -> None:
        pass

    def Destroy(self) -> None:
        pass


class _StubApp:
    def Yield(self) -> None:
        pass


# ── Step 1: Install wx stub BEFORE any PixelFlasher import ───────────────────
_install_wx_stub()

# ── Step 2: Import runtime (triggers runtime.py module-level init) ────────────
import runtime  # noqa: E402

# ── Step 3: Disable puml (PlantUML logging) ──────────────────────────────────
runtime.set_puml_state(False)
runtime.puml = lambda message="", left_ts=False, mode="a": None  # type: ignore[assignment]

# ── Step 4: Set headless-safe globals ────────────────────────────────────────
runtime.set_window_shown(False)
if hasattr(runtime, "set_console_widget"):
    runtime.set_console_widget(None)

# ── Step 5: run_shell2 / run_shell3 decision ─────────────────────────────────
# run_shell2 callers in phone.py (lines 1261, 1526, 5212) inspect .returncode and
# .stdout, which CompletedProcess provides. run_shell3 is used for detached GUI
# apps (scrcpy) and returns a Popen in normal operation. With wx stubbed,
# wx.YieldIfNeeded is already a no-op, so run_shell2/3 execute without GUI
# pumping. Redirecting run_shell3 to run_shell would change its return type from
# Popen to CompletedProcess and could block on detached processes. Therefore we
# leave run_shell2 and run_shell3 untouched; the stub makes them safe enough for
# headless use, and callers that need streaming behavior keep working.

# ── Step 6-7: Standalone helpers for platform tools and config ──────────────
def configure_platform_tools(adb_path: str, fastboot_path: str) -> None:
    """Set the ADB and fastboot binary paths in runtime globals."""
    runtime.set_adb(adb_path)
    runtime.set_fastboot(fastboot_path)


def load_config(config_path: str | None = None) -> "Config":
    """Load or create a PixelFlasher Config and register it with runtime."""
    from config import Config

    cfg = Config()
    if config_path and os.path.exists(config_path):
        cfg.load(config_path)
    runtime.set_config(cfg)
    runtime.set_config_path(os.path.dirname(config_path) if config_path else os.getcwd())
    return cfg


# ── Step 8: Import phone (now safe — runtime fully initialized) ─────────────
from phone import Backup, Device, DeviceProps, Magisk, Package, Vbmeta  # noqa: E402


def bootstrap(
    adb_path: str,
    fastboot_path: str,
    config_path: str | None = None,
) -> tuple[types.ModuleType, "Config"]:
    """Complete headless initialization.

    Returns (runtime_module, config_instance).
    """
    # The wx stub and runtime import happen at module load time; this function
    # completes the remaining runtime configuration steps.
    configure_platform_tools(adb_path, fastboot_path)
    cfg = load_config(config_path)
    return runtime, cfg


def get_device(device_id: str, mode: str = "adb") -> "Device":
    """Construct a Device instance for the given device ID.

    The default mode is 'adb'. Callers that know the device is in fastboot or
    another mode should pass it explicitly.
    """
    return Device(id=device_id, mode=mode)


# Re-export headless-safe runtime symbols.
run_shell = runtime.run_shell

__all__ = [
    "runtime",
    "Device",
    "Package",
    "Backup",
    "Vbmeta",
    "Magisk",
    "DeviceProps",
    "run_shell",
    "configure_platform_tools",
    "load_config",
    "bootstrap",
    "get_device",
]

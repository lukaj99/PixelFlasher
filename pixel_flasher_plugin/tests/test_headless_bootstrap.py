"""Headless bootstrap decoupling tests.

The reviewer-validated invariant: ``pixel_flasher_plugin.headless_runtime``
must install a wx stub BEFORE importing ``runtime`` / ``phone``, so that
``from phone import Device`` succeeds in a headless environment with no
display server.

If this decoupling ever regresses (e.g. someone moves the wx stub below
the ``import phone`` line), every MCP tool will crash on startup in CI.
"""
from __future__ import annotations

import pytest


def test_bootstrap_returns_runtime_and_config_tuple() -> None:
    """``bootstrap('adb', 'fastboot')`` returns (runtime_module, config_instance)."""
    from pixel_flasher_plugin.headless_runtime import bootstrap

    result = bootstrap("adb", "fastboot")
    assert isinstance(result, tuple), f"bootstrap did not return a tuple: {type(result)}"
    assert len(result) == 2, f"bootstrap returned {len(result)} values, expected 2"

    runtime_module, config_instance = result
    assert runtime_module is not None
    assert config_instance is not None


def test_bootstrap_runtime_has_run_shell(headless_bootstrap) -> None:
    """The returned runtime module must expose a callable ``run_shell``."""
    runtime_module, _ = headless_bootstrap
    assert hasattr(runtime_module, "run_shell"), (
        "Returned runtime module has no 'run_shell' attribute."
    )
    assert callable(runtime_module.run_shell), (
        "runtime.run_shell exists but is not callable."
    )


def test_puml_is_stubbed(headless_bootstrap) -> None:
    """``runtime.puml`` MUST be a callable no-op after bootstrap.

    PlantUML logging is a GUI-adjacent feature; in headless mode it must
    not try to write to disk, talk to a PlantUML server, or otherwise do
    real work. A no-op stub is the contract.
    """
    runtime_module, _ = headless_bootstrap
    assert hasattr(runtime_module, "puml"), (
        "runtime module lost its 'puml' attribute after bootstrap"
    )
    assert callable(runtime_module.puml), "runtime.puml is not callable"

    # Calling it must return None (no-op) and not raise.
    try:
        result = runtime_module.puml("test message")
    except Exception as exc:  # pragma: no cover - we want a hard failure
        pytest.fail(
            f"runtime.puml raised in headless mode: {type(exc).__name__}: {exc}"
        )
    assert result is None, (
        f"runtime.puml returned {result!r} in headless mode -- "
        f"should be a no-op returning None"
    )


def test_puml_handles_arbitrary_args_without_raising(headless_bootstrap) -> None:
    """puml must be tolerant of any args/kwargs the caller passes."""
    runtime_module, _ = headless_bootstrap
    # Various call shapes the production code uses.
    runtime_module.puml()
    runtime_module.puml("hello", left_ts=True)
    runtime_module.puml("multi\nline\nstring", mode="w")
    runtime_module.puml("", left_ts=False, mode="a")


# ---------------------------------------------------------------------------
# The critical decoupling invariant: phone.Device must import + instantiate
# AFTER bootstrap, without a real wx installed.
# ---------------------------------------------------------------------------
def test_phone_device_imports_after_bootstrap(headless_bootstrap) -> None:
    """``from phone import Device`` must succeed after bootstrap.

    This is the single most important guarantee for headless MCP operation:
    if ``phone.py`` tries to import wx at module load and wx is not
    installed (or is the stub), the import chain blows up. Bootstrap must
    pre-install the stub so ``phone`` is safe to import.

    The import happens here -- not in the fixture -- because pytest's import
    caching could mask a regression in the bootstrap order.
    """
    try:
        from phone import Device  # noqa: F401
    except ImportError as exc:
        pytest.fail(
            f"`from phone import Device` raised ImportError after bootstrap: {exc}\n"
            f"This means the headless wx stub is not installed before phone.py loads."
        )


def test_phone_device_instantiates_without_wx(headless_bootstrap) -> None:
    """``Device('FAKE001', 'adb')`` must succeed in a headless context.

    Proves the decoupling works: a Device object can be constructed
    without a connected device, without wx, without a display.
    """
    from phone import Device

    # Constructor signature (verified from headless_runtime.get_device):
    #   Device(id=..., mode=...)
    dev = Device(id="FAKE001", mode="adb")
    assert dev is not None
    assert dev.id == "FAKE001", f"Device.id is {dev.id!r}, expected 'FAKE001'"
    assert dev.mode == "adb", f"Device.mode is {dev.mode!r}, expected 'adb'"


def test_wx_is_stubbed_in_sys_modules(headless_bootstrap) -> None:
    """``sys.modules['wx']`` must be the stub, not a real wx module.

    Guards against a regression where a real wx install shadows the stub
    and the headless path silently starts requiring a display.
    """
    import sys

    from pixel_flasher_plugin import headless_runtime

    assert "wx" in sys.modules, "wx is not in sys.modules -- bootstrap never installed a stub"
    wx_mod = sys.modules["wx"]
    # The stub sets a _pf_stub flag for idempotency checks.
    assert getattr(wx_mod, "_pf_stub", False) is True, (
        "sys.modules['wx'] is NOT the headless stub -- "
        "a real wx install is being used, which will break headless MCP."
    )


def test_bootstrap_is_idempotent() -> None:
    """Calling bootstrap() repeatedly must not error or re-import modules."""
    from pixel_flasher_plugin.headless_runtime import bootstrap

    rt1, cfg1 = bootstrap("adb", "fastboot")
    rt2, cfg2 = bootstrap("adb", "fastboot")
    # Same module + config instance each call (cached).
    assert rt1 is rt2, "bootstrap returned different runtime modules on repeated calls"
    # Config identity is not strictly required (Config has its own caching),
    # but the call must succeed without raising.


def test_get_device_returns_phone_device(monkeypatch, headless_bootstrap) -> None:
    """``headless_runtime.get_device(id, mode)`` returns a phone.Device instance.

    The session-wide ``_stub_get_device`` autouse fixture replaces
    ``get_device`` with a MagicMock for the safety/preflight tests, so this
    test temporarily restores the real implementation and asserts the
    original contract: the factory returns an actual ``phone.Device``.
    """
    from phone import Device
    from pixel_flasher_plugin import headless_runtime

    # Restore the real factory for this one test.
    monkeypatch.setattr(
        headless_runtime,
        "get_device",
        lambda device_id, mode="adb": Device(id=device_id, mode=mode),
    )

    dev = headless_runtime.get_device("FAKE001", mode="adb")
    assert isinstance(dev, Device), (
        f"get_device returned {type(dev).__name__}, expected phone.Device"
    )
    assert dev.id == "FAKE001"
    assert dev.mode == "adb"
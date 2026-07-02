"""Shared pytest configuration for pixel_flasher_plugin tests.

This conftest is the earliest point pytest imports before test collection,
which is the only safe place to seed environment variables that downstream
modules (runtime, protobuf, headless_runtime) need before they are imported.

It also installs a session-scoped autouse fixture that stubs out
``headless_runtime.get_device`` so that SafetyGateway pre-flight checks and
DeviceOps never try to talk to a real adb/fastboot binary. Without this
stub, ``_check_oem_unlock_ability`` would call ``fastboot -s <id> ...`` and
block for the 60s ``run_shell`` timeout on a non-existent device.
"""
from __future__ import annotations

import os
import sys
import types
from unittest.mock import MagicMock

# PROTOBUF PURE-PYTHON: must be set BEFORE any import chain that reaches
# runtime.py / config.py (which is reached transitively from
# pixel_flasher_plugin.* -> headless_runtime -> runtime).  The pure-python
# implementation avoids the C++ descriptor pool that segfaults on this Python
# 3.14 build when the generated update_metadata_pb2 is imported.
os.environ.setdefault("PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION", "python")

# Ensure the project root is on sys.path so ``import constants``,
# ``from phone import Device`` etc. resolve when pytest is invoked from
# any working directory.
_PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)


# ---------------------------------------------------------------------------
# Session-scoped fixtures
# ---------------------------------------------------------------------------
import pytest  # noqa: E402  (after env seeding)


def _make_fake_device() -> MagicMock:
    """Build a MagicMock that quacks like ``phone.Device`` for tests.

    The values returned for ``is_connected`` / ``unlocked`` / battery / props
    are intentionally "not connected, locked, no battery info" so that
    pre-flight checks return a deterministic, fast result without any
    subprocess I/O.
    """
    device = MagicMock(name="fake_phone_Device")
    # Identity / mode
    device.id = "FAKE001"
    device.mode = "adb"
    device.true_mode = "adb"
    # Connection / state
    device.is_connected.return_value = False
    device.get_device_state.return_value = "ERROR"
    # Properties
    device.unlocked = False
    device.unlock_ability = "UNKNOWN"
    device.get_unlock_ability.return_value = None
    # Battery / props
    device.get_battery_details.return_value = ""
    device.get_prop.return_value = ""
    # Misc
    device.install_apk.return_value = 0
    device.active_slot = ""
    device.inactive_slot = ""
    return device


@pytest.fixture(scope="session", autouse=True)
def _stub_get_device():
    """Replace ``headless_runtime.get_device`` with a fast stub.

    Affects every test in this directory automatically. Patches the symbol
    in both ``headless_runtime`` (where it is defined) and
    ``pixel_flasher_plugin.safety_engine`` (which imports it by name).
    """
    fake = _make_fake_device()

    # Import lazily so the env-var seeding above is in effect.
    from pixel_flasher_plugin import headless_runtime
    from pixel_flasher_plugin import safety_engine

    original = headless_runtime.get_device
    headless_runtime.get_device = lambda device_id, mode="adb": fake  # type: ignore[assignment]
    # safety_engine does ``from pixel_flasher_plugin import headless_runtime``
    # then calls ``headless_runtime.get_device(...)`` so the same module
    # reference is patched. The dispatcher also references it via
    # ``self._get_device`` which uses the same import.
    safety_engine.headless_runtime.get_device = headless_runtime.get_device  # type: ignore[attr-defined]
    try:
        yield fake
    finally:
        headless_runtime.get_device = original  # type: ignore[assignment]
        safety_engine.headless_runtime.get_device = original  # type: ignore[attr-defined]


@pytest.fixture(scope="session")
def project_root() -> str:
    """Absolute path to the PixelFlasher project root."""
    return _PROJECT_ROOT


@pytest.fixture(scope="session")
def headless_bootstrap():
    """Run the headless bootstrap once per session.

    Returns the (runtime_module, config_instance) tuple from
    pixel_flasher_plugin.headless_runtime.bootstrap().
    """
    from pixel_flasher_plugin.headless_runtime import bootstrap

    return bootstrap("adb", "fastboot")


@pytest.fixture(scope="session")
def mcp_server_module():
    """Import pixel_flasher_plugin.mcp_server once per session.

    Importing this module registers all 28 tools and triggers the
    ``import pixel_flasher_plugin.mcp_resources`` at the bottom of
    mcp_server.py, which adds 7 resources.
    """
    import pixel_flasher_plugin.mcp_server as mcp_server

    return mcp_server

"""Regression tests for shell command-injection hardening in mcp_server.

Every tool interpolates ``device_id`` into an ``adb -s <id> ...`` string that
is ultimately executed through a shell=True subprocess. A crafted device_id,
package_name, or state must not be able to smuggle shell metacharacters into
that command. These tests pin:

  * _ops() rejects any device_id that isn't a plain ADB serial / ip:port.
  * package_name is shlex-quoted (injection payloads become inert literals)
    while legitimate package names still pass the command whitelist.
  * wait_for_device rejects a non-charset state.
"""
from __future__ import annotations

import types
from unittest.mock import MagicMock

import pytest

pytest.importorskip("mcp")  # server module imports FastMCP

from pixel_flasher_plugin import mcp_server
from pixel_flasher_plugin.command_validator import CommandValidator


def _fake_ctx(ops: MagicMock) -> types.SimpleNamespace:
    """Minimal Context stand-in exposing the lifespan device_ops singleton."""
    lifespan = types.SimpleNamespace(device_ops=ops, gateway=MagicMock())
    return types.SimpleNamespace(
        request_context=types.SimpleNamespace(lifespan_context=lifespan)
    )


# ---------------------------------------------------------------------------
# device_id validation (the vector shared by every tool)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "device_id",
    ["100.123.230.67:5555", "emulator-5554", "1A2B3C4D", "ABC.def-01:5555"],
)
def test_ops_accepts_real_device_ids(device_id: str) -> None:
    ops = MagicMock()
    ops.device_id = None
    ctx = _fake_ctx(ops)
    assert mcp_server._ops(device_id, ctx) is ops


@pytest.mark.parametrize(
    "device_id",
    ["x;reboot", "$(reboot)", "a|reboot", "`reboot`", "a b", "dev && rm -rf /", ""],
)
def test_ops_rejects_injection_device_ids(device_id: str) -> None:
    ops = MagicMock()
    ctx = _fake_ctx(ops)
    with pytest.raises(ValueError):
        mcp_server._ops(device_id, ctx)


# ---------------------------------------------------------------------------
# package_name is neutralised (shlex-quoted) yet still whitelist-valid
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "tool_name",
    ["uninstall_package", "enable_package", "disable_package"],
)
@pytest.mark.parametrize(
    "payload",
    ["com.foo", "com.foo;reboot", "$(reboot)", "a|reboot", "`reboot`"],
)
def test_package_name_is_quoted_and_inert(tool_name: str, payload: str) -> None:
    captured: dict[str, str] = {}

    ops = MagicMock()
    ops.device_id = "DEV"

    def fake_run_shell(command, confirm=False, timeout=None):
        captured["command"] = command
        return MagicMock(success=True, data={}, error=None)

    ops.run_shell = MagicMock(side_effect=fake_run_shell)
    ctx = _fake_ctx(ops)

    tool = getattr(mcp_server, tool_name)
    tool(ctx, "DEV", payload, dry_run=True)

    command = captured["command"]
    # The payload must appear only inside single quotes -- a bare metachar
    # sequence (unquoted) would mean the shell could execute it.
    if payload != "com.foo":
        assert f"'{payload}'" in command or "'" in command
        assert f" {payload}" not in command  # never interpolated bare
    # And the resulting command still passes the structural whitelist.
    allowed, reason = CommandValidator.is_allowed(command)
    assert allowed, f"{command!r} rejected: {reason}"


# ---------------------------------------------------------------------------
# wait_for_device state validation
# ---------------------------------------------------------------------------
def test_wait_for_device_rejects_bad_state() -> None:
    ops = MagicMock()
    ops.device_id = "DEV"
    ops.run_shell = MagicMock()
    ctx = _fake_ctx(ops)

    result = mcp_server.wait_for_device(ctx, "DEV", state="x;reboot")
    assert not result.success
    ops.run_shell.assert_not_called()

"""Tests for keybox.xml management tools.

Covers ``DeviceOps.get_keybox_status`` and ``DeviceOps.update_keybox`` with a
mocked ``phone.Device`` so no real adb/fastboot interaction happens.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from pixel_flasher_plugin.command_validator import CommandValidator
from pixel_flasher_plugin.device_ops import DeviceOps
from pixel_flasher_plugin.safety_engine import Decision


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _make_ops():
    """Return a DeviceOps instance with a mocked gateway and device."""
    gateway = MagicMock()
    gateway.evaluate.return_value = (Decision.ALLOW, "")
    gateway.run_preflight.return_value = []

    ops = DeviceOps(device_id="FAKE001", gateway=gateway)
    device = MagicMock()
    device.rooted = True
    device.su_version = "Magisk"
    device.true_mode = "adb"

    # Default primitive return codes.
    device.check_file.return_value = (0, None)
    device.pull_file.return_value = 0
    device.push_file.return_value = 0

    ops._device = device
    return ops, device, gateway


# Minimal keybox XML that passes local validation.
_VALID_KEYBOX_XML = """<AndroidAttestation>
<NumberOfCertificates>1</NumberOfCertificates>
<DeviceCertificate>-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHBfpegPjMCMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBmZha2VzMB4X
DTI0MDEwMTAwMDAwMFoXDTI1MDEwMTAwMDAwMFowETEPMA0GA1UEAwwGZmFrZXMwXDANBgkq
hkiG9w0BAQEFAANLADBIAkEA0FakeKeyForTestingOnly0FakeKeyForTestingOnly0FakeKeyFor
TestingOnly0FakeKeyForTestingOnly0FakeKeyForTestingOnly0FakeKeyForTesting=
-----END CERTIFICATE-----</DeviceCertificate>
</AndroidAttestation>"""


def _mock_check_kb(revoked: bool):
    """Return a check_kb result string for the given revocation state."""
    if revoked:
        return "Certificate serial 1234567890ABCDEF is REVOKED: compromised key"
    return "Certificate serial 1234567890ABCDEF is valid (not on CRL)"


# ---------------------------------------------------------------------------
# get_keybox_status
# ---------------------------------------------------------------------------
def test_get_keybox_status_exists_not_revoked(monkeypatch) -> None:
    """get_keybox_status reports exists=True and revoked=False."""
    ops, device, _ = _make_ops()
    device.check_file.return_value = (1, None)
    device.pull_file.return_value = 0

    monkeypatch.setattr(
        "pixel_flasher_plugin.device_ops._runtime.check_kb",
        lambda path: _mock_check_kb(False),
    )
    monkeypatch.setattr(
        DeviceOps,
        "_parse_keybox_cert",
        lambda self, path: ("1234567890abcdef", "2025-01-01 00:00:00 UTC"),
    )

    result = ops.get_keybox_status()

    assert result.success is True
    data = result.data or {}
    assert data["exists"] is True
    assert data["revoked"] is False
    assert data["revoked_reason"] is None
    assert data["certificate_serial"] == "1234567890abcdef"
    assert data["expiry_date"] == "2025-01-01 00:00:00 UTC"
    assert "valid" in data["raw_check_kb_result"]
    device.pull_file.assert_called_once()


def test_get_keybox_status_missing() -> None:
    """get_keybox_status reports exists=False when keybox.xml is absent."""
    ops, device, _ = _make_ops()
    device.check_file.return_value = (0, None)

    result = ops.get_keybox_status()

    assert result.success is True
    data = result.data or {}
    assert data["exists"] is False
    assert data["revoked"] is None
    assert data["revoked_reason"] is None
    assert data["certificate_serial"] is None
    assert data["expiry_date"] is None
    device.pull_file.assert_not_called()


def test_get_keybox_status_revoked(monkeypatch) -> None:
    """get_keybox_status reports revoked=True when check_kb finds revocation."""
    ops, device, _ = _make_ops()
    device.check_file.return_value = (1, None)
    device.pull_file.return_value = 0

    monkeypatch.setattr(
        "pixel_flasher_plugin.device_ops._runtime.check_kb",
        lambda path: _mock_check_kb(True),
    )

    result = ops.get_keybox_status()

    assert result.success is True
    data = result.data or {}
    assert data["exists"] is True
    assert data["revoked"] is True
    assert data["revoked_reason"] is not None
    assert "REVOKED" in data["raw_check_kb_result"]


# ---------------------------------------------------------------------------
# update_keybox local validation
# ---------------------------------------------------------------------------
def test_update_keybox_valid_xml_dry_run(monkeypatch) -> None:
    """update_keybox dry_run validates XML and does not push."""
    ops, device, _ = _make_ops()
    monkeypatch.setattr(
        "pixel_flasher_plugin.device_ops._runtime.check_kb",
        lambda path: _mock_check_kb(False),
    )

    result = ops.update_keybox(content=_VALID_KEYBOX_XML, dry_run=True, confirm=False)

    assert result.success is True
    assert result.dry_run is True
    data = result.data or {}
    assert data["pushed"] is False
    assert data["revoked"] is False
    device.push_file.assert_not_called()


def test_update_keybox_invalid_xml_rejected() -> None:
    """update_keybox rejects malformed XML before touching the device."""
    ops, device, _ = _make_ops()

    result = ops.update_keybox(content="not xml", dry_run=True, confirm=False)

    assert result.success is False
    assert "Invalid XML" in (result.error or "")
    device.push_file.assert_not_called()


def test_update_keybox_missing_structure_rejected() -> None:
    """update_keybox rejects XML missing required keybox elements."""
    ops, device, _ = _make_ops()

    result = ops.update_keybox(
        content="<AndroidAttestation></AndroidAttestation>",
        dry_run=True,
        confirm=False,
    )

    assert result.success is False
    assert "NumberOfCertificates" in (result.error or "")
    device.push_file.assert_not_called()


def test_update_keybox_revoked_refused_pre_push(monkeypatch) -> None:
    """update_keybox refuses to push a revoked keybox before any push."""
    ops, device, _ = _make_ops()
    monkeypatch.setattr(
        "pixel_flasher_plugin.device_ops._runtime.check_kb",
        lambda path: _mock_check_kb(True),
    )

    result = ops.update_keybox(
        content=_VALID_KEYBOX_XML,
        dry_run=False,
        confirm=True,
    )

    assert result.success is False
    assert "revoked" in (result.error or "").lower()
    device.push_file.assert_not_called()


def test_update_keybox_dry_run_does_not_push(monkeypatch) -> None:
    """update_keybox dry_run does not call push_file even when valid."""
    ops, device, _ = _make_ops()
    monkeypatch.setattr(
        "pixel_flasher_plugin.device_ops._runtime.check_kb",
        lambda path: _mock_check_kb(False),
    )

    ops.update_keybox(content=_VALID_KEYBOX_XML, dry_run=True, confirm=False)

    device.push_file.assert_not_called()


def test_update_keybox_confirm_gate(monkeypatch) -> None:
    """update_keybox requires confirm=True when dry_run=False."""
    ops, device, _ = _make_ops()
    monkeypatch.setattr(
        "pixel_flasher_plugin.device_ops._runtime.check_kb",
        lambda path: _mock_check_kb(False),
    )

    result = ops.update_keybox(
        content=_VALID_KEYBOX_XML,
        dry_run=False,
        confirm=False,
    )

    assert result.success is False
    assert "confirm" in (result.error or "").lower()
    device.push_file.assert_not_called()


def test_update_keybox_successful_push(monkeypatch) -> None:
    """update_keybox pushes and installs the keybox when confirmed."""
    ops, device, _ = _make_ops()
    monkeypatch.setattr(
        "pixel_flasher_plugin.device_ops._runtime.check_kb",
        lambda path: _mock_check_kb(False),
    )
    ops._run_shell_safe = MagicMock(return_value=MagicMock(returncode=0, stdout="", stderr=""))  # type: ignore[method-assign]

    result = ops.update_keybox(
        content=_VALID_KEYBOX_XML,
        dry_run=False,
        confirm=True,
    )

    assert result.success is True
    data = result.data or {}
    assert data["pushed"] is True
    assert data["revoked"] is False
    device.push_file.assert_called_once()
    assert CommandValidator.is_allowed(result.command or "")[0] is True


# ---------------------------------------------------------------------------
# MCP registration invariants
# ---------------------------------------------------------------------------
def test_mcp_keybox_tools_registered(mcp_server_module) -> None:
    """Both keybox tools are registered on the MCP server."""
    tools = mcp_server_module.mcp._tool_manager._tools
    assert "get_keybox_status" in tools
    assert "update_keybox" in tools


def test_get_keybox_status_has_no_dry_run_or_confirm(mcp_server_module) -> None:
    """get_keybox_status is INFO tier and lacks dry_run/confirm params."""
    tool = mcp_server_module.mcp._tool_manager._tools["get_keybox_status"]
    props = tool.parameters.get("properties", {})
    assert "dry_run" not in props
    assert "confirm" not in props


def test_update_keybox_has_dry_run_and_confirm(mcp_server_module) -> None:
    """update_keybox is WARN tier and exposes dry_run + confirm params."""
    tool = mcp_server_module.mcp._tool_manager._tools["update_keybox"]
    props = tool.parameters.get("properties", {})
    assert "dry_run" in props
    assert "confirm" in props


# ---------------------------------------------------------------------------
# Whitelist invariant
# ---------------------------------------------------------------------------
def test_keybox_cp_chmod_command_passes_whitelist() -> None:
    """The canonical single-quoted cp+chmod command passes the whitelist."""
    cmd = (
        "adb -s FAKE001 shell su -c "
        "'cp /data/local/tmp/keybox.xml /data/adb/tricky_store/keybox.xml "
        "&& chmod 644 /data/adb/tricky_store/keybox.xml'"
    )
    allowed, reason = CommandValidator.is_allowed(cmd)
    assert allowed is True, f"Keybox cp+chmod command blocked: {reason}"

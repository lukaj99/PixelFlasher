"""Live Play Integrity verdict tests (LJD-286).

These tests cover the new ``check_play_integrity`` live-probe path:

  * Display-locked refusal in ``live`` mode.
  * Auto fallback to module state when no checker app is installed.
  * Parser selection and verdict extraction for each supported app.
  * Command-shape validation against the real CommandValidator whitelist.

All device-side shell execution is mocked; the whitelist verification uses the
real validator so we catch the recurring "command blocked in production" defect.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from pixel_flasher_plugin.command_validator import CommandValidator
from pixel_flasher_plugin.device_ops import DeviceOps


def _make_ops(monkeypatch: pytest.MonkeyPatch) -> DeviceOps:
    """Return a DeviceOps instance with a permissive gateway and mocked shell."""
    gateway_mock = MagicMock()
    from pixel_flasher_plugin.safety_engine import Decision

    gateway_mock.evaluate.return_value = (Decision.ALLOW, "")
    ops = DeviceOps(device_id="FAKE001", gateway=gateway_mock)
    ops._run_shell_safe = MagicMock(  # type: ignore[method-assign]
        return_value=MagicMock(returncode=0, stdout="", stderr="")
    )
    return ops


# ---------------------------------------------------------------------------
# Command whitelist verification -- REAL validator, no mocks
# ---------------------------------------------------------------------------
PI_COMMANDS = [
    pytest.param(
        "adb -s FAKE001 shell am force-stop gr.nikolasspyr.integritycheck",
        id="am-force-stop",
    ),
    pytest.param(
        "adb -s FAKE001 shell am start -n gr.nikolasspyr.integritycheck/.MainActivity",
        id="am-start",
    ),
    pytest.param(
        "adb -s FAKE001 shell uiautomator dump /data/local/tmp/pi_mcp.xml",
        id="uiautomator-dump",
    ),
    pytest.param(
        "adb -s FAKE001 shell input tap 540 1200",
        id="input-tap",
    ),
    pytest.param(
        "adb -s FAKE001 pull /data/local/tmp/pi_mcp.xml /tmp/pi_mcp.xml",
        id="pull-xml",
    ),
    pytest.param(
        "adb -s FAKE001 shell cat /data/local/tmp/pi_mcp.xml",
        id="cat-xml",
    ),
]


@pytest.mark.parametrize("cmd", PI_COMMANDS)
def test_pi_command_passes_real_validator(cmd: str) -> None:
    """Every command built by the live probe must pass the real whitelist."""
    allowed, reason = CommandValidator.is_allowed(cmd)
    assert allowed is True, f"COMMAND BLOCKED: {cmd!r}\nReason: {reason!r}"
    assert reason == "", f"Allowed command should have empty reason, got {reason!r}"


def test_am_start_command_shape_matches_validator() -> None:
    """The am start command produced by DeviceOps matches the whitelist."""
    ops = DeviceOps(device_id="FAKE001")
    cmd = ops._adb_cmd("shell am start -n gr.nikolasspyr.integritycheck/.MainActivity")
    allowed, reason = CommandValidator.is_allowed(cmd)
    assert allowed is True, f"am start command blocked: {cmd!r}\nReason: {reason!r}"


# ---------------------------------------------------------------------------
# Display-locked refusal
# ---------------------------------------------------------------------------
def test_check_play_integrity_refuses_when_display_locked(
    monkeypatch: pytest.MonkeyPatch,
    _stub_get_device: MagicMock,
) -> None:
    """In live mode a locked display returns a clear error."""
    fake = _stub_get_device
    fake.true_mode = "adb"
    fake.is_display_unlocked.return_value = False

    ops = _make_ops(monkeypatch)
    monkeypatch.setattr(
        ops,
        "_read_pi_module_state",
        lambda: {
            "module_installed": True,
            "module_enabled": True,
            "module_version": "v17.9",
            "module_name": "PlayIntegrityFix",
        },
    )

    result = ops.check_play_integrity(probe_method="live")

    assert result.success is False
    assert "unlocked" in (result.error or "").lower()


# ---------------------------------------------------------------------------
# Auto fallback when no checker app is installed
# ---------------------------------------------------------------------------
def test_check_play_integrity_auto_fallback_without_checker(
    monkeypatch: pytest.MonkeyPatch,
    _stub_get_device: MagicMock,
) -> None:
    """Auto mode falls back to module state and warns when no checker app exists."""
    fake = _stub_get_device
    fake.true_mode = "adb"
    fake.is_display_unlocked.return_value = True
    fake.get_package_list.return_value = "package:com.android.settings\n"

    ops = _make_ops(monkeypatch)
    monkeypatch.setattr(
        ops,
        "_read_pi_module_state",
        lambda: {
            "module_installed": True,
            "module_enabled": True,
            "module_version": "v17.9",
            "module_name": "PlayIntegrityFix",
        },
    )

    result = ops.check_play_integrity(probe_method="auto")

    assert result.success is True
    data = result.data or {}
    assert data["probe_method"] == "module_state_only"
    assert any("No supported checker app" in w for w in (result.warnings or []))


# ---------------------------------------------------------------------------
# Live probe with mocked dump/tap/parser
# ---------------------------------------------------------------------------
def _write_dummy_xml(local_path: str) -> bool:
    """Helper used to mock _uiautomator_dump_and_pull."""
    with open(local_path, "w", encoding="utf-8") as f:
        f.write('<node text="CHECK" bounds="[100,200][300,400]"/>')
    return True


def test_check_play_integrity_live_spic_extracts_verdict(
    monkeypatch: pytest.MonkeyPatch,
    _stub_get_device: MagicMock,
) -> None:
    """A live SPIC probe returns structured BASIC/DEVICE/STRONG verdicts."""
    fake = _stub_get_device
    fake.true_mode = "adb"
    fake.is_display_unlocked.return_value = True
    fake.get_package_list.return_value = "package:com.henrikherzig.playintegritychecker\n"

    ops = _make_ops(monkeypatch)
    monkeypatch.setattr(
        ops,
        "_read_pi_module_state",
        lambda: {
            "module_installed": True,
            "module_enabled": True,
            "module_version": "v17.9",
            "module_name": "PlayIntegrityFix",
        },
    )

    def _write_spic_xml(local: str) -> bool:
        with open(local, "w", encoding="utf-8") as f:
            f.write(
                '<node text="Make Play Integrity Request" '
                'bounds="[100,200][300,400]"/>'
            )
        return True

    monkeypatch.setattr(
        ops,
        "_uiautomator_dump_and_pull",
        lambda remote, local, retries=3: _write_spic_xml(local),
    )
    monkeypatch.setattr(ops, "_tap", lambda x, y: True)  # type: ignore[method-assign]

    import pixel_flasher_plugin.device_ops as device_ops_module

    monkeypatch.setattr(
        device_ops_module._runtime,
        "process_pi_xml_spic",
        lambda filename: "[✓] [✓] [✗] MEETS_DEVICE_INTEGRITY",
    )

    result = ops.check_play_integrity(probe_method="live", timeout=1)

    assert result.success is True
    data = result.data or {}
    assert data["probe_method"] == "live_spic"
    assert data["checker_app"] == "com.henrikherzig.playintegritychecker"
    assert data["basic_integrity"] is True
    assert data["device_integrity"] is True
    assert data["strong_integrity"] is False
    assert data["verdict_raw"] == "[✓] [✓] [✗] MEETS_DEVICE_INTEGRITY"


def test_check_play_integrity_live_aic_extracts_verdict(
    monkeypatch: pytest.MonkeyPatch,
    _stub_get_device: MagicMock,
) -> None:
    """A live AIC probe parses the Device recognition verdict string."""
    fake = _stub_get_device
    fake.true_mode = "adb"
    fake.is_display_unlocked.return_value = True
    fake.get_package_list.return_value = "package:com.thend.integritychecker\n"

    ops = _make_ops(monkeypatch)
    monkeypatch.setattr(
        ops,
        "_read_pi_module_state",
        lambda: {
            "module_installed": True,
            "module_enabled": True,
            "module_version": "v17.9",
            "module_name": "PlayIntegrityFix",
        },
    )

    def _write_aic_xml(local: str) -> bool:
        with open(local, "w", encoding="utf-8") as f:
            f.write(
                '<node class="android.widget.Button" '
                'bounds="[100,200][300,400]"/>'
            )
        return True

    monkeypatch.setattr(
        ops,
        "_uiautomator_dump_and_pull",
        lambda remote, local, retries=3: _write_aic_xml(local),
    )
    monkeypatch.setattr(ops, "_tap", lambda x, y: True)  # type: ignore[method-assign]

    import pixel_flasher_plugin.device_ops as device_ops_module

    monkeypatch.setattr(
        device_ops_module._runtime,
        "process_pi_xml_aic",
        lambda filename: "[✓] [✗] [✗]\nMEETS_BASIC_INTEGRITY",
    )

    result = ops.check_play_integrity(probe_method="live", timeout=1)

    assert result.success is True
    data = result.data or {}
    assert data["probe_method"] == "live_aic"
    assert data["basic_integrity"] is True
    assert data["device_integrity"] is False
    assert data["strong_integrity"] is False


def test_check_play_integrity_live_piac_heuristic(
    monkeypatch: pytest.MonkeyPatch,
    _stub_get_device: MagicMock,
) -> None:
    """A live PIAC probe maps content-desc lines to booleans."""
    fake = _stub_get_device
    fake.true_mode = "adb"
    fake.is_display_unlocked.return_value = True
    fake.get_package_list.return_value = "package:gr.nikolasspyr.integritycheck\n"

    ops = _make_ops(monkeypatch)
    monkeypatch.setattr(
        ops,
        "_read_pi_module_state",
        lambda: {
            "module_installed": True,
            "module_enabled": True,
            "module_version": "v17.9",
            "module_name": "PlayIntegrityFix",
        },
    )

    def _write_piac_xml(local: str) -> bool:
        with open(local, "w", encoding="utf-8") as f:
            f.write('<node text="CHECK" bounds="[100,200][300,400]"/>')
        return True

    monkeypatch.setattr(
        ops,
        "_uiautomator_dump_and_pull",
        lambda remote, local, retries=3: _write_piac_xml(local),
    )
    monkeypatch.setattr(ops, "_tap", lambda x, y: True)  # type: ignore[method-assign]

    import pixel_flasher_plugin.device_ops as device_ops_module

    monkeypatch.setattr(
        device_ops_module._runtime,
        "process_pi_xml_piac",
        lambda filename: "basic_integrity:\tChecked\ndevice_integrity:\tChecked\nstrong_integrity:\tUnchecked",
    )

    result = ops.check_play_integrity(probe_method="live", timeout=1)

    assert result.success is True
    data = result.data or {}
    assert data["probe_method"] == "live_piac"
    assert data["basic_integrity"] is True
    assert data["device_integrity"] is True
    assert data["strong_integrity"] is False


# ---------------------------------------------------------------------------
# Verdict mapping edge cases
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "raw,expected_basic,expected_device,expected_strong",
    [
        ("[✓] [✓] [✓] MEETS_STRONG_INTEGRITY", True, True, True),
        ("[✓] [✓] [✗] MEETS_DEVICE_INTEGRITY", True, True, False),
        ("[✓] [✗] [✗] MEETS_BASIC_INTEGRITY", True, False, False),
        ("[✗] [✗] [✗] NO_INTEGRITY", False, False, False),
    ],
)
def test_verdict_mapping_for_spic(
    raw: str,
    expected_basic: bool,
    expected_device: bool,
    expected_strong: bool,
) -> None:
    """SPIC-style raw strings map to the correct boolean triple."""
    ops = DeviceOps(device_id="FAKE001")
    mapped = ops._map_verdict(raw, [])
    assert mapped["basic_integrity"] is expected_basic
    assert mapped["device_integrity"] is expected_device
    assert mapped["strong_integrity"] is expected_strong


def test_quota_reached_sets_flag() -> None:
    """Quota error strings surface quota_reached=True without crashing."""
    ops = DeviceOps(device_id="FAKE001")
    mapped = ops._map_verdict(
        "Quota Reached.\nSimple Play Integrity Checker\nis making too many requests to the Google API.",
        ["Integrity API error (-8)"],
    )
    assert mapped["quota_reached"] is True
    assert mapped["error"] == "Checker app API quota exceeded"

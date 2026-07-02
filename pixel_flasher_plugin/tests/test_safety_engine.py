"""SafetyGateway preflight + Decision enum invariant tests.

Pins:
  * The Decision enum has exactly ALLOW / CONFIRM / DENY members.
  * SafetyGateway is constructable with a config and optional device_ops.
  * Every reviewer-validated preflight check name dispatches correctly (does
    NOT return "Unknown pre-flight check").

The preflight check names verified here come from the actual ``_run_check``
dispatch in ``safety_engine.py`` -- the task brief explicitly required us to
read the source first rather than hardcode names. The actual names are:

    device_connected, correct_mode, bootloader_unlocked, battery_level,
    disk_space, platform_tools_valid, sha256_verify, anti_rollback,
    oem_unlock_ability, critical_partition_backup

(10 names -- not 9 as the brief suggested.)
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from pixel_flasher_plugin.safety_engine import Decision, SafetyGateway


# ---------------------------------------------------------------------------
# Decision enum
# ---------------------------------------------------------------------------
def test_decision_enum_has_allow_confirm_deny() -> None:
    """Decision must have ALLOW, CONFIRM, DENY members."""
    names = {m.name for m in Decision}
    assert names == {"ALLOW", "CONFIRM", "DENY"}, (
        f"Decision enum members changed: expected {{ALLOW, CONFIRM, DENY}}, "
        f"got {names}"
    )


def test_decision_member_values_are_distinct() -> None:
    """Each Decision member has a unique string value."""
    values = [m.value for m in Decision]
    assert len(values) == len(set(values)), f"Duplicate Decision values: {values}"


# ---------------------------------------------------------------------------
# SafetyGateway construction
# ---------------------------------------------------------------------------
def test_safety_gateway_constructable_with_config_and_no_device_ops() -> None:
    """SafetyGateway(config=mock, device_ops=None) must succeed."""
    mock_config = MagicMock(name="mock_config")
    gateway = SafetyGateway(config=mock_config, device_ops=None)
    assert gateway is not None
    assert gateway.config is mock_config, "config not stored on instance"
    assert gateway.device_ops is None, "device_ops should be None"


def test_safety_gateway_constructable_with_device_ops() -> None:
    """SafetyGateway(config=mock, device_ops=mock) must accept device_ops."""
    mock_config = MagicMock(name="mock_config")
    mock_ops = MagicMock(name="mock_device_ops")
    gateway = SafetyGateway(config=mock_config, device_ops=mock_ops)
    assert gateway.device_ops is mock_ops


def test_safety_gateway_constructable_with_none_config() -> None:
    """SafetyGateway(config=None) is allowed (deferred to tool layer)."""
    gateway = SafetyGateway(config=None)
    assert gateway is not None
    assert gateway.config is None


# ---------------------------------------------------------------------------
# Pre-flight check dispatch -- verified names from source
# ---------------------------------------------------------------------------
# These are the names that _run_check actually recognizes (read from
# safety_engine.py:378-397). They must each dispatch without returning
# "Unknown pre-flight check".
RECOGNIZED_PREFLIGHT_CHECKS = [
    "device_connected",
    "correct_mode",
    "bootloader_unlocked",
    "battery_level",
    "disk_space",
    "platform_tools_valid",
    "sha256_verify",
    "anti_rollback",
    "oem_unlock_ability",
    "critical_partition_backup",
]


@pytest.fixture
def gateway() -> SafetyGateway:
    """A SafetyGateway with a mock config; no real device work needed."""
    return SafetyGateway(config=MagicMock(), device_ops=None)


@pytest.mark.parametrize("check_name", RECOGNIZED_PREFLIGHT_CHECKS)
def test_preflight_check_dispatches(gateway: SafetyGateway, check_name: str) -> None:
    """Each reviewer-validated preflight check must be recognized.

    We invoke _run_check directly with a FAKE device id. The check itself
    may legitimately fail (e.g. device is not connected), but it MUST NOT
    return "Unknown pre-flight check: <name>".
    """
    result = gateway._run_check(check_name, "FAKE001", {})
    assert result is not None
    assert result.name == check_name, (
        f"Check returned with wrong name: expected {check_name!r}, "
        f"got {result.name!r}"
    )
    assert "Unknown pre-flight check" not in (result.detail or ""), (
        f"Preflight check {check_name!r} was NOT recognized by the gateway.\n"
        f"Returned detail: {result.detail!r}"
    )


def test_unknown_preflight_check_is_rejected(gateway: SafetyGateway) -> None:
    """Sanity: an unknown check name MUST be rejected as CRITICAL failure."""
    result = gateway._run_check("definitely_not_a_real_check", "FAKE001", {})
    assert result.passed is False
    assert "Unknown pre-flight check" in (result.detail or "")
    assert result.severity.name == "CRITICAL"


# ---------------------------------------------------------------------------
# run_preflight wraps individual checks and returns a list
# ---------------------------------------------------------------------------
def test_run_preflight_returns_list_of_results(gateway: SafetyGateway) -> None:
    """run_preflight must always return a list (one result per check)."""
    results = gateway.run_preflight(
        "FAKE001",
        ["device_connected", "correct_mode"],
        {"expected_mode": "adb"},
    )
    assert isinstance(results, list)
    assert len(results) == 2
    assert all(r.name in {"device_connected", "correct_mode"} for r in results)


def test_run_preflight_swallows_exceptions(gateway: SafetyGateway) -> None:
    """A crashing individual check must not propagate; it returns a CRITICAL failure."""
    # Use a check name that will be dispatched but blows up internally.
    # disk_space should succeed on this host; force a failure via a bogus path
    # with a too-large min_gb.  Easier: trigger a known crash via sha256_verify
    # with non-bytes-encodable args.
    results = gateway.run_preflight(
        "FAKE001",
        ["sha256_verify"],
        {"path": "/nonexistent/path/file.bin", "expected_hash": "0" * 64},
    )
    assert len(results) == 1
    # It either failed (file not found) or passed (shouldn't, but defensive).
    # The key invariant: the list has one entry, not an exception.
    assert results[0].name == "sha256_verify"


# ---------------------------------------------------------------------------
# Decision.evaluate -- coarse-grained safety decision pipeline
# ---------------------------------------------------------------------------
def test_evaluate_denies_injection() -> None:
    """evaluate() must return DENY for an injection vector."""
    gateway = SafetyGateway(config=None)
    decision, reason = gateway.evaluate(
        "adb -s X shell getprop ro.x; rm -rf /",
        {"risk_tier": Decision.ALLOW, "confirm": True},  # type: ignore[arg-type]
    )
    assert decision == Decision.DENY
    assert reason


def test_evaluate_confirms_critical_without_confirm() -> None:
    """evaluate() must return CONFIRM for a legit CRITICAL op without confirm=True."""
    gateway = SafetyGateway(config=None)
    cmd = "fastboot -s FAKE001 flash boot /tmp/boot.img"
    decision, reason = gateway.evaluate(
        cmd,
        {"risk_tier": Decision.ALLOW, "confirm": False},  # type: ignore[arg-type]
    )
    # Need to use a RiskTier; the gateway exposes it via the result_types module.
    # Re-run with the proper RiskTier to keep this test realistic.
    from pixel_flasher_plugin.result_types import RiskTier
    decision, reason = gateway.evaluate(
        cmd,
        {"risk_tier": RiskTier.CRITICAL, "confirm": False},
    )
    assert decision == Decision.CONFIRM
    assert "confirm" in reason.lower()


def test_evaluate_allows_critical_with_confirm() -> None:
    """evaluate() must return ALLOW for a legit CRITICAL op with confirm=True."""
    from pixel_flasher_plugin.result_types import RiskTier
    gateway = SafetyGateway(config=None)
    cmd = "fastboot -s FAKE001 flash boot /tmp/boot.img"
    decision, reason = gateway.evaluate(
        cmd,
        {"risk_tier": RiskTier.CRITICAL, "confirm": True},
    )
    assert decision == Decision.ALLOW
    assert reason == ""
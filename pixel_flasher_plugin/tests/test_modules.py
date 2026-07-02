"""Tests for the SOTA root module operations in DeviceOps.

These tests exercise the six new module-management methods
(list_modules, install_module, uninstall_module, enable_module,
disable_module, run_module_action) with a mocked ``phone.Device`` so no
real adb/fastboot interaction happens.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from pixel_flasher_plugin.device_ops import DeviceOps
from pixel_flasher_plugin.safety_engine import Decision


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _make_ops(su_version: str = "Magisk", rooted: bool = True):
    """Return a DeviceOps instance with a mocked gateway and device."""
    gateway = MagicMock()
    gateway.evaluate.return_value = (Decision.ALLOW, "")
    gateway.run_preflight.return_value = []

    ops = DeviceOps(device_id="FAKE001", gateway=gateway)
    device = MagicMock()
    device.rooted = rooted
    device.su_version = su_version
    device.true_mode = "adb"

    # Default module getters return empty lists.
    device.get_magisk_detailed_modules.return_value = []
    device.get_ksu_detailed_modules.return_value = []
    device.get_sukisu_detailed_modules.return_value = []
    device.get_wild_ksu_detailed_modules.return_value = []
    device.get_apatch_detailed_modules.return_value = []

    # Default primitive return codes.
    device.magisk_install_module.return_value = 0
    device.magisk_uninstall_module.return_value = 0
    device.enable_magisk_module.return_value = 0
    device.disable_magisk_module.return_value = 0
    device.magisk_run_module_action.return_value = 0

    ops._device = device
    return ops, device, gateway


def _module(id: str, name: str = "", version: str = "", state: str = "enabled", has_action: bool = False):
    return SimpleNamespace(id=id, name=name, version=version, state=state, hasAction=has_action)


# ---------------------------------------------------------------------------
# list_modules
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "su_version, getter_name",
    [
        ("Magisk", "get_magisk_detailed_modules"),
        ("KernelSU", "get_ksu_detailed_modules"),
        ("SukiSU", "get_sukisu_detailed_modules"),
        ("Wild_KSU", "get_wild_ksu_detailed_modules"),
        ("APatch", "get_apatch_detailed_modules"),
    ],
)
def test_list_modules_auto_detects_root_solution(su_version: str, getter_name: str) -> None:
    """list_modules dispatches to the correct getter based on su_version."""
    ops, device, _ = _make_ops(su_version=su_version)
    getter = getattr(device, getter_name)
    getter.return_value = [_module(id="trickystore", name="TrickyStore", version="1.0", state="enabled", has_action=True)]

    result = ops.list_modules()

    assert result.success is True
    assert result.data["root_solution"] == su_version
    assert result.data["count"] == 1
    entry = result.data["modules"][0]
    assert entry["id"] == "trickystore"
    assert entry["name"] == "TrickyStore"
    assert entry["version"] == "1.0"
    assert entry["state"] == "enabled"
    assert entry["has_action"] is True
    getter.assert_called_once()


def test_list_modules_not_rooted() -> None:
    """list_modules returns an error when the device is not rooted."""
    ops, _, _ = _make_ops(rooted=False)
    result = ops.list_modules()
    assert result.success is False
    assert "not rooted" in (result.error or "").lower()


def test_list_modules_unrecognized_root_solution() -> None:
    """list_modules returns an error listing the detected su_version."""
    ops, _, _ = _make_ops(su_version="SuperRoot")
    result = ops.list_modules()
    assert result.success is False
    assert "SuperRoot" in (result.error or "")


# ---------------------------------------------------------------------------
# install_module
# ---------------------------------------------------------------------------
def _make_zip(tmp_path, name: str = "module.zip") -> str:
    import zipfile
    path = tmp_path / name
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("module.prop", "id=test\nname=Test\n")
    return str(path)


def test_install_module_dry_run(tmp_path) -> None:
    """install_module dry_run validates the zip and returns a preview."""
    ops, device, _ = _make_ops()
    zip_path = _make_zip(tmp_path)

    result = ops.install_module(zip_path, dry_run=True, confirm=True)

    assert result.success is True
    assert result.dry_run is True
    assert result.data["module_name"] == "module.zip"
    device.magisk_install_module.assert_not_called()


def test_install_module_confirm_gate(tmp_path) -> None:
    """install_module requires confirm=True when dry_run=False."""
    ops, _, gateway = _make_ops()
    gateway.evaluate.return_value = (Decision.CONFIRM, "Operation requires confirmation")
    zip_path = _make_zip(tmp_path)

    result = ops.install_module(zip_path, dry_run=False, confirm=False)

    assert result.success is False
    assert "confirm" in (result.error or "").lower()


def test_install_module_url_not_supported() -> None:
    """install_module rejects URL module paths."""
    ops, _, _ = _make_ops()
    result = ops.install_module("https://example.com/module.zip", dry_run=True, confirm=True)
    assert result.success is False
    assert "URL" in (result.error or "")


def test_install_module_invalid_zip(tmp_path) -> None:
    """install_module rejects a non-zip file."""
    ops, _, _ = _make_ops()
    bad = tmp_path / "not_a_zip.zip"
    bad.write_text("not a zip")
    result = ops.install_module(str(bad), dry_run=True, confirm=True)
    assert result.success is False
    assert "zip" in (result.error or "").lower()


def test_install_module_executes(tmp_path) -> None:
    """install_module calls magisk_install_module when executing."""
    ops, device, _ = _make_ops()
    zip_path = _make_zip(tmp_path)

    result = ops.install_module(zip_path, dry_run=False, confirm=True)

    assert result.success is True
    device.magisk_install_module.assert_called_once_with(zip_path)


# ---------------------------------------------------------------------------
# module_id validation
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "bad_id",
    [
        "../tricky",
        "a;rm -rf /",
        "",
        "foo bar",
        "module$id",
    ],
)
def test_module_id_validation_rejects_unsafe_ids(bad_id: str) -> None:
    """uninstall_module rejects path traversal / shell metacharacters / empty ids."""
    ops, _, _ = _make_ops()
    result = ops.uninstall_module(bad_id, dry_run=False, confirm=True)
    assert result.success is False
    assert "Invalid module_id" in (result.error or "")


# ---------------------------------------------------------------------------
# uninstall_module
# ---------------------------------------------------------------------------
def test_uninstall_module_dry_run_checks_existence() -> None:
    """uninstall_module dry_run succeeds only when the module is installed."""
    ops, device, _ = _make_ops()
    device.get_magisk_detailed_modules.return_value = [_module(id="trickystore")]

    result = ops.uninstall_module("trickystore", dry_run=True, confirm=True)

    assert result.success is True
    assert result.dry_run is True
    device.magisk_uninstall_module.assert_not_called()


def test_uninstall_module_dry_run_missing() -> None:
    """uninstall_module dry_run fails when the module is not installed."""
    ops, _, _ = _make_ops()
    result = ops.uninstall_module("missing", dry_run=True, confirm=True)
    assert result.success is False
    assert "not installed" in (result.error or "").lower()


def test_uninstall_module_executes() -> None:
    """uninstall_module calls magisk_uninstall_module when executing."""
    ops, device, _ = _make_ops()
    device.get_magisk_detailed_modules.return_value = [_module(id="trickystore")]

    result = ops.uninstall_module("trickystore", dry_run=False, confirm=True)

    assert result.success is True
    device.magisk_uninstall_module.assert_called_once_with("trickystore")


# ---------------------------------------------------------------------------
# enable_module / disable_module
# ---------------------------------------------------------------------------
def test_enable_module_executes() -> None:
    """enable_module calls enable_magisk_module when executing."""
    ops, device, _ = _make_ops()
    result = ops.enable_module("trickystore", dry_run=False, confirm=True)
    assert result.success is True
    device.enable_magisk_module.assert_called_once_with("trickystore")


def test_disable_module_executes() -> None:
    """disable_module calls disable_magisk_module when executing."""
    ops, device, _ = _make_ops()
    result = ops.disable_module("trickystore", dry_run=False, confirm=True)
    assert result.success is True
    device.disable_magisk_module.assert_called_once_with("trickystore")


# ---------------------------------------------------------------------------
# run_module_action
# ---------------------------------------------------------------------------
def test_run_module_action_dry_run_missing_action() -> None:
    """run_module_action dry_run fails when the module has no action.sh."""
    ops, device, _ = _make_ops()
    device.get_magisk_detailed_modules.return_value = [_module(id="trickystore", has_action=False)]

    result = ops.run_module_action("trickystore", dry_run=True, confirm=True)

    assert result.success is False
    assert "action.sh" in (result.error or "").lower()


def test_run_module_action_executes() -> None:
    """run_module_action calls magisk_run_module_action when executing."""
    ops, device, _ = _make_ops()
    device.get_magisk_detailed_modules.return_value = [_module(id="trickystore", has_action=True)]

    result = ops.run_module_action("trickystore", dry_run=False, confirm=True)

    assert result.success is True
    device.magisk_run_module_action.assert_called_once_with("trickystore")

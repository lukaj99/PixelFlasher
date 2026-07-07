"""Tests for root-based, app-independent package data backup/restore.

Covers the pure command-builders in ``package_backup.py`` and
``DeviceOps.backup_app_data``/``restore_app_data`` with a mocked shell.
"""
from __future__ import annotations

import os
from unittest.mock import MagicMock

import pytest

from pixel_flasher_plugin import package_backup
from pixel_flasher_plugin.device_ops import DeviceOps
from pixel_flasher_plugin.safety_engine import Decision


def _make_ops():
    gateway = MagicMock()
    gateway.evaluate.return_value = (Decision.ALLOW, "")
    gateway.run_preflight.return_value = []
    ops = DeviceOps(device_id="FAKE001", gateway=gateway)
    ops._device = MagicMock()
    return ops


# ---------------------------------------------------------------------------
# package_backup.py pure helpers
# ---------------------------------------------------------------------------
def test_validate_package_name_rejects_bad_input():
    with pytest.raises(ValueError):
        package_backup.validate_package_name('"; rm -rf /; echo "')


def test_build_backup_script_uses_selinux_and_excludes_cache():
    script = package_backup.build_backup_script("com.a.b", "/data/local/tmp/x.tar")
    assert "--selinux" in script
    assert "--exclude=data/data/com.a.b/cache" in script
    assert "--exclude=data/data/com.a.b/code_cache" in script
    assert "data/user_de/0/com.a.b" in script


def test_build_backup_script_rejects_bad_package():
    with pytest.raises(ValueError):
        package_backup.build_backup_script('com.a.b"; reboot; echo "', "/tmp/x.tar")


def test_build_restore_script_requires_numeric_uid_gid():
    with pytest.raises(ValueError):
        package_backup.build_restore_script("com.a.b", "/tmp/x.tar", uid="not-a-number", gid="1000")


def test_build_restore_script_uses_selinux_and_chown():
    script = package_backup.build_restore_script("com.a.b", "/tmp/x.tar", uid="10123", gid="10123")
    assert "--selinux" in script
    assert "chown -R 10123:10123" in script
    assert "restorecon" not in script  # deliberately not used -- see module docstring


def test_build_restore_script_includes_external_when_requested():
    script = package_backup.build_restore_script(
        "com.a.b", "/tmp/x.tar", uid="10123", gid="10123", include_external=True
    )
    assert "sdcard/Android/data/com.a.b" in script
    # sdcard paths are excluded from chown (owned by media_rw, not the app UID)
    assert "sdcard/Android/data/com.a.b" not in script.split("chown")[1]


# ---------------------------------------------------------------------------
# DeviceOps.backup_app_data / restore_app_data
# ---------------------------------------------------------------------------
def test_backup_app_data_invalid_package_short_circuits():
    ops = _make_ops()
    ops._run_shell_safe = MagicMock()
    result = ops.backup_app_data('com.a.b"; reboot', "/tmp/out", confirm=True)
    assert not result.success
    ops._run_shell_safe.assert_not_called()


def test_backup_app_data_full_flow_succeeds(tmp_path):
    ops = _make_ops()
    fake_tar_content = b"fake tar contents"

    def fake_run_shell_safe(command, timeout=None):
        if command.strip().startswith("pull") or " pull " in command:
            local_path = command.split()[-1]
            with open(local_path, "wb") as f:
                f.write(fake_tar_content)
        return MagicMock(returncode=0, stdout="", stderr="")

    ops._run_shell_safe = MagicMock(side_effect=fake_run_shell_safe)
    dest_dir = str(tmp_path / "backups")
    result = ops.backup_app_data("com.a.b", dest_dir, confirm=True)
    assert result.success, result.error
    assert os.path.isfile(result.data["local_path"])
    assert result.data["size_bytes"] == len(fake_tar_content)


def test_backup_app_data_tar_failure_surfaces_error():
    ops = _make_ops()

    def fake_run_shell_safe(command, timeout=None):
        if "_backup.sh" in command and "su -c" in command:
            return MagicMock(returncode=1, stdout="", stderr="tar: NO_DATA_FOUND")
        return MagicMock(returncode=0, stdout="", stderr="")

    ops._run_shell_safe = MagicMock(side_effect=fake_run_shell_safe)
    result = ops.backup_app_data("com.a.b", "/tmp/out", confirm=True)
    assert not result.success
    assert "tar backup failed" in result.error


def test_restore_app_data_missing_tar_errors():
    ops = _make_ops()
    ops._run_shell_safe = MagicMock()
    result = ops.restore_app_data("com.a.b", "/no/such/file.tar", confirm=True)
    assert not result.success
    ops._run_shell_safe.assert_not_called()


def test_restore_app_data_full_flow_succeeds(tmp_path):
    ops = _make_ops()
    tar_path = tmp_path / "backup.tar"
    tar_path.write_bytes(b"fake tar contents")

    def fake_run_shell_safe(command, timeout=None):
        if "stat -c" in command:
            return MagicMock(returncode=0, stdout="10123:10123\n", stderr="")
        return MagicMock(returncode=0, stdout="", stderr="")

    ops._run_shell_safe = MagicMock(side_effect=fake_run_shell_safe)
    result = ops.restore_app_data("com.a.b", str(tar_path), confirm=True)
    assert result.success, result.error
    assert result.data["uid"] == "10123"


def test_restore_app_data_stat_failure_surfaces_error():
    ops = _make_ops()
    tar_path_holder = {}

    def fake_run_shell_safe(command, timeout=None):
        if "stat -c" in command:
            return MagicMock(returncode=1, stdout="", stderr="No such file or directory")
        return MagicMock(returncode=0, stdout="", stderr="")

    ops._run_shell_safe = MagicMock(side_effect=fake_run_shell_safe)

    import tempfile
    fd, path = tempfile.mkstemp(suffix=".tar")
    os.close(fd)
    try:
        result = ops.restore_app_data("com.a.b", path, confirm=True)
        assert not result.success
        assert "installed" in result.error
    finally:
        os.remove(path)

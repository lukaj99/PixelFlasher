"""Tests for host-side restic snapshot orchestration.

Covers the pure command-builders in ``restic_backup.py`` (validation +
shlex-quoting) and ``DeviceOps.snapshot_app_data`` /
``restore_from_snapshot`` / ``list_app_snapshots`` with a mocked shell. The
restic/rclone commands are host-side and are executed through ``_run_shell_safe``
(they are not adb/fastboot, so they bypass the adb whitelist by design);
safety comes from shlex-quoting every interpolated value.
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from pixel_flasher_plugin import restic_backup
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
# restic_backup.py pure builders
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "repo",
    ["/srv/restic", "rclone:gdrive:backups/pixel", "sftp:luka@vps:/home/luka/restic"],
)
def test_validate_repo_accepts_supported_backends(repo):
    restic_backup.validate_repo(repo)  # no raise


@pytest.mark.parametrize(
    "repo",
    ["rclone:gdrive:$(reboot)", "/srv/x; rm -rf /", "http://evil", "", "rclone:g|drive:p"],
)
def test_validate_repo_rejects_bad_specs(repo):
    with pytest.raises(ValueError):
        restic_backup.validate_repo(repo)


def test_build_backup_command_quotes_and_tags():
    # shlex.quote leaves metacharacter-free tokens unquoted -- the safety
    # guarantee is that a token WITH shell metachars would be quoted (see the
    # injection tests below), not that every arg is wrapped in quotes.
    cmd = restic_backup.build_backup_command(
        "rclone:gdrive:backups/pixel", "/tmp/stage", tags=["pixel-appdata", "nightly"]
    )
    assert cmd.startswith("restic -r rclone:gdrive:backups/pixel backup --json")
    assert "--tag pixel-appdata" in cmd
    assert "--tag nightly" in cmd
    assert "/tmp/stage" in cmd


def test_build_backup_command_rejects_injection_tag():
    with pytest.raises(ValueError):
        restic_backup.build_backup_command("/srv/r", "/tmp/s", tags=["ok", "$(reboot)"])


def test_build_command_quotes_metacharacter_staging_dir():
    # A staging dir containing a shell metachar (e.g. a space) MUST be quoted.
    cmd = restic_backup.build_backup_command("/srv/r", "/tmp/my stage")
    assert "'/tmp/my stage'" in cmd


def test_build_copy_command_uses_from_repo():
    cmd = restic_backup.build_copy_command("sftp:luka@vps:/r", "/srv/primary")
    assert cmd == "restic -r sftp:luka@vps:/r copy --from-repo /srv/primary --verbose"


def test_build_forget_command_retention_and_int_validation():
    cmd = restic_backup.build_forget_command("/srv/r", keep_daily=7, keep_weekly=5, keep_monthly=12)
    assert "forget --keep-daily 7 --keep-weekly 5 --keep-monthly 12 --prune" in cmd
    with pytest.raises(ValueError):
        restic_backup.build_forget_command("/srv/r", keep_daily=-1)


def test_build_restore_command_validates_snapshot():
    cmd = restic_backup.build_restore_command("/srv/r", "latest", "/tmp/out")
    assert cmd == "restic -r /srv/r restore latest --target /tmp/out"
    with pytest.raises(ValueError):
        restic_backup.build_restore_command("/srv/r", "$(reboot)", "/tmp/out")


def test_parse_snapshot_id_from_json_summary():
    out = "\n".join([
        json.dumps({"message_type": "status", "percent_done": 0.5}),
        json.dumps({"message_type": "summary", "snapshot_id": "abcd1234", "files_new": 3}),
    ])
    assert restic_backup.parse_snapshot_id(out) == "abcd1234"
    assert restic_backup.parse_snapshot_id("no json here") is None


# ---------------------------------------------------------------------------
# DeviceOps orchestration (mocked shell + reused primitives)
# ---------------------------------------------------------------------------
def test_snapshot_app_data_full_flow(tmp_path):
    ops = _make_ops()

    # Stub the device-side pull primitive so no real adb runs.
    def fake_backup(package, dest_dir, **kw):
        from pixel_flasher_plugin.result_types import ToolResult
        import os
        os.makedirs(dest_dir, exist_ok=True)
        path = os.path.join(dest_dir, f"{package}_backup.tar")
        with open(path, "wb") as f:
            f.write(b"tar")
        return ToolResult(success=True, data={"package": package, "local_path": path})

    ops.backup_app_data = MagicMock(side_effect=fake_backup)

    def fake_shell(command, timeout=None):
        if "restic" in command and " backup " in command:
            return MagicMock(
                returncode=0,
                stdout=json.dumps({"message_type": "summary", "snapshot_id": "deadbeef"}),
                stderr="",
            )
        return MagicMock(returncode=0, stdout="", stderr="")

    ops._run_shell_safe = MagicMock(side_effect=fake_shell)

    result = ops.snapshot_app_data(
        ["com.a.b", "com.c.d"],
        primary_repo="/srv/primary",
        copy_repos=["rclone:gdrive:backups/pixel"],
        confirm=True,
    )
    assert result.success, result.error
    assert result.data["snapshot_id"] == "deadbeef"
    assert ops.backup_app_data.call_count == 2
    # copy + forget commands ran for the secondary repo
    ran = " ".join(c.args[0] for c in ops._run_shell_safe.call_args_list)
    assert "copy --from-repo" in ran
    assert "forget" in ran


def test_snapshot_app_data_rejects_bad_repo():
    ops = _make_ops()
    ops._run_shell_safe = MagicMock()
    result = ops.snapshot_app_data(["com.a.b"], primary_repo="/srv/x; reboot", confirm=True)
    assert not result.success
    ops._run_shell_safe.assert_not_called()


def test_restore_from_snapshot_reuses_restore_primitive(tmp_path):
    ops = _make_ops()
    from pixel_flasher_plugin.result_types import ToolResult

    def fake_restore(package, tar_path, **kw):
        assert tar_path.endswith(f"{package}_backup.tar")
        return ToolResult(success=True, data={"package": package})

    ops.restore_app_data = MagicMock(side_effect=fake_restore)

    def fake_shell(command, timeout=None):
        # emulate `restic restore --target <dir>` recreating the tar
        if "restic" in command and " restore " in command:
            target = command.split("--target")[1].strip().strip("'")
            import os
            d = os.path.join(target, "srv", "stage")
            os.makedirs(d, exist_ok=True)
            open(os.path.join(d, "com.a.b_backup.tar"), "wb").write(b"tar")
            return MagicMock(returncode=0, stdout="", stderr="")
        return MagicMock(returncode=0, stdout="", stderr="")

    ops._run_shell_safe = MagicMock(side_effect=fake_shell)

    result = ops.restore_from_snapshot(["com.a.b"], repo="/srv/primary", snapshot="latest", confirm=True)
    assert result.success, result.error
    ops.restore_app_data.assert_called_once()


def test_list_app_snapshots_parses_json():
    ops = _make_ops()
    snaps = [{"short_id": "abcd1234", "time": "2026-07-08T03:00:00Z", "tags": ["pixel-appdata"], "paths": ["/tmp/stage"]}]
    ops._run_shell_safe = MagicMock(return_value=MagicMock(returncode=0, stdout=json.dumps(snaps), stderr=""))
    result = ops.list_app_snapshots("/srv/primary")
    assert result.success
    assert result.data["count"] == 1
    assert result.data["snapshots"][0]["id"] == "abcd1234"

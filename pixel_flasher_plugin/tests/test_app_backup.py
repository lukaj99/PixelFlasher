"""Tests for app+data backup tool integration (Neo Backup / Swift Backup).

Covers the pure helpers in ``app_backup.py`` and ``DeviceOps.get_backup_tool_release``
/ ``install_backup_tool`` / ``trigger_app_backup`` / ``get_app_backup_status`` with a
mocked shell, plus real ``CommandValidator`` whitelist checks for every command shape
these tools can produce -- this project has a recurring "command blocked in
production" defect class, so the whitelist check is not optional here.
"""
from __future__ import annotations

import sqlite3
from unittest.mock import MagicMock, patch

import pytest

from pixel_flasher_plugin import app_backup
from pixel_flasher_plugin.command_validator import CommandValidator
from pixel_flasher_plugin.device_ops import DeviceOps
from pixel_flasher_plugin.safety_engine import Decision


def _make_ops() -> tuple[DeviceOps, MagicMock, MagicMock]:
    """Return a DeviceOps instance with a permissive gateway and mocked device/shell."""
    gateway = MagicMock()
    gateway.evaluate.return_value = (Decision.ALLOW, "")
    gateway.run_preflight.return_value = []

    ops = DeviceOps(device_id="FAKE001", gateway=gateway)
    device = MagicMock()
    device.rooted = True
    device.true_mode = "adb"
    device.install_apk.return_value = 0
    ops._device = device
    ops._run_shell_safe = MagicMock(  # type: ignore[method-assign]
        return_value=MagicMock(returncode=0, stdout="", stderr="")
    )
    return ops, device, gateway


# ---------------------------------------------------------------------------
# app_backup.py pure helpers
# ---------------------------------------------------------------------------
def test_package_for_known_apps():
    assert app_backup.package_for("neo_backup") == "com.machiav3lli.backup"
    assert app_backup.package_for("swift_backup") == "org.swiftapps.swiftbackup"


def test_package_for_unknown_app_raises():
    with pytest.raises(ValueError):
        app_backup.package_for("totally_bogus_app")


def test_build_trigger_command_neo_backup():
    cmd = app_backup.build_trigger_command("neo_backup", schedule_name="nightly")
    assert cmd == (
        'am broadcast -a schedule --es name "nightly" '
        "-n com.machiav3lli.backup/.manager.services.CommandReceiver"
    )


def test_build_trigger_command_neo_backup_requires_schedule_name():
    with pytest.raises(ValueError):
        app_backup.build_trigger_command("neo_backup")


def test_build_trigger_command_swift_backup_all_schedules():
    cmd = app_backup.build_trigger_command("swift_backup")
    assert cmd == "am start -n org.swiftapps.swiftbackup/.shortcuts.ShortcutsActivity"


def test_build_trigger_command_swift_backup_specific_ids():
    cmd = app_backup.build_trigger_command("swift_backup", schedule_ids=["1", "2"])
    assert cmd == (
        "am start -n org.swiftapps.swiftbackup/.shortcuts.ShortcutsActivity "
        '-e "cmd" "-s 1 2"'
    )


def test_build_trigger_command_unsupported_app():
    with pytest.raises(ValueError):
        app_backup.build_trigger_command("totally_bogus_app")


@pytest.mark.parametrize(
    "payload",
    [
        '"; rm -rf /sdcard; echo "',
        "$(reboot)",
        "`reboot`",
        "a" * 65,  # over the length cap
    ],
)
def test_build_trigger_command_rejects_shell_metacharacters_in_schedule_name(payload):
    with pytest.raises(ValueError):
        app_backup.build_trigger_command("neo_backup", schedule_name=payload)


@pytest.mark.parametrize(
    "payload",
    ['"; rm -rf /sdcard; echo "', "$(reboot)", "`reboot`"],
)
def test_build_trigger_command_rejects_shell_metacharacters_in_schedule_ids(payload):
    with pytest.raises(ValueError):
        app_backup.build_trigger_command("swift_backup", schedule_ids=["1", payload])


def test_fetch_neo_backup_latest_release():
    fake_response = MagicMock()
    fake_response.json.return_value = {
        "tag_name": "8.3.18",
        "assets": [
            {"name": "Neo_Backup_8.3.18_release.apk", "browser_download_url": "https://example.test/x.apk"},
            {"name": "checksums.txt", "browser_download_url": "https://example.test/checksums.txt"},
        ],
    }
    fake_response.raise_for_status.return_value = None
    with patch("pixel_flasher_plugin.app_backup.requests.get", return_value=fake_response) as get:
        release = app_backup.fetch_neo_backup_latest_release()
    get.assert_called_once()
    assert release == {
        "version": "8.3.18",
        "apk_name": "Neo_Backup_8.3.18_release.apk",
        "apk_url": "https://example.test/x.apk",
    }


def test_fetch_neo_backup_latest_release_no_apk_asset_raises():
    fake_response = MagicMock()
    fake_response.json.return_value = {"tag_name": "8.3.18", "assets": []}
    fake_response.raise_for_status.return_value = None
    with patch("pixel_flasher_plugin.app_backup.requests.get", return_value=fake_response):
        with pytest.raises(ValueError):
            app_backup.fetch_neo_backup_latest_release()


# ---------------------------------------------------------------------------
# Command whitelist verification -- REAL validator, no mocks
# ---------------------------------------------------------------------------
APP_BACKUP_COMMANDS = [
    pytest.param(
        'adb -s FAKE001 shell am broadcast -a schedule --es name "nightly" '
        "-n com.machiav3lli.backup/.manager.services.CommandReceiver",
        id="neo-backup-broadcast",
    ),
    pytest.param(
        "adb -s FAKE001 shell am start -n org.swiftapps.swiftbackup/.shortcuts.ShortcutsActivity",
        id="swift-backup-run-all",
    ),
    pytest.param(
        "adb -s FAKE001 shell am start -n org.swiftapps.swiftbackup/.shortcuts.ShortcutsActivity "
        '-e "cmd" "-s 1 2"',
        id="swift-backup-specific-ids",
    ),
]


@pytest.mark.parametrize("command", APP_BACKUP_COMMANDS)
def test_app_backup_commands_pass_real_whitelist(command: str) -> None:
    valid, _ = CommandValidator.is_allowed(command)
    assert valid, f"Command rejected by whitelist: {command}"


# ---------------------------------------------------------------------------
# DeviceOps.get_backup_tool_release
# ---------------------------------------------------------------------------
def test_get_backup_tool_release_neo_backup():
    ops, _, _ = _make_ops()
    with patch(
        "pixel_flasher_plugin.app_backup.fetch_neo_backup_latest_release",
        return_value={"version": "8.3.18", "apk_name": "x.apk", "apk_url": "https://example.test/x.apk"},
    ):
        result = ops.get_backup_tool_release(app="neo_backup")
    assert result.success
    assert result.data["version"] == "8.3.18"


def test_get_backup_tool_release_swift_backup_errors():
    ops, _, _ = _make_ops()
    result = ops.get_backup_tool_release(app="swift_backup")
    assert not result.success
    assert "no public release" in result.error


def test_get_backup_tool_release_unknown_app_errors():
    ops, _, _ = _make_ops()
    result = ops.get_backup_tool_release(app="bogus")
    assert not result.success


# ---------------------------------------------------------------------------
# DeviceOps.install_backup_tool
# ---------------------------------------------------------------------------
def test_install_backup_tool_swift_backup_requires_apk_path():
    ops, _, _ = _make_ops()
    result = ops.install_backup_tool(app="swift_backup", apk_path=None, confirm=True)
    assert not result.success
    assert "requires an explicit apk_path" in result.error


def test_install_backup_tool_neo_backup_fetches_and_installs(tmp_path):
    ops, _, _ = _make_ops()
    fake_apk = tmp_path / "Neo_Backup_8.3.18_release.apk"
    fake_apk.write_bytes(b"fake apk contents")

    with patch(
        "pixel_flasher_plugin.app_backup.fetch_neo_backup_latest_release",
        return_value={"version": "8.3.18", "apk_name": fake_apk.name, "apk_url": "https://example.test/x.apk"},
    ), patch(
        "pixel_flasher_plugin.app_backup.download_apk", return_value=str(fake_apk)
    ):
        result = ops.install_backup_tool(app="neo_backup", apk_path=None, confirm=True)

    assert result.success
    assert result.data["apk_path"] == str(fake_apk)


def test_install_backup_tool_with_explicit_apk_path(tmp_path):
    ops, _, _ = _make_ops()
    fake_apk = tmp_path / "swift_backup.apk"
    fake_apk.write_bytes(b"fake apk contents")

    result = ops.install_backup_tool(app="swift_backup", apk_path=str(fake_apk), confirm=True)
    assert result.success
    assert result.data["apk_path"] == str(fake_apk)


# ---------------------------------------------------------------------------
# DeviceOps.trigger_app_backup
# ---------------------------------------------------------------------------
def test_trigger_app_backup_neo_backup_succeeds():
    ops, _, _ = _make_ops()
    result = ops.trigger_app_backup("neo_backup", schedule_name="nightly", confirm=True)
    assert result.success
    assert result.data["app"] == "neo_backup"
    assert result.data["schedule_name"] == "nightly"


def test_trigger_app_backup_swift_backup_with_ids_succeeds():
    ops, _, _ = _make_ops()
    result = ops.trigger_app_backup("swift_backup", schedule_ids=["1", "2"], confirm=True)
    assert result.success
    assert result.data["schedule_ids"] == ["1", "2"]


def test_trigger_app_backup_neo_backup_missing_schedule_name_errors():
    ops, _, _ = _make_ops()
    result = ops.trigger_app_backup("neo_backup", confirm=True)
    assert not result.success


def test_trigger_app_backup_shell_failure_surfaces_error():
    ops, _, _ = _make_ops()
    ops._run_shell_safe = MagicMock(
        return_value=MagicMock(returncode=1, stdout="", stderr="Activity not started")
    )
    result = ops.trigger_app_backup("neo_backup", schedule_name="nightly", confirm=True)
    assert not result.success
    assert "trigger failed" in result.error


# ---------------------------------------------------------------------------
# DeviceOps.get_app_backup_status
# ---------------------------------------------------------------------------
def test_get_app_backup_status_installed_with_version():
    ops, device, _ = _make_ops()
    device.get_package_list.return_value = "package:com.machiav3lli.backup\npackage:com.android.chrome\n"
    ops._run_shell_safe = MagicMock(
        return_value=MagicMock(returncode=0, stdout="versionName=8.3.18\n", stderr="")
    )
    result = ops.get_app_backup_status("neo_backup")
    assert result.success
    assert result.data["installed"] is True
    assert result.data["version"] == "8.3.18"


def test_get_app_backup_status_not_installed():
    ops, device, _ = _make_ops()
    device.get_package_list.return_value = "package:com.android.chrome\n"
    result = ops.get_app_backup_status("swift_backup")
    assert result.success
    assert result.data["installed"] is False
    assert result.data["version"] is None


def test_get_app_backup_status_unknown_app_errors():
    ops, _, _ = _make_ops()
    result = ops.get_app_backup_status("bogus")
    assert not result.success


# ---------------------------------------------------------------------------
# app_backup.py schedule-creation helpers (Schema verified empirically
# against a real on-device main.db, release 8.3.18 -- see LESSONS.md)
# ---------------------------------------------------------------------------
def test_serialize_package_set_empty():
    assert app_backup.serialize_package_set(None) == ""
    assert app_backup.serialize_package_set([]) == ""


def test_serialize_package_set_comma_joins():
    assert app_backup.serialize_package_set(["com.a.b", "com.c.d"]) == "com.a.b,com.c.d"


def test_serialize_package_set_rejects_bad_package_name():
    with pytest.raises(ValueError):
        app_backup.serialize_package_set(["not a package; rm -rf /"])


def test_build_schedule_insert_sql_defaults():
    sql, params = app_backup.build_schedule_insert_sql("nightly", now_millis=1000)
    assert "INSERT INTO Schedule" in sql
    assert params == [1, "nightly", 12, 0, 1, 1000, app_backup.NB_FILTER_USER, app_backup.NB_MODE_APK_AND_DATA, "", ""]


def test_build_schedule_insert_sql_with_packages():
    sql, params = app_backup.build_schedule_insert_sql(
        "nightly", packages=["com.a.b"], block_packages=["com.c.d"], now_millis=1000
    )
    assert params[-2:] == ["com.a.b", "com.c.d"]


def test_build_schedule_insert_sql_rejects_bad_name():
    with pytest.raises(ValueError):
        app_backup.build_schedule_insert_sql('"; DROP TABLE Schedule; --', now_millis=1000)


@pytest.mark.parametrize("hour", [-1, 24])
def test_build_schedule_insert_sql_rejects_bad_hour(hour):
    with pytest.raises(ValueError):
        app_backup.build_schedule_insert_sql("nightly", time_hour=hour, now_millis=1000)


def test_build_schedule_insert_sql_rejects_bad_interval():
    with pytest.raises(ValueError):
        app_backup.build_schedule_insert_sql("nightly", interval_days=0, now_millis=1000)


def test_build_schedule_insert_sql_actually_executes_against_real_sqlite(tmp_path):
    """The real, verified CREATE TABLE from the on-device schema -- confirms
    the generated SQL is not just string-shaped-right but genuinely valid."""
    db_path = tmp_path / "main.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "CREATE TABLE `Schedule` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, "
        "`enabled` INTEGER NOT NULL, `name` TEXT NOT NULL, `timeHour` INTEGER NOT NULL, "
        "`timeMinute` INTEGER NOT NULL, `interval` INTEGER NOT NULL, `timePlaced` INTEGER NOT NULL, "
        "`filter` INTEGER NOT NULL, `mode` INTEGER NOT NULL, "
        "`launchableFilter` INTEGER NOT NULL DEFAULT 0, `updatedFilter` INTEGER NOT NULL DEFAULT 0, "
        "`latestFilter` INTEGER NOT NULL DEFAULT 0, `enabledFilter` INTEGER NOT NULL DEFAULT 0, "
        "`timeToRun` INTEGER NOT NULL, `customList` TEXT NOT NULL, `blockList` TEXT NOT NULL, "
        "`tagsList` TEXT NOT NULL DEFAULT '')"
    )
    sql, params = app_backup.build_schedule_insert_sql(
        "nightly", packages=["com.a.b", "com.c.d"], now_millis=1234567890
    )
    conn.execute(sql, params)
    conn.commit()
    row = conn.execute("SELECT name, mode, customList FROM Schedule").fetchone()
    conn.close()
    assert row == ("nightly", app_backup.NB_MODE_APK_AND_DATA, "com.a.b,com.c.d")


# ---------------------------------------------------------------------------
# DeviceOps.create_backup_schedule (full flow, real local sqlite3 exercised)
# ---------------------------------------------------------------------------
def _schedule_schema_sql():
    return (
        "CREATE TABLE `Schedule` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, "
        "`enabled` INTEGER NOT NULL, `name` TEXT NOT NULL, `timeHour` INTEGER NOT NULL, "
        "`timeMinute` INTEGER NOT NULL, `interval` INTEGER NOT NULL, `timePlaced` INTEGER NOT NULL, "
        "`filter` INTEGER NOT NULL, `mode` INTEGER NOT NULL, "
        "`launchableFilter` INTEGER NOT NULL DEFAULT 0, `updatedFilter` INTEGER NOT NULL DEFAULT 0, "
        "`latestFilter` INTEGER NOT NULL DEFAULT 0, `enabledFilter` INTEGER NOT NULL DEFAULT 0, "
        "`timeToRun` INTEGER NOT NULL, `customList` TEXT NOT NULL, `blockList` TEXT NOT NULL, "
        "`tagsList` TEXT NOT NULL DEFAULT '')"
    )


def _make_schedule_ops():
    """DeviceOps whose mocked shell fakes an adb pull by writing a real, schema-valid
    local sqlite3 file -- so the method's actual INSERT/checkpoint logic runs for real."""
    ops, device, gateway = _make_ops()

    def fake_run_shell_safe(command, timeout=None):
        if "stat -c" in command:
            return MagicMock(returncode=0, stdout="12345:12345:660\n", stderr="")
        if command.strip().startswith("pull ") or " pull " in command:
            # adb-style: "pull <remote> <local>"
            parts = command.split()
            local_path = parts[-1]
            if local_path.endswith("main.db"):
                conn = sqlite3.connect(local_path)
                conn.execute(_schedule_schema_sql())
                conn.commit()
                conn.close()
            # wal/shm: legitimately absent, leave unwritten
            return MagicMock(returncode=0, stdout="", stderr="")
        # force-stop, stage mkdir/cp, push, replace cp/chown/chmod, am start: all succeed
        return MagicMock(returncode=0, stdout="", stderr="")

    ops._run_shell_safe = MagicMock(side_effect=fake_run_shell_safe)
    return ops, device, gateway


def test_create_backup_schedule_swift_backup_unsupported():
    ops, _, _ = _make_ops()
    result = ops.create_backup_schedule("swift_backup", "nightly", confirm=True)
    assert not result.success
    assert "swift_backup" in result.error


def test_create_backup_schedule_invalid_name_errors_before_touching_device():
    ops, _, _ = _make_schedule_ops()
    result = ops.create_backup_schedule("neo_backup", '"; DROP TABLE Schedule; --', confirm=True)
    assert not result.success
    ops._run_shell_safe.assert_not_called()


def test_create_backup_schedule_full_flow_succeeds():
    ops, _, _ = _make_schedule_ops()
    result = ops.create_backup_schedule(
        "neo_backup", "nightly", packages=["com.a.b"], confirm=True
    )
    assert result.success, result.error
    assert result.data["name"] == "nightly"
    assert isinstance(result.data["schedule_id"], int)


def test_create_backup_schedule_pull_failure_surfaces_error():
    ops, _, gateway = _make_ops()

    def fake_run_shell_safe(command, timeout=None):
        if "stat -c" in command:
            return MagicMock(returncode=0, stdout="12345:12345:660\n", stderr="")
        # Never actually write main.db locally -- simulates a failed pull.
        return MagicMock(returncode=0, stdout="", stderr="")

    ops._run_shell_safe = MagicMock(side_effect=fake_run_shell_safe)
    result = ops.create_backup_schedule("neo_backup", "nightly", confirm=True)
    assert not result.success
    assert "pull" in result.error.lower()

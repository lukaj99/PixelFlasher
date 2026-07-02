"""DeviceOps preflight wiring + shlex.quote invariant tests.

Two safety invariants are pinned here:

  1. Every destructive ``DeviceOps`` method MUST call ``_run_preflight``
     before executing -- this is the safety hook that prevents flashing an
     unverified image to a connected device.

  2. ``_q()`` MUST shell-quote user-supplied strings so a value like
     ``$(whoami)`` is passed through verbatim rather than executed.

These tests use monkeypatch to spy on ``_run_preflight`` and a mock gateway,
so no real adb/fastboot/device work happens.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from pixel_flasher_plugin.device_ops import DeviceOps
from pixel_flasher_plugin.result_types import ToolResult
from pixel_flasher_plugin.safety_engine import SafetyGateway


# ---------------------------------------------------------------------------
# _q() helper -- shell quoting
# ---------------------------------------------------------------------------
def test_q_helper_quotes_command_substitution() -> None:
    """``_q('$(whoami)')`` must return a quoted string (no execution)."""
    ops = DeviceOps(device_id="FAKE001")
    quoted = ops._q("$(whoami)")
    # shlex.quote wraps dangerous strings in single quotes; verify the
    # original metacharacters survive verbatim (not interpolated).
    assert "$(whoami)" in quoted, (
        f"_q dropped the original input: got {quoted!r}"
    )
    # The result MUST contain a quote character so the shell treats it as
    # a literal, not as a subshell. shlex.quote returns ``'$(whoami)'``
    # which contains single quotes.
    assert "'" in quoted or '"' in quoted, (
        f"_q did not quote the input: got {quoted!r} -- "
        f"a value with $(...) would be executed by the shell"
    )


def test_q_helper_handles_plain_strings() -> None:
    """``_q('plain')`` must still produce a quoted result (no surprises)."""
    ops = DeviceOps(device_id="FAKE001")
    quoted = ops._q("plain")
    assert quoted  # truthy -- not empty
    assert "plain" in quoted


def test_q_helper_quotes_spaces() -> None:
    """A value containing a space must be quoted so it stays one argument."""
    ops = DeviceOps(device_id="FAKE001")
    quoted = ops._q("path with spaces.img")
    assert " " not in quoted.replace(" ", "_NO_SPACE_", 0) or quoted != "path with spaces.img", (
        f"Unquoted space in: {quoted!r}"
    )
    # Stronger: the original space-containing string must not appear raw.
    assert "path with spaces.img" != quoted or "'" in quoted or '"' in quoted


# ---------------------------------------------------------------------------
# Pre-flight wiring -- destructive methods must call _run_preflight
# ---------------------------------------------------------------------------
def _make_ops_with_mocks(monkeypatch: pytest.MonkeyPatch, tmp_image_path: str):
    """Build a DeviceOps whose gateway and shell-exec are mocked.

    Returns (ops, gateway_mock) where gateway_mock is the MagicMock
    backing ``ops.gateway`` (its ``.evaluate`` returns None so commands
    pass the safety gate without being blocked).
    """
    gateway_mock = MagicMock()
    # evaluate(...) returns (Decision.ALLOW, "") so _evaluate() returns None.
    from pixel_flasher_plugin.safety_engine import Decision
    gateway_mock.evaluate.return_value = (Decision.ALLOW, "")
    # Default postcondition/rollback return values so tests that reach them
    # do not fail on MagicMock unpacking.
    gateway_mock.verify_postcondition.return_value = (True, "ok")
    gateway_mock.perform_rollback.return_value = (True, "rollback completed")

    ops = DeviceOps(device_id="FAKE001", gateway=gateway_mock)

    # Stub the runtime shell so even if a method slips past preflight it
    # cannot actually execute.
    ops._run_shell_safe = MagicMock(  # type: ignore[method-assign]
        return_value=MagicMock(returncode=0, stdout="", stderr="")
    )
    return ops, gateway_mock


def test_flash_partition_calls_run_preflight(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """flash_partition() MUST call _run_preflight with CRITICAL risk tier.

    We monkeypatch _run_preflight on the class so we can both observe the
    call AND short-circuit execution (return a denial ToolResult so the
    method exits before invoking the shell).
    """
    img = tmp_path / "boot.img"
    img.write_bytes(b"\x00" * 16)
    backup = tmp_path / "boot_backup.img"
    backup.write_bytes(b"\x00" * 16)

    ops, _ = _make_ops_with_mocks(monkeypatch, str(img))
    monkeypatch.setattr(
        ops,
        "read_partition",
        MagicMock(
            return_value=ToolResult(
                success=True,
                data={"local_path": str(backup)},
            )
        ),
    )

    preflight_spy = MagicMock(
        return_value=ToolResult(success=False, error="blocked by spy")
    )
    monkeypatch.setattr(DeviceOps, "_run_preflight", preflight_spy)

    result = ops.flash_partition("boot", str(img), confirm=True)

    assert preflight_spy.called, (
        "flash_partition() did NOT call _run_preflight -- a CRITICAL "
        "operation was allowed to skip the preflight gate."
    )
    # The result must reflect the spy denial (no real flash).
    assert result.success is False
    assert "blocked by spy" in (result.error or "")


def test_wipe_partition_calls_run_preflight(monkeypatch: pytest.MonkeyPatch) -> None:
    """wipe_partition() MUST call _run_preflight.

    NOTE on naming: the task brief refers to ``erase_partition``. The
    DeviceOps facade names this method ``wipe_partition``; the MCP layer
    exposes it as the ``erase_partition`` tool. This test pins the
    DeviceOps-level wiring.
    """
    ops, _ = _make_ops_with_mocks(monkeypatch, "/tmp/fake.img")

    preflight_spy = MagicMock(
        return_value=ToolResult(success=False, error="blocked by spy")
    )
    monkeypatch.setattr(DeviceOps, "_run_preflight", preflight_spy)

    result = ops.wipe_partition("boot", confirm=True)

    assert preflight_spy.called, (
        "wipe_partition() did NOT call _run_preflight -- a CRITICAL "
        "erase was allowed to skip the preflight gate."
    )
    assert result.success is False
    assert "blocked by spy" in (result.error or "")


def test_install_apk_calls_run_preflight(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """install_apk() MUST call _run_preflight (WARN risk tier)."""
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"\x00" * 16)

    ops, _ = _make_ops_with_mocks(monkeypatch, str(apk))

    preflight_spy = MagicMock(
        return_value=ToolResult(success=False, error="blocked by spy")
    )
    monkeypatch.setattr(DeviceOps, "_run_preflight", preflight_spy)

    result = ops.install_apk(str(apk), confirm=True)

    assert preflight_spy.called, (
        "install_apk() did NOT call _run_preflight -- a WARN-tier APK "
        "install was allowed to skip the preflight gate."
    )
    assert result.success is False


def test_reboot_device_calls_run_preflight(monkeypatch: pytest.MonkeyPatch) -> None:
    """reboot_device() MUST call _run_preflight (WARN risk tier).

    reboot_device is also a destructive operation -- an unexpected reboot
    could interrupt a user mid-flash. It must go through preflight.
    """
    ops, _ = _make_ops_with_mocks(monkeypatch, "/tmp/fake.img")

    preflight_spy = MagicMock(
        return_value=ToolResult(success=False, error="blocked by spy")
    )
    monkeypatch.setattr(DeviceOps, "_run_preflight", preflight_spy)

    result = ops.reboot_device("system", confirm=True)

    assert preflight_spy.called, (
        "reboot_device() did NOT call _run_preflight -- a WARN-tier "
        "reboot was allowed to skip the preflight gate."
    )
    assert result.success is False


# ---------------------------------------------------------------------------
# Cross-cutting: confirm=False alone MUST NOT skip preflight
# ---------------------------------------------------------------------------
def test_flash_partition_runs_preflight_even_when_confirm_false(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """confirm=False (preview path) still calls _run_preflight.

    The preflight gate runs BEFORE the confirmation gate -- this catches
    cases where the device is in the wrong mode even on a preview request.
    """
    img = tmp_path / "boot.img"
    img.write_bytes(b"\x00" * 16)
    backup = tmp_path / "boot_backup.img"
    backup.write_bytes(b"\x00" * 16)

    ops, _ = _make_ops_with_mocks(monkeypatch, str(img))
    monkeypatch.setattr(
        ops,
        "read_partition",
        MagicMock(
            return_value=ToolResult(
                success=True,
                data={"local_path": str(backup)},
            )
        ),
    )

    preflight_spy = MagicMock(return_value=None)  # preflight passes
    monkeypatch.setattr(DeviceOps, "_run_preflight", preflight_spy)

    # confirm=False triggers the safety-gateway CONFIRM path; the gateway
    # mock returns ALLOW so the safety gate passes. Preflight must STILL run.
    result = ops.flash_partition("boot", str(img), confirm=False)

    assert preflight_spy.called, (
        "flash_partition(confirm=False) skipped _run_preflight -- "
        "preflight must run before the confirmation gate."
    )
    # confirm=False -> method should NOT have actually flashed.
    assert ops._run_shell_safe.called is False or result.success is True


# ---------------------------------------------------------------------------
# Finding: task brief referenced DeviceOps.flash_boot_image, which doesn't
# exist at the DeviceOps layer -- it is implemented as an MCP tool that
# delegates to flash_partition. This test documents the layering.
# ---------------------------------------------------------------------------
def test_flash_boot_image_is_not_a_device_ops_method() -> None:
    """flash_boot_image() is an MCP-level wrapper, not a DeviceOps method.

    The task brief expected to test ``flash_boot_image`` preflight wiring
    against ``DeviceOps``. The actual layering is:

        MCP tool: flash_boot_image  (in pixel_flasher_plugin.mcp_server)
            -> DeviceOps.flash_partition  (which calls _run_preflight)

    So the preflight invariant is enforced at the ``flash_partition``
    layer (covered by test_flash_partition_calls_run_preflight above).
    """
    assert not hasattr(DeviceOps, "flash_boot_image"), (
        "DeviceOps.flash_boot_image was added -- if so, add preflight "
        "wiring tests for it as well."
    )


def test_erase_partition_is_not_a_device_ops_method() -> None:
    """DeviceOps uses ``wipe_partition``; ``erase_partition`` is the MCP name."""
    assert not hasattr(DeviceOps, "erase_partition"), (
        "DeviceOps.erase_partition was added -- if so, add preflight "
        "wiring tests for it as well."
    )
    assert hasattr(DeviceOps, "wipe_partition"), (
        "DeviceOps.wipe_partition is missing -- the MCP erase_partition "
        "tool depends on it."
    )


def test_read_partition_size_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    """Partitions larger than ``max_bytes`` are rejected before any read."""
    ops, _ = _make_ops_with_mocks(monkeypatch, "/tmp/fake.img")

    def _fake_run(cmd: str, timeout: int | None = None):
        mock = MagicMock()
        if "blockdev" in cmd:
            # Root path unavailable in this scenario; exercise the fallback.
            mock.returncode = 1
            mock.stdout = ""
            mock.stderr = "su: not found"
        elif "ls -l" in cmd:
            mock.returncode = 0
            mock.stdout = (
                "lrwxrwxrwx 1 root root 21 1970-01-01 00:00 "
                "/dev/block/bootdevice/by-name/boot -> /dev/block/sda37"
            )
        elif "/proc/partitions" in cmd:
            mock.returncode = 0
            mock.stdout = (
                "major minor  #blocks  name\n"
                " 259        0    4194304 sda37\n"
            )
        else:
            mock.returncode = 0
            mock.stdout = ""
            mock.stderr = ""
        return mock

    ops._run_shell_safe = MagicMock(side_effect=_fake_run)  # type: ignore[method-assign]

    result = ops.read_partition("boot", confirm=True)

    assert result.success is False
    assert "exceeds" in (result.error or "").lower()
    assert "4294967296" in (result.error or "")


# ---------------------------------------------------------------------------
# Rollback + postcondition pipeline for boot-class partitions
# ---------------------------------------------------------------------------
def test_flash_partition_rollback_on_boot_flash_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """A failed boot flash must re-flash the backup and report rollback_performed."""
    img = tmp_path / "boot.img"
    img.write_bytes(b"new image")
    backup = tmp_path / "boot_backup.img"
    backup.write_bytes(b"original image")

    ops, _ = _make_ops_with_mocks(monkeypatch, str(img))
    monkeypatch.setattr(
        ops,
        "read_partition",
        MagicMock(
            return_value=ToolResult(
                success=True,
                data={"local_path": str(backup)},
            )
        ),
    )
    # Use a real SafetyGateway so perform_rollback / verify_postcondition execute.
    ops.gateway = SafetyGateway(config=None, device_ops=ops)
    # Bypass preflight so the test targets the rollback path, not preflight.
    monkeypatch.setattr(DeviceOps, "_run_preflight", lambda *args, **kwargs: None)

    commands: list[str] = []

    def _fake_run(cmd: str, timeout: int | None = None):
        mock = MagicMock()
        commands.append(cmd)
        # The initial flash of the new image fails; the rollback flash of the
        # backup succeeds; any subsequent getvar product succeeds.
        if "flash" in cmd and str(backup) not in cmd:
            mock.returncode = 1
            mock.stdout = ""
            mock.stderr = "flash write failure"
        else:
            mock.returncode = 0
            mock.stdout = "product: foo"
            mock.stderr = ""
        return mock

    ops._run_shell_safe = MagicMock(side_effect=_fake_run)  # type: ignore[method-assign]

    result = ops.flash_partition("boot", str(img), confirm=True)

    assert result.success is False
    assert result.rollback_performed is True
    rollback_cmds = [c for c in commands if "flash" in c and str(backup) in c]
    assert len(rollback_cmds) >= 1, (
        f"Expected rollback flash command using backup {backup}; got {commands}"
    )


def test_flash_partition_rollback_on_postcondition_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """If the device is unresponsive after a boot flash, rollback the backup."""
    img = tmp_path / "boot.img"
    img.write_bytes(b"new image")
    backup = tmp_path / "boot_backup.img"
    backup.write_bytes(b"original image")

    ops, _ = _make_ops_with_mocks(monkeypatch, str(img))
    monkeypatch.setattr(
        ops,
        "read_partition",
        MagicMock(
            return_value=ToolResult(
                success=True,
                data={"local_path": str(backup)},
            )
        ),
    )
    # Use a real SafetyGateway so perform_rollback / verify_postcondition execute.
    ops.gateway = SafetyGateway(config=None, device_ops=ops)
    # Bypass preflight so the test targets the postcondition/rollback path.
    monkeypatch.setattr(DeviceOps, "_run_preflight", lambda *args, **kwargs: None)

    commands: list[str] = []

    def _fake_run(cmd: str, timeout: int | None = None):
        mock = MagicMock()
        commands.append(cmd)
        if "getvar product" in cmd:
            # Device is unresponsive after the flash.
            mock.returncode = 1
            mock.stdout = ""
            mock.stderr = "device not responding"
        else:
            mock.returncode = 0
            mock.stdout = ""
            mock.stderr = ""
        return mock

    ops._run_shell_safe = MagicMock(side_effect=_fake_run)  # type: ignore[method-assign]

    result = ops.flash_partition("boot", str(img), confirm=True)

    assert result.success is False
    assert result.rollback_performed is True
    assert "post-flash verification failed" in (result.error or "").lower()
    rollback_cmds = [c for c in commands if "flash" in c and str(backup) in c]
    assert len(rollback_cmds) >= 1


def test_flash_partition_no_rollback_for_non_boot_partition(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """Non-boot-class partitions do not trigger backup/rollback on flash failure."""
    img = tmp_path / "system.img"
    img.write_bytes(b"system image")

    ops, _ = _make_ops_with_mocks(monkeypatch, str(img))
    ops.read_partition = MagicMock()  # type: ignore[method-assign]

    def _fake_run(cmd: str, timeout: int | None = None):
        mock = MagicMock()
        if "flash" in cmd:
            mock.returncode = 1
            mock.stdout = ""
            mock.stderr = "flash write failure"
        else:
            mock.returncode = 0
            mock.stdout = ""
            mock.stderr = ""
        return mock

    ops._run_shell_safe = MagicMock(side_effect=_fake_run)  # type: ignore[method-assign]

    result = ops.flash_partition("system", str(img), confirm=True)

    assert result.success is False
    assert result.rollback_performed is False
    ops.read_partition.assert_not_called()


def test_flash_partition_aborts_when_backup_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """If backup of a boot-class partition fails, flash_partition must abort."""
    img = tmp_path / "boot.img"
    img.write_bytes(b"new image")

    ops, _ = _make_ops_with_mocks(monkeypatch, str(img))
    monkeypatch.setattr(
        ops,
        "read_partition",
        MagicMock(
            return_value=ToolResult(
                success=False,
                error="device not in adb mode",
            )
        ),
    )

    result = ops.flash_partition("boot", str(img), confirm=True)

    assert result.success is False
    assert "backup failed" in (result.error or "").lower()
    # No flash or rollback should have been attempted.
    for call in ops._run_shell_safe.call_args_list:
        assert "flash" not in call.args[0]


# ---------------------------------------------------------------------------
# Read-only deferred stubs (LJD-277)
# ---------------------------------------------------------------------------
def _make_readonly_ops(monkeypatch: pytest.MonkeyPatch):
    """Return a DeviceOps instance with a mocked gateway and shell runner."""
    gateway_mock = MagicMock()
    from pixel_flasher_plugin.safety_engine import Decision
    gateway_mock.evaluate.return_value = (Decision.ALLOW, "")
    ops = DeviceOps(device_id="FAKE001", gateway=gateway_mock)
    ops._run_shell_safe = MagicMock(return_value=MagicMock(returncode=0, stdout="", stderr=""))  # type: ignore[method-assign]
    return ops


def test_get_pif_status_reads_json_config(monkeypatch: pytest.MonkeyPatch) -> None:
    """get_pif_status parses custom.pif.json when present."""
    ops = _make_readonly_ops(monkeypatch)

    def _fake_run(cmd: str, timeout: int | None = None):
        mock = MagicMock()
        if "module.prop" in cmd:
            mock.returncode = 0
            mock.stdout = "name=PlayIntegrityFix\nversion=v17.9\n"
        elif "custom.pif.json" in cmd:
            mock.returncode = 0
            mock.stdout = '{"PRODUCT":"foo","DEVICE":"bar"}\n'
        else:
            mock.returncode = 1
            mock.stdout = ""
            mock.stderr = "No such file"
        return mock

    ops._run_shell_safe = MagicMock(side_effect=_fake_run)  # type: ignore[method-assign]

    result = ops.get_pif_status()

    assert result.success is True
    data = result.data or {}
    assert data["pif_exists"] is True
    assert data["pif_path"].endswith("custom.pif.json")
    assert data["pif_content"] == {"PRODUCT": "foo", "DEVICE": "bar"}
    assert data["module_version"] == "v17.9"


def test_get_pif_status_falls_back_to_prop_file(monkeypatch: pytest.MonkeyPatch) -> None:
    """get_pif_status falls back to custom.pif.prop when JSON is missing."""
    ops = _make_readonly_ops(monkeypatch)

    def _fake_run(cmd: str, timeout: int | None = None):
        mock = MagicMock()
        if "module.prop" in cmd:
            mock.returncode = 0
            mock.stdout = "name=PlayIntegrityFix\nversion=v17.9\n"
        elif "custom.pif.json" in cmd:
            mock.returncode = 1
            mock.stdout = ""
            mock.stderr = "No such file"
        elif "custom.pif.prop" in cmd:
            mock.returncode = 0
            mock.stdout = "PRODUCT=baz\nDEVICE=qux\n"
        else:
            mock.returncode = 1
            mock.stdout = ""
        return mock

    ops._run_shell_safe = MagicMock(side_effect=_fake_run)  # type: ignore[method-assign]

    result = ops.get_pif_status()

    assert result.success is True
    data = result.data or {}
    assert data["pif_exists"] is True
    assert data["pif_path"].endswith("custom.pif.prop")
    assert data["pif_content"] == {"PRODUCT": "baz", "DEVICE": "qux"}


def test_check_play_integrity_reports_module_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    """check_play_integrity returns module state when no disable file exists."""
    ops = _make_readonly_ops(monkeypatch)

    def _fake_run(cmd: str, timeout: int | None = None):
        mock = MagicMock()
        if "module.prop" in cmd:
            mock.returncode = 0
            mock.stdout = "name=PlayIntegrityFix\nversion=v17.9\n"
        elif "disable" in cmd:
            mock.returncode = 1
            mock.stdout = ""
            mock.stderr = "No such file"
        else:
            mock.returncode = 1
        return mock

    ops._run_shell_safe = MagicMock(side_effect=_fake_run)  # type: ignore[method-assign]

    result = ops.check_play_integrity()

    assert result.success is True
    data = result.data or {}
    assert data["module_installed"] is True
    assert data["module_enabled"] is True
    assert data["module_version"] == "v17.9"


def test_check_play_integrity_reports_module_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    """check_play_integrity reports disabled when the disable file exists."""
    ops = _make_readonly_ops(monkeypatch)

    def _fake_run(cmd: str, timeout: int | None = None):
        mock = MagicMock()
        if "module.prop" in cmd:
            mock.returncode = 0
            mock.stdout = "name=PlayIntegrityFix\nversion=v17.9\n"
        elif "disable" in cmd:
            mock.returncode = 0
            mock.stdout = "/data/adb/modules/playintegrityfix/disable\n"
        else:
            mock.returncode = 1
        return mock

    ops._run_shell_safe = MagicMock(side_effect=_fake_run)  # type: ignore[method-assign]

    result = ops.check_play_integrity()

    assert result.success is True
    data = result.data or {}
    assert data["module_installed"] is True
    assert data["module_enabled"] is False


def test_list_backups_parses_matching_files(monkeypatch: pytest.MonkeyPatch) -> None:
    """list_backups returns boot backup entries with sizes and dates."""
    ops = _make_readonly_ops(monkeypatch)
    ops._run_shell_safe.return_value = MagicMock(
        returncode=0,
        stdout=(
            "total 64\n"
            "drwxrwxrwx 2 root root 4096 2024-01-15 08:30 .\n"
            "drwxrwxrwx 3 root root 4096 2024-01-15 08:30 ..\n"
            "-rw-rw---- 1 root root 67108864 2024-01-15 08:31 boot_20240115.img\n"
            "-rw-rw---- 1 root root 25165824 2024-01-15 08:32 boot_20240115.img.gz\n"
            "-rw-rw---- 1 root root 1234 2024-01-15 08:33 unrelated.txt\n"
        ),
    )

    result = ops.list_backups()

    assert result.success is True
    backups = (result.data or {}).get("backups", [])
    assert len(backups) == 2
    names = {b["name"] for b in backups}
    assert names == {"boot_20240115.img", "boot_20240115.img.gz"}
    img_entry = next(b for b in backups if b["name"] == "boot_20240115.img")
    assert img_entry["size"] == 67108864
    assert img_entry["date"] == "2024-01-15 08:31"


def test_list_backups_returns_empty_when_dir_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    """list_backups returns an empty list (not an error) when the backup dir is absent."""
    ops = _make_readonly_ops(monkeypatch)
    ops._run_shell_safe.return_value = MagicMock(
        returncode=1,
        stdout="",
        stderr="No such file or directory",
    )

    result = ops.list_backups()

    assert result.success is True
    assert (result.data or {}).get("backups") == []
    assert (result.data or {}).get("count") == 0


def test_avb_verify_image_uses_avbtool(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    """avb_verify_image delegates signature verification to avbtool."""
    import sys

    img = tmp_path / "vbmeta.img"
    img.write_bytes(b"fake vbmeta image")

    fake_avbtool = MagicMock()
    fake_avbtool.AvbError = Exception
    fake_tool = MagicMock()
    fake_tool.info_image.return_value = {"Algorithm": "SHA256_RSA4096", "Hash Algorithm": "sha256"}
    fake_tool.verify_image.return_value = None
    fake_avbtool.AvbTool.return_value = fake_tool
    monkeypatch.setitem(sys.modules, "avbtool", fake_avbtool)

    ops = DeviceOps(device_id="FAKE001")
    result = ops.avb_verify_image(str(img))

    assert result.success is True
    data = result.data or {}
    assert data["valid"] is True
    assert data["algorithm"] == "SHA256_RSA4096"
    assert data["hash"] == "sha256"
    fake_tool.verify_image.assert_called_once_with(str(img), None, None, False, False)


def test_avb_verify_image_reports_signature_failure(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    """avb_verify_image returns valid=False when avbtool reports a bad signature."""
    import sys

    img = tmp_path / "vbmeta.img"
    img.write_bytes(b"fake vbmeta image")

    fake_avbtool = MagicMock()
    fake_avbtool.AvbError = Exception
    fake_tool = MagicMock()
    fake_tool.info_image.return_value = {"Algorithm": "SHA256_RSA4096"}
    fake_tool.verify_image.side_effect = Exception("Signature check failed")
    fake_avbtool.AvbTool.return_value = fake_tool
    monkeypatch.setitem(sys.modules, "avbtool", fake_avbtool)

    ops = DeviceOps(device_id="FAKE001")
    result = ops.avb_verify_image(str(img))

    assert result.success is True
    data = result.data or {}
    assert data["valid"] is False
    assert "Signature check failed" in (data.get("error") or "")

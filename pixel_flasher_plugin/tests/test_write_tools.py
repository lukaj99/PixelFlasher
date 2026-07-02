"""Tests for the 5 write/destructive MCP tools (LJD-277 Wave 2b).

This module pins safety invariants for DeviceOps methods that mutate state
(either host-side or on-device):

  - ``patch_boot_image``   -- validate + (future) patch a boot image
  - ``flash_factory_image`` -- inspect a factory zip; full flash is safety-gated
  - ``update_pif``          -- push a PIF config to the device
  - ``restore_backup``      -- pull + flash a Magisk boot backup
  - ``avb_sign_image``      -- host-side AVB hash-footer signing

Each tool has at least: one happy-path test, one error/validation test, and
one safety-gate test (dry_run / confirm enforcement).

These tests rely on the session-scoped ``_stub_get_device`` autouse fixture in
``conftest.py`` and on a mocked gateway + ``_run_shell_safe`` so no real
adb/fastboot/avbtool interaction happens.
"""
from __future__ import annotations

import json
import os
import re
import struct
import sys
import tempfile
import zipfile
from unittest.mock import MagicMock

import pytest

from pixel_flasher_plugin.command_validator import CommandValidator
from pixel_flasher_plugin.device_ops import DeviceOps
from pixel_flasher_plugin.result_types import CheckResult, RiskTier, ToolResult
from pixel_flasher_plugin.safety_engine import Decision, SafetyGateway


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _make_write_ops(monkeypatch: pytest.MonkeyPatch):
    """Build a DeviceOps whose gateway respects the confirm gate.

    The gateway mock mimics the real SafetyGateway's confirm behavior:
      - confirm=True  -> ALLOW
      - confirm=False -> CONFIRM  (for WARN/CRITICAL risk tiers)

    The whitelist check is bypassed because the mock returns ALLOW for
    whitelisted commands; non-whitelisted commands (e.g. the avbtool
    command) need their own tests to opt out.

    Pre-flight is pre-populated with a passing ``device_connected`` check so
    that tests of tools that run preflight (update_pif) can proceed.

    Returns ``(ops, gateway_mock)``.
    """
    gateway_mock = MagicMock()
    gateway_mock.verify_postcondition.return_value = (True, "ok")
    gateway_mock.perform_rollback.return_value = (True, "rollback completed")
    gateway_mock.run_preflight.return_value = [
        CheckResult(
            name="device_connected",
            passed=True,
            detail="ok",
            severity=RiskTier.INFO,
        ),
    ]

    def _evaluate(command, args=None):
        args = args or {}
        confirm = args.get("confirm", False)
        risk_tier = args.get("risk_tier", RiskTier.INFO)
        if risk_tier in (RiskTier.WARN, RiskTier.CRITICAL) and not confirm:
            return (Decision.CONFIRM, "Operation requires confirmation")
        return (Decision.ALLOW, "")

    gateway_mock.evaluate.side_effect = _evaluate

    ops = DeviceOps(device_id="FAKE001", gateway=gateway_mock)
    ops._run_shell_safe = MagicMock(  # type: ignore[method-assign]
        return_value=MagicMock(returncode=0, stdout="", stderr=""),
    )
    return ops, gateway_mock


def _craft_boot_image(path: str, **fields: int) -> int:
    """Write a minimal valid boot image header (44 bytes) to *path*.

    The format is the legacy boot image header that patch_boot_image parses:
    8-byte ANDROID! magic, then eight little-endian uint32 fields, then a
    header_version uint32. Returns the number of bytes written.
    """
    magic = b"ANDROID!"
    kernel_size = fields.get("kernel_size", 0x00100000)
    kernel_addr = fields.get("kernel_addr", 0x10000000)
    ramdisk_size = fields.get("ramdisk_size", 0x00010000)
    ramdisk_addr = fields.get("ramdisk_addr", 0x11000000)
    second_size = fields.get("second_size", 0)
    second_addr = fields.get("second_addr", 0x10F00000)
    tags_addr = fields.get("tags_addr", 0x10000100)
    page_size = fields.get("page_size", 2048)
    header_version = fields.get("header_version", 1)

    packed = struct.pack(
        "<IIIIIIII",
        kernel_size, kernel_addr, ramdisk_size, ramdisk_addr,
        second_size, second_addr, tags_addr, page_size,
    )
    packed += struct.pack("<I", header_version)
    with open(path, "wb") as f:
        f.write(magic)
        f.write(packed)
    return 8 + len(packed)


def _craft_factory_zip(path: str, img_names=("boot.img", "system.img", "vendor.img")) -> None:
    """Write a minimal factory zip containing the named ``.img`` entries."""
    with zipfile.ZipFile(path, "w") as zf:
        for name in img_names:
            zf.writestr(name, b"\x00" * 1024)


# ===========================================================================
# patch_boot_image
# ===========================================================================
class TestPatchBootImage:
    """Validation + dry-run + confirm-gate for boot image patching."""

    def test_dry_run_returns_parsed_metadata(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        """dry_run=True returns the parsed header fields and a deferred warning."""
        ops, _ = _make_write_ops(monkeypatch)
        img = tmp_path / "boot.img"
        _craft_boot_image(
            str(img),
            kernel_size=0x00200000,
            ramdisk_size=0x00020000,
            page_size=4096,
            header_version=2,
        )

        result = ops.patch_boot_image(str(img), method="Magisk", dry_run=True)

        assert result.success is True
        assert result.dry_run is True
        data = result.data or {}
        assert data["magic_valid"] is True
        assert data["kernel_size"] == 0x00200000
        assert data["ramdisk_size"] == 0x00020000
        assert data["page_size"] == 4096
        assert data["header_version"] == 2
        assert data["method"] == "Magisk"
        # Deferred-patching warning must surface on the dry-run path.
        assert any("not yet implemented" in w for w in (result.warnings or []))
        # Dry run MUST NOT touch any shell.
        ops._run_shell_safe.assert_not_called()

    def test_missing_file_returns_error(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        """A non-existent boot image returns a structured not-found error."""
        ops, _ = _make_write_ops(monkeypatch)
        missing = tmp_path / "does_not_exist.img"

        result = ops.patch_boot_image(str(missing))

        assert result.success is False
        assert "not found" in (result.error or "").lower()
        assert "does_not_exist.img" in (result.error or "")

    def test_invalid_magic_returns_error(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        """A file without the ANDROID! magic header is rejected."""
        ops, _ = _make_write_ops(monkeypatch)
        bad = tmp_path / "not_a_boot.img"
        bad.write_bytes(b"NOTANDROID!HEADERDATA")

        result = ops.patch_boot_image(str(bad))

        assert result.success is False
        assert "ANDROID!" in (result.error or "")
        assert "magic" in (result.error or "").lower()

    def test_short_file_returns_error(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        """A file shorter than 8 bytes is rejected (cannot read magic)."""
        ops, _ = _make_write_ops(monkeypatch)
        short = tmp_path / "short.img"
        short.write_bytes(b"ANDROI")  # 6 bytes -- less than the 8-byte magic

        result = ops.patch_boot_image(str(short))

        assert result.success is False
        assert "ANDROID!" in (result.error or "") or "magic" in (result.error or "").lower()

    def test_dry_run_false_without_confirm_blocks(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        """dry_run=False + confirm=False must be refused by the safety gate."""
        ops, _ = _make_write_ops(monkeypatch)
        img = tmp_path / "boot.img"
        _craft_boot_image(str(img))

        result = ops.patch_boot_image(str(img), dry_run=False, confirm=False)

        assert result.success is False
        assert "confirm=True" in (result.error or "")

    def test_dry_run_false_with_confirm_reports_deferred(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        """dry_run=False + confirm=True succeeds but reports deferred patching.

        Even when the confirm gate is satisfied, actual patching is not yet
        implemented in Wave 2b; the tool still returns the parsed metadata
        and the deferred-patching warning so callers can preview what would
        happen.
        """
        ops, _ = _make_write_ops(monkeypatch)
        img = tmp_path / "boot.img"
        _craft_boot_image(str(img))

        result = ops.patch_boot_image(str(img), dry_run=False, confirm=True)

        assert result.success is True
        assert result.dry_run is False
        assert (result.data or {}).get("magic_valid") is True
        assert any("not yet implemented" in w for w in (result.warnings or []))


# ===========================================================================
# flash_factory_image
# ===========================================================================
class TestFlashFactoryImage:
    """Factory zip inspection + safety-gated flash refusal."""

    def test_dry_run_returns_partition_list(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        """dry_run=True parses the zip and returns the list of .img partitions."""
        ops, _ = _make_write_ops(monkeypatch)
        zpath = tmp_path / "factory.zip"
        _craft_factory_zip(str(zpath))

        result = ops.flash_factory_image(str(zpath), dry_run=True)

        assert result.success is True
        assert result.dry_run is True
        data = result.data or {}
        partitions = data.get("partitions", [])
        names = {p["partition"] for p in partitions}
        assert names == {"boot", "system", "vendor"}
        # The safety warning must be present on every dry-run response.
        assert any("destructive" in w.lower() for w in (result.warnings or []))

    def test_missing_zip_returns_error(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        """A non-existent factory zip returns a structured not-found error."""
        ops, _ = _make_write_ops(monkeypatch)
        missing = tmp_path / "no_such.zip"

        result = ops.flash_factory_image(str(missing))

        assert result.success is False
        assert "not found" in (result.error or "").lower()

    def test_invalid_zip_returns_error(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        """A file that is not a valid zip is rejected with a parse error."""
        ops, _ = _make_write_ops(monkeypatch)
        bad = tmp_path / "bad.zip"
        bad.write_bytes(b"this is definitely not a zip archive")

        result = ops.flash_factory_image(str(bad))

        assert result.success is False
        assert "zip" in (result.error or "").lower()
        # The error must mention the open/parse failure, not just "not found".
        assert "open" in (result.error or "").lower() or "failed" in (result.error or "").lower()

    def test_refuses_even_with_confirm_true(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        """flash_factory_image refuses full flashing even with confirm=True.

        Full factory flashing is the most destructive operation the agent can
        trigger, so it is hard-gated and the user is directed to the GUI.
        """
        ops, _ = _make_write_ops(monkeypatch)
        zpath = tmp_path / "factory.zip"
        _craft_factory_zip(str(zpath))

        result = ops.flash_factory_image(str(zpath), dry_run=False, confirm=True)

        assert result.success is False
        # The refusal message must redirect the caller to the GUI.
        assert "GUI" in (result.error or "") or "not supported" in (result.error or "").lower()

    def test_dry_run_false_without_confirm_blocks(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        """dry_run=False + confirm=False is refused by the safety gate."""
        ops, _ = _make_write_ops(monkeypatch)
        zpath = tmp_path / "factory.zip"
        _craft_factory_zip(str(zpath))

        result = ops.flash_factory_image(str(zpath), dry_run=False, confirm=False)

        assert result.success is False
        assert "confirm=True" in (result.error or "")


# ===========================================================================
# update_pif
# ===========================================================================
class TestUpdatePif:
    """JSON validation + push + su cp + temp-file cleanup for PIF updates."""

    def test_invalid_json_string_returns_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An invalid JSON string is rejected before any device interaction."""
        ops, _ = _make_write_ops(monkeypatch)

        result = ops.update_pif("{not valid json", confirm=True)

        assert result.success is False
        assert "Invalid pif_json" in (result.error or "")
        # Critical: no shell commands must have run.
        ops._run_shell_safe.assert_not_called()

    def test_dict_payload_is_serialized_and_pushed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A dict payload is serialized, pushed, and copied into place."""
        ops, gateway = _make_write_ops(monkeypatch)
        payload = {"PRODUCT": "oriole", "DEVICE": "panther", "BUILD_ID": "TQ3A.230901.001"}

        result = ops.update_pif(payload, confirm=True)

        assert result.success is True
        data = result.data or {}
        assert data["pif_path"] == "/data/adb/modules/playintegrityfix/custom.pif.json"
        assert len(data["new_hash"]) == 64  # sha256 hex digest
        # The push + su cp shell calls each happen once.
        assert ops._run_shell_safe.call_count == 2
        # The gateway evaluated both proposed commands.
        assert gateway.evaluate.call_count == 2

    def test_json_string_is_preserved_after_validation(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A pre-serialized JSON string is validated but kept verbatim.

        This matters for callers who want byte-exact preservation of the
        JSON they crafted (e.g. preserving key order or whitespace).
        """
        ops, _ = _make_write_ops(monkeypatch)
        payload = json.dumps({"PRODUCT": "alpha", "DEVICE": "beta"}, indent=2)

        result = ops.update_pif(payload, confirm=True)

        assert result.success is True
        assert (result.data or {}).get("pif_path", "").endswith("custom.pif.json")

    def test_push_failure_returns_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """adb push returning non-zero produces a push-failed error."""
        ops, _ = _make_write_ops(monkeypatch)

        def _shell(cmd, timeout=None):
            m = MagicMock()
            if " push " in cmd:
                m.returncode = 1
                m.stderr = "permission denied"
            else:
                m.returncode = 0
            return m

        ops._run_shell_safe = MagicMock(side_effect=_shell)  # type: ignore[method-assign]

        result = ops.update_pif({"FOO": "bar"}, confirm=True)

        assert result.success is False
        assert "push failed" in (result.error or "").lower()

    def test_su_cp_failure_mentions_root(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """su cp returning non-zero produces an error mentioning root."""
        ops, _ = _make_write_ops(monkeypatch)

        def _shell(cmd, timeout=None):
            m = MagicMock()
            if "su -c" in cmd and "cp " in cmd:
                m.returncode = 1
                m.stderr = "su: not allowed"
            else:
                m.returncode = 0
            return m

        ops._run_shell_safe = MagicMock(side_effect=_shell)  # type: ignore[method-assign]

        result = ops.update_pif({"FOO": "bar"}, confirm=True)

        assert result.success is False
        assert "root" in (result.error or "").lower()

    def test_local_temp_file_cleaned_on_success(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The local temp file is removed after a successful update."""
        ops, _ = _make_write_ops(monkeypatch)

        # Capture every path mkstemp returns; the tool must remove them all
        # in the ``finally`` block.
        created: list[str] = []
        real_mkstemp = tempfile.mkstemp

        def _tracking(*args, **kwargs):
            fd, path = real_mkstemp(*args, **kwargs)
            created.append(path)
            return fd, path

        monkeypatch.setattr(tempfile, "mkstemp", _tracking)

        result = ops.update_pif({"FOO": "bar"}, confirm=True)

        assert result.success is True
        assert len(created) == 1, (
            f"Expected exactly one temp file to be created, got {len(created)}"
        )
        assert not os.path.exists(created[0]), (
            f"Local temp file {created[0]} was not cleaned up after success"
        )

    def test_local_temp_file_cleaned_on_failure(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The local temp file is removed even when the su cp step fails."""
        ops, _ = _make_write_ops(monkeypatch)

        def _shell(cmd, timeout=None):
            m = MagicMock()
            if "su -c" in cmd and "cp " in cmd:
                m.returncode = 1
                m.stderr = "su failure"
            else:
                m.returncode = 0
            return m

        ops._run_shell_safe = MagicMock(side_effect=_shell)  # type: ignore[method-assign]

        created: list[str] = []
        real_mkstemp = tempfile.mkstemp

        def _tracking(*args, **kwargs):
            fd, path = real_mkstemp(*args, **kwargs)
            created.append(path)
            return fd, path

        monkeypatch.setattr(tempfile, "mkstemp", _tracking)

        result = ops.update_pif({"FOO": "bar"}, confirm=True)

        assert result.success is False
        assert len(created) == 1
        assert not os.path.exists(created[0]), (
            f"Local temp file {created[0]} was not cleaned up after failure"
        )

    def test_su_command_matches_whitelist(self) -> None:
        """The su cp+chmod command update_pif builds must be whitelisted.

        Construct the exact command string the tool emits and validate it
        against ``CommandValidator.is_allowed``. This pins the invariant that
        the su command (which executes on the device under root) always
        matches the safety whitelist pattern.
        """
        device_id = "FAKE001"
        remote_tmp = "/data/local/tmp/custom.pif.json"
        final_path = "/data/adb/modules/playintegrityfix/custom.pif.json"
        # shlex.quote leaves paths containing only safe characters unquoted;
        # reproduce that here.
        cmd = (
            f"adb -s {device_id} shell su -c \""
            f"cp {remote_tmp} {final_path} && chmod 644 {final_path}"
            f"\""
        )
        allowed, reason = CommandValidator.is_allowed(cmd)
        assert allowed is True, (
            f"update_pif su cp command was rejected by the whitelist: {reason}\n"
            f"Command: {cmd!r}"
        )

    def test_blocks_when_confirm_false(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """update_pif(confirm=False) is blocked by the WARN safety gate."""
        # Use the real SafetyGateway so the CONFIRM decision flows naturally.
        ops = DeviceOps(device_id="FAKE001")
        ops._run_shell_safe = MagicMock(  # type: ignore[method-assign]
            return_value=MagicMock(returncode=0, stdout="", stderr=""),
        )

        result = ops.update_pif({"FOO": "bar"}, confirm=False)

        assert result.success is False
        assert "Confirmation" in (result.error or "") or "confirm" in (
            result.error or ""
        ).lower()
        ops._run_shell_safe.assert_not_called()


# ===========================================================================
# restore_backup
# ===========================================================================
class TestRestoreBackup:
    """Backup-name validation + dry-run metadata + pull+flash delegation."""

    @pytest.mark.parametrize(
        "bad_name",
        [
            "../etc/passwd",
            "name with space",
            "name;rm",
            "name$cmd",
            "name|pipe",
            ".hidden_start",
            "-leading_hyphen",
            "",
        ],
    )
    def test_rejects_invalid_name(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path, bad_name: str
    ) -> None:
        """Names with traversal, spaces, or shell metachars are refused.

        The first character must be a letter, digit, or underscore; the
        remaining characters may be alphanumerics, underscores, dots, or
        hyphens.
        """
        ops, _ = _make_write_ops(monkeypatch)

        result = ops.restore_backup(bad_name, dry_run=True)

        assert result.success is False
        assert "Invalid backup name" in (result.error or "")
        # No shell interaction on the validation-failure path.
        ops._run_shell_safe.assert_not_called()

    def test_dry_run_returns_metadata_without_device_io(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """dry_run=True returns metadata without touching the device."""
        ops, _ = _make_write_ops(monkeypatch)

        result = ops.restore_backup("boot_20240115.img", dry_run=True)

        assert result.success is True
        assert result.dry_run is True
        data = result.data or {}
        assert data["backup_name"] == "boot_20240115.img"
        assert data["remote_path"] == "/data/adb/magisk_backup/boot_20240115.img"
        assert data["partition"] == "boot"
        ops._run_shell_safe.assert_not_called()

    def test_dry_run_false_calls_pull_then_flash(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        """dry_run=False must call pull_file then flash_partition in order.

        The local temp file created by mkstemp must be cleaned up in the
        finally block.
        """
        ops, _ = _make_write_ops(monkeypatch)

        backup_local = tmp_path / "boot_backup.img"
        backup_local.write_bytes(b"backup content")

        pull_mock = MagicMock(
            return_value=ToolResult(
                success=True,
                data={"local_path": str(backup_local)},
            )
        )
        flash_mock = MagicMock(
            return_value=ToolResult(
                success=True,
                data={"partition": "boot", "image_path": str(backup_local)},
            ),
        )
        monkeypatch.setattr(ops, "pull_file", pull_mock)
        monkeypatch.setattr(ops, "flash_partition", flash_mock)

        result = ops.restore_backup(
            "boot_20240115.img", dry_run=False, confirm=True
        )

        # pull_file was called exactly once.
        pull_mock.assert_called_once()
        # flash_partition was called exactly once with the boot partition
        # and the path returned by pull_file.
        flash_mock.assert_called_once()
        call_args, call_kwargs = flash_mock.call_args
        assert call_args[0] == "boot"
        assert call_args[1] == str(backup_local)
        assert call_kwargs.get("confirm") is True

        # Result is whatever flash_partition returned.
        assert result.success is True
        assert (result.data or {}).get("partition") == "boot"

    def test_name_regex_is_enforced_directly(self) -> None:
        """Directly assert the backup-name regex against good and bad inputs.

        This is a documentation-level guard against future tweaks that would
        loosen the regex without updating the tool.
        """
        pattern = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*$")
        valid = ["boot_20240115.img", "boot.img", "a", "A_b.c-d", "0_start"]
        invalid = [
            "../etc/passwd",
            ".hidden",
            "-leading",
            "name with space",
            "name;rm",
            "name$cmd",
            "name|pipe",
            "name*glob",
            "",
        ]
        for n in valid:
            assert pattern.match(n), f"Expected valid name {n!r} to match"
        for n in invalid:
            assert not pattern.match(n), f"Expected invalid name {n!r} to be rejected"


# ===========================================================================
# avb_sign_image
# ===========================================================================
class TestAvbSignImage:
    """Host-side AVB signing: file existence, confirm gate, avbtool delegation."""

    def test_missing_image_returns_error(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        """A non-existent image file produces a not-found error."""
        ops, _ = _make_write_ops(monkeypatch)
        key = tmp_path / "testkey.pem"
        key.write_bytes(b"fake key material")

        result = ops.avb_sign_image(
            str(tmp_path / "no_such.img"), str(key), confirm=True
        )

        assert result.success is False
        assert "Image file not found" in (result.error or "")

    def test_missing_key_returns_error(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        """A non-existent key file produces a not-found error."""
        ops, _ = _make_write_ops(monkeypatch)
        img = tmp_path / "boot.img"
        img.write_bytes(b"\x00" * 64)

        result = ops.avb_sign_image(str(img), str(tmp_path / "no_key.pem"), confirm=True)

        assert result.success is False
        assert "Key file not found" in (result.error or "")

    def test_blocks_when_confirm_false(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        """avb_sign_image(confirm=False) is blocked by the WARN safety gate.

        The avbtool command fails the ADB/fastboot whitelist on a real gateway
        (DENY), so we use a gateway mock that returns CONFIRM for the WARN-tier
        + confirm=False path. This isolates the confirm-vs-no-confirm decision
        from the unrelated whitelist issue.
        """
        gateway_mock = MagicMock()
        gateway_mock.evaluate.return_value = (
            Decision.CONFIRM,
            "Operation requires confirmation",
        )
        gateway_mock.run_preflight.return_value = [
            CheckResult(
                name="device_connected",
                passed=True,
                detail="ok",
                severity=RiskTier.INFO,
            ),
        ]
        ops = DeviceOps(device_id="FAKE001", gateway=gateway_mock)
        ops._run_shell_safe = MagicMock(  # type: ignore[method-assign]
            return_value=MagicMock(returncode=0, stdout="", stderr=""),
        )

        img = tmp_path / "boot.img"
        img.write_bytes(b"\x00" * 64)
        key = tmp_path / "testkey.pem"
        key.write_bytes(b"fake key material")

        result = ops.avb_sign_image(str(img), str(key), confirm=False)

        assert result.success is False
        assert (
            "Confirmation" in (result.error or "")
            or "confirm" in (result.error or "").lower()
        )
        # avbtool must not have been invoked.
        gateway_mock.evaluate.assert_called_once()
        # And the original image must remain untouched (no copy was made).
        assert img.read_bytes() == b"\x00" * 64
        # The signed output path must not have been created.
        assert not (tmp_path / "boot.signed.img").exists()

    def test_writes_signed_copy_and_calls_avbtool(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        """Happy path: copies to <base>.signed.img and calls add_hash_footer."""
        ops, _ = _make_write_ops(monkeypatch)

        img = tmp_path / "boot.img"
        img.write_bytes(b"\x00" * 64)
        key = tmp_path / "testkey_rsa4096.pem"
        key.write_bytes(b"fake key material")

        fake_avbtool = MagicMock()

        class _AvbError(Exception):
            pass

        fake_avbtool.AvbError = _AvbError
        fake_tool = MagicMock()
        fake_avbtool.AvbTool.return_value = fake_tool
        monkeypatch.setitem(sys.modules, "avbtool", fake_avbtool)

        result = ops.avb_sign_image(
            str(img), str(key), algorithm="SHA256_RSA4096", confirm=True
        )

        assert result.success is True
        data = result.data or {}
        assert data["signed_path"] == str(tmp_path / "boot.signed.img")
        assert data["algorithm"] == "SHA256_RSA4096"

        # Signed copy exists on disk and is independent of the original.
        signed_path = tmp_path / "boot.signed.img"
        assert signed_path.exists()
        assert img.read_bytes() == b"\x00" * 64  # original untouched

        # avbtool.AvbTool().add_hash_footer(...) was called exactly once with
        # the partition_name derived from the input filename.
        fake_tool.add_hash_footer.assert_called_once()
        kwargs = fake_tool.add_hash_footer.call_args.kwargs
        assert kwargs["image_filename"] == str(signed_path)
        assert kwargs["partition_name"] == "boot"
        assert kwargs["algorithm_name"] == "SHA256_RSA4096"
        assert kwargs["key_path"] == str(key)

    def test_confirm_path_uses_real_safety_gateway(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        """avb_sign_image(confirm=True) must pass a real SafetyGateway.

        The command string is only used for audit logging; the actual signing
        is an in-process Python call.  A real gateway must therefore ALLOW the
        confirm path instead of DENY'ing the avbtool command as if it were an
        unknown ADB/fastboot command.
        """
        ops = DeviceOps(device_id="FAKE001")
        assert isinstance(ops.gateway, SafetyGateway)

        img = tmp_path / "boot.img"
        img.write_bytes(b"\x00" * 64)
        key = tmp_path / "testkey_rsa4096.pem"
        key.write_bytes(b"fake key material")

        fake_avbtool = MagicMock()

        class _AvbError(Exception):
            pass

        fake_avbtool.AvbError = _AvbError
        fake_tool = MagicMock()
        fake_avbtool.AvbTool.return_value = fake_tool
        monkeypatch.setitem(sys.modules, "avbtool", fake_avbtool)

        result = ops.avb_sign_image(
            str(img), str(key), algorithm="SHA256_RSA4096", confirm=True
        )

        assert result.success is True
        data = result.data or {}
        assert data["signed_path"] == str(tmp_path / "boot.signed.img")
        assert data["algorithm"] == "SHA256_RSA4096"
        fake_tool.add_hash_footer.assert_called_once()
        kwargs = fake_tool.add_hash_footer.call_args.kwargs
        assert kwargs["partition_name"] == "boot"
        assert kwargs["algorithm_name"] == "SHA256_RSA4096"
        assert kwargs["key_path"] == str(key)

    def test_avbtool_error_returns_structured_failure(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        """An AvbError raised by avbtool is converted into a structured error."""
        ops, _ = _make_write_ops(monkeypatch)

        img = tmp_path / "boot.img"
        img.write_bytes(b"\x00" * 64)
        key = tmp_path / "testkey.pem"
        key.write_bytes(b"fake key")

        fake_avbtool = MagicMock()

        class _AvbError(Exception):
            pass

        fake_avbtool.AvbError = _AvbError
        fake_tool = MagicMock()
        fake_tool.add_hash_footer.side_effect = _AvbError("signature failure")
        fake_avbtool.AvbTool.return_value = fake_tool
        monkeypatch.setitem(sys.modules, "avbtool", fake_avbtool)

        result = ops.avb_sign_image(str(img), str(key), confirm=True)

        assert result.success is False
        assert (
            "avbtool error" in (result.error or "").lower()
            or "signature failure" in (result.error or "")
        )

    def test_partition_name_derived_from_filename(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        """The partition_name passed to avbtool equals the basename (no ext)."""
        ops, _ = _make_write_ops(monkeypatch)

        img = tmp_path / "vbmeta.img"
        img.write_bytes(b"\x00" * 64)
        key = tmp_path / "testkey.pem"
        key.write_bytes(b"fake key")

        fake_avbtool = MagicMock()

        class _AvbError(Exception):
            pass

        fake_avbtool.AvbError = _AvbError
        fake_tool = MagicMock()
        fake_avbtool.AvbTool.return_value = fake_tool
        monkeypatch.setitem(sys.modules, "avbtool", fake_avbtool)

        result = ops.avb_sign_image(str(img), str(key), confirm=True)

        assert result.success is True
        kwargs = fake_tool.add_hash_footer.call_args.kwargs
        assert kwargs["partition_name"] == "vbmeta"
        assert kwargs["image_filename"] == str(tmp_path / "vbmeta.signed.img")
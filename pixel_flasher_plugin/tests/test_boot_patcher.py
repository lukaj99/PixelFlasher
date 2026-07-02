"""Tests for the boot-patch script generators and patching facade.

These tests exercise ``pixel_flasher_plugin.boot_patcher`` and the
``patch_boot_image`` flow with a fully mocked device/runtime.
"""
from __future__ import annotations

import zipfile
from unittest.mock import MagicMock

import pytest

from pixel_flasher_plugin import boot_patcher
from pixel_flasher_plugin.tests.test_write_tools import _craft_boot_image, _make_write_ops


def _apk_zip(path: str) -> None:
    """Write a minimal valid APK-shaped ZIP to *path*."""
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("assets/boot_patch.sh", b"#!/system/bin/sh\n")


def _make_apatch_zip(tmp_path) -> str:
    apk = tmp_path / "apatch.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("assets/boot_patch.sh", b"#!/system/bin/sh\n")
    return str(apk)


class TestScriptGenerators:
    """Pure-function script generation."""

    def test_generate_magisk_script_contains_boot_path(self) -> None:
        script = boot_patcher.generate_magisk_script(
            boot_path="/data/local/tmp/stock_boot.img",
            work_dir="/data/local/tmp/pf",
            zip_path="/data/local/tmp/pf.zip",
            out_dir="/data/local/tmp",
            arch="arm64-v8a",
            stock_sha1="deadbeef",
            version_code="27000",
        )
        assert "./boot_patch.sh" in script
        assert "/data/local/tmp/stock_boot.img" in script
        assert "magisk_patched" in script

    def test_generate_ksu_script_uses_ksud(self) -> None:
        script = boot_patcher.generate_ksu_script(
            boot_path="/data/local/tmp/stock_boot.img",
            work_dir="/data/local/tmp/pf",
            zip_path="/data/local/tmp/pf.zip",
            out_dir="/data/local/tmp",
            arch="arm64-v8a",
            stock_sha1="deadbeef",
            version_code="12000",
            method="KernelSU",
        )
        assert "ksud boot-patch" in script
        assert "kernelsu_patched" in script

    def test_generate_ksu_script_sukisu_old_uses_zakozako(self) -> None:
        script = boot_patcher.generate_ksu_script(
            boot_path="/data/local/tmp/stock_boot.img",
            work_dir="/data/local/tmp/pf",
            zip_path="/data/local/tmp/pf.zip",
            out_dir="/data/local/tmp",
            arch="arm64-v8a",
            stock_sha1="deadbeef",
            version_code="39999",
            method="SukiSU",
        )
        assert "zakozako boot-patch" in script
        assert "zakoboot" in script

    def test_generate_ksu_script_sukisu_new_uses_ksud(self) -> None:
        script = boot_patcher.generate_ksu_script(
            boot_path="/data/local/tmp/stock_boot.img",
            work_dir="/data/local/tmp/pf",
            zip_path="/data/local/tmp/pf.zip",
            out_dir="/data/local/tmp",
            arch="arm64-v8a",
            stock_sha1="deadbeef",
            version_code="40000",
            method="SukiSU",
        )
        assert "ksud boot-patch" in script
        assert "zakozako" not in script

    def test_generate_ksu_script_mount_type_overlayfs(self) -> None:
        script = boot_patcher.generate_ksu_script(
            boot_path="/data/local/tmp/stock_boot.img",
            work_dir="/data/local/tmp/pf",
            zip_path="/data/local/tmp/pf.zip",
            out_dir="/data/local/tmp",
            arch="arm64-v8a",
            stock_sha1="deadbeef",
            version_code="32857",
            method="KernelSU-Next",
            mount_type="overlayfs",
        )
        assert "ksud_overlayfs boot-patch" in script

    def test_generate_apatch_script_hides_superkey_in_env(self) -> None:
        script = boot_patcher.generate_apatch_script(
            boot_path="/data/local/tmp/stock_boot.img",
            work_dir="/data/local/tmp/pf",
            zip_path="/data/local/tmp/pf.zip",
            out_dir="/data/local/tmp",
            arch="arm64-v8a",
            stock_sha1="deadbeef",
            superkey="S3cr3tK3y",
            version_code="10400",
        )
        assert "APATCH_SUPERKEY=" in script
        assert "S3cr3tK3y" in script
        assert "set -- \"$APATCH_SUPERKEY\"" in script
        assert "boot_patch.sh" in script

    def test_parse_patch_log_extracts_all_fields(self) -> None:
        log = "magisk_patched_27000_abc12345_def67890.img\n27000\ndef67890\n"
        parsed = boot_patcher.parse_patch_log(log)
        assert parsed == {
            "patched_filename": "magisk_patched_27000_abc12345_def67890.img",
            "version": "27000",
            "patch_sha1": "def67890",
        }

    def test_parse_patch_log_handles_empty_log(self) -> None:
        parsed = boot_patcher.parse_patch_log("")
        assert parsed == {
            "patched_filename": None,
            "version": None,
            "patch_sha1": None,
        }


class TestPatchBootImageFacade:
    """DeviceOps.patch_boot_image safety and validation invariants."""

    def test_dry_run_returns_script_preview_without_shell(self, monkeypatch, tmp_path):
        ops, _ = _make_write_ops(monkeypatch)
        img = tmp_path / "boot.img"
        _craft_boot_image(str(img))
        apk = tmp_path / "magisk.apk"
        _apk_zip(str(apk))

        result = ops.patch_boot_image(
            str(img), method="Magisk", apk_path=str(apk), dry_run=True
        )

        assert result.success is True
        assert result.dry_run is True
        assert "script_preview" in (result.data or {})
        assert "boot_patch.sh" in (result.data or {}).get("script_preview", "")
        ops._run_shell_safe.assert_not_called()

    def test_refuses_without_confirm(self, monkeypatch, tmp_path):
        ops, _ = _make_write_ops(monkeypatch)
        img = tmp_path / "boot.img"
        _craft_boot_image(str(img))
        apk = tmp_path / "magisk.apk"
        _apk_zip(str(apk))

        result = ops.patch_boot_image(
            str(img), method="Magisk", apk_path=str(apk), dry_run=False, confirm=False
        )

        assert result.success is False
        assert "confirm=True" in (result.error or "")

    def test_apatch_superkey_validation(self, monkeypatch, tmp_path):
        ops, _ = _make_write_ops(monkeypatch)
        img = tmp_path / "boot.img"
        _craft_boot_image(str(img))
        apk = tmp_path / "apatch.apk"
        _apk_zip(str(apk))

        # Too short
        result = ops.patch_boot_image(
            str(img),
            method="APatch",
            apk_path=str(apk),
            superkey="short1",
            dry_run=True,
        )
        assert result.success is False
        assert "superkey" in (result.error or "").lower()

        # Missing digit
        result = ops.patch_boot_image(
            str(img),
            method="APatch",
            apk_path=str(apk),
            superkey="SecretKey",
            dry_run=True,
        )
        assert result.success is False

        # Missing letter
        result = ops.patch_boot_image(
            str(img),
            method="APatch",
            apk_path=str(apk),
            superkey="12345678",
            dry_run=True,
        )
        assert result.success is False

        # Valid
        result = ops.patch_boot_image(
            str(img),
            method="APatch",
            apk_path=str(apk),
            superkey="S3cr3tK3y",
            dry_run=True,
        )
        assert result.success is True

    def test_apk_validation_rejects_non_zip(self, monkeypatch, tmp_path):
        ops, _ = _make_write_ops(monkeypatch)
        img = tmp_path / "boot.img"
        _craft_boot_image(str(img))
        not_apk = tmp_path / "not_apk.txt"
        not_apk.write_text("not a zip")

        result = ops.patch_boot_image(
            str(img), method="Magisk", apk_path=str(not_apk), dry_run=True
        )

        assert result.success is False
        assert "zip" in (result.error or "").lower()

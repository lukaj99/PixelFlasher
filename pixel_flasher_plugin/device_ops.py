"""Core device operations facade for the PixelFlasher MCP server.

This module wraps :class:`phone.Device` behind a lazy, headless-safe API that
returns structured :class:`ToolResult` objects.  Every state-changing operation
is routed through :class:`SafetyGateway` before execution.
"""
from __future__ import annotations

import fnmatch
import hashlib
import io
import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET
import zipfile
from typing import Any, ClassVar

from pixel_flasher_plugin import boot_patcher, command_validator, telemetry
from pixel_flasher_plugin.headless_runtime import bootstrap, get_device
from pixel_flasher_plugin.headless_runtime import runtime as _runtime
from pixel_flasher_plugin.headless_runtime import run_shell as _run_shell
from pixel_flasher_plugin.result_types import RiskTier, ToolResult
from pixel_flasher_plugin.safety_engine import Decision, SafetyGateway

# Bootstrap state is cached process-wide so that every DeviceOps instance shares
# the same headless runtime configuration.
_runtime: Any | None = None
_config: Any | None = None


def _ensure_bootstrap(adb_path: str = "adb", fastboot_path: str = "fastboot") -> tuple[Any, Any]:
    """Initialize the headless runtime exactly once."""
    global _runtime, _config
    if _runtime is None:
        _runtime, _config = bootstrap(adb_path, fastboot_path)
    return _runtime, _config


class DeviceOps:
    """Agent-callable facade over :class:`phone.Device`.

    The device handle is created lazily so that constructing ``DeviceOps`` does
    not require a connected device and never triggers a GUI import.
    """

    _REBOOT_TARGETS: ClassVar[dict[str, str]] = {
        "system": "reboot_system",
        "bootloader": "reboot_bootloader",
        "recovery": "reboot_recovery",
        "fastboot": "reboot_fastboot",
        "sideload": "reboot_sideload",
    }

    _BOOT_CLASS_PARTITIONS: ClassVar[set[str]] = {
        "boot",
        "init_boot",
        "vendor_boot",
        "dtbo",
    }

    _KNOWN_ANDROID_ABIS: ClassVar[set[str]] = {
        "arm64-v8a",
        "armeabi-v7a",
        "x86",
        "x86_64",
    }

    _PATCH_METHODS: ClassVar[set[str]] = {
        "Magisk",
        "KernelSU",
        "KernelSU-Next",
        "APatch",
        "SukiSU",
        "Wild_KSU",
    }

    def __init__(
        self,
        device_id: str | None = None,
        mode: str = "adb",
        gateway: SafetyGateway | None = None,
        adb_path: str = "adb",
        fastboot_path: str = "fastboot",
    ) -> None:
        self.device_id = device_id
        self.mode = mode
        self.adb_path = adb_path
        self.fastboot_path = fastboot_path
        self._device: Any | None = None
        self.gateway = gateway or SafetyGateway(config=None, device_ops=self)
        # Ensure runtime is initialized so that ``get_device`` can resolve adb/fastboot.
        _ensure_bootstrap(adb_path, fastboot_path)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _lazy_device(self) -> Any:
        """Return a lazily constructed :class:`phone.Device` handle."""
        if self._device is None:
            if not self.device_id:
                raise ValueError("device_id is required for this operation")
            _ensure_bootstrap(self.adb_path, self.fastboot_path)
            self._device = get_device(self.device_id, self.mode)
        return self._device

    def _init_props(self) -> None:
        """Populate device properties when needed by read-only queries."""
        dev = self._lazy_device()
        # ``init`` parses getprop / fastboot getvar output into ``dev.props``.
        try:
            dev.init(self.mode)
        except Exception:
            # ``init`` already logs internally; empty props are handled below.
            pass

    def _q(self, value: str) -> str:
        """Shell-quote a user-supplied parameter to prevent injection."""
        return shlex.quote(str(value))

    def _adb_cmd(self, subcommand: str) -> str:
        """Build a canonical ``adb -s <id> <subcommand>`` string for validation."""
        return f"adb -s {self._q(self.device_id)} {subcommand}"

    def _exec_adb_cmd(self, subcommand: str) -> str:
        """Build a shell-safe ``adb -s <id> <subcommand>`` string for execution."""
        rt, _ = _ensure_bootstrap(self.adb_path, self.fastboot_path)
        adb = rt.get_adb() or "adb"
        return f"{self._q(adb)} -s {self._q(self.device_id)} {subcommand}"

    def _fastboot_cmd(self, subcommand: str) -> str:
        """Build a canonical ``fastboot -s <id> <subcommand>`` string for validation."""
        return f"fastboot -s {self._q(self.device_id)} {subcommand}"

    def _exec_fastboot_cmd(self, subcommand: str) -> str:
        """Build a shell-safe ``fastboot -s <id> <subcommand>`` string for execution."""
        rt, _ = _ensure_bootstrap(self.adb_path, self.fastboot_path)
        fastboot = rt.get_fastboot() or "fastboot"
        return f"{self._q(fastboot)} -s {self._q(self.device_id)} {subcommand}"

    def _evaluate(
        self,
        command: str,
        risk_tier: RiskTier,
        confirm: bool,
    ) -> ToolResult | None:
        """Route a proposed command through the safety gateway.

        Returns ``None`` when the operation may proceed.  Otherwise returns a
        :class:`ToolResult` explaining the deny/confirm outcome.
        """
        decision, reason = self.gateway.evaluate(
            command,
            {"risk_tier": risk_tier, "confirm": confirm},
        )
        if decision == Decision.DENY:
            return ToolResult(
                success=False,
                error=f"Denied by safety gateway: {reason}",
                command=command,
            )
        if decision == Decision.CONFIRM and not confirm:
            return ToolResult(
                success=False,
                error=f"Confirmation required: {reason}",
                data={"requires_confirmation": True},
                command=command,
            )
        return None

    def _preflight_checks_for(self, risk_tier: RiskTier, **kwargs: Any) -> list[str]:
        """Return the pre-flight check names that apply to a risk tier."""
        if risk_tier == RiskTier.CRITICAL:
            if kwargs.get("operation") == "erase":
                return ["device_connected", "correct_mode", "bootloader_unlocked"]
            return ["device_connected", "correct_mode", "bootloader_unlocked", "battery_level"]
        if risk_tier == RiskTier.WARN:
            return ["device_connected"]
        return []

    def _run_preflight(self, risk_tier: RiskTier, **kwargs: Any) -> ToolResult | None:
        """Run pre-flight checks for a risk tier and return a ToolResult on failure."""
        checks = self._preflight_checks_for(risk_tier, **kwargs)
        if not checks:
            return None
        check_args: dict[str, Any] = {}
        if "expected_mode" in kwargs:
            check_args["expected_mode"] = kwargs["expected_mode"]
        if "min_battery" in kwargs:
            check_args["min_battery"] = kwargs["min_battery"]
        preflight = self.gateway.run_preflight(self.device_id or "", checks, check_args)
        failed = [c for c in preflight if not c.passed]
        if failed:
            return ToolResult(
                success=False,
                error=f"Preflight checks failed: {failed[0].detail}",
                preflight_checks=preflight,
            )
        return None

    def _is_boot_class_partition(self, partition: str) -> bool:
        """Return True if *partition* (ignoring A/B slot suffix) is boot-class."""
        base = partition
        if len(partition) > 2 and partition[-2] == "_" and partition[-1] in ("a", "b"):
            base = partition[:-2]
        return base in self._BOOT_CLASS_PARTITIONS

    def _backup_partition(self, partition: str, confirm: bool) -> tuple[bool, str]:
        """Back up *partition* to a local temp file using read_partition machinery.

        Returns (True, backup_path) on success, or (False, error_message).
        """
        result = self.read_partition(partition, confirm=confirm)
        if not result.success:
            return False, result.error or "backup read_partition failed"
        data = result.data or {}
        backup_path = data.get("local_path")
        if not backup_path or not os.path.isfile(backup_path):
            return False, "backup did not produce a local file"
        return True, backup_path

    def _rollback_flash(
        self,
        partition: str,
        backup_path: str,
        confirm: bool,
    ) -> ToolResult:
        """Re-flash *backup_path* to *partition* via fastboot."""
        subcommand = f"flash {self._q(partition)} {self._q(backup_path)}"
        command = self._fastboot_cmd(subcommand)
        blocked = self._evaluate(command, RiskTier.CRITICAL, confirm)
        if blocked:
            return blocked

        exec_cmd = self._exec_fastboot_cmd(subcommand)
        res = self._run_shell_safe(exec_cmd, timeout=300)
        success = res.returncode == 0
        self._log("rollback_flash", command, success)
        if not success:
            return ToolResult(
                success=False,
                error=f"rollback flash failed (exit {res.returncode}): {res.stderr}",
                command=command,
            )
        return ToolResult(
            success=True,
            data={"partition": partition, "backup_path": backup_path},
            command=command,
        )

    def _rollback_from_args(self, args: dict[str, Any]) -> None:
        """Adapter used by SafetyGateway.perform_rollback; raises on failure."""
        result = self._rollback_flash(
            args["partition"],
            args["backup_path"],
            args["confirm"],
        )
        if not result.success:
            raise RuntimeError(result.error or "rollback failed")

    def _verify_fastboot_responsive(self, confirm: bool) -> tuple[bool, str]:
        """Lightweight post-flash check: fastboot getvar product must succeed."""
        subcommand = "getvar product"
        command = self._fastboot_cmd(subcommand)
        blocked = self._evaluate(command, RiskTier.INFO, confirm)
        if blocked:
            return False, blocked.error or "post-flash verification blocked"

        exec_cmd = self._exec_fastboot_cmd(subcommand)
        res = self._run_shell_safe(exec_cmd, timeout=30)
        if res.returncode != 0:
            return False, f"device unresponsive (exit {res.returncode}): {res.stderr}"
        return True, "device responsive"

    def _postcondition_device_responsive(
        self,
        args: dict[str, Any],
        data: Any,
    ) -> tuple[bool, str]:
        """Postcondition callable for SafetyGateway.verify_postcondition."""
        return self._verify_fastboot_responsive(args.get("confirm", False))

    def _run_shell_safe(
        self,
        command: str,
        timeout: int | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """Execute a shell command through the headless runtime."""
        return _run_shell(command, timeout=timeout)

    def _log(self, action: str, command: str | None, success: bool) -> None:
        """Write a non-blocking audit log entry."""
        try:
            telemetry.log_audit(
                event="device_ops",
                device_id=self.device_id,
                command=command,
                result="success" if success else "failure",
                action=action,
                success=success,
            )
        except Exception:
            # Telemetry must never break an operation.
            pass

    @staticmethod
    def _tool_error(action: str, exc: Exception, command: str | None = None) -> ToolResult:
        """Build a structured error result from an exception."""
        return ToolResult(
            success=False,
            error=f"{type(exc).__name__}: {exc}",
            command=command,
        )

    # ------------------------------------------------------------------
    # Static / class-level discovery
    # ------------------------------------------------------------------
    @classmethod
    def list_devices(
        cls,
        adb_path: str = "adb",
        fastboot_path: str = "fastboot",
    ) -> ToolResult:
        """List attached ADB and fastboot devices."""
        rt, _ = _ensure_bootstrap(adb_path, fastboot_path)
        devices: list[dict[str, Any]] = []

        try:
            adb = rt.get_adb() or "adb"
            res = _run_shell(f'"{adb}" devices -l', timeout=30)
            if res and isinstance(res, subprocess.CompletedProcess) and res.returncode == 0:
                for line in res.stdout.splitlines():
                    if "List of devices attached" in line or "\t" not in line:
                        continue
                    parts = line.split("\t")
                    if len(parts) < 2:
                        continue
                    d_id = parts[0].strip()
                    state = parts[1].strip()
                    entry: dict[str, Any] = {
                        "id": d_id,
                        "state": state,
                        "mode": state,
                    }
                    if state == "device":
                        entry["mode"] = "adb"
                    if len(parts) > 2:
                        for field in parts[2].split():
                            if ":" in field:
                                key, value = field.split(":", 1)
                                if key in ("product", "model", "transport_id"):
                                    entry[key] = value
                    devices.append(entry)
        except Exception as exc:
            return ToolResult(success=False, error=f"adb devices failed: {exc}")

        try:
            fastboot = rt.get_fastboot() or "fastboot"
            res = _run_shell(f'"{fastboot}" devices', timeout=30)
            if res and isinstance(res, subprocess.CompletedProcess) and res.returncode == 0:
                for line in res.stdout.splitlines():
                    if "\tfastboot" in line:
                        d_id = line.split("\t")[0].strip()
                        devices.append({
                            "id": d_id,
                            "state": "fastboot",
                            "mode": "fastboot",
                        })
        except Exception as exc:
            return ToolResult(success=False, error=f"fastboot devices failed: {exc}")

        return ToolResult(success=True, data={"devices": devices, "count": len(devices)})

    # ------------------------------------------------------------------
    # Read-only device queries
    # ------------------------------------------------------------------
    def get_device_info(self) -> ToolResult:
        """Return high-level device identity and state."""
        try:
            self._init_props()
            dev = self._lazy_device()
            if not dev.is_connected(self.device_id):
                return ToolResult(
                    success=False,
                    error=f"Device {self.device_id} is not connected",
                )
            data = {
                "device_id": self.device_id,
                "mode": self.mode,
                "hardware": dev.hardware,
                "build": dev.build,
                "api_level": dev.api_level,
                "active_slot": dev.active_slot,
                "unlocked": dev.unlocked,
                "rooted": dev.rooted,
                "kernel": dev.kernel,
                "has_init_boot": dev.has_init_boot,
            }
            self._log("get_device_info", None, True)
            return ToolResult(success=True, data=data)
        except Exception as exc:
            self._log("get_device_info", None, False)
            return self._tool_error("get_device_info", exc)

    def get_system_info(self) -> ToolResult:
        """Return key Android build properties."""
        try:
            self._init_props()
            dev = self._lazy_device()
            props = {
                "ro.build.fingerprint",
                "ro.build.id",
                "ro.build.version.security_patch",
                "ro.product.model",
                "ro.product.manufacturer",
                "ro.build.version.release",
                "ro.build.version.sdk",
                "ro.build.display.id",
                "ro.bootloader",
                "ro.boot.slot_suffix",
            }
            data = {prop: dev.get_prop(prop) for prop in props}
            self._log("get_system_info", None, True)
            return ToolResult(success=True, data=data)
        except Exception as exc:
            self._log("get_system_info", None, False)
            return self._tool_error("get_system_info", exc)

    def list_partitions(self) -> ToolResult:
        """List block-device partitions exposed by the device."""
        try:
            dev = self._lazy_device()
            partitions = dev.get_partitions()
            if partitions == -1 or partitions is None:
                return ToolResult(
                    success=False,
                    error="Could not retrieve partition list (device may be disconnected or not in ADB mode)",
                )
            entries = [{"name": name.strip()} for name in partitions if name.strip()]
            self._log("list_partitions", None, True)
            return ToolResult(
                success=True,
                data={"partitions": entries, "count": len(entries)},
            )
        except Exception as exc:
            self._log("list_partitions", None, False)
            return self._tool_error("list_partitions", exc)

    def get_boot_images(self) -> ToolResult:
        """Locate the active boot/init_boot partition for the current slot."""
        try:
            self._init_props()
            dev = self._lazy_device()
            slot = dev.active_slot
            has_init = dev.has_init_boot
            base = "init_boot" if has_init else "boot"
            data: dict[str, Any] = {
                "active_slot": slot,
                "boot_partition": base,
                "has_init_boot": has_init,
            }
            if slot:
                data["boot_partition_a"] = f"{base}_a"
                data["boot_partition_b"] = f"{base}_b"
            self._log("get_boot_images", None, True)
            return ToolResult(success=True, data=data)
        except Exception as exc:
            self._log("get_boot_images", None, False)
            return self._tool_error("get_boot_images", exc)

    # ------------------------------------------------------------------
    # Destructive / state-changing operations
    # ------------------------------------------------------------------
    def flash_partition(
        self,
        partition: str,
        image_path: str,
        confirm: bool = False,
    ) -> ToolResult:
        """Flash a partition image via fastboot with backup + rollback for boot-class partitions."""
        resolved = os.path.abspath(os.path.expanduser(image_path))
        if not os.path.isfile(resolved):
            return ToolResult(
                success=False,
                error=f"Image file not found: {resolved}",
            )

        subcommand = f"flash {self._q(partition)} {self._q(resolved)}"
        command = self._fastboot_cmd(subcommand)
        blocked = self._evaluate(command, RiskTier.CRITICAL, confirm)
        if blocked:
            self._log("flash_partition", command, False)
            return blocked

        preflight = self._run_preflight(
            RiskTier.CRITICAL,
            expected_mode="fastboot",
            operation="flash",
            partition=partition,
        )
        if preflight:
            self._log("flash_partition", command, False)
            return preflight

        backup_path: str | None = None
        cleanup_backup = False
        rollback_performed = False

        try:
            if self._is_boot_class_partition(partition):
                ok, backup_path_or_error = self._backup_partition(partition, confirm)
                if not ok:
                    self._log("flash_partition", command, False)
                    return ToolResult(
                        success=False,
                        error=f"Backup failed, aborting flash: {backup_path_or_error}",
                        command=command,
                    )
                backup_path = backup_path_or_error

            exec_cmd = self._exec_fastboot_cmd(subcommand)
            res = self._run_shell_safe(exec_cmd, timeout=300)
            flash_success = res.returncode == 0

            if not flash_success:
                self._log("flash_partition", command, False)
                if backup_path:
                    rb_ok, rb_detail = self.gateway.perform_rollback(
                        self._rollback_from_args,
                        {
                            "partition": partition,
                            "backup_path": backup_path,
                            "confirm": confirm,
                        },
                        reason="flash command failed",
                    )
                    rollback_performed = rb_ok
                    return ToolResult(
                        success=False,
                        error=(
                            f"flash failed (exit {res.returncode}): {res.stderr}; "
                            f"rollback: {rb_detail if rb_ok else rb_detail}"
                        ),
                        command=command,
                        rollback_performed=rollback_performed,
                    )
                return ToolResult(
                    success=False,
                    error=f"flash failed (exit {res.returncode}): {res.stderr}",
                    command=command,
                )

            # Lightweight post-flash verification: device must still respond in fastboot.
            post_ok, post_detail = self.gateway.verify_postcondition(
                self._postcondition_device_responsive,
                {"confirm": confirm, "device_id": self.device_id},
                data=None,
            )
            if not post_ok:
                self._log("flash_partition", command, False)
                if backup_path:
                    rb_ok, rb_detail = self.gateway.perform_rollback(
                        self._rollback_from_args,
                        {
                            "partition": partition,
                            "backup_path": backup_path,
                            "confirm": confirm,
                        },
                        reason="post-flash verification failed",
                    )
                    rollback_performed = rb_ok
                    return ToolResult(
                        success=False,
                        error=(
                            f"post-flash verification failed: {post_detail}; "
                            f"rollback: {rb_detail}"
                        ),
                        command=command,
                        rollback_performed=rollback_performed,
                    )
                return ToolResult(
                    success=False,
                    error=f"post-flash verification failed: {post_detail}",
                    command=command,
                )

            cleanup_backup = True
            self._log("flash_partition", command, True)
            return ToolResult(
                success=True,
                data={"partition": partition, "image_path": resolved},
                command=command,
                rollback_performed=False,
            )
        except Exception as exc:
            self._log("flash_partition", command, False)
            if backup_path:
                try:
                    rb_ok, rb_detail = self.gateway.perform_rollback(
                        self._rollback_from_args,
                        {
                            "partition": partition,
                            "backup_path": backup_path,
                            "confirm": confirm,
                        },
                        reason=f"exception during flash: {exc}",
                    )
                    rollback_performed = rb_ok
                except Exception:
                    pass
                return ToolResult(
                    success=False,
                    error=f"{type(exc).__name__}: {exc}; rollback: {'completed' if rollback_performed else 'failed'}",
                    command=command,
                    rollback_performed=rollback_performed,
                )
            return self._tool_error("flash_partition", exc, command)
        finally:
            if cleanup_backup and backup_path and os.path.exists(backup_path):
                try:
                    os.remove(backup_path)
                except Exception:
                    pass

    def patch_boot_image(
        self,
        boot_path: str,
        method: str = "Magisk",
        apk_path: str | None = None,
        superkey: str | None = None,
        kmi_override: str | None = None,
        mount_type: str | None = None,
        dry_run: bool = True,
        confirm: bool = False,
    ) -> ToolResult:
        """Validate, preview, and patch a boot image for the requested root solution.

        This is a CRITICAL operation: ``dry_run=True`` previews the generated
        on-device script, and ``confirm=True`` is required for execution.
        """
        if method not in self._PATCH_METHODS:
            return ToolResult(
                success=False,
                error=f"Unsupported patch method: {method}. "
                f"Supported: {sorted(self._PATCH_METHODS)}",
            )

        resolved_boot = os.path.abspath(os.path.expanduser(boot_path))
        if not os.path.isfile(resolved_boot):
            return ToolResult(
                success=False,
                error=f"Boot image not found: {resolved_boot}",
            )

        stock_sha1 = ""
        metadata: dict[str, Any] = {"method": method, "local_boot": True}

        try:
            with open(resolved_boot, "rb") as f:
                header = f.read(44)
        except Exception as exc:
            return ToolResult(
                success=False,
                error=f"Failed to read boot image: {exc}",
            )

        if len(header) < 8 or header[:8] != b"ANDROID!":
            return ToolResult(
                success=False,
                error=f"Invalid boot image: missing ANDROID! magic header in {resolved_boot}",
            )

        try:
            import struct

            (
                kernel_size,
                kernel_addr,
                ramdisk_size,
                ramdisk_addr,
                second_size,
                second_addr,
                tags_addr,
                page_size,
            ) = struct.unpack("<IIIIIIII", header[8:40])
            header_version = struct.unpack("<I", header[40:44])[0]
        except Exception as exc:
            return ToolResult(
                success=False,
                error=f"Failed to parse boot image header: {exc}",
            )

        metadata.update({
            "image_path": resolved_boot,
            "magic_valid": True,
            "file_size": os.path.getsize(resolved_boot),
            "kernel_size": kernel_size,
            "kernel_addr": kernel_addr,
            "ramdisk_size": ramdisk_size,
            "ramdisk_addr": ramdisk_addr,
            "second_size": second_size,
            "second_addr": second_addr,
            "tags_addr": tags_addr,
            "page_size": page_size,
            "header_version": header_version,
        })
        stock_sha1 = hashlib.sha1(open(resolved_boot, "rb").read()).hexdigest()

        # Method-specific input validation.
        if method == "APatch":
            if not superkey:
                return ToolResult(success=False, error="APatch requires superkey")
            if len(superkey) < 8 or not any(c.isalpha() for c in superkey) or not any(c.isdigit() for c in superkey):
                return ToolResult(
                    success=False,
                    error="APatch superkey must be at least 8 characters and contain both letters and digits",
                )

        resolved_apk: str | None = None
        if apk_path:
            resolved_apk = os.path.abspath(os.path.expanduser(apk_path))
            if not os.path.isfile(resolved_apk):
                return ToolResult(
                    success=False,
                    error=f"APK not found: {resolved_apk}",
                )
            if not zipfile.is_zipfile(resolved_apk):
                return ToolResult(
                    success=False,
                    error=f"APK is not a valid ZIP file: {resolved_apk}",
                )

        if mount_type and mount_type not in {"magicmount", "overlayfs", "dynamic"}:
            return ToolResult(
                success=False,
                error=f"Invalid mount_type: {mount_type}. Use magicmount, overlayfs, or dynamic",
            )

        # Unique on-device working directory for this patching run.
        timestamp = int(time.time())
        work_dir = f"/data/local/tmp/pf_{timestamp}"
        zip_path = f"{work_dir}.zip"
        script_path = "/data/local/tmp/pf_patch.sh"
        out_dir = "/data/local/tmp"
        boot_device_path = f"{work_dir}_stock_boot.img"

        # Dry-run path: generate script preview without touching the device.
        if dry_run:
            preview_metadata = dict(metadata)
            preview_metadata["script_preview"] = self._generate_patch_script(
                method=method,
                boot_path=boot_device_path,
                work_dir=work_dir,
                zip_path=zip_path,
                arch=self._get_arch(),
                version_code=self._get_solution_version_code(method),
                stock_sha1=stock_sha1,
                superkey=superkey,
                kmi_override=kmi_override,
                mount_type=mount_type,
            )
            if not resolved_apk:
                preview_metadata["script_preview"] = None
                preview_metadata.setdefault("warnings", []).append(
                    "apk_path required for full script preview"
                )
            return ToolResult(
                success=True,
                dry_run=True,
                data=preview_metadata,
                warnings=["Dry run - no changes made"],
            )

        if not confirm:
            return ToolResult(
                success=False,
                error="CRITICAL operation requires confirm=True",
            )

        if not resolved_apk:
            return ToolResult(
                success=False,
                error="apk_path is required to execute patching",
            )

        preflight = self._run_preflight(RiskTier.CRITICAL)
        if preflight:
            return preflight

        dev = self._lazy_device()
        arch = self._get_arch()
        version_code = self._get_solution_version_code(method)

        push_cmd = f"adb -s {self._q(self.device_id)} push {self._q(resolved_boot)} {self._q(boot_device_path)}"
        res = self.run_shell(push_cmd, confirm=True)
        if not res.success:
            return ToolResult(
                success=False,
                error=f"Failed to push boot image: {res.error}",
                command=push_cmd,
            )

        # Push the APK to the device.
        push_apk_cmd = f"adb -s {self._q(self.device_id)} push {self._q(resolved_apk)} {self._q(zip_path)}"
        res = self.run_shell(push_apk_cmd, confirm=True)
        if not res.success:
            return ToolResult(
                success=False,
                error=f"Failed to push APK: {res.error}",
                command=push_apk_cmd,
            )

        # Push busybox to the device.
        busybox_local = self._busybox_path(arch)
        if not busybox_local:
            return ToolResult(
                success=False,
                error=f"Busybox binary not found for architecture {arch}",
            )
        busybox_device = "/data/local/tmp/busybox"
        push_busy_cmd = f"adb -s {self._q(self.device_id)} push {self._q(busybox_local)} {self._q(busybox_device)}"
        res = self.run_shell(push_busy_cmd, confirm=True)
        if not res.success:
            return ToolResult(
                success=False,
                error=f"Failed to push busybox: {res.error}",
                command=push_busy_cmd,
            )

        # Generate and push the patch script.
        script = self._generate_patch_script(
            method=method,
            boot_path=boot_device_path,
            work_dir=work_dir,
            zip_path=zip_path,
            arch=arch,
            version_code=version_code,
            stock_sha1=stock_sha1,
            superkey=superkey,
            kmi_override=kmi_override,
            mount_type=mount_type,
        )

        local_script = tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False).name
        try:
            with open(local_script, "w", encoding="utf-8") as f:
                f.write(script)

            push_script_cmd = f"adb -s {self._q(self.device_id)} push {self._q(local_script)} {self._q(script_path)}"
            res = self.run_shell(push_script_cmd, confirm=True)
            if not res.success:
                return ToolResult(
                    success=False,
                    error=f"Failed to push patch script: {res.error}",
                    command=push_script_cmd,
                )

            chmod_cmd = f"adb -s {self._q(self.device_id)} shell chmod 755 {self._q(script_path)}"
            res = self.run_shell(chmod_cmd, confirm=True)
            if not res.success:
                return ToolResult(
                    success=False,
                    error=f"Failed to chmod patch script: {res.error}",
                    command=chmod_cmd,
                )

            exec_cmd = f"adb -s {self._q(self.device_id)} shell /data/local/tmp/pf_patch.sh"
            res = self.run_shell(exec_cmd, confirm=True, timeout=300)
            if not res.success:
                return ToolResult(
                    success=False,
                    error=f"Patch script failed: {res.error}",
                    command=exec_cmd,
                    data=res.data,
                )

            # Read the patch log.
            log_cmd = f"adb -s {self._q(self.device_id)} shell cat /data/local/tmp/pf_patch.log"
            log_res = self.run_shell(log_cmd, confirm=True)
            if not log_res.success:
                return ToolResult(
                    success=False,
                    error=f"Failed to read patch log: {log_res.error}",
                    command=log_cmd,
                )
            log_stdout = (log_res.data or {}).get("stdout", "")
            parsed = boot_patcher.parse_patch_log(log_stdout)
            if not parsed["patched_filename"]:
                return ToolResult(
                    success=False,
                    error="Patch log did not report a patched file",
                    command=exec_cmd,
                )

            patched_path = f"{out_dir}/{parsed['patched_filename']}"

            # Pull and verify the patched image.
            local_patched = tempfile.NamedTemporaryFile(suffix=".img", delete=False).name
            try:
                pull_cmd = f"adb -s {self._q(self.device_id)} pull {self._q(patched_path)} {self._q(local_patched)}"
                pull_res = self.run_shell(pull_cmd, confirm=True)
                if not pull_res.success:
                    return ToolResult(
                        success=False,
                        error=f"Failed to pull patched image: {pull_res.error}",
                        command=pull_cmd,
                    )

                if not os.path.isfile(local_patched) or os.path.getsize(local_patched) == 0:
                    return ToolResult(
                        success=False,
                        error="Patched image is empty or missing",
                        command=exec_cmd,
                    )

                with open(local_patched, "rb") as f:
                    magic = f.read(8)
                if magic != b"ANDROID!":
                    return ToolResult(
                        success=False,
                        error="Patched image has invalid ANDROID! magic header",
                        command=exec_cmd,
                    )

                with open(local_patched, "rb") as f:
                    patched_sha256 = hashlib.sha256(f.read()).hexdigest()
            finally:
                try:
                    os.remove(local_patched)
                except Exception:
                    pass

            return ToolResult(
                success=True,
                dry_run=False,
                data={
                    "patched_path": patched_path,
                    "method": method,
                    "version": parsed.get("version") or version_code,
                    "sha256": patched_sha256,
                    "patch_sha1": parsed.get("patch_sha1") or "",
                    "stock_sha1": stock_sha1,
                    "patch_filename": parsed["patched_filename"],
                    "boot_metadata": metadata,
                },
                command=exec_cmd,
            )
        finally:
            try:
                os.remove(local_script)
            except Exception:
                pass

    def _generate_patch_script(
        self,
        method: str,
        boot_path: str,
        work_dir: str,
        zip_path: str,
        arch: str,
        version_code: str,
        stock_sha1: str,
        superkey: str | None,
        kmi_override: str | None,
        mount_type: str | None,
    ) -> str:
        """Dispatch to the per-solution script generator."""
        out_dir = "/data/local/tmp"
        if method == "Magisk":
            return boot_patcher.generate_magisk_script(
                boot_path=boot_path,
                work_dir=work_dir,
                zip_path=zip_path,
                out_dir=out_dir,
                arch=arch,
                stock_sha1=stock_sha1,
                version_code=version_code,
            )
        if method == "APatch":
            return boot_patcher.generate_apatch_script(
                boot_path=boot_path,
                work_dir=work_dir,
                zip_path=zip_path,
                out_dir=out_dir,
                arch=arch,
                stock_sha1=stock_sha1,
                superkey=superkey or "",
                version_code=version_code,
            )
        return boot_patcher.generate_ksu_script(
            boot_path=boot_path,
            work_dir=work_dir,
            zip_path=zip_path,
            out_dir=out_dir,
            arch=arch,
            stock_sha1=stock_sha1,
            version_code=version_code,
            kmi_override=kmi_override,
            mount_type=mount_type,
            method=method,
        )

    def _get_arch(self) -> str:
        """Return a sane device ABI, falling back to arm64-v8a."""
        try:
            dev = self._lazy_device()
            arch = dev.architecture
            if arch in self._KNOWN_ANDROID_ABIS:
                return arch
        except Exception:
            pass
        return "arm64-v8a"

    def _get_solution_version_code(self, method: str) -> str:
        """Best-effort version code from the device's installed root app."""
        mapping = {
            "Magisk": "magisk_app_version_code",
            "KernelSU": "ksu_app_version_code",
            "KernelSU-Next": "ksu_next_app_version_code",
            "APatch": "apatch_app_version_code",
            "SukiSU": "sukisu_app_version_code",
            "Wild_KSU": "wild_ksu_app_version_code",
        }
        prop = mapping.get(method)
        if not prop:
            return "0"
        try:
            dev = self._lazy_device()
            val = getattr(dev, prop, None)
            if val is None:
                return "0"
            s = str(val).strip()
            int(s)
            return s
        except Exception:
            return "0"

    def _busybox_path(self, arch: str) -> str | None:
        """Return the bundled busybox path for *arch*, or None if missing."""
        try:
            from runtime import get_bundle_dir

            path = os.path.join(get_bundle_dir(), "bin", f"busybox_{arch}")
            if os.path.isfile(path):
                return path
        except Exception:
            pass
        return None

    def flash_factory_image(
        self,
        firmware_path: str,
        mode: str = "dryRun",
        dry_run: bool = True,
        confirm: bool = False,
    ) -> ToolResult:
        """Inspect a factory image zip; full flashing is safety-gated.

        Wave 1 implementation: in dry-run mode the zip is parsed and the list of
        contained partition images is returned.  Executing a full factory flash
        is the most destructive operation the agent could trigger, so even with
        confirm=True it is refused and the user is directed to the PixelFlasher
        GUI where device state can be supervised.
        """
        resolved = os.path.abspath(os.path.expanduser(firmware_path))
        if not os.path.isfile(resolved):
            return ToolResult(
                success=False,
                error=f"Factory image zip not found: {resolved}",
            )

        try:
            import zipfile
            with zipfile.ZipFile(resolved, "r") as zf:
                namelist = zf.namelist()
        except Exception as exc:
            return ToolResult(
                success=False,
                error=f"Failed to open factory zip: {exc}",
            )

        image_files = [n for n in namelist if n.lower().endswith(".img")]
        partitions = []
        for name in image_files:
            base = os.path.basename(name)
            part, _ = os.path.splitext(base)
            partitions.append({"file": name, "partition": part})

        safety_warning = (
            "Full factory image flashing is the most destructive operation and "
            "is not supported via the MCP agent in this release."
        )

        if dry_run:
            return ToolResult(
                success=True,
                dry_run=True,
                data={
                    "mode": mode,
                    "factory_zip": resolved,
                    "image_files": image_files,
                    "partitions": partitions,
                },
                warnings=[safety_warning],
            )

        if not confirm:
            return ToolResult(
                success=False,
                error="CRITICAL operation requires confirm=True",
            )

        return ToolResult(
            success=False,
            error=(
                "Full factory image flashing is not supported via the MCP agent. "
                "Please use the PixelFlasher GUI for this operation."
            ),
        )

    def wipe_partition(self, partition: str, confirm: bool = False) -> ToolResult:
        """Erase a partition via fastboot."""
        try:
            subcommand = f"erase {self._q(partition)}"
            command = self._fastboot_cmd(subcommand)
            blocked = self._evaluate(command, RiskTier.CRITICAL, confirm)
            if blocked:
                self._log("wipe_partition", command, False)
                return blocked

            preflight = self._run_preflight(
                RiskTier.CRITICAL,
                expected_mode="fastboot",
                operation="erase",
                partition=partition,
            )
            if preflight:
                self._log("wipe_partition", command, False)
                return preflight

            exec_cmd = self._exec_fastboot_cmd(subcommand)
            res = self._run_shell_safe(exec_cmd, timeout=120)
            success = res.returncode == 0
            self._log("wipe_partition", command, success)
            if not success:
                return ToolResult(
                    success=False,
                    error=f"erase failed (exit {res.returncode}): {res.stderr}",
                    command=command,
                )
            return ToolResult(
                success=True,
                data={"partition": partition},
                command=command,
            )
        except Exception as exc:
            self._log("wipe_partition", None, False)
            return self._tool_error("wipe_partition", exc)

    def reboot_device(self, target: str = "system", confirm: bool = False) -> ToolResult:
        """Reboot the device to the requested target."""
        if target not in self._REBOOT_TARGETS:
            return ToolResult(
                success=False,
                error=f"Unsupported reboot target: {target}",
            )

        try:
            if target == "system":
                command = self._adb_cmd("reboot")
            elif target == "bootloader":
                command = self._adb_cmd("reboot bootloader")
            elif target == "recovery":
                command = self._adb_cmd("reboot recovery")
            elif target == "fastboot":
                command = self._adb_cmd("reboot fastboot")
            else:  # sideload
                command = self._adb_cmd("reboot sideload")

            blocked = self._evaluate(command, RiskTier.WARN, confirm)
            if blocked:
                self._log("reboot_device", command, False)
                return blocked

            preflight = self._run_preflight(RiskTier.WARN, expected_mode="adb")
            if preflight:
                self._log("reboot_device", command, False)
                return preflight

            dev = self._lazy_device()
            method = getattr(dev, self._REBOOT_TARGETS[target])
            rc = method(timeout=60)
            success = rc == 0
            self._log("reboot_device", command, success)
            if not success:
                return ToolResult(
                    success=False,
                    error=f"Reboot to {target} failed",
                    command=command,
                )
            return ToolResult(
                success=True,
                data={"target": target},
                command=command,
            )
        except Exception as exc:
            self._log("reboot_device", None, False)
            return self._tool_error("reboot_device", exc)

    def push_file(
        self,
        local_path: str,
        remote_path: str,
        confirm: bool = False,
    ) -> ToolResult:
        """Push a local file to the device."""
        try:
            resolved = os.path.abspath(os.path.expanduser(local_path))
            if not os.path.isfile(resolved):
                return ToolResult(
                    success=False,
                    error=f"Local file not found: {resolved}",
                )
            command = self._adb_cmd(f"push {self._q(resolved)} {self._q(remote_path)}")
            blocked = self._evaluate(command, RiskTier.INFO, confirm)
            if blocked:
                self._log("push_file", command, False)
                return blocked

            dev = self._lazy_device()
            rc = dev.push_file(resolved, remote_path)
            success = rc == 0
            self._log("push_file", command, success)
            if not success:
                return ToolResult(
                    success=False,
                    error="push_file returned non-zero",
                    command=command,
                )
            return ToolResult(
                success=True,
                data={"local_path": resolved, "remote_path": remote_path},
                command=command,
            )
        except Exception as exc:
            self._log("push_file", None, False)
            return self._tool_error("push_file", exc)

    def pull_file(
        self,
        remote_path: str,
        local_path: str,
        confirm: bool = False,
    ) -> ToolResult:
        """Pull a file from the device to the local filesystem."""
        try:
            resolved = os.path.abspath(os.path.expanduser(local_path))
            command = self._adb_cmd(f"pull {self._q(remote_path)} {self._q(resolved)}")
            blocked = self._evaluate(command, RiskTier.INFO, confirm)
            if blocked:
                self._log("pull_file", command, False)
                return blocked

            dev = self._lazy_device()
            rc = dev.pull_file(remote_path, resolved)
            success = rc == 0
            self._log("pull_file", command, success)
            if not success:
                return ToolResult(
                    success=False,
                    error="pull_file returned non-zero",
                    command=command,
                )
            return ToolResult(
                success=True,
                data={"remote_path": remote_path, "local_path": resolved},
                command=command,
            )
        except Exception as exc:
            self._log("pull_file", None, False)
            return self._tool_error("pull_file", exc)

    def install_apk(self, apk_path: str, confirm: bool = False) -> ToolResult:
        """Install an APK package via ADB."""
        try:
            resolved = os.path.abspath(os.path.expanduser(apk_path))
            if not os.path.isfile(resolved):
                return ToolResult(
                    success=False,
                    error=f"APK file not found: {resolved}",
                )
            command = self._adb_cmd(f"install -r {self._q(resolved)}")
            blocked = self._evaluate(command, RiskTier.WARN, confirm)
            if blocked:
                self._log("install_apk", command, False)
                return blocked

            preflight = self._run_preflight(RiskTier.WARN, expected_mode="adb")
            if preflight:
                self._log("install_apk", command, False)
                return preflight

            dev = self._lazy_device()
            rc = dev.install_apk(resolved)
            success = rc == 0
            self._log("install_apk", command, success)
            if not success:
                return ToolResult(
                    success=False,
                    error="install_apk returned non-zero",
                    command=command,
                )
            return ToolResult(
                success=True,
                data={"apk_path": resolved},
                command=command,
            )
        except Exception as exc:
            self._log("install_apk", None, False)
            return self._tool_error("install_apk", exc)

    def read_partition(
        self,
        partition: str,
        confirm: bool = False,
        max_bytes: int = 256 * 1024 * 1024,
    ) -> ToolResult:
        """Dump a partition to a local temporary file (non-destructive)."""
        if not re.match(r"^[A-Za-z0-9_]+$", partition):
            return ToolResult(
                success=False,
                error=f"Invalid partition name: {partition}",
            )

        local_tmp = tempfile.NamedTemporaryFile(
            prefix=f"{partition}_",
            suffix=".img",
            delete=False,
        ).name

        def _size_via_blockdev(block_path: str) -> int | None:
            subcommand = (
                f"shell su -c \"blockdev --getsize64 {self._q(block_path)}\""
            )
            command = self._adb_cmd(subcommand)
            blocked = self._evaluate(command, RiskTier.INFO, confirm)
            if blocked:
                return None
            exec_cmd = self._exec_adb_cmd(subcommand)
            res = self._run_shell_safe(exec_cmd, timeout=30)
            if res.returncode != 0:
                return None
            try:
                return int(res.stdout.strip())
            except Exception:
                return None

        def _device_name_from_ls(block_path: str) -> str | None:
            subcommand = f"shell ls -l {self._q(block_path)}"
            command = self._adb_cmd(subcommand)
            blocked = self._evaluate(command, RiskTier.INFO, confirm)
            if blocked:
                return None
            exec_cmd = self._exec_adb_cmd(subcommand)
            res = self._run_shell_safe(exec_cmd, timeout=30)
            if res.returncode != 0:
                return None
            line = res.stdout.strip()
            if " -> " in line:
                target = line.split(" -> ", 1)[1].strip()
                target = target.lstrip("./")
                return os.path.basename(target)
            return os.path.basename(block_path)

        def _size_via_proc_partitions(device_name: str) -> int | None:
            subcommand = "shell cat /proc/partitions"
            command = self._adb_cmd(subcommand)
            blocked = self._evaluate(command, RiskTier.INFO, confirm)
            if blocked:
                return None
            exec_cmd = self._exec_adb_cmd(subcommand)
            res = self._run_shell_safe(exec_cmd, timeout=30)
            if res.returncode != 0:
                return None
            for line in res.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 4 and parts[-1] == device_name:
                    try:
                        return int(parts[2]) * 1024
                    except Exception:
                        return None
            return None

        def _partition_size(block_path: str) -> int | None:
            size = _size_via_blockdev(block_path)
            if size is not None:
                return size
            device_name = _device_name_from_ls(block_path)
            if device_name is None:
                return None
            return _size_via_proc_partitions(device_name)

        def _try_read(block_path: str) -> subprocess.CompletedProcess[str] | None:
            redirect = f" > {self._q(local_tmp)}"
            # Try ``dd`` under ``su`` first; it streams block reads reliably
            # for large partitions when root is available.
            subcommand = (
                f"shell su -c \"dd if={self._q(block_path)} bs=1M 2>/dev/null\""
            )
            command = self._adb_cmd(subcommand) + redirect
            blocked = self._evaluate(command, RiskTier.INFO, confirm)
            if blocked:
                return None
            exec_cmd = self._exec_adb_cmd(subcommand) + redirect
            res = self._run_shell_safe(exec_cmd, timeout=300)
            if res.returncode == 0 and os.path.getsize(local_tmp) > 0:
                return res
            # Fall back to ``cat`` when root is unavailable or ``dd`` fails.
            subcommand = f"shell cat {self._q(block_path)}"
            command = self._adb_cmd(subcommand) + redirect
            blocked = self._evaluate(command, RiskTier.INFO, confirm)
            if blocked:
                return None
            exec_cmd = self._exec_adb_cmd(subcommand) + redirect
            return self._run_shell_safe(exec_cmd, timeout=300)

        try:
            last_error = f"Could not read partition {partition!r}"
            for block_path in (
                f"/dev/block/bootdevice/by-name/{partition}",
                f"/dev/block/by-name/{partition}",
            ):
                size = _partition_size(block_path)
                if size is None:
                    last_error = (
                        f"Could not determine size of partition {partition!r} "
                        f"at {block_path}"
                    )
                    continue
                if size > max_bytes:
                    return ToolResult(
                        success=False,
                        error=(
                            f"Partition {partition!r} is {size} bytes, "
                            f"which exceeds the maximum allowed {max_bytes} bytes"
                        ),
                    )
                res = _try_read(block_path)
                if res is None:
                    return ToolResult(
                        success=False,
                        error="read_partition blocked by safety gateway",
                    )
                if res.returncode == 0 and os.path.getsize(local_tmp) > 0:
                    break
                last_error = (
                    f"Could not read partition {partition!r} "
                    f"(exit {res.returncode}): {res.stderr}"
                )
            else:
                return ToolResult(success=False, error=last_error)

            sha = hashlib.sha256()
            with open(local_tmp, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha.update(chunk)

            self._log("read_partition", None, True)
            return ToolResult(
                success=True,
                data={
                    "partition": partition,
                    "local_path": local_tmp,
                    "size": os.path.getsize(local_tmp),
                    "sha256": sha.hexdigest(),
                },
            )
        except Exception as exc:
            self._log("read_partition", None, False)
            return self._tool_error("read_partition", exc)

    def list_packages(self) -> ToolResult:
        """Return installed package names via ``pm list packages``."""
        try:
            dev = self._lazy_device()
            output = dev.get_package_list("all")
            if output is None:
                return ToolResult(
                    success=False,
                    error="Could not retrieve package list",
                )
            packages = [line.strip() for line in output.splitlines() if line.strip()]
            self._log("list_packages", None, True)
            return ToolResult(
                success=True,
                data={"packages": packages, "count": len(packages)},
            )
        except Exception as exc:
            self._log("list_packages", None, False)
            return self._tool_error("list_packages", exc)

    def run_shell(
        self,
        command: str,
        confirm: bool = False,
        timeout: int | None = 30,
    ) -> ToolResult:
        """Run an arbitrary ADB/fastboot shell command.

        The command is validated against the whitelist before execution.
        """
        try:
            allowed, reason = command_validator.CommandValidator.is_allowed(command)
            if not allowed:
                self._log("run_shell", command, False)
                return ToolResult(
                    success=False,
                    error=f"Command blocked: {reason}",
                    command=command,
                )

            blocked = self._evaluate(command, RiskTier.WARN, confirm)
            if blocked:
                self._log("run_shell", command, False)
                return blocked

            preflight = self._run_preflight(RiskTier.WARN)
            if preflight:
                self._log("run_shell", command, False)
                return preflight

            res = self._run_shell_safe(command, timeout=timeout)
            success = res.returncode == 0
            self._log("run_shell", command, success)
            return ToolResult(
                success=success,
                data={
                    "returncode": res.returncode,
                    "stdout": res.stdout,
                    "stderr": res.stderr,
                },
                command=command,
                error=None if success else f"exit code {res.returncode}",
            )
        except Exception as exc:
            self._log("run_shell", command if "command" in dir() else None, False)
            return self._tool_error("run_shell", exc, command)

    # ------------------------------------------------------------------
    # PIF / Play Integrity (read-only)
    # ------------------------------------------------------------------
    def _read_module_prop(self) -> dict[str, str]:
        """Read /data/adb/modules/playintegrityfix/module.prop into a dict."""
        path = "/data/adb/modules/playintegrityfix/module.prop"
        subcommand = f"shell cat {self._q(path)}"
        command = self._adb_cmd(subcommand)
        blocked = self._evaluate(command, RiskTier.INFO, confirm=False)
        if blocked:
            return {}
        exec_cmd = self._exec_adb_cmd(subcommand)
        res = self._run_shell_safe(exec_cmd, timeout=30)
        if res.returncode != 0:
            return {}
        props: dict[str, str] = {}
        for line in res.stdout.splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                props[key.strip()] = value.strip()
        return props

    def get_pif_status(self) -> ToolResult:
        """Read the PIF module's custom configuration and module metadata."""
        try:
            module_dir = "/data/adb/modules/playintegrityfix"
            json_path = f"{module_dir}/custom.pif.json"
            prop_path = f"{module_dir}/custom.pif.prop"

            module_prop = self._read_module_prop()
            module_installed = bool(module_prop)
            module_name = module_prop.get("name")
            module_version = module_prop.get("version")

            # Try JSON config first.
            for pif_path in (json_path, prop_path):
                subcommand = f"shell cat {self._q(pif_path)}"
                command = self._adb_cmd(subcommand)
                blocked = self._evaluate(command, RiskTier.INFO, confirm=False)
                if blocked:
                    return ToolResult(
                        success=False,
                        error=blocked.error or "PIF read blocked by safety gateway",
                        command=command,
                    )
                exec_cmd = self._exec_adb_cmd(subcommand)
                res = self._run_shell_safe(exec_cmd, timeout=30)
                if res.returncode != 0 or not res.stdout.strip():
                    continue

                content: dict[str, Any] | str
                if pif_path.endswith(".json"):
                    try:
                        content = json.loads(res.stdout)
                    except json.JSONDecodeError as exc:
                        content = {"raw": res.stdout, "parse_error": str(exc)}
                else:
                    props: dict[str, str] = {}
                    for line in res.stdout.splitlines():
                        if "=" in line:
                            key, value = line.split("=", 1)
                            props[key.strip()] = value.strip()
                    content = props

                self._log("get_pif_status", command, True)
                return ToolResult(
                    success=True,
                    data={
                        "pif_exists": True,
                        "pif_path": pif_path,
                        "pif_content": content,
                        "module_name": module_name,
                        "module_version": module_version,
                        "module_installed": module_installed,
                    },
                )

            self._log("get_pif_status", None, True)
            return ToolResult(
                success=True,
                data={
                    "pif_exists": False,
                    "pif_path": None,
                    "pif_content": None,
                    "module_name": module_name,
                    "module_version": module_version,
                    "module_installed": module_installed,
                },
            )
        except Exception as exc:
            self._log("get_pif_status", None, False)
            return self._tool_error("get_pif_status", exc)

    def check_play_integrity(self) -> ToolResult:
        """Report the PIF Magisk module state.

        This does NOT invoke the Play Integrity API (that requires a device UI
        and a calling app). It only reports whether the PIF module is installed
        and enabled on the device.
        """
        try:
            module_dir = "/data/adb/modules/playintegrityfix"
            module_prop = self._read_module_prop()
            module_installed = bool(module_prop)
            module_version = module_prop.get("version")

            disable_path = f"{module_dir}/disable"
            subcommand = f"shell ls {self._q(disable_path)}"
            command = self._adb_cmd(subcommand)
            blocked = self._evaluate(command, RiskTier.INFO, confirm=False)
            if blocked:
                return ToolResult(
                    success=False,
                    error=blocked.error or "PIF disable check blocked by safety gateway",
                    command=command,
                )
            exec_cmd = self._exec_adb_cmd(subcommand)
            res = self._run_shell_safe(exec_cmd, timeout=30)
            # If the disable file exists, the module is disabled.
            module_enabled = module_installed and res.returncode != 0

            self._log("check_play_integrity", command, True)
            return ToolResult(
                success=True,
                data={
                    "module_installed": module_installed,
                    "module_enabled": module_enabled,
                    "module_version": module_version,
                    "module_name": module_prop.get("name"),
                },
            )
        except Exception as exc:
            self._log("check_play_integrity", None, False)
            return self._tool_error("check_play_integrity", exc)

    def update_pif(self, pif_json: str | dict, confirm: bool = False) -> ToolResult:
        """Push a new PIF config to the device.

        The JSON is validated locally, pushed to a temporary location, and then
        moved into place under root.  Root access is required for the final
        copy/chmod step.
        """
        try:
            if isinstance(pif_json, dict):
                json_bytes = json.dumps(pif_json, indent=2).encode("utf-8")
            else:
                # Validate by parsing, then preserve the original serialization.
                json.loads(pif_json)
                json_bytes = pif_json.encode("utf-8")
        except Exception as exc:
            return ToolResult(success=False, error=f"Invalid pif_json: {exc}")

        new_hash = hashlib.sha256(json_bytes).hexdigest()
        fd, local_tmp = tempfile.mkstemp(prefix="pif_", suffix=".json")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(json_bytes)
        except Exception as exc:
            return ToolResult(success=False, error=f"Failed to write temp file: {exc}")

        remote_tmp = "/data/local/tmp/custom.pif.json"
        final_path = "/data/adb/modules/playintegrityfix/custom.pif.json"

        try:
            # Push the validated config to a temporary device path.
            push_cmd = self._adb_cmd(f"push {self._q(local_tmp)} {self._q(remote_tmp)}")
            blocked = self._evaluate(push_cmd, RiskTier.WARN, confirm)
            if blocked:
                self._log("update_pif", push_cmd, False)
                return blocked

            preflight = self._run_preflight(RiskTier.WARN, expected_mode="adb")
            if preflight:
                self._log("update_pif", push_cmd, False)
                return preflight

            exec_cmd = self._exec_adb_cmd(f"push {self._q(local_tmp)} {self._q(remote_tmp)}")
            res = self._run_shell_safe(exec_cmd, timeout=60)
            if res.returncode != 0:
                self._log("update_pif", push_cmd, False)
                return ToolResult(
                    success=False,
                    error=f"push failed (exit {res.returncode}): {res.stderr}",
                    command=push_cmd,
                )

            # Move into place as root and fix permissions.
            su_cmd = self._adb_cmd(
                f'shell su -c "cp {self._q(remote_tmp)} {self._q(final_path)} '
                f'&& chmod 644 {self._q(final_path)}"'
            )
            blocked = self._evaluate(su_cmd, RiskTier.WARN, confirm)
            if blocked:
                self._log("update_pif", su_cmd, False)
                return blocked

            exec_cmd = self._exec_adb_cmd(
                f'shell su -c "cp {self._q(remote_tmp)} {self._q(final_path)} '
                f'&& chmod 644 {self._q(final_path)}"'
            )
            res = self._run_shell_safe(exec_cmd, timeout=60)
            if res.returncode != 0:
                self._log("update_pif", su_cmd, False)
                return ToolResult(
                    success=False,
                    error=(
                        f"su copy failed (exit {res.returncode}): {res.stderr}; "
                        "root is required to install the PIF config"
                    ),
                    command=su_cmd,
                )

            self._log("update_pif", su_cmd, True)
            return ToolResult(
                success=True,
                data={
                    "new_hash": new_hash,
                    "pif_path": final_path,
                    "previous_hash": None,
                },
                command=su_cmd,
            )
        except Exception as exc:
            self._log("update_pif", None, False)
            return self._tool_error("update_pif", exc)
        finally:
            try:
                os.remove(local_tmp)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Keybox / hardware attestation management
    # ------------------------------------------------------------------
    KEYBOX_PATH: ClassVar[str] = "/data/adb/tricky_store/keybox.xml"

    def _parse_keybox_cert(self, keybox_path: str) -> tuple[str | None, str | None]:
        """Extract the first certificate serial number and expiry from a keybox.xml.

        The keybox XML contains one or more ``Certificate`` elements (some
        keybox variants use ``DeviceCertificate``).  The first parseable PEM
        certificate is used to obtain the serial and not-after date.
        """
        try:
            tree = ET.parse(keybox_path)
            root = tree.getroot()
        except Exception:
            return None, None

        for elem in root.iter():
            if elem.tag not in ("Certificate", "DeviceCertificate"):
                continue
            text = (elem.text or "").strip()
            if not text:
                continue
            try:
                from cryptography import x509

                cert = x509.load_pem_x509_certificate(text.encode())
                serial = f"{cert.serial_number:x}"
                expiry = None
                if cert.not_valid_after_utc:
                    expiry = cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
                return serial, expiry
            except Exception:
                continue
        return None, None

    def _check_kb_result(self, result: Any) -> tuple[bool, str]:
        """Normalize the output of ``runtime.check_kb`` into (revoked, raw_text).

        ``check_kb`` returns either a list of status strings or a single string.
        """
        if isinstance(result, list):
            raw = " ".join(str(item) for item in result)
            revoked = "revoked" in raw.lower()
        else:
            raw = str(result)
            revoked = "revoked" in raw.lower()
        return revoked, raw

    def get_keybox_status(self, device_id: str | None = None) -> ToolResult:
        """Check the device's keybox.xml for existence and revocation status.

        Pulls the keybox to a local temp file, runs ``runtime.check_kb`` against
        Google's certificate revocation list, and parses the XML for the leaf
        certificate serial number and expiry.
        """
        keybox_xml = self.KEYBOX_PATH
        local_tmp: str | None = None
        try:
            dev = self._lazy_device()
            res, _ = dev.check_file(keybox_xml, with_su=True, verbose=False)
            if res != 1:
                return ToolResult(
                    success=True,
                    data={
                        "exists": False,
                        "revoked": None,
                        "revoked_reason": None,
                        "certificate_serial": None,
                        "expiry_date": None,
                        "raw_check_kb_result": "",
                    },
                )

            local_tmp = tempfile.NamedTemporaryFile(
                prefix="keybox_",
                suffix=".xml",
                delete=False,
            ).name

            rc = dev.pull_file(keybox_xml, local_tmp, with_su=True, quiet=False)
            if rc != 0:
                return ToolResult(
                    success=False,
                    error=f"Failed to pull keybox.xml from device (rc={rc})",
                )

            check_result = _runtime.check_kb(local_tmp)
            revoked, raw = self._check_kb_result(check_result)
            revoked_reason = raw if revoked else None
            serial, expiry = self._parse_keybox_cert(local_tmp)

            self._log("get_keybox_status", None, True)
            return ToolResult(
                success=True,
                data={
                    "exists": True,
                    "revoked": revoked,
                    "revoked_reason": revoked_reason,
                    "certificate_serial": serial,
                    "expiry_date": expiry,
                    "raw_check_kb_result": raw,
                },
            )
        except Exception as exc:
            self._log("get_keybox_status", None, False)
            return self._tool_error("get_keybox_status", exc)
        finally:
            if local_tmp and os.path.exists(local_tmp):
                try:
                    os.remove(local_tmp)
                except Exception:
                    pass

    def update_keybox(
        self,
        source: str | None = None,
        content: str | None = None,
        dry_run: bool = True,
        confirm: bool = False,
        device_id: str | None = None,
    ) -> ToolResult:
        """Validate and push a new keybox.xml to the device.

        The supplied keybox is validated locally as XML and checked against
        Google's certificate revocation list before any device interaction.
        Revoked keyboxes are refused.  The file is pushed to a temporary
        location and then moved into place under root.
        """
        if source:
            source_path = os.path.abspath(os.path.expanduser(source))
            if not os.path.isfile(source_path):
                return ToolResult(
                    success=False,
                    error=f"Keybox file not found: {source_path}",
                )
            try:
                with open(source_path, "r", encoding="utf-8") as f:
                    xml_content = f.read()
            except Exception as exc:
                return ToolResult(
                    success=False,
                    error=f"Failed to read keybox file: {exc}",
                )
        elif content:
            xml_content = content
        else:
            return ToolResult(
                success=False,
                error="Either source or content must be provided",
            )

        # Validate XML structure.
        try:
            root = ET.fromstring(xml_content)
        except ET.ParseError as exc:
            return ToolResult(success=False, error=f"Invalid XML: {exc}")

        if root.tag != "AndroidAttestation":
            return ToolResult(
                success=False,
                error=f"Invalid keybox root element: {root.tag}",
            )

        has_num_certs = any(elem.tag == "NumberOfCertificates" for elem in root.iter())
        has_cert = any(
            elem.tag in ("Certificate", "DeviceCertificate") for elem in root.iter()
        )
        if not has_num_certs or not has_cert:
            return ToolResult(
                success=False,
                error=(
                    "Invalid keybox structure: missing NumberOfCertificates "
                    "or Certificate/DeviceCertificate elements"
                ),
            )

        local_tmp: str | None = None
        try:
            fd, local_tmp = tempfile.mkstemp(prefix="keybox_", suffix=".xml")
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(xml_content)

            check_result = _runtime.check_kb(local_tmp)
            revoked, raw = self._check_kb_result(check_result)
            if revoked:
                return ToolResult(
                    success=False,
                    error=f"Refusing to push revoked keybox: {raw}",
                    data={
                        "pushed": False,
                        "remote_path": self.KEYBOX_PATH,
                        "revoked": True,
                        "revoked_reason": raw,
                    },
                )

            if dry_run:
                return ToolResult(
                    success=True,
                    dry_run=True,
                    data={
                        "pushed": False,
                        "remote_path": self.KEYBOX_PATH,
                        "revoked": False,
                        "revoked_reason": None,
                    },
                    warnings=["Dry run - no changes made"],
                )

            if not confirm:
                return ToolResult(
                    success=False,
                    error="WARN operation requires confirm=True when dry_run=False",
                    data={"requires_confirmation": True},
                )

            remote_tmp = "/data/local/tmp/keybox.xml"
            final_path = self.KEYBOX_PATH

            dev = self._lazy_device()

            # Push the validated keybox to a temporary device path.
            push_cmd = self._adb_cmd(f"push {self._q(local_tmp)} {self._q(remote_tmp)}")
            blocked = self._evaluate(push_cmd, RiskTier.WARN, confirm)
            if blocked:
                self._log("update_keybox", push_cmd, False)
                return blocked

            preflight = self._run_preflight(RiskTier.WARN, expected_mode="adb")
            if preflight:
                self._log("update_keybox", push_cmd, False)
                return preflight

            rc = dev.push_file(local_tmp, remote_tmp)
            if rc != 0:
                self._log("update_keybox", push_cmd, False)
                return ToolResult(
                    success=False,
                    error=f"push_file returned {rc}",
                    command=push_cmd,
                )

            # Move into place as root and fix permissions.
            su_cmd = self._adb_cmd(
                f'shell su -c "cp {self._q(remote_tmp)} {self._q(final_path)} '
                f'&& chmod 644 {self._q(final_path)}"'
            )
            blocked = self._evaluate(su_cmd, RiskTier.WARN, confirm)
            if blocked:
                self._log("update_keybox", su_cmd, False)
                return blocked

            exec_cmd = self._exec_adb_cmd(
                f'shell su -c "cp {self._q(remote_tmp)} {self._q(final_path)} '
                f'&& chmod 644 {self._q(final_path)}"'
            )
            res = self._run_shell_safe(exec_cmd, timeout=60)
            if res.returncode != 0:
                self._log("update_keybox", su_cmd, False)
                return ToolResult(
                    success=False,
                    error=(
                        f"su copy failed (exit {res.returncode}): {res.stderr}; "
                        "root is required to install the keybox"
                    ),
                    command=su_cmd,
                )

            self._log("update_keybox", su_cmd, True)
            return ToolResult(
                success=True,
                data={
                    "pushed": True,
                    "remote_path": final_path,
                    "revoked": False,
                    "revoked_reason": None,
                },
                command=su_cmd,
            )
        except Exception as exc:
            self._log("update_keybox", None, False)
            return self._tool_error("update_keybox", exc)
        finally:
            if local_tmp and os.path.exists(local_tmp):
                try:
                    os.remove(local_tmp)
                except Exception:
                    pass

    # ------------------------------------------------------------------
    # SOTA / root module operations
    # ------------------------------------------------------------------
    _MODULE_ID_RE: ClassVar[re.Pattern[str]] = re.compile(r"^[a-zA-Z0-9_.-]+$")

    def _module_manager(self, dev: Any) -> str:
        """Return the module CLI name for the device's root solution."""
        su = str(getattr(dev, "su_version", "")).lower()
        if "kernelsu" in su or "sukisu" in su or "wild_ksu" in su:
            return "ksud"
        if "apatch" in su:
            return "apd"
        return "magisk"

    def _build_module_command(self, inner: str) -> str:
        """Build a canonical ``adb -s <id> shell su -c '<inner>'`` string."""
        return self._adb_cmd(f"shell su -c {self._q(inner)}")

    def _validate_module_id(self, module_id: str) -> ToolResult | None:
        """Return a ToolResult error if *module_id* contains unsafe characters."""
        if not module_id or not self._MODULE_ID_RE.match(module_id):
            return ToolResult(
                success=False,
                error=f"Invalid module_id: {module_id!r}. Only [a-zA-Z0-9_.-] is allowed.",
            )
        return None

    def _get_modules(self, dev: Any) -> tuple[list[dict[str, Any]], str]:
        """Return (modules, root_solution) by auto-detecting the root solution."""
        su = str(getattr(dev, "su_version", ""))
        su_lower = su.lower()
        if "magisk" in su_lower:
            modules = dev.get_magisk_detailed_modules()
            return modules, su
        if "kernelsu" in su_lower:
            modules = dev.get_ksu_detailed_modules()
            return modules, su
        if "sukisu" in su_lower:
            modules = dev.get_sukisu_detailed_modules()
            return modules, su
        if "wild_ksu" in su_lower:
            modules = dev.get_wild_ksu_detailed_modules()
            return modules, su
        if "apatch" in su_lower:
            modules = dev.get_apatch_detailed_modules()
            return modules, su
        raise ValueError(f"Unrecognized root solution: {su!r}")

    def list_modules(self) -> ToolResult:
        """List installed root modules, auto-detecting the root solution."""
        try:
            dev = self._lazy_device()
            if not getattr(dev, "rooted", False):
                return ToolResult(
                    success=False,
                    error="Device is not rooted; cannot list modules.",
                )
            modules, root_solution = self._get_modules(dev)
            entries = [
                {
                    "id": getattr(m, "id", ""),
                    "name": getattr(m, "name", ""),
                    "version": getattr(m, "version", ""),
                    "state": getattr(m, "state", "enabled"),
                    "has_action": bool(getattr(m, "hasAction", False)),
                }
                for m in modules or []
            ]
            self._log("list_modules", None, True)
            return ToolResult(
                success=True,
                data={
                    "modules": entries,
                    "count": len(entries),
                    "root_solution": root_solution,
                },
            )
        except Exception as exc:
            self._log("list_modules", None, False)
            return self._tool_error("list_modules", exc)

    def install_module(
        self,
        module_path: str,
        dry_run: bool = True,
        confirm: bool = False,
    ) -> ToolResult:
        """Install a local module zip on the device."""
        try:
            dev = self._lazy_device()
            if not getattr(dev, "rooted", False):
                return ToolResult(
                    success=False,
                    error="Device is not rooted; cannot install modules.",
                )

            module_path = module_path.strip()
            if module_path.lower().startswith(("http://", "https://")):
                return ToolResult(
                    success=False,
                    error="URL module download is not supported in this release; please download the zip locally first.",
                )

            resolved = os.path.abspath(os.path.expanduser(module_path))
            if not os.path.isfile(resolved):
                return ToolResult(
                    success=False,
                    error=f"Module zip not found: {resolved}",
                )
            if not zipfile.is_zipfile(resolved):
                return ToolResult(
                    success=False,
                    error=f"File is not a valid zip archive: {resolved}",
                )

            module_name = os.path.basename(resolved)
            manager = self._module_manager(dev)
            if manager == "magisk":
                inner = f"magisk --install-module /sdcard/Download/{module_name}"
            else:
                inner = f"{manager} module install /sdcard/Download/{module_name}"
            command = self._build_module_command(inner)

            # Dry-run previews still pass the whitelist gate; execution requires
            # the real confirm value.
            blocked = self._evaluate(
                command,
                RiskTier.WARN,
                confirm=True if dry_run else confirm,
            )
            if blocked:
                self._log("install_module", command, False)
                return blocked

            if dry_run:
                self._log("install_module", command, True)
                return ToolResult(
                    success=True,
                    dry_run=True,
                    data={
                        "module_path": resolved,
                        "module_name": module_name,
                    },
                    command=command,
                    warnings=["Dry run - no changes made"],
                )

            preflight = self._run_preflight(RiskTier.WARN, expected_mode="adb")
            if preflight:
                self._log("install_module", command, False)
                return preflight

            rc = dev.magisk_install_module(resolved)
            success = rc == 0
            self._log("install_module", command, success)
            if not success:
                return ToolResult(
                    success=False,
                    error=f"magisk_install_module returned {rc}",
                    command=command,
                )
            return ToolResult(
                success=True,
                data={"module_path": resolved, "module_name": module_name},
                command=command,
            )
        except Exception as exc:
            self._log("install_module", None, False)
            return self._tool_error("install_module", exc)

    def uninstall_module(
        self,
        module_id: str,
        dry_run: bool = True,
        confirm: bool = False,
    ) -> ToolResult:
        """Uninstall (mark for removal) a root module."""
        invalid = self._validate_module_id(module_id)
        if invalid:
            return invalid

        try:
            dev = self._lazy_device()
            manager = self._module_manager(dev)
            if manager in ("ksud", "apd"):
                inner = f"{manager} module uninstall {module_id}"
            else:
                inner = f"touch /data/adb/modules/{module_id}/remove"
            command = self._build_module_command(inner)

            if dry_run:
                modules = self.list_modules()
                if not modules.success:
                    return modules
                ids = {m.get("id") for m in modules.data.get("modules", [])}
                if module_id not in ids:
                    return ToolResult(
                        success=False,
                        error=f"Module {module_id!r} is not installed",
                    )

            blocked = self._evaluate(
                command,
                RiskTier.WARN,
                confirm=True if dry_run else confirm,
            )
            if blocked:
                self._log("uninstall_module", command, False)
                return blocked

            if dry_run:
                self._log("uninstall_module", command, True)
                return ToolResult(
                    success=True,
                    dry_run=True,
                    data={"module_id": module_id},
                    command=command,
                    warnings=["Dry run - no changes made"],
                )

            preflight = self._run_preflight(RiskTier.WARN, expected_mode="adb")
            if preflight:
                self._log("uninstall_module", command, False)
                return preflight

            rc = dev.magisk_uninstall_module(module_id)
            success = rc == 0
            self._log("uninstall_module", command, success)
            if not success:
                return ToolResult(
                    success=False,
                    error=f"magisk_uninstall_module returned {rc}",
                    command=command,
                )
            return ToolResult(
                success=True,
                data={"module_id": module_id},
                command=command,
            )
        except Exception as exc:
            self._log("uninstall_module", None, False)
            return self._tool_error("uninstall_module", exc)

    def enable_module(
        self,
        module_id: str,
        dry_run: bool = True,
        confirm: bool = False,
    ) -> ToolResult:
        """Enable a previously disabled root module."""
        invalid = self._validate_module_id(module_id)
        if invalid:
            return invalid

        try:
            dev = self._lazy_device()
            inner = f"rm -f /data/adb/modules/{module_id}/disable"
            command = self._build_module_command(inner)

            blocked = self._evaluate(
                command,
                RiskTier.WARN,
                confirm=True if dry_run else confirm,
            )
            if blocked:
                self._log("enable_module", command, False)
                return blocked

            if dry_run:
                self._log("enable_module", command, True)
                return ToolResult(
                    success=True,
                    dry_run=True,
                    data={"module_id": module_id, "current_state": "enabled"},
                    command=command,
                    warnings=["Dry run - no changes made"],
                )

            preflight = self._run_preflight(RiskTier.WARN, expected_mode="adb")
            if preflight:
                self._log("enable_module", command, False)
                return preflight

            rc = dev.enable_magisk_module(module_id)
            success = rc == 0
            self._log("enable_module", command, success)
            if not success:
                return ToolResult(
                    success=False,
                    error=f"enable_magisk_module returned {rc}",
                    command=command,
                )
            return ToolResult(
                success=True,
                data={"module_id": module_id, "current_state": "enabled"},
                command=command,
            )
        except Exception as exc:
            self._log("enable_module", None, False)
            return self._tool_error("enable_module", exc)

    def disable_module(
        self,
        module_id: str,
        dry_run: bool = True,
        confirm: bool = False,
    ) -> ToolResult:
        """Disable a root module."""
        invalid = self._validate_module_id(module_id)
        if invalid:
            return invalid

        try:
            dev = self._lazy_device()
            inner = f"touch /data/adb/modules/{module_id}/disable"
            command = self._build_module_command(inner)

            blocked = self._evaluate(
                command,
                RiskTier.WARN,
                confirm=True if dry_run else confirm,
            )
            if blocked:
                self._log("disable_module", command, False)
                return blocked

            if dry_run:
                self._log("disable_module", command, True)
                return ToolResult(
                    success=True,
                    dry_run=True,
                    data={"module_id": module_id, "current_state": "disabled"},
                    command=command,
                    warnings=["Dry run - no changes made"],
                )

            preflight = self._run_preflight(RiskTier.WARN, expected_mode="adb")
            if preflight:
                self._log("disable_module", command, False)
                return preflight

            rc = dev.disable_magisk_module(module_id)
            success = rc == 0
            self._log("disable_module", command, success)
            if not success:
                return ToolResult(
                    success=False,
                    error=f"disable_magisk_module returned {rc}",
                    command=command,
                )
            return ToolResult(
                success=True,
                data={"module_id": module_id, "current_state": "disabled"},
                command=command,
            )
        except Exception as exc:
            self._log("disable_module", None, False)
            return self._tool_error("disable_module", exc)

    def run_module_action(
        self,
        module_id: str,
        dry_run: bool = True,
        confirm: bool = False,
    ) -> ToolResult:
        """Run a module's action.sh script."""
        invalid = self._validate_module_id(module_id)
        if invalid:
            return invalid

        try:
            dev = self._lazy_device()
            inner = f"busybox sh -o standalone /data/adb/modules/{module_id}/action.sh"
            command = self._build_module_command(inner)

            if dry_run:
                modules = self.list_modules()
                if not modules.success:
                    return modules
                entry = next(
                    (m for m in modules.data.get("modules", []) if m.get("id") == module_id),
                    None,
                )
                if entry is None:
                    return ToolResult(
                        success=False,
                        error=f"Module {module_id!r} is not installed",
                    )
                if not entry.get("has_action"):
                    return ToolResult(
                        success=False,
                        error=f"Module {module_id!r} does not have an action.sh script",
                    )

            blocked = self._evaluate(
                command,
                RiskTier.WARN,
                confirm=True if dry_run else confirm,
            )
            if blocked:
                self._log("run_module_action", command, False)
                return blocked

            if dry_run:
                self._log("run_module_action", command, True)
                return ToolResult(
                    success=True,
                    dry_run=True,
                    data={"module_id": module_id},
                    command=command,
                    warnings=["Dry run - no changes made"],
                )

            preflight = self._run_preflight(RiskTier.WARN, expected_mode="adb")
            if preflight:
                self._log("run_module_action", command, False)
                return preflight

            rc = dev.magisk_run_module_action(module_id)
            success = rc == 0
            self._log("run_module_action", command, success)
            if not success:
                return ToolResult(
                    success=False,
                    error=f"magisk_run_module_action returned {rc}",
                    command=command,
                )
            return ToolResult(
                success=True,
                data={"module_id": module_id},
                command=command,
            )
        except Exception as exc:
            self._log("run_module_action", None, False)
            return self._tool_error("run_module_action", exc)

    # ------------------------------------------------------------------
    # Backup listing (read-only)
    # ------------------------------------------------------------------
    def list_backups(self) -> ToolResult:
        """List boot backup files in /data/adb/magisk_backup/."""
        backup_dir = "/data/adb/magisk_backup"
        subcommand = f"shell ls -la {self._q(backup_dir)}"
        command = self._adb_cmd(subcommand)
        blocked = self._evaluate(command, RiskTier.INFO, confirm=False)
        if blocked:
            return ToolResult(
                success=False,
                error=blocked.error or "Backup listing blocked by safety gateway",
                command=command,
            )
        exec_cmd = self._exec_adb_cmd(subcommand)
        res = self._run_shell_safe(exec_cmd, timeout=30)
        if res.returncode != 0:
            # Directory likely does not exist; this is not an error for callers.
            return ToolResult(success=True, data={"backups": [], "count": 0})

        backups: list[dict[str, Any]] = []
        for line in res.stdout.splitlines():
            parts = line.split()
            if len(parts) < 8:
                continue
            name = parts[-1]
            if name in (".", ".."):
                continue
            if not (fnmatch.fnmatch(name, "boot_*.img") or fnmatch.fnmatch(name, "*.img.gz")):
                continue
            try:
                size = int(parts[4])
            except ValueError:
                size = None
            date = f"{parts[5]} {parts[6]}"
            backups.append(
                {
                    "sha1": name,
                    "date": date,
                    "firmware": None,
                    "name": name,
                    "size": size,
                }
            )

        self._log("list_backups", command, True)
        return ToolResult(success=True, data={"backups": backups, "count": len(backups)})

    def restore_backup(
        self,
        backup_name: str,
        dry_run: bool = True,
        confirm: bool = False,
    ) -> ToolResult:
        """Restore a previously-created boot backup.

        The backup is pulled from the device and then flashed to the boot
        partition via :meth:`flash_partition`, which provides the same backup
        and rollback safety as a normal boot flash.
        """
        if not re.match(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*$", backup_name):
            return ToolResult(
                success=False,
                error=f"Invalid backup name: {backup_name}",
            )

        remote_path = f"/data/adb/magisk_backup/{backup_name}"

        if dry_run:
            command = self._adb_cmd(f"pull {self._q(remote_path)} <local_tmp>")
            return ToolResult(
                success=True,
                dry_run=True,
                data={
                    "backup_name": backup_name,
                    "remote_path": remote_path,
                    "partition": "boot",
                },
                command=command,
                warnings=["Dry run - no changes made"],
            )

        local_fd, local_tmp = tempfile.mkstemp(prefix="backup_", suffix=".img")
        os.close(local_fd)
        try:
            pull_result = self.pull_file(remote_path, local_tmp, confirm=False)
            if not pull_result.success:
                return pull_result
            local_path = (pull_result.data or {}).get("local_path", local_tmp)
            return self.flash_partition("boot", local_path, confirm=confirm)
        finally:
            if os.path.exists(local_tmp):
                try:
                    os.remove(local_tmp)
                except Exception:
                    pass

    # ------------------------------------------------------------------
    # AVB verification / signing (host-side)
    # ------------------------------------------------------------------
    def avb_sign_image(
        self,
        image_path: str,
        key_path: str,
        algorithm: str = "SHA256_RSA4096",
        confirm: bool = False,
    ) -> ToolResult:
        """Sign a local image using avbtool.

        The input image is copied to ``<image>.signed.img`` and a hash footer is
        added with the supplied key and algorithm.  This is a host-side operation;
        it does not touch the device.
        """
        resolved = os.path.abspath(os.path.expanduser(image_path))
        key_resolved = os.path.abspath(os.path.expanduser(key_path))

        if not os.path.isfile(resolved):
            return ToolResult(
                success=False,
                error=f"Image file not found: {resolved}",
            )
        if not os.path.isfile(key_resolved):
            return ToolResult(
                success=False,
                error=f"Key file not found: {key_resolved}",
            )

        base, ext = os.path.splitext(resolved)
        signed_path = f"{base}.signed{ext}"
        partition_name = os.path.basename(base)

        command = (
            f"avbtool add_hash_footer --image {self._q(resolved)} "
            f"--dynamic_partition_size --partition_name {self._q(partition_name)} "
            f"--hash_algorithm sha256 --algorithm {self._q(algorithm)} "
            f"--key {self._q(key_resolved)}"
        )
        blocked = self._evaluate(command, RiskTier.WARN, confirm)
        if blocked:
            self._log("avb_sign_image", command, False)
            return blocked

        try:
            import avbtool
        except Exception as exc:
            return ToolResult(
                success=False,
                error=f"Could not import avbtool: {exc}",
            )

        try:
            shutil.copy2(resolved, signed_path)
            tool = avbtool.AvbTool()
            tool.add_hash_footer(
                image_filename=signed_path,
                partition_size=0,
                dynamic_partition_size=True,
                partition_name=partition_name,
                hash_algorithm="sha256",
                salt=None,
                chain_partitions_use_ab=None,
                chain_partitions_do_not_use_ab=None,
                algorithm_name=algorithm,
                key_path=key_resolved,
                public_key_metadata_path=None,
                rollback_index=0,
                flags=0,
                rollback_index_location=0,
                props=None,
                props_from_file=None,
                kernel_cmdlines=None,
                setup_rootfs_from_kernel=None,
                include_descriptors_from_image=None,
                calc_max_image_size=False,
                signing_helper=None,
                signing_helper_with_files=None,
                release_string=None,
                append_to_release_string=None,
                output_vbmeta_image=None,
                do_not_append_vbmeta_image=False,
                print_required_libavb_version=False,
                use_persistent_digest=False,
                do_not_use_ab=False,
            )
            self._log("avb_sign_image", command, True)
            return ToolResult(
                success=True,
                data={"signed_path": signed_path, "algorithm": algorithm},
                command=command,
            )
        except avbtool.AvbError as exc:
            self._log("avb_sign_image", command, False)
            return ToolResult(
                success=False,
                error=f"avbtool error: {exc}",
                command=command,
            )
        except Exception as exc:
            self._log("avb_sign_image", command, False)
            return ToolResult(
                success=False,
                error=f"AVB signing failed: {exc}",
                command=command,
            )

    def avb_verify_image(self, image_path: str) -> ToolResult:
        """Verify the AVB signature of a local image using avbtool."""
        resolved = os.path.abspath(os.path.expanduser(image_path))
        if not os.path.isfile(resolved):
            return ToolResult(
                success=False,
                error=f"Image file not found: {resolved}",
            )

        try:
            import avbtool
        except Exception as exc:
            return ToolResult(
                success=False,
                error=f"Could not import avbtool: {exc}",
            )

        try:
            tool = avbtool.AvbTool()
            output = io.StringIO()
            info = tool.info_image(resolved, output, atx=False) or {}
            algorithm = info.get("Algorithm")
            hash_alg = info.get("Hash Algorithm")

            try:
                tool.verify_image(resolved, None, None, False, False)
                valid = True
                error = None
            except avbtool.AvbError as exc:
                valid = False
                error = str(exc)

            return ToolResult(
                success=True,
                data={
                    "valid": valid,
                    "algorithm": algorithm,
                    "hash": hash_alg,
                    "chain": [],
                    "warnings": [],
                    "error": error,
                },
            )
        except Exception as exc:
            return ToolResult(
                success=False,
                error=f"AVB verification failed: {exc}",
            )


__all__ = ["DeviceOps"]

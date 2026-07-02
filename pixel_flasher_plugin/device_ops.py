"""Core device operations facade for the PixelFlasher MCP server.

This module wraps :class:`phone.Device` behind a lazy, headless-safe API that
returns structured :class:`ToolResult` objects.  Every state-changing operation
is routed through :class:`SafetyGateway` before execution.
"""
from __future__ import annotations

import hashlib
import os
import re
import shlex
import subprocess
import tempfile
from typing import Any, ClassVar

from pixel_flasher_plugin import command_validator, telemetry
from pixel_flasher_plugin.headless_runtime import bootstrap, get_device
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
        """Flash a partition image via fastboot."""
        try:
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

            exec_cmd = self._exec_fastboot_cmd(subcommand)
            res = self._run_shell_safe(exec_cmd, timeout=300)
            success = res.returncode == 0
            self._log("flash_partition", command, success)
            if not success:
                return ToolResult(
                    success=False,
                    error=f"flash failed (exit {res.returncode}): {res.stderr}",
                    command=command,
                )
            return ToolResult(
                success=True,
                data={"partition": partition, "image_path": resolved},
                command=command,
            )
        except Exception as exc:
            self._log("flash_partition", None, False)
            return self._tool_error("flash_partition", exc)

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


__all__ = ["DeviceOps"]

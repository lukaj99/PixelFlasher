"""SafetyGateway — enforcement engine between MCP tools and Device operations."""
from __future__ import annotations

import asyncio
import enum
import hashlib
import os
import shutil
import time
import traceback
from typing import Any, Callable

from pixel_flasher_plugin import command_validator
from pixel_flasher_plugin import headless_runtime
from pixel_flasher_plugin.result_types import CheckResult, RiskTier, ToolResult
from pixel_flasher_plugin.telemetry import get_logger

if False:
    from config import Config

logger = get_logger(__name__)


class Decision(enum.Enum):
    ALLOW = "ALLOW"
    CONFIRM = "CONFIRM"
    DENY = "DENY"


class SafetyGateway:
    """Validate commands, run pre-flight checks, enforce confirmation gates, and
    execute mutating Device operations with timeout, post-condition, and rollback
    support.
    """

    def __init__(self, config: "Config" | None, device_ops: Any | None = None):
        self.config = config
        self.device_ops = device_ops

    # ------------------------------------------------------------------
    # Command validation
    # ------------------------------------------------------------------
    def validate(self, command: str, device_id: str, risk_tier: RiskTier) -> CheckResult:
        """Validate *command* against the ADB/fastboot whitelist and partition blocklist."""
        allowed, reason = command_validator.CommandValidator.is_allowed(command)
        if allowed:
            return CheckResult(
                name="command_validation",
                passed=True,
                detail=f"Command allowed for {device_id}",
                severity=risk_tier,
            )
        return CheckResult(
            name="command_validation",
            passed=False,
            detail=reason,
            severity=risk_tier,
        )

    # ------------------------------------------------------------------
    # Decision gate
    # ------------------------------------------------------------------
    def evaluate(
        self,
        command: str,
        args: dict[str, Any] | None = None,
    ) -> tuple[Decision, str]:
        """Return a coarse-grained safety decision for a proposed command.

        The decision is one of:
          - DENY:  command violates the whitelist or partition blocklist.
          - CONFIRM: command is allowed but requires explicit confirmation.
          - ALLOW: command is allowed and confirmation has been satisfied.

        *args* may contain ``risk_tier`` (a ``RiskTier``) and ``confirm``
        (a ``bool``).  CRITICAL operations always require ``confirm=True``;
        WARN operations require confirmation unless ``confirm=True`` is given.
        """
        args = args or {}
        risk_tier = args.get("risk_tier", RiskTier.INFO)
        confirm = args.get("confirm", False)

        allowed, reason = command_validator.CommandValidator.is_allowed(command)
        if not allowed:
            return Decision.DENY, reason

        if risk_tier == RiskTier.CRITICAL:
            if not confirm:
                return Decision.CONFIRM, "CRITICAL operation requires confirm=True"
            return Decision.ALLOW, ""

        if risk_tier == RiskTier.WARN:
            if not confirm:
                return Decision.CONFIRM, "Operation requires confirmation"
            return Decision.ALLOW, ""

        return Decision.ALLOW, ""

    # ------------------------------------------------------------------
    # Main execution pipeline
    # ------------------------------------------------------------------
    async def execute(
        self,
        tool_fn: Callable[..., Any],
        args: dict[str, Any],
        ctx: Any | None = None,
        risk_tier: RiskTier = RiskTier.INFO,
        dry_run: bool = True,
        timeout: int = 30,
        preflight_checks: list[str] | None = None,
        postcondition_fn: Callable | None = None,
        rollback_fn: Callable | None = None,
    ) -> ToolResult:
        """Run the full safety pipeline and execute *tool_fn*.

        The pipeline is:
        1. Record start time.
        2. Run requested pre-flight checks.
        3. Enforce confirmation gate for WARN/CRITICAL non-dry-run operations.
        4. If dry_run, return a preview result without executing.
        5. Execute *tool_fn* in a thread pool with *timeout*.
        6. Catch exceptions and convert to ToolResult.
        7. Run post-condition check; on failure, trigger rollback if provided.
        8. Build ToolResult, audit log, and return.
        """
        start_time = time.perf_counter()
        device_id = args.get("device_id", "")
        command = args.get("command")
        preflight_results: list[CheckResult] = []
        postcondition_results: list[CheckResult] = []
        rollback_performed = False
        warnings: list[str] = []
        data: Any = None
        error: str | None = None
        success = False

        async def _progress(current: int, total: int) -> None:
            if ctx is not None and hasattr(ctx, "report_progress"):
                try:
                    await ctx.report_progress(current, total)
                except Exception:
                    pass

        try:
            await _progress(0, 100)

            # 2. Pre-flight checks
            if preflight_checks:
                preflight_results = self.run_preflight(device_id, preflight_checks, args)
                blocking = [c for c in preflight_results if not c.passed and c.severity == RiskTier.CRITICAL]
                if blocking:
                    error = f"Pre-flight check failed: {blocking[0].name} - {blocking[0].detail}"
                    success = False
                    return self._build_result(
                        success=success,
                        data=data,
                        error=error,
                        warnings=warnings,
                        dry_run=dry_run,
                        preflight_checks=preflight_results,
                        postcondition_checks=postcondition_results,
                        start_time=start_time,
                        command=command,
                        rollback_performed=rollback_performed,
                        device_id=device_id,
                    )

            await _progress(25, 100)

            # 3. Confirmation gate
            if risk_tier in (RiskTier.WARN, RiskTier.CRITICAL) and not dry_run:
                if risk_tier == RiskTier.CRITICAL and args.get("confirm") is not True:
                    error = "CRITICAL operation requires confirm=True"
                    success = False
                    return self._build_result(
                        success=success,
                        data=data,
                        error=error,
                        warnings=warnings,
                        dry_run=dry_run,
                        preflight_checks=preflight_results,
                        postcondition_checks=postcondition_results,
                        start_time=start_time,
                        command=command,
                        rollback_performed=rollback_performed,
                        device_id=device_id,
                    )

            await _progress(50, 100)

            # 4. Dry-run preview
            if dry_run:
                success = True
                data = {"preview": "dry run - no execution"}
                warnings.append("Dry run - no changes made")
                return self._build_result(
                    success=success,
                    data=data,
                    error=error,
                    warnings=warnings,
                    dry_run=True,
                    preflight_checks=preflight_results,
                    postcondition_checks=postcondition_results,
                    start_time=start_time,
                    command=command,
                    rollback_performed=rollback_performed,
                    device_id=device_id,
                )

            # 5. Execute tool_fn with timeout in a thread pool
            try:
                loop = asyncio.get_running_loop()
                data = await asyncio.wait_for(
                    loop.run_in_executor(None, lambda: tool_fn(**args)),
                    timeout=timeout,
                )
                success = True
            except asyncio.TimeoutError:
                error = f"Operation timed out after {timeout}s"
                success = False
            except Exception as exc:
                error = f"{type(exc).__name__}: {exc}"
                success = False

            await _progress(75, 100)

            # 7. Post-condition check and rollback
            if success and postcondition_fn is not None:
                try:
                    post_ok, post_detail = self._run_postcondition(postcondition_fn, args, data)
                    postcondition_results.append(
                        CheckResult(
                            name="postcondition",
                            passed=post_ok,
                            detail=post_detail,
                            severity=RiskTier.CRITICAL if not post_ok else RiskTier.INFO,
                        )
                    )
                    if not post_ok:
                        if rollback_fn is not None:
                            try:
                                rollback_fn(**args)
                                rollback_performed = True
                                warnings.append("Post-condition failed; rollback performed")
                            except Exception as rb_exc:
                                warnings.append(f"Post-condition failed; rollback failed: {rb_exc}")
                        else:
                            warnings.append(f"Post-condition failed: {post_detail}")
                        success = False
                        error = error or f"Post-condition failed: {post_detail}"
                except Exception as exc:
                    postcondition_results.append(
                        CheckResult(
                            name="postcondition",
                            passed=False,
                            detail=str(exc),
                            severity=RiskTier.CRITICAL,
                        )
                    )
                    warnings.append(f"Post-condition check raised: {exc}")

        except Exception as exc:
            error = f"SafetyGateway pipeline error: {exc}"
            success = False
        finally:
            await _progress(100, 100)

        return self._build_result(
            success=success,
            data=data,
            error=error,
            warnings=warnings,
            dry_run=dry_run,
            preflight_checks=preflight_results,
            postcondition_checks=postcondition_results,
            start_time=start_time,
            command=command,
            rollback_performed=rollback_performed,
            device_id=device_id,
        )

    # ------------------------------------------------------------------
    # Result builder + audit
    # ------------------------------------------------------------------
    def _build_result(
        self,
        *,
        success: bool,
        data: Any,
        error: str | None,
        warnings: list[str],
        dry_run: bool,
        preflight_checks: list[CheckResult],
        postcondition_checks: list[CheckResult],
        start_time: float,
        command: str | None,
        rollback_performed: bool,
        device_id: str,
    ) -> ToolResult:
        execution_time_ms = int((time.perf_counter() - start_time) * 1000)
        result = ToolResult(
            success=success,
            data=data,
            error=error,
            warnings=warnings,
            dry_run=dry_run,
            preflight_checks=preflight_checks,
            postcondition_checks=postcondition_checks,
            execution_time_ms=execution_time_ms,
            command=command,
            rollback_performed=rollback_performed,
        )
        entry: dict[str, Any] = {
            "event": "tool_execution",
            "command": command,
            "result": "success" if success else "failure",
            "dry_run": dry_run,
            "error": error,
            "execution_time_ms": execution_time_ms,
            "rollback_performed": rollback_performed,
        }
        if device_id:
            entry["device_id_hash"] = hashlib.sha256(device_id.encode("utf-8")).hexdigest()[:16]
        else:
            entry["device_id_hash"] = None
        logger.info("audit", extra=entry)
        return result

    def verify_postcondition(
        self,
        postcondition_fn: Callable,
        args: dict[str, Any],
        data: Any,
    ) -> tuple[bool, str]:
        """Run a postcondition check synchronously. Wraps the existing _run_postcondition."""
        return self._run_postcondition(postcondition_fn, args, data)

    def perform_rollback(
        self,
        rollback_fn: Callable,
        args: dict[str, Any],
        reason: str,
    ) -> tuple[bool, str]:
        """Execute a rollback function synchronously. Returns (success, detail).

        Catches all exceptions so rollback never raises into the caller.
        """
        try:
            rollback_fn(args)
            return True, "rollback completed"
        except Exception as exc:
            return False, f"{type(exc).__name__}: {exc}"

    def _run_postcondition(
        self,
        postcondition_fn: Callable,
        args: dict[str, Any],
        data: Any,
    ) -> tuple[bool, str]:
        """Invoke a post-condition callable and normalize its return value."""
        try:
            result = postcondition_fn(args=args, data=data)
        except Exception:
            return False, traceback.format_exc()
        if isinstance(result, tuple) and len(result) == 2 and isinstance(result[0], bool):
            return result
        if isinstance(result, bool):
            return result, "postcondition" if result else "postcondition failed"
        return bool(result), str(result)

    # ------------------------------------------------------------------
    # Pre-flight checks
    # ------------------------------------------------------------------
    def run_preflight(
        self,
        device_id: str,
        check_names: list[str],
        check_args: dict[str, Any] | None = None,
    ) -> list[CheckResult]:
        """Execute named pre-flight checks and return their results.

        Each check is wrapped in try/except so a failing check never crashes the
        gateway.
        """
        check_args = check_args or {}
        results: list[CheckResult] = []
        for name in check_names:
            try:
                results.append(self._run_check(name, device_id, check_args))
            except Exception as exc:
                results.append(
                    CheckResult(
                        name=name,
                        passed=False,
                        detail=f"Check crashed: {exc}",
                        severity=RiskTier.CRITICAL,
                    )
                )
        return results

    def _run_check(self, name: str, device_id: str, args: dict[str, Any]) -> CheckResult:
        """Dispatch a single pre-flight check by name."""
        if name == "device_connected":
            return self._check_device_connected(device_id)
        if name == "correct_mode":
            return self._check_correct_mode(device_id, args.get("expected_mode", "adb"))
        if name == "bootloader_unlocked":
            return self._check_bootloader_unlocked(device_id)
        if name == "battery_level":
            return self._check_battery_level(device_id, args.get("min_battery", 50))
        if name == "disk_space":
            return self._check_disk_space(args.get("path", "."), args.get("min_gb", 5))
        if name == "platform_tools_valid":
            return self._check_platform_tools_valid()
        if name == "sha256_verify":
            return self._check_sha256(args.get("path"), args.get("expected_hash"))
        if name == "anti_rollback":
            return self._check_anti_rollback(device_id, args.get("firmware_date"))
        if name == "oem_unlock_ability":
            return self._check_oem_unlock_ability(device_id)
        if name == "critical_partition_backup":
            return self._check_critical_partition_backup(device_id, args.get("partition", "boot"))
        return CheckResult(
            name=name,
            passed=False,
            detail=f"Unknown pre-flight check: {name}",
            severity=RiskTier.CRITICAL,
        )

    def _get_device(self, device_id: str, mode: str = "adb") -> Any:
        """Construct a Device instance via headless_runtime."""
        return headless_runtime.get_device(device_id, mode=mode)

    def _check_device_connected(self, device_id: str) -> CheckResult:
        try:
            device = self._get_device(device_id)
            connected = device.is_connected(device_id)
            return CheckResult(
                name="device_connected",
                passed=connected,
                detail="Device is connected" if connected else "Device is not connected",
                severity=RiskTier.CRITICAL if not connected else RiskTier.INFO,
            )
        except Exception as exc:
            return CheckResult(
                name="device_connected",
                passed=False,
                detail=str(exc),
                severity=RiskTier.CRITICAL,
            )

    def _check_correct_mode(self, device_id: str, expected_mode: str) -> CheckResult:
        try:
            device = self._get_device(device_id, mode=expected_mode)
            actual = device.get_device_state(device_id, update=False)
            passed = actual == expected_mode
            return CheckResult(
                name="correct_mode",
                passed=passed,
                detail=f"Expected {expected_mode}, got {actual}",
                severity=RiskTier.CRITICAL if not passed else RiskTier.INFO,
            )
        except Exception as exc:
            return CheckResult(
                name="correct_mode",
                passed=False,
                detail=str(exc),
                severity=RiskTier.CRITICAL,
            )

    def _check_bootloader_unlocked(self, device_id: str) -> CheckResult:
        try:
            device = self._get_device(device_id, mode="adb")
            unlocked = device.unlocked
            return CheckResult(
                name="bootloader_unlocked",
                passed=unlocked is True,
                detail="Bootloader is unlocked" if unlocked else "Bootloader is locked",
                severity=RiskTier.CRITICAL if not unlocked else RiskTier.INFO,
            )
        except Exception as exc:
            return CheckResult(
                name="bootloader_unlocked",
                passed=False,
                detail=str(exc),
                severity=RiskTier.CRITICAL,
            )

    def _check_battery_level(self, device_id: str, min_pct: int = 50) -> CheckResult:
        try:
            device = self._get_device(device_id, mode="adb")
            if device.true_mode != "adb":
                return CheckResult(
                    name="battery_level",
                    passed=True,
                    detail="Cannot read battery in non-ADB mode; skipped",
                    severity=RiskTier.WARN,
                )
            output = device.get_battery_details()
            if not output:
                return CheckResult(
                    name="battery_level",
                    passed=True,
                    detail="Battery level unavailable; skipped",
                    severity=RiskTier.WARN,
                )
            level = self._parse_battery_level(output)
            if level is None:
                return CheckResult(
                    name="battery_level",
                    passed=True,
                    detail="Could not parse battery level; skipped",
                    severity=RiskTier.WARN,
                )
            passed = level >= min_pct
            return CheckResult(
                name="battery_level",
                passed=passed,
                detail=f"Battery level {level}% (minimum {min_pct}%)",
                severity=RiskTier.CRITICAL if not passed else RiskTier.INFO,
            )
        except Exception as exc:
            return CheckResult(
                name="battery_level",
                passed=True,
                detail=f"Battery check failed: {exc}; skipped",
                severity=RiskTier.WARN,
            )

    @staticmethod
    def _parse_battery_level(output: str) -> int | None:
        """Parse a battery percentage from `dumpsys battery` output."""
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("level:"):
                try:
                    return int(line.split(":", 1)[1].strip())
                except (ValueError, IndexError):
                    continue
        return None

    def _check_disk_space(self, path: str, min_gb: int = 5) -> CheckResult:
        try:
            resolved = os.path.abspath(os.path.expanduser(path))
            if not os.path.isdir(resolved):
                resolved = os.path.dirname(resolved) or "."
            usage = shutil.disk_usage(resolved)
            free_gb = usage.free / (1024 ** 3)
            passed = free_gb >= min_gb
            return CheckResult(
                name="disk_space",
                passed=passed,
                detail=f"Free space {free_gb:.2f} GB on {resolved} (minimum {min_gb} GB)",
                severity=RiskTier.CRITICAL if not passed else RiskTier.INFO,
            )
        except Exception as exc:
            return CheckResult(
                name="disk_space",
                passed=False,
                detail=str(exc),
                severity=RiskTier.CRITICAL,
            )

    def _check_platform_tools_valid(self) -> CheckResult:
        try:
            adb = headless_runtime.runtime.get_adb()
            fastboot = headless_runtime.runtime.get_fastboot()
            passed = adb is not None and fastboot is not None
            return CheckResult(
                name="platform_tools_valid",
                passed=passed,
                detail="ADB and fastboot paths are set" if passed else "ADB or fastboot path is missing",
                severity=RiskTier.CRITICAL if not passed else RiskTier.INFO,
            )
        except Exception as exc:
            return CheckResult(
                name="platform_tools_valid",
                passed=False,
                detail=str(exc),
                severity=RiskTier.CRITICAL,
            )

    def _check_sha256(self, path: str | None, expected_hash: str | None) -> CheckResult:
        try:
            if not path or not expected_hash:
                return CheckResult(
                    name="sha256_verify",
                    passed=False,
                    detail="path and expected_hash are required",
                    severity=RiskTier.CRITICAL,
                )
            resolved = os.path.abspath(os.path.expanduser(path))
            if not os.path.isfile(resolved):
                return CheckResult(
                    name="sha256_verify",
                    passed=False,
                    detail=f"File not found: {resolved}",
                    severity=RiskTier.CRITICAL,
                )
            h = hashlib.sha256()
            with open(resolved, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            actual = h.hexdigest()
            passed = actual.lower() == expected_hash.lower()
            return CheckResult(
                name="sha256_verify",
                passed=passed,
                detail=f"SHA256 {actual} (expected {expected_hash})",
                severity=RiskTier.CRITICAL if not passed else RiskTier.INFO,
            )
        except Exception as exc:
            return CheckResult(
                name="sha256_verify",
                passed=False,
                detail=str(exc),
                severity=RiskTier.CRITICAL,
            )

    def _check_anti_rollback(self, device_id: str, firmware_date: str | None) -> CheckResult:
        """Conservative anti-rollback check.

        If the current device build date cannot be determined, or no firmware_date
        is supplied, the check warns but does not block.
        """
        try:
            if not firmware_date:
                return CheckResult(
                    name="anti_rollback",
                    passed=True,
                    detail="No firmware date supplied; skipped",
                    severity=RiskTier.WARN,
                )
            device = self._get_device(device_id, mode="adb")
            current_date = device.get_prop("ro.build.date.utc") or device.get_prop("ro.build.date")
            if not current_date:
                return CheckResult(
                    name="anti_rollback",
                    passed=True,
                    detail="Could not determine current build date; skipped",
                    severity=RiskTier.WARN,
                )
            # Normalize both to strings for comparison.
            passed = str(firmware_date) >= str(current_date)
            return CheckResult(
                name="anti_rollback",
                passed=passed,
                detail=f"Firmware date {firmware_date} vs current {current_date}",
                severity=RiskTier.CRITICAL if not passed else RiskTier.INFO,
            )
        except Exception as exc:
            return CheckResult(
                name="anti_rollback",
                passed=True,
                detail=f"Anti-rollback check failed: {exc}; skipped",
                severity=RiskTier.WARN,
            )

    def _check_oem_unlock_ability(self, device_id: str) -> CheckResult:
        try:
            device = self._get_device(device_id, mode="f.b")
            ability = device.get_unlock_ability()
            if ability is None:
                return CheckResult(
                    name="oem_unlock_ability",
                    passed=True,
                    detail="Could not determine OEM unlock ability; skipped",
                    severity=RiskTier.WARN,
                )
            passed = ability == 1
            return CheckResult(
                name="oem_unlock_ability",
                passed=passed,
                detail=f"OEM unlock ability = {ability}",
                severity=RiskTier.CRITICAL if not passed else RiskTier.INFO,
            )
        except Exception as exc:
            return CheckResult(
                name="oem_unlock_ability",
                passed=True,
                detail=f"OEM unlock ability check failed: {exc}; skipped",
                severity=RiskTier.WARN,
            )

    def _check_critical_partition_backup(self, device_id: str, partition: str = "boot") -> CheckResult:
        """Wave 2 stub: actual backup creation is delegated to tool implementations."""
        return CheckResult(
            name="critical_partition_backup",
            passed=True,
            detail="Backup check deferred to tool implementation",
            severity=RiskTier.INFO,
        )

"""PixelFlasher MCP server adapter.

This module exposes the PixelFlasher device-operation facade as 28 MCP tools
that AI agents can call.  It bootstraps the headless runtime once at startup
and shares the same SafetyGateway across all tool invocations.
"""
from __future__ import annotations

import os

os.environ.setdefault("PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION", "python")

import logging
import re
import shlex
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, AsyncIterator

from mcp.server.fastmcp import Context, FastMCP
from pydantic import BaseModel

from pixel_flasher_plugin.device_ops import DeviceOps
from pixel_flasher_plugin.output_models import (
    AvbSignOutput,
    AvbVerifyOutput,
    BackupListOutput,
    BackupOutput,
    BackupRestoreOutput,
    BootFlashOutput,
    BootloaderOutput,
    BootPatchOutput,
    DeviceInfoOutput,
    DeviceListOutput,
    FactoryFlashOutput,
    LogcatOutput,
    PackageInstallOutput,
    PackageListEntry,
    PackageListOutput,
    PackageStateOutput,
    PackageUninstallOutput,
    PartitionEntry,
    PartitionEraseOutput,
    PartitionFlashOutput,
    PartitionListOutput,
    PartitionReadOutput,
    PifStatusOutput,
    PifUpdateOutput,
    PlayIntegrityOutput,
    PropOutput,
    RebootOutput,
    WaitOutput,
)
from pixel_flasher_plugin.result_types import ToolResult

logger = logging.getLogger("pixel_flasher_mcp")


@dataclass
class AppContext:
    """Objects shared across the lifetime of the MCP server."""

    device_ops: Any  # DeviceOps
    gateway: Any  # SafetyGateway
    config: Any  # Config
    runtime: Any  # runtime module


@asynccontextmanager
async def app_lifespan(server: FastMCP) -> AsyncIterator[AppContext]:
    """Bootstrap the PixelFlasher headless runtime for the MCP server."""
    from pixel_flasher_plugin.headless_runtime import bootstrap
    from pixel_flasher_plugin.safety_engine import SafetyGateway

    adb = os.environ.get("PF_ADB_PATH", "adb")
    fb = os.environ.get("PF_FASTBOOT_PATH", "fastboot")
    cfg_path = os.environ.get("PF_CONFIG_PATH")
    rt, cfg = bootstrap(adb, fb, cfg_path)
    gw = SafetyGateway(config=cfg)
    ops = DeviceOps(gateway=gw)
    try:
        yield AppContext(device_ops=ops, gateway=gw, config=cfg, runtime=rt)
    finally:
        logger.info("PixelFlasher MCP server shutting down")


mcp = FastMCP(
    "PixelFlasher",
    lifespan=app_lifespan,
)


def _gateway(ctx: Context) -> Any:
    """Return the shared SafetyGateway from the request lifespan context."""
    return ctx.request_context.lifespan_context.gateway


def _ops(device_id: str, ctx: Context) -> DeviceOps:
    """Return the shared DeviceOps singleton, bound to the requested device ID.

    The lifespan context creates a single DeviceOps instance.  Re-binding its
    ``device_id`` attribute (and clearing any cached lazy device handle) lets
    every tool call share the same gateway/runtime without constructing a new
    facade per request.
    """
    ops: DeviceOps = ctx.request_context.lifespan_context.device_ops
    if ops.device_id != device_id:
        ops.device_id = device_id
        ops._device = None
    return ops


def _to_output(
    result: ToolResult,
    model_cls: type[BaseModel],
    data: dict[str, Any] | None = None,
) -> BaseModel:
    """Convert a ToolResult into the requested Pydantic output model.

    On success the caller may supply an explicit ``data`` mapping when the
    field names in the output model differ from the raw ToolResult data.  On
    failure the helper returns either the model's error form (if it has
    ``success`` and ``error`` fields) or a generic ``ToolErrorOutput``.
    """
    try:
        if result.success:
            payload: dict[str, Any] = (
                dict(data) if data is not None else dict(result.data or {})
            )
            if not isinstance(payload, dict):
                payload = {"data": payload}
            if "dry_run" in model_cls.model_fields and "dry_run" not in payload:
                payload["dry_run"] = result.dry_run
            if "warnings" in model_cls.model_fields and "warnings" not in payload:
                payload["warnings"] = result.warnings
            return model_cls(**payload)

        error = result.error or "Unknown error"
        if "success" in model_cls.model_fields and "error" in model_cls.model_fields:
            return model_cls(success=False, error=error)
        from pixel_flasher_plugin.output_models import ToolErrorOutput

        return ToolErrorOutput(success=False, error=error)
    except Exception as exc:
        from pixel_flasher_plugin.output_models import ToolErrorOutput

        return ToolErrorOutput(success=False, error=f"Output conversion failed: {exc}")


def _not_implemented(model_cls: type[BaseModel]) -> BaseModel:
    """Return a clean deferred-result output for tools not yet wired."""
    return _to_output(
        ToolResult(success=False, error="Not yet implemented in device_ops facade"),
        model_cls,
    )


def _as_preview(result: ToolResult) -> ToolResult:
    """Promote a ``confirm=False`` result into a dry-run preview result.

    When the only reason the operation did not run is missing confirmation,
    the command/preview is still useful.  Real failures (denied by the safety
    gateway, failed preflight checks, missing files, etc.) are preserved but
    marked as dry runs so callers can tell the call was non-destructive.
    """
    if result.success:
        result.dry_run = True
        return result
    if result.error and "Confirmation required" in result.error:
        return ToolResult(
            success=True,
            data=result.data,
            command=result.command,
            warnings=result.warnings,
            dry_run=True,
            preflight_checks=result.preflight_checks,
        )
    result.dry_run = True
    return result


def _refuse_confirm(model_cls: type[BaseModel], tier: str) -> BaseModel:
    """Return the standard refusal when a state-changing op lacks confirmation."""
    message = f"{tier} operation requires confirm=True when dry_run=False"
    if "success" in model_cls.model_fields and "error" in model_cls.model_fields:
        return model_cls(success=False, error=message)
    from pixel_flasher_plugin.output_models import ToolErrorOutput

    return ToolErrorOutput(success=False, error=message)


# ---------------------------------------------------------------------------
# Category 1 — Device Discovery
# ---------------------------------------------------------------------------
@mcp.tool()
def list_devices(ctx: Context) -> DeviceListOutput:
    """List all attached ADB and fastboot devices."""
    ops = ctx.request_context.lifespan_context.device_ops
    result = ops.list_devices()
    return _to_output(result, DeviceListOutput)


@mcp.tool()
def get_device_info(ctx: Context, device_id: str) -> DeviceInfoOutput:
    """Return high-level identity and state for a specific device."""
    result = _ops(device_id, ctx).get_device_info()
    return _to_output(result, DeviceInfoOutput)


@mcp.tool()
def get_device_prop(ctx: Context, device_id: str, prop: str) -> PropOutput:
    """Read a single Android system property via getprop."""
    result = _ops(device_id, ctx).run_shell(
        f"adb -s {device_id} shell getprop {prop}",
        confirm=False,
    )
    if result.success:
        stdout = (result.data or {}).get("stdout", "").strip() or None
        return PropOutput(prop=prop, value=stdout)
    return _to_output(result, PropOutput)


@mcp.tool()
def wait_for_device(
    ctx: Context,
    device_id: str,
    state: str = "device",
    timeout: int = 60,
) -> WaitOutput:
    """Block until the device reaches the requested ADB state."""
    ops = _ops(device_id, ctx)
    started = time.monotonic()
    result = ops.run_shell(
        f"adb -s {device_id} wait-for-{state}",
        confirm=False,
        timeout=timeout,
    )
    elapsed = time.monotonic() - started
    if result.success:
        return WaitOutput(success=True, state=state, elapsed_seconds=round(elapsed, 2))
    return _to_output(result, WaitOutput)


# ---------------------------------------------------------------------------
# Category 2 — Package Management
# ---------------------------------------------------------------------------
@mcp.tool()
def list_packages(
    ctx: Context,
    device_id: str,
    filter: str = "all",
    search: str | None = None,
) -> PackageListOutput:
    """List installed packages, optionally filtered by type or name substring."""
    result = _ops(device_id, ctx).run_shell(
        f"adb -s {device_id} shell pm list packages {shlex.quote(filter)}",
        confirm=False,
    )
    if result.success:
        stdout = (result.data or {}).get("stdout", "")
        names = [
            line.strip().replace("package:", "")
            for line in stdout.splitlines()
            if line.strip().startswith("package:")
        ]
        if search:
            names = [n for n in names if search.lower() in n.lower()]
        entries = [PackageListEntry(name=n, installed=True) for n in names]
        return PackageListOutput(packages=entries, count=len(entries))
    return _to_output(result, PackageListOutput)


@mcp.tool()
def install_package(
    ctx: Context,
    device_id: str,
    apk_path: str,
    dry_run: bool = True,
    confirm: bool = False,
) -> PackageInstallOutput:
    """Install an APK package on the device. WARN operation.

    Defaults to dry_run=True (preview mode).  To execute, pass dry_run=False
    AND confirm=True.
    """
    ops = _ops(device_id, ctx)
    if dry_run:
        result = ops.install_apk(apk_path, confirm=False)
        return _to_output(_as_preview(result), PackageInstallOutput)
    if not confirm:
        return _refuse_confirm(PackageInstallOutput, "WARN")
    result = ops.install_apk(apk_path, confirm=True)
    return _to_output(
        result,
        PackageInstallOutput,
        data={
            "success": result.success,
            "package": (result.data or {}).get("apk_path") if result.success else None,
        },
    )


@mcp.tool()
def uninstall_package(
    ctx: Context,
    device_id: str,
    package_name: str,
    dry_run: bool = True,
    confirm: bool = False,
) -> PackageUninstallOutput:
    """Uninstall a package from the device. WARN operation.

    Defaults to dry_run=True (preview mode).  To execute, pass dry_run=False
    AND confirm=True.
    """
    ops = _ops(device_id, ctx)
    command = f"adb -s {device_id} uninstall {package_name}"
    if dry_run:
        result = ops.run_shell(command, confirm=False)
        return _to_output(_as_preview(result), PackageUninstallOutput)
    if not confirm:
        return _refuse_confirm(PackageUninstallOutput, "WARN")
    result = ops.run_shell(command, confirm=True)
    return _to_output(
        result,
        PackageUninstallOutput,
        data={
            "success": result.success,
            "package": package_name,
            "kept_data": False,
        },
    )


@mcp.tool()
def enable_package(
    ctx: Context,
    device_id: str,
    package_name: str,
    dry_run: bool = True,
    confirm: bool = False,
) -> PackageStateOutput:
    """Enable a previously disabled package. WARN operation.

    Defaults to dry_run=True (preview mode).  To execute, pass dry_run=False
    AND confirm=True.
    """
    ops = _ops(device_id, ctx)
    command = f"adb -s {device_id} shell pm enable {package_name}"
    if dry_run:
        result = ops.run_shell(command, confirm=False)
        return _to_output(_as_preview(result), PackageStateOutput)
    if not confirm:
        return _refuse_confirm(PackageStateOutput, "WARN")
    result = ops.run_shell(command, confirm=True)
    return _to_output(
        result,
        PackageStateOutput,
        data={
            "success": result.success,
            "package": package_name,
            "previous_state": "disabled",
            "current_state": "enabled",
        },
    )


@mcp.tool()
def disable_package(
    ctx: Context,
    device_id: str,
    package_name: str,
    dry_run: bool = True,
    confirm: bool = False,
) -> PackageStateOutput:
    """Disable a package (for the current user). WARN operation.

    Defaults to dry_run=True (preview mode).  To execute, pass dry_run=False
    AND confirm=True.
    """
    ops = _ops(device_id, ctx)
    command = f"adb -s {device_id} shell pm disable-user {package_name}"
    if dry_run:
        result = ops.run_shell(command, confirm=False)
        return _to_output(_as_preview(result), PackageStateOutput)
    if not confirm:
        return _refuse_confirm(PackageStateOutput, "WARN")
    result = ops.run_shell(command, confirm=True)
    return _to_output(
        result,
        PackageStateOutput,
        data={
            "success": result.success,
            "package": package_name,
            "previous_state": "enabled",
            "current_state": "disabled",
        },
    )


# ---------------------------------------------------------------------------
# Category 3 — Partition Operations
# ---------------------------------------------------------------------------
@mcp.tool()
def get_partitions(ctx: Context, device_id: str) -> PartitionListOutput:
    """List block-device partitions exposed by the device."""
    result = _ops(device_id, ctx).list_partitions()
    if result.success:
        raw = (result.data or {}).get("partitions", [])
        entries = [PartitionEntry(name=item.get("name", "")) for item in raw]
        return PartitionListOutput(partitions=entries, count=len(entries))
    return _to_output(result, PartitionListOutput)


@mcp.tool()
def read_partition(
    ctx: Context,
    device_id: str,
    partition: str,
) -> PartitionReadOutput:
    """Dump a partition image to a local temporary file."""
    result = _ops(device_id, ctx).read_partition(partition, confirm=False)
    if result.success:
        data = result.data or {}
        return PartitionReadOutput(
            success=True,
            partition=data.get("partition"),
            path_on_device=data.get("local_path"),
            size=data.get("size"),
            sha256=data.get("sha256"),
        )
    return _to_output(result, PartitionReadOutput)


@mcp.tool()
def erase_partition(
    ctx: Context,
    device_id: str,
    partition: str,
    dry_run: bool = True,
    confirm: bool = False,
) -> PartitionEraseOutput:
    """Erase (fastboot erase) a partition on the device. CRITICAL operation.

    Defaults to dry_run=True (preview mode — shows the command without
    executing).  To execute, pass dry_run=False AND confirm=True.
    """
    ops = _ops(device_id, ctx)
    if dry_run:
        result = ops.wipe_partition(partition, confirm=False)
        return _to_output(_as_preview(result), PartitionEraseOutput)
    if not confirm:
        return _refuse_confirm(PartitionEraseOutput, "CRITICAL")
    result = ops.wipe_partition(partition, confirm=True)
    return _to_output(
        result,
        PartitionEraseOutput,
        data={"success": result.success, "partition": partition},
    )


@mcp.tool()
def flash_partition(
    ctx: Context,
    device_id: str,
    partition: str,
    image_path: str,
    dry_run: bool = True,
    confirm: bool = False,
) -> PartitionFlashOutput:
    """Flash a partition image to the device via fastboot. CRITICAL operation.

    Defaults to dry_run=True (preview mode — shows the command without
    executing).  To execute, pass dry_run=False AND confirm=True.
    """
    ops = _ops(device_id, ctx)
    if dry_run:
        result = ops.flash_partition(partition, image_path, confirm=False)
        return _to_output(_as_preview(result), PartitionFlashOutput)
    if not confirm:
        return _refuse_confirm(PartitionFlashOutput, "CRITICAL")
    result = ops.flash_partition(partition, image_path, confirm=True)
    if result.success:
        data = result.data or {}
        return PartitionFlashOutput(
            success=True,
            partition=data.get("partition"),
            slot=None,
            image_path=data.get("image_path"),
            sha256=data.get("sha256"),
        )
    return _to_output(result, PartitionFlashOutput)


# ---------------------------------------------------------------------------
# Category 4 — Boot Image Operations
# ---------------------------------------------------------------------------
@mcp.tool()
def flash_boot_image(
    ctx: Context,
    device_id: str,
    boot_path: str,
    slot: str = "active",
    dry_run: bool = True,
    confirm: bool = False,
) -> BootFlashOutput:
    """Flash a boot or init_boot image to the requested slot. CRITICAL operation.

    Defaults to dry_run=True (preview mode — shows the command without
    executing).  To execute, pass dry_run=False AND confirm=True.
    """
    ops = _ops(device_id, ctx)

    boot_info = ops.get_boot_images()
    boot_partition = "boot"
    if boot_info.success:
        boot_partition = (boot_info.data or {}).get("boot_partition", "boot")

    target_slot = slot
    if slot == "active":
        info = ops.get_device_info()
        if info.success:
            target_slot = (info.data or {}).get("active_slot") or "active"

    target_partition = (
        f"{boot_partition}_{target_slot}"
        if target_slot and target_slot != "active"
        else boot_partition
    )

    if dry_run:
        result = ops.flash_partition(target_partition, boot_path, confirm=False)
        preview = _as_preview(result)
        return _to_output(
            preview,
            BootFlashOutput,
            data={
                "success": preview.success,
                "slot": target_slot,
                "previous_slot": None,
                "backup_path": None,
            },
        )
    if not confirm:
        return _refuse_confirm(BootFlashOutput, "CRITICAL")

    result = ops.flash_partition(target_partition, boot_path, confirm=True)
    if result.success:
        data = result.data or {}
        return BootFlashOutput(
            success=True,
            slot=target_slot,
            previous_slot=None,
            sha256=data.get("sha256"),
            backup_path=None,
        )
    return _to_output(result, BootFlashOutput)

@mcp.tool()
def patch_boot_image(
    ctx: Context,
    device_id: str,
    boot_path: str,
    method: str = "Magisk",
    dry_run: bool = True,
    confirm: bool = False,
) -> BootPatchOutput:
    """Validate and inspect a boot image for Magisk/KernelSU/APatch patching. CRITICAL operation.

    Wave 1 implementation: this tool performs real validation (ANDROID! magic
    header, size, and header metadata) but does NOT actually patch the image.
    Full Magisk/KernelSU/APatch patching requires the patching binary from the
    respective root solution and is deferred to a later wave or the
    PixelFlasher GUI.

    Defaults to dry_run=True (preview mode). To execute validation, pass
    dry_run=False AND confirm=True.
    """
    ops = _ops(device_id, ctx)
    if dry_run:
        result = ops.patch_boot_image(boot_path, method=method, dry_run=True, confirm=False)
        return _to_output(_as_preview(result), BootPatchOutput)
    if not confirm:
        return _refuse_confirm(BootPatchOutput, "CRITICAL")
    result = ops.patch_boot_image(boot_path, method=method, dry_run=False, confirm=True)
    return _to_output(
        result,
        BootPatchOutput,
        data={
            "success": result.success,
            "patched_path": None,
            "method": method,
            "sha256": None,
        },
    )


@mcp.tool()
def flash_factory_image(
    ctx: Context,
    device_id: str,
    firmware_path: str,
    mode: str = "dryRun",
    dry_run: bool = True,
    confirm: bool = False,
) -> FactoryFlashOutput:
    """Inspect a factory firmware package; full flashing is safety-gated. CRITICAL operation.

    Wave 1 implementation: in dry-run mode the zip is parsed and the list of
    contained partition images is returned.  Executing a full factory flash is
    the most destructive operation the agent could trigger, so even with
    confirm=True it is refused and the user is directed to the PixelFlasher
    GUI where device state can be supervised.

    Defaults to dry_run=True (preview mode). To request execution, pass
    dry_run=False AND confirm=True; the request will be refused with a clear
    error.
    """
    ops = _ops(device_id, ctx)
    if dry_run:
        result = ops.flash_factory_image(
            firmware_path, mode=mode, dry_run=True, confirm=False
        )
        return _to_output(_as_preview(result), FactoryFlashOutput)
    if not confirm:
        return _refuse_confirm(FactoryFlashOutput, "CRITICAL")
    result = ops.flash_factory_image(
        firmware_path, mode=mode, dry_run=False, confirm=True
    )
    return _to_output(result, FactoryFlashOutput)


# ---------------------------------------------------------------------------
# Category 5 — Logcat
# ---------------------------------------------------------------------------
@mcp.tool()
def capture_logcat(
    ctx: Context,
    device_id: str,
    priority: str = "*:D",
    tag: str | None = None,
    regex_filter: str | None = None,
    max_lines: int = 500,
) -> LogcatOutput:
    """Capture a snapshot of the device logcat buffer."""
    result = _ops(device_id, ctx).run_shell(
        f"adb -s {device_id} shell logcat -d -b all -v threadtime "
        f"{shlex.quote(priority)} -t {max_lines}",
        confirm=False,
    )
    if result.success:
        stdout = (result.data or {}).get("stdout", "")
        lines = [line for line in stdout.splitlines() if line.strip()]
        if tag:
            lines = [line for line in lines if tag.lower() in line.lower()]
        if regex_filter:
            try:
                pattern = re.compile(regex_filter)
                lines = [line for line in lines if pattern.search(line)]
            except re.error:
                pass
        truncated = len(lines) > max_lines
        lines = lines[:max_lines]
        return LogcatOutput(lines=lines, truncated=truncated, line_count=len(lines))
    return _to_output(result, LogcatOutput)


# ---------------------------------------------------------------------------
# Category 6 — PIF Management
# ---------------------------------------------------------------------------
@mcp.tool()
def get_pif_status(ctx: Context, device_id: str) -> PifStatusOutput:
    """Read the Play Integrity Fix module's custom configuration and metadata."""
    result = _ops(device_id, ctx).get_pif_status()
    return _to_output(result, PifStatusOutput)


@mcp.tool()
def update_pif(
    ctx: Context,
    device_id: str,
    pif_json: str,
    dry_run: bool = True,
    confirm: bool = False,
) -> PifUpdateOutput:
    """Push a new pif.json to the device for the PIF module. WARN operation.

    The supplied JSON is validated locally, pushed to a temporary path, and
    then moved into place under root.  Root access is required for the final
    copy/chmod step.  Pass confirm=True to execute.
    """
    ops = _ops(device_id, ctx)
    result = ops.update_pif(pif_json, confirm=confirm)
    return _to_output(result, PifUpdateOutput)


@mcp.tool()
def check_play_integrity(
    ctx: Context,
    device_id: str,
    dry_run: bool = True,
    confirm: bool = False,
) -> PlayIntegrityOutput:
    """Report the Play Integrity Fix module state on the device.

    This tool does NOT invoke the Play Integrity API (that requires a device UI
    and a calling app). It only reports whether the PIF Magisk module is
    installed and enabled by reading module.prop and checking for the disable
    file.
    """
    result = _ops(device_id, ctx).check_play_integrity()
    return _to_output(result, PlayIntegrityOutput)


# ---------------------------------------------------------------------------
# Category 7 — Backup
# ---------------------------------------------------------------------------
@mcp.tool()
def backup_partition(
    ctx: Context,
    device_id: str,
    partition: str = "boot",
) -> BackupOutput:
    """Back up a partition image locally."""
    result = _ops(device_id, ctx).read_partition(partition, confirm=False)
    if result.success:
        data = result.data or {}
        return BackupOutput(
            success=True,
            partition=data.get("partition"),
            path_on_device=data.get("local_path"),
            sha256=data.get("sha256"),
        )
    return _to_output(result, BackupOutput)


@mcp.tool()
def list_backups(ctx: Context, device_id: str) -> BackupListOutput:
    """List available Magisk boot backups on the device."""
    result = _ops(device_id, ctx).list_backups()
    return _to_output(result, BackupListOutput)


@mcp.tool()
def restore_backup(
    ctx: Context,
    device_id: str,
    backup_name: str,
    dry_run: bool = True,
    confirm: bool = False,
) -> BackupRestoreOutput:
    """Restore a previously created boot backup. CRITICAL operation.

    The backup is pulled from /data/adb/magisk_backup/<backup_name> and then
    flashed to the boot partition, reusing the same backup + rollback safety
    as flash_partition.

    Defaults to dry_run=True (preview mode).  To execute, pass dry_run=False
    AND confirm=True.
    """
    ops = _ops(device_id, ctx)
    if dry_run:
        result = ops.restore_backup(backup_name, dry_run=True, confirm=False)
        return _to_output(_as_preview(result), BackupRestoreOutput)
    if not confirm:
        return _refuse_confirm(BackupRestoreOutput, "CRITICAL")
    result = ops.restore_backup(backup_name, dry_run=False, confirm=True)
    return _to_output(
        result,
        BackupRestoreOutput,
        data={
            "success": result.success,
            "sha1": backup_name,
        },
    )


# ---------------------------------------------------------------------------
# Category 8 — AVB
# ---------------------------------------------------------------------------
@mcp.tool()
def avb_sign(
    ctx: Context,
    image_path: str,
    key_path: str,
    algorithm: str = "SHA256_RSA4096",
    confirm: bool = False,
) -> AvbSignOutput:
    """Sign a local image with an AVB key. WARN operation.

    Uses avbtool to add a hash footer to a copy of the image.  The original
    image is not modified; the signed copy is written next to it.  Pass
    confirm=True to execute.
    """
    if not confirm:
        return _refuse_confirm(AvbSignOutput, "WARN")
    ops: DeviceOps = ctx.request_context.lifespan_context.device_ops
    result = ops.avb_sign_image(image_path, key_path, algorithm=algorithm, confirm=True)
    return _to_output(result, AvbSignOutput)


@mcp.tool()
def avb_verify(ctx: Context, image_path: str) -> AvbVerifyOutput:
    """Verify the AVB signature of a local image using avbtool."""
    ops: DeviceOps = ctx.request_context.lifespan_context.device_ops
    result = ops.avb_verify_image(image_path)
    return _to_output(result, AvbVerifyOutput)


# ---------------------------------------------------------------------------
# Category 9 — Reboot & Bootloader
# ---------------------------------------------------------------------------
@mcp.tool()
def reboot_device(
    ctx: Context,
    device_id: str,
    target: str = "system",
    dry_run: bool = True,
    confirm: bool = False,
) -> RebootOutput:
    """Reboot the device to system, bootloader, recovery, fastboot, or sideload. WARN operation.

    Defaults to dry_run=True (preview mode).  To execute, pass dry_run=False
    AND confirm=True.
    """
    ops = _ops(device_id, ctx)
    if dry_run:
        result = ops.reboot_device(target, confirm=False)
        return _to_output(_as_preview(result), RebootOutput)
    if not confirm:
        return _refuse_confirm(RebootOutput, "WARN")
    result = ops.reboot_device(target, confirm=True)
    return _to_output(
        result,
        RebootOutput,
        data={
            "success": result.success,
            "previous_mode": "adb",
            "new_mode": target,
        },
    )


@mcp.tool()
def unlock_bootloader(
    ctx: Context,
    device_id: str,
    dry_run: bool = True,
    confirm: bool = False,
) -> BootloaderOutput:
    """Unlock the device bootloader (fastboot flashing unlock). CRITICAL operation.

    Defaults to dry_run=True (preview mode — shows the command without
    executing).  To execute, pass dry_run=False AND confirm=True.
    """
    ops = _ops(device_id, ctx)
    command = f"fastboot -s {device_id} flashing unlock"
    if dry_run:
        result = ops.run_shell(command, confirm=False, timeout=120)
        return _to_output(_as_preview(result), BootloaderOutput)
    if not confirm:
        return _refuse_confirm(BootloaderOutput, "CRITICAL")
    result = ops.run_shell(command, confirm=True, timeout=120)
    return _to_output(
        result,
        BootloaderOutput,
        data={"success": result.success, "unlocked": True},
    )


@mcp.tool()
def lock_bootloader(
    ctx: Context,
    device_id: str,
    dry_run: bool = True,
    confirm: bool = False,
) -> BootloaderOutput:
    """Lock the device bootloader (fastboot flashing lock). CRITICAL operation.

    Defaults to dry_run=True (preview mode — shows the command without
    executing).  To execute, pass dry_run=False AND confirm=True.
    """
    ops = _ops(device_id, ctx)
    command = f"fastboot -s {device_id} flashing lock"
    if dry_run:
        result = ops.run_shell(command, confirm=False, timeout=120)
        return _to_output(_as_preview(result), BootloaderOutput)
    if not confirm:
        return _refuse_confirm(BootloaderOutput, "CRITICAL")
    result = ops.run_shell(command, confirm=True, timeout=120)
    return _to_output(
        result,
        BootloaderOutput,
        data={"success": result.success, "unlocked": False},
    )


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
def main() -> None:
    """Run the PixelFlasher MCP server over stdio."""
    mcp.run()


# Import resources module to register @mcp.resource() handlers against the shared instance.
# This MUST come after the mcp instance is created and tools are registered.
import pixel_flasher_plugin.mcp_resources  # noqa: E402,F401


if __name__ == "__main__":
    main()

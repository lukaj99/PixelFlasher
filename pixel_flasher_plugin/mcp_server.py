"""PixelFlasher MCP server adapter.

This module exposes the PixelFlasher device-operation facade as 43 MCP tools
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
    AppBackupStatusOutput,
    AppBackupTriggerOutput,
    AppDataBackupOutput,
    AppDataRestoreOutput,
    AvbSignOutput,
    AvbVerifyOutput,
    BackupListOutput,
    BackupOutput,
    BackupRestoreOutput,
    BackupScheduleCreateOutput,
    BackupToolInstallOutput,
    BackupToolReleaseOutput,
    BootFlashOutput,
    BootloaderOutput,
    BootPatchOutput,
    DeviceInfoOutput,
    DeviceListOutput,
    FactoryFlashOutput,
    KeyboxStatusOutput,
    KeyboxUpdateOutput,
    LogcatOutput,
    ModuleActionOutput,
    ModuleInstallOutput,
    ModuleListOutput,
    ModuleStateOutput,
    ModuleUninstallOutput,
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


# A device_id is interpolated into every command string (``adb -s <id> ...``),
# and those strings are ultimately executed through a shell=True subprocess.
# Real ADB serials / IP:port transports only ever contain this character set,
# so validating it here -- the single chokepoint every tool routes through --
# stops a crafted device_id (e.g. ``x;reboot`` or ``$(reboot)``) from carrying
# a shell-injection payload into any command.
_DEVICE_ID_RE = re.compile(r"^[A-Za-z0-9._:-]+$")


def _ops(device_id: str, ctx: Context) -> DeviceOps:
    """Return the shared DeviceOps singleton, bound to the requested device ID.

    The lifespan context creates a single DeviceOps instance.  Re-binding its
    ``device_id`` attribute (and clearing any cached lazy device handle) lets
    every tool call share the same gateway/runtime without constructing a new
    facade per request.
    """
    if not _DEVICE_ID_RE.match(device_id or ""):
        raise ValueError(
            f"Invalid device_id {device_id!r}: only letters, digits, and "
            f".:_- are allowed (an ADB serial or ip:port)."
        )
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
    result = _ops(device_id, ctx).get_device_prop(prop)
    return _to_output(
        result,
        PropOutput,
        data={"prop": prop, "value": (result.data or {}).get("value")} if result.success else None,
    )


@mcp.tool()
def wait_for_device(
    ctx: Context,
    device_id: str,
    state: str = "device",
    timeout: int = 60,
) -> WaitOutput:
    """Block until the device reaches the requested ADB state."""
    ops = _ops(device_id, ctx)
    if not re.fullmatch(r"[a-z-]+", state):
        return WaitOutput(success=False, error=f"Invalid state {state!r}")
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
    result = _ops(device_id, ctx).list_packages(filter=filter)
    if result.success:
        names = (result.data or {}).get("packages", [])
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
def get_backup_tool_release(ctx: Context, device_id: str, app: str = "neo_backup") -> BackupToolReleaseOutput:
    """Fetch the latest release metadata for a supported app-data backup tool.

    ``app`` is ``neo_backup`` (default, open source, public GitHub releases)
    or ``swift_backup`` (closed source, no release API -- always returns an
    error for this tool; supply your own apk_path to install_backup_tool).
    """
    result = _ops(device_id, ctx).get_backup_tool_release(app=app)
    return _to_output(result, BackupToolReleaseOutput)


@mcp.tool()
def install_backup_tool(
    ctx: Context,
    device_id: str,
    app: str = "neo_backup",
    apk_path: str | None = None,
    dry_run: bool = True,
    confirm: bool = False,
) -> BackupToolInstallOutput:
    """Fetch (if needed) and install an app+data backup tool. WARN operation.

    For neo_backup with no apk_path, downloads the latest GitHub release
    first. swift_backup always requires an explicit apk_path (closed
    source, no release feed -- pull your own licensed copy off the device
    or supply the APK yourself). Defaults to dry_run=True (preview mode).
    To execute, pass dry_run=False AND confirm=True.
    """
    ops = _ops(device_id, ctx)
    if dry_run:
        result = ops.install_backup_tool(app=app, apk_path=apk_path, confirm=False)
        return _to_output(_as_preview(result), BackupToolInstallOutput)
    if not confirm:
        return _refuse_confirm(BackupToolInstallOutput, "WARN")
    result = ops.install_backup_tool(app=app, apk_path=apk_path, confirm=True)
    return _to_output(
        result,
        BackupToolInstallOutput,
        data={
            "success": result.success,
            "apk_path": (result.data or {}).get("apk_path") if result.success else None,
        },
    )


@mcp.tool()
def trigger_app_backup(
    ctx: Context,
    device_id: str,
    app: str,
    schedule_name: str | None = None,
    schedule_ids: list[str] | None = None,
    dry_run: bool = True,
    confirm: bool = False,
) -> AppBackupTriggerOutput:
    """Trigger a pre-configured backup schedule on an installed backup app. WARN operation.

    Neither neo_backup nor swift_backup supports an ad-hoc single-package
    backup -- the schedule (which packages, what mode, recurrence) must
    already exist, created once via the app's own UI. This only fires an
    existing schedule: schedule_name is required for neo_backup; for
    swift_backup, pass schedule_ids to run specific schedules or omit it to
    run all enabled schedules. Defaults to dry_run=True (preview mode). To
    execute, pass dry_run=False AND confirm=True.
    """
    ops = _ops(device_id, ctx)
    if dry_run:
        result = ops.trigger_app_backup(
            app, schedule_name=schedule_name, schedule_ids=schedule_ids, confirm=False
        )
        return _to_output(_as_preview(result), AppBackupTriggerOutput)
    if not confirm:
        return _refuse_confirm(AppBackupTriggerOutput, "WARN")
    result = ops.trigger_app_backup(
        app, schedule_name=schedule_name, schedule_ids=schedule_ids, confirm=True
    )
    return _to_output(result, AppBackupTriggerOutput)


@mcp.tool()
def get_app_backup_status(ctx: Context, device_id: str, app: str) -> AppBackupStatusOutput:
    """Check whether a backup app (neo_backup | swift_backup) is installed, and its version."""
    result = _ops(device_id, ctx).get_app_backup_status(app)
    return _to_output(result, AppBackupStatusOutput)


@mcp.tool()
def create_backup_schedule(
    ctx: Context,
    device_id: str,
    app: str,
    name: str,
    packages: list[str] | None = None,
    block_packages: list[str] | None = None,
    time_hour: int = 12,
    time_minute: int = 0,
    interval_days: int = 1,
    mode: int | None = None,
    enabled: bool = True,
    dry_run: bool = True,
    confirm: bool = False,
) -> BackupScheduleCreateOutput:
    """Create a backup schedule by inserting directly into Neo Backup's database. WARN operation.

    Only app="neo_backup" is supported -- its Room DB schema was verified
    empirically against a real device. swift_backup's schedule storage
    format is closed-source/obfuscated and unconfirmed, so it isn't
    supported. packages/block_packages are lists of Android package names
    (omit packages for "all user apps", matching the app's own default).
    mode defaults to APK+data (bit flags 16|8=24) if not given -- the app's
    own "Add Schedule" button only sets APK-only (16), which is NOT enough
    for a seamless-restore use case; pass mode explicitly only if you know
    the exact bit flags you want (see app_backup.py NB_MODE_* constants).
    This force-stops neo_backup and relaunches it once as part of the
    operation. Defaults to dry_run=True (preview mode). To execute, pass
    dry_run=False AND confirm=True.
    """
    ops = _ops(device_id, ctx)
    kwargs = dict(
        packages=packages,
        block_packages=block_packages,
        time_hour=time_hour,
        time_minute=time_minute,
        interval_days=interval_days,
        mode=mode,
        enabled=enabled,
    )
    if dry_run:
        result = ops.create_backup_schedule(app, name, confirm=False, **kwargs)
        return _to_output(_as_preview(result), BackupScheduleCreateOutput)
    if not confirm:
        return _refuse_confirm(BackupScheduleCreateOutput, "WARN")
    result = ops.create_backup_schedule(app, name, confirm=True, **kwargs)
    return _to_output(result, BackupScheduleCreateOutput)


@mcp.tool()
def backup_app_data(
    ctx: Context,
    device_id: str,
    package: str,
    dest_dir: str,
    include_external: bool = False,
    include_obb: bool = False,
    dry_run: bool = True,
    confirm: bool = False,
) -> AppDataBackupOutput:
    """Back up an installed package's private data directly via root tar. WARN operation.

    App-independent -- no Neo Backup/Swift Backup needed. Covers
    /data/data/<package> and /data/user_de/0/<package> (session tokens,
    SharedPreferences, SQLite databases). Does NOT back up the APK. Defaults
    to dry_run=True (preview mode). To execute, pass dry_run=False AND
    confirm=True.
    """
    ops = _ops(device_id, ctx)
    kwargs = dict(include_external=include_external, include_obb=include_obb)
    if dry_run:
        result = ops.backup_app_data(package, dest_dir, confirm=False, **kwargs)
        return _to_output(_as_preview(result), AppDataBackupOutput)
    if not confirm:
        return _refuse_confirm(AppDataBackupOutput, "WARN")
    result = ops.backup_app_data(package, dest_dir, confirm=True, **kwargs)
    return _to_output(result, AppDataBackupOutput)


@mcp.tool()
def restore_app_data(
    ctx: Context,
    device_id: str,
    package: str,
    tar_path: str,
    include_external: bool = False,
    include_obb: bool = False,
    dry_run: bool = True,
    confirm: bool = False,
) -> AppDataRestoreOutput:
    """Restore a package's private data from a backup_app_data tar. WARN operation.

    The app must already be installed (data only, not the APK -- use
    install_apk/install_package first if needed). Defaults to dry_run=True
    (preview mode). To execute, pass dry_run=False AND confirm=True.
    """
    ops = _ops(device_id, ctx)
    kwargs = dict(include_external=include_external, include_obb=include_obb)
    if dry_run:
        result = ops.restore_app_data(package, tar_path, confirm=False, **kwargs)
        return _to_output(_as_preview(result), AppDataRestoreOutput)
    if not confirm:
        return _refuse_confirm(AppDataRestoreOutput, "WARN")
    result = ops.restore_app_data(package, tar_path, confirm=True, **kwargs)
    return _to_output(result, AppDataRestoreOutput)


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
    command = f"adb -s {device_id} uninstall {shlex.quote(package_name)}"
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
    command = f"adb -s {device_id} shell pm enable {shlex.quote(package_name)}"
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
    command = f"adb -s {device_id} shell pm disable-user {shlex.quote(package_name)}"
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
        entries = []
        for item in raw:
            fields = {
                k: item.get(k)
                for k in ("name", "size", "type", "fs_type", "mount_point")
                if item.get(k) is not None
            }
            fields.setdefault("name", item.get("name", ""))
            entries.append(PartitionEntry(**fields))
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
    apk_path: str | None = None,
    superkey: str | None = None,
    kmi_override: str | None = None,
    mount_type: str | None = None,
    dry_run: bool = True,
    confirm: bool = False,
) -> BootPatchOutput:
    """Patch a stock boot image with Magisk, KernelSU, APatch, etc. CRITICAL operation.

    Defaults to dry_run=True (preview mode). To execute, pass dry_run=False
    AND confirm=True. An ``apk_path`` pointing to the root-solution APK is
    required for actual patching.
    """
    ops = _ops(device_id, ctx)
    if dry_run:
        result = ops.patch_boot_image(
            boot_path,
            method=method,
            apk_path=apk_path,
            superkey=superkey,
            kmi_override=kmi_override,
            mount_type=mount_type,
            dry_run=True,
            confirm=False,
        )
        return _to_output(_as_preview(result), BootPatchOutput)
    if not confirm:
        return _refuse_confirm(BootPatchOutput, "CRITICAL")
    result = ops.patch_boot_image(
        boot_path,
        method=method,
        apk_path=apk_path,
        superkey=superkey,
        kmi_override=kmi_override,
        mount_type=mount_type,
        dry_run=False,
        confirm=True,
    )
    return _to_output(result, BootPatchOutput)


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
    probe_method: str = "auto",
    checker_app: str | None = None,
    timeout: int = 30,
) -> PlayIntegrityOutput:
    """Return a live Play Integrity verdict (BASIC / DEVICE / STRONG).

    Launches an installed checker app, taps its CHECK button, and parses the
    resulting UI hierarchy. This is an INFO-tier read-only tool, but it is NOT
    fully headless: the device display must be on and unlocked for Play Services
    to process the integrity request.

    probe_method: auto | module_state_only | live
    checker_app: optional package name override (must be a supported app)
    timeout: seconds to wait for the verdict after tapping CHECK
    """
    result = _ops(device_id, ctx).check_play_integrity(
        probe_method=probe_method,
        checker_app=checker_app,
        timeout=timeout,
    )
    return _to_output(result, PlayIntegrityOutput)


# ---------------------------------------------------------------------------
# Category 6.5 — Keybox / Hardware Attestation
# ---------------------------------------------------------------------------
@mcp.tool()
def get_keybox_status(ctx: Context, device_id: str) -> KeyboxStatusOutput:
    """Read the device's keybox.xml status. INFO operation.

    Reports whether /data/adb/tricky_store/keybox.xml exists, whether its
    certificates are on Google's revocation list, and the leaf certificate
    serial/expiry when available.
    """
    result = _ops(device_id, ctx).get_keybox_status()
    return _to_output(result, KeyboxStatusOutput)


@mcp.tool()
def update_keybox(
    ctx: Context,
    device_id: str,
    source: str | None = None,
    content: str | None = None,
    dry_run: bool = True,
    confirm: bool = False,
) -> KeyboxUpdateOutput:
    """Push a new keybox.xml to the device. WARN operation.

    The supplied keybox is validated locally as XML, checked against Google's
    certificate revocation list, and only pushed if it is not revoked. Root
    access is required for the final copy/chmod step. Pass confirm=True to
    execute.
    """
    ops = _ops(device_id, ctx)
    if dry_run:
        result = ops.update_keybox(source=source, content=content, dry_run=True, confirm=False)
        return _to_output(_as_preview(result), KeyboxUpdateOutput)
    if not confirm:
        return _refuse_confirm(KeyboxUpdateOutput, "WARN")
    result = ops.update_keybox(source=source, content=content, dry_run=False, confirm=True)
    return _to_output(result, KeyboxUpdateOutput)


# ---------------------------------------------------------------------------
# Category 10 — SOTA Module Management
# ---------------------------------------------------------------------------
@mcp.tool()
def list_modules(ctx: Context, device_id: str) -> ModuleListOutput:
    """List installed root modules (Magisk/KernelSU/APatch). INFO operation."""
    result = _ops(device_id, ctx).list_modules()
    return _to_output(result, ModuleListOutput)


@mcp.tool()
def install_module(
    ctx: Context,
    device_id: str,
    module_path: str,
    dry_run: bool = True,
    confirm: bool = False,
) -> ModuleInstallOutput:
    """Install a local module zip on the device. WARN operation.

    Defaults to dry_run=True (preview mode). To execute, pass dry_run=False
    AND confirm=True. URL module downloads are not supported in this release.
    """
    ops = _ops(device_id, ctx)
    if dry_run:
        result = ops.install_module(module_path, dry_run=True, confirm=False)
        return _to_output(_as_preview(result), ModuleInstallOutput)
    if not confirm:
        return _refuse_confirm(ModuleInstallOutput, "WARN")
    result = ops.install_module(module_path, dry_run=False, confirm=True)
    return _to_output(
        result,
        ModuleInstallOutput,
        data={
            "success": result.success,
            "module_path": (result.data or {}).get("module_path") if result.success else None,
            "module_name": (result.data or {}).get("module_name") if result.success else None,
        },
    )


@mcp.tool()
def uninstall_module(
    ctx: Context,
    device_id: str,
    module_id: str,
    dry_run: bool = True,
    confirm: bool = False,
) -> ModuleUninstallOutput:
    """Uninstall (mark for removal) a root module. WARN operation.

    Defaults to dry_run=True (preview mode). To execute, pass dry_run=False
    AND confirm=True.
    """
    ops = _ops(device_id, ctx)
    if dry_run:
        result = ops.uninstall_module(module_id, dry_run=True, confirm=False)
        return _to_output(_as_preview(result), ModuleUninstallOutput)
    if not confirm:
        return _refuse_confirm(ModuleUninstallOutput, "WARN")
    result = ops.uninstall_module(module_id, dry_run=False, confirm=True)
    return _to_output(
        result,
        ModuleUninstallOutput,
        data={
            "success": result.success,
            "module_id": module_id,
        },
    )


@mcp.tool()
def enable_module(
    ctx: Context,
    device_id: str,
    module_id: str,
    dry_run: bool = True,
    confirm: bool = False,
) -> ModuleStateOutput:
    """Enable a previously disabled root module. WARN operation.

    Defaults to dry_run=True (preview mode). To execute, pass dry_run=False
    AND confirm=True.
    """
    ops = _ops(device_id, ctx)
    if dry_run:
        result = ops.enable_module(module_id, dry_run=True, confirm=False)
        return _to_output(_as_preview(result), ModuleStateOutput)
    if not confirm:
        return _refuse_confirm(ModuleStateOutput, "WARN")
    result = ops.enable_module(module_id, dry_run=False, confirm=True)
    return _to_output(
        result,
        ModuleStateOutput,
        data={
            "success": result.success,
            "module_id": module_id,
            "current_state": "enabled",
        },
    )


@mcp.tool()
def disable_module(
    ctx: Context,
    device_id: str,
    module_id: str,
    dry_run: bool = True,
    confirm: bool = False,
) -> ModuleStateOutput:
    """Disable a root module. WARN operation.

    Defaults to dry_run=True (preview mode). To execute, pass dry_run=False
    AND confirm=True.
    """
    ops = _ops(device_id, ctx)
    if dry_run:
        result = ops.disable_module(module_id, dry_run=True, confirm=False)
        return _to_output(_as_preview(result), ModuleStateOutput)
    if not confirm:
        return _refuse_confirm(ModuleStateOutput, "WARN")
    result = ops.disable_module(module_id, dry_run=False, confirm=True)
    return _to_output(
        result,
        ModuleStateOutput,
        data={
            "success": result.success,
            "module_id": module_id,
            "current_state": "disabled",
        },
    )


@mcp.tool()
def run_module_action(
    ctx: Context,
    device_id: str,
    module_id: str,
    dry_run: bool = True,
    confirm: bool = False,
) -> ModuleActionOutput:
    """Run a root module's action.sh script. WARN operation.

    Defaults to dry_run=True (preview mode). To execute, pass dry_run=False
    AND confirm=True.
    """
    ops = _ops(device_id, ctx)
    if dry_run:
        result = ops.run_module_action(module_id, dry_run=True, confirm=False)
        return _to_output(_as_preview(result), ModuleActionOutput)
    if not confirm:
        return _refuse_confirm(ModuleActionOutput, "WARN")
    result = ops.run_module_action(module_id, dry_run=False, confirm=True)
    return _to_output(
        result,
        ModuleActionOutput,
        data={
            "success": result.success,
            "module_id": module_id,
        },
    )


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

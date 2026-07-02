"""Pydantic BaseModel output schemas for the 34-tool MCP catalog."""
from __future__ import annotations

from pydantic import BaseModel, Field


class DeviceListEntry(BaseModel):
    id: str = Field(description="Device serial ID")
    mode: str = Field(description="adb | fastboot | recovery | sideload | unauthorized | offline")
    state: str = Field(description="device | offline | unauthorized")
    product: str | None = Field(default=None, description="Product codename from adb devices -l")
    model: str | None = Field(default=None, description="Human-readable model name")
    transport_id: str | None = Field(default=None, description="ADB transport ID")


class DeviceListOutput(BaseModel):
    devices: list[DeviceListEntry] = Field(description="Connected devices")
    count: int = Field(description="Number of connected devices")


class DeviceInfoOutput(BaseModel):
    device_id: str = Field(description="Device serial ID")
    hardware: str | None = Field(default=None, description="Device codename")
    build: str | None = Field(default=None, description="Build ID / fingerprint")
    api_level: str | None = Field(default=None, description="Android API level")
    active_slot: str | None = Field(default=None, description="Active A/B slot (a | b)")
    unlocked: bool | None = Field(default=None, description="Bootloader unlocked state")
    rooted: bool | None = Field(default=None, description="Root access detected")
    kernel: str | None = Field(default=None, description="Kernel version string")
    has_init_boot: bool | None = Field(default=None, description="Device uses init_boot partition")
    vbmeta_state: str | None = Field(default=None, description="VBMeta verification/verity state")


class PropOutput(BaseModel):
    prop: str = Field(description="Property name queried")
    value: str | None = Field(default=None, description="Property value")


class WaitOutput(BaseModel):
    success: bool = Field(description="Whether the device reached the requested state")
    state: str | None = Field(default=None, description="State waited for")
    elapsed_seconds: float | None = Field(default=None, description="Time spent waiting")


class PackageListEntry(BaseModel):
    name: str = Field(description="Package name")
    installed: bool | None = Field(default=None, description="Whether the package is installed")
    enabled: bool | None = Field(default=None, description="Whether the package is enabled")
    path: str | None = Field(default=None, description="APK path on device")
    label: str | None = Field(default=None, description="Application label")
    uid: str | None = Field(default=None, description="Application UID")


class PackageListOutput(BaseModel):
    packages: list[PackageListEntry] = Field(description="Matching packages")
    count: int = Field(description="Number of packages returned")


class PackageInstallOutput(BaseModel):
    success: bool = Field(description="Whether the install succeeded")
    package: str | None = Field(default=None, description="Installed package name")
    version: str | None = Field(default=None, description="Installed version")
    dry_run: bool = Field(default=True, description="Whether this was a dry run")
    warnings: list[str] = Field(default_factory=list, description="Non-fatal warnings")


class PackageUninstallOutput(BaseModel):
    success: bool = Field(description="Whether the uninstall succeeded")
    package: str | None = Field(default=None, description="Uninstalled package name")
    kept_data: bool | None = Field(default=None, description="Whether app data was preserved")
    dry_run: bool = Field(default=True, description="Whether this was a dry run")


class PackageStateOutput(BaseModel):
    success: bool = Field(description="Whether the state change succeeded")
    package: str | None = Field(default=None, description="Package name")
    previous_state: str | None = Field(default=None, description="State before the operation")
    current_state: str | None = Field(default=None, description="State after the operation")
    dry_run: bool = Field(default=True, description="Whether this was a dry run")


class PartitionEntry(BaseModel):
    name: str = Field(description="Partition name")
    size: int | None = Field(default=None, description="Partition size in bytes")
    type: str | None = Field(default=None, description="Partition type")
    fs_type: str | None = Field(default=None, description="Filesystem type")
    mount_point: str | None = Field(default=None, description="Mount point on device")


class PartitionListOutput(BaseModel):
    partitions: list[PartitionEntry] = Field(description="Device partitions")
    count: int = Field(description="Number of partitions")


class PartitionReadOutput(BaseModel):
    success: bool = Field(description="Whether the partition was dumped")
    partition: str | None = Field(default=None, description="Partition name")
    path_on_device: str | None = Field(default=None, description="Dump path on device")
    size: int | None = Field(default=None, description="Dump size in bytes")
    sha256: str | None = Field(default=None, description="SHA256 of dumped image")
    dry_run: bool = Field(default=True, description="Whether this was a dry run")


class PartitionEraseOutput(BaseModel):
    success: bool = Field(description="Whether the erase succeeded")
    partition: str | None = Field(default=None, description="Erased partition name")
    dry_run: bool = Field(default=True, description="Whether this was a dry run")
    warnings: list[str] = Field(default_factory=list, description="Non-fatal warnings")


class PartitionFlashOutput(BaseModel):
    success: bool = Field(description="Whether the flash succeeded")
    partition: str | None = Field(default=None, description="Flashed partition name")
    slot: str | None = Field(default=None, description="Target slot")
    image_path: str | None = Field(default=None, description="Local image path")
    sha256: str | None = Field(default=None, description="SHA256 of flashed image")
    dry_run: bool = Field(default=True, description="Whether this was a dry run")


class BootFlashOutput(BaseModel):
    success: bool = Field(description="Whether the boot flash succeeded")
    slot: str | None = Field(default=None, description="Target slot")
    previous_slot: str | None = Field(default=None, description="Slot before the flash")
    sha256: str | None = Field(default=None, description="SHA256 of boot image")
    backup_path: str | None = Field(default=None, description="Auto-created backup path")
    dry_run: bool = Field(default=True, description="Whether this was a dry run")
    warnings: list[str] = Field(default_factory=list, description="Non-fatal warnings")


class BootPatchOutput(BaseModel):
    success: bool = Field(description="Whether the patch succeeded")
    patched_path: str | None = Field(default=None, description="Path to patched image")
    method: str | None = Field(default=None, description="Magisk | KernelSU | APatch")
    version: str | None = Field(default=None, description="Root solution version used")
    sha256: str | None = Field(default=None, description="SHA256 of patched image")
    dry_run: bool = Field(default=True, description="Whether this was a dry run")
    warnings: list[str] = Field(default_factory=list, description="Non-fatal warnings")


class FactoryFlashOutput(BaseModel):
    success: bool = Field(description="Whether the factory flash succeeded")
    mode: str | None = Field(default=None, description="dryRun | keepData | wipeData | OTA")
    flash_script_preview: list[str] = Field(default_factory=list, description="Planned fastboot commands")
    warnings: list[str] = Field(default_factory=list, description="Non-fatal warnings")
    dry_run: bool = Field(default=True, description="Whether this was a dry run")


class LogcatOutput(BaseModel):
    lines: list[str] = Field(description="Captured log lines")
    truncated: bool = Field(description="Whether output was truncated at max_lines")
    line_count: int = Field(description="Number of lines returned")


class PifStatusOutput(BaseModel):
    pif_exists: bool = Field(description="Whether /data/adb/pif.json exists")
    pif_path: str | None = Field(default=None, description="Path to pif.json on device")
    pif_content: dict | None = Field(default=None, description="Parsed PIF JSON content")
    module_name: str | None = Field(default=None, description="PIF module name")
    module_version: str | None = Field(default=None, description="PIF module version")


class PifUpdateOutput(BaseModel):
    success: bool = Field(description="Whether the PIF update succeeded")
    previous_hash: str | None = Field(default=None, description="SHA256 of previous pif.json")
    new_hash: str | None = Field(default=None, description="SHA256 of new pif.json")
    dry_run: bool = Field(default=True, description="Whether this was a dry run")
    warnings: list[str] = Field(default_factory=list, description="Non-fatal warnings")


class PlayIntegrityOutput(BaseModel):
    device_integrity: bool | None = Field(default=None, description="Device integrity verdict")
    basic_integrity: bool | None = Field(default=None, description="Basic integrity verdict")
    strong_integrity: bool | None = Field(default=None, description="Strong integrity verdict")
    timestamp: str | None = Field(default=None, description="ISO timestamp of the check")
    dry_run: bool = Field(default=True, description="Whether this was a dry run")
    module_installed: bool = Field(default=False, description="Whether the PIF Magisk module is present")
    module_enabled: bool = Field(default=False, description="Whether the PIF Magisk module is enabled")
    module_version: str | None = Field(default=None, description="PIF module version from module.prop")


class BackupOutput(BaseModel):
    success: bool = Field(description="Whether the backup succeeded")
    partition: str | None = Field(default=None, description="Partition backed up")
    path_on_device: str | None = Field(default=None, description="Backup path on device")
    sha256: str | None = Field(default=None, description="SHA256 of backup image")


class BackupListEntry(BaseModel):
    sha1: str = Field(description="Backup SHA1 identifier")
    date: str | None = Field(default=None, description="Backup date")
    firmware: str | None = Field(default=None, description="Associated firmware")
    name: str | None = Field(default=None, description="Backup file name")
    size: int | None = Field(default=None, description="Backup file size in bytes")


class BackupListOutput(BaseModel):
    backups: list[BackupListEntry] = Field(description="Available Magisk boot backups")
    count: int = Field(description="Number of backups")


class BackupRestoreOutput(BaseModel):
    success: bool = Field(description="Whether the restore succeeded")
    sha1: str | None = Field(default=None, description="Restored backup SHA1")
    firmware: str | None = Field(default=None, description="Associated firmware")
    dry_run: bool = Field(default=True, description="Whether this was a dry run")
    warnings: list[str] = Field(default_factory=list, description="Non-fatal warnings")


class AvbSignOutput(BaseModel):
    success: bool = Field(description="Whether the image was signed")
    signed_path: str | None = Field(default=None, description="Path to signed image")
    signature: str | None = Field(default=None, description="Signature hex or identifier")
    warnings: list[str] = Field(default_factory=list, description="Non-fatal warnings")


class AvbVerifyOutput(BaseModel):
    valid: bool = Field(description="Whether the AVB signature is valid")
    chain: list[str] = Field(default_factory=list, description="Verification chain details")
    warnings: list[str] = Field(default_factory=list, description="Non-fatal warnings")
    algorithm: str | None = Field(default=None, description="AVB algorithm name")
    hash: str | None = Field(default=None, description="Hash algorithm from descriptors")
    error: str | None = Field(default=None, description="Verification error message")


class RebootOutput(BaseModel):
    success: bool = Field(description="Whether the reboot command was issued")
    previous_mode: str | None = Field(default=None, description="Mode before reboot")
    new_mode: str | None = Field(default=None, description="Target mode")
    dry_run: bool = Field(default=False, description="Whether this was a dry run")


class BootloaderOutput(BaseModel):
    success: bool = Field(description="Whether the bootloader command succeeded")
    unlocked: bool | None = Field(default=None, description="Current bootloader lock state")
    dry_run: bool = Field(default=True, description="Whether this was a dry run")
    warnings: list[str] = Field(default_factory=list, description="Non-fatal warnings")


class ModuleListEntry(BaseModel):
    id: str = Field(description="Module ID")
    name: str = Field(description="Module name")
    version: str = Field(description="Module version string")
    state: str = Field(description="enabled | disabled | remove")
    has_action: bool = Field(description="Whether the module exposes an action.sh script")


class ModuleListOutput(BaseModel):
    modules: list[ModuleListEntry] = Field(description="Installed modules")
    count: int = Field(description="Number of modules")
    root_solution: str | None = Field(default=None, description="Detected root solution")


class ModuleInstallOutput(BaseModel):
    success: bool = Field(description="Whether the install succeeded")
    module_path: str | None = Field(default=None, description="Local module zip path")
    module_name: str | None = Field(default=None, description="Module file name pushed to the device")
    dry_run: bool = Field(default=True, description="Whether this was a dry run")
    warnings: list[str] = Field(default_factory=list, description="Non-fatal warnings")


class ModuleUninstallOutput(BaseModel):
    success: bool = Field(description="Whether the uninstall succeeded")
    module_id: str | None = Field(default=None, description="Module ID")
    dry_run: bool = Field(default=True, description="Whether this was a dry run")
    warnings: list[str] = Field(default_factory=list, description="Non-fatal warnings")


class ModuleStateOutput(BaseModel):
    success: bool = Field(description="Whether the state change succeeded")
    module_id: str | None = Field(default=None, description="Module ID")
    current_state: str | None = Field(default=None, description="State after the operation")
    dry_run: bool = Field(default=True, description="Whether this was a dry run")
    warnings: list[str] = Field(default_factory=list, description="Non-fatal warnings")


class ModuleActionOutput(BaseModel):
    success: bool = Field(description="Whether the action script ran")
    module_id: str | None = Field(default=None, description="Module ID")
    dry_run: bool = Field(default=True, description="Whether this was a dry run")
    warnings: list[str] = Field(default_factory=list, description="Non-fatal warnings")


class ToolErrorOutput(BaseModel):
    success: bool = Field(default=False, description="Always false for errors")
    error: str = Field(description="Human-readable error message")
    error_code: str | None = Field(default=None, description="Stable error code")

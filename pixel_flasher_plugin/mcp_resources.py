from __future__ import annotations

import os

os.environ.setdefault("PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION", "python")

import json
import logging
from pathlib import Path

from pixel_flasher_plugin.mcp_server import mcp  # shared FastMCP instance

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _load_json_file(filename: str) -> str:
    """Load a JSON file from the project root and return its raw contents."""
    path = _PROJECT_ROOT / filename
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


# ---------------------------------------------------------------------------
# 1. Device database
# ---------------------------------------------------------------------------
@mcp.resource("pf://devices")
def device_database() -> str:
    """Complete Android device database (codename -> model, name, is_pixel_watch).

    Source: android_devices.json. Use this to look up device codenames, models,
    and identify Pixel vs Pixel Watch devices.
    """
    return _load_json_file("android_devices.json")


# ---------------------------------------------------------------------------
# 2. Android versions
# ---------------------------------------------------------------------------
@mcp.resource("pf://versions")
def android_versions() -> str:
    """Android API level -> version name mapping.

    Source: android_versions.json. Use this to translate API levels to
    version names (e.g., API 34 -> Android 14).
    """
    return _load_json_file("android_versions.json")


# ---------------------------------------------------------------------------
# 3. Banned kernels
# ---------------------------------------------------------------------------
@mcp.resource("pf://constants/banned_kernels")
def banned_kernels() -> str:
    """Kernel identifiers known to be incompatible with Magisk/PIF.

    Source: constants.BANNED_KERNELS. Check this before patching a boot image.
    """
    try:
        from constants import BANNED_KERNELS
        return json.dumps(BANNED_KERNELS, indent=2)
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("Failed to load BANNED_KERNELS: %s", exc)
        return json.dumps({"error": str(exc)})


# ---------------------------------------------------------------------------
# 4. Minimum safe bootloader versions (anti-rollback)
# ---------------------------------------------------------------------------
@mcp.resource("pf://constants/bootloader_versions")
def min_safe_bootloaders() -> str:
    """Minimum safe bootloader versions per device codename (anti-rollback protection).

    Source: constants.MIN_SAFE_BOOTLOADER_VERSIONS. Check this BEFORE flashing
    firmware — downgrading below these versions will brick the device.
    """
    try:
        from constants import MIN_SAFE_BOOTLOADER_VERSIONS
        return json.dumps(MIN_SAFE_BOOTLOADER_VERSIONS, indent=2)
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("Failed to load MIN_SAFE_BOOTLOADER_VERSIONS: %s", exc)
        return json.dumps({"error": str(exc)})


# ---------------------------------------------------------------------------
# 5. Root package names
# ---------------------------------------------------------------------------
@mcp.resource("pf://constants/package_names")
def root_package_names() -> str:
    """Package names for Magisk, KernelSU, APatch and variants.

    Source: constants. Use these to detect which root solution is installed.
    """
    try:
        import constants as c
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("Failed to import constants: %s", exc)
        return json.dumps({"error": str(exc)})

    names = {}
    for attr in dir(c):
        if attr.endswith("_PKG_NAME") or attr.endswith("_PACKAGE_NAME"):
            val = getattr(c, attr)
            if isinstance(val, str):
                names[attr] = val
    return json.dumps(names, indent=2)


# ---------------------------------------------------------------------------
# 6. PIF update URLs
# ---------------------------------------------------------------------------
@mcp.resource("pf://constants/pif_urls")
def pif_update_urls() -> str:
    """Play Integrity Fix update URLs (chiteroman, osm0sis, trickystore, etc.).

    Source: constants. Use these to fetch the latest PIF modules.
    """
    try:
        import constants as c
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("Failed to import constants: %s", exc)
        return json.dumps({"error": str(exc)})

    urls = {}
    for attr in dir(c):
        val = getattr(c, attr)
        if not isinstance(val, str):
            continue
        if "PIF" in attr or "UPDATE_URL" in attr:
            if val.startswith("http") or "url" in attr.lower():
                urls[attr] = val
    return json.dumps(urls, indent=2)


# ---------------------------------------------------------------------------
# 7. Safe flashing guide (inline doc)
# ---------------------------------------------------------------------------
_SAFE_FLASHING_DOC = """# Safe Flashing Guide for PixelFlasher MCP Server

## Risk Tiers

- **INFO**: Read-only operations. Safe to execute without confirmation.
  Examples: list_devices, get_device_info, get_partitions, capture_logcat.

- **WARN**: Mutating operations that are reversible. Require `confirm=True`.
  Examples: install_package, reboot_device, update_pif.

- **CRITICAL**: Operations that can brick the device. Require `confirm=True` AND `dry_run=False`.
  Pre-flight checks run automatically: bootloader unlocked, battery >=50%, disk space, SHA256.
  Examples: flash_boot_image, flash_partition, erase_partition, unlock_bootloader.

## Pre-Flight Checks (Automatic for CRITICAL ops)

1. **Device connected**: Verifies the device is reachable.
2. **Correct mode**: Boot operations need fastboot mode; package ops need adb mode.
3. **Bootloader unlocked**: Flash operations require an unlocked bootloader.
4. **Battery level**: Device must have >=50% battery before flashing.
5. **Disk space**: Host must have >=5GB free for image extraction.
6. **SHA256 verify**: If expected_checksum provided, verifies the image hash.
7. **Anti-rollback**: Firmware date must not be older than the current bootloader version.
8. **OEM unlock ability**: For unlock_bootloader, verifies OEM unlocking is enabled.
9. **Critical partition backup**: Auto-backs-up boot partition before flash.

## Blocked Partitions (HARD BLOCK — never flashable)

These partitions are firmware-critical. Flashing them can permanently brick the device:

    xbl, xbl_config, abl, aop, devcfg, hyp, keymaster, qupfw, tz,
    uefisecapp, multiimgoem, multiimgqti, cpucp, shrm, storsec, spunvm, modem

The server will REJECT any attempt to flash or erase these, regardless of confirmation.

## Recommended Workflow

1. Call `list_devices` to identify connected devices.
2. Call `get_device_info` to check model, slot, unlock/root state.
3. Read `pf://constants/bootloader_versions` to verify anti-rollback safety.
4. Read `pf://constants/banned_kernels` if patching boot.
5. For flashing: first call with `dry_run=True` to preview the command.
6. Verify the preview command looks correct.
7. Call with `confirm=True` and `dry_run=False` to execute.
8. Check the result's `postcondition_checks` for verification.

## A/B Slot Safety

Pixel devices use A/B slots. When flashing boot images:
- The server targets the ACTIVE slot by default.
- The inactive slot remains untouched, providing a fallback.
- Never flash to both slots simultaneously unless intentionally restoring factory state.

## Rollback Behavior

- `flash_boot_image`: Auto-backs-up current boot before flashing. On post-condition failure, restores from backup.
- `flash_factory_image`: No auto-rollback (too many partitions). Pre-flight creates a boot backup. Proceed with extreme caution.
- `erase_partition`: No rollback. CRITICAL confirmation required.
- `lock_bootloader`: IRREVERSIBLE if device is not on stock firmware. Pre-flight verifies stock fingerprint.
"""


@mcp.resource("pf://docs/safe_flashing")
def safe_flashing_guide() -> str:
    """Safe flashing procedures and pre-flight check documentation.

    Read this before performing any CRITICAL operation (flash, erase, unlock bootloader).
    """
    return _SAFE_FLASHING_DOC

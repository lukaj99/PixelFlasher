"""App+data backup tool integration (Neo Backup / Swift Backup).

Pure helper functions for fetching the Neo Backup APK from its GitHub
releases and building the exact shell subcommands that trigger a
pre-configured backup schedule on either app. No device or network I/O
happens as a side effect of importing this module; :class:`DeviceOps`
methods in ``device_ops.py`` call into these helpers and drive the actual
adb/network calls.

Both apps expose the same automation ceiling: an exported component that
runs an *already-configured* schedule (by name or ID list), not an ad-hoc
single-package backup. The schedule itself must be created once via each
app's UI -- see LESSONS.md-style notes in the docstrings below rather than
assuming a headless schedule-creation path exists.
"""
from __future__ import annotations

import os
import re

import requests

from constants import (
    NEO_BACKUP_COMMAND_RECEIVER,
    NEO_BACKUP_PACKAGE,
    NEO_BACKUP_RELEASES_API,
    SWIFT_BACKUP_PACKAGE,
    SWIFT_BACKUP_SHORTCUTS_ACTIVITY,
)

SUPPORTED_APPS = ("neo_backup", "swift_backup")

_PACKAGE_BY_APP = {
    "neo_backup": NEO_BACKUP_PACKAGE,
    "swift_backup": SWIFT_BACKUP_PACKAGE,
}

# Neo Backup Schedule.mode bit flags -- verified against
# src/main/java/com/machiav3lli/backup/Constants.kt (NeoApplications/Neo-Backup).
# Do not change these values without re-checking that source.
NB_MODE_DATA_OBB = 0b0000001
NB_MODE_DATA_EXT = 0b0000010
NB_MODE_DATA_DE = 0b0000100
NB_MODE_DATA = 0b0001000
NB_MODE_APK = 0b0010000
NB_MODE_NONE = 0b0100000
NB_MODE_DATA_MEDIA = 0b1000000
# Default for a *useful* schedule -- APK + regular app data. The app's own
# "Add Schedule" button only sets NB_MODE_APK (verified empirically against a
# real on-device row), which is not enough for a seamless-restore use case.
NB_MODE_APK_AND_DATA = NB_MODE_APK | NB_MODE_DATA

# Neo Backup Schedule.filter bit flags (which apps to consider, not what to
# back up -- separate from "mode" above). Verified against the same source.
NB_FILTER_SPECIAL = 0b001
NB_FILTER_USER = 0b010
NB_FILTER_SYSTEM = 0b100

# Android package name: reverse-DNS segments of alphanumerics/underscore.
# Deliberately conservative -- this is inserted into a schedule's
# customList/blockList, not just displayed, so reject anything unusual
# rather than trying to support every edge case Android technically allows.
_PACKAGE_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+")


def _quote(value: str) -> str:
    return '"' + value.replace('"', '\\"') + '"'


# Schedule names/IDs are only ever used to build a shell command string, so
# quoting alone isn't a sufficient defense -- reject anything outside a safe
# charset before it ever reaches _quote(). Matches the whitelist regex in
# command_validator.py; keep both in sync.
_SAFE_TOKEN = re.compile(r"[\w.\- ]{1,64}")


def _validate_token(value: str, label: str) -> None:
    if not _SAFE_TOKEN.fullmatch(value):
        raise ValueError(
            f"Invalid {label} {value!r}: only letters, digits, '.', '-', '_' and spaces allowed (max 64 chars)"
        )


def package_for(app: str) -> str:
    """Return the Android package name for a supported backup app."""
    if app not in SUPPORTED_APPS:
        raise ValueError(f"Unsupported app {app!r}; expected one of {SUPPORTED_APPS}")
    return _PACKAGE_BY_APP[app]


def fetch_neo_backup_latest_release(timeout: int = 15) -> dict[str, str]:
    """Fetch Neo Backup's latest GitHub release metadata.

    Returns ``{"version": ..., "apk_name": ..., "apk_url": ...}``. Raises
    ``requests.RequestException`` on network failure or ``ValueError`` if
    the release has no APK asset (callers should wrap this in a
    ``ToolResult`` error, not let it propagate to an MCP client raw).
    """
    resp = requests.get(NEO_BACKUP_RELEASES_API, timeout=timeout)
    resp.raise_for_status()
    release = resp.json()

    apk_asset = next(
        (a for a in release.get("assets", []) if a.get("name", "").endswith(".apk")),
        None,
    )
    if apk_asset is None:
        raise ValueError("Neo Backup release has no .apk asset")

    return {
        "version": release.get("tag_name", ""),
        "apk_name": apk_asset["name"],
        "apk_url": apk_asset["browser_download_url"],
    }


def download_apk(url: str, dest_dir: str, filename: str, timeout: int = 60) -> str:
    """Stream-download an APK to ``dest_dir/filename``. Returns the local path."""
    os.makedirs(dest_dir, exist_ok=True)
    dest_path = os.path.join(dest_dir, filename)
    with requests.get(url, timeout=timeout, stream=True) as resp:
        resp.raise_for_status()
        with open(dest_path, "wb") as f:
            for chunk in resp.iter_content(chunk_size=1024 * 1024):
                f.write(chunk)
    return dest_path


def serialize_package_set(packages: list[str] | None) -> str:
    """Serialize a package list to Neo Backup's on-disk format.

    Verified against Converters.kt (NeoApplications/Neo-Backup): a
    ``Set<String>`` column is just ``set.joinToString(",")`` -- comma-joined,
    no JSON, no brackets. Empty/None serializes to "" (matches the app's own
    default-schedule row, verified empirically against a real device).
    """
    if not packages:
        return ""
    for pkg in packages:
        if not _PACKAGE_NAME.fullmatch(pkg):
            raise ValueError(f"Invalid package name {pkg!r}")
    return ",".join(packages)


def build_schedule_insert_sql(
    name: str,
    packages: list[str] | None = None,
    block_packages: list[str] | None = None,
    time_hour: int = 12,
    time_minute: int = 0,
    interval_days: int = 1,
    mode: int = NB_MODE_APK_AND_DATA,
    main_filter: int = NB_FILTER_USER,
    enabled: bool = True,
    now_millis: int = 0,
) -> tuple[str, list]:
    """Build a parameterized INSERT for Neo Backup's Schedule table.

    Schema verified empirically against a real on-device ``main.db`` (Room
    DB, release 8.3.18) -- NOT the possibly-stale exported schema JSON in the
    upstream repo, which lags the actual shipped schema (missing
    launchableFilter/updatedFilter/latestFilter/enabledFilter/tagsList).
    ``id`` is omitted (AUTOINCREMENT). ``now_millis`` should be the caller's
    current epoch-millis timestamp (this module doesn't call time.time()
    itself, kept as a pure function); it maps to Schedule.timePlaced.

    Returns ``(sql, params)`` for ``sqlite3`` parameter binding -- never
    interpolate these values into a raw SQL string.
    """
    if not _SAFE_TOKEN.fullmatch(name):
        raise ValueError(f"Invalid schedule name {name!r}: {_SAFE_TOKEN.pattern}")
    if not (0 <= time_hour <= 23):
        raise ValueError(f"time_hour out of range: {time_hour}")
    if not (0 <= time_minute <= 59):
        raise ValueError(f"time_minute out of range: {time_minute}")
    if interval_days < 1:
        raise ValueError(f"interval_days must be >= 1: {interval_days}")

    custom_list = serialize_package_set(packages)
    block_list = serialize_package_set(block_packages)

    sql = (
        "INSERT INTO Schedule ("
        "enabled, name, timeHour, timeMinute, interval, timePlaced, filter, mode, "
        "launchableFilter, updatedFilter, latestFilter, enabledFilter, timeToRun, "
        "customList, blockList, tagsList"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 0, 0, 0, ?, ?, '')"
    )
    params = [
        1 if enabled else 0,
        name,
        time_hour,
        time_minute,
        interval_days,
        now_millis,
        main_filter,
        mode,
        custom_list,
        block_list,
    ]
    return sql, params


def build_trigger_command(
    app: str,
    schedule_name: str | None = None,
    schedule_ids: list[str] | None = None,
) -> str:
    """Build the adb-shell subcommand that triggers a pre-configured schedule.

    ``neo_backup`` only supports triggering by ``schedule_name`` (its
    ``CommandReceiver`` broadcast takes a ``name`` extra). ``swift_backup``
    supports triggering specific schedules by ID list, or all enabled
    schedules if ``schedule_ids`` is omitted.
    """
    if app not in SUPPORTED_APPS:
        raise ValueError(f"Unsupported app {app!r}; expected one of {SUPPORTED_APPS}")

    if app == "neo_backup":
        if not schedule_name:
            raise ValueError("neo_backup requires schedule_name (CommandReceiver has no 'run all' action)")
        _validate_token(schedule_name, "schedule_name")
        return (
            f"am broadcast -a schedule --es name {_quote(schedule_name)} "
            f"-n {NEO_BACKUP_COMMAND_RECEIVER}"
        )

    # swift_backup
    if schedule_ids:
        for schedule_id in schedule_ids:
            _validate_token(schedule_id, "schedule_id")
        ids_arg = "-s " + " ".join(schedule_ids)
        return f'am start -n {SWIFT_BACKUP_SHORTCUTS_ACTIVITY} -e "cmd" {_quote(ids_arg)}'
    return f"am start -n {SWIFT_BACKUP_SHORTCUTS_ACTIVITY}"

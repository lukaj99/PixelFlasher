"""Root-based, app-independent package data backup/restore.

Pure helper functions for building the tar shell commands that back up and
restore an arbitrary installed package's private data directly via root --
no dependency on Neo Backup, Swift Backup, or any other third-party app.
This is what makes ad-hoc, single-package, right-now backup/restore
possible: the app-automation surfaces investigated elsewhere
(CommandReceiver, ShortcutsActivity) only trigger pre-configured schedules,
never an arbitrary package on demand.

Scope is deliberately narrow: only the two private data locations that
actually hold session tokens/SharedPreferences/SQLite databases --
/data/data/<pkg> (credential-encrypted) and /data/user_de/0/<pkg>
(device-encrypted, Direct Boot). External storage and OBB are opt-in
(can be large, rarely hold auth state). The APK itself is out of scope --
that's what install_apk/install_package already do; this module only
covers data.

Grounded against NeoApplications/Neo-Backup's own restore logic (TarUtils.kt)
and toybox's actual tar implementation (toys/posix/tar.c) rather than
assumption:
  - Neo Backup's restore path does chmod/chown/mtime per file but never
    calls restorecon or otherwise sets SELinux context -- ownership (UID)
    is what's load-bearing for Android's app-data isolation on this path,
    not SELinux relabeling. New files inherit their parent directory's
    SELinux context automatically, which is why this isn't required.
  - toybox tar (confirmed present on-device, `tar --help` lists it) has a
    real `--selinux` flag that saves/restores the `security.selinux` xattr
    per-entry -- more precise than a bare restorecon, which only *infers*
    a label from the current file_contexts policy rather than restoring
    the exact original. Used here as a precise, load-bearing step;
    restorecon is intentionally NOT used since --selinux supersedes it.
  - cache/code_cache are excluded from both backup and restore, matching
    Neo Backup's own DATA_EXCLUDED_CACHE_DIRS -- restoring stale cache
    causes more harm than skipping it, and it holds no auth state anyway.
"""
from __future__ import annotations

import re

_PACKAGE_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+")

# Matches Neo Backup's own DATA_EXCLUDED_CACHE_DIRS -- restoring stale
# cache/code_cache causes more harm than skipping it, and neither holds
# session/auth state.
_EXCLUDED_SUBDIRS = ("cache", "code_cache")


def validate_package_name(package: str) -> None:
    """Raise ValueError unless *package* looks like a real Android package name.

    This is embedded directly into shell commands run under su, so this
    check is a hard security boundary, not a UX nicety.
    """
    if not _PACKAGE_NAME.fullmatch(package):
        raise ValueError(f"Invalid package name {package!r}")


def _candidate_paths(package: str, include_external: bool, include_obb: bool) -> list[str]:
    paths = [f"data/data/{package}", f"data/user_de/0/{package}"]
    if include_external:
        paths.append(f"sdcard/Android/data/{package}")
    if include_obb:
        paths.append(f"sdcard/Android/obb/{package}")
    return paths


def _exclude_flags(paths: list[str]) -> str:
    excludes = [f"--exclude={p}/{sub}" for p in paths for sub in _EXCLUDED_SUBDIRS]
    return " ".join(excludes)


def build_backup_script(
    package: str,
    remote_tar_path: str,
    include_external: bool = False,
    include_obb: bool = False,
) -> str:
    """Build the full shell script that tars up a package's private data.

    Returned as standalone script *text* -- the caller pushes it to a file
    on-device (e.g. ``/data/local/tmp/pf_backup_<pkg>.sh``) via ``adb push``
    and executes it with ``su -c '<path>'``, mirroring boot_patcher.py's
    push-a-script convention. This sidesteps a real nested-quoting bug: the
    project's ``run_shell`` executes commands via
    ``subprocess.Popen(cmd, shell=True)`` -- the *local* host shell parses
    the entire command line first, so a multi-statement fragment (its own
    ``$vars``, ``&&``/``;`` control flow) embedded inline inside a single
    ``su -c "..."`` string would have its ``$p``/``"`` characters
    interpreted/terminated locally before ever reaching the device. Writing
    the fragment to a file and executing the file avoids a second layer of
    shell parsing entirely.

    Only paths that actually exist on-device are included (checked via
    ``[ -e "$p" ]`` in the script -- a package that's never written to
    device-encrypted storage, or has no external app-data dir, shouldn't
    make the whole backup fail). ``--selinux`` preserves the exact original
    SELinux label per file for a precise restore later.
    """
    validate_package_name(package)
    paths = _candidate_paths(package, include_external, include_obb)
    path_list = " ".join(paths)
    excludes = _exclude_flags(paths)
    return (
        "cd /\n"
        "INCLUDE=\"\"\n"
        f"for p in {path_list}; do\n"
        '    if [ -e "$p" ]; then\n'
        '        INCLUDE="$INCLUDE $p"\n'
        "    fi\n"
        "done\n"
        'if [ -z "$INCLUDE" ]; then\n'
        "    echo NO_DATA_FOUND >&2\n"
        "    exit 1\n"
        "fi\n"
        f"tar --selinux {excludes} -cf {remote_tar_path} $INCLUDE\n"
    )


def build_restore_script(
    package: str,
    remote_tar_path: str,
    uid: str,
    gid: str,
    include_external: bool = False,
    include_obb: bool = False,
) -> str:
    """Build the full shell script that extracts a data tar and restores ownership.

    Returned as standalone script *text* -- see :func:`build_backup_script`
    for why this is pushed as a file and executed rather than embedded
    inline in a ``su -c "..."`` string.

    ``uid``/``gid`` should come from a live ``stat`` on the *currently
    installed* app's data directory (the app must already be installed --
    this restores data only, not the APK). ``chown -R`` is the load-bearing
    step for Android's UID-based app-data isolation (verified against Neo
    Backup's own restore logic, which does exactly this and nothing SELinux
    -related). ``--selinux`` on extract restores the exact label saved at
    backup time, which is more precise than inferring one from policy.
    """
    validate_package_name(package)
    if not re.fullmatch(r"\d+", uid) or not re.fullmatch(r"\d+", gid):
        raise ValueError(f"uid/gid must be numeric, got uid={uid!r} gid={gid!r}")
    paths = _candidate_paths(package, include_external, include_obb)
    excludes = _exclude_flags(paths)
    chown_paths = " ".join(p for p in paths if not p.startswith("sdcard/"))
    return (
        "cd /\n"
        f"tar --selinux {excludes} -xf {remote_tar_path}\n"
        f'if [ -n "{chown_paths}" ]; then\n'
        f"    chown -R {uid}:{gid} {chown_paths}\n"
        "fi\n"
    )

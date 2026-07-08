"""Host-side restic orchestration for incremental, deduplicated, encrypted
app-data snapshots (backup "Tier 2").

Where the ``backup_app_data`` / ``restore_app_data`` tools produce a single
full ``.tar`` per package per run, this layer feeds those tars into a restic
repository so you get:

  * incremental *storage* -- restic content-addresses everything with
    content-defined chunking, so N nightly snapshots of a slowly-changing
    phone cost barely more than one; every snapshot is independently
    restorable.
  * version history, encryption at rest, and offsite copies.
  * 3-2-1 via one engine: back up once to a primary repo, then
    ``restic copy`` (dedup-preserving) to any number of secondary repos
    (e.g. ``rclone:gdrive:`` and ``sftp:vps:``).

Design choice -- we snapshot the *tar files*, not extracted trees. restic
still chunk-dedups the uncompressed tars across snapshots (do NOT gzip them,
which would defeat dedup), and storing tars lets restore compose directly
from the already-verified ``restore_app_data`` primitive instead of
reconstructing an on-device tree by hand.

Everything here builds *host-side* shell commands (restic / rclone run on the
Mac/VPS, never on the phone), executed through the same shell=True runner as
the rest of the package, so every interpolated value is ``shlex.quote``d --
consistent with the command-injection hardening in mcp_server.py. See
[[reference_mcp_shell_quoting_convention]].

Secrets: the restic repository password is NEVER passed here. restic reads it
from the environment at run time -- set ``RESTIC_PASSWORD_COMMAND`` (and
``RESTIC_FROM_PASSWORD_COMMAND`` for the copy source) to a Bitwarden lookup,
e.g. ``bw-wrapper get "restic-pixel"``. One-time repo setup (init each repo,
and init the copy targets with ``--copy-chunker-params`` so cross-repo dedup
works) is documented in pixel_flasher_plugin/README.md.

Verified against restic's current CLI docs (copy uses ``--from-repo``; the
``RESTIC_FROM_*`` env vars carry the source-repo password).
"""
from __future__ import annotations

import json
import re
import shlex

# A restic repository spec: a local absolute path, an rclone remote, or an
# sftp target. This is a sanity/UX gate; safety comes from shlex.quote below.
_REPO_RE = re.compile(
    r"^(?:"
    r"/[\w./@:+-]+"                      # local absolute path
    r"|rclone:[\w.-]+:[\w./@+-]*"        # rclone:remote:path
    r"|sftp:[\w.@-]+:/[\w./@+-]*"        # sftp:user@host:/path
    r"|s3:[\w.:/@+-]+"                   # s3:endpoint/bucket (allowed, not required)
    r")$"
)
_TAG_RE = re.compile(r"^[\w.-]{1,64}$")
_SNAPSHOT_RE = re.compile(r"^(?:latest|[0-9a-f]{4,64})$")


def validate_repo(repo: str) -> None:
    """Raise ValueError unless *repo* looks like a supported restic backend spec."""
    if not _REPO_RE.match(repo or ""):
        raise ValueError(
            f"Invalid restic repository {repo!r}. Expected a local absolute "
            f"path, rclone:remote:path, or sftp:user@host:/path."
        )


def validate_tag(tag: str) -> None:
    """Raise ValueError unless *tag* is a safe restic tag token."""
    if not _TAG_RE.match(tag or ""):
        raise ValueError(f"Invalid restic tag {tag!r}: allowed chars are [A-Za-z0-9._-], max 64.")


def validate_snapshot(snapshot: str) -> None:
    """Raise ValueError unless *snapshot* is ``latest`` or a hex snapshot id."""
    if not _SNAPSHOT_RE.match(snapshot or ""):
        raise ValueError(f"Invalid snapshot id {snapshot!r}: expected 'latest' or a hex id.")


def build_backup_command(repo: str, staging_dir: str, tags: list[str] | None = None) -> str:
    """``restic -r <repo> backup [--tag ...] <staging_dir>`` (JSON output)."""
    validate_repo(repo)
    tag_flags = ""
    for tag in tags or []:
        validate_tag(tag)
        tag_flags += f" --tag {shlex.quote(tag)}"
    return (
        f"restic -r {shlex.quote(repo)} backup --json{tag_flags} "
        f"{shlex.quote(staging_dir)}"
    )


def build_copy_command(dest_repo: str, source_repo: str) -> str:
    """``restic -r <dest> copy --from-repo <source>`` -- dedup-preserving replication.

    The destination repo MUST have been created with
    ``restic -r <dest> init --from-repo <source> --copy-chunker-params`` or the
    copy re-chunks everything (no cross-repo dedup). Source-repo password comes
    from ``RESTIC_FROM_PASSWORD_COMMAND`` in the environment.
    """
    validate_repo(dest_repo)
    validate_repo(source_repo)
    return (
        f"restic -r {shlex.quote(dest_repo)} copy "
        f"--from-repo {shlex.quote(source_repo)} --verbose"
    )


def build_forget_command(
    repo: str,
    keep_daily: int = 7,
    keep_weekly: int = 5,
    keep_monthly: int = 12,
    prune: bool = True,
) -> str:
    """``restic -r <repo> forget --keep-* [--prune]`` retention policy."""
    validate_repo(repo)
    for name, value in (("keep_daily", keep_daily), ("keep_weekly", keep_weekly), ("keep_monthly", keep_monthly)):
        if not isinstance(value, int) or value < 0:
            raise ValueError(f"{name} must be a non-negative integer, got {value!r}")
    prune_flag = " --prune" if prune else ""
    return (
        f"restic -r {shlex.quote(repo)} forget "
        f"--keep-daily {keep_daily} --keep-weekly {keep_weekly} "
        f"--keep-monthly {keep_monthly}{prune_flag}"
    )


def build_restore_command(repo: str, snapshot: str, target_dir: str) -> str:
    """``restic -r <repo> restore <snapshot> --target <dir>``."""
    validate_repo(repo)
    validate_snapshot(snapshot)
    return (
        f"restic -r {shlex.quote(repo)} restore {shlex.quote(snapshot)} "
        f"--target {shlex.quote(target_dir)}"
    )


def build_snapshots_command(repo: str) -> str:
    """``restic -r <repo> snapshots --json`` for listing."""
    validate_repo(repo)
    return f"restic -r {shlex.quote(repo)} snapshots --json"


def parse_snapshot_id(backup_stdout: str) -> str | None:
    """Extract the new snapshot id from ``restic backup --json`` output.

    restic emits newline-delimited JSON; the final ``message_type=="summary"``
    object carries ``snapshot_id``. Returns None if not found (e.g. restic
    version whose summary lacks it) rather than raising.
    """
    for line in (backup_stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if obj.get("message_type") == "summary" and obj.get("snapshot_id"):
            return str(obj["snapshot_id"])
    return None

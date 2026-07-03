#!/usr/bin/env python3
"""Detect and mirror new commits on the upstream PixelFlasher remote.

Single responsibility: fetch ``upstream``, fast-forward the local
``upstream-sync`` mirror branch to match, and report what moved. This script
never touches the checked-out working branch and never merges anything into
it -- it only updates an isolated bookkeeping branch and prints a structured
summary for a human (or another script/agent) to act on.

Usage:
    python scripts/sync_upstream.py [--json]

Exit codes:
    0  ran successfully (whether or not upstream moved)
    1  git command failed (no upstream remote, network error, etc.)
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys

MIRROR_BRANCH = "upstream-sync"
UPSTREAM_REF = "upstream/main"

# Files this fork has patched locally. If upstream also touches these, a
# later merge into a real working branch is more likely to conflict or to
# silently re-introduce a bug we already fixed -- worth flagging explicitly.
LOCALLY_PATCHED_FILES = {"constants.py", "phone.py"}

# Files pixel_flasher_plugin's contract test (test_phone_contract.py) pins
# against. If these appear in the upstream diff, run that test before trusting
# a merge.
CONTRACT_SENSITIVE_FILES = {"phone.py"}


def run(*args: str) -> str:
    result = subprocess.run(["git", *args], capture_output=True, text=True, check=True)
    return result.stdout.strip()


def try_run(*args: str) -> str | None:
    try:
        return run(*args)
    except subprocess.CalledProcessError:
        return None


def sync() -> dict:
    run("fetch", "upstream")
    new_sha = run("rev-parse", UPSTREAM_REF)

    old_sha = try_run("rev-parse", "--verify", MIRROR_BRANCH)
    first_run = old_sha is None

    if first_run:
        run("branch", MIRROR_BRANCH, UPSTREAM_REF)
        old_sha = new_sha  # nothing to diff against yet
    elif old_sha != new_sha:
        run("branch", "-f", MIRROR_BRANCH, UPSTREAM_REF)

    moved = old_sha != new_sha
    commits: list[str] = []
    changed_files: list[str] = []
    if moved and not first_run:
        commits = run("log", f"{old_sha}..{new_sha}", "--oneline").splitlines()
        changed_files = run("diff", "--name-only", old_sha, new_sha).splitlines()

    current_branch = run("rev-parse", "--abbrev-ref", "HEAD")
    behind = run("log", f"HEAD..{UPSTREAM_REF}", "--oneline")
    commits_behind = behind.splitlines() if behind else []

    touches_local_patches = sorted(LOCALLY_PATCHED_FILES & set(changed_files))
    touches_contract = sorted(CONTRACT_SENSITIVE_FILES & set(changed_files))

    return {
        "first_run": first_run,
        "moved": moved,
        "old_sha": old_sha,
        "new_sha": new_sha,
        "new_commits": commits,
        "changed_files": changed_files,
        "touches_locally_patched_files": touches_local_patches,
        "touches_contract_sensitive_files": touches_contract,
        "working_branch": current_branch,
        "working_branch_commits_behind_upstream": commits_behind,
        "mirror_branch": MIRROR_BRANCH,
    }


def format_human(result: dict) -> str:
    lines = []
    if result["first_run"]:
        lines.append(f"Initialized '{MIRROR_BRANCH}' mirror branch at {result['new_sha'][:8]}.")
    elif not result["moved"]:
        lines.append(f"No upstream movement. '{UPSTREAM_REF}' still at {result['new_sha'][:8]}.")
    else:
        lines.append(
            f"Upstream moved: {result['old_sha'][:8]} -> {result['new_sha'][:8]} "
            f"({len(result['new_commits'])} commit(s))."
        )
        lines.append(f"'{MIRROR_BRANCH}' fast-forwarded to match.")
        for c in result["new_commits"]:
            lines.append(f"  {c}")
        lines.append(f"Files changed: {len(result['changed_files'])}")
        if result["touches_locally_patched_files"]:
            lines.append(
                f"  ⚠ touches file(s) we've locally patched: "
                f"{', '.join(result['touches_locally_patched_files'])} -- review before merging."
            )
        if result["touches_contract_sensitive_files"]:
            lines.append(
                f"  ⚠ touches contract-sensitive file(s): "
                f"{', '.join(result['touches_contract_sensitive_files'])} -- "
                f"run pixel_flasher_plugin/tests/test_phone_contract.py against "
                f"'{MIRROR_BRANCH}' before merging."
            )

    if result["working_branch_commits_behind_upstream"]:
        lines.append(
            f"Working branch '{result['working_branch']}' is "
            f"{len(result['working_branch_commits_behind_upstream'])} commit(s) behind "
            f"'{UPSTREAM_REF}' (not yet merged into your working branch)."
        )
    else:
        lines.append(f"Working branch '{result['working_branch']}' is up to date with '{UPSTREAM_REF}'.")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="print machine-readable JSON instead of text")
    args = parser.parse_args()

    try:
        result = sync()
    except subprocess.CalledProcessError as exc:
        print(f"git command failed: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(result, indent=2) if args.json else format_human(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

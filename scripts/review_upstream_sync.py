#!/usr/bin/env python3
"""Orchestrate: mirror upstream, review with claude -p, notify via n8n/Telegram.

Single responsibility per stage:
  1. sync_upstream.sync() -- pure git plumbing (see sync_upstream.py).
  2. If it moved, run a tightly-scoped, read-only `claude -p` review locally
     (never inside n8n -- that OOM'd; see commit history / session notes).
  3. POST the summary to an n8n webhook, which forwards to Telegram.

The webhook URL and shared secret are fetched from Bitwarden at runtime via
bw-wrapper -- never hardcoded here, since this file lives in a public git
fork. Run `bw-wrapper unlock --shell` (or ensure a cached session) before
running this from an interactive shell; the systemd service is expected to
run under a session where bw-wrapper's cache is already warm.

Usage:
    python3 scripts/review_upstream_sync.py
"""
from __future__ import annotations

import json
import subprocess
import sys
import urllib.request

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from sync_upstream import sync  # noqa: E402

BW_ITEM = "PixelFlasher Upstream Webhook"

ALLOWED_TOOLS = (
    "Read Grep Glob Bash(git diff*) Bash(git log*) Bash(git show*) "
    "Bash(git worktree*) Bash(git rev-parse*) Bash(cd*) Bash(pytest*) "
    "Bash(.venv/bin/pytest*) Bash(PYTHONPATH=*) Bash(rm -rf /tmp/pf-upstream-review*)"
)
DISALLOWED_TOOLS = (
    "Edit Write NotebookEdit Bash(git push*) Bash(git commit*) "
    "Bash(git merge*) Bash(git reset*) Bash(git rebase*) Bash(git checkout*)"
)


def bw_field(field: str) -> str:
    result = subprocess.run(
        ["bw-wrapper", "field", BW_ITEM, field], capture_output=True, text=True, check=True
    )
    return result.stdout.strip()


def build_prompt(result: dict) -> str:
    return f"""You're reviewing an upstream sync for the PixelFlasher repo at /home/luka/projects/PixelFlasher (GitHub: badabing2005/PixelFlasher).

The 'upstream-sync' local branch was just fast-forwarded to mirror upstream/main, moving from {result['old_sha']} to {result['new_sha']}.

New commits:
{chr(10).join(result['new_commits'])}

Changed files ({len(result['changed_files'])} total):
{chr(10).join(result['changed_files'])}

Locally-patched files touched by this diff (we already fixed bugs in these -- check upstream didn't reintroduce them or conflict): {', '.join(result['touches_locally_patched_files']) or 'none'}

Contract-sensitive files touched (device_ops.py depends on phone.Device's exact surface): {', '.join(result['touches_contract_sensitive_files']) or 'none'}

Do the following, READ-ONLY (you have no Edit/Write/push/merge/commit/reset access -- it will be blocked):
1. For each locally-patched or contract-sensitive file, read the actual diff: git diff {result['old_sha']} {result['new_sha']} -- <file>
2. If phone.py changed: create a temp worktree of upstream-sync (git worktree add /tmp/pf-upstream-review upstream-sync), run pixel_flasher_plugin/tests/test_phone_contract.py against that worktree's phone.py (e.g. PYTHONPATH=/tmp/pf-upstream-review .venv/bin/pytest pixel_flasher_plugin/tests/test_phone_contract.py --no-header -q). Report pass/fail. Clean up afterward: git worktree remove --force /tmp/pf-upstream-review
3. Summarize in under 150 words: what changed, whether anything is risky for our patches (constants.py PIF_UPDATE_URL, phone.py magisk_uninstall_module elif chain) or breaks the phone.Device contract, and a clear recommendation: SAFE TO MERGE / NEEDS MANUAL REVIEW / CONTRACT BROKEN.

Your entire response becomes a Telegram message verbatim. Do not narrate your steps or say things like "confirmed" or "ready to deliver the summary" before it. The FIRST character of your response must be the first character of the summary itself -- no preamble, no code fences, no meta-commentary."""


def run_review(prompt: str) -> str:
    proc = subprocess.run(
        [
            "/home/luka/.local/bin/claude", "-p",
            "--output-format", "json",
            "--permission-mode", "bypassPermissions",
            "--allowedTools", ALLOWED_TOOLS,
            "--disallowedTools", DISALLOWED_TOOLS,
        ],
        input=prompt, capture_output=True, text=True, timeout=600, cwd="/home/luka/projects/PixelFlasher",
    )
    if proc.returncode != 0:
        return f"Claude review process failed (exit {proc.returncode}): {proc.stderr[-800:]}"
    try:
        return json.loads(proc.stdout).get("result", proc.stdout)
    except json.JSONDecodeError:
        return proc.stdout[-2000:]


def notify(webhook_url: str, secret: str, message: str) -> None:
    body = json.dumps({"secret": secret, "message": message}).encode()
    req = urllib.request.Request(
        webhook_url,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "curl/8.21.0"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        print(f"webhook notify: HTTP {resp.status}")


def main() -> int:
    result = sync()
    if not result["moved"]:
        print("No upstream movement.")
        return 0

    print(f"Upstream moved: {result['old_sha'][:8]} -> {result['new_sha'][:8]}. Running review...")
    review_text = run_review(build_prompt(result))

    message = (
        f"🔄 *PixelFlasher upstream moved*\n\n"
        f"{result['old_sha'][:8]} → {result['new_sha'][:8]} ({len(result['new_commits'])} commits)\n\n"
        f"{review_text}"
    )

    webhook_url = bw_field("webhook_url")
    secret = bw_field("secret")
    notify(webhook_url, secret, message)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

# PixelFlasher MCP Server

A headless [Model Context Protocol](https://modelcontextprotocol.io) server that
exposes PixelFlasher's device operations as tools an AI agent (e.g. Claude Code)
can call directly — flashing, patching, partition backup/restore, module and
package management, Play Integrity, and app **data** backup/restore.

It reuses PixelFlasher's own `runtime.py` / `phone.py` / `config.py` under a wx
stub (see `headless_runtime.py`), so no GUI toolkit is loaded.

## Registration

The repo ships a project-scoped `.mcp.json` at the root. Any Claude Code session
started **in this directory** picks the server up automatically — no global
config, so the CRITICAL-tier tools (flash / erase / lock / unlock) only ever
exist for sessions opened here.

The launch command is machine-independent:

```json
{
  "mcpServers": {
    "pixelflasher": {
      "command": "uv",
      "args": ["run", "--project", ".", "python", "-m", "pixel_flasher_plugin.mcp_server"],
      "env": { "PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION": "python" }
    }
  }
}
```

`uv run` resolves the environment from `pyproject.toml` + `uv.lock`, creating the
`.venv` on first launch. `PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python` avoids a
protobuf C++ descriptor-pool crash on newer CPython builds.

## Setup on a fresh machine (e.g. macOS, over USB)

Prerequisite: [`uv`](https://docs.astral.sh/uv/) and the Android platform-tools
(`adb` / `fastboot`) on `PATH`.

```bash
git clone <this-fork> PixelFlasher && cd PixelFlasher
uv sync                       # creates .venv from uv.lock (reproducible)
adb devices                   # confirm the phone shows over USB
claude                        # start Claude Code here; .mcp.json is auto-loaded
```

Verify from inside the session with the `list_devices` tool, or from a shell:

```bash
claude mcp list | grep pixelflasher    # -> ✔ Connected
```

wxPython, PyInstaller, and other GUI/build-only packages from the app's
`requirements.txt` are intentionally **excluded** from this package's
dependencies — the headless server never needs them.

## Safety model

- **CRITICAL** tools (flash/erase/lock/unlock, factory image) and **WARN** tools
  (backup/restore/schedule, force-stop) require explicit `dry_run=False` +
  `confirm=True`; they default to a dry-run preview.
- All shell commands pass through `command_validator.py`'s allow-list and the
  `safety_engine.py` gateway before execution.

## App-data backup tiers

**Tier 1 — on-device (Neo Backup).** `create_backup_schedule` /
`trigger_app_backup` drive Neo Backup for convenient, app-granular,
restore-from-the-phone backups. `backup_app_data` / `restore_app_data` do a
one-shot, app-independent root `tar --selinux` of a package's private data.

**Tier 2 — host-side restic (incremental / dedup / encrypted / offsite).**
`snapshot_app_data` pulls each package's tar into a staging dir and commits it
to a [restic](https://restic.net) repo, then `restic copy` replicates
(dedup-preserving) to secondary repos for a 3-2-1 setup;
`restore_from_snapshot` and `list_app_snapshots` complete the loop. restic and
rclone run on the **host** (Mac/VPS), never on the phone.

One-time repo setup (do this on the Mac before first `snapshot_app_data`):

```bash
# Password comes from Bitwarden -- never stored in plaintext or passed as a param.
export RESTIC_PASSWORD_COMMAND='bw-wrapper get "restic-pixel"'
export RESTIC_FROM_PASSWORD_COMMAND='bw-wrapper get "restic-pixel"'   # for `copy`

# Primary (fast, local) + two replicas (offsite + fast LAN):
restic -r /Volumes/backup/restic-pixel init
restic -r rclone:gdrive:backups/pixel   init --from-repo /Volumes/backup/restic-pixel --copy-chunker-params
restic -r sftp:luka@vps:/home/luka/restic-pixel init --from-repo /Volumes/backup/restic-pixel --copy-chunker-params
```

`--copy-chunker-params` on the copy targets is **required** — without it
`restic copy` re-chunks everything and cross-repo dedup is lost. Set both
`RESTIC_*_PASSWORD_COMMAND` vars in the environment that launches the MCP server
(e.g. add them to `.mcp.json`'s `env`, sourcing from `bw-wrapper`).

Then a nightly snapshot over USB is one tool call, e.g.:
`snapshot_app_data(device_id, packages=[...], primary_repo="/Volumes/backup/restic-pixel",
copy_repos=["rclone:gdrive:backups/pixel", "sftp:luka@vps:/home/luka/restic-pixel"],
dry_run=False, confirm=True)`.

## Tests

```bash
uv run --extra test pytest pixel_flasher_plugin/tests/ -q
```

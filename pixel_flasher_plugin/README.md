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

## Tests

```bash
uv run --extra test pytest pixel_flasher_plugin/tests/ -q
```

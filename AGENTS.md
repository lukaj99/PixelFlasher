# AGENTS.md — PixelFlasher

> Symlinked as CLAUDE.md. Single source of truth for AI agents.

## Project Overview

PixelFlasher is a Python GUI application for flashing (updating) Google Pixel
phones, with a companion headless MCP server that exposes device operations as
AI-agent-callable tools. The GUI wraps `adb`/`fastboot` with automated
Magisk/APatch/KernelSU patching, Play Integrity management, and firmware
flashing workflows. The MCP plugin (`pixelflasher-mcp`) runs the same backend
without wxPython, providing device management over the MCP protocol.

## Commands

All commands verified from `pyproject.toml`, `PixelFlasher.py`, `build.sh`,
and `.mcp.json`.

### Run

| Command | What |
|---|---|
| `python PixelFlasher.py` | Launch the GUI (imports `Main.main()`) |
| `pixelflasher-mcp` | Start the headless MCP server (from `pyproject.toml` `[project.scripts]`) |
| `uv run --project . python -m pixel_flasher_plugin.mcp_server` | MCP server via uv (`.mcp.json` default) |

### Build

| Command | What |
|---|---|
| `./build.sh` | PyInstaller build (auto-selects spec by OS/arch) |
| `pip install -r requirements.txt` | Install runtime deps (includes wxPython) |
| `uv sync` | Install headless deps only (excludes wxPython, from `pyproject.toml`) |

### Test / Lint

| Command | What |
|---|---|
| `uv run pytest` | Run tests (requires `[project.optional-dependencies] test`) |

ruff is available in `.venv` but has no config in `pyproject.toml` — lint
manually or via IDE.

## Architecture

```
PixelFlasher.py          # GUI entry point → Main.main()
├── Main.py              # Main window (wxPython, ~400k)
├── phone.py             # Device/ADB/Fastboot operations (~287k)
├── runtime.py           # Core runtime, config loading (~503k)
├── config.py            # Settings management
├── pf_modules.py        # Magisk/APatch/KSU module handling (~408k)
├── pif_manager.py       # Play Integrity Fix management (~189k)
├── magisk_modules.py    # Magisk module UI (~49k)
├── package_manager.py   # Android package operations (~67k)
├── partition_manager.py # Partition/image management (~25k)
└── pixel_flasher_plugin/  # Headless MCP server (separate package)
    ├── mcp_server.py    # FastMCP server, 46 tools exposed
    ├── device_ops.py    # ADB/fastboot operations
    ├── headless_runtime.py  # wxPython stub for headless imports
    ├── safety_engine.py # Command safety gating
    ├── boot_patcher.py  # Automated boot image patching
    ├── app_backup.py    # App data backup/restore
    ├── restic_backup.py # Restic-based full backups
    └── tools/           # MCP tool definitions
```

The MCP plugin reuses `runtime.py`, `phone.py`, and `config.py` from the
parent app via a wxPython stub (`headless_runtime.py`), so headless and GUI
modes share all device-operation logic.

### Build artifacts

- `build-on-linux.spec`, `build-on-mac.spec`, `build-on-mac-intel-only.spec`,
  `build-on-win.spec`, `build-on-win-arm64.spec` — PyInstaller spec files.
- `build.sh` auto-selects the correct spec based on `$OSTYPE` and `arch`.

## Key Files

| Path | Purpose |
|---|---|
| `PixelFlasher.py` | GUI entry point |
| `Main.py` | Main application window |
| `phone.py` | ADB/fastboot/device abstraction |
| `runtime.py` | Core runtime, settings persistence |
| `config.py` | Configuration management |
| `pf_modules.py` | Root solution module handling |
| `pif_manager.py` | Play Integrity Fix workflows |
| `pyproject.toml` | Headless package metadata + deps |
| `requirements.txt` | Full runtime deps (GUI + headless) |
| `build.sh` | PyInstaller build script |
| `pixel_flasher_plugin/mcp_server.py` | MCP server entry point |
| `.mcp.json` | MCP client config for this project |

## Critical Rules

- The headless MCP server (`pixelflasher-mcp`) MUST NOT import wxPython.
  `headless_runtime.py` installs a stub before the shared runtime modules are
  loaded. Any new import path through `Main.py` or GUI-only modules will break
  the headless server.
- `PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python` is required in the
  environment for protobuf compatibility (set in `PixelFlasher.py` and
  `mcp_server.py`).
- The `pixel_flasher_plugin` package is the only package distributed (see
  `[tool.setuptools.packages.find]` in `pyproject.toml`). Core app modules
  (`Main.py`, `phone.py`, etc.) are NOT packaged — they're imported from the
  repo root at runtime.

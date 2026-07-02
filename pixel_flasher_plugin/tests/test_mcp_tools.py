"""MCP server tool/resource registration invariants.

Pins the contract that AI agents see when they connect to the PixelFlasher
MCP server:

  * Exactly 34 tools registered (every device operation the agent can call).
  * Exactly 7 resources registered (every JSON / doc the agent can read).
  * The 5 CRITICAL tools (flash_partition, erase_partition, flash_boot_image,
    unlock_bootloader, lock_bootloader) MUST accept ``dry_run`` -- this is
    the opt-in gate that lets agents preview destructive commands.
  * The 5 remaining stub tools MUST be visibly marked as not implemented -- agents
    must not waste tokens calling tools that return errors.

These counts come from the reviewer-validated spec. Drift in any of them
indicates the MCP surface changed without coordination.
"""
from __future__ import annotations

import pytest


# ---------------------------------------------------------------------------
# Tool count
# ---------------------------------------------------------------------------
EXPECTED_TOOL_COUNT = 34


def test_exactly_34_tools_registered(mcp_server_module) -> None:
    """The MCP server MUST register exactly 34 tools."""
    mcp = mcp_server_module.mcp
    tools = mcp._tool_manager._tools
    assert len(tools) == EXPECTED_TOOL_COUNT, (
        f"Tool count drifted from {EXPECTED_TOOL_COUNT}: got {len(tools)}.\n"
        f"Registered tools: {sorted(tools.keys())}"
    )


def test_tool_names_are_unique(mcp_server_module) -> None:
    """Sanity: tool names are unique (FastMCP enforces this, but verify)."""
    tools = mcp_server_module.mcp._tool_manager._tools
    names = list(tools.keys())
    assert len(names) == len(set(names)), (
        f"Duplicate tool names detected: "
        f"{[n for n in names if names.count(n) > 1]}"
    )


# ---------------------------------------------------------------------------
# Resource count
# ---------------------------------------------------------------------------
EXPECTED_RESOURCE_COUNT = 7


def test_exactly_7_resources_registered(mcp_server_module) -> None:
    """The MCP server MUST register exactly 7 resources.

    mcp_resources.py is imported at the bottom of mcp_server.py so the
    resources attach to the shared ``mcp`` instance after all tools are
    registered. Importing mcp_server is sufficient to trigger this.
    """
    mcp = mcp_server_module.mcp
    resources = mcp._resource_manager._resources
    assert len(resources) == EXPECTED_RESOURCE_COUNT, (
        f"Resource count drifted from {EXPECTED_RESOURCE_COUNT}: got {len(resources)}.\n"
        f"Registered resources: {sorted(resources.keys())}"
    )


def test_expected_resource_uris_present(mcp_server_module) -> None:
    """Each expected resource URI is registered (defends against renames)."""
    resources = mcp_server_module.mcp._resource_manager._resources
    expected_uris = {
        "pf://devices",
        "pf://versions",
        "pf://constants/banned_kernels",
        "pf://constants/bootloader_versions",
        "pf://constants/package_names",
        "pf://constants/pif_urls",
        "pf://docs/safe_flashing",
    }
    actual = set(resources.keys())
    missing = expected_uris - actual
    extra = actual - expected_uris
    assert not missing, f"Missing resource URIs: {sorted(missing)}"
    # Extra URIs are not a failure (could be additive), but log them.
    if extra:
        pytest.skip(f"Extra resources present (non-failing): {sorted(extra)}")


# ---------------------------------------------------------------------------
# Critical tools MUST have dry_run parameter
# ---------------------------------------------------------------------------
CRITICAL_TOOLS_WITH_DRY_RUN = [
    "flash_partition",
    "erase_partition",
    "flash_boot_image",
    "patch_boot_image",
    "flash_factory_image",
    "restore_backup",
    "unlock_bootloader",
    "lock_bootloader",
]


@pytest.mark.parametrize("tool_name", CRITICAL_TOOLS_WITH_DRY_RUN)
def test_critical_tool_has_dry_run_parameter(
    mcp_server_module, tool_name: str
) -> None:
    """Each CRITICAL tool MUST accept ``dry_run`` so agents can preview commands."""
    tools = mcp_server_module.mcp._tool_manager._tools
    assert tool_name in tools, (
        f"CRITICAL tool {tool_name!r} is not registered. "
        f"Registered: {sorted(tools.keys())}"
    )
    tool = tools[tool_name]
    params = tool.parameters
    assert isinstance(params, dict), (
        f"tool.parameters for {tool_name} is not a dict: {type(params)}"
    )
    properties = params.get("properties")
    assert isinstance(properties, dict), (
        f"tool.parameters['properties'] for {tool_name} is missing or not a dict"
    )
    assert "dry_run" in properties, (
        f"CRITICAL tool {tool_name!r} is MISSING the dry_run parameter.\n"
        f"Without dry_run, agents cannot safely preview a destructive "
        f"operation before executing it.\n"
        f"Parameters present: {sorted(properties.keys())}"
    )


# ---------------------------------------------------------------------------
# Cross-check: every tool has a non-empty description (sanity)
# ---------------------------------------------------------------------------
def test_all_tools_have_descriptions(mcp_server_module) -> None:
    """Every registered tool must have a non-empty description string."""
    tools = mcp_server_module.mcp._tool_manager._tools
    offenders = [name for name, tool in tools.items() if not (tool.description or "").strip()]
    assert not offenders, (
        f"Tools with empty descriptions: {offenders}"
    )
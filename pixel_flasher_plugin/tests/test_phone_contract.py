"""Contract test pinning the ``phone.Device`` surface ``device_ops.py`` depends on.

``phone.py`` is upstream (badabing2005/PixelFlasher) GUI code we track via the
``upstream`` remote, not code this plugin owns. A merge from upstream can
rename, remove, or reshape any of these members with zero merge conflicts
(the merge is textually clean; the breakage is semantic) and the first sign
would otherwise be a runtime ``AttributeError``/``TypeError`` inside a live
MCP tool call.

This test makes that class of break fail loudly and immediately after any
upstream sync, instead of silently.

To regenerate the dependency list after intentionally changing what
``device_ops.py`` (or another plugin module) calls on a ``Device``, run:

    grep -ohE "\\b(dev|device)\\.[a-zA-Z_][a-zA-Z0-9_]*" pixel_flasher_plugin/*.py \\
        | sed -E 's/^(dev|device)\\.//' | sort -u
"""
from __future__ import annotations

import inspect

import pytest

# name -> ("property", ()) | ("method", (required_param_names...))
# Instance-only attributes (set in __init__, not class-level) are asserted
# separately in test_instance_level_attributes_exist below.
DEVICE_CONTRACT = {
    "active_slot": ("property", ()),
    "api_level": ("property", ()),
    "architecture": ("property", ()),
    "build": ("property", ()),
    "hardware": ("property", ()),
    "has_init_boot": ("property", ()),
    "kernel": ("property", ()),
    "rooted": ("property", ()),
    "unlocked": ("property", ()),
    "check_file": ("method", ("file_path", "with_su", "verbose")),
    "disable_magisk_module": ("method", ("dirname",)),
    "enable_magisk_module": ("method", ("dirname",)),
    "get_apatch_detailed_modules": ("method", ("refresh",)),
    "get_battery_details": ("method", ()),
    "get_device_state": ("method", ("device_id", "timeout", "retry", "update")),
    "get_ksu_detailed_modules": ("method", ("refresh",)),
    "get_magisk_detailed_modules": ("method", ("refresh",)),
    "get_package_list": ("method", ("state",)),
    "get_partitions": ("method", ()),
    "get_prop": ("method", ("prop", "prop2")),
    "get_sukisu_detailed_modules": ("method", ("refresh",)),
    "get_unlock_ability": ("method", ()),
    "get_wild_ksu_detailed_modules": ("method", ("refresh",)),
    "init": ("method", ("mode",)),
    "install_apk": ("method", ("app", "fastboot_included", "owner_playstore", "bypass_low_target")),
    "is_connected": ("method", ("device_id",)),
    "is_display_unlocked": ("method", ()),
    "magisk_install_module": ("method", ("module",)),
    "magisk_run_module_action": ("method", ("dirname",)),
    "magisk_uninstall_module": ("method", ("dirname",)),
    "pull_file": ("method", ("remote_file", "local_file", "with_su", "quiet")),
    "push_file": ("method", ("local_file", "file_path", "with_su")),
}

INSTANCE_ONLY_ATTRS = ("props", "true_mode")


@pytest.mark.parametrize("name,spec", sorted(DEVICE_CONTRACT.items()))
def test_device_member_matches_contract(headless_bootstrap, name, spec) -> None:
    from phone import Device

    kind, required_params = spec
    member = inspect.getattr_static(Device, name, None)
    assert member is not None, (
        f"phone.Device.{name} no longer exists -- device_ops.py depends on it. "
        f"Upstream likely renamed or removed it."
    )

    if kind == "property":
        assert isinstance(member, property), (
            f"phone.Device.{name} used to be a property but is now {type(member).__name__} "
            f"-- device_ops.py accesses it as an attribute, not a call."
        )
        return

    assert callable(member) or isinstance(member, (staticmethod, classmethod)), (
        f"phone.Device.{name} is no longer callable (now {type(member).__name__})."
    )
    func = member.__func__ if isinstance(member, (staticmethod, classmethod)) else member
    params = set(inspect.signature(func).parameters) - {"self"}
    missing = set(required_params) - params
    assert not missing, (
        f"phone.Device.{name} signature dropped parameter(s) {missing} that "
        f"device_ops.py passes. Current params: {sorted(params)}"
    )


def test_instance_level_attributes_exist(headless_bootstrap) -> None:
    """``props`` and ``true_mode`` are set in ``__init__``, not class-level."""
    from phone import Device

    dev = Device(id="FAKE001", mode="adb")
    for attr in INSTANCE_ONLY_ATTRS:
        assert hasattr(dev, attr), (
            f"phone.Device instances no longer have a '{attr}' attribute -- "
            f"device_ops.py depends on it."
        )

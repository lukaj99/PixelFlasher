"""Root-solution dispatch tests for ``phone.Device`` module (un)install helpers.

Pins the command each root solution's ``su_version`` string must dispatch to.
``magisk_uninstall_module`` previously used three independent ``if`` statements
(kernelsu / sukisu / wild_ksu) instead of an ``if/elif/elif`` chain, so the
trailing ``if wild_ksu / elif apatch / else`` block silently overwrote the
correct KernelSU/SukiSU command with the Magisk ``touch .../remove`` fallback.
"""
from __future__ import annotations

import pytest


@pytest.mark.parametrize(
    "su_version,expected_fragment,forbidden_fragment",
    [
        ("KernelSU v1.2.3", "ksud module uninstall", "touch"),
        ("SukiSU Ultra v1.0", "ksud module uninstall", "touch"),
        ("Wild_KSU v1.0", "ksud module uninstall", "touch"),
        ("APatch v1.0", "apd module uninstall", "touch"),
        ("Magisk v27.0", "touch", "ksud"),
    ],
)
def test_magisk_uninstall_module_dispatches_by_root_solution(
    monkeypatch, headless_bootstrap, su_version, expected_fragment, forbidden_fragment
) -> None:
    from phone import Device

    dev = Device(id="FAKE001", mode="adb")
    dev.true_mode = "adb"
    dev._su_version = su_version

    captured_cmd = {}

    monkeypatch.setattr("phone.get_adb", lambda: "/fake/adb")
    monkeypatch.setattr(
        "phone.run_shell",
        lambda cmd, *a, **kw: captured_cmd.setdefault("cmd", cmd),
    )

    result = dev.magisk_uninstall_module("test_module")

    assert result == 0
    assert "cmd" in captured_cmd, "run_shell was never called"
    assert expected_fragment in captured_cmd["cmd"], (
        f"su_version={su_version!r} produced command {captured_cmd['cmd']!r}, "
        f"expected it to contain {expected_fragment!r}"
    )
    assert forbidden_fragment not in captured_cmd["cmd"], (
        f"su_version={su_version!r} produced command {captured_cmd['cmd']!r}, "
        f"which incorrectly contains {forbidden_fragment!r}"
    )

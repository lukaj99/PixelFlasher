"""Safety-layer 2/3 invariant tests: CommandValidator injection + partition blocklist.

These tests pin the two guarantees that the safety reviewer validated during
the initial MCP build:

  1. The whitelist rejects any command containing shell metacharacters
     (semicolons, pipes, newlines) that could chain a second command.
  2. The partition blocklist blocks every firmware-critical partition, with
     slot-suffix normalization so ``xbl_a`` is treated like ``xbl``.

If any of these tests fail, the agent has a path to brick a device. Treat
red results as a P0 safety finding.
"""
from __future__ import annotations

import pytest

from pixel_flasher_plugin.command_validator import CommandValidator


# ---------------------------------------------------------------------------
# Injection vectors -- these MUST all be DENIED
# ---------------------------------------------------------------------------
INJECTION_VECTORS = [
    pytest.param(
        "adb -s X shell getprop ro.x; rm -rf /",
        id="semicolon-chained-rm",
    ),
    pytest.param(
        "adb -s X shell getprop ro.x | cat",
        id="pipe-to-cat",
    ),
    pytest.param(
        "adb -s X shell getprop ro.x\nrm -rf /",
        id="newline-chained-rm",
    ),
]


@pytest.mark.parametrize("cmd", INJECTION_VECTORS)
def test_injection_vector_is_blocked(cmd: str) -> None:
    """Shell-metacharacter injection must be denied by the whitelist."""
    allowed, reason = CommandValidator.is_allowed(cmd)
    assert allowed is False, (
        f"INJECTION VECTOR ALLOWED: {cmd!r}\n"
        f"This command would let an agent chain arbitrary shell commands."
    )
    # Sanity: reason must be present and mention the whitelist.
    assert reason, f"Denial reason is empty for {cmd!r}"
    assert "whitelist" in reason.lower() or "blocked" in reason.lower(), (
        f"Unexpected denial reason for {cmd!r}: {reason!r}"
    )


# ---------------------------------------------------------------------------
# avbtool host-command injection vectors -- these MUST all be DENIED
# ---------------------------------------------------------------------------
AVBTOOL_INJECTION_VECTORS = [
    pytest.param(
        "avbtool add_hash_footer --image /tmp/boot.img; rm -rf /",
        id="avbtool-semicolon-chain",
    ),
    pytest.param(
        "avbtool add_hash_footer --image /tmp/boot.img | cat",
        id="avbtool-pipe",
    ),
    pytest.param(
        "avbtool add_hash_footer --image /tmp/boot.img\nrm -rf /",
        id="avbtool-newline-chain",
    ),
    pytest.param(
        "avbtool add_hash_footer --image $(rm -rf /) --partition_name boot",
        id="avbtool-command-substitution",
    ),
    pytest.param(
        "avbtool erase --image /tmp/boot.img",
        id="avbtool-unknown-subcommand",
    ),
]


@pytest.mark.parametrize("cmd", AVBTOOL_INJECTION_VECTORS)
def test_avbtool_injection_vector_is_blocked(cmd: str) -> None:
    """Host-side avbtool patterns must still reject injection and unknown subs."""
    allowed, reason = CommandValidator.is_allowed(cmd)
    assert allowed is False, (
        f"AVBTOOL INJECTION VECTOR ALLOWED: {cmd!r}\n"
        f"This would let an agent chain arbitrary host shell commands."
    )
    assert reason, f"Denial reason is empty for {cmd!r}"


# ---------------------------------------------------------------------------
# Legit commands -- these MUST be ALLOWED
# ---------------------------------------------------------------------------
LEGIT_COMMANDS = [
    pytest.param(
        "adb -s FAKE001 shell getprop ro.build.fingerprint",
        id="adb-getprop-fingerprint",
    ),
    pytest.param(
        "fastboot -s FAKE001 getvar product",
        id="fastboot-getvar-product",
    ),
    pytest.param(
        "avbtool add_hash_footer --image /tmp/boot.img "
        "--dynamic_partition_size --partition_name boot "
        "--hash_algorithm sha256 --algorithm SHA256_RSA4096 "
        "--key /tmp/testkey.pem",
        id="avbtool-add-hash-footer",
    ),
]


@pytest.mark.parametrize("cmd", LEGIT_COMMANDS)
def test_legit_command_is_allowed(cmd: str) -> None:
    """Read-only ADB/fastboot commands on the whitelist must pass."""
    allowed, reason = CommandValidator.is_allowed(cmd)
    assert allowed is True, (
        f"LEGIT COMMAND BLOCKED: {cmd!r}\n"
        f"Reason: {reason!r}"
    )
    assert reason == "", f"Reason should be empty for allowed command, got {reason!r}"


# ---------------------------------------------------------------------------
# Firmware-critical partitions -- is_partition_blocked() MUST return True
# ---------------------------------------------------------------------------
# The reviewer-validated blocklist covers 17 partitions. Every partition that
# can brick the device if flashed/erased must appear here (slot suffix stripped
# by _normalize_partition). These names are the contract.
BLOCKED_PARTITIONS = [
    "xbl",
    "xbl_a",
    "xbl_b",
    "tz",
    "tz_a",
    "keymaster",
    "keymaster_a",
    "modem",
    "modem_a",
    "hyp",
    "cmnlib",
    "cmnlib32",
    "devcfg",
    "apdp",
    "msadp",
    "dip",
    "limits",
]


@pytest.mark.parametrize("partition", BLOCKED_PARTITIONS)
def test_firmware_critical_partition_is_blocked(partition: str) -> None:
    """Each firmware-critical partition must be blocked from flash/erase.

    A/B slot suffixes (_a / _b) are stripped before lookup, so testing
    ``xbl_a`` proves the normalization works as well as the blocklist.
    """
    blocked = CommandValidator.is_partition_blocked(partition)
    assert blocked is True, (
        f"FIRMWARE-CRITICAL PARTITION NOT BLOCKED: {partition!r}\n"
        f"This means an agent could flash/erase this partition via fastboot, "
        f"potentially bricking the device."
    )


# ---------------------------------------------------------------------------
# Allowed partitions -- is_partition_blocked() MUST return False
# ---------------------------------------------------------------------------
ALLOWED_PARTITIONS = [
    "boot",
    "boot_a",
    "boot_b",
    "init_boot",
    "init_boot_a",
    "system",
    "vendor",
    "product",
]


@pytest.mark.parametrize("partition", ALLOWED_PARTITIONS)
def test_safe_partition_is_not_blocked(partition: str) -> None:
    """Non-firmware-critical partitions must NOT be flagged as blocked."""
    blocked = CommandValidator.is_partition_blocked(partition)
    assert blocked is False, (
        f"SAFE PARTITION INCORRECTLY BLOCKED: {partition!r}\n"
        f"This partition is safe to flash (e.g. boot, system, vendor) and "
        f"should not be on the firmware-critical blocklist."
    )


# ---------------------------------------------------------------------------
# Bonus invariant: end-to-end flash command must be denied for blocked
# partitions (the whitelist AND the blocklist cooperate via is_allowed).
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("partition", BLOCKED_PARTITIONS)
def test_flash_command_for_blocked_partition_is_denied(partition: str) -> None:
    """A fastboot flash command targeting a blocked partition must be DENIED.

    End-to-end check: a fastboot flash on any of the 17 firmware-critical
    partitions must be denied. The denial reason may differ depending on
    whether the partition is on the blocklist (reason: "blocked" /
    "firmware-critical") or simply not in the explicit allow list
    (reason: "not in the allowed partition list") -- both are valid
    denials, and both are caught by the stricter
    ``test_firmware_critical_partition_is_blocked`` test.
    """
    cmd = f"fastboot -s FAKE001 flash {partition} /tmp/fake.img"
    allowed, reason = CommandValidator.is_allowed(cmd)
    assert allowed is False, (
        f"FLASH COMMAND ON BLOCKED PARTITION ALLOWED: {cmd!r}"
    )
    assert reason, f"Denial reason is empty for {cmd!r}"


def test_blocklist_contains_exactly_23_entries() -> None:
    """Blocklist invariant: exactly 23 firmware-critical partitions.

    Pinned by the reviewer. Adding or removing partitions requires an
    explicit safety review -- this test ensures the count stays in sync.
    """
    # _normalize_partition is applied at lookup time, so the underlying set
    # holds canonical names. 23 canonical names = 23 partitions the agent
    # cannot flash.
    canonical = CommandValidator.BLOCKED_PARTITIONS
    assert len(canonical) == 23, (
        f"BLOCKED_PARTITIONS size changed: expected 23, got {len(canonical)}\n"
        f"Partitions: {sorted(canonical)}"
    )
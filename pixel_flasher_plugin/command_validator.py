"""Command whitelist and partition blocklist (safety Layers 2 and 3)."""
from __future__ import annotations

import re


class CommandValidator:
    ALLOWED_ADB_COMMANDS = [
        re.compile(r"^adb\s+devices(-l)?$"),
        re.compile(r"^adb\s+-s\s+\S+\s+shell\s+getprop\s+\S+$"),
        re.compile(r"^adb\s+-s\s+\S+\s+shell\s+pm\s+list\s+packages(-\S+)?$"),
        re.compile(r"^adb\s+-s\s+\S+\s+shell\s+pm\s+path\s+\S+$"),
        re.compile(r"^adb\s+-s\s+\S+\s+shell\s+pm\s+(enable|disable)\s+\S+$"),
        re.compile(r"^adb\s+-s\s+\S+\s+shell\s+pm\s+(grant|revoke)\s+\S+\s+\S+$"),
        re.compile(r"^adb\s+-s\s+\S+\s+shell\s+dumpsys(\s+\S+)*$"),
        re.compile(r"^adb\s+-s\s+\S+\s+shell\s+logcat(\s+\S+)*$"),
        re.compile(r"^adb\s+-s\s+\S+\s+shell\s+su\s+-c\s+\"blockdev\s+--getsize64\s+\S+\"$"),
        re.compile(r"^adb\s+-s\s+\S+\s+shell\s+su\s+-c\s+\"dd\s+if=\S+\s+bs=1M\s+2>/dev/null\"\s*>\s*\S+$"),
        re.compile(r"^adb\s+-s\s+\S+\s+shell\s+(uname|ls|cat|stat)(\s+\S+)*$"),
        re.compile(r"^adb\s+-s\s+\S+\s+(install|uninstall|push|pull|reboot|wait-for-\S+|get-state)(\s+\S+)*$"),
        # Host-side redirect used by read_partition; partition is sanitized before
        # this pattern is reached.
        re.compile(r"^adb\s+-s\s+\S+\s+shell\s+cat\s+\S+\s*>\s*\S+$"),
        # PIF update: copy temp config into place under root and fix permissions.
        re.compile(
            r"^adb\s+-s\s+\S+\s+shell\s+su\s+-c\s+"
            r"\"cp\s+\S+\s+\S+\s+&&\s+chmod\s+\d+\s+\S+\"$"
        ),
        # SOTA module install (Magisk / KernelSU / APatch variants)
        re.compile(
            r"^adb\s+-s\s+\S+\s+shell\s+su\s+-c\s+"
            r"'(ksud|apd)\s+module\s+install\s+/sdcard/Download/[a-zA-Z0-9_.-]+'$"
        ),
        re.compile(
            r"^adb\s+-s\s+\S+\s+shell\s+su\s+-c\s+"
            r"'magisk\s+--install-module\s+/sdcard/Download/[a-zA-Z0-9_.-]+'$"
        ),
        # SOTA module uninstall (KSU/APD CLI) and Magisk "remove" marker
        re.compile(
            r"^adb\s+-s\s+\S+\s+shell\s+su\s+-c\s+"
            r"'(ksud|apd)\s+module\s+uninstall\s+[a-zA-Z0-9_.-]+'$"
        ),
        re.compile(
            r"^adb\s+-s\s+\S+\s+shell\s+su\s+-c\s+"
            r"'touch\s+/data/adb/modules/[a-zA-Z0-9_.-]+/remove'$"
        ),
        # SOTA module enable/disable
        re.compile(
            r"^adb\s+-s\s+\S+\s+shell\s+su\s+-c\s+"
            r"'rm\s+-f\s+/data/adb/modules/[a-zA-Z0-9_.-]+/disable'$"
        ),
        re.compile(
            r"^adb\s+-s\s+\S+\s+shell\s+su\s+-c\s+"
            r"'touch\s+/data/adb/modules/[a-zA-Z0-9_.-]+/disable'$"
        ),
        # SOTA module action.sh execution
        re.compile(
            r"^adb\s+-s\s+\S+\s+shell\s+su\s+-c\s+"
            r"'busybox\s+sh\s+-o\s+standalone\s+/data/adb/modules/[a-zA-Z0-9_.-]+/action\.sh'$"
        ),
        # SOTA module listing for-loop used by Magisk/KernelSU/APatch module enumeration.
        re.compile(
            r"^adb\s+-s\s+\S+\s+shell\s+su\s+-c\s+"
            r"'for\s+FILE\s+in\s+/data/adb/modules/\*;\s+do\s+if\s+test\s+-d\s+\"\$FILE\";\s+then\s+echo\s+\$FILE;\s+if\s+test\s+-f\s+\"\$FILE/remove\";\s+then\s+echo\s+\"state=remove\";\s+elif\s+test\s+-f\s+\"\$FILE/disable\";\s+then\s+echo\s+\"state=disabled\";\s+else\s+echo\s+\"state=enabled\";\s+fi;\s+if\s+test\s+-f\s+\"\$FILE/action\.sh\";\s+then\s+echo\s+\"hasAction=True\";\s+else\s+echo\s+\"hasAction=False\";\s+fi;\s+cat\s+\"\$FILE/module\.prop\";\s+echo;\s+echo\s+-----pf;\s+fi;\s+done'$"
        ),
    ]

    ALLOWED_FASTBOOT_COMMANDS = [
        re.compile(r"^fastboot\s+devices$"),
        re.compile(r"^fastboot\s+-s\s+\S+\s+getvar(\s+\S+)*$"),
        re.compile(r"^fastboot\s+-s\s+\S+\s+flash\s+\S+\s+\S+$"),
        re.compile(r"^fastboot\s+-s\s+\S+\s+erase\s+\S+$"),
        re.compile(r"^fastboot\s+-s\s+\S+\s+reboot(-bootloader)?$"),
        re.compile(
            r"^fastboot\s+-s\s+\S+\s+flashing\s+"
            r"(unlock|lock|get_unlock_ability|unlock_critical|lock_critical)$"
        ),
        re.compile(r"^fastboot\s+-s\s+\S+\s+oem\s+\S+$"),
    ]

    # Host-side tools whose command string is used only for audit logging; the
    # actual work is performed by an in-process Python call.  The regexes are
    # anchored and tokenized so shell metacharacters cannot slip through.
    ALLOWED_HOST_COMMANDS = [
        re.compile(
            r"^avbtool\s+add_hash_footer"
            r"(?:\s+--\w+(?:\s+\S+)?)*$"
        ),
    ]

    BLOCKED_PARTITIONS = {
        "xbl",
        "xbl_config",
        "abl",
        "aop",
        "apdp",
        "cmnlib",
        "cmnlib32",
        "devcfg",
        "dip",
        "hyp",
        "keymaster",
        "limits",
        "qupfw",
        "tz",
        "uefisecapp",
        "multiimgoem",
        "multiimgqti",
        "cpucp",
        "shrm",
        "storsec",
        "spunvm",
        "modem",
        "msadp",
    }

    ALLOWED_PARTITIONS = {
        "boot",
        "init_boot",
        "vendor_boot",
        "dtbo",
        "vbmeta",
        "vbmeta_system",
        "system",
        "vendor",
        "product",
        "system_ext",
        "userdata",
        "cache",
        "super",
        "metadata",
    }

    _SLOT_SUFFIX = re.compile(r"_[ab]$")

    @classmethod
    def is_allowed(cls, cmd: str) -> tuple[bool, str]:
        """Return (allowed, reason). Empty reason means the command is allowed."""
        stripped = cmd.strip()
        matched = False
        for pattern in cls.ALLOWED_ADB_COMMANDS:
            if pattern.match(stripped):
                matched = True
                break
        if not matched:
            for pattern in cls.ALLOWED_FASTBOOT_COMMANDS:
                if pattern.match(stripped):
                    matched = True
                    break
        if not matched:
            for pattern in cls.ALLOWED_HOST_COMMANDS:
                if pattern.match(stripped):
                    matched = True
                    break
        if not matched:
            return False, "Command does not match the command whitelist."

        # For flash/erase commands, extract and validate the partition name.
        partition = cls._extract_partition(stripped)
        if partition is not None:
            normalized = cls._normalize_partition(partition)
            if cls.is_partition_blocked(normalized):
                return False, f"Partition '{partition}' is firmware-critical and blocked."
            if normalized not in cls.ALLOWED_PARTITIONS:
                return False, f"Partition '{partition}' is not in the allowed partition list."
        return True, ""

    @classmethod
    def _extract_partition(cls, cmd: str) -> str | None:
        """Pull the partition name out of a fastboot flash/erase command."""
        tokens = cmd.split()
        for i, token in enumerate(tokens):
            if token in ("flash", "erase") and i + 1 < len(tokens):
                return tokens[i + 1].strip("\"'")
        return None

    @classmethod
    def _normalize_partition(cls, partition: str) -> str:
        """Strip A/B slot suffix for validation."""
        return cls._SLOT_SUFFIX.sub("", partition)

    @classmethod
    def is_partition_blocked(cls, partition: str) -> bool:
        """True if the partition (ignoring slot suffix) is firmware-critical."""
        return cls._normalize_partition(partition) in cls.BLOCKED_PARTITIONS

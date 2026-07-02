"""Pure, testable boot-patch script generators for the MCP server.

These functions mirror the proven on-device script templates from
``pf_modules.py`` without importing GUI code or touching devices.
"""
from __future__ import annotations

import os
import shlex


KNOWN_ANDROID_ABIS = {"arm64-v8a", "armeabi-v7a", "x86", "x86_64"}


def _q(value: str) -> str:
    """Shell-quote a value for embedding in a generated shell script."""
    return shlex.quote(str(value))


def generate_magisk_script(
    boot_path: str,
    work_dir: str,
    zip_path: str,
    out_dir: str,
    arch: str,
    stock_sha1: str,
    version_code: str = "",
    api_level: str = "",
    zygote: str = "",
) -> str:
    """Return the contents of a Magisk ``pf_patch.sh`` script.

    Ported from ``pf_modules.py:2780-2862``.
    """
    if arch not in KNOWN_ANDROID_ABIS:
        arch = "arm64-v8a"
    version_code = version_code or "0"
    api_level = api_level or "0"
    stock_sha1 = stock_sha1 or ""
    patch_name = "magisk_patched"
    work_base = work_dir.rstrip("/")

    zip_name = os.path.basename(zip_path)

    lines: list[str] = [
        " #!/system/bin/sh",
        " ##############################################################################",
        " # PixelFlasher Magisk patch script",
        " ##############################################################################",
        f'MAGISK_VERSION="{version_code}"',
        f"STOCK_SHA1={_q(stock_sha1)}",
        f"ARCH={_q(arch)}",
        "cd /data/local/tmp",
        "rm -f /data/local/tmp/pf_patch.log",
        f"rm -rf {_q(work_base)} || {{ echo 'ERROR: Failed to remove directory {work_base}'; exit 1; }}",
        f"mkdir {_q(work_base)} || {{ echo 'ERROR: Failed to create directory {work_base}'; exit 1; }}",
        f"cd {_q(work_base)}",
        f"../busybox unzip -o ../{zip_name}",
        "cd assets",
    ]

    # Optional 32-bit Magisk binary copy (matches GUI logic).
    if arch == "x86_64":
        lines.append('[ -f ../lib/x86/libmagisk32.so ] && cp ../lib/x86/libmagisk32.so magisk32')
    elif arch == "arm64-v8a" and (zygote != "zygote64" or "zygote64_32" in version_code.lower()):
        lines.append('[ -f ../lib/armeabi-v7a/libmagisk32.so ] && cp ../lib/armeabi-v7a/libmagisk32.so magisk32')

    lines.extend([
        "chmod 755 *",
        f"if [[ -f \"{work_base}/assets/magisk\" ]]; then",
        f"    PATCHING_MAGISK_VERSION=$({work_base}/assets/magisk -c)",
        '    echo "PATCHING_MAGISK_VERSION: $PATCHING_MAGISK_VERSION"',
        f"elif [[ -f \"{work_base}/assets/magisk32\" ]]; then",
        f"    PATCHING_MAGISK_VERSION=$({work_base}/assets/magisk32 -c)",
        '    echo "PATCHING_MAGISK_VERSION: $PATCHING_MAGISK_VERSION"',
        f"elif [[ -f \"{work_base}/assets/magisk64\" ]]; then",
        f"    PATCHING_MAGISK_VERSION=$({work_base}/assets/magisk64 -c)",
        '    echo "PATCHING_MAGISK_VERSION: $PATCHING_MAGISK_VERSION"',
        "else",
        '    echo "ERROR: Magisk binary not found"',
        "fi",
        f"SDK_INT={_q(api_level)}",
        "export SDK_INT",
        'if [[ -f "./app_functions.sh" ]]; then',
        "    . ./app_functions.sh",
        "    app_init",
        "    . ./util_functions.sh",
        "else",
        "    SYSTEM_ROOT=false",
        "    SYSTEM_AS_ROOT=false",
        "    grep ' / ' /proc/mounts | grep -qv 'rootfs' && SYSTEM_ROOT=true",
        "    grep ' / ' /proc/mounts | grep -qv 'rootfs' && SYSTEM_AS_ROOT=true",
        "    . ./util_functions.sh",
        "    mount_partitions >/dev/null",
        "    get_flags",
        "fi",
        "echo -------------------------",
        'echo "SLOT:              $SLOT"',
        'echo "SYSTEM_AS_ROOT:    $SYSTEM_AS_ROOT"',
        'echo "PATCHVBMETAFLAG:   $PATCHVBMETAFLAG"',
        'echo "LEGACYSAR:         $LEGACYSAR"',
        'echo "RECOVERYMODE:      $RECOVERYMODE"',
        'echo "KEEPVERITY:        $KEEPVERITY"',
        'echo "KEEPFORCEENCRYPT:  $KEEPFORCEENCRYPT"',
        "export SLOT SYSTEM_AS_ROOT PATCHVBMETAFLAG LEGACYSAR RECOVERYMODE KEEPVERITY KEEPFORCEENCRYPT",
        "echo -------------------------",
        'echo "Creating a patch ..."',
        "./magiskboot cleanup",
        f"./boot_patch.sh {_q(boot_path)}",
        "PATCH_SHA1=$(./magiskboot sha1 new-boot.img | cut -c-8)",
        'echo "PATCH_SHA1:     $PATCH_SHA1"',
        f"PATCH_FILENAME={patch_name}_${{MAGISK_VERSION}}_${{STOCK_SHA1}}_${{PATCH_SHA1}}.img",
        'echo "PATCH_FILENAME: $PATCH_FILENAME"',
        f"cp -f {work_base}/assets/new-boot.img {_q(out_dir)}/${{PATCH_FILENAME}}",
        "# Backup stock boot for Magisk restore",
        f"if [ -d /data/adb/magisk ]; then cp -f {_q(boot_path)} /data/adb/magisk/stock_boot.img; fi",
        f"if [[ -s {_q(out_dir)}/${{PATCH_FILENAME}} ]]; then",
        "    echo $PATCH_FILENAME > /data/local/tmp/pf_patch.log",
        '    if [[ -n "$PATCHING_MAGISK_VERSION" ]]; then echo $PATCHING_MAGISK_VERSION >> /data/local/tmp/pf_patch.log; fi',
        f"    ./magiskboot sha1 {out_dir}/${{PATCH_FILENAME}} | cut -c-8 >> /data/local/tmp/pf_patch.log",
        "else",
        '    echo "ERROR: Patching failed!"',
        "fi",
        'echo "Cleaning up ..."',
        f"rm -f /data/local/tmp/pf_patch.sh {zip_name}",
        f"rm -rf {_q(work_base)}",
        "",
    ])
    return "\n".join(lines)


def generate_ksu_script(
    boot_path: str,
    work_dir: str,
    zip_path: str,
    out_dir: str,
    arch: str,
    stock_sha1: str,
    version_code: str = "",
    kmi_override: str | None = None,
    mount_type: str | None = None,
    method: str = "KernelSU",
) -> str:
    """Return the contents of a KernelSU-family ``pf_patch.sh`` script.

    Covers KernelSU, KernelSU-Next, SukiSU, and Wild_KSU.  Ported from
    ``pf_modules.py:3240-3310``.
    """
    if arch not in KNOWN_ANDROID_ABIS:
        arch = "arm64-v8a"
    version_code = version_code or "0"
    stock_sha1 = stock_sha1 or ""
    patch_name = "kernelsu_patched"
    work_base = work_dir.rstrip("/")
    zip_name = os.path.basename(zip_path)

    # SukiSU < 4.0.0 used zakozako/zakoboot.
    try:
        version_int = int(version_code)
    except ValueError:
        version_int = 0

    if method == "SukiSU" and version_int < 40000:
        ksud_mount = "zakozako"
        magiskboot = "zakoboot"
    else:
        ksud_mount = "ksud"
        magiskboot = "magiskboot"

    # Optional mount-type binary selection (KSU-Next / Wild_KSU).
    if mount_type in ("magicmount", "overlayfs") and ksud_mount == "ksud":
        ksud_mount = f"ksud_{mount_type}"

    kmi_arg = ""
    if kmi_override:
        kmi_arg = f" --kmi {_q(kmi_override)}"

    lines: list[str] = [
        " #!/system/bin/sh",
        " ##############################################################################",
        f" # PixelFlasher {method} patch script",
        " ##############################################################################",
        f'KSU_VERSION="{version_code}"',
        f"STOCK_SHA1={_q(stock_sha1)}",
        f"ARCH={_q(arch)}",
        "cd /data/local/tmp",
        "rm -f /data/local/tmp/pf_patch.log",
        f"rm -rf {_q(work_base)} || {{ echo 'ERROR: Failed to remove directory {work_base}'; exit 1; }}",
        f"mkdir {_q(work_base)} || {{ echo 'ERROR: Failed to create directory {work_base}'; exit 1; }}",
        f"cd {_q(work_base)}",
        f"../busybox unzip -o ../{zip_name}",
        "cd assets",
        "for FILE in ../lib/$ARCH/lib*.so; do",
        r"    NEWNAME=$(echo $FILE | sed -En 's/.*/lib(.*)\.so/\1/p')",
        '    echo "Copying [$FILE] to [$NEWNAME]"',
        "    cp $FILE $NEWNAME",
        "done",
        "chmod 755 *",
        f"PATCHING_KSU_VERSION=$({work_base}/assets/{ksud_mount} -V)",
        'echo "PATCHING_KSU_VERSION: $PATCHING_KSU_VERSION"',
        "echo -------------------------",
        'echo "Creating a patch ..."',
        "rm -f kernelsu_boot_* kernelsu_patched_*",
        "NEWEST_FILE1=$(ls -t | head -n 1)",
        f"./{ksud_mount} boot-patch -b {_q(boot_path)} --magiskboot {magiskboot}{kmi_arg} | tee temp_file",
        f"OUTPUT_FILE=$(grep -o '{work_base}/assets/[^ ]*' \"temp_file\" | tail -n 1 | xargs basename)",
        'echo "OUTPUT_FILE: [${OUTPUT_FILE}]"',
        "rm -f temp_file",
        "NEWEST_FILE2=$(ls -t | head -n 1)",
        'if [ "${NEWEST_FILE1}" = "${NEWEST_FILE2}" ] || [ "${OUTPUT_FILE}" != "${NEWEST_FILE2}" ]; then',
        '    echo "ERROR: No new file is created. Patching failed!"',
        '    echo "       NEWEST_FILE:    [${NEWEST_FILE2}]"',
        "else",
        '    echo "Found ${NEWEST_FILE2} continuing ..."',
        f"    PATCH_SHA1=$(./{magiskboot} sha1 ${{NEWEST_FILE2}} | cut -c-8)",
        '    echo "PATCH_SHA1:     $PATCH_SHA1"',
        f"    PATCH_FILENAME={patch_name}_${{KSU_VERSION}}_${{STOCK_SHA1}}_${{PATCH_SHA1}}.img",
        '    echo "PATCH_FILENAME: $PATCH_FILENAME"',
        '    if [ -f "${NEWEST_FILE2}" ]; then',
        f"        cp \"${{NEWEST_FILE2}}\" \"{out_dir}/${{PATCH_FILENAME}}\"",
        "    fi",
        f"    if [[ -s \"{out_dir}/${{PATCH_FILENAME}}\" ]]; then",
        "        echo $PATCH_FILENAME > /data/local/tmp/pf_patch.log",
        '        if [[ -n "$PATCHING_KSU_VERSION" ]]; then echo "$PATCHING_KSU_VERSION" >> /data/local/tmp/pf_patch.log; fi',
        f"        ./{magiskboot} sha1 \"{out_dir}/${{PATCH_FILENAME}}\" | cut -c-8 >> /data/local/tmp/pf_patch.log",
        "    else",
        '        echo "ERROR: Patching failed!"',
        "    fi",
        "fi",
        'echo "Cleaning up ..."',
        f"rm -f /data/local/tmp/pf_patch.sh {zip_name}",
        f"rm -rf {_q(work_base)}",
        "",
    ]
    return "\n".join(lines)


def generate_apatch_script(
    boot_path: str,
    work_dir: str,
    zip_path: str,
    out_dir: str,
    arch: str,
    stock_sha1: str,
    superkey: str,
    version_code: str = "",
) -> str:
    """Return the contents of an APatch ``pf_patch.sh`` script.

    The superkey is exported as an environment variable and passed to
    ``boot_patch.sh`` by sourcing it with positional parameters set, so the
    key never appears in an ``adb shell ps`` command line.

    Ported from ``pf_modules.py:3452-3546``.
    """
    if arch not in KNOWN_ANDROID_ABIS:
        arch = "arm64-v8a"
    version_code = version_code or "0"
    stock_sha1 = stock_sha1 or ""
    patch_name = "apatch_patched"
    work_base = work_dir.rstrip("/")
    zip_name = os.path.basename(zip_path)

    lines: list[str] = [
        " #!/system/bin/sh",
        " ##############################################################################",
        " # PixelFlasher APatch patch script",
        " ##############################################################################",
        f'APATCH_VERSION="{version_code}"',
        f"STOCK_SHA1={_q(stock_sha1)}",
        f"ARCH={_q(arch)}",
        "cd /data/local/tmp",
        "rm -f /data/local/tmp/pf_patch.log",
        f"rm -rf {_q(work_base)} || {{ echo 'ERROR: Failed to remove directory {work_base}'; exit 1; }}",
        f"mkdir {_q(work_base)} || {{ echo 'ERROR: Failed to create directory {work_base}'; exit 1; }}",
        f"cd {_q(work_base)}",
        f"../busybox unzip -o ../{zip_name}",
        "cd assets",
        "for FILE in ../lib/$ARCH/lib*.so; do",
        r"    NEWNAME=$(echo $FILE | sed -En 's/.*/lib(.*)\.so/\1/p')",
        '    echo "Copying [$FILE] to [$NEWNAME]"',
        "    cp $FILE $NEWNAME",
        "done",
        "chmod 755 *",
        f"PATCHING_APATCH_VERSION=$({work_base}/assets/apd -V)",
        'echo "PATCHING_APATCH_VERSION: $PATCHING_APATCH_VERSION"',
        'echo "Creating a patch ..."',
        f"export APATCH_SUPERKEY={_q(superkey)}",
        f"set -- \"$APATCH_SUPERKEY\" {_q(boot_path)} -K kpatch",
        ". ./boot_patch.sh",
        "PATCH_SHA1=$(./magiskboot sha1 new-boot.img | cut -c-8)",
        'echo "PATCH_SHA1:     $PATCH_SHA1"',
        f"PATCH_FILENAME={patch_name}_${{APATCH_VERSION}}_${{STOCK_SHA1}}_${{PATCH_SHA1}}.img",
        'echo "PATCH_FILENAME: $PATCH_FILENAME"',
        f"cp -f {work_base}/assets/new-boot.img {_q(out_dir)}/${{PATCH_FILENAME}}",
        f"if [[ -s {_q(out_dir)}/${{PATCH_FILENAME}} ]]; then",
        "    echo $PATCH_FILENAME > /data/local/tmp/pf_patch.log",
        '    if [[ -n "$PATCHING_APATCH_VERSION" ]]; then echo $PATCHING_APATCH_VERSION >> /data/local/tmp/pf_patch.log; fi',
        f"    ./magiskboot sha1 {out_dir}/${{PATCH_FILENAME}} | cut -c-8 >> /data/local/tmp/pf_patch.log",
        "else",
        '    echo "ERROR: Patching failed!"',
        "fi",
        'echo "Cleaning up ..."',
        f"rm -f /data/local/tmp/pf_patch.sh {zip_name}",
        f"rm -rf {_q(work_base)}",
        "",
    ]
    return "\n".join(lines)


def parse_patch_log(log_content: str) -> dict[str, str | None]:
    """Parse ``/data/local/tmp/pf_patch.log`` into filename/version/sha1.

    The log is written by the generated scripts as up to three lines:
    ``<patched_filename>``, ``<version>``, ``<patch_sha1>``.
    """
    lines = [line.strip() for line in (log_content or "").splitlines() if line.strip()]
    return {
        "patched_filename": lines[0] if len(lines) > 0 else None,
        "version": lines[1] if len(lines) > 1 else None,
        "patch_sha1": lines[2] if len(lines) > 2 else None,
    }

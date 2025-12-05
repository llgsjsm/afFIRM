import os, sys

def _infer_device_suggestion(dest_dir: str, kernel_filename: str, model_for_desc: str):
    """
    Build a row for files/emux/devices:
    ID,qemu-binary,machine-type,cpu-type,dtb,memory,kernel-image,qemuopts,description
    Fills qemuopts using your EMUX presets.
    """
    # Defaults
    qemu_binary  = ""
    machine_type = ""
    cpu_type     = ""
    dtb          = ""
    memory       = "256M"
    kernel_image = kernel_filename  # already copied into dest/kernel
    qemuopts     = ""
    description  = f"{model_for_desc}"

    # --- Infer arch/machine from kernel filename pattern ---
    k = kernel_filename.lower()

    # MIPS Malta (big/little endian)
    if "malta" in k:
        qemu_binary = "qemu-system-mips"
        machine_type = "malta"
        if "-le" in k or "little" in k:
            cpu_type = ""  # let kernel select; or set "mips32r2" if you prefer
            qemuopts = "MALTA3"  # your preset for little-endian
        else:
            cpu_type = ""
            qemuopts = "MALTA2"  # your preset for big-endian

    # ARM VersatilePB (ARMv5)
    elif "versatile" in k:
        qemu_binary  = "qemu-system-arm"
        machine_type = "versatilepb"
        cpu_type     = ""       # often left blank
        qemuopts     = "VERSATILEPB"

    # ARM Realview-EB (ARMv6)
    elif "realview" in k or "realview-eb" in k:
        qemu_binary  = "qemu-system-arm"
        machine_type = "realview-eb"
        cpu_type     = ""       # often left blank
        qemuopts     = "REALVIEW-EB"

    # ARM vexpress (ARMv7)
    elif "vexpress" in k:
        qemu_binary  = "qemu-system-arm"
        machine_type = "vexpress-a9"
        cpu_type     = ""       # usually blank; kernel selects
        # Choose between your two presets; simple heuristic by version/name:
        # you can tweak this to your house rules.
        qemuopts     = "VEXPRESS1"  # default
        if "-a15" in k:
            machine_type = "vexpress-a15"
            qemuopts     = "VEXPRESS2"

    # AArch64 generic virt (if you add aarch64 kernels later)
    elif k.endswith(".img") and ("aarch64" in k or "arm64" in k or "virt" in k):
        qemu_binary  = "qemu-system-aarch64"
        machine_type = "virt"
        cpu_type     = ""
        qemuopts     = "VIRTARM64"

    # Fallbacks (leave qemuopts empty if we truly don't know)
    if not qemu_binary:
        # Guess by prefix
        if kernel_filename.startswith("zImage"):
            qemu_binary = "qemu-system-arm"
            machine_type = "vexpress-a9"
            qemuopts = "VEXPRESS1"
        elif kernel_filename.startswith("vmlinux"):
            if "malta" in k:
                qemu_binary = "qemu-system-mips"
                machine_type = "malta"
                qemuopts = "MALTA3" if "-le" in k else "MALTA2"

    # Compose CSV row
    # ID is relative to files/emux: firmware/<folder>
    device_id = f"firmware/{os.path.basename(dest_dir)}"
    row = f"{device_id},{qemu_binary},{machine_type},{cpu_type},{dtb},{memory},{kernel_image},{qemuopts},{description}"
    return row

import os, re, sys

# ---- scratch utils & log analysis helpers ----
def _numeric_dirs(path: str):
    try:
        return sorted(int(d) for d in os.listdir(path) if d.isdigit())
    except Exception:
        return []

def _latest_iid_dir(scratch_root: str):
    ids = _numeric_dirs(scratch_root)
    return os.path.join(scratch_root, str(ids[-1])) if ids else None

def _safe_tail(path: str, max_bytes: int = 64_000, max_lines: int = 200) -> str:
    """
    Return up to max_lines from the end of the file (bounded by max_bytes).
    Gracefully handles non-existent files.
    """
    if not os.path.exists(path):
        return ""
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            if size > max_bytes:
                f.seek(-max_bytes, os.SEEK_END)
            data = f.read()
        text = data.decode("utf-8", "replace")
        lines = text.splitlines()[-max_lines:]
        return "\n".join(lines)
    except Exception as e:
        return f"[could not read {path}: {e}]"

# Heuristic pattern detector: returns list of human-readable reasons
def _analyze_logs(text_by_name: dict[str, str]) -> list[str]:
    reasons = []
    combined = "\n".join(v for v in text_by_name.values() if v)

    PATTERNS = [
        ("Filesystem image build error",
         r"(mke2fs|e2fsck).*(error|aborted|unable|fail)|No such file or directory.*(root|image)|mount:.*failed", re.I),
        ("Architecture / binfmt issue",
         r"(Unknown architecture|binfmt_misc|Exec format error|qemu-.*: Could not open|get architecture.*fail)", re.I),
        ("QEMU boot/kernel failure",
         r"(Kernel panic|Unable to mount root|Segmentation fault|qemu: .*error|end Kernel panic)", re.I),
        ("Network bridging/tap error",
         r"(tap|bridge|br_add_if|br_dev_ioctl|SIOCSIF).* (fail|error|denied)|Network unreachable", re.I),
        ("Permission / capability problem",
         r"(Permission denied|Operation not permitted|cap_net_admin)", re.I),
        ("Timeout / watchdog",
         r"\b(timeout|timed out)\b", re.I),
        ("Web service did not come up",
         r"(Web service on .* (down|failed)|httpd.*fail|lighttpd.*fail|nginx.*fail)", re.I),
    ]

    for title, pat, flags in PATTERNS:
        if re.search(pat, combined, flags):
            reasons.append(title)

    # Special: if makeNetwork.log shows IP but no web, hint firewall/service init
    mk = text_by_name.get("makeNetwork.log", "")
    if mk and re.search(r"Network reachable on \d+\.\d+\.\d+\.\d+", mk) and \
       not re.search(r"Web service on .*", combined):
        reasons.append("Network reachable but web service not detected")

    return sorted(set(reasons))

def _collect_failure_context(scratch_root: str) -> tuple[str | None, dict[str, str]]:
    """
    Returns (iid_dir, texts) where texts maps log name -> tail text.
    Picks the newest numeric scratch/<iid>.
    """
    iid_dir = _latest_iid_dir(scratch_root)
    logs = {}
    if iid_dir:
        for fname in ("makeImage.log", "makeNetwork.log", "qemu.final.serial.log", "emulation.log"):
            fpath = os.path.join(iid_dir, fname)
            logs[fname] = _safe_tail(fpath)
    return iid_dir, logs

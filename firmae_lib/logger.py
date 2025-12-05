import os, csv

def _to_bool_str(val: bool) -> str:
    return "true" if bool(val) else "false"

def _safe_read(path: str) -> str:
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return f.read().strip()
    except Exception:
        pass
    return ""

def _parse_bool(s: str):
    """
    Convert common truthy/falsey strings to bool.
    Returns True/False, or None if indeterminate/empty.
    """
    if s is None:
        return None
    s = s.strip().lower()
    if not s:
        return None

    # BOOLEAN PARSE LOGIC - look for these values
    # Adjust where necessary
    truthy = {"1", "true", "yes", "y", "ok", "success", "on", "reachable", "up"}
    falsy  = {"0", "false", "no", "n", "fail", "failed", "off", "unreachable", "down"}
    
    if s in truthy:
        return True
    if s in falsy:
        return False
        
    # Try numeric fallback
    try:
        return float(s) != 0.0
    except Exception:
        return None

def _next_record_number(csv_path: str) -> int:
    """
    Reads the last data row’s number if file exists; else 1.
    """
    if not os.path.exists(csv_path):
        return 1
    last_num = 0
    try:
        with open(csv_path, "r", encoding="utf-8") as f:
            rows = [ln.strip() for ln in f if ln.strip()]
        if len(rows) >= 2:
            first_col = rows[-1].split(",")[0]
            last_num = int(first_col)
            return last_num + 1
    except Exception:
        try:
            with open(csv_path, "r", encoding="utf-8") as f:
                count = sum(1 for _ in f) - 1
            return max(1, count + 1)
        except Exception:
            return 1
    return last_num + 1

def append_emulation_record(
    firmae_home: str,
    fw_path: str,
    brand: str,
    exit_code: int,
) -> dict:
    """
    Append one emulation result row into <FIRMAE_HOME>/emulation_records.csv.
    Columns: number, firmware_name, architecture, brand, ping, web, result
    Values are read from latest scratch/<iid>/ files:
      - name          -> firmware_name (fallback: basename of fw_path without extension)
      - architecture  -> architecture (fallback: "")
      - brand         -> brand (fallback: function arg `brand`)
      - ping          -> boolean via file 'ping' (fallback: false if missing/indeterminate)
      - web           -> boolean via file 'web'  (fallback: false if missing/indeterminate)
      - result        -> boolean via file 'result' (fallback: exit_code == 0)
    """
    scratch_root = os.path.join(firmae_home, "scratch")
    csv_path = os.path.join(firmae_home, "emulation_records.csv")

    # Latest numeric scratch iid
    latest_dir = None
    try:
        if os.path.exists(scratch_root):
            nums = [int(d) for d in os.listdir(scratch_root) if d.isdigit()]
            if nums:
                latest_dir = os.path.join(scratch_root, str(max(nums)))
    except Exception:
        latest_dir = None

    firmware_name = os.path.splitext(os.path.basename(fw_path))[0]
    architecture = ""
    brand_val = brand or ""
    ping_bool = False
    web_bool = False
    result_bool = (exit_code == 0)  # default fallback

    if latest_dir:
        name_file = _safe_read(os.path.join(latest_dir, "name"))
        if name_file:
            firmware_name = name_file

        architecture_file = _safe_read(os.path.join(latest_dir, "architecture"))
        if architecture_file:
            architecture = architecture_file

        brand_file = _safe_read(os.path.join(latest_dir, "brand"))
        if brand_file:
            brand_val = brand_file

        # Boolean flags from files
        ping_file = _parse_bool(_safe_read(os.path.join(latest_dir, "ping")))
        if ping_file is not None:
            ping_bool = ping_file
        else:
            ping_bool = False

        web_file = _parse_bool(_safe_read(os.path.join(latest_dir, "web")))
        if web_file is not None:
            web_bool = web_file
        else:
            web_bool = False

        result_file = _parse_bool(_safe_read(os.path.join(latest_dir, "result")))
        if result_file is not None:
            result_bool = result_file
        # else keep fallback from exit_code

    header = ["number", "firmware_name", "architecture", "brand", "ping", "web", "result"]
    row = {
        "number": _next_record_number(csv_path),
        "firmware_name": firmware_name,
        "architecture": architecture,
        "brand": brand_val,
        "ping": _to_bool_str(ping_bool),
        "web": _to_bool_str(web_bool),
        "result": _to_bool_str(result_bool),
    }

    try:
        write_header = not os.path.exists(csv_path)
        with open(csv_path, "a", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=header)
            if write_header:
                writer.writeheader()
            writer.writerow(row)
    except Exception:
        pass

    return row

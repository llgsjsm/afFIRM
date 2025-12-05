#!/usr/bin/env python3
import os, sys, json, shlex, subprocess, time, re, threading
from firmae_lib.tools import list_tools
from firmae_lib.logger import append_emulation_record
from firmae_lib.help import _load_help_md
from firmae_lib.analysis import _numeric_dirs, _latest_iid_dir, _safe_tail, _analyze_logs, _collect_failure_context
from firmae_lib.sqlite_helper import kb_insert_run, kb_insert_analysis
from emux_lib.tar_helper import _find_rootfs_dir, _make_rootfs_tar_bz2
from emux_lib.emux_detect import _infer_device_suggestion

SUPPORTED = {"2025-03-26", "2024-11-05"}
WRITE_LOCK = threading.Lock()
KB_DB_PATH  = os.path.join(os.path.dirname(os.path.abspath(__file__)), "firmae_kb.sqlite")

def jwrite(obj):
    with WRITE_LOCK:
        sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")
        sys.stdout.flush()

def choose_version(req):
    if req in SUPPORTED:
        return req
    return sorted(SUPPORTED)[-1]

def expand_home(path: str) -> str:
    return os.path.expanduser(path) if path else path

# default to /home/ubuntu-server/FirmAE
FIRMAE_HOME = expand_home(os.environ.get("FIRMAE_HOME", "/home/ubuntu-server/FirmAE"))

def safe_cwd():
    try:
        os.chdir(FIRMAE_HOME)
    except Exception:
        pass

safe_cwd()

def run_cmd(cmd: str, args: list[str] | None, timeout_sec: int | None):
    """
    Execute within FIRMAE_HOME. Returns (exit_code, stdout, stderr, duration).
    Always returns stdout/stderr as str (never bytes).
    """
    safe_cwd()
    args = args or []
    full = cmd if not args else cmd + " " + " ".join(shlex.quote(str(a)) for a in args)

    start = time.time()
    ANSI_ESCAPE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

    def _to_str(x):
        if x is None:
            return ""
        if isinstance(x, bytes):
            return x.decode("utf-8", "replace")
        return x

    def _strip_ansi(x: str) -> str:
        try:
            return ANSI_ESCAPE.sub("", x)
        except Exception:
            return x

    try:
        proc = subprocess.run(
            full,
            shell=True,
            cwd=FIRMAE_HOME,
            capture_output=True,
            text=True,              # request text, but we'll still normalize defensively
            timeout=timeout_sec
        )
        dur = time.time() - start

        out = _strip_ansi(_to_str(proc.stdout))
        err = _strip_ansi(_to_str(proc.stderr))
        return proc.returncode, out, err, dur

    except subprocess.TimeoutExpired as e:
        dur = time.time() - start
        out = _strip_ansi(_to_str(getattr(e, "stdout", "")))
        err = _strip_ansi(_to_str(getattr(e, "stderr", ""))) + "\n[timeout]"
        return 124, out, err, dur

    except FileNotFoundError as e:
        dur = time.time() - start
        return 127, "", f"[error] {e}", dur

    except Exception as e:
        dur = time.time() - start
        # Surface the actual exception text in stderr for diagnostics
        return 1, "", f"[error] {e}", dur

def handle_call(params):
    name = params.get("name")
    arguments = params.get("arguments") or {}
    emulate_ctx = None

    # firmae.help
    if name == "firmae.help":
        guide = _load_help_md(FIRMAE_HOME)
        return {"content": [{"type": "text", "text": guide}], "isError": False}
    # firmae.emulate
    elif name == "firmae.emulate":
        brand = arguments.get("brand")
        fw = arguments.get("firmware_file")
        timeout = arguments.get("timeout") or 1800
        if not brand or not fw:
            return {
                "content": [{"type": "text", "text": "Missing brand or firmware_file"}],
                "isError": True
            }

        fw_path = expand_home(fw)
        if not os.path.isabs(fw_path):
            fw_path = os.path.join(FIRMAE_HOME, fw_path)
        if not os.path.exists(fw_path):
            return {
                "content": [{"type": "text", "text": f"Firmware file not found: {fw_path}"}],
                "isError": True
            }

        cmd = "./run.sh"
        args = ["-c", brand, fw_path]
        emulate_ctx = {"fw_path": fw_path, "brand": brand}
        scratch_root = os.path.join(FIRMAE_HOME, "scratch")

        rc, out, err, dur = run_cmd(cmd, args, timeout)
        result_truth = None  # set this if you have logic to read scratch/<iid>/result (true/false)
        is_error = (result_truth is False) if (result_truth is not None) else (rc != 0)

        csv_note = ""
        try:
            row = append_emulation_record(
                firmae_home=FIRMAE_HOME,
                fw_path=fw_path,
                brand=brand,
                exit_code=rc,
            )
            csv_note = "\n[+] Emulation record appended to emulation_records.csv"
        except Exception as e:
            csv_note = f"\n[!] Failed to append emulation record: {e}"

        # If failed, analyze logs
        iid_dir = None
        reasons = []
        analysis_block = ""
        texts = {}
        if is_error:
            iid_dir, texts = _collect_failure_context(scratch_root)
            have_any_logs = any(texts.get(k) for k in ("makeImage.log", "makeNetwork.log", "qemu.final.serial.log", "emulation.log"))
            if not iid_dir or not have_any_logs:
                analysis_block = "\n[analysis] Emulation appears to have failed before logs were produced in scratch/."
            else:
                reasons = _analyze_logs(texts)
                if reasons:
                    analysis_block = "**Failure analysis (heuristics):**\n" + "".join(f"- {r}\n" for r in reasons)
                else:
                    analysis_block = "**Failure analysis:**\n- No specific signature matched; review logs below."

                parts = [analysis_block]
                for name in ("makeImage.log", "makeNetwork.log", "qemu.final.serial.log", "emulation.log"):
                    content_tail = texts.get(name, "")
                    if content_tail:
                        parts.append(f"\n--- {name} (tail) ---\n{content_tail}")
                analysis_block = "\n".join(parts)

        # Build final output
        lines = []
        if out:
            lines.append(out)
        if err:
            lines.append(f"[stderr]\n{err}")
        if analysis_block:
            lines.append(analysis_block)
        lines.append(f"[exit={rc}] [duration={dur:.2f}s] [cwd={FIRMAE_HOME}]{csv_note}")

        # --- Persist run + analysis to SQLite KB ---
        try:
            db_path = KB_DB_PATH
            firmware_name = os.path.basename(fw_path)
            model_guess = None  # derive if you want

            run_id = kb_insert_run(
                db_path,
                brand=brand,
                model=model_guess,
                firmware=firmware_name,
                iid_dir=iid_dir if is_error else None,
                exit_code=rc,
                result_bool=(False if is_error else True) if result_truth is None else bool(result_truth),
                duration_sec=dur,
            )

            reasons_payload = {"reasons": reasons or []} if is_error else None
            kb_insert_analysis(
                db_path,
                run_id=run_id,
                source=("heuristic" if is_error else "summary"),
                summary=("Emulation failure analysis" if is_error else "Emulation summary"),
                content=(analysis_block or (out.strip()[:2000] if out else "[no analysis text]")),
                reasons_json=reasons_payload
            )
        except Exception as e:
            lines.append(f"\n[KB] Failed to persist analysis: {e}")

        return {
            "content": [{"type": "text", "text": "\n".join(lines)}],
            "isError": is_error
        }
    # firmae.clean — remove folders inside scratch/
    elif name == "firmae.clean":
        scratch_dir = os.path.join(FIRMAE_HOME, "scratch")
        if not os.path.exists(scratch_dir):
            return {
                "content": [{"type": "text", "text": f"Scratch folder not found: {scratch_dir}"}],
                "isError": True
            }

        removed = 0
        for entry in os.listdir(scratch_dir):
            full_path = os.path.join(scratch_dir, entry)
            try:
                if os.path.isdir(full_path):
                    import shutil
                    shutil.rmtree(full_path)
                    removed += 1
                else:
                    os.remove(full_path)
                    removed += 1
            except Exception as e:
                return {
                    "content": [{"type": "text", "text": f"Error removing {entry}: {e}"}],
                    "isError": True
                }

        return {
            "content": [{"type": "text", "text": f"Cleared {removed} items from {scratch_dir}."}],
            "isError": False
        }
    # firmae.search — list or download firmware for a given brand and model
    elif name == "firmae.search":
        import requests, re
        from bs4 import BeautifulSoup

        brand = arguments.get("brand", "").strip().lower()
        model = arguments.get("model", "").strip().lower()
        do_download = arguments.get("download", False)
        selection_index = (
            arguments.get("selection_index")
            or arguments.get("index")
        )

        if not brand or not model:
            return {
                "content": [{"type": "text", "text": "Missing brand or model. Example: brand=TPLINK, model=tl-wr841n"}],
                "isError": True
            }

        headers = {"User-Agent": "Mozilla/5.0"}
        firmware_links = []

        # TP-Link firmware search
        if brand in ["tplink", "tp-link", "tp link"]:
            model_slug = model.replace(" ", "-").lower()
            base_url = f"https://www.tp-link.com/us/support/download/{model_slug}/"
            firmware_url = base_url + "#Firmware"  # purely for reference / debugging

            try:
                res = requests.get(base_url, headers=headers, timeout=25)
                res.raise_for_status()
            except Exception as e:
                return {
                    "content": [{"type": "text", "text": f"Failed to fetch page for {model.upper()}: {e}\nURL: {base_url}"}],
                    "isError": True
                }

            soup = BeautifulSoup(res.text, "html.parser")

            # Find only the Firmware section
            firmware_section = soup.find("div", id="Firmware")
            if not firmware_section:
                firmware_section = soup.find("div", id=re.compile("firmware", re.IGNORECASE))

            if not firmware_section:
                return {
                    "content": [{"type": "text", "text": f"No Firmware section found for {model.upper()} at {base_url}"}],
                    "isError": False
                }

            for a in firmware_section.find_all("a", href=True):
                href = a["href"]
                if re.search(r"\.(zip|bin|tar\.gz)$", href, re.IGNORECASE):
                    full_url = href if href.startswith("http") else f"https://www.tp-link.com{href}"
                    filename = os.path.basename(href.split("?")[0])
                    
                    title = filename or "Unknown Firmware"
                    firmware_links.append(title + "|" + full_url)

            if not firmware_links:
                return {
                    "content": [{"type": "text", "text": f"No firmware download links found for {model.upper()}."}],
                    "isError": False
                }

            # List results
            if not do_download:
                listing = "\n".join(
                    f"{i+1}. {f.split('|')[0]}\n   {f.split('|')[1]}"
                    for i, f in enumerate(firmware_links)
                )
                msg = (
                    f"Found {len(firmware_links)} firmware file(s) for {model.upper()}:\n\n{listing}\n\n"
                    f"To download, call again with download=true and selection_index=<number>."
                )
                return {"content": [{"type": "text", "text": msg}], "isError": False}

            # Download selected file
            if not selection_index or not (1 <= selection_index <= len(firmware_links)):
                return {
                    "content": [{"type": "text", "text": "Invalid or missing selection_index for download."}],
                    "isError": True
                }

            selected = firmware_links[selection_index - 1]
            name, url = selected.split("|")
            filename = os.path.basename(url.split("?")[0])
            filename = filename.replace(" ", "_")
            firmware_dir = os.path.join(FIRMAE_HOME, "firmware")
            os.makedirs(firmware_dir, exist_ok=True)
            save_path = os.path.join(firmware_dir, filename)

            try:
                r = requests.get(url, headers=headers, timeout=90)
                r.raise_for_status()
                with open(save_path, "wb") as f:
                    f.write(r.content)
                msg = f"Downloaded {filename} to {save_path}"
            except Exception as e:
                msg = f"Failed to download {filename}: {e}"
                return {"content": [{"type": "text", "text": msg}], "isError": True}

            return {"content": [{"type": "text", "text": msg}], "isError": False}
    # firmae.lookupKB — checks against tplink-kb
    elif name == "firmae.lookupKB":
        kb_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "kb", "tplink-kb")
        if not os.path.exists(kb_path):
            return {
                "content": [{"type": "text", "text": f"Knowledge base file not found: {kb_path}"}],
                "isError": True
            }

        try:
            with open(kb_path, "r", encoding="utf-8") as f:
                lines = [line.strip() for line in f if line.strip()]
        except Exception as e:
            return {
                "content": [{"type": "text", "text": f"Error reading tplink-kb: {e}"}],
                "isError": True
            }

        if not lines:
            return {
                "content": [{"type": "text", "text": "No models found in tplink-kb."}],
                "isError": False
            }

        listing = "\n".join(f"{i+1}. {line}" for i, line in enumerate(lines))
        msg = (
            "**TP-Link Knowledge Base — Available Models**\n\n"
            f"{listing}\n\n"
            "You can search for firmware using:\n"
            "→ `brand: TPLINK, model: <ModelName>`\n\n"
            "Example:\n"
            "`brand: TPLINK, model: Archer AX73`\n"
        )

        return {"content": [{"type": "text", "text": msg}], "isError": False}
    # firmae.history — view past emulation records with filters
    elif name == "firmae.history":
        import csv, re

        brand_q = (arguments.get("brand") or "").strip()
        model_q = (arguments.get("model") or "").strip()
        success_only = bool(arguments.get("success_only") or False)
        last_n = int(arguments.get("last_n") or 20)

        def norm(s: str) -> str:
            return re.sub(r"[^a-z0-9]+", "", (s or "").lower())

        def contains_loose(hay: str, needle: str) -> bool:
            if not (needle or "").strip():
                return True
            return norm(needle) in norm(hay)

        csv_path = os.path.join(FIRMAE_HOME, "emulation_records.csv")
        if not os.path.exists(csv_path):
            return {
                "content": [{"type": "text", "text": f"No records yet. CSV not found at {csv_path}"}],
                "isError": False
            }

        rows = []
        try:
            with open(csv_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for r in reader:
                    rows.append(r)
        except Exception as e:
            return {
                "content": [{"type": "text", "text": f"Failed to read emulation_records.csv: {e}"}],
                "isError": True
            }

        # Sort newest first by numeric 'number'
        def num(r): 
            try: return int(r.get("number") or 0)
            except: return 0
        rows.sort(key=num, reverse=True)

        # Apply filters
        out = []
        for r in rows:
            if brand_q and norm(brand_q) != norm(r.get("brand") or ""):
                continue
            if model_q and not contains_loose(r.get("firmware_name") or "", model_q):
                continue
            if success_only:
                v = (r.get("result") or "").strip().lower()
                if v not in ("1","true","yes","ok","success","on","reachable","up"):
                    continue
            out.append(r)
            if len(out) >= last_n:
                break

        if not out:
            msg = "No matching emulation records."
            hints = []
            if brand_q: hints.append(f"brand={brand_q}")
            if model_q: hints.append(f"model~{model_q}")
            if success_only: hints.append("success_only=true")
            if hints: msg += " Filters: " + ", ".join(hints)
            return {"content": [{"type": "text", "text": msg}], "isError": False}

        # Pretty print
        def tick(v):
            v = (v or "").strip().lower()
            return "✓" if v in ("1","true","yes","ok","success","on","reachable","up") else "✗"

        lines = ["**Emulation History (most recent first)**"]
        for r in out:
            lines.append(
                f"- #{r.get('number','')} | {r.get('brand','')} | {r.get('firmware_name','')} "
                f"| arch={r.get('architecture','')} | ping={tick(r.get('ping'))} "
                f"web={tick(r.get('web'))} result={tick(r.get('result'))}"
            )

        # Tiny footer with how to refine
        lines.append(
            "\nFilters: brand=<DLINK|TPLINK> model=<substring> success_only=<true|false> last_n=<N>\n"
            "Example: brand=DLINK model=DIR-868L success_only=true last_n=10"
        )
        return {"content": [{"type": "text", "text": "\n".join(lines)}], "isError": False}
    # emux.emuxbuild — create emux firmware folder from template
    elif name == "emux.emuxbuild":
        import shutil, re, zipfile, glob, subprocess, tarfile

        EMUX_HOME = os.environ.get("EMUX_HOME", "/home/ubuntu-server/emux")

        firmware_model     = (arguments.get("firmware_model") or "").strip()
        firmware_image_arg = (arguments.get("firmware_image") or "").strip()
        kernel_choice      = (arguments.get("kernel_choice") or "").strip()   # filename under template/kernel
        kernel_path_arg    = (arguments.get("kernel_path") or "").strip()     # absolute/relative file path
        nvram_path_arg     = (arguments.get("nvram_path") or "").strip()      # optional

        # Validate required
        if not firmware_model:
            return {"content":[{"type":"text","text":"firmware_model is required (e.g., DIR-868L, Archer C7)."}], "isError": True}
        if not firmware_image_arg:
            return {"content":[{"type":"text","text":"firmware_image is required (path to .zip/.bin/etc)."}], "isError": True}

        # Helpers
        def safe_name(s: str) -> str:
            s = s.replace(" ", "_")
            return re.sub(r"[^A-Za-z0-9_\-\.]+", "", s)

        def _abs(p: str) -> str:
            if not p: return p
            p = os.path.expanduser(p)
            return p if os.path.isabs(p) else os.path.abspath(p)

        def _safe_extract_zip(zip_path: str, extract_to: str):
            with zipfile.ZipFile(zip_path, 'r') as zf:
                for member in zf.infolist():
                    # Prevent zip-slip
                    target = os.path.normpath(os.path.join(extract_to, member.filename))
                    base   = os.path.abspath(extract_to) + os.sep
                    if not (os.path.abspath(target).startswith(base) or os.path.abspath(target) == os.path.abspath(extract_to)):
                        raise RuntimeError(f"Unsafe path in zip: {member.filename}")
                zf.extractall(extract_to)

        # --- rootfs helpers (deep search + tar) ---
        def _find_rootfs_dir(extract_root: str) -> str | None:
            """
            Recursively search for likely rootfs directories under `extract_root`.
            Accept names: squashfs-root, cramfs-root, rootfs (case-insensitive).
            Prefer candidates that contain etc/ and bin/, are deeper, and larger.
            """
            candidates = []
            for r, dnames, _ in os.walk(extract_root):
                for dn in dnames:
                    dn_l = dn.lower()
                    if dn_l in ("squashfs-root", "cramfs-root", "rootfs"):
                        full = os.path.join(r, dn)
                        score = 0
                        if os.path.isdir(os.path.join(full, "etc")): score += 2
                        if os.path.isdir(os.path.join(full, "bin")): score += 1
                        depth = full.count(os.sep)
                        total_sz = 0
                        for rr, _, fns in os.walk(full):
                            for fn in fns:
                                fp = os.path.join(rr, fn)
                                try:
                                    total_sz += os.path.getsize(fp)
                                except Exception:
                                    pass
                        candidates.append((score, depth, total_sz, full))
            if not candidates:
                return None
            candidates.sort(key=lambda t: (-t[0], -t[1], -t[2]))
            return candidates[0][3]

        def _make_rootfs_tar_bz2(rootfs_dir: str, dest_tar_path: str) -> None:
            """Create bzip2 tarball with the CONTENTS of `rootfs_dir` at tar root."""
            os.makedirs(os.path.dirname(dest_tar_path), exist_ok=True)
            with tarfile.open(dest_tar_path, "w:bz2") as tf:
                # put contents at archive root:
                for item in os.listdir(rootfs_dir):
                    full = os.path.join(rootfs_dir, item)
                    tf.add(full, arcname=item)

        # Template paths
        template_dir = os.path.join(EMUX_HOME, "files", "emux", "template")
        template_kernel_dir = os.path.join(template_dir, "kernel")
        if not os.path.isdir(template_dir):
            return {"content":[{"type":"text","text":f"Template not found: {template_dir}"}], "isError": True}
        if not os.path.isdir(template_kernel_dir):
            return {"content":[{"type":"text","text":f"Template kernel dir not found: {template_kernel_dir}"}], "isError": True}

        # Kernel mandatory: if none supplied, list choices and exit nicely
        available_kernels = sorted(
            [f for f in os.listdir(template_kernel_dir)
            if os.path.isfile(os.path.join(template_kernel_dir, f))]
        )
        if not kernel_choice and not kernel_path_arg:
            listing = "\n".join(f"- {k}" for k in available_kernels) or "(no kernels found in template/kernel)"
            guide = (
                "**Kernel required**\n\n"
                "Pick ONE and call again with:\n"
                "  • `kernel_choice`: a filename from the list below\n"
                "  • OR `kernel_path`: an absolute path to your own kernel file\n\n"
                f"Available kernels:\n{listing}\n"
            )
            return {"content":[{"type":"text","text":guide}], "isError": False}

        # Validate kernel inputs (only one allowed)
        if kernel_choice and kernel_path_arg:
            return {"content":[{"type":"text","text":"Provide only one of: kernel_choice OR kernel_path."}], "isError": True}

        if kernel_choice:
            if kernel_choice not in available_kernels:
                return {"content":[{"type":"text","text":f"kernel_choice '{kernel_choice}' not found. Available: {', '.join(available_kernels) or '(none)'}"}], "isError": True}
            chosen_kernel_src = os.path.join(template_kernel_dir, kernel_choice)
        else:
            kp = _abs(kernel_path_arg)
            if not os.path.isfile(kp):
                return {"content":[{"type":"text","text":f"kernel_path not found or not a file: {kp}"}], "isError": True}
            chosen_kernel_src = kp

        # Determine destination firmware folder (never overwrite; add -2, -3, ...)
        model_dirname = safe_name(firmware_model)
        base_dest = os.path.join(EMUX_HOME, "files", "emux", "firmware", model_dirname)
        dest_dir = base_dest
        if os.path.exists(dest_dir):
            i = 2
            while True:
                candidate = f"{base_dest}-{i}"
                if not os.path.exists(candidate):
                    dest_dir = candidate
                    break
                i += 1

        # Copy template → destination
        try:
            os.makedirs(os.path.dirname(dest_dir), exist_ok=True)
            shutil.copytree(template_dir, dest_dir)
        except Exception as e:
            return {"content":[{"type":"text","text":f"Copy failed: {e}"}], "isError": True}

        # Patch config (file name is exactly 'config')
        cfg_path = os.path.join(dest_dir, "config")
        if not os.path.isfile(cfg_path):
            return {"content":[{"type":"text","text":f"Template copied, but 'config' not found in {dest_dir}"}], "isError": True}

        try:
            with open(cfg_path, "r", encoding="utf-8") as f:
                cfg_text = f.read()
        except Exception as e:
            return {"content":[{"type":"text","text":f"Failed to read {cfg_path}: {e}"}], "isError": True}

        # Set id=firmware/<foldername>
        new_id_line = f"id=firmware/{os.path.basename(dest_dir)}"
        id_re = re.compile(r'(?mi)^\s*id\s*=\s*.*$')
        if id_re.search(cfg_text):
            cfg_text = id_re.sub(new_id_line, cfg_text, count=1)
        else:
            if not cfg_text.endswith("\n"):
                cfg_text += "\n"
            cfg_text += new_id_line + "\n"

        # Handle nvram: set line if provided; else comment out any nvram= lines
        nvram_re = re.compile(r'(?mi)^\s*(#\s*)?nvram\s*=\s*.*$')
        if nvram_path_arg:
            nvram_abs = _abs(nvram_path_arg)
            if not os.path.exists(nvram_abs):
                return {"content":[{"type":"text","text":f"nvram_path does not exist: {nvram_abs}"}], "isError": True}
            new_nv_line = f"nvram={nvram_abs}"
            if nvram_re.search(cfg_text):
                cfg_text = nvram_re.sub(new_nv_line, cfg_text, count=1)
            else:
                if not cfg_text.endswith("\n"):
                    cfg_text += "\n"
                cfg_text += new_nv_line + "\n"
            nvram_note = f"nvram set to {nvram_abs}"
        else:
            def _comment_nv(m):
                line = m.group(0)
                return line if line.lstrip().startswith("#") else "# " + line
            cfg_text = nvram_re.sub(_comment_nv, cfg_text)
            nvram_note = "nvram line commented (no nvram_path provided)"

        try:
            with open(cfg_path, "w", encoding="utf-8") as f:
                f.write(cfg_text)
        except Exception as e:
            return {"content":[{"type":"text","text":f"Failed to write {cfg_path}: {e}"}], "isError": True}

        # Stage firmware image into dest
        fw_src = _abs(firmware_image_arg)
        if not os.path.exists(fw_src):
            return {"content":[{"type":"text","text":f"firmware_image not found: {fw_src}"}], "isError": True}
        try:
            os.makedirs(dest_dir, exist_ok=True)
            fw_dst = os.path.join(dest_dir, os.path.basename(fw_src))
            shutil.copy2(fw_src, fw_dst)
        except Exception as e:
            return {"content":[{"type":"text","text":f"Failed to copy firmware image: {e}"}], "isError": True}

        # If ZIP, safely extract into dest
        extracted_note = ""
        if fw_dst.lower().endswith(".zip"):
            try:
                _safe_extract_zip(fw_dst, dest_dir)
                extracted_note = f"Extracted ZIP into {dest_dir}"
            except Exception as e:
                return {"content":[{"type":"text","text":f"Copy OK, but ZIP extraction failed: {e}"}], "isError": True}

        # Find FW binaries to binwalk (-e). Look in dest_dir for common extensions.
        def _find_fw_bins(root: str):
            exts = ("*.bin", "*.img", "*.trx", "*.chk", "*.bin.enc", "*.bin.enc2")
            paths = []
            for pat in exts:
                paths.extend(glob.glob(os.path.join(root, pat)))
            return sorted(set(paths))

        fw_bins = _find_fw_bins(dest_dir)
        binwalk_runs = 0
        bw_errors = []
        for fwf in fw_bins:
            try:
                subprocess.run(["binwalk", "-e", fwf], cwd=dest_dir, check=True, capture_output=True, text=True)
                binwalk_runs += 1
            except Exception as e:
                bw_errors.append(f"{os.path.basename(fwf)}: {e}")

        # Look for rootfs under any *.extracted tree (and nested)
        extracted_dirs = glob.glob(os.path.join(dest_dir, "*.extracted"))
        search_roots = extracted_dirs[:]
        for ed in extracted_dirs:
            for sub_ed, _, _ in os.walk(ed):
                if sub_ed.endswith(".extracted") and sub_ed not in search_roots:
                    search_roots.append(sub_ed)

        rootfs_dir = None
        for root in [*search_roots, dest_dir]:
            rootfs_dir = _find_rootfs_dir(root)
            if rootfs_dir:
                break

        # Tar the rootfs directory into rootfs.tar.bz2 at dest_dir
        if rootfs_dir:
            tar_path = os.path.join(dest_dir, "rootfs.tar.bz2")
            try:
                _make_rootfs_tar_bz2(rootfs_dir, tar_path)
                tar_note = f"Packed rootfs from {rootfs_dir} -> {tar_path}"
            except Exception as e:
                return {"content":[{"type":"text","text":f"Found rootfs at {rootfs_dir}, but failed to create rootfs.tar.bz2: {e}"}], "isError": True}
        else:
            tar_note = "No rootfs directory found after binwalk extraction."

        # Set the chosen kernel into dest/kernel (replace whatever template copied)
        dest_kernel_dir = os.path.join(dest_dir, "kernel")
        os.makedirs(dest_kernel_dir, exist_ok=True)

        def _clear_dest_kernel_dir():
            for item in os.listdir(dest_kernel_dir):
                try:
                    os.remove(os.path.join(dest_kernel_dir, item))
                except Exception:
                    pass

        _clear_dest_kernel_dir()
        try:
            final_kernel_name = os.path.basename(chosen_kernel_src)
            final_kernel_path = os.path.join(dest_kernel_dir, final_kernel_name)
            shutil.copy2(chosen_kernel_src, final_kernel_path)
            kernel_msg = f"Kernel set to: {final_kernel_name}"
        except Exception as e:
            return {"content":[{"type":"text","text":f"Failed to place kernel: {e}"}], "isError": True}

        # --- Suggest devices row with qemuopts preset mapping ---
        def _first_dtb_in_kernel_dir(kdir: str) -> str:
            try:
                cands = [f for f in os.listdir(kdir) if f.lower().endswith(".dtb")]
                if cands:
                    return os.path.join(kdir, cands[0])
            except Exception:
                pass
            return ""

            dtb = _first_dtb_in_kernel_dir(os.path.join(dest_dir, "kernel"))

            device_id = f"firmware/{os.path.basename(dest_dir)}"
            row = f"{device_id},{qemu_binary},{machine_type},{cpu_type},{dtb},{memory},{kernel_image},{qemuopts},{description}"
            return row

        suggestion_row = _infer_device_suggestion(dest_dir, final_kernel_name, firmware_model)

        # Build final message
        lines = [
            "[emuxbuild] Template copied, config updated, firmware staged.",
            f"- Model     : {firmware_model}",
            f"- Template  : {template_dir}",
            f"- Dest      : {dest_dir}",
            f"- Config    : {cfg_path}",
            f"- Set       : id=firmware/{os.path.basename(dest_dir)}",
            f"- NVRAM     : {nvram_note}",
            f"- Firmware  : {fw_dst}",
            f"- Binwalk   : ran on {binwalk_runs} file(s)" + (f" (errors: {', '.join(bw_errors)})" if bw_errors else ""),
            f"- RootFS    : {tar_note}",
            f"- Kernel    : {kernel_msg}",
            "",
            "Additionally, the device suggestion for this configuration is:",
            "",
            "ID,qemu-binary,machine-type,cpu-type,dtb,memory,kernel-image,qemuopts,description",
            suggestion_row,
            "",
            "You can paste this into files/emux/devices manually or use emux.applyconfig to add it automatically."
        ]
        if extracted_note:
            lines.insert(6, f"- Action    : {extracted_note}")

        return {"content":[{"type":"text","text":"\n".join(lines)}], "isError": False}
    # emux.applyconfig — add or update a device row in devices/devices-extra
    elif name == "emux.applyconfig":
        import re, csv, time, shutil

        EMUX_HOME = os.environ.get("EMUX_HOME", "/home/ubuntu-server/emux")

        # Inputs:
        #   devices_target: "devices" (default) or "devices-extra"
        #   row: a full CSV row string (as printed by emuxbuild suggestion)
        #   fields: optional dict with columns to build the row if 'row' not provided
        devices_target = (arguments.get("devices_target") or "devices").strip()
        row_str        = (arguments.get("row") or "").strip()
        fields         = arguments.get("fields") or None  # dict or None
        allow_update   = bool(arguments.get("allow_update") if arguments.get("allow_update") is not None else True)
        create_backup  = bool(arguments.get("create_backup") if arguments.get("create_backup") is not None else True)

        # Resolve path
        devices_path = os.path.join(EMUX_HOME, "files", "emux", "firmware", devices_target)
        os.makedirs(os.path.dirname(devices_path), exist_ok=True)

        # Expected header columns
        header = ["ID","qemu-binary","machine-type","cpu-type","dtb","memory","kernel-image","qemuopts","description"]

        # If no row provided, try building from fields
        def build_row_from_fields(fields: dict) -> str:
            missing = [c for c in header if c not in fields]
            if missing:
                raise ValueError(f"Missing fields for CSV build: {', '.join(missing)}")
            return ",".join(fields.get(c, "") or "" for c in header)

        if not row_str:
            if not isinstance(fields, dict):
                return {"content":[{"type":"text","text":"Provide either 'row' (CSV line) or 'fields' (object with all columns)."}], "isError": True}
            try:
                row_str = build_row_from_fields(fields)
            except Exception as e:
                return {"content":[{"type":"text","text":f"Could not build CSV row from fields: {e}"}], "isError": True}

        # Parse ID from row (first column)
        try:
            row_cols = [c.strip() for c in next(csv.reader([row_str]))]
        except Exception as e:
            return {"content":[{"type":"text","text":f"Invalid CSV row format: {e}"}], "isError": True}

        if len(row_cols) != len(header):
            return {"content":[{"type":"text","text":f"CSV row must have {len(header)} columns, got {len(row_cols)}"}], "isError": True}

        row_id = row_cols[0]
        if not row_id:
            return {"content":[{"type":"text","text":"First column (ID) cannot be empty."}], "isError": True}

        # Read existing contents (if any)
        existing_lines = []
        had_header = False
        if os.path.exists(devices_path):
            try:
                with open(devices_path, "r", encoding="utf-8") as f:
                    existing_lines = [ln.rstrip("\n") for ln in f.readlines()]
                if existing_lines and re.sub(r"\s+", "", existing_lines[0]) == re.sub(r"\s+", "", ",".join(header)):
                    had_header = True
            except Exception as e:
                return {"content":[{"type":"text","text":f"Failed to read {devices_path}: {e}"}], "isError": True}

        # Backup
        backup_note = ""
        if create_backup and os.path.exists(devices_path):
            ts = time.strftime("%Y%m%d-%H%M%S")
            backup_path = devices_path + f".bak.{ts}"
            try:
                shutil.copy2(devices_path, backup_path)
                backup_note = f"Backup created: {backup_path}"
            except Exception as e:
                backup_note = f"Backup failed: {e}"

        # Build new content: ensure header, then add/update row
        new_lines = []
        if had_header:
            new_lines.append(",".join(header))
            body = existing_lines[1:]
        else:
            # If file existed but no valid header, we’ll keep its lines but prepend our header
            body = existing_lines[:]
            new_lines.append(",".join(header))

        # Search for existing ID
        replaced = False
        if allow_update:
            for i, ln in enumerate(body):
                if not ln.strip() or ln.strip().startswith("#"):
                    continue
                try:
                    cols = next(csv.reader([ln]))
                except Exception:
                    continue
                if cols and cols[0].strip() == row_id:
                    body[i] = row_str
                    replaced = True
                    break

        if not replaced:
            body.append(row_str)

        new_lines.extend(body)

        # Write back
        try:
            with open(devices_path, "w", encoding="utf-8") as f:
                for ln in new_lines:
                    f.write(ln + "\n")
        except Exception as e:
            return {"content":[{"type":"text","text":f"Failed to write {devices_path}: {e}"}], "isError": True}

        action = "updated existing row" if replaced else "appended new row"
        notes = [f"[emuxapplyconfig] {action} in {devices_path} for ID='{row_id}'."]
        if backup_note:
            notes.append(backup_note)

        # Echo final file tail for quick confirmation
        tail_preview = []
        try:
            with open(devices_path, "r", encoding="utf-8") as f:
                all_lines = [ln.rstrip("\n") for ln in f.readlines()]
            tail_preview = all_lines[-5:]
        except Exception:
            pass

        msg = "\n".join(notes) + ("\n\nLast lines:\n" + "\n".join(tail_preview) if tail_preview else "")
        return {"content":[{"type":"text","text":msg}], "isError": False}

    # emux.rebuild — run EMUX rebuild scripts inside EMUX_HOME
    elif name == "emux.rebuild":
        import shlex, subprocess, time

        EMUX_HOME   = os.environ.get("EMUX_HOME", "/home/ubuntu-server/emux")
        timeout_sec = int(arguments.get("timeout_sec") or 7200)   # 2h default
        no_sudo     = bool(arguments.get("no_sudo") or False)     # set True to avoid sudo

        if not os.path.isdir(EMUX_HOME):
            return {
                "content": [{"type": "text", "text": f"EMUX home not found: {EMUX_HOME}"}],
                "isError": True
            }

        def _run_in(cwd_dir: str, cmd_list: list[str], timeout: int):
            start = time.time()
            try:
                proc = subprocess.run(
                    cmd_list,
                    cwd=cwd_dir,
                    capture_output=True,
                    text=True,
                    timeout=timeout
                )
                dur = time.time() - start
                return proc.returncode, (proc.stdout or ""), (proc.stderr or ""), dur
            except subprocess.TimeoutExpired as e:
                dur = time.time() - start
                return 124, (e.stdout or ""), ((e.stderr or "") + "\n[timeout]"), dur
            except FileNotFoundError as e:
                dur = time.time() - start
                return 127, "", f"[error] {e}", dur
            except Exception as e:
                dur = time.time() - start
                return 1, "", f"[error] {e}", dur

        def _sudo_hint(stderr: str) -> str:
            s = (stderr or "").lower()
            if "a terminal is required" in s or "no tty present" in s:
                return "\n[hint] sudo may require a TTY. Configure NOPASSWD or run without sudo (no_sudo=true) if permitted."
            if "may not run sudo" in s or "password" in s:
                return "\n[hint] sudo denied or needs a password. Configure NOPASSWD or set no_sudo=true."
            return ""

        # Build commands
        vol_cmd  = ["./build-emux-volume"]
        dock_cmd = ["./build-emux-docker"]
        if not no_sudo:
            vol_cmd  = ["sudo", "-n"] + vol_cmd
            dock_cmd = ["sudo", "-n"] + dock_cmd

        # Step 1: volume
        rc1, out1, err1, dur1 = _run_in(EMUX_HOME, vol_cmd, timeout_sec)
        if rc1 != 0:
            text = []
            text.append("[emux.rebuild] build-emux-volume failed.")
            text.append(f"[cmd] {' '.join(shlex.quote(c) for c in vol_cmd)}")
            if out1: text.append(out1)
            if err1: text.append(f"[stderr]\n{err1}{_sudo_hint(err1)}")
            text.append(f"[exit={rc1}] [duration={dur1:.2f}s] [cwd={EMUX_HOME}]")
            return {"content":[{"type":"text","text":"\n".join(text)}], "isError": True}

        # Step 2: docker
        rc2, out2, err2, dur2 = _run_in(EMUX_HOME, dock_cmd, timeout_sec)

        # Report
        lines = []
        lines.append("[emux.rebuild] Completed EMUX rebuild sequence.")

        lines.append("\n--- build-emux-volume ---")
        lines.append(f"[cmd] {' '.join(shlex.quote(c) for c in vol_cmd)}")
        if out1: lines.append(out1)
        if err1: lines.append(f"[stderr]\n{err1}{_sudo_hint(err1)}")
        lines.append(f"[exit={rc1}] [duration={dur1:.2f}s] [cwd={EMUX_HOME}]")

        lines.append("\n--- build-emux-docker ---")
        lines.append(f"[cmd] {' '.join(shlex.quote(c) for c in dock_cmd)}")
        if out2: lines.append(out2)
        if err2: lines.append(f"[stderr]\n{err2}{_sudo_hint(err2)}")
        lines.append(f"[exit={rc2}] [duration={dur2:.2f}s] [cwd={EMUX_HOME}]")

        is_error = (rc2 != 0)
        if is_error:
            lines.append("\nOne or more steps failed. Check stderr above.")

        return {"content":[{"type":"text","text":"\n".join(lines)}], "isError": is_error}

    else:
        return {
            "content": [{"type": "text", "text": f"Unknown tool: {name}"}],
            "isError": True
        }

    rc, out, err, dur = run_cmd(cmd, args, timeout)
    csv_note = ""
    if emulate_ctx is not None:
        try:
            row = append_emulation_record(
                firmae_home=FIRMAE_HOME,
                fw_path=emulate_ctx["fw_path"],
                brand=emulate_ctx["brand"],
                exit_code=rc,
            )
            csv_note = "\n[+] Emulation record appended to emulation_records.csv"
        except Exception as e:
            csv_note = f"\n[!] Failed to append emulation record: {e}"

    body = []
    if out:
        body.append({"type": "text", "text": out})
    if err:
        body.append({"type": "text", "text": f"[stderr]\n{err}"})
    meta = f"[exit={rc}] [duration={dur:.2f}s] [cwd={FIRMAE_HOME}]"
    body.append({"type": "text", "text": meta})
    is_error = rc != 0 and "emulation start" not in out.lower()
    return {
        "content": body,
        "isError": is_error
    }

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    busy = True
    try:
        msg = json.loads(line)
        mid = msg.get("id")
        m = msg.get("method")
        params = msg.get("params", {})

        if m == "ping":
            # If host sent a request, echo its id; if it's a notification, use a dummy id.
            jwrite({"jsonrpc": "2.0", "id": mid if mid is not None else 0, "result": {"ok": True}})
            continue

        if mid is None and m:
            continue

        if m == "initialize":
            agreed = choose_version(params.get("protocolVersion") or "2024-11-05")
            jwrite({
                "jsonrpc": "2.0",
                "id": mid,
                "result": {
                    "protocolVersion": agreed,
                    "serverInfo": {"name": "firmae-adapter", "version": "0.2.0"},
                    "capabilities": {}
                }
            })
        elif m == "shutdown":
            jwrite({"jsonrpc": "2.0", "id": mid, "result": None})
        elif m == "ping":
            jwrite({"jsonrpc": "2.0", "id": mid, "result": {"ok": True}})
        elif m == "tools/list":
            jwrite({"jsonrpc": "2.0", "id": mid, "result": list_tools()})
        elif m == "resources/list":
            jwrite({"jsonrpc": "2.0", "id": mid, "result": {"resources": []}})
        elif m == "prompts/list":
            jwrite({"jsonrpc": "2.0", "id": mid, "result": {"prompts": []}})
        elif m == "tools/call":
            tool_name = (params or {}).get("name", "")

            def run_and_reply(_mid, _params):
                try:
                    result = handle_call(_params)
                except Exception as e:
                    result = {"content":[{"type":"text","text":f"Internal error: {e}"}], "isError": True}
                jwrite({"jsonrpc":"2.0", "id": _mid, "result": result})

            LONG = {"firmae.emulate"}  # add others if they can block a while
            if tool_name in LONG:
                threading.Thread(target=run_and_reply, args=(mid, params), daemon=True).start()
                # DO NOT write a response here; thread will respond when done
            else:
                jwrite({"jsonrpc":"2.0", "id": mid, "result": handle_call(params)})

        else:
            jwrite({
                "jsonrpc": "2.0",
                "id": mid,
                "error": {"code": -32601, "message": f"Method not found: {m}"}
            })

    except Exception as e:
        jwrite({
            "jsonrpc": "2.0",
            "id": msg.get("id"),
            "error": {"code": -32603, "message": str(e)}
        })

    finally:
        busy = False

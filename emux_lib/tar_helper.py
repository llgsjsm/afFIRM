import os, tarfile

def _find_rootfs_dir(extract_root: str) -> str | None:
    """
    Recursively search for a likely rootfs directory under `extract_root`.
    Accept names like squashfs-root, cramfs-root, rootfs.
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

                # rough size heuristic (can be expensive on huge trees; keep if okay)
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

    # Best: more "filesystem-like", deeper, larger
    candidates.sort(key=lambda t: (-t[0], -t[1], -t[2]))
    return candidates[0][3]

def _make_rootfs_tar_bz2(rootfs_dir: str, dest_tar_path: str) -> None:
    """
    Create bzip2 tarball with the contents of `rootfs_dir`.
    The tar will contain files at './' (not nested under the source folder name).
    """
    # Ensure parent exists
    os.makedirs(os.path.dirname(dest_tar_path), exist_ok=True)
    with tarfile.open(dest_tar_path, "w:bz2") as tf:
        # add contents of rootfs_dir at tar root
        tf.add(rootfs_dir, arcname=".", recursive=True)

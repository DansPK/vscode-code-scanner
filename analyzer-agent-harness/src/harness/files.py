"""Path rules from the contract, and file access that cannot leave a folder."""

import os
from pathlib import Path, PurePosixPath

MAX_SEARCH_FILE_BYTES = 1_000_000


class PathError(ValueError):
    pass


def check_rel_path(path):
    """Validate a contract path: relative, forward slashes, no '..' and no empty parts."""
    if not isinstance(path, str) or not path or "\\" in path or "\x00" in path:
        raise PathError(f"invalid path: {path!r}")
    if path.startswith("/") or (len(path) > 1 and path[1] == ":"):
        raise PathError(f"path must be relative: {path!r}")
    parts = path.split("/")
    if any(p in ("", ".", "..") for p in parts):
        raise PathError(f"invalid path: {path!r}")
    return path


def safe_join(root, path):
    """Resolve `path` inside `root`, refusing anything that ends up outside (including via symlinks)."""
    check_rel_path(path)
    root = Path(root).resolve()
    full = (root / PurePosixPath(path)).resolve()
    if not full.is_relative_to(root) or full == root:
        raise PathError(f"path is outside the project: {path!r}")
    return full


def walk_files(root):
    """Relative paths of regular files under root, skipping .git and symlinks."""
    root = Path(root)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != ".git" and not os.path.islink(os.path.join(dirpath, d))]
        for name in filenames:
            full = os.path.join(dirpath, name)
            if not os.path.islink(full) and os.path.isfile(full):
                yield Path(full).relative_to(root).as_posix()


def search(root, query, limit):
    """Plain-text search. Returns [(path, line_no, line_text)]."""
    results = []
    if not query:
        return results
    for rel in sorted(walk_files(root)):
        full = Path(root) / rel
        if full.stat().st_size > MAX_SEARCH_FILE_BYTES:
            continue
        data = full.read_bytes()
        if b"\x00" in data[:8192]:
            continue
        for i, line in enumerate(data.decode(errors="replace").splitlines(), 1):
            if query in line:
                results.append((rel, i, line.strip()[:300]))
                if len(results) >= limit:
                    return results
    return results

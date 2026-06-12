"""Package splunk_app/ as counterspell-<version>.tgz for AppInspect + install.

Splunk's AppInspect expects:
  - top-level directory inside the tarball matches the app id ('counterspell')
  - no .pyc, __pycache__, .DS_Store, .git, or editor cruft
  - default/app.conf with [id] block and [launcher] version
"""

from __future__ import annotations

import re
import shutil
import sys
import tarfile
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
APP_SRC = REPO_ROOT / "splunk_app"
APP_NAME = "counterspell"

EXCLUDE_DIRS = {"__pycache__", ".git", ".idea", ".vscode", "node_modules"}
EXCLUDE_SUFFIXES = {".pyc", ".pyo", ".swp", ".DS_Store"}


def _read_version() -> str:
    app_conf = APP_SRC / "default" / "app.conf"
    text = app_conf.read_text(encoding="utf-8")
    in_launcher = False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("[") and s.endswith("]"):
            in_launcher = s == "[launcher]"
            continue
        if in_launcher and s.startswith("version"):
            m = re.match(r"version\s*=\s*(\S+)", s)
            if m:
                return m.group(1)
    raise RuntimeError("Could not find [launcher] version in app.conf")


def _filter(tarinfo: tarfile.TarInfo) -> tarfile.TarInfo | None:
    name = Path(tarinfo.name).name
    if name in EXCLUDE_DIRS:
        return None
    for part in Path(tarinfo.name).parts:
        if part in EXCLUDE_DIRS:
            return None
    if any(name.endswith(s) for s in EXCLUDE_SUFFIXES):
        return None
    # Normalize ownership to make AppInspect happy.
    tarinfo.uid = 0
    tarinfo.gid = 0
    tarinfo.uname = ""
    tarinfo.gname = ""
    return tarinfo


def main() -> int:
    if not APP_SRC.is_dir():
        print(f"error: {APP_SRC} not found", file=sys.stderr)
        return 1
    version = _read_version()
    out_path = REPO_ROOT / f"{APP_NAME}-{version}.tgz"

    # Stage into a tmp dir under the correct top-level name.
    with tempfile.TemporaryDirectory() as tmpd:
        staged = Path(tmpd) / APP_NAME
        shutil.copytree(APP_SRC, staged)

        # Remove any stray pyc files.
        for p in staged.rglob("*"):
            if p.is_dir() and p.name in EXCLUDE_DIRS:
                shutil.rmtree(p, ignore_errors=True)
            elif p.suffix in EXCLUDE_SUFFIXES:
                p.unlink(missing_ok=True)

        with tarfile.open(out_path, "w:gz") as tar:
            tar.add(staged, arcname=APP_NAME, filter=_filter)

    size = out_path.stat().st_size
    print(f"wrote {out_path}  ({size:,} bytes)")
    print("Next steps:")
    print("  • Splunk UI → Apps → Manage Apps → Install app from file")
    print("  • AppInspect: splunk-appinspect inspect "
          f"{out_path.name} --mode precert")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

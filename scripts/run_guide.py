"""Execute every ```bash block of docs/TRY-IT-YOURSELF.md in one shell session.

Proves the copy-paste guide works as written. Usage, from the repo root:

    python3 scripts/run_guide.py [bash|zsh]

Skips the final clean-up block (stop/reset) and the `cd` line. Prints each block's
output and exits non-zero if any block fails.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

GUIDE = Path("docs/TRY-IT-YOURSELF.md")
SKIP = ("./run.sh reset", "./run.sh stop", "cd ~/Desktop")


def blocks() -> list[str]:
    text = GUIDE.read_text()
    out = []
    for b in re.findall(r"```bash\n(.*?)```", text, re.S):
        lines = [ln for ln in b.splitlines() if not ln.strip().startswith(SKIP)]
        out.append("\n".join(lines))
    return out


def main() -> int:
    shell = sys.argv[1] if len(sys.argv) > 1 else "bash"
    # Optional: run on other ports (e.g. while another checkout is using 8000/8100/8200).
    api, llm = os.environ.get("SV_API_PORT"), os.environ.get("LLM_PORT")
    script = []
    for i, b in enumerate(blocks()):
        if api:
            b = b.replace("127.0.0.1:8000", f"127.0.0.1:{api}")
        if llm:
            b = b.replace("127.0.0.1:8200", f"127.0.0.1:{llm}")
        script.append(f'echo "### block {i}"')
        script.append(b)
        script.append(f'rc=$?; [ $rc -eq 0 ] || echo "### block {i} exit $rc"')
    r = subprocess.run([shell, "-c", "\n".join(script)],  # noqa: S603 - our own doc
                       capture_output=True, text=True, check=False)
    print(r.stdout)
    print(r.stderr, file=sys.stderr)
    failed = re.findall(r"### block (\d+) exit", r.stdout)
    print(f"{len(blocks())} blocks, failed: {failed or 'none'}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())

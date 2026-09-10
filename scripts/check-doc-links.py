#!/usr/bin/env python3
"""Check local Markdown link targets without making network requests."""
from pathlib import Path
import re
import subprocess
from urllib.parse import unquote, urlsplit

root = Path(__file__).resolve().parent.parent
files = subprocess.check_output(
    ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z", "*.md"],
    cwd=root,
).decode().split("\0")
errors = []
for name in sorted(set(filter(None, files))):
    path = root / name
    if not path.is_file():
        continue
    text = re.sub(r"```.*?```", "", path.read_text(), flags=re.S)
    for target in re.findall(r"\]\(([^\s)]+)(?:\s+[^)]*)?\)", text):
        target = target.strip("<>")
        parsed = urlsplit(target)
        if parsed.scheme or parsed.netloc or not parsed.path:
            continue
        destination = path.parent / unquote(parsed.path)
        if not destination.exists():
            errors.append(f"{name}: missing link target {target}")
if errors:
    raise SystemExit("\n".join(errors))
print("Local Markdown links OK")

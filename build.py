#!/usr/bin/env python3
"""Assemble cloud-init.yaml from template + source files.

Reads cloud-init.tmpl.yaml, finds {{FILE:path}} markers, and replaces
each with the file contents indented to match the YAML block scalar level.
"""

import re
import sys
from pathlib import Path

TEMPLATE = "cloud-init.tmpl.yaml"
OUTPUT = "cloud-init.yaml"
MARKER_RE = re.compile(r"^(\s*)(\{\{FILE:(.+?)\}\})\s*$")


def build(root: Path) -> str:
    template = (root / TEMPLATE).read_text()
    lines = template.splitlines(keepends=True)
    out = []

    for line in lines:
        m = MARKER_RE.match(line)
        if not m:
            out.append(line)
            continue

        indent = m.group(1)
        filename = m.group(3)
        source = root / filename

        if not source.exists():
            print(f"ERROR: source file not found: {filename}", file=sys.stderr)
            sys.exit(1)

        content = source.read_text()
        # Indent every line of the source file to match the YAML level
        for src_line in content.splitlines():
            if src_line:
                out.append(indent + src_line + "\n")
            else:
                out.append("\n")

    return "".join(out)


def main():
    root = Path(__file__).resolve().parent
    result = build(root)
    outpath = root / OUTPUT
    outpath.write_text(result)
    print(f"Built {OUTPUT} ({len(result)} bytes)")


if __name__ == "__main__":
    main()

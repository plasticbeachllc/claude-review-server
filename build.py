#!/usr/bin/env python3
"""Assemble cloud-init.yaml from template + source files.

Reads cloud-init.tmpl.yaml, finds {{FILE:path}} markers, and replaces
each with the file contents indented to match the YAML block scalar level.

Usage:
    python3 build.py    # Build cloud-init.yaml
"""

import re
import sys
from pathlib import Path

TEMPLATE = "cloud-init.tmpl.yaml"
OUTPUT = "cloud-init.yaml"
MARKER_RE = re.compile(r"^(\s*)(\{\{FILE:(.+?)\}\})\s*$")


class BuildError(Exception):
    """Raised when a source file referenced in the template is missing."""


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
        source = (root / filename).resolve()

        # Guard against path traversal (e.g. {{FILE:../../etc/passwd}})
        if not source.is_relative_to(root):
            raise BuildError(f"path traversal not allowed: {filename}")

        if not source.exists():
            raise BuildError(f"source file not found: {filename}")

        content = source.read_text()
        # Indent every line of the source file to match the YAML level.
        # splitlines() omits the trailing newline, which is correct for
        # YAML block scalars (content: |) that implicitly add one.
        for src_line in content.splitlines():
            if src_line:
                out.append(indent + src_line + "\n")
            else:
                out.append("\n")

    return "".join(out)


def main():
    root = Path(__file__).resolve().parent

    try:
        result = build(root)
    except BuildError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    outpath = root / OUTPUT
    outpath.write_text(result)
    print(f"Built {OUTPUT} ({len(result)} bytes)")


if __name__ == "__main__":
    main()

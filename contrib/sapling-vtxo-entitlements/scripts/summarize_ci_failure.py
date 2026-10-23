#!/usr/bin/env python3
"""Turn a failed genuine-regtest log into public GitHub annotations.

Actions job logs need a signed-in viewer, but check-run annotations are
readable through the unauthenticated REST API. This prints the failing
stage, test panics, nextest verdicts, compiler errors and the log tail as
``::error`` workflow commands, and the same text to the step summary.

The input is a disposable-regtest log. Extended keys, cookie values and
mnemonic-looking lines are still masked before anything is echoed.
"""
import argparse
import os
from pathlib import Path
import re
import sys

ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
STAGE = re.compile(r"^==> stage: (.+)$")
EXTENDED_KEY = re.compile(r"\b[tx]prv[1-9A-HJ-NP-Za-km-z]{20,}")
SECRET_LINE = re.compile(r"(mnemonic|cookie|rpcpassword|rpcauth|seed phrase)", re.I)
MAX_ANNOTATIONS = 9
MAX_CHARS = 3_500


def clean(line):
    line = ANSI.sub("", line.rstrip("\n"))
    line = EXTENDED_KEY.sub("[extended-key-redacted]", line)
    if SECRET_LINE.search(line):
        name = SECRET_LINE.search(line).group(1)
        return f"[line mentioning {name} redacted]"
    return line


def blocks(lines, start, follow, limit):
    found = []
    for index, line in enumerate(lines):
        if start(line):
            found.append("\n".join(lines[index:index + follow]))
            if len(found) == limit:
                break
    return found


def classify(lines):
    stage = "before the first stage marker"
    for line in lines:
        match = STAGE.match(line.strip())
        if match:
            stage = match.group(1)
    return stage


def escape(text):
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def chunks(title, text):
    for start in range(0, len(text), MAX_CHARS):
        yield title, text[start:start + MAX_CHARS]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path)
    parser.add_argument("--tail", type=int, default=60)
    args = parser.parse_args()
    raw = args.log.read_text(encoding="utf-8", errors="replace").splitlines()
    lines = [clean(line) for line in raw]

    stage = classify(lines)
    sections = [("Failed stage", stage)]
    panics = blocks(lines, lambda l: "panicked at" in l, 60, 2)
    sections += [("Test panic", text) for text in panics]
    verdicts = [l for l in lines if re.search(
        r"\b(FAIL|TIMEOUT|SIGABRT|SIGSEGV|SIGKILL|LEAK)\b *\[|Summary \[|error: test run failed", l)]
    if verdicts:
        sections.append(("nextest verdicts", "\n".join(verdicts[-20:])))
    errors = blocks(lines, lambda l: re.match(r"^\s*error(\[E\d+\])?:", l) is not None, 14, 3)
    sections += [("Compiler or tool error", text) for text in errors]
    sections.append(("Log tail", "\n".join(lines[-args.tail:])))

    emitted = 0
    for title, text in sections:
        for part_title, part in chunks(title, text):
            if emitted == MAX_ANNOTATIONS:
                break
            print(f"::error title={escape(part_title)}::{escape(part)}")
            emitted += 1

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as out:
            out.write(f"## Genuine regtest failure\n\nFailed stage: `{stage}`\n\n")
            for title, text in sections[1:]:
                out.write(f"### {title}\n\n```text\n{text}\n```\n\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())

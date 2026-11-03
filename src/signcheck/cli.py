"""signcheck: what does this wallet signature request really do?"""

from __future__ import annotations

import argparse
import json
import sys
import textwrap
from pathlib import Path

from signcheck import __version__
from signcheck.eip712 import TypedDataError
from signcheck.explain import Report, explain

LABELS = {"danger": "DANGER ", "warning": "WARNING", "note": "note   "}
EXIT_DANGER = 3


def render(r: Report) -> str:
    out = [r.title]
    width = max((len(k) for k, _ in r.fields), default=0)
    for key, value in r.fields:
        out.append(f"  {key:<{width}}  {value}")
    if r.findings:
        out.append("")
    for f in r.findings:
        out.append(textwrap.fill(f.text, 96, initial_indent=f"{LABELS[f.level]}  ", subsequent_indent=" " * 9))
    if r.hashes:
        out.append("")
        out.append("Hashes (compare with what your hardware wallet shows):")
        width = max(len(k) for k, _ in r.hashes)
        for key, value in r.hashes:
            out.append(f"  {key:<{width}}  {value}")
    return "\n".join(out)


def read_input(source: str | None) -> str:
    if source in (None, "-"):
        if sys.stdin.isatty():
            raise SystemExit("paste a request on stdin, or pass a file, JSON or 0x calldata as an argument (see --help)")
        return sys.stdin.read()
    path = Path(source)
    if len(source) < 260 and not source.lstrip().startswith(("{", "0x")) and path.is_file():
        return path.read_text(encoding="utf-8-sig")
    return source


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="signcheck",
        description="Explain a wallet signature or transaction request and flag drainer patterns. Works offline.",
        epilog=f"Exit status: 0 when nothing dangerous was found, {EXIT_DANGER} when something was, 1 on errors.",
    )
    ap.add_argument("request", nargs="?", help="a JSON file, '-' for stdin, inline JSON, or 0x calldata")
    ap.add_argument("--chain", type=int, help="chain id, when the request does not state one (default: Ethereum, 1)")
    ap.add_argument("--json", action="store_true", help="print the report as JSON")
    ap.add_argument("--now", type=int, help=argparse.SUPPRESS)  # fixed clock for tests and examples
    ap.add_argument("-V", "--version", action="version", version=f"signcheck {__version__}")
    args = ap.parse_args(argv)

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    try:
        report = explain(read_input(args.request), chain=args.chain if args.chain is not None else 1, now=args.now)
    except (TypedDataError, KeyError, TypeError, ValueError) as err:
        msg = f"missing field {err}" if isinstance(err, KeyError) else str(err)
        print(f"signcheck: {msg}", file=sys.stderr)
        return 1
    print(json.dumps(report.to_dict(), indent=2) if args.json else render(report))
    return EXIT_DANGER if report.worst == "danger" else 0


if __name__ == "__main__":
    sys.exit(main())

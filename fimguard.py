import argparse
import json
import os
import sys

import store
from compare import compare
from report import count_changes, render
from snapshot import take_snapshot


def read_key(args):
    if args.key_file:
        with open(args.key_file, "rb") as handle:
            data = handle.read().strip()
        if not data:
            raise ValueError("key file is empty")
        return data
    value = os.environ.get("FIM_KEY")
    return value.encode("utf-8") if value else None


def baseline_exclusion(root, baseline):
    try:
        rel = os.path.relpath(os.path.abspath(baseline), os.path.abspath(root))
    except ValueError:
        return []
    if rel.startswith(".."):
        return []
    return [rel.replace(os.sep, "/")]


def run_init(args):
    root = os.path.abspath(args.directory)
    if not os.path.isdir(root):
        print(f"error: not a directory: {args.directory}", file=sys.stderr)
        return 2
    key = read_key(args)
    ignore = list(args.ignore) + baseline_exclusion(root, args.baseline)
    files, unreadable = take_snapshot(root, ignore)
    store.save(args.baseline, root, files, ignore, key)
    state = "signed" if key else "unsigned"
    print(f"baseline saved: {len(files)} files, {state} -> {args.baseline}")
    for rel in unreadable:
        print(f"warning: could not read {rel}", file=sys.stderr)
    return 0


def run_check(args):
    root = os.path.abspath(args.directory)
    if not os.path.isdir(root):
        print(f"error: not a directory: {args.directory}", file=sys.stderr)
        return 2
    try:
        key = read_key(args)
        document = store.load(args.baseline, key)
    except (OSError, ValueError, store.SignatureError) as problem:
        print(f"error: {problem}", file=sys.stderr)
        return 2
    ignore = list(document.get("ignore", [])) + baseline_exclusion(root, args.baseline)
    files, unreadable = take_snapshot(root, ignore)
    result = compare(document["files"], files)
    result["unreadable"] = unreadable
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(render(result))
    return 1 if count_changes(result) else 0


def build_parser():
    parser = argparse.ArgumentParser(
        prog="fimguard",
        description="Detect changes to files in a directory using SHA-256 baselines.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    for name, handler, text in (
        ("init", run_init, "create a baseline of a directory"),
        ("check", run_check, "compare a directory against its baseline"),
    ):
        sub = commands.add_parser(name, help=text)
        sub.add_argument("directory")
        sub.add_argument("--baseline", default="baseline.json")
        sub.add_argument("--key-file", help="file holding the secret used to sign the baseline")
        if name == "init":
            sub.add_argument("--ignore", action="append", default=[], metavar="PATTERN")
        else:
            sub.add_argument("--json", action="store_true")
        sub.set_defaults(handler=handler)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.handler(args)
    except (OSError, ValueError) as problem:
        print(f"error: {problem}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

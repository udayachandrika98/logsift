"""Command line interface for logsift."""

from __future__ import annotations

import argparse
import re
import sys
from datetime import datetime, timedelta
from pathlib import Path

from .analyse import (
    Filter,
    buckets,
    parse_field_filters,
    parse_since,
    spikes,
    summarise,
    top,
)
from .formats import PROFILES, detect, parse_stream


def _open(path: str):
    if path == "-":
        return sys.stdin
    return Path(path).open(encoding="utf-8", errors="replace")


def _resolve_profile(args, handle) -> tuple[str, list[str]]:
    """Pick a profile, sniffing the first lines if the user didn't say."""
    if args.format != "auto":
        return args.format, []
    sample = [handle.readline() for _ in range(20)]
    sample = [line for line in sample if line]
    return detect(sample), sample


def _entries(args):
    handle = _open(args.file)
    try:
        profile, sample = _resolve_profile(args, handle)
        if args.verbose:
            print(f"# format: {profile}", file=sys.stderr)
        lines = iter(sample + handle.readlines()) if sample else handle
        yield from parse_stream(lines, profile)
    finally:
        if handle is not sys.stdin:
            handle.close()


def _build_filter(args) -> Filter:
    pattern = re.compile(args.grep, 0 if args.case_sensitive else re.IGNORECASE) if args.grep else None
    now = datetime.now()
    return Filter(
        min_level=args.level,
        pattern=pattern,
        invert=args.invert,
        since=parse_since(args.since, now) if args.since else None,
        until=parse_since(args.until, now) if args.until else None,
        field_equals=parse_field_filters(args.field) if args.field else None,
    )


def cmd_show(args) -> int:
    matched = 0
    for entry in _build_filter(args).apply(_entries(args)):
        matched += 1
        if args.limit and matched > args.limit:
            break
        print(entry.raw)
    return 0 if matched else 1


def cmd_summary(args) -> int:
    summary = summarise(_build_filter(args).apply(_entries(args)))
    if summary.total == 0:
        print("no matching entries")
        return 1

    print(f"entries   : {summary.total}")
    if summary.unparsed:
        share = summary.unparsed / summary.total
        print(f"unparsed  : {summary.unparsed} ({share:.1%})")
    if summary.first and summary.last:
        print(f"first     : {summary.first}")
        print(f"last      : {summary.last}")
        print(f"span      : {summary.span}")
    print(f"error rate: {summary.error_rate:.2%}")
    print("\nby level:")
    width = max(len(level) for level in summary.by_level)
    for level, count in summary.by_level.most_common():
        share = count / summary.total
        bar = "#" * int(share * 40)
        print(f"  {level:<{width}}  {count:>7}  {share:>6.1%}  {bar}")
    return 0


def cmd_top(args) -> int:
    rows = top(_build_filter(args).apply(_entries(args)), args.key, args.limit)
    if not rows:
        print(f"no entries carry a '{args.key}' field", file=sys.stderr)
        return 1

    total = sum(count for _, count in rows)
    width = max(len(value) for value, _ in rows)
    print(f"top {len(rows)} by {args.key}:")
    for value, count in rows:
        share = count / total
        print(f"  {value:<{width}}  {count:>7}  {share:>6.1%}")
    return 0


def cmd_rate(args) -> int:
    width = timedelta(seconds=args.window)
    series = buckets(_build_filter(args).apply(_entries(args)), width, level=args.at_level)
    if not series:
        print("no timestamped entries to plot", file=sys.stderr)
        return 1

    peak = max(count for _, count in series)
    for when, count in series:
        bar = "#" * max(1, int(count / peak * 40))
        print(f"  {when:%Y-%m-%d %H:%M:%S}  {count:>6}  {bar}")

    hot = spikes(series, factor=args.spike_factor)
    if hot:
        print(f"\n{len(hot)} spike(s) at >= {args.spike_factor}x the median bucket:")
        for when, count in hot:
            print(f"  {when:%Y-%m-%d %H:%M:%S}  {count}")
        return 2
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="logsift",
        description="Filter, summarise and find spikes in log files.",
    )
    parser.add_argument("--version", action="version", version="logsift 0.1.0")
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p):
        """Shared flags. The `file` positional is added last by `with_file`
        so that a subcommand's own positionals read first on the command
        line -- `logsift top status access.log`, not `top access.log status`.
        """
        p.add_argument(
            "-f", "--format", choices=[*PROFILES, "auto"], default="auto",
            help="log format (default: sniff it)",
        )
        p.add_argument("-l", "--level", choices=("trace", "debug", "info", "warn", "error", "fatal"),
                       help="keep this level and above")
        p.add_argument("-g", "--grep", help="regex the raw line must match")
        p.add_argument("-v", "--invert", action="store_true", help="invert --grep")
        p.add_argument("--case-sensitive", action="store_true")
        p.add_argument("--since", help="ISO time, or an offset like 30m / 2h / 1d")
        p.add_argument("--until", help="ISO time, or an offset like 30m / 2h / 1d")
        p.add_argument("--field", action="append", metavar="KEY=VALUE",
                       help="require a field value (repeatable)")
        p.add_argument("--verbose", action="store_true", help="report the detected format")
        return p

    def with_file(p):
        p.add_argument("file", nargs="?", default="-", help="log file, or - for stdin")
        return p

    show = common(sub.add_parser("show", help="print matching lines"))
    show.add_argument("-n", "--limit", type=int, default=0, help="stop after N lines")
    with_file(show).set_defaults(func=cmd_show)

    summary = common(sub.add_parser("summary", help="counts, level breakdown and time span"))
    with_file(summary).set_defaults(func=cmd_summary)

    topcmd = common(sub.add_parser("top", help="most common values of a field"))
    topcmd.add_argument("key", help="field name, e.g. status, path, client, process")
    topcmd.add_argument("-n", "--limit", type=int, default=10)
    with_file(topcmd).set_defaults(func=cmd_top)

    rate = common(sub.add_parser("rate", help="entries over time, with spike detection"))
    rate.add_argument("-w", "--window", type=int, default=60, help="bucket width in seconds")
    rate.add_argument("--at-level", help="only count this level and above")
    rate.add_argument("--spike-factor", type=float, default=3.0)
    with_file(rate).set_defaults(func=cmd_rate)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except BrokenPipeError:  # piping into head/less
        return 0


if __name__ == "__main__":
    raise SystemExit(main())

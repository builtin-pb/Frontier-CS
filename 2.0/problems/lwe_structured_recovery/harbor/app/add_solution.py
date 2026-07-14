#!/usr/bin/env python3
"""Merge one candidate witness into the cumulative solution ledger."""

from __future__ import annotations

import argparse
from typing import NoReturn

import lwe_challenge.ledger as ledger


class _SanitizedArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> NoReturn:
        self.exit(2, "error: invalid command line\n")


def _parser() -> argparse.ArgumentParser:
    parser = _SanitizedArgumentParser()
    parser.add_argument("instance_id", metavar="INSTANCE_ID")
    parser.add_argument("secret", metavar="SECRET", nargs="?")
    parser.add_argument("--ledger", default="/app/solution.json")
    parser.add_argument("--replace", action="store_true")
    return parser


def main() -> int:
    parser = _parser()
    args, unknown = parser.parse_known_args()
    if args.secret is None and len(unknown) == 1:
        args.secret = unknown[0]
        unknown = []
    if args.secret is None or unknown:
        parser.error("INSTANCE_ID and SECRET are required")
    try:
        secret = tuple(int(component, 10) for component in args.secret.split(","))
    except ValueError:
        parser.error("SECRET must be a comma-separated integer vector")

    try:
        with ledger.ledger_lock(args.ledger):
            current = ledger.load_ledger(args.ledger)
            updated = ledger.merge_witness(
                current,
                instance_id=args.instance_id,
                secret=secret,
                replace=args.replace,
            )
            ledger.write_ledger_atomic(args.ledger, updated)
    except (OSError, TypeError, ValueError):
        parser.exit(2, "error: unable to update ledger\n")

    print(len(updated.solutions))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

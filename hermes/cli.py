"""
cli.py - python -m hermes.cli dry-run --scenario noise|signal

This is the entry point that proves Hermes runs standalone: no Discord
process, no bot token, no server, nothing but this repo and Python.
`dry-run` is the only subcommand, and the name is deliberate - this always
evaluates a static fixture under hermes/fixtures/, never a live
environment, so there's no ambiguity about it reaching out to anything
external.
"""

import argparse
import json

from hermes.dispatcher import run_scenario
from hermes.reporting import format_result


def main():
    parser = argparse.ArgumentParser(prog="python -m hermes.cli")
    subparsers = parser.add_subparsers(dest="command", required=True)

    dry_run = subparsers.add_parser("dry-run", help="Run Hermes against a fixture scenario")
    dry_run.add_argument("--scenario", required=True, choices=["noise", "signal"])

    args = parser.parse_args()

    if args.command == "dry-run":
        result = run_scenario(args.scenario)
        output = format_result(result)
        print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()

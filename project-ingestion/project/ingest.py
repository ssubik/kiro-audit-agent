#!/usr/bin/env python3
"""
Main entry point for ingesting raw findings from multiple sources.
"""

import argparse
import json

from .sources import code4rena, sherlock, trail_of_bits, openzeppelin


def parse_args():
    parser = argparse.ArgumentParser(description="Ingest raw findings from configured sources")
    parser.add_argument(
        "--output",
        default="raw_findings.json",
        help="Path to write raw findings JSON (default: raw_findings.json)",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    data = []
    data += code4rena.run()
    data += sherlock.run()
    data += trail_of_bits.run()
    data += openzeppelin.run()
    print(f"Collected {len(data)} raw findings")
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Main entry point for ingesting raw findings from multiple sources.

This script collects findings from the Code4rena, Sherlock, Trail of Bits
and OpenZeppelin ingestion modules and writes them to a JSON file
(`raw_findings.json`).  Each source module returns a list of
minimal dictionaries with information about the finding; the synthesis
layer will later convert these into full security rules.
"""

import json

# Use relative imports so that this module can be run with
# `python3 -m project.ingest`.  When invoked as a module, the
# `project` package is on the import path and these imports resolve correctly.
from .sources import code4rena, sherlock, trail_of_bits, openzeppelin


def main():
    """
    Aggregate findings from all sources and write them to disk.
    """
    data = []
    data += code4rena.run()
    data += sherlock.run()
    data += trail_of_bits.run()
    data += openzeppelin.run()
    print(f"Collected {len(data)} raw findings")
    with open("raw_findings.json", "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


if __name__ == "__main__":
    main()
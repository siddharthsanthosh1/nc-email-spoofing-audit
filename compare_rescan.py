#!/usr/bin/env python3
"""
compare_rescan.py — count how many domains got fixed between two scans.

Usage:
    python3 compare_rescan.py original_results.csv rescan_results.csv

"Fixed" = was NO_DMARC / MONITOR_ONLY / PARTIAL / MALFORMED in the original
and is ENFORCED_QUARANTINE or ENFORCED_REJECT in the re-scan.
"Improved" = moved up at least one rung (e.g., NO_DMARC -> MONITOR_ONLY),
which is real progress even if not yet enforced.
"""
import csv
import sys

RANK = {"LOOKUP_FAILED": -1, "NO_DMARC": 0, "MALFORMED": 0, "MONITOR_ONLY": 1,
        "PARTIAL": 2, "ENFORCED_QUARANTINE": 3, "ENFORCED_REJECT": 4}
UNPROTECTED = {"NO_DMARC", "MONITOR_ONLY", "PARTIAL", "MALFORMED"}
ENFORCED = {"ENFORCED_QUARANTINE", "ENFORCED_REJECT"}


def load(path):
    return {r["domain"].strip().lower(): r for r in csv.DictReader(open(path, newline=""))}


def main(before_path, after_path):
    before, after = load(before_path), load(after_path)
    fixed, improved, regressed = [], [], []
    for dom, b in before.items():
        a = after.get(dom)
        if not a or a["grade"] == "LOOKUP_FAILED" or b["grade"] == "LOOKUP_FAILED":
            continue
        rb, ra = RANK[b["grade"]], RANK[a["grade"]]
        if b["grade"] in UNPROTECTED and a["grade"] in ENFORCED:
            fixed.append((b["name"], dom, b["grade"], a["grade"]))
        elif ra > rb:
            improved.append((b["name"], dom, b["grade"], a["grade"]))
        elif ra < rb:
            regressed.append((b["name"], dom, b["grade"], a["grade"]))

    was_unprotected = sum(1 for b in before.values() if b["grade"] in UNPROTECTED)

    print(f"Originally unprotected: {was_unprotected}")
    print(f"Now enforced (FIXED):   {len(fixed)}")
    print(f"Improved but not yet enforced: {len(improved)}")
    print(f"Regressed: {len(regressed)}")
    print()
    for label, rows in [("FIXED", fixed), ("IMPROVED", improved), ("REGRESSED", regressed)]:
        if rows:
            print(f"--- {label} ---")
            for name, dom, g1, g2 in sorted(rows):
                print(f"  {name[:40]:<40} {dom:<32} {g1} -> {g2}")
            print()


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__); sys.exit(1)
    main(sys.argv[1], sys.argv[2])

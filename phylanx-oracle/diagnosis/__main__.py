"""
diagnosis/__main__.py — emit taxonomy.json from the Python source of truth.

Run:
    python3 -m diagnosis  > diagnosis/taxonomy.json

Or:
    python3 -m diagnosis --in-place

The JSON file is what the web app (phylanx-web) imports on Day 35 —
the contract is "one source of truth, the Python; everything else is
generated." If a reviewer hand-edits taxonomy.json the Day-35 build
falls out of sync; the regeneration step is the only safe edit path.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .remediation import RemediationCode
from .taxonomy import FailureMode, LABEL_METADATA


def build_payload() -> dict:
    """Build the canonical taxonomy.json payload."""
    return {
        "schema_version": 1,
        "failure_modes": [
            {
                "name":                meta.name,
                "bit":                 meta.bit,
                "value":               int(mode),
                "description":         meta.description,
                "severity":            meta.severity.name,
                "owasp_refs":          list(meta.owasp_refs),
                "default_remediation": {
                    "value": int(meta.default_remediation),
                    "codes": [
                        rc.name
                        for rc in RemediationCode
                        if (int(meta.default_remediation) & int(rc)) == int(rc)
                    ],
                },
            }
            for mode, meta in sorted(LABEL_METADATA.items(), key=lambda kv: kv[1].bit)
        ],
        "remediation_codes": [
            {"name": rc.name, "bit": int(rc).bit_length() - 1, "value": int(rc)}
            for rc in sorted(RemediationCode, key=lambda rc: int(rc).bit_length())
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="diagnosis", add_help=True)
    parser.add_argument(
        "--in-place",
        action="store_true",
        help="write the JSON next to this module instead of stdout",
    )
    args = parser.parse_args(argv)

    payload = build_payload()
    serialised = json.dumps(payload, indent=2, sort_keys=False) + "\n"

    if args.in_place:
        target = Path(__file__).resolve().parent / "taxonomy.json"
        target.write_text(serialised, encoding="utf-8")
        print(f"wrote {target}", file=sys.stderr)
    else:
        sys.stdout.write(serialised)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

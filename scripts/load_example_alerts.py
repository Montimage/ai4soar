#!/usr/bin/env python3
"""
Load the example alerts (data/example_alerts.json) into MongoDB. AI4SOAR already does it
at startup for the missing ones; this script is for doing it by hand.

    python3 scripts/load_example_alerts.py           # insert the missing ones
    python3 scripts/load_example_alerts.py --force   # restore all of them as shipped
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.database import example_alerts  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--force", action="store_true", help="overwrite the examples already in MongoDB")
    n = example_alerts.load(force=ap.parse_args().force)
    print(f"{n} example alert(s) loaded")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""PHASE 14 live validation CLI.

Run (live Wazuh dev environment only):
    python scripts/live_validation.py --live
    python scripts/live_validation.py --live --scenario detection_ssh_rule --auto-approve --confirm-execute

Never runs automatically as part of the unit suite. Requires --live and real
(non-mock) connectors. See docs/phase14-validation.md.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from live_validation.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())

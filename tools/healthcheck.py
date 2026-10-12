#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Reject persisted status from a previous container run.

Container health check: healthcheck.py STATUS_FILE KEY exits 0 only when the status file was
written since this container started, less than 10 s ago, and its KEY is true. No 3GPP behaviour.
"""

import json
import os
import pathlib
import sys
import time

try:
    path = pathlib.Path(sys.argv[1])
    modified = path.stat().st_mtime
    boot_time = next(
        int(row.split()[1]) for row in pathlib.Path("/proc/stat").read_text().splitlines() if row.startswith("btime ")
    )
    # The init process is recreated on every container restart.
    init_stat = pathlib.Path("/proc/1/stat").read_text().rsplit(")", 1)[1].split()
    started = boot_time + int(init_stat[19]) / os.sysconf("SC_CLK_TCK")
    healthy = modified >= started and time.time() - modified < 10
    healthy = healthy and json.loads(path.read_text()).get(sys.argv[2]) is True
    sys.exit(0 if healthy else 1)
except (OSError, ValueError, KeyError, IndexError):
    sys.exit(1)

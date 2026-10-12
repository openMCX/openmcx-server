#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Waiting helpers shared by the lab scenarios.

A negative check ("nothing is invited", "the call stays up") cannot wait for an event. Sleeping a fixed time and
then looking once passes if the wrong event comes after the look, and says nothing about what happened during the
sleep. holds() looks during the whole window instead: it fails at the first look that sees the wrong state, and
passes only when every look in the window saw the right one.

Specifications: none; no 3GPP procedure is tested here.
"""

import time

# How often holds() looks: often enough to see a short-lived wrong state, rarely enough not to load the lab.
POLL_INTERVAL_S = 0.2


# ------------------------------------------------------------------------------
def holds(predicate, seconds, interval=POLL_INTERVAL_S):
    """Whether predicate() is true at every look for the given seconds from now; False at the first look where it is
    not (then without waiting out the window). The first look is immediate and the last at the end of the window.
    """
    deadline = time.monotonic() + seconds
    while True:
        if not predicate():
            return False
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return True
        time.sleep(min(interval, remaining))

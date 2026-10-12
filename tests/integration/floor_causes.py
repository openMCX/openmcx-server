#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""The Reject Cause of every Floor Deny and Floor Revoke in a capture (TS 24.380 clauses 8.2.6 and 8.2.10).

A wire verifier calls causes(capture) and checks:
  - every Floor Deny and Floor Revoke carries the Reject Cause field (field ID 2, table 8.2.3.1-2), coded as
    table 8.2.3.4-1: a 16-bit <Reject Cause> value, a <Reject Phrase> only if the length is above 2;
  - the value is one defined for the message: Floor Deny #1 to #7 and #255 (clause 8.2.6.2), Floor Revoke #1 to #4,
    #6, #7 and #255 (clause 8.2.10.2);
and then that the causes it expects for its scenario were sent, e.g. Deny #1 for a floor request while another
client has permission (clause 6.3.5.4.4).

Specifications: TS 24.380 V19.2.0 (Rel-19).
"""

import collections
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from verify_broadcast_call import floor_messages  # noqa: E402

DENY, REVOKE = 3, 6
NAMES = {DENY: 'Deny', REVOKE: 'Revoke'}
ALLOWED = {DENY: {1, 2, 3, 4, 5, 6, 7, 255}, REVOKE: {1, 2, 3, 4, 6, 7, 255}}


# ------------------------------------------------------------------------------
def causes(capture):
    """(counts, violations): the number of Floor Deny and Floor Revoke messages per (name, cause) in the capture,
    e.g. counts[('Deny', 1)], and a description of each message whose Reject Cause is missing or not allowed."""
    counts, violations = collections.Counter(), []
    for subtype, fields in floor_messages(capture):
        if subtype not in NAMES:
            continue
        name = NAMES[subtype]
        value = fields.get(2, b'')
        if len(value) < 2:
            violations.append(f'Floor {name} without a Reject Cause')
            continue
        cause = struct.unpack('!H', value[:2])[0]
        counts[(name, cause)] += 1
        if cause not in ALLOWED[subtype]:
            violations.append(f'Floor {name} with cause #{cause}, not defined for the message')
    return counts, violations


# ------------------------------------------------------------------------------
def summary(counts):
    """The counts as {"Deny #1": n, ...}, for a verifier's report."""
    return {f'{name} #{cause}': number for (name, cause), number in sorted(counts.items())}

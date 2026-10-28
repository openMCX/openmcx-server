#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Wire check of held_rekey_scenario.py at the MCPTT server: a held call's floor control across a key download.

For every call dialog a client set up with protected floor control, the floor control SRTCP (TS 33.180 clause 9.4)
of each direction is followed up to the dialog's BYE:
  - its SRTCP index only grows, also where the MKI changes (RFC 3711 section 3.4: "after a re-key, the SRTCP index MUST
    NOT be reset to zero again");
  - its MKI is a CSK-ID (purpose tag 2, TS 33.180 clause 9.4.6), the caller's uploaded CSK-ID first.
Every dialog's MKIs follow the caller's keys in order: its uploaded CSK-ID, then the CSK-IDs of the key downloads to
it (MESSAGE with a MIKEY I_MESSAGE answered 200), each first used after that download. Every held dialog (one with a
re-INVITE that holds it, a=sendonly, RFC 5359 section 2.1), and at least one, must carry exactly the uploaded CSK-ID
and then the downloaded one in both directions, with each direction's index growing across the change.

Usage: verify_held_rekey.py capture.pcap --output report.json

Specifications: TS 33.180 V19.4.0 (Rel-19), TS 24.380 V19.2.0 (Rel-19), RFC 3711.
"""

import argparse
import base64
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from verify_protected import accepted, mikey_header, mime_parts, parse_srtcp, read_sip, require
from verify_reinvite_ssrc import (
    client_csks,
    csk_of,
    dialog_id,
    dialogs,
    final_response,
    floor_sdp,
    read_floor,
    tag,
    user,
)


# ------------------------------------------------------------------------------
def key_downloads(messages):
    """The CSK downloads the server made (TS 33.180 clause 5.8.2): (frame of the 200, recipient URI, CSK-ID) of each
    MESSAGE with a MIKEY I_MESSAGE of the CSK purpose tag 2 that was answered 200."""
    found = []
    for message in messages:
        if message['method'] != 'MESSAGE' or message['status'] or not accepted(message, messages):
            continue
        for kind, body in mime_parts(message):
            if kind == 'application/mikey':
                raw = base64.b64decode(body.strip(), validate=True)
                answer = final_response(messages, message)
                found.append((answer['frame'], user(message['headers'].get('to')), mikey_header(raw, 2)))
    return found


# ------------------------------------------------------------------------------
def follow(packets, setup, end):
    """The floor control SRTCP of one dialog, per direction: the packets' (frame, index, MKI) in order."""
    caller = (setup['offer']['address'], setup['offer']['port'])
    callee = (setup['answer']['address'], setup['answer']['port'])
    directions = {'caller-to-server': (caller, callee), 'server-to-caller': (callee, caller)}
    result = {name: [] for name in directions}
    for frame, src, sport, dst, dport, payload in packets:
        if frame < setup['frame'] or frame > end:
            continue
        for name, (source, destination) in directions.items():
            if (src, sport) == source and (dst, dport) == destination:
                srtcp = parse_srtcp(payload)
                result[name].append((frame, srtcp['index'], srtcp['csk_id']))
    return result


# ------------------------------------------------------------------------------
def main():
    """Inspect the capture and write the report; exit status 1 on any error."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--tshark', default=os.environ.get('MCX_TSHARK') or shutil.which('tshark'))
    parser.add_argument('--tshark-option', action='append', default=[])
    args = parser.parse_args()
    result = dict(passed=False, capture=str(args.capture), dialogs=[], errors=[])
    try:
        require(bool(args.tshark), 'tshark unavailable; install it or set MCX_TSHARK')
        messages = read_sip(args)
        setups = dialogs(messages)
        csks = client_csks(messages)
        downloads = key_downloads(messages)
        endpoints = set()
        for setup in setups.values():
            endpoints |= {(setup['offer']['address'], setup['offer']['port'])}
            endpoints |= {(setup['answer']['address'], setup['answer']['port'])}
        require(endpoints, 'no call dialog with floor control')
        packets = read_floor(args, endpoints)
        held = {
            dialog_id(message)
            for message in messages
            if message['method'] == 'INVITE'
            and not message['status']
            and tag(message['headers'].get('to'))
            and (floor_sdp(message) or {}).get('hold')
        }
        require(any(key in setups for key in held), 'no held call dialog in the capture')
        rekeyed = 0
        for key, setup in setups.items():
            byes = [
                message['frame']
                for message in messages
                if message['method'] == 'BYE' and not message['status'] and dialog_id(message) == key
            ]
            end = min(byes or [sys.maxsize])
            flows = follow(packets, setup, end)
            if not any(flows.values()):
                continue
            entry = dict(call_id=key[0], caller=setup['caller'], directions={})
            uploaded = None
            if any(uri == setup['caller'] for _, uri, _ in csks):
                uploaded = csk_of(csks, setup['caller'], setup['frame'])
            # The caller's keys in this dialog, in order: the uploaded CSK, then each downloaded one.
            keys = [(setup['frame'], uploaded)] + [
                (frame, csk_id)
                for frame, uri, csk_id in downloads
                if uri == setup['caller'] and setup['frame'] < frame < end
            ]
            expected = [csk_id for _, csk_id in keys]
            changed_both = True
            for name, flow in flows.items():
                for (frame, index, _), (_, previous, _) in zip(flow[1:], flow, strict=False):
                    require(index > previous, f'{key[0]} {name}: frame {frame} SRTCP index {index} after {previous}')
                mkis = []
                for _, _, mki in flow:
                    if not mkis or mkis[-1] != mki:
                        mkis.append(mki)
                if uploaded is not None and mkis:
                    require(
                        mkis == expected[: len(mkis)],
                        f'{key[0]} {name}: MKIs {[hex(mki) for mki in mkis]}, the caller\'s keys in order '
                        f'{[hex(csk_id) for csk_id in expected]}',
                    )
                    # Each downloaded key is first used after its download was answered.
                    for download_frame, csk_id in keys[1:]:
                        first = next((frame for frame, _, mki in flow if mki == csk_id), None)
                        require(
                            first is None or first > download_frame,
                            f'{key[0]} {name}: {csk_id:#010x} in frame {first} before its download '
                            f'(frame {download_frame})',
                        )
                changed_both = changed_both and len(expected) == 2 and mkis == expected
                entry['directions'][name] = dict(packets=len(flow), mkis=[f'{mki:#010x}' for mki in mkis])
            entry['held'] = key in held
            if uploaded is not None and changed_both:
                rekeyed += 1
                entry['rekeyed'] = True
            result['dialogs'].append(entry)
            if key in held:
                require(
                    entry.get('rekeyed'),
                    f'{key[0]}: the held call did not go on under the new CSK in both directions: '
                    f'{entry["directions"]}',
                )
        require(
            all(entry.get('rekeyed') for entry in result['dialogs'] if entry['held'])
            and any(entry['held'] for entry in result['dialogs']),
            'no held dialog with floor control re-keyed in both directions',
        )
        result['rekeyed_dialogs'] = rekeyed
        result['passed'] = True
    except (ValueError, KeyError, TypeError, OSError, subprocess.CalledProcessError) as error:
        result['errors'].append(error.stderr if isinstance(error, subprocess.CalledProcessError) else str(error))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, default=str) + '\n')
    print(json.dumps({key: result.get(key) for key in ['passed', 'rekeyed_dialogs', 'errors']}))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())

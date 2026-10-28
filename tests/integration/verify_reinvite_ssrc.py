#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Wire check of reinvite_ssrc_scenario.py at the MCPTT server: re-INVITEs that change the floor control SSRC.

For every re-INVITE a client sends in a call's dialog without MC service information (a session refresh, RFC 4028
section 7.4, or a hold or resume, RFC 5359 section 2.1), its offer's "mc_floor_ssrc" (TS 24.380 clause 4.3.3.1) is
compared with the client's SSRC negotiated at the call's setup:
  - the same SSRC is answered 200 (OK); another one, the server's own among them, 488 (Not Acceptable Here);
  - every 488 is acknowledged by an ACK of the same CSeq number (RFC 3261 section 17.1.1.3);
  - no BYE ends the dialog before its last re-INVITE (the refusal keeps the session, RFC 3261 section 14.2);
  - the floor control SRTCP of such a dialog (TS 33.180 clause 9.4) carries the client's CSK-ID as MKI in both
    directions (clause 9.4.6; the CSK-ID of the client's last CSK upload before the call), keeps its SSRCs in both
    directions (the server's packets with the client's SSRC, the client's with the server's), its SRTCP index
    only grows (RFC 3711 section 3.4), and floor control goes on in both directions after each refusal.
The capture needs visible SIP (debug TCP labs). At least one refusal of a new SSRC, one of the server's own SSRC, one
refused hold and accepted refreshes, holds and resumes are required.

Usage: verify_reinvite_ssrc.py capture.pcap --output report.json

Specifications: TS 24.380 V19.2.0 (Rel-19), TS 33.180 V19.4.0 (Rel-19), RFC 3261, RFC 3711, RFC 4028, RFC 5359.
"""

import argparse
import base64
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from verify_protected import accepted, mikey_header, mime_parts, parse_srtcp, read_sip, require, tshark_command


# ------------------------------------------------------------------------------
def tag(value):
    """The tag parameter of a From or To header field value, or ''."""
    match = re.search(r';\s*tag=([^;>\s]+)', value or '', re.I)
    return match.group(1) if match else ''


# ------------------------------------------------------------------------------
def user(value):
    """The SIP URI of a From or To header field value."""
    match = re.search(r'<(sips?:[^>]+)>', value or '') or re.search(r'(sips?:[^\s;>]+)', value or '')
    return match.group(1) if match else ''


# ------------------------------------------------------------------------------
def branch(message):
    """The branch of the message's top Via header field value (its transaction at this hop, RFC 3261 section
    17.2.3), or ''."""
    match = re.search(r';\s*branch=([^;,\s]+)', message['headers'].get('via', ''), re.I)
    return match.group(1) if match else ''


# ------------------------------------------------------------------------------
def dialog_id(message):
    """The dialog of a message in either direction: its Call-ID and the From and To tags (RFC 3261 section 12)."""
    headers = message['headers']
    return headers['call-id'], frozenset({tag(headers.get('from')), tag(headers.get('to'))})


# ------------------------------------------------------------------------------
def cseq_number(message):
    """The CSeq number of a message."""
    return int(message['headers']['cseq'].split()[0])


# ------------------------------------------------------------------------------
def floor_sdp(message):
    """The floor control part of the message's SDP: its SSRC, address and port; None without one."""
    body = message['body']
    ssrc = re.search(r'mc_floor_ssrc=(\d+)', body)
    port = re.search(r'^m=application (\d+) ', body, re.M)
    address = re.search(r'^c=IN IP4 (\S+)', body, re.M)
    if not ssrc or not port or not address:
        return None
    return dict(
        ssrc=int(ssrc.group(1)),
        port=int(port.group(1)),
        address=address.group(1),
        hold=bool(re.search(r'^a=sendonly\s*$', body, re.M)),
    )


# ------------------------------------------------------------------------------
def final_response(messages, request):
    """The final response to the request: its transaction (top Via branch, CSeq and method, RFC 3261 section 17.1.3)
    in its dialog (Call-ID, From tag and, once the request has one, To tag); None without one."""
    for message in messages:
        if (
            message['status'] >= 200
            and message['frame'] >= request['frame']
            and message['method'] == request['method']
            and message['headers']['call-id'] == request['headers']['call-id']
            and message['headers']['cseq'] == request['headers']['cseq']
            and branch(message) == branch(request)
            and tag(message['headers'].get('from')) == tag(request['headers'].get('from'))
            and (
                not tag(request['headers'].get('to'))
                or tag(message['headers'].get('to')) == tag(request['headers'].get('to'))
            )
        ):
            return message
    return None


# ------------------------------------------------------------------------------
def dialogs(messages):
    """The confirmed call dialogs: Call-ID -> the client (the sender of the re-INVITEs), the floor SDP of the client
    and of the server at setup, and the setup's 200 frame."""
    found = {}
    for invite in messages:
        headers = invite['headers']
        if invite['method'] != 'INVITE' or invite['status'] or tag(headers.get('to')):
            continue
        answer = final_response(messages, invite)
        if not answer or answer['status'] != 200:
            continue
        offer, accepted = floor_sdp(invite), floor_sdp(answer)
        if not offer or not accepted:
            continue
        found[dialog_id(answer)] = dict(
            caller=user(headers.get('from')),
            caller_tag=tag(headers.get('from')),
            offer=offer,
            answer=accepted,
            frame=answer['frame'],
        )
    return found


# ------------------------------------------------------------------------------
def reinvites(messages, setups):
    """The re-INVITEs without MC service information in the dialogs, each with its sender's negotiated floor SDP
    and the server's, its offer and its final response."""
    result = []
    for request in messages:
        headers = request['headers']
        if request['method'] != 'INVITE' or request['status'] or not tag(headers.get('to')):
            continue
        call_id = dialog_id(request)
        if call_id not in setups:
            continue
        if request['fields']:
            continue  # with mcptt-info: an MC procedure, not a refresh
        setup = setups[call_id]
        client_is_caller = user(headers.get('from')) == setup['caller']
        client, server = (setup['offer'], setup['answer']) if client_is_caller else (setup['answer'], setup['offer'])
        offer = floor_sdp(request)
        require(offer is not None, f'frame {request["frame"]}: re-INVITE without a floor control offer')
        response = final_response(messages, request)
        require(response is not None, f'frame {request["frame"]}: re-INVITE without a final response')
        result.append(dict(request=request, response=response, client=client, server=server, offer=offer))
    return result


# ------------------------------------------------------------------------------
def read_floor(args, endpoints):
    """The UDP packets between the floor endpoints: (frame, source address, source port, destination address,
    destination port, payload)."""
    ports = sorted({port for _, port in endpoints})
    fields = ['frame.number', 'ip.src', 'udp.srcport', 'ip.dst', 'udp.dstport', 'udp.payload']
    command = tshark_command(args) + [
        '-Y',
        'udp && (' + ' || '.join(f'udp.port=={port}' for port in ports) + ')',
        '-T',
        'fields',
        '-E',
        'occurrence=f',
    ]
    for field in fields:
        command += ['-e', field]
    output = subprocess.run(command, check=True, capture_output=True, text=True).stdout
    packets = []
    for line in output.splitlines():
        values = line.split('\t')
        require(len(values) == len(fields), 'incomplete UDP dissection')
        frame, src, sport, dst, dport, payload = values
        packets.append((int(frame), src, int(sport), dst, int(dport), bytes.fromhex(payload.replace(':', ''))))
    return packets


# ------------------------------------------------------------------------------
def client_csks(messages):
    """The CSKs the clients uploaded: (frame, client URI, CSK-ID) of each accepted PUBLISH with a MIKEY I_MESSAGE
    of the CSK purpose tag 2 (TS 33.180 clause 9.2.1, TS 24.379 clause 7.2.1)."""
    found = []
    for message in messages:
        if message['method'] != 'PUBLISH' or message['status'] or not accepted(message, messages):
            continue
        if message['headers'].get('event', '').split(';')[0].strip().lower() != 'poc-settings':
            continue
        for kind, body in mime_parts(message):
            if kind == 'application/mikey':
                raw = base64.b64decode(body.strip(), validate=True)
                found.append((message['frame'], user(message['headers'].get('from')), mikey_header(raw, 2)))
    return found


# ------------------------------------------------------------------------------
def csk_of(csks, client, frame):
    """The CSK-ID of the client's last CSK upload before frame; ValueError without one."""
    uploads = [csk_id for upload_frame, uri, csk_id in csks if uri == client and upload_frame < frame]
    require(uploads, f'no CSK upload by {client} before frame {frame}')
    return uploads[-1]


# ------------------------------------------------------------------------------
def check_floor(packets, dialog, refusals, last_frame):
    """The floor control SRTCP of one dialog keeps its SSRCs, its MKI (the client's CSK-ID, TS 33.180 clause 9.4.6:
    both directions are under the client's CSK) and its index, and goes on after each refusal."""
    client = (dialog['client']['address'], dialog['client']['port'])
    server = (dialog['server']['address'], dialog['server']['port'])
    directions = {
        'server-to-client': dict(src=server, dst=client, ssrc=dialog['client']['ssrc'], frames=[], last=-1),
        'client-to-server': dict(src=client, dst=server, ssrc=dialog['server']['ssrc'], frames=[], last=-1),
    }
    for frame, src, sport, dst, dport, payload in packets:
        if frame < dialog['setup_frame'] or frame > last_frame:
            continue
        for name, direction in directions.items():
            if (src, sport) != direction['src'] or (dst, dport) != direction['dst']:
                continue
            srtcp = parse_srtcp(payload)
            require(
                srtcp['csk_id'] == dialog['csk_id'],
                f'frame {frame}: {name} floor packet with MKI {srtcp["csk_id"]:#010x}, the client\'s CSK-ID is '
                f'{dialog["csk_id"]:#010x}',
            )
            require(
                srtcp['ssrc'] == direction['ssrc'],
                f'frame {frame}: {name} floor packet with SSRC {srtcp["ssrc"]}, negotiated {direction["ssrc"]}',
            )
            require(
                srtcp['index'] > direction['last'],
                f'frame {frame}: {name} SRTCP index {srtcp["index"]} after {direction["last"]}',
            )
            direction['last'] = srtcp['index']
            direction['frames'].append(frame)
    for name, direction in directions.items():
        for refused in refusals:
            require(
                any(frame > refused for frame in direction['frames']),
                f'no {name} floor control after the refusal in frame {refused}',
            )
    return {
        name: dict(packets=len(direction['frames']), last_index=direction['last'])
        for name, direction in directions.items()
    }


# ------------------------------------------------------------------------------
def main():
    """Inspect the capture and write the report; exit status 1 on any error."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--tshark', default=os.environ.get('MCX_TSHARK') or shutil.which('tshark'))
    parser.add_argument('--tshark-option', action='append', default=[])
    args = parser.parse_args()
    result = dict(passed=False, capture=str(args.capture), counts={}, errors=[], dialogs={})
    try:
        require(bool(args.tshark), 'tshark unavailable; install it or set MCX_TSHARK')
        messages = read_sip(args)
        setups = dialogs(messages)
        checked = reinvites(messages, setups)
        counts = dict(accepted=0, accepted_hold=0, refused_changed=0, refused_colliding=0, refused_hold=0)
        refusals = {}
        for entry in checked:
            request, response, offer = entry['request'], entry['response'], entry['offer']
            call_id = dialog_id(request)
            same = offer['ssrc'] == entry['client']['ssrc']
            expected = 200 if same else 488
            require(
                response['status'] == expected,
                f'frame {request["frame"]}: re-INVITE with floor SSRC {offer["ssrc"]} (negotiated '
                f'{entry["client"]["ssrc"]}) answered {response["status"]}, expected {expected}',
            )
            if same:
                counts['accepted'] += 1
                counts['accepted_hold'] += offer['hold']
                continue
            counts['refused_hold' if offer['hold'] else 'refused_changed'] += 1
            counts['refused_colliding'] += offer['ssrc'] == entry['server']['ssrc']
            # RFC 3261 section 17.1.1.3: the ACK of a non-2xx final response belongs to the INVITE's transaction: the
            # top Via of the INVITE, its Call-ID, From and CSeq number, and the To of the response.
            acks = [
                message
                for message in messages
                if message['method'] == 'ACK'
                and not message['status']
                and message['frame'] > response['frame']
                and branch(message) == branch(request)
                and message['headers']['call-id'] == request['headers']['call-id']
                and tag(message['headers'].get('from')) == tag(request['headers'].get('from'))
                and tag(message['headers'].get('to')) == tag(response['headers'].get('to'))
                and cseq_number(message) == cseq_number(request)
            ]
            require(acks, f'frame {response["frame"]}: 488 to the re-INVITE without the ACK of its transaction')
            dialog = result['dialogs'].setdefault(
                call_id,
                dict(
                    client=entry['client'],
                    server=entry['server'],
                    setup_frame=setups[call_id]['frame'],
                    last=0,
                    client_uri=user(request['headers'].get('from')),
                ),
            )
            refusals.setdefault(call_id, []).append(response['frame'])
        for entry in checked:
            call_id = dialog_id(entry['request'])
            if call_id in result['dialogs']:
                result['dialogs'][call_id]['last'] = max(result['dialogs'][call_id]['last'], entry['response']['frame'])
        require(counts['accepted'] >= 2 and counts['accepted_hold'] >= 1, f'too few accepted re-INVITEs: {counts}')
        require(
            counts['refused_changed'] >= 1 and counts['refused_colliding'] >= 1 and counts['refused_hold'] >= 1,
            f'too few refused re-INVITEs: {counts}',
        )
        endpoints = set()
        for dialog in result['dialogs'].values():
            endpoints |= {(dialog['client']['address'], dialog['client']['port'])}
            endpoints |= {(dialog['server']['address'], dialog['server']['port'])}
        packets = read_floor(args, endpoints)
        csks = client_csks(messages)
        for dialog in result['dialogs'].values():
            dialog['csk_id'] = csk_of(csks, dialog['client_uri'], dialog['setup_frame'])
        for call_id, dialog in result['dialogs'].items():
            # The scenario's own teardown is the only BYE of the dialog: the caller hangs up (client-a, the caller of
            # the private call and the initiator whose hangup makes the server release the group call's legs), after
            # the dialog's last re-INVITE, the final refused one included, was answered; anything else ended the
            # session the refusal had to keep (RFC 3261 section 14.2).
            byes = {
                branch(message): message
                for message in messages
                if message['method'] == 'BYE' and not message['status'] and dialog_id(message) == call_id
            }
            require(len(byes) == 1, f'{call_id[0]}: {len(byes)} BYE transactions in the dialog, expected the teardown')
            bye = next(iter(byes.values()))
            require(
                bye['frame'] > dialog['last'],
                f'{call_id[0]}: BYE in frame {bye["frame"]} before the dialog\'s last re-INVITE was answered '
                f'(frame {dialog["last"]})',
            )
            require(
                tag(bye['headers'].get('from')) == setups[call_id]['caller_tag'],
                f'{call_id[0]}: the BYE in frame {bye["frame"]} is not the teardown by the call\'s caller',
            )
            bye_answer = final_response(messages, bye)
            require(bye_answer and bye_answer['status'] == 200, f'{call_id[0]}: teardown BYE not answered 200')
            dialog['teardown_frame'] = bye['frame']
            end = bye['frame']
            dialog['floor'] = check_floor(packets, dialog, refusals[call_id], end)
        result['counts'] = dict(counts, sip_messages=len(messages), dialogs_checked=len(result['dialogs']))
        result['passed'] = True
    except (ValueError, KeyError, TypeError, OSError, subprocess.CalledProcessError) as error:
        result['errors'].append(error.stderr if isinstance(error, subprocess.CalledProcessError) else str(error))
    result['dialogs'] = {f'{key[0]};{",".join(sorted(key[1]))}': value for key, value in result['dialogs'].items()}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, default=str) + '\n')
    print(json.dumps({key: result[key] for key in ['passed', 'counts', 'errors']}))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())

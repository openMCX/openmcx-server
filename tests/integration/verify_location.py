#!/usr/bin/env python3
"""Verify location signalling from a clear-SIP server-side capture.

MCPTT (TS 24.379 clause 13, the participating function's request of clause 6.3.2.4), or with --mcdata MCData (TS 24.282
clause 17, the area notifications of clauses 6.3.7.1.6 and 6.3.7.1.7): location configurations to every client, reports
and requests, refusals with warnings 192 to 194 (TS 24.379 table 4.4.2-2) or 244 to 246 (TS 24.282), the location of an
emergency alert (TS 24.379 clause 6.2.9.1, TS 24.282 clause 6.2.5.1). With --protected (an MCData fixture with
confidentiality protection), the location content itself must cross encrypted (TS 24.282 annex D.4.3, TS 33.180 clause
9.3).

Usage: verify_location.py capture.pcap --service sip:mcptt@DOMAIN --output result.json [--mcdata [--protected]]

Reads the capture taken in the server's namespace during location_scenario.py or mcdata_location_scenario.py. Check IDs
match tests/mcptt/LOCATION_TEST.md and tests/mcdata/MCDATA_LOCATION_TEST.md.

Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19), TS 33.180 V19.4.0 (Rel-19).
"""

import argparse
import json
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parent))
from verify_private_call import header, parse, sip_messages, tcp_streams  # noqa: E402

PROFILES = {
    'mcptt': dict(
        ns='urn:3gpp:ns:mcpttLocationInfo:1.0',
        mime='application/vnd.3gpp.mcptt-location-info+xml',
        info_ns='urn:3gpp:ns:mcpttInfo:1.0',
        icsi='urn:urn-7:3gpp-service.ims.icsi.mcptt',
        tag='+g.3gpp.mcptt',
        reporting='mcptt-reporting-uri',
        events='McpttSignallingEvent',
        warnings=('192', '193', '194'),
        prefix='W',
    ),
    'mcdata': dict(
        ns='urn:3gpp:ns:mcdataLocationInfo:1.0',
        mime='application/vnd.3gpp.mcdata-location-info+xml',
        info_ns='urn:3gpp:ns:mcdataInfo:1.0',
        icsi='urn:urn-7:3gpp-service.ims.icsi.mcdata',
        tag='+g.3gpp.mcdata',
        reporting='mcdata-reporting-uri',
        events='McdataSignallingEvent',
        warnings=('244', '245', '246'),
        prefix='M',
    ),
}


# ------------------------------------------------------------------------------
def location_body(message):
    """The location-info document of a message, single-bodied or in a multipart."""
    body = message['body']
    start = body.find('<location-info')
    if start < 0:
        return None
    end = body.find('</location-info>', start)
    return ET.fromstring(body[start : end + len('</location-info>')])


# ------------------------------------------------------------------------------
def info_of(message, ns):
    """The plain elements of the message's mcptt-info or mcdata-info (encrypted ones are absent)."""
    root = 'mcpttinfo' if 'mcptt' in ns else 'mcdatainfo'
    match = re.search(rf'<(?:[\w.-]+:)?{root}\b.*?</(?:[\w.-]+:)?{root}\s*>', message['body'], re.S)
    if not match:
        return {}
    try:
        return {
            element.tag.replace('{' + ns + '}', ''): ''.join(element.itertext()).strip()
            for element in ET.fromstring(match.group()).iter()
            if element.tag.startswith('{' + ns + '}')
        }
    except ET.ParseError:
        return {}


# ------------------------------------------------------------------------------
def main():
    """Decode the capture, run the checks of the chosen service and write the result; exit status 1 on any failure."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('--service', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--mcdata', action='store_true')
    parser.add_argument('--protected', action='store_true')
    args = parser.parse_args()
    profile = PROFILES['mcdata' if args.mcdata else 'mcptt']
    LOC = '{' + profile['ns'] + '}'
    icsi_ref = '+g.3gpp.icsi-ref="' + profile['icsi'].replace(':', '%3A') + '"'
    messages, seen = [], set()
    for _, stream in tcp_streams(args.capture):
        for head, body in sip_messages(stream):
            message = parse(head, body)
            key = (message['call_id'], header(message, 'cseq'), message['line'])
            if key not in seen:
                seen.add(key)
                message['info'] = info_of(message, profile['info_ns'])
                messages.append(message)
    checks, failures, observations = [], [], {}
    prefix = profile['prefix']

    # ------------------------------------------------------------------------------
    def check(label, condition):
        """Record label, prefixed with the service letter, as passed or failed."""
        (checks if condition else failures).append(f'{prefix}-{label}')

    # ------------------------------------------------------------------------------
    def answer(request):
        """The final response to request (same Call-ID and CSeq), or None."""
        return next(
            (
                message
                for message in messages
                if not message['request']
                and message['call_id'] == request['call_id']
                and header(message, 'cseq') == header(request, 'cseq')
                and message['status'] >= 200
            ),
            None,
        )

    located = []
    for message in messages:
        if message['request'] and message['method'] == 'MESSAGE':
            try:
                doc = location_body(message)
            except ET.ParseError:
                doc = 'invalid'
            if doc is not None:
                located.append((message, doc))
    check(
        '00 every location-info body is well-formed XML in the service\'s location namespace',
        located and all(doc != 'invalid' and doc.tag == LOC + 'location-info' for _, doc in located),
    )
    kinds = {'Configuration': [], 'Request': [], 'Report': []}
    for message, doc in located:
        if doc == 'invalid':
            continue
        children = [child.tag.replace(LOC, '') for child in doc]
        if len(children) == 1 and children[0] in kinds:
            kinds[children[0]].append((message, doc[0]))
    observations['counts'] = {kind: len(value) for kind, value in kinds.items()}
    to_server = lambda message: message['target'].split(';')[0] == args.service
    has_tag = lambda message, needle: any(
        needle in value and 'require' in value and 'explicit' in value
        for value in message['headers'].get('accept-contact', [])
    )

    configs = [(message, configuration) for message, configuration in kinds['Configuration'] if not to_server(message)]
    check(
        '01 configurations go to each client public user identity with the icsi-ref Accept-Contact and P-Asserted-Service',
        len({message['target'] for message, _ in configs}) >= 4
        and all(
            has_tag(message, icsi_ref) and header(message, 'p-asserted-service') == profile['icsi']
            for message, _ in configs
        ),
    )
    first = next((configuration for _, configuration in configs if configuration.get('ConfigScope') == 'Full'), None)
    ids = (
        [element.get('TriggerId') for element in first.iter() if element.get('TriggerId')] if first is not None else []
    )
    check(
        '01 a Full configuration with a TriggerId per criterion, the emergency criteria in its anyExt',
        first is not None
        and first.find(LOC + 'TriggeringCriteria') is not None
        and first.find(f'{LOC}anyExt/{LOC}EmergencyTriggeringCriteria/{LOC}PeriodicReport') is not None
        and first.find(f'{LOC}TriggeringCriteria/{LOC}{profile["events"]}/{LOC}InitialLogOn') is not None
        and {'t1', 't2', 't3', 't4', 't5', 't6', 't7'} <= set(ids),
    )

    # An emergency alert's location (TS 24.379 clause 6.2.9.1, TS 24.282 clause 6.2.5.1) travels with its info body.
    alert_reports = [
        (message, report)
        for message, report in kinds['Report']
        if to_server(message) and ('mcpttinfo' in message['body'] or 'mcdatainfo' in message['body'])
    ]
    reports = [
        (message, report)
        for message, report in kinds['Report']
        if to_server(message) and (message, report) not in alert_reports
    ]
    observations['alert_locations'] = len(alert_reports)
    check(
        '02 reports go to the participating function as a single location-info body with the service Accept-Contact',
        reports
        and all(
            header(message, 'content-type').startswith(profile['mime']) and has_tag(message, profile['tag'])
            for message, _ in reports
        ),
    )
    check(
        '02 each report has a ReportType, its fired TriggerIds or a ReportID, and a current location',
        all(
            report.get('ReportType') in ('Emergency', 'NonEmergency')
            and (report.findall(LOC + 'TriggerId') or report.get('ReportID'))
            and report.find(f'{LOC}CurrentLocation/{LOC}CurrentCoordinate') is not None
            for _, report in reports
        ),
    )
    accepted = [answer(message) for message, _ in reports]
    check(
        '02 reports are answered 200, except those of the user not allowed to report (403)',
        any(reply and reply['status'] == 403 for reply in accepted)
        and sum(1 for reply in accepted if reply and reply['status'] == 200)
        >= len(reports) - sum(1 for reply in accepted if reply and reply['status'] == 403),
    )
    check(
        '02 an Emergency report on the emergency periodic trigger t7',
        any(
            report.get('ReportType') == 'Emergency'
            and 't7' in [trigger.text for trigger in report.findall(LOC + 'TriggerId')]
            for _, report in reports
        ),
    )

    own = [(message, request) for message, request in kinds['Request'] if not to_server(message)]
    answered_ids = {report.get('ReportID') for _, report in reports}
    check(
        '03 the participating function requests a client report, and the client answers with its RequestId as ReportID',
        own and all(request.get('RequestId') in answered_ids for _, request in own),
    )
    client_requests = [(message, request) for message, request in kinds['Request'] if to_server(message)]
    check(
        '04 authorised requests carry a RequestId, refresh and a LocationFilter',
        any(request.get('RequestId') and 'resource-lists' in message['body'] for message, request in client_requests)
        and any(request.get('refresh') == 'true' for _, request in client_requests)
        and any(
            request.find(f'{LOC}anyExt/{LOC}LocationFilter/{LOC}AreaIdentifier') is not None
            for _, request in client_requests
        ),
    )
    delivered = [
        (message, report) for message, report in kinds['Report'] if not to_server(message) and report.get('ReportID')
    ]
    requested_ids = {request.get('RequestId') for _, request in client_requests}
    check(
        '04 reports to the requester carry its RequestId as ReportID and the reporting user',
        delivered
        and all(
            report.get('ReportID') in requested_ids
            and (report.findtext(LOC + profile['reporting']) or '').startswith('sip:')
            for _, report in delivered
        ),
    )
    warnings = [
        header(reply, 'warning')
        for reply in (answer(message) for message, _ in kinds['Request'] + kinds['Configuration'] if to_server(message))
        if reply
    ]
    check(
        '05 refusals carry warnings ' + ', '.join(profile['warnings']),
        all(any(f'"{code} ' in warning for warning in warnings) for code in profile['warnings']),
    )
    check(
        '06 an authorised configuration change is sent as an Update and reaches its target',
        any(
            configuration.get('ConfigScope') == 'Update'
            for message, configuration in kinds['Configuration']
            if to_server(message)
        )
        and any(configuration.get('ConfigScope') == 'Update' for _, configuration in configs),
    )
    notices = [
        message
        for message in messages
        if message['request']
        and message['method'] == 'MESSAGE'
        and ('emergency-alert-area-ind' in message['info'] or 'group-geo-area-ind' in message['info'])
    ]
    check(
        '07 emergency alert area and group geographic area entries and exits are notified',
        {notice['info'].get('emergency-alert-area-ind') for notice in notices} >= {'true', 'false'}
        and {notice['info'].get('group-geo-area-ind') for notice in notices} >= {'true', 'false'},
    )
    check(
        '07 notices carry both Accept-Contact feature tags and are answered 200',
        notices
        and all(
            has_tag(notice, profile['tag'])
            and has_tag(notice, icsi_ref)
            and (answer(notice) or {}).get('status') == 200
            for notice in notices
        ),
    )
    if args.protected:
        # TS 24.282 annex D.4.3 rule 2) with TS 33.180 clause 9.3: the reported location and the areas of a
        # configuration are xmlenc EncryptedData; nothing of them crosses in clear.
        clear = [
            message for message, doc in located if doc != 'invalid' and doc.find(f'.//{LOC}threebytes') is not None
        ]
        encrypted = [
            doc
            for _, doc in located
            if doc != 'invalid' and any(element.get('type') == 'Encrypted' for element in doc.iter())
        ]
        check(
            '08 no location coordinate crosses in clear between the clients and the participating function',
            not clear and all(re.search(r'<(?:[\w.-]+:)?EncryptedData\b', message['body']) for message, _ in reports),
        )
        check(
            '08 every report and every configuration with an area carries its location as type="Encrypted" EncryptedData',
            len(encrypted) >= len(reports)
            and all(
                report.find(f'{LOC}CurrentLocation/{LOC}CurrentCoordinate/{LOC}latitude').get('type') == 'Encrypted'
                for _, report in reports
            ),
        )
        observations['encrypted_location_bodies'] = len(encrypted)
    result = dict(
        capture=str(args.capture), passed=not failures, checks=checks, failures=failures, observations=observations
    )
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(dict(passed=result['passed'], checks=len(checks), failures=failures)))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())

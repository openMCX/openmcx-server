#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Verify the XML integrity protection of the SIP signalling in a clear-SIP capture at an MC server.

Checks (TS 33.180 clause 9.3.5 "When integrity protection is enabled, all XML MIME bodies transported in SIP requests
and responses are integrity protected"; TS 24.379 clause 6.6.3, TS 24.281 clause 6.6.3, TS 24.282 clause 6.5.3; the
signatures body of TS 24.379 annex F.6; W3C XML Signature Syntax and Processing (Second Edition); RFC 2392):
  - every message with an application/vnd.3gpp.mcptt-signed+xml body has a Content-ID on each of its other XML
    bodies, and each of those is referenced by a Reference whose cid URL (%-decoded) names it, with the SHA-256
    digest of the body's octets;
  - every Signature carries SignedInfo with a CanonicalizationMethod, a SignatureMethod (HMAC-SHA256) and a
    SignatureValue; OpenMCX signs with Exclusive XML Canonicalization 1.0;
  - negative: once a user's service authorisation that uploaded a CSK (a PUBLISH, or the client REGISTER in a
    third-party REGISTER, with an application/mikey body) was answered 200 (OK), no later message between that user
    and the server carries an XML body without signatures (the client REGISTER inside a third-party REGISTER is
    checked as a message of its own);
  - at least --users users were authorised with a CSK and at least one signed message was seen.
The messages of a client's CMS, GMS or GKTP subscription without the CSK in its initial SUBSCRIBE are left out: they
are not protected (TS 24.484 and TS 24.481 clause 6.3.13.3.2.2; verify_subscription_protection.py), and so are the
test's own hand-made requests (Call-ID "security-...", sip_negative.py).

The HMAC values are not checked: they need the CSK, which the capture does not show.

Self-contained (no tshark); reuses the SIP reassembly of verify_private_call.py.

Specifications: TS 33.180 V19.5.0 (Rel-19), TS 24.379 V19.7.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19), TS 24.282
V19.7.0 (Rel-19).
"""

import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import sys
import urllib.parse
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parent))
from verify_private_call import header, timed_messages  # noqa: E402

SIGNED = 'application/vnd.3gpp.mcptt-signed+xml'
DSIG = '{http://www.w3.org/2000/09/xmldsig#}'
EXCLUSIVE_C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#'
HMAC_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#hmac-sha256'


# ------------------------------------------------------------------------------
def media_type(value):
    """The media type of a Content-Type value, lower case and without parameters."""
    return value.split(';')[0].strip().lower()


# ------------------------------------------------------------------------------
def is_xml(value):
    """RFC 7303 and RFC 6839: application/xml, text/xml or a "+xml" type."""
    kind = media_type(value)
    return kind in ('application/xml', 'text/xml') or (len(kind) > 4 and kind.endswith('+xml'))


# ------------------------------------------------------------------------------
def body_parts(content_type, body):
    """The parts of a body as (type, Content-ID, octets): the parts of a multipart body (RFC 2046 section 5.1), or
    the body itself."""
    if not media_type(content_type).startswith('multipart/'):
        return [(media_type(content_type), '', body)] if body else []
    match = re.search(r'boundary="?([^";]+)"?', content_type, re.I)
    if not match:
        return []
    marker = '--' + match.group(1)
    parts = []
    for chunk in body.split(marker)[1:]:
        if chunk.startswith('--'):
            break
        chunk = chunk[2:] if chunk.startswith('\r\n') else chunk
        if chunk.endswith('\r\n'):
            chunk = chunk[:-2]
        head, _, content = chunk.partition('\r\n\r\n')
        kind, cid = '', ''
        for line in head.split('\r\n'):
            name, _, value = line.partition(':')
            if name.strip().lower() == 'content-type':
                kind = media_type(value)
            elif name.strip().lower() == 'content-id':
                cid = value.strip().removeprefix('<').removesuffix('>')
        parts.append((kind, cid, content))
    return parts


# ------------------------------------------------------------------------------
def inner_register(body):
    """The client's REGISTER of a message/sip body: its Content-Type and its body."""
    head, _, content = body.partition('\r\n\r\n')
    kind = ''
    for line in head.split('\r\n')[1:]:
        name, _, value = line.partition(':')
        if name.strip().lower() in ('content-type', 'c'):
            kind = value.strip()
    return kind, content


RESOURCE_LISTS = 'application/resource-lists+xml'
KINDS = (
    ('gktp', ('org.3gpp.MCPTT-GKTP/',)),
    ('group', ('org.openmobilealliance.groups/',)),
    ('configuration', ('org.3gpp.mcptt.', 'org.3gpp.mcvideo.', 'org.3gpp.mcdata.')),
)


# ------------------------------------------------------------------------------
def bare(value):
    """The URI of a From or To header field value, without angle brackets and parameters."""
    value = value.split('<', 1)[-1].split('>', 1)[0] if '<' in value else value
    return value.split(';', 1)[0].strip()


# ------------------------------------------------------------------------------
def subscription_dialogs(messages):
    """The clients' CMS, GMS and GKTP subscriptions of a capture: Call-ID -> (kind, subscriber, identity hiding,
    capture time of the initial SUBSCRIBE)."""
    found = {}
    for message in messages:
        if not (
            message['request']
            and message['method'] == 'SUBSCRIBE'
            and header(message, 'event').split(';')[0].strip() == 'xcap-diff'
            and 'tag=' not in header(message, 'to')
            and message['call_id'] not in found
        ):
            continue
        parts = body_parts(header(message, 'content-type'), message['body'])
        lists = ' '.join(content for kind, _, content in parts if kind == RESOURCE_LISTS)
        kind = next((name for name, auids in KINDS if any(auid in lists for auid in auids)), None)
        if kind:
            hiding = any(part_kind == 'application/mikey' for part_kind, _, _ in parts)
            found[message['call_id']] = (kind, bare(header(message, 'from')), hiding, message['time'])
    return found


# ------------------------------------------------------------------------------
def signature_problems(parts):
    """What is wrong with the signatures of a message's parts (empty when they cover every XML body)."""
    problems = []
    signed = [content for kind, _, content in parts if kind == SIGNED]
    xml_parts = [(cid, content) for kind, cid, content in parts if kind != SIGNED and is_xml(kind)]
    if len(signed) != 1:
        return [f'{len(signed)} signatures bodies']
    try:
        root = ET.fromstring(signed[0])
    except ET.ParseError as error:
        return [f'signatures body is not XML: {error}']
    references = {}
    for signature in root.findall(DSIG + 'Signature'):
        info = signature.find(DSIG + 'SignedInfo')
        if info is None or signature.find(DSIG + 'SignatureValue') is None:
            problems.append('Signature without SignedInfo or SignatureValue')
            continue
        method = info.find(DSIG + 'CanonicalizationMethod')
        if method is None:
            problems.append('SignedInfo without CanonicalizationMethod')
        elif method.get('Algorithm') != EXCLUSIVE_C14N:
            problems.append(f'canonicalisation {method.get("Algorithm")} instead of Exclusive XML Canonicalization 1.0')
        signature_method = info.find(DSIG + 'SignatureMethod')
        if signature_method is None or signature_method.get('Algorithm') != HMAC_SHA256:
            problems.append('SignatureMethod is not HMAC-SHA256')
        for reference in info.findall(DSIG + 'Reference'):
            uri = reference.get('URI', '')
            if not uri.startswith('cid:'):
                problems.append(f'Reference {uri} is not a cid URL')
                continue
            digest = reference.find(DSIG + 'DigestValue')
            references[urllib.parse.unquote(uri[4:])] = ''.join(digest.itertext()).strip() if digest is not None else ''
    for cid, content in xml_parts:
        if not cid:
            problems.append('an XML body without Content-ID')
        elif cid not in references:
            problems.append(f'XML body {cid} not referenced')
        elif base64.b64decode(references[cid]) != hashlib.sha256(content.encode('utf-8')).digest():
            problems.append(f'digest of {cid} does not match its octets')
    return problems


# ------------------------------------------------------------------------------
def main():
    """Decode the capture, run the checks and write the result file; exit status 1 on any failure."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('--users', type=int, default=2)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    messages, seen = [], set()
    for message in timed_messages(args.capture):
        key = (message['call_id'], header(message, 'cseq'), message['line'])
        if key not in seen:
            seen.add(key)
            messages.append(message)
    checks, failures = [], []

    # ------------------------------------------------------------------------------
    def check(label, condition):
        (checks if condition else failures).append(label)

    def bare(value):
        value = value.split('<', 1)[-1].split('>', 1)[0] if '<' in value else value
        return value.split(';', 1)[0].strip()

    # The service authorisations that uploaded a CSK, by their transaction, and their user.
    uploads, keyed = {}, {}
    for message in messages:
        if not message['request'] or message['method'] not in ('PUBLISH', 'REGISTER'):
            continue
        parts = body_parts(header(message, 'content-type'), message['body'])
        user = bare(header(message, 'from' if message['method'] == 'PUBLISH' else 'to'))
        for kind, _, content in parts:
            if kind == 'message/sip':
                inner_type, inner_body = inner_register(content)
                parts = parts + body_parts(inner_type, inner_body)
        if any(kind == 'application/mikey' for kind, _, _ in parts):
            uploads[(message['call_id'], header(message, 'cseq'))] = user
    for message in messages:
        transaction = (message['call_id'], header(message, 'cseq'))
        if not message['request'] and message['status'] == 200 and transaction in uploads:
            keyed.setdefault(uploads[transaction], message['time'])
    uploaders = set(uploads.values())

    # TS 24.484 and TS 24.481 clause 6.3.13.3.2.2: the CMS, GMS and GKTP subscriptions without the CSK in their initial
    # SUBSCRIBE (no identity hiding) are not protected, so their messages are not required to carry signatures
    # (verify_subscription_protection.py checks them).
    exempt = {call_id for call_id, (_, _, hiding, _) in subscription_dialogs(messages).items() if not hiding}
    signed_messages, unsigned, broken, exempted = 0, [], [], 0
    for message in messages:
        # The test's own hand-made requests (sip_negative.py and the scenarios' probes, Call-ID "security-...") are
        # not OpenMCX signalling.
        if message['call_id'] in exempt or message['call_id'].startswith('security-'):
            exempted += 1
            continue
        units = [(header(message, 'content-type'), message['body'])]
        if message['request'] and message['method'] == 'REGISTER':
            units = [inner_register(content) for kind, _, content in body_parts(*units[0]) if kind == 'message/sip']
        # The users of the hop: From or To among the users that uploaded a CSK.
        parties = {bare(header(message, 'from')), bare(header(message, 'to'))} & uploaders
        for content_type, body in units:
            parts = body_parts(content_type, body)
            if not any(kind != SIGNED and is_xml(kind) for kind, _, _ in parts):
                continue
            label = f'{message["line"]} (Call-ID {message["call_id"]})'
            if any(kind == SIGNED for kind, _, _ in parts):
                signed_messages += 1
                problems = signature_problems(parts)
                if problems:
                    broken.append(f'{label}: {"; ".join(problems)}')
                continue
            if parties and all(party in keyed and message['time'] > keyed[party] for party in parties):
                unsigned.append(label)

    check(f'at least {args.users} users authorised with a CSK upload', len(keyed) >= args.users)
    check('signed messages were seen', signed_messages > 0)
    check('every signatures body covers each XML body with a matching digest (TS 33.180 clause 9.3.5)', not broken)
    check('no XML body without signatures after the CSK upload was accepted (all XML MIME bodies)', not unsigned)
    result = dict(
        capture=str(args.capture),
        passed=not failures,
        checks=checks,
        failures=failures,
        counts=dict(keyed_users=sorted(keyed), signed_messages=signed_messages, subscription_messages_exempt=exempted),
        broken=broken[:20],
        unsigned=unsigned[:20],
    )
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())

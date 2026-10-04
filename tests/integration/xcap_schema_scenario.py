#!/usr/bin/env python3
"""Schema validation of group and user profile documents (RFC 4825 section 8.2.5).

The GMS checks group documents against the OMA group schema with the TS 24.481 extensions (TS 24.481 clause 7.2.4), GMOP
documents against their schema (TS 24.481 clause 7.3.3), and the constraints of OMA-TS-XDM_Group-V1_1_1 5.1.6 and 7.2.7;
the CMS checks user profile documents against the TS 24.484 schema (TS 24.484 clause 8.3.2.3), serves them with their
namespace and MIME type (clauses 8.3.2.4 and 8.3.2.5) and enforces the constraints of clause 8.3.2.6. A probe inside
client-a's container signs in as client-a (allowed to create groups and to update other users' profiles) and sends XCAP
requests directly, so that the documents can be malformed on purpose. Run against a fixture prepared with
--group-management. Check IDs match tests/mcptt/GROUP_MANAGEMENT_TEST.md.

Specifications: TS 24.481 V19.3.0 (Rel-19), TS 24.484 V19.6.0 (Rel-19).
"""

import argparse
import json
from pathlib import Path
import subprocess
import time
from urllib.parse import quote as url_quote

ROOT = Path(__file__).resolve().parents[2]

# Runs in the client container: OIDC sign-in as the configured user (PKCE, as the
# client does), then the requests given on stdin; prints each status, content type
# and body. No token or password is printed.
PROBE = r'''
import base64, hashlib, http.client, json, secrets, ssl, sys, urllib.parse
cfg = json.load(open(sys.argv[1]))
requests = json.loads(sys.argv[2])
context = ssl.create_default_context(cafile=cfg["tls"]["ca_file"])
def call(method, url, body=None, headers=None):
    u = urllib.parse.urlsplit(url)
    c = http.client.HTTPSConnection(u.hostname, u.port or 443, context=context, timeout=15)
    c.request(method, u.path + ("?" + u.query if u.query else ""), body=body, headers=headers or {})
    r = c.getresponse()
    out = (r.status, r.getheader("Content-Type") or "", r.getheader("Location") or "", r.getheader("ETag") or "", r.read())
    c.close()
    return out
oauth = cfg["oauth"]
verifier = secrets.token_urlsafe(48)
challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
state = secrets.token_hex(8)
query = urllib.parse.urlencode({"response_type": "code", "client_id": oauth["client_id"], "redirect_uri": oauth["redirect_uri"],
    "scope": "openid 3gpp:mc:ptt_service", "state": state, "nonce": secrets.token_hex(8), "code_challenge": challenge,
    "code_challenge_method": "S256"})
request_id = json.loads(call("GET", oauth["issuer"] + "/authorize?" + query)[4])["request_id"]
form = {"Content-Type": "application/x-www-form-urlencoded"}
location = call("POST", oauth["issuer"] + "/login", urllib.parse.urlencode({"request_id": request_id,
    "username": oauth["username"], "password": oauth["password"]}), form)[2]
code = urllib.parse.parse_qs(urllib.parse.urlsplit(location).query)["code"][0]
token = json.loads(call("POST", oauth["issuer"] + "/token", urllib.parse.urlencode({"grant_type": "authorization_code",
    "client_id": oauth["client_id"], "redirect_uri": oauth["redirect_uri"], "code": code, "code_verifier": verifier}), form)[4])["access_token"]
results = []
for method, url, content_type, body in requests:
    headers = {"Authorization": "Bearer " + token}
    if content_type:
        headers["Content-Type"] = content_type
    status, kind, _, etag, raw = call(method, url, body.encode() if body is not None else None, headers)
    results.append({"status": status, "content_type": kind, "etag": etag, "body": raw.decode("utf-8", "replace")[:4000]})
print(json.dumps(results))
'''

GROUP_MIME = 'application/vnd.oma.poc.groups+xml'
PROFILE_MIME = 'application/vnd.3gpp.mcptt-user-profile+xml'
GMOP_MIME = 'application/vnd.3gpp.GMOP+xml'
MCPTT_ICSI = 'urn:urn-7:3gpp-service.ims.icsi.mcptt'


# ------------------------------------------------------------------------------
def main():
    """Send the conforming and malformed group and profile documents and check each answer (XS-00 to XS-20); write
    xcap-schema.json.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-groups')
    args = parser.parse_args()
    if args.project == 'openmcx':
        parser.error('this scenario requires a separate test project')
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    generated = args.compose.resolve().parent / 'generated'
    configs = {role: json.loads((generated / f'{role}.json').read_text()) for role in ['client-a', 'client-b']}
    ids = {role: config['mcptt']['user_id'] for role, config in configs.items()}
    cfg = configs['client-a']
    domain = cfg['mcptt']['group_id'].split('@')[1]
    gms, cms = cfg['endpoints']['gms'], cfg['endpoints']['cms']

    # ------------------------------------------------------------------------------
    def quote(text):
        """Percent-encode text for one XCAP path segment."""
        return url_quote(text, safe='')

    tree = f"{gms}/xcap-root/org.openmobilealliance.groups/users/{quote(ids['client-a'])}/"
    profile_b = f"{cms}/xcap-root/org.3gpp.mcptt.user-profile/users/{quote(ids['client-b'])}/mcptt-user-profile-1.xml"
    profile_a = f"{cms}/xcap-root/org.3gpp.mcptt.user-profile/users/{quote(ids['client-a'])}/mcptt-user-profile-1.xml"
    squad = f'sip:schema-{int(time.time()) % 100000}@{domain}'
    checks, observations = [], {}
    result = dict(scenario='xcap-schema', passed=False, checks=checks, observations=observations)

    # ------------------------------------------------------------------------------
    def status(role):
        """The role's status.json, or an empty dict while it is missing or half written."""
        try:
            return json.loads((args.artifacts / role / 'status.json').read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    # ------------------------------------------------------------------------------
    def probe(requests):
        """Run the XCAP requests from client-a's container, signed in as client-a; the answers (status, content type,
        ETag, body).
        """
        run = subprocess.run(
            cli + ['exec', '-T', 'client-a', 'python3', '-c', PROBE, '/config/client-a.json', json.dumps(requests)],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if run.returncode:
            raise RuntimeError(f'probe: {run.stderr.strip()[-2000:]}')
        return json.loads(run.stdout.strip().splitlines()[-1])

    # ------------------------------------------------------------------------------
    def check(label, condition, detail=None):
        """Record label if condition holds, else raise with detail."""
        if not condition:
            raise AssertionError(label + ' failed: ' + json.dumps(detail)[:4000])
        checks.append(label)
        print(label, flush=True)

    # ------------------------------------------------------------------------------
    def group(inner, uri=None):
        """A group document whose list-service (uri, or the test group) holds inner."""
        return (
            '<?xml version="1.0" encoding="UTF-8"?><group xmlns="urn:oma:xml:poc:list-service"'
            ' xmlns:gi="urn:3gpp:ns:mcpttGroupInfo:1.0" xmlns:cp="urn:ietf:params:xml:ns:common-policy"'
            f' xmlns:oxe="urn:oma:xml:xdm:extensions"><list-service uri="{uri or squad}">{inner}</list-service></group>'
        )

    valid = (
        f'<list><entry uri="{ids["client-a"]}"><gi:user-priority>3</gi:user-priority></entry></list>'
        '<cp:ruleset><cp:rule id="members"><cp:conditions><is-list-member/></cp:conditions><cp:actions>'
        '<gi:on-network-allow-getting-member-list>true</gi:on-network-allow-getting-member-list></cp:actions></cp:rule></cp:ruleset>'
        f'<oxe:supported-services><oxe:service enabler="{MCPTT_ICSI}"><oxe:group-media><gi:mcptt-speech/></oxe:group-media>'
        '</oxe:service></oxe:supported-services><gi:protect-media>false</gi:protect-media>'
    )
    entry_url = f"{gms}/xcap-root/org.openmobilealliance.groups/global/byGroupID/{quote(squad)}/~~/" + quote(
        f'group/list-service/list/entry[@uri="{ids["client-b"]}"]'
    )
    # Each case: ID and label, request, expected status, a text the body must hold.
    group_cases = [
        (
            'XS-01 a conforming group document is created: 201',
            ['PUT', tree + 'schema', GROUP_MIME, group(valid)],
            201,
            '',
        ),
        (
            'XS-02 a body that is not well-formed: 409 <not-well-formed>',
            ['PUT', tree + 'bad', GROUP_MIME, '<group xmlns="urn:oma:xml:poc:list-service"><list-service>'],
            409,
            '<not-well-formed',
        ),
        (
            'XS-03 an <entry-ref> (OMA 5.1.6): 409 <schema-validation-error>',
            ['PUT', tree + 'bad', GROUP_MIME, group('<list><entry-ref ref="x"/></list>')],
            409,
            '<schema-validation-error',
        ),
        (
            'XS-04 an MCS element with an invalid value: 409 <schema-validation-error>',
            ['PUT', tree + 'bad', GROUP_MIME, group('<gi:protect-media>sometimes</gi:protect-media>')],
            409,
            '<schema-validation-error',
        ),
        (
            'XS-05 an element the mcpttGroupInfo schema does not define: 409 <schema-validation-error>',
            ['PUT', tree + 'bad', GROUP_MIME, group('<gi:on-network-colour>red</gi:on-network-colour>')],
            409,
            '<schema-validation-error',
        ),
        (
            'XS-06 elements of the list-service out of schema order: 409 <schema-validation-error>',
            ['PUT', tree + 'bad', GROUP_MIME, group('<max-participant-count>3</max-participant-count><list/>')],
            409,
            '<schema-validation-error',
        ),
        (
            'XS-07 two <list-service> elements: 409 <constraint-failure> (OMA 5.1.6)',
            [
                'PUT',
                tree + 'bad',
                GROUP_MIME,
                group('').replace('</group>', f'<list-service uri="sip:other@{domain}"/></group>'),
            ],
            409,
            'No more than one list-service element allowed',
        ),
        (
            'XS-08 a duplicate <entry>: 409 <constraint-failure> "Duplicate entry"',
            [
                'PUT',
                tree + 'bad',
                GROUP_MIME,
                group(f'<list><entry uri="{ids["client-a"]}"/><entry uri="{ids["client-a"]}"/></list>'),
            ],
            409,
            'Duplicate entry',
        ),
        (
            'XS-09 a rule with two identity conditions: 409 <constraint-failure> "Complex rules are not allowed"',
            [
                'PUT',
                tree + 'bad',
                GROUP_MIME,
                group(
                    '<cp:ruleset><cp:rule id="r"><cp:conditions><is-list-member/><cp:identity>'
                    f'<cp:one id="{ids["client-b"]}"/></cp:identity></cp:conditions></cp:rule></cp:ruleset>'
                ),
            ],
            409,
            'Complex rules are not allowed',
        ),
        (
            'XS-10 an element PUT whose result does not conform: 409 <schema-validation-error>',
            [
                'PUT',
                entry_url,
                'application/xcap-el+xml',
                f'<entry xmlns="urn:oma:xml:poc:list-service" uri="{ids["client-b"]}">'
                '<user-priority xmlns="urn:3gpp:ns:mcpttGroupInfo:1.0">high</user-priority></entry>',
            ],
            409,
            '<schema-validation-error',
        ),
        (
            'XS-11 a GMOP document that does not conform (TS 24.481 7.3.3): 409 <schema-validation-error>',
            [
                'POST',
                tree + 'temporary',
                GMOP_MIME,
                '<?xml version="1.0"?><document xmlns="urn:3gpp:ns:mcpttGMOP:1.0"><request>'
                '<group-regroup-creation><group xmlns="urn:oma:xml:poc:list-service"/></group-regroup-creation>'
                '</request></document>',
            ],
            409,
            '<schema-validation-error',
        ),
        (
            'XS-12 the conforming element is added: 201',
            [
                'PUT',
                entry_url,
                'application/xcap-el+xml',
                f'<entry xmlns="urn:oma:xml:poc:list-service" uri="{ids["client-b"]}"/>',
            ],
            201,
            '',
        ),
        ('XS-12 the conforming document is deleted: 200', ['DELETE', tree + 'schema', None, None], 200, ''),
    ]
    try:
        for _ in range(100):
            if status('client-a').get('authorized') and status('client-b').get('authorized'):
                break
            time.sleep(0.4)
        # A GMS or CMS whose lab documents do not conform to the schemas stops at start-up (TS 24.481 clauses 7.2.4
        # and 7.2.7, TS 24.484 clauses 8.3.2.3 and 8.3.2.6): both must answer, the GMS for a document of the user's
        # own tree (there or not yet) and the CMS with the user's profile.
        gms_answer, cms_answer = probe([['GET', tree + 'schema', None, None], ['GET', profile_a, None, None]])
        check(
            'XS-00 the GMS and CMS started with the lab documents, which they checked against the schemas, and the clients are authorised',
            status('client-a').get('authorized')
            and status('client-b').get('authorized')
            and gms_answer['status'] in (200, 404)
            and cms_answer['status'] == 200,
            dict(gms=gms_answer, cms=cms_answer),
        )
        replies = probe([case[1] for case in group_cases])
        observations['group'] = {
            case[0][:5] + str(index): {'status': reply['status'], 'body': reply['body'][:300]}
            for index, (case, reply) in enumerate(zip(group_cases, replies))
        }
        for (label, _, want, text), reply in zip(group_cases, replies):
            error = want == 409
            check(
                label,
                reply['status'] == want
                and text in reply['body']
                and (not error or reply['content_type'].startswith('application/xcap-error+xml')),
                reply,
            )

        # The user profile documents (TS 24.484 clause 8.3).
        own, current = probe([['GET', profile_a, None, None], ['GET', profile_b, None, None]])
        check(
            'XS-13 the CMS serves the user profile with its MIME type, namespace and XUI-URI (8.3.2.4, 8.3.2.5)',
            own['status'] == 200
            and own['content_type'].startswith(PROFILE_MIME)
            and 'xmlns="urn:3gpp:mcptt:user-profile:1.0"' in own['body']
            and f'XUI-URI="{ids["client-a"]}"' in own['body'],
            own,
        )
        body = current['body']
        check(
            'XS-13 client-b\'s profile is readable by the administrator',
            current['status'] == 200 and '</mcptt-user-profile>' in body,
            current,
        )
        named = body.replace('</mcptt-user-profile>', '<Name>client b</Name></mcptt-user-profile>')
        profile_cases = [
            (
                'XS-14 a profile with another MIME type: 415',
                ['PUT', profile_b, 'application/xcap-el+xml', named],
                415,
                '',
            ),
            (
                'XS-15 a profile that is not well-formed: 409 <not-well-formed>',
                ['PUT', profile_b, PROFILE_MIME, body[: len(body) // 2]],
                409,
                '<not-well-formed',
            ),
            (
                'XS-16 a profile with an invalid <Status>: 409 <schema-validation-error>',
                ['PUT', profile_b, PROFILE_MIME, named.replace('<Status>true</Status>', '<Status>maybe</Status>')],
                409,
                '<schema-validation-error',
            ),
            (
                'XS-17 a profile with an element the schema does not define: 409 <schema-validation-error>',
                ['PUT', profile_b, PROFILE_MIME, named.replace('<Name>client b</Name>', '<Colour>blue</Colour>')],
                409,
                '<schema-validation-error',
            ),
            (
                'XS-18 a profile of another user: 409 <constraint-failure> "Wrong User Profile URI" (8.3.2.6)',
                [
                    'PUT',
                    profile_b,
                    PROFILE_MIME,
                    named.replace(f'XUI-URI="{ids["client-b"]}"', f'XUI-URI="{ids["client-a"]}"'),
                ],
                409,
                'Wrong User Profile URI',
            ),
            (
                'XS-19 a group call <Priority> above 255: 409 <constraint-failure> "Priority value out of range" (8.3.2.6)',
                [
                    'PUT',
                    profile_b,
                    PROFILE_MIME,
                    named.replace(
                        '<Name>client b</Name>',
                        '<Common><MCPTT-group-call><Priority>300</Priority></MCPTT-group-call></Common>',
                    ),
                ],
                409,
                'Priority value out of range',
            ),
            ('XS-20 the conforming profile is accepted: 200', ['PUT', profile_b, PROFILE_MIME, named], 200, ''),
        ]
        replies = probe([case[1] for case in profile_cases])
        observations['profile'] = [{'status': reply['status'], 'body': reply['body'][:300]} for reply in replies]
        for (label, _, want, text), reply in zip(profile_cases, replies):
            check(
                label,
                reply['status'] == want
                and text in reply['body']
                and (want != 409 or reply['content_type'].startswith('application/xcap-error+xml')),
                reply,
            )
        result['passed'] = True
    except Exception as failure:
        result['error'] = str(failure)
        print(str(failure)[:3000], flush=True)
    finally:
        (args.artifacts / 'xcap-schema.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(dict(scenario=result['scenario'], passed=result['passed'], checks=len(checks))))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())

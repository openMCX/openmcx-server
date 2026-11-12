#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""A received request protected under an XPK-ID the MC client does not hold is refused.

TS 24.379 clause 6.6.1.4: the receiver verifies, then decrypts, before any other procedure. The XPK of clause 6.6.3.4.2
step 4 cannot be obtained for an XPK-ID the receiver does not hold, so the signature validation fails and step 5 sends
403 with "139 integrity protection check failed"; the decryption of clause 6.6.2.4.2 step 2 fails and step 3 sends 403
with "140 unable to decrypt XML content". The request is not processed.

Run against a fixture prepared with prepare-prearranged-test.py --protected --key-parameters-iei N --xml-protection:
once client-a is authorised, client-b's container opens a TLS connection to client-a's SIP port (with client-b's lab
certificate; in clear in a debug TCP lab) and sends two MESSAGE requests whose mcptt-info is signed (XK-01) or has an
element encrypted (XK-02) under an XPK-ID other than client-a's CSK-IDs; the refusal comes before any key is used, so
the signature and cipher values are placeholders. Checks: each answered 403 with the warning, client-a's refused counter up by two, client-a
still authorised (XK-03). The check IDs match tests/mcptt/XML_PROTECTION_TEST.md.

Specifications: TS 24.379 V19.8.0 (Rel-19), TS 33.180 V19.5.0 (Rel-19).
"""

import argparse
import base64
import json
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]

# The sender: runs in client-b's container, prints the status line and the Warning header field of the answer.
SENDER = r'''
import json, socket, ssl, sys
target, port, clear, request = json.loads(sys.argv[1])
context = ssl.create_default_context(cafile="/config/tls/ca.crt")
context.check_hostname = False
context.load_cert_chain("/config/tls/client-b.crt", "/config/tls/client-b.key")
with socket.create_connection((target, port), timeout=10) as raw, (raw if clear else context.wrap_socket(raw)) as tls:
    tls.sendall(request.encode())
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = tls.recv(4096)
        if not chunk:
            break
        data += chunk
    lines = data.split(b"\r\n\r\n")[0].decode(errors="replace").split("\r\n")
    print(json.dumps({"status": lines[0], "warning": [l.split(":", 1)[1].strip() for l in lines[1:]
                                                       if l.lower().startswith("warning:")]}))
'''


# ------------------------------------------------------------------------------
def key_name(xpk_id):
    """TS 24.379 annex F.1.3 and F.6.3: the base64 encoded XPK-ID of a ds:KeyName."""
    return base64.b64encode(xpk_id.to_bytes(4, 'big')).decode()


# ------------------------------------------------------------------------------
def request(target, number, parts, clear=False):
    """A MESSAGE from the MCPTT server's PSI to alice, its multipart/mixed body of parts (type, body, content id)."""
    boundary = 'xk-boundary'
    body = ''
    for content_type, text, content_id in parts:
        body += f'--{boundary}\r\nContent-Type: {content_type}\r\n'
        if content_id:
            body += f'Content-ID: <{content_id}>\r\n'
        body += f'\r\n{text}\r\n'
    body += f'--{boundary}--\r\n'
    return (
        f'MESSAGE sip:alice@{target};transport={"tcp" if clear else "tls"} SIP/2.0\r\n'
        f'Via: SIP/2.0/{"TCP" if clear else "TLS"} client-b:{5060 if clear else 5061};branch=z9hG4bKxk{number}'
        f'{int(time.time())}\r\n'
        'Max-Forwards: 70\r\n'
        f'From: <sip:mcptt@mcx.test>;tag=xk{number}\r\n'
        'To: <sip:alice@mcx.test>\r\n'
        f'Call-ID: xk{number}-{int(time.time())}@client-b\r\n'
        f'CSeq: 1 MESSAGE\r\n'
        f'Content-Type: multipart/mixed;boundary={boundary}\r\n'
        f'Content-Length: {len(body.encode())}\r\n\r\n' + body
    )


# ------------------------------------------------------------------------------
def main():
    """Run the checks XK-00 to XK-03 and write xml-unknown-key.json."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--project', default='openmcx-xml')
    args = parser.parse_args()
    cli = [str(ROOT / '.cache/deps/docker-compose-linux-x86_64'), '-p', args.project, '-f', str(args.compose.resolve())]
    generated = args.compose.resolve().parent / 'generated'
    sip = json.loads((generated / 'client-a.json').read_text())['sip']
    checks = []
    result = dict(scenario='xml-unknown-key', passed=False, checks=checks)

    # ------------------------------------------------------------------------------
    def status(role):
        """The role's status.json, or an empty dict while it is missing or half written."""
        try:
            return json.loads((args.artifacts / role / 'status.json').read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    # ------------------------------------------------------------------------------
    def refused():
        """client-a's count of refused protected content."""
        return (status('client-a').get('xml_protection') or {}).get('refused', 0)

    # ------------------------------------------------------------------------------
    def wait(label, predicate, timeout=30):
        """Poll predicate every 0.2 s until it holds (record label) or timeout seconds pass (raise)."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                checks.append(label)
                print(label, flush=True)
                return
            time.sleep(0.2)
        raise AssertionError(label + ' timed out: ' + json.dumps(status('client-a'))[:3000])

    # ------------------------------------------------------------------------------
    def send(number, parts):
        """Send one request to client-a from client-b's container; its answer's status line and warnings. In a debug
        TCP lab (mcx-client --disable-tls) the client listens in clear on sip.debug_port (default 5060), else over TLS
        on sip.port (src/common/runtime.cpp sip_config)."""
        clear = status('client-a').get('sip_transport') == 'tcp'
        port = sip.get('debug_port', 5060) if clear else sip['port']
        run = subprocess.run(
            cli + ['exec', '-T', 'client-b', 'python3', '-c', SENDER,
                   json.dumps(['client-a', port, clear, request('client-a', number, parts, clear)])],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if run.returncode:
            raise RuntimeError(f'sender: {run.stderr.strip() or run.stdout.strip()}')
        return json.loads(run.stdout.strip().splitlines()[-1])

    # ------------------------------------------------------------------------------
    def refusal(label, answer, code):
        """The answer is 403 with the warning code."""
        if not (answer['status'].startswith('SIP/2.0 403') and any(f'"{code} ' in w for w in answer['warning'])):
            raise AssertionError(f'{label}: answered {answer}')
        checks.append(label)
        print(label, flush=True)

    try:
        wait(
            'XK-00 client-a is authorised with XML protection enabled',
            lambda: status('client-a').get('authorized') and (status('client-a').get('xml_protection') or {}).get(
                'enabled'),
            120,
        )
        before = refused()
        # An XPK-ID none of client-a's CSKs has (a CSK-ID is random, TS 33.180 clause 9.2.1.1).
        unknown = key_name(0x2ABCDEF1)
        info = ('<mcpttinfo xmlns="urn:3gpp:ns:mcpttInfo:1.0"><mcptt-Params>'
                '<mcptt-calling-user-id type="Normal"><mcpttURI>sip:bob.mcptt@mcx.test</mcpttURI>'
                '</mcptt-calling-user-id></mcptt-Params></mcpttinfo>')
        signatures = (
            '<signatures xmlns="urn:3gpp:ns:mcpttSignedDoc:1.0">'
            '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
            '<ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
            '<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"/>'
            '<ds:Reference URI="cid:i@xk"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>'
            '<ds:DigestValue>AAAA</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>AAAA'
            f'</ds:SignatureValue><ds:KeyInfo><ds:KeyName>{unknown}</ds:KeyName></ds:KeyInfo></ds:Signature>'
            '</signatures>')
        refusal('XK-01 signed under an unknown XPK-ID: 403 with warning 139',
                send(1, [('application/vnd.3gpp.mcptt-info+xml', info, 'i@xk'),
                         ('application/vnd.3gpp.mcptt-signed+xml', signatures, '')]), 139)
        encrypted = info.replace(
            '<mcptt-calling-user-id type="Normal"><mcpttURI>sip:bob.mcptt@mcx.test</mcpttURI>',
            '<mcptt-calling-user-id type="Encrypted">'
            '<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" '
            'Type="http://www.w3.org/2001/04/xmlenc#Content"><xenc:EncryptionMethod '
            'Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><ds:KeyInfo '
            f'xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:KeyName>{unknown}</ds:KeyName></ds:KeyInfo>'
            '<xenc:CipherData><xenc:CipherValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA</xenc:CipherValue></xenc:CipherData>'
            '</xenc:EncryptedData>')
        refusal('XK-02 element encrypted under an unknown XPK-ID: 403 with warning 140',
                send(2, [('application/vnd.3gpp.mcptt-info+xml', encrypted, ''),
                         ('application/resource-lists+xml',
                          '<resource-lists xmlns="urn:ietf:params:xml:ns:resource-lists"/>', '')]), 140)
        wait('XK-03 client-a counted both refusals and stays authorised',
             lambda: refused() >= before + 2 and status('client-a').get('authorized'), 10)
        result['passed'] = True
    except Exception as error:
        result['error'] = str(error)
        print(str(error)[:3000], flush=True)
    finally:
        (args.artifacts / 'xml-unknown-key.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(dict(scenario=result['scenario'], passed=result['passed'], checks=len(checks))))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())

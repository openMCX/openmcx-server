#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""What alice, the administrator, does in MCX Admin, and what erin does with the link alice gives her.

run.sh runs it with python3 in client-a's container (alice's own computer), on the lab network:

  admin.py create-erin                 alice creates the user erin, with bob's rights   -> revision
  admin.py password-link               alice gets erin a one-time set-password link     -> the link
  admin.py set-password LINK PASSWORD  erin opens the link and sets her password        -> HTTP status
  admin.py activation                  alice issues erin's activation URL (and QR code) -> the URL
  admin.py fetch URL                   the HTTP status of a GET of the URL

alice signs in at IdMS with the OpenID Connect authorisation code flow and PKCE of TS 33.180 annex B.4.2 (her user
name and password from client-a's configuration), then calls MCX Admin's REST API with the access token. All of it is
HTTPS, to https://idms:8443 and https://mcxadmin:8443, with the lab's CA.
"""

import base64
import hashlib
import json
import secrets
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

IDMS = 'https://idms:8443'
ADMIN = 'https://mcxadmin:8443'
CONFIG = '/config/client-a.json'
CA = '/config/tls/ca.crt'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Follow no redirect: the sign-in reads the 302 and its Location itself."""

    def redirect_request(self, *args, **kwargs):
        return None


opener = urllib.request.build_opener(
    urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=CA)), NoRedirect
)


def request(method, url, data=None, headers=None):
    """One HTTPS request: (status, lower-case headers, body), also for an error status."""
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        with opener.open(req, timeout=15) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read()
    except urllib.error.HTTPError as error:
        return error.code, {k.lower(): v for k, v in error.headers.items()}, error.read()


def form(data):
    return urllib.parse.urlencode(data).encode()


def sign_in():
    """alice's access token: authorize, post her credentials, exchange the code (TS 33.180 annex B.4.2)."""
    oauth = json.load(open(CONFIG))['oauth']
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
    query = urllib.parse.urlencode(
        dict(response_type='code', client_id=oauth['client_id'], redirect_uri=oauth['redirect_uri'], scope='openid',
             state='s1', nonce='n1', code_challenge=challenge, code_challenge_method='S256'))
    status, _, body = request('GET', f'{IDMS}/authorize?{query}')
    assert status == 200, f'authorize: {status}'
    urlencoded = {'Content-Type': 'application/x-www-form-urlencoded'}
    status, headers, _ = request(
        'POST', f'{IDMS}/login',
        form(dict(request_id=json.loads(body)['request_id'], username=oauth['username'], password=oauth['password'])),
        urlencoded)
    assert status == 302, f'login: {status}'
    code = urllib.parse.parse_qs(urllib.parse.urlparse(headers['location']).query)['code'][0]
    status, _, body = request(
        'POST', f'{IDMS}/token',
        form(dict(grant_type='authorization_code', code=code, client_id=oauth['client_id'],
                  redirect_uri=oauth['redirect_uri'], code_verifier=verifier)),
        urlencoded)
    assert status == 200, f'token: {status}'
    return json.loads(body)['access_token']


def api(token, method, path, if_match=None, body=None):
    """MCX Admin's REST API with the bearer token: (status, entity tag, JSON body)."""
    headers = {'Authorization': f'Bearer {token}'}
    if if_match:
        headers['If-Match'] = f'"{if_match}"'
    if body is not None:
        headers['Content-Type'] = 'application/json'
    data = json.dumps(body).encode() if body is not None else (b'' if method in ('POST', 'PUT') else None)
    status, headers, raw = request(method, ADMIN + path, data, headers)
    return status, headers.get('etag', '').strip('"'), json.loads(raw) if raw else None


def create_erin():
    """erin: a new user with bob's profile and rights, her own identities and client ID, no group."""
    token = sign_in()
    status, etag, config = api(token, 'GET', '/v1/config')
    assert status == 200, f'GET /v1/config: {status}'
    domain = config['system']['domain']
    erin = dict(next(user for user in config['users'] if user['login'] == 'bob'))
    erin.update(login='erin', display_name='Erin', status='active', mc_id=f'sip:erin.mc@{domain}',
                mcptt_id=f'sip:erin.mcptt@{domain}', sip_uri=f'sip:erin@{domain}',
                client_ids=['urn:uuid:5d3c9a1e-6f0b-4c1e-9a55-0000000000e5'], groups=[])
    for key in ('mcdata_id', 'mcvideo_id', 'email'):
        erin.pop(key, None)
    status, etag, _ = api(token, 'PUT', '/v1/users/erin', etag, erin)
    assert status == 200, f'PUT /v1/users/erin: {status}'
    return f'revision {etag}'


def password_link():
    status, _, body = api(sign_in(), 'POST', '/v1/users/erin/password-link')
    assert status == 200, f'password-link: {status}'
    return body['url']


def set_password(link, password):
    """erin opens the one-time link (IdMS's form) and posts her new password twice."""
    status, _, _ = request('GET', link)
    if status != 200:
        return status
    parsed = urllib.parse.urlparse(link)
    token = urllib.parse.parse_qs(parsed.query)['token'][0]
    status, _, _ = request(
        'POST', f'{parsed.scheme}://{parsed.netloc}{parsed.path}',
        form(dict(token=token, password=password, confirm=password)),
        {'Content-Type': 'application/x-www-form-urlencoded'})
    return status


def activation():
    """The activation URL; MCX Admin gives the same URL as a QR code (PNG) for a phone's camera."""
    status, _, body = api(sign_in(), 'POST', '/v1/users/erin/activation')
    assert status == 200 and base64.b64decode(body['qr_png']).startswith(b'\x89PNG'), f'activation: {status}'
    return body['url']


def fetch(url):
    return request('GET', url)[0]


if __name__ == '__main__':
    command, *words = sys.argv[1:]
    print({'create-erin': create_erin, 'password-link': password_link, 'set-password': set_password,
           'activation': activation, 'fetch': fetch}[command](*words))

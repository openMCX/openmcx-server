#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Inside an admin lab's network: sign in at IdMS as a user and call MCX Admin.

Run in a container on the lab network with the lab's CA (admin_scenario.py does):
  admin_helper.py login <user> <password> <client_id> <redirect_uri>      -> {"status": ..., "token": ...}
  admin_helper.py api <token> <METHOD> <path> [if-match] [json-body]       -> {"status": ..., "etag": ..., "body": ...}
  admin_helper.py internal <client_id> <secret> <url>                      -> {"status": ..., "body": ...}
  admin_helper.py set-password <link> <password>                           -> {"status": ...}
  admin_helper.py fetch <url>                                              -> {"status": ...}
  admin_helper.py console <user> <password>                                -> the console's sign-in, step by step
  admin_helper.py xcap <token> <METHOD> <url> [content-type] [body]         -> {"status": ..., "body": ...} (TS 24.481)
It prints one JSON line. The IdMS is https://idms:8443, MCX Admin https://mcxadmin:8443.

The sign-in is the OpenID Connect authorisation code flow with PKCE of TS 33.180 annex B.4.2
(the identity management client of TS 24.482 clause 6.2.1); the rest is MCX Admin's own REST API
and the XCAP access of TS 24.481.

Specifications: TS 33.180 V19.4.0 (Rel-19), TS 24.482 V19.1.0 (Rel-19), TS 24.481 V19.3.0 (Rel-19).
"""

import base64
import hashlib
import html
import json
import secrets
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

CA = '/ca.crt'
IDMS = 'https://idms:8443'
ADMIN = 'https://mcxadmin:8443'
context = ssl.create_default_context(cafile=CA)


# ------------------------------------------------------------------------------
class NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect handler that follows no redirect, so that a 302 and its Location reach the caller."""

    # ------------------------------------------------------------------------------
    def redirect_request(self, *args, **kwargs):
        """Follow no redirect."""
        return None


opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), NoRedirect)


# ------------------------------------------------------------------------------
def request(method, url, data=None, headers=None):
    """One HTTPS request, no redirect followed: (status, lower-case headers, body), also for an error status."""
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        with opener.open(req, timeout=15) as resp:
            return resp.status, {key.lower(): value for key, value in resp.headers.items()}, resp.read()
    except urllib.error.HTTPError as error:
        return error.code, {key.lower(): value for key, value in error.headers.items()}, error.read()


# ------------------------------------------------------------------------------
def login(user, password, client_id, redirect_uri, scope='openid'):
    """Sign in at IdMS with the authorisation code flow and PKCE (TS 33.180 annex B.4.2.2 to B.4.2.5):
    authorize with the scope, post the user's credentials, then exchange the code for an access token."""
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
    query = urllib.parse.urlencode(
        dict(
            response_type='code',
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            state='s1',
            nonce='n1',
            code_challenge=challenge,
            code_challenge_method='S256',
        )
    )
    status, _, body = request('GET', f'{IDMS}/authorize?{query}')
    if status != 200:
        return dict(status=status, stage='authorize')
    form = urllib.parse.urlencode(
        dict(request_id=json.loads(body)['request_id'], username=user, password=password)
    ).encode()
    status, headers, _ = request('POST', f'{IDMS}/login', form, {'Content-Type': 'application/x-www-form-urlencoded'})
    if status != 302:
        return dict(status=status, stage='login')
    code = urllib.parse.parse_qs(urllib.parse.urlparse(headers['location']).query)['code'][0]
    form = urllib.parse.urlencode(
        dict(
            grant_type='authorization_code',
            code=code,
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_verifier=verifier,
        )
    ).encode()
    status, _, body = request('POST', f'{IDMS}/token', form, {'Content-Type': 'application/x-www-form-urlencoded'})
    return dict(status=status, stage='token', token=json.loads(body).get('access_token') if status == 200 else None)


# ------------------------------------------------------------------------------
def api(token, method, path, if_match=None, data=None):
    """Call the MCX Admin REST API with the bearer token: status, entity tag and JSON (or text) body."""
    headers = {'Authorization': f'Bearer {token}'}
    if if_match:
        headers['If-Match'] = f'"{if_match}"'
    if data is not None:
        headers['Content-Type'] = 'application/json'
    body = data.encode() if data is not None else (b'' if method in ('POST', 'PUT') else None)
    status, response_headers, body = request(method, ADMIN + path, body, headers)
    try:
        parsed = json.loads(body)
    except ValueError:
        parsed = body.decode(errors='replace')[:200]
    return dict(status=status, etag=response_headers.get('etag', '').strip('"'), body=parsed)


# ------------------------------------------------------------------------------
def internal(client_id, secret, url):
    """Call an internal MCX Admin URL with HTTP basic client credentials: status and JSON body."""
    auth = base64.b64encode(f'{client_id}:{secret}'.encode()).decode()
    status, _, body = request('GET', url, None, {'Authorization': f'Basic {auth}'})
    try:
        parsed = json.loads(body)
    except ValueError:
        parsed = None
    return dict(status=status, body=parsed)


# ------------------------------------------------------------------------------
def set_password(link, password):
    """Follow a one-time set-password link of IdMS as its user would."""
    status, _, _ = request('GET', link)
    if status != 200:
        return dict(status=status, stage='form')
    parsed = urllib.parse.urlparse(link)
    token = urllib.parse.parse_qs(parsed.query)['token'][0]
    form = urllib.parse.urlencode(dict(token=token, password=password, confirm=password)).encode()
    status, _, _ = request(
        'POST',
        f'{parsed.scheme}://{parsed.netloc}{parsed.path}',
        form,
        {'Content-Type': 'application/x-www-form-urlencoded'},
    )
    return dict(status=status, stage='set')


# ------------------------------------------------------------------------------
def browse(method, url, cookies=None, data=None, accept='text/html'):
    """One browser request, no redirect followed: status, Location, cookies set, body."""
    headers = {'Accept': accept}
    if cookies:
        headers['Cookie'] = '; '.join(f'{key}={value}' for key, value in cookies.items())
    if data is not None:
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
        data = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        resp = opener.open(req, timeout=15)
    except urllib.error.HTTPError as error:
        resp = error
    set_cookies = {}
    for line in resp.headers.get_all('Set-Cookie') or []:
        name, _, rest = line.partition('=')
        set_cookies[name.strip()] = dict(value=rest.split(';', 1)[0], attrs=rest.lower())
    return dict(
        status=resp.status if hasattr(resp, 'status') else resp.code,
        location=resp.headers.get('Location', ''),
        cookies=set_cookies,
        csp=resp.headers.get('Content-Security-Policy', ''),
        body=resp.read().decode(errors='replace'),
    )


# ------------------------------------------------------------------------------
def console_sign_in(user, password):
    """The console's sign-in as a browser does it; returns each step's result."""
    start = browse('GET', ADMIN + '/ui/login')
    login_cookie = start['cookies'].get('mcxadmin_login', {}).get('value', '')
    form = browse('GET', start['location'])
    # TS 37.579-1 table 5.3.2.3.2-5: the form's action URI (it carries the request) and its inputs user and password.
    marker = '<form action="'
    action = html.unescape(form['body'].split(marker, 1)[1].split('"', 1)[0]) if marker in form['body'] else ''
    request_id = 'request_id=' in action
    posted = browse('POST', urllib.parse.urljoin(start['location'], action), data=dict(user=user, password=password))
    back = (
        browse('GET', posted['location'], cookies={'mcxadmin_login': login_cookie})
        if posted['location'].startswith(ADMIN)
        else {}
    )
    session = back.get('cookies', {}).get('mcxadmin_session', {})
    return dict(
        start=start['status'],
        authorize=start['location'].split('?')[0],
        form=form['status'],
        request_id=bool(request_id),
        login=posted['status'],
        callback=posted['location'].split('?')[0],
        denied='error=access_denied' in posted['location'],
        landing=back.get('location', ''),
        session=session.get('value', ''),
        session_attrs=session.get('attrs', ''),
    )


# ------------------------------------------------------------------------------
def console(user, password):
    """The console's checks: the page and its Content-Security-Policy, a good and a wrong-password sign-in,
    the session's /v1/me and /v1/status, and a write without the CSRF header."""
    page = browse('GET', ADMIN + '/')
    good = console_sign_in(user, password)
    token = good.pop('session')
    cookies = {'mcxadmin_session': token}
    me = browse('GET', ADMIN + '/v1/me', cookies, accept='application/json')
    status = browse('GET', ADMIN + '/v1/status', cookies, accept='application/json')
    write = browse('POST', ADMIN + '/v1/users/nobody/suspend', cookies, accept='application/json')
    bad = console_sign_in(user, password + '-wrong')
    bad.pop('session')
    return dict(
        page=page['status'],
        page_logo='openMCX' in page['body'],
        page_csp="default-src 'self'" in page['csp'],
        signin=good,
        session=bool(token),
        me=json.loads(me['body']) if me['status'] == 200 else me['status'],
        status=json.loads(status['body']) if status['status'] == 200 else status['status'],
        write_without_header=write['status'],
        wrong_password=bad,
    )


# ------------------------------------------------------------------------------
def xcap(token, method, url, content_type=None, body=None):
    """An XCAP request (TS 24.481) with the bearer token: status and the first 500 characters of the body."""
    headers = {'Authorization': f'Bearer {token}'}
    if content_type:
        headers['Content-Type'] = content_type
    status, _, raw = request(method, url, body.encode() if body is not None else None, headers)
    return dict(status=status, body=raw.decode(errors='replace')[:500])


# ------------------------------------------------------------------------------
def fetch(url):
    """The status of a GET of the URL."""
    status, _, _ = request('GET', url)
    return dict(status=status)


if __name__ == '__main__':
    command, *rest = sys.argv[1:]
    print(
        json.dumps(
            {
                'login': login,
                'api': api,
                'internal': internal,
                'set-password': set_password,
                'fetch': fetch,
                'console': console,
                'xcap': xcap,
            }[command](*rest)
        )
    )

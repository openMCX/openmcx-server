#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

# Signs the clients of a Keycloak lab (tools/prepare-prearranged-test.py --keycloak) in on Keycloak's own login
# page, as their users would in a browser, and keeps each one's refresh token where the client reads it
# (oauth.refresh_token_file, in generated/refresh): the authorization code grant with PKCE of TS 33.180 annex B.4.2
# (the authentication request of table B.4.2.2-1, the token request of annex B.4.2.4). The clients then start with
# the refresh token grant (annex B.5) and never hold a password. Runs on the lab's network, after Keycloak and before
# the clients:
#
#   docker run --rm --network <project>_mcx -v <lab>:<lab> -v $PWD/tools:/tools openmcx-dev:0.1 \
#     python3 /tools/keycloak-sign-in.py <lab> [client ...]
#
# Specifications: TS 33.180 V19.4.0 (Rel-19), RFC 6749, RFC 7636, OpenID Connect Core 1.0.
"""Sign the clients of a Keycloak lab in on Keycloak's login page and keep their refresh tokens."""

import argparse
import base64
import hashlib
import html.parser
import http.cookiejar
import json
import secrets
import ssl
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


# ------------------------------------------------------------------------------
class LoginForm(html.parser.HTMLParser):
    """The action of Keycloak's login form (id kc-form-login)."""

    def __init__(self):
        super().__init__()
        self.action = None

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag == 'form' and attributes.get('id') == 'kc-form-login':
            self.action = attributes.get('action')


# ------------------------------------------------------------------------------
class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Stops at the redirect to the client's redirect URI, which carries the code."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# ------------------------------------------------------------------------------
def scope(cfg):
    """TS 33.180 table B.4.2.2-1: the scope the client asks for (client_rules.hpp oidc_scope)."""
    words = ['openid']
    for service, enabled in (('ptt', True), ('data', 'mcdata' in cfg), ('video', 'mcvideo' in cfg)):
        if enabled:
            words += [
                f'3gpp:mc:{service}_{kind}'
                for kind in ('service', 'config_management_service', 'group_management_service')
            ]
            if 'security' in cfg:
                words.append(f'3gpp:mc:{service}_key_management_service')
    return ' '.join(words)


# ------------------------------------------------------------------------------
def sign_in(cfg, password, username, context):
    """The code grant on Keycloak's login page: the refresh token and the nonce of the authentication."""
    oauth = cfg['oauth']
    jar = http.cookiejar.CookieJar()
    https = urllib.request.HTTPSHandler(context=context)
    browser = urllib.request.build_opener(https, urllib.request.HTTPCookieProcessor(jar), NoRedirect)
    discovery = json.load(browser.open(oauth['issuer'] + '/.well-known/openid-configuration'))
    state, nonce, verifier = (secrets.token_urlsafe(32) for _ in range(3))
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
    query = urllib.parse.urlencode(
        dict(
            response_type='code',
            client_id=oauth['client_id'],
            redirect_uri=oauth['redirect_uri'],
            scope=scope(cfg),
            state=state,
            nonce=nonce,
            acr_values='3gpp:acr:password',
            code_challenge=challenge,
            code_challenge_method='S256',
        )
    )
    form = LoginForm()
    form.feed(browser.open(discovery['authorization_endpoint'] + '?' + query).read().decode())
    if not form.action:
        raise RuntimeError('no login form on the authorization page')
    try:
        browser.open(form.action, urllib.parse.urlencode(dict(username=username, password=password)).encode())
        raise RuntimeError('the login did not redirect to the client')
    except urllib.error.HTTPError as answer:
        if answer.code not in (302, 303):
            raise
        location = answer.headers['Location']
    if not location.startswith(oauth['redirect_uri']):
        raise RuntimeError(f'login refused (back at {location[:80]})')
    params = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)
    if params.get('state') != [state] or 'code' not in params:
        raise RuntimeError(f'authorization response refused: {params}')
    tokens = json.load(
        browser.open(
            discovery['token_endpoint'],
            urllib.parse.urlencode(
                dict(
                    grant_type='authorization_code',
                    code=params['code'][0],
                    redirect_uri=oauth['redirect_uri'],
                    client_id=oauth['client_id'],
                    code_verifier=verifier,
                )
            ).encode(),
        )
    )
    return tokens['refresh_token'], nonce


# ------------------------------------------------------------------------------
def main():
    """Sign every client (or those named) in and write its refresh token file."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('lab', type=Path, help='the prepared lab directory')
    parser.add_argument('clients', nargs='*', help='the clients (default: all with a refresh token file)')
    args = parser.parse_args()
    gen = args.lab / 'generated'
    site = json.loads((gen / 'site.json').read_text())
    users = {user['mcptt_id']: user for user in site['users']}
    context = ssl.create_default_context(cafile=str(gen / 'tls/ca.crt'))
    names = args.clients or sorted(path.stem for path in gen.glob('client-*.json'))
    for name in names:
        cfg = json.loads((gen / f'{name}.json').read_text())
        target = cfg.get('oauth', {}).get('refresh_token_file')
        if not target:
            continue
        user = users[cfg['mcptt']['user_id']]
        refresh_token, nonce = sign_in(cfg, user['password'], user['username'], context)
        path = gen / 'refresh' / Path(target).name
        path.unlink(missing_ok=True)  # a file of an earlier sign-in, maybe the client's
        path.write_text(json.dumps(dict(refresh_token=refresh_token, nonce=nonce)) + '\n')
        path.chmod(0o666)  # the client's own user rewrites it with every refresh
        print(f'{name}: signed in as {user["username"]}')


if __name__ == '__main__':
    main()

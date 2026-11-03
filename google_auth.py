"""Sign in / sign up with Google for HawkEye Optical Clinic (OpenID Connect, authorization-code flow + PKCE).

Setup (see DEPLOY.md): create an OAuth client of type "Web application" in Google Cloud Console and set
    GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET
in .env. The authorised redirect URI to register is  <APP_BASE_URL>/auth/google/callback .
When GOOGLE_CLIENT_ID is empty the Google buttons are hidden and the routes refuse to run.

Only the standard library is used (urllib), so there is nothing extra to install.
"""
import base64
import hashlib
import json
import os
import secrets
import time
from urllib.error import URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth'
TOKEN_URL = 'https://oauth2.googleapis.com/token'
ISSUERS = ('https://accounts.google.com', 'accounts.google.com')
CLOCK_SKEW = 120   # seconds of leeway when checking the token's expiry


class GoogleAuthError(Exception):
    """Anything that stops a Google sign-in; the message is safe to log, never shown to the visitor."""


def client_id():
    return os.getenv('GOOGLE_CLIENT_ID', '').strip()


def client_secret():
    return os.getenv('GOOGLE_CLIENT_SECRET', '').strip()


# True when both the client id and secret are set in .env.
def configured():
    return bool(client_id() and client_secret())


def _b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode('ascii')


# Random values for one sign-in attempt: `state` stops cross-site forgery, `nonce` ties the ID token to this
# attempt, and the PKCE verifier/challenge pair stops a stolen authorization code from being redeemed.
def new_attempt():
    verifier = secrets.token_urlsafe(48)
    return {'state': secrets.token_urlsafe(24), 'nonce': secrets.token_urlsafe(24), 'verifier': verifier,
            'challenge': _b64url(hashlib.sha256(verifier.encode('ascii')).digest())}


# The Google address the visitor is sent to.
def authorize_url(attempt, redirect_uri):
    return AUTH_URL + '?' + urlencode({
        'client_id': client_id(), 'redirect_uri': redirect_uri, 'response_type': 'code',
        'scope': 'openid email profile', 'state': attempt['state'], 'nonce': attempt['nonce'],
        'code_challenge': attempt['challenge'], 'code_challenge_method': 'S256',
        'prompt': 'select_account',
    })


# Trades the one-time code Google sent back for the signed-in person's details (the ID token claims).
def exchange_code(code, verifier, redirect_uri, timeout=10):
    body = urlencode({'code': code, 'client_id': client_id(), 'client_secret': client_secret(),
                      'redirect_uri': redirect_uri, 'grant_type': 'authorization_code', 'code_verifier': verifier}).encode()
    req = Request(TOKEN_URL, data=body, headers={'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json'})
    try:
        with urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode('utf-8'))
    except URLError as exc:                    # also covers HTTPError (Google rejected the code)
        raise GoogleAuthError(f'token request failed: {exc}') from exc
    except (ValueError, OSError) as exc:
        raise GoogleAuthError(f'token response unreadable: {exc}') from exc
    token = payload.get('id_token')
    if not token:
        raise GoogleAuthError('token response had no id_token')
    return decode_id_token(token)


# Reads the claims out of the ID token. The token came straight from Google's token endpoint over HTTPS in
# the request above, which OpenID Connect Core (section 3.1.3.7) accepts in place of checking its signature.
# Never use this on a token that arrived through the browser.
def decode_id_token(token):
    try:
        part = token.split('.')[1]
        return json.loads(base64.urlsafe_b64decode(part + '=' * (-len(part) % 4)))
    except (IndexError, ValueError) as exc:
        raise GoogleAuthError('id_token is not a valid JWT') from exc


# Checks the claims belong to this app and this attempt, and that Google vouches for the email address.
# Returns (sub, email, name). Raises GoogleAuthError otherwise.
def validate_claims(claims, expected_nonce, now=None):
    now = time.time() if now is None else now
    if claims.get('iss') not in ISSUERS:
        raise GoogleAuthError('wrong issuer')
    aud = claims.get('aud')
    if client_id() not in (aud if isinstance(aud, list) else [aud]):
        raise GoogleAuthError('token was issued for a different app')
    if not isinstance(claims.get('exp'), (int, float)) or claims['exp'] + CLOCK_SKEW < now:
        raise GoogleAuthError('token expired')
    if not expected_nonce or not secrets.compare_digest(str(claims.get('nonce', '')).encode(), expected_nonce.encode()):
        raise GoogleAuthError('nonce mismatch')
    sub, email = str(claims.get('sub') or ''), str(claims.get('email') or '').strip().lower()
    if not sub or not email:
        raise GoogleAuthError('token has no subject or email')
    if claims.get('email_verified') not in (True, 'true'):
        raise GoogleAuthError('Google has not verified this email address')
    return sub, email, str(claims.get('name') or '').strip()

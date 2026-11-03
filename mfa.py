"""Two-step sign-in helpers for HawkEye Optical Clinic: authenticator-app codes (TOTP, RFC 6238) and
one-time backup codes. No database or Flask code lives here, so everything can be tested on its own.

    new_secret()                      random key to put in the authenticator app
    provisioning_uri(...)             otpauth:// link (what the QR code contains)
    qr_data_uri(text)                 QR image as a data: URI, or None if the optional 'segno' package is missing
    verify_totp(secret, code, last)   matching 30-second step number, or None
    new_backup_codes()                10 fresh one-time recovery codes
    hash_backup_code(user_id, code)   what is stored in the database for a backup code
"""
import base64
import hashlib
import hmac
import os
import secrets
import struct
import sys
import time
from urllib.parse import quote

# Use the 'segno' QR library bundled in ./vendor when it is not installed, so the QR code always works.
_VENDOR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vendor')
if os.path.isdir(_VENDOR) and _VENDOR not in sys.path:
    sys.path.append(_VENDOR)

PERIOD = 30          # seconds per code (the value every authenticator app assumes)
DIGITS = 6
WINDOW = 1           # also accept the previous/next step, to forgive small clock differences
BACKUP_COUNT = 10
_BACKUP_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'   # no 0/O/1/I, easy to read out and type
_BACKUP_LEN = 10


# A new random shared secret (160 bits, base32, the format authenticator apps expect).
def new_secret():
    return base64.b32encode(os.urandom(20)).decode('ascii').rstrip('=')


# Shows a secret in groups of four so it is easier to type by hand.
def pretty_secret(secret):
    return ' '.join(secret[i:i + 4] for i in range(0, len(secret), 4))


# The 6-digit code for one 30-second step number (RFC 4226 HOTP with the step as the counter).
def totp_at(secret, step):
    key = base64.b32decode(secret.upper() + '=' * (-len(secret) % 8))
    digest = hmac.new(key, struct.pack('>Q', step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    number = (struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** DIGITS)
    return f'{number:0{DIGITS}d}'


# Checks a typed code. Returns the step number it matched, or None. A step at or below last_step is refused,
# so the same code cannot be used twice (a shoulder-surfed or intercepted code is worthless once used).
def verify_totp(secret, code, last_step=None, now=None):
    code = ''.join(ch for ch in (code or '') if ch.isdigit())
    if len(code) != DIGITS or not secret:
        return None
    current = int((time.time() if now is None else now) // PERIOD)
    matched = None
    for step in range(current - WINDOW, current + WINDOW + 1):
        # compare every candidate (no early exit) so timing does not reveal which step was close
        if hmac.compare_digest(totp_at(secret, step), code) and (last_step is None or step > int(last_step)):
            matched = step
    return matched


# The otpauth:// link that authenticator apps read from the QR code.
def provisioning_uri(secret, account, issuer):
    label = quote(f'{issuer}:{account}', safe='')
    return f'otpauth://totp/{label}?secret={secret}&issuer={quote(issuer, safe="")}&algorithm=SHA1&digits={DIGITS}&period={PERIOD}'


# Turns text into a QR image (SVG data: URI). Uses 'segno' (installed, or the copy in ./vendor); if it still
# cannot load, returns None and the page falls back to showing the setup key for typing in by hand.
def qr_data_uri(text):
    try:
        import segno
        return segno.make(text, error='m').svg_data_uri(scale=5, border=2, dark='#000000', light='#ffffff')
    except Exception:
        return None


# Ten random one-time backup codes, shown as XXXXX-XXXXX.
def new_backup_codes(count=BACKUP_COUNT):
    return [''.join(secrets.choice(_BACKUP_ALPHABET) for _ in range(_BACKUP_LEN)) for _ in range(count)]


def format_backup_code(code):
    return f'{code[:5]}-{code[5:]}'


# Reduces whatever the person typed to the stored form: upper-case letters and digits only.
# Returns None unless it has the right length for a backup code.
def normalize_backup_code(raw):
    cleaned = ''.join(ch for ch in (raw or '').upper() if ch.isalnum())
    return cleaned if len(cleaned) == _BACKUP_LEN and all(ch in _BACKUP_ALPHABET for ch in cleaned) else None


# What is stored for a backup code: a slow, salted hash (the salt is the user id), never the code itself.
def hash_backup_code(user_id, code):
    return hashlib.pbkdf2_hmac('sha256', code.encode('ascii'), f'hawkeye-mfa-backup:{user_id}'.encode(), 100_000).hex()

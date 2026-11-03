"""Production hardening for HawkEye Optical Clinic.

Everything here is driven by environment variables (.env) so the same code runs on a laptop
(APP_ENV=development, the default) and on a live server (APP_ENV=production).

    validate_config()   refuse to start in production with unsafe settings
    harden(app)         security headers, optional reverse-proxy support, no-store caching
    setup_logging(app)  optional rotating log file
"""
import logging
import os
import secrets
from logging.handlers import RotatingFileHandler


# Reads a yes/no setting from the environment: "1", "true", "yes" or "on" mean True.
def _flag(name, default='false'):
    return os.getenv(name, default).strip().lower() in ('1', 'true', 'yes', 'on')


# True when APP_ENV=production, which switches on the strict safety checks.
def is_production():
    return os.getenv('APP_ENV', 'development').strip().lower() == 'production'


# Startup safety check: in production, stops the app (with a list of fixes) if the secret key,
# HTTPS cookies, base URL, database password or contact email are missing or unsafe.
def validate_config():
    """Raise RuntimeError listing every unsafe setting. Only enforced when APP_ENV=production."""
    if not is_production():
        return
    problems = []
    key = os.getenv('FLASK_SECRET_KEY') or os.getenv('SECRET_KEY') or ''
    if len(key) < 32:
        problems.append('FLASK_SECRET_KEY must be set to a random value of at least 32 characters '
                        '(python -c "import secrets; print(secrets.token_hex(32))").')
    if _flag('FLASK_DEBUG'):
        problems.append('FLASK_DEBUG must be false.')
    if _flag('SEED_DEMO_ACCOUNTS'):
        problems.append('SEED_DEMO_ACCOUNTS must be false (it creates accounts with well-known passwords).')
    if not _flag('COOKIE_SECURE'):
        problems.append('COOKIE_SECURE must be true (the site must be served over HTTPS).')
    if not os.getenv('APP_BASE_URL', '').strip().lower().startswith('https://'):
        problems.append('APP_BASE_URL must be your public https:// address (it is used in emailed links).')
    if not os.getenv('MYSQL_PASSWORD', ''):
        problems.append('MYSQL_PASSWORD is empty. Create a dedicated MySQL user with a strong password.')
    if not os.getenv('CLINIC_CONTACT_EMAIL', '').strip():
        problems.append('CLINIC_CONTACT_EMAIL must be set (shown on the Privacy Notice for patient requests).')
    if problems:
        raise RuntimeError('Unsafe production configuration:\n  - ' + '\n  - '.join(problems) +
                           '\nFix these in .env (see .env.production.example), then start again.')


# Returns the key used to sign sessions and email links; random per run if none is configured (dev only).
def secret_key():
    """Configured key, or (development only) a random per-process key."""
    key = os.getenv('FLASK_SECRET_KEY') or os.getenv('SECRET_KEY')
    return key or secrets.token_hex(32)


# Builds the Content-Security-Policy header: the browser may only load scripts, styles, images and fonts
# from this site (inline scripts need the per-request nonce).
def build_csp(nonce):
    # Only same-origin resources. Inline <script> is allowed solely with this request's nonce;
    # inline style attributes are used throughout the templates, so style-src keeps 'unsafe-inline'.
    # "Sign in with Google" posts a form to this site that is redirected to accounts.google.com; browsers check
    # form-action on that redirect too, so Google is allowed there (only when Google sign-in is configured).
    form_action = "form-action 'self'" + (" https://accounts.google.com" if os.getenv('GOOGLE_CLIENT_ID', '').strip() else "")
    return "; ".join([
        "default-src 'self'",
        f"script-src 'self' 'nonce-{nonce}'",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data:",
        "font-src 'self' data:",
        "connect-src 'self'",
        "object-src 'none'",
        "base-uri 'self'",
        form_action,
        "frame-ancestors 'none'",
    ])


# Adds security to the Flask app: reverse-proxy support, a CSP nonce for each request, and standard
# security headers (no framing, no MIME sniffing, HTTPS-only if enabled, no caching of patient pages).
def harden(app):
    """Attach security headers and (optionally) trust a reverse proxy."""
    from flask import g, request

    if _flag('TRUST_PROXY'):
        # Needed behind Nginx / Cloudflare / a PaaS router: makes request.remote_addr, https URLs and
        # secure cookies reflect the real visitor instead of the proxy.
        from werkzeug.middleware.proxy_fix import ProxyFix
        hops = max(1, int(os.getenv('PROXY_HOPS', '1')))
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=hops, x_proto=hops, x_host=hops)

    hsts = _flag('COOKIE_SECURE')

    # Runs before every request: creates a one-time nonce that lets this page's inline scripts run.
    @app.before_request
    def _csp_nonce():
        g.csp_nonce = secrets.token_urlsafe(16)

    # Makes csp_nonce() available inside templates.
    @app.context_processor
    def _inject_nonce():
        return {'csp_nonce': lambda: getattr(g, 'csp_nonce', '')}

    # Runs after every request: attaches the security headers to the response.
    @app.after_request
    def _headers(resp):
        h = resp.headers
        h.setdefault('X-Content-Type-Options', 'nosniff')
        h.setdefault('X-Frame-Options', 'DENY')
        h.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')
        h.setdefault('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()')
        h.setdefault('Cross-Origin-Opener-Policy', 'same-origin')
        if hsts:
            h.setdefault('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
        if request.endpoint != 'static':
            h.setdefault('Content-Security-Policy', build_csp(getattr(g, 'csp_nonce', '')))
            # Pages contain patient records: never let the browser or a proxy keep a copy.
            h.setdefault('Cache-Control', 'no-store')
        return resp


# Configures logging: always to the console, plus a size-limited rotating file when LOG_FILE is set.
def setup_logging(app):
    """INFO logs to stderr always; plus a rotating file when LOG_FILE is set."""
    level = getattr(logging, os.getenv('LOG_LEVEL', 'INFO').upper(), logging.INFO)
    app.logger.setLevel(level)
    path = os.getenv('LOG_FILE', '').strip()
    if not path:
        return
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    handler = RotatingFileHandler(path, maxBytes=5 * 1024 * 1024, backupCount=5, encoding='utf-8')
    handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(name)s: %(message)s'))
    for name in (app.logger.name, 'apscheduler', 'waitress', 'gunicorn.error'):
        lg = logging.getLogger(name)
        lg.addHandler(handler)
        lg.setLevel(level)

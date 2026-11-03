# =============================================================================================
# HawkEye Optical Clinic: Flask backend (single file).
#
# What this file contains, top to bottom:
#   1. Setup            - Flask app, CSRF protection, security hardening, error pages.
#   2. Email            - Gmail SMTP sending plus appointment / prescription reminder jobs.
#   3. Database         - MySQL connection wrapper, table definitions, schema upgrades.
#   4. Safety helpers   - login lockout / rate limits, cross-process locks, access decorators.
#   5. Public pages     - landing, patient sign-up with emailed code, sign-in, password reset.
#   6. Staff portal     - dashboard, patients, prescriptions, appointments, doctor schedule,
#                         reminders, clinic chat, reports, user + branch administration.
#   7. Patient portal   - home, booking, prescription, reminders, messages, profile.
#   8. Startup          - scheduler jobs and bootstrap().
#
# Roles: Admin (all branches), Clinic Staff and Optometrist (their own branch), Patient.
# Settings come from the .env file (database, Gmail, base URL); see DEPLOY.md.
# =============================================================================================

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, make_response
import os, sys, secrets, logging, re, hashlib
from contextlib import contextmanager, ExitStack
import mysql.connector
from mysql.connector import Error as MySQLError, IntegrityError
from datetime import datetime, timedelta, date
from functools import wraps
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from dotenv import load_dotenv
from flask_wtf.csrf import CSRFProtect
from apscheduler.schedulers.background import BackgroundScheduler
from werkzeug.security import generate_password_hash, check_password_hash
import smtplib
from email.message import EmailMessage
from markupsafe import escape as esc          # HTML-escape anything a person typed before it goes into an email
from werkzeug.exceptions import HTTPException
import production
import mfa, google_auth
import time as _time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, '.env'))
production.validate_config()   # refuses to start with unsafe settings when APP_ENV=production
app = Flask(__name__)
app.secret_key = production.secret_key()
app.config.update(WTF_CSRF_TIME_LIMIT=7200, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax', SESSION_COOKIE_SECURE=os.getenv('COOKIE_SECURE','false').lower() == 'true', PERMANENT_SESSION_LIFETIME=timedelta(hours=8), MAX_CONTENT_LENGTH=2 * 1024 * 1024)
csrf = CSRFProtect(app)
production.setup_logging(app)
production.harden(app)         # security headers, CSP nonce, no-store caching, optional proxy support

# Adds ?v=<file modified time> to every /static/ link so phones and browsers load updated CSS/JS right after a deploy.
@app.url_defaults
def _static_cache_bust(endpoint, values):
    if endpoint == 'static' and 'v' not in values and values.get('filename'):
        try: values['v'] = int(os.path.getmtime(os.path.join(app.static_folder, values['filename'])))
        except OSError: pass

TOKEN_SALT = 'hawkeyes-email-verification-v1'
_EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')   # no whitespace/newlines: blocks mail-header injection

# Builds the signed, time-limited token maker used for email-verification and password-reset
# links.
def token_serializer():
    return URLSafeTimedSerializer(app.secret_key, salt=TOKEN_SALT)

# Short hash of the current password hash; embedded in reset links so a link dies once the
# password changes.
def pw_fingerprint(password_hash):
    """Short fingerprint of the current password hash. Reset links carry it, so a link stops working the
    moment the password changes (links are single-use in effect)."""
    return hashlib.sha256((password_hash or '').encode()).hexdigest()[:20]


# Error handler for HTTP 400: shows a friendly flash message (or JSON for /api/ calls) instead
# of a raw error.
@app.errorhandler(400)
def bad_request(error):
    app.logger.info('Bad request: %s', error)
    if request.path.startswith('/api/'):
        return jsonify(ok=False, error='The request was invalid. Please check your input.'), 400
    flash('The request could not be processed. Please check your input and try again.', 'error')
    return redirect(request.referrer or url_for('index'))

# Error handler for HTTP 403 (no permission): renders the error page, or JSON for /api/ calls.
@app.errorhandler(403)
def forbidden(error):
    if request.path.startswith('/api/'):
        return jsonify(ok=False, error='You do not have permission to perform this action.'), 403
    return render_template('error.html', code=403, title='Access denied', message='You do not have permission to view this page.'), 403

# Error handler for HTTP 404 (page missing): renders the error page, or JSON for /api/ calls.
@app.errorhandler(404)
def not_found(error):
    if request.path.startswith('/api/'):
        return jsonify(ok=False, error='The requested resource was not found.'), 404
    return render_template('error.html', code=404, title='Page not found', message='The page may have moved or the link may be incorrect.'), 404

# Error handler for HTTP 413 (request body too big).
@app.errorhandler(413)
def too_large(error):
    if request.path.startswith('/api/'):
        return jsonify(ok=False, error='The submitted request is too large.'), 413
    return render_template('error.html', code=413, title='Request too large', message='Please submit a smaller request.'), 413

# Error handler for HTTP 500: logs the problem and shows a generic error page.
@app.errorhandler(500)
def server_error(error):
    app.logger.exception('Unhandled application error: %s', error)
    if request.path.startswith('/api/'):
        return jsonify(ok=False, error='A server error occurred. Please try again later.'), 500
    return render_template('error.html', code=500, title='Something went wrong', message='Your request could not be completed. Please try again.'), 500

# Catch-all for any unhandled exception: logs the details privately and shows the user a
# generic message.
@app.errorhandler(Exception)
def unexpected_error(error):
    # HTTP errors without a dedicated handler above (405, 401, 429, ...) keep their own status code
    # instead of being reported as a 500 and logged as a crash.
    if isinstance(error, HTTPException):
        if error.code is None or error.code < 400: return error          # redirects etc. pass straight through
        if request.path.startswith('/api/'):
            return jsonify(ok=False, error=error.description or error.name), error.code
        resp = make_response(render_template('error.html', code=error.code, title=error.name, message=error.description or ''), error.code)
        if getattr(error, 'valid_methods', None): resp.headers['Allow'] = ', '.join(error.valid_methods)
        return resp
    # Keep unexpected exceptions out of the browser while preserving diagnostics in logs.
    app.logger.exception('Unhandled exception on %s', request.path)
    if request.path.startswith('/api/'):
        return jsonify(ok=False, error='An unexpected error occurred. Please try again.'), 500
    return render_template('error.html', code=500, title='Something went wrong', message='Your request could not be completed. Please try again.'), 500


# Sends one HTML email through Gmail SMTP using the .env settings. Returns (ok, message) and
# never raises, so callers can show the result.
def send_email(to_email, subject, html, text_body=None):
    """Send email using Gmail SMTP with a Google App Password."""
    mail_username = os.getenv('GMAIL_ADDRESS', os.getenv('MAIL_USERNAME', '')).strip()
    mail_password = os.getenv('GMAIL_APP_PASSWORD', os.getenv('MAIL_PASSWORD', '')).replace(' ', '').strip()
    mail_from = os.getenv('MAIL_DEFAULT_SENDER', mail_username).strip()
    mail_server = os.getenv('MAIL_SERVER', 'smtp.gmail.com').strip()

    try:
        mail_port = int(os.getenv('MAIL_PORT', '587'))
    except ValueError:
        app.logger.error('Invalid MAIL_PORT setting in .env.')
        return False, 'Email settings are invalid. Check MAIL_PORT in .env.'

    if not mail_username or not mail_password or not mail_from:
        return False, (
            'Gmail is not configured. Set GMAIL_ADDRESS, GMAIL_APP_PASSWORD, '
            'and MAIL_DEFAULT_SENDER in .env.'
        )

    message = EmailMessage()
    message['Subject'] = subject
    message['From'] = mail_from
    message['To'] = to_email
    message.set_content(text_body or 'Please view this email in an HTML-compatible email client.')
    message.add_alternative(html, subtype='html')

    try:
        with smtplib.SMTP(mail_server, mail_port, timeout=20) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(mail_username, mail_password)
            server.send_message(message)
        app.logger.info('Email successfully sent through Gmail SMTP to %s', to_email)
        return True, 'Email sent successfully through Gmail.'
    except smtplib.SMTPAuthenticationError as exc:
        app.logger.error('Gmail authentication failed: %s', exc)
        return False, 'Gmail login failed. Check the Gmail address and Google App Password.'
    except (smtplib.SMTPException, OSError, TimeoutError) as exc:
        app.logger.error('Gmail SMTP error: %s', exc)
        return False, 'Gmail could not send the email. Check SMTP settings and internet connection.'


# Creates the full URL a patient clicks to verify their email (signed token + APP_BASE_URL).
def email_verification_link(user_id, email):
    token = token_serializer().dumps({'uid': user_id, 'email': email})
    base = os.getenv('APP_BASE_URL', 'http://127.0.0.1:5000').rstrip('/')
    return f'{base}{url_for("verify_email", token=token)}'

# Saves a reminder row in the database so it appears on the patient's Reminders page and nav
# badge.
def post_website_reminder(c, patient_id, appointment_id, message, channel='Website', status='Sent'):
    """Create the reminder row the patient sees under Reminders on the client website."""
    c.execute('INSERT INTO reminders(patient_id,appointment_id,channel,message,sent_date,status,read_status) VALUES(?,?,?,?,?,?,?)',
              (patient_id, appointment_id, channel, message, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), status, 'Unread'))

# Reminds a patient about an appointment: always posts a website reminder, also emails them if
# an address exists, and records Sent/Failed on the appointment.
def send_appointment_email(appointment_id, reason='scheduled reminder'):
    """Remind a patient about an appointment.

    The reminder is ALWAYS posted to the patient's Reminders page on the website (and shows in their
    menu badge / home page). An email is also sent when the patient has an address on file.
    Returns (ok, detail) where ok means the patient was successfully reminded by at least the website."""
    c = db()
    a = c.execute('SELECT a.*, p.name, p.email, p.channel, p.patient_id AS patient_code FROM appointments a JOIN patients p ON p.id=a.patient_id WHERE a.id=?', (appointment_id,)).fetchone()
    if not a:
        c.close(); return False, 'Appointment not found.'
    msg = f"Hello {a['name']}, this is HawkEye Optical Clinic. Your {a['type'].lower()} is scheduled for {a['date']} at {a['time']}. Please contact the clinic if you need to reschedule."
    if a['email']:
        ok, detail = send_email(a['email'], 'HawkEye Optical Clinic appointment reminder', f'<p>Hello {esc(a["name"])},</p><p>This is a reminder that your <b>{esc(a["type"])}</b> is scheduled for <b>{esc(a["date"])} at {esc(a["time"])}</b>.</p><p>Please contact the clinic if you need to reschedule.</p><p>HawkEye Optical Clinic</p>', msg)
        post_website_reminder(c, a['patient_id'], appointment_id, msg, 'Email + Website' if ok else 'Website (email failed)', 'Sent' if ok else 'Failed')
        c.execute('UPDATE appointments SET reminder_status=? WHERE id=?', ('Sent' if ok else 'Failed', appointment_id))
        c.commit(); c.close()
        return True, (detail if ok else 'Posted on the patient website, but the email failed: ' + detail)
    post_website_reminder(c, a['patient_id'], appointment_id, msg, 'Website', 'Sent')
    c.execute('UPDATE appointments SET reminder_status=? WHERE id=?', ('Sent', appointment_id))
    c.commit(); c.close()
    return True, 'Posted on the patient website (no email address on file).'

# Scheduled job (every 15 min): finds confirmed appointments about 24 hours away that have not
# been reminded yet and reminds the patient.
def send_due_reminders():
    """Background job: email reminders for confirmed appointments occurring in 24 hours."""
    now = datetime.now(); start = now + timedelta(hours=23); end = now + timedelta(hours=25)
    c = db()
    rows = c.execute("SELECT a.id FROM appointments a WHERE a.status='Confirmed' AND a.date BETWEEN ? AND ?", (start.strftime('%Y-%m-%d'), end.strftime('%Y-%m-%d'))).fetchall()
    ids = []
    for row in rows:
        a = c.execute('SELECT date,time FROM appointments WHERE id=?', (row['id'],)).fetchone()
        try: appt = datetime.strptime(f"{a['date']} {a['time']}", '%Y-%m-%d %H:%M')
        except ValueError: continue
        if start <= appt <= end:
            already = c.execute("SELECT 1 FROM reminders WHERE appointment_id=? AND sent_date>=? AND status IN ('Sent','Failed') LIMIT 1", (row['id'], (now-timedelta(hours=26)).strftime('%Y-%m-%d %H:%M:%S'))).fetchone()
            if not already: ids.append(row['id'])
    c.close()
    for aid in ids: send_appointment_email(aid, 'automatic reminder')



class DBRow(dict):
    """Mapping row that also supports SQLite-style numeric indexing."""
    def __getitem__(self, key):
        if isinstance(key, int):
            return list(self.values())[key]
        return super().__getitem__(key)

# Wraps a MySQL cursor so query results come back as DBRow objects (fetchone / fetchall).
class DBResult:
    def __init__(self, cursor):
        self._cursor = cursor
        self.lastrowid = cursor.lastrowid
        self.rowcount = cursor.rowcount
        self.description = cursor.description
    def _row(self, row):
        if row is None: return None
        names = [d[0] for d in self._cursor.description or []]
        return DBRow(zip(names, row))
    def fetchone(self): return self._row(self._cursor.fetchone())
    def fetchall(self): return [self._row(r) for r in self._cursor.fetchall()]

# Thin wrapper around a MySQL connection. execute() converts SQLite-style SQL (? placeholders,
# INSERT OR IGNORE) into MySQL syntax.
class DBConnection:
    def __init__(self, connection): self._connection = connection
    def execute(self, sql, params=()):
        sql = sql.replace('?', '%s')
        sql = re.sub(r'\bINSERT\s+OR\s+IGNORE\s+INTO\b', 'INSERT IGNORE INTO', sql, flags=re.I)
        sql = re.sub(r'\bSELECT\s+last_insert_rowid\s*\(\s*\)', 'SELECT LAST_INSERT_ID()', sql, flags=re.I)
        if sql.strip().upper() == 'BEGIN IMMEDIATE': sql = 'START TRANSACTION'
        cur = self._connection.cursor()
        cur.execute(sql, params or ())
        return DBResult(cur)
    def commit(self): return self._connection.commit()
    def rollback(self): return self._connection.rollback()
    def close(self): return self._connection.close()

# Opens a new database connection using the MYSQL_* settings in .env. Callers must close() it
# when finished.
def db():
    """Connect to the XAMPP MariaDB/MySQL database configured in .env."""
    connection = mysql.connector.connect(
        host=os.getenv('MYSQL_HOST', '127.0.0.1'),
        port=int(os.getenv('MYSQL_PORT', '3306')),
        user=os.getenv('MYSQL_USER', 'root'),
        password=os.getenv('MYSQL_PASSWORD', ''),
        database=os.getenv('MYSQL_DATABASE', 'hawkeye_database'),
        charset='utf8mb4',
        use_unicode=True,
        autocommit=False,
        connection_timeout=10,
    )
    return DBConnection(connection)

# CREATE TABLE statements for every table the app uses (users, patients, appointments,
# prescriptions, reminders, chat, rate limits, ...).
MYSQL_SCHEMA = [
"""CREATE TABLE IF NOT EXISTS users (
 id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, name VARCHAR(255), email VARCHAR(255) UNIQUE,
 password VARCHAR(255), role VARCHAR(50), status VARCHAR(30) DEFAULT 'Active',
 email_verified TINYINT DEFAULT 1, reset_token VARCHAR(255), branch_id INT NULL,
 mfa_enabled TINYINT NOT NULL DEFAULT 0, mfa_secret VARCHAR(64) NULL, mfa_last_step BIGINT NULL, google_sub VARCHAR(64) NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci""",
"""CREATE TABLE IF NOT EXISTS branches (
 id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, name VARCHAR(255) UNIQUE, address TEXT,
 active TINYINT DEFAULT 1
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci""",
"""CREATE TABLE IF NOT EXISTS patients (
 id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, patient_id VARCHAR(100) UNIQUE, name VARCHAR(255),
 birthdate VARCHAR(30), phone VARCHAR(60), email VARCHAR(255), address TEXT,
 channel VARCHAR(30) DEFAULT 'Email', user_id INT NULL, branch_id INT NULL,
 INDEX idx_patients_name(name), INDEX idx_patients_branch(branch_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci""",
"""CREATE TABLE IF NOT EXISTS prescriptions (
 id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, patient_id INT, recorded VARCHAR(30), optometrist VARCHAR(255),
 od_sphere VARCHAR(30), od_cylinder VARCHAR(30), od_axis VARCHAR(30), od_add VARCHAR(30), od_pd VARCHAR(30),
 os_sphere VARCHAR(30), os_cylinder VARCHAR(30), os_axis VARCHAR(30), os_add VARCHAR(30), os_pd VARCHAR(30),
 notes TEXT, return_date VARCHAR(30), reference VARCHAR(100), INDEX idx_prescriptions_patient(patient_id),
 INDEX idx_prescriptions_return_date(return_date)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci""",
"""CREATE TABLE IF NOT EXISTS appointments (
 id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, patient_id INT, type VARCHAR(80), `date` VARCHAR(30), `time` VARCHAR(30),
 status VARCHAR(40), reminder_status VARCHAR(40), notes TEXT, request_only TINYINT DEFAULT 0, branch_id INT NULL, doctor_id INT NULL,
 INDEX idx_appointments_doctor(doctor_id), INDEX idx_appointments_date(`date`), INDEX idx_appointments_patient(patient_id), INDEX idx_appointments_type(type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci""",
"""CREATE TABLE IF NOT EXISTS reminders (
 id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, patient_id INT, appointment_id INT NULL, channel VARCHAR(30),
 message TEXT, sent_date VARCHAR(30), status VARCHAR(30), read_status VARCHAR(30) DEFAULT 'Unread',
 INDEX idx_reminders_patient(patient_id), INDEX idx_reminders_appointment(appointment_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci""",
"""CREATE TABLE IF NOT EXISTS access_requests (
 id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, email VARCHAR(255), password VARCHAR(255),
 status VARCHAR(30) DEFAULT 'Pending', name VARCHAR(255), role VARCHAR(50) DEFAULT 'Clinic Staff', created_at VARCHAR(30)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci""",
"""CREATE TABLE IF NOT EXISTS audit_logs (
 id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, user_id INT, action VARCHAR(255), entity VARCHAR(100),
 entity_id INT, created_at VARCHAR(30), INDEX idx_audit_created(created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci""",
"""CREATE TABLE IF NOT EXISTS patient_sessions (
 id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, patient_id INT NOT NULL, visit_date VARCHAR(30) NOT NULL,
 visit_type VARCHAR(80) NOT NULL DEFAULT 'Eye check', notes TEXT, outcome VARCHAR(255), recorded_by INT,
 created_at VARCHAR(30) NOT NULL, updated_at VARCHAR(30) NOT NULL,
 INDEX idx_sessions_patient(patient_id), INDEX idx_sessions_date(visit_date)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci""",
"""CREATE TABLE IF NOT EXISTS patient_reviews (
 patient_id INT NOT NULL PRIMARY KEY, reviewed_by INT, reviewed_at VARCHAR(30)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci""",
"""CREATE TABLE IF NOT EXISTS clinic_chat_messages (
 id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, patient_id INT NOT NULL, staff_id INT NOT NULL,
 message TEXT NOT NULL, created_at VARCHAR(30) NOT NULL, read_status VARCHAR(30) DEFAULT 'Unread',
 sender VARCHAR(20) NOT NULL DEFAULT 'Staff',
 INDEX idx_chat_patient(patient_id), INDEX idx_chat_created(created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci""",
"""CREATE TABLE IF NOT EXISTS email_tokens (
 id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, user_id INT, token_hash VARCHAR(255), expires_at VARCHAR(30), used TINYINT DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci""",
"""CREATE TABLE IF NOT EXISTS pending_signups (
 email VARCHAR(255) NOT NULL PRIMARY KEY, name VARCHAR(255) NOT NULL, password_hash VARCHAR(255) NOT NULL,
 patient_id VARCHAR(100), birthdate VARCHAR(30), code_hash VARCHAR(255) NOT NULL, expires_at VARCHAR(30) NOT NULL,
 attempts INT NOT NULL DEFAULT 0, created_at VARCHAR(30) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci""",
"""CREATE TABLE IF NOT EXISTS mfa_backup_codes (
 id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, user_id INT NOT NULL, code_hash VARCHAR(64) NOT NULL,
 used TINYINT NOT NULL DEFAULT 0, INDEX idx_mfa_backup_user(user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci""",
"""CREATE TABLE IF NOT EXISTS rate_limits (
 key_hash VARCHAR(64) NOT NULL PRIMARY KEY, hits INT NOT NULL DEFAULT 0, window_start VARCHAR(30) NOT NULL,
 locked_until VARCHAR(30) NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci""",
]

# Creates any missing tables and adds newly introduced columns to existing tables, without
# deleting data.
def ensure_schema():
    c = db()
    try:
        for statement in MYSQL_SCHEMA: c.execute(statement)
        # Add columns introduced by recent app versions without deleting existing data.
        migrations = {
            'users': [('email_verified', 'TINYINT DEFAULT 1'), ('reset_token', 'VARCHAR(255)'), ('branch_id', 'INT NULL'),
                      # two-step sign-in (authenticator app) and "Sign in with Google"
                      ('mfa_enabled', 'TINYINT NOT NULL DEFAULT 0'), ('mfa_secret', 'VARCHAR(64) NULL'),
                      ('mfa_last_step', 'BIGINT NULL'), ('google_sub', 'VARCHAR(64) NULL')],
            'patients': [('branch_id', 'INT NULL')],
            'appointments': [('branch_id', 'INT NULL'), ('request_only', 'TINYINT DEFAULT 0'), ('doctor_id', 'INT NULL')],
            'access_requests': [('name', 'VARCHAR(255)'), ('role', "VARCHAR(50) DEFAULT 'Clinic Staff'"), ('created_at', 'VARCHAR(30)')],
            'reminders': [('read_status', "VARCHAR(30) DEFAULT 'Unread'")],
            # Clinic chat is now two-way: existing rows were all sent by staff.
            'clinic_chat_messages': [('sender', "VARCHAR(20) NOT NULL DEFAULT 'Staff'")],
        }
        for table, columns in migrations.items():
            existing = {r['COLUMN_NAME'] for r in c.execute(
                'SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s',
                (os.getenv('MYSQL_DATABASE', 'hawkeye_database'), table)).fetchall()}
            for column, definition in columns:
                if column not in existing: c.execute(f'ALTER TABLE `{table}` ADD COLUMN `{column}` {definition}')
        # One Google account can be linked to only one user (NULLs are allowed many times).
        if not c.execute("SELECT 1 FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=%s AND TABLE_NAME='users' AND INDEX_NAME='uniq_users_google_sub'",
                         (os.getenv('MYSQL_DATABASE', 'hawkeye_database'),)).fetchone():
            c.execute('ALTER TABLE `users` ADD UNIQUE INDEX `uniq_users_google_sub` (`google_sub`)')
        c.commit()
    except Exception:
        c.rollback(); raise
    finally: c.close()

# ---------------------------------------------------------------------------------------------
# Production helpers: brute-force protection and cross-process locking.
# State lives in MySQL (not memory) so limits and locks hold across several worker processes.
# ---------------------------------------------------------------------------------------------
_TS = '%Y-%m-%d %H:%M:%S'

# Returns the visitor's IP address (the real one when TRUST_PROXY is on behind a reverse
# proxy).
def client_ip():
    # With TRUST_PROXY=true (see DEPLOY.md) this is the real visitor address, not the proxy's.
    return request.remote_addr or 'unknown'

# Turns a label + value (e.g. 'login-acct', an email) into a hashed key for the rate-limit
# table.
def _rl_key(kind, value):
    return hashlib.sha256(f'{kind}|{(value or "").strip().lower()}'.encode()).hexdigest()

# Returns how many seconds are left on the longest active lock among the given rate-limit keys
# (0 = not locked).
def rl_locked_seconds(*keys):
    """Seconds left on the longest active lock among keys (0 = not locked)."""
    now = datetime.now(); wait = 0
    c = db()
    try:
        for key in keys:
            row = c.execute('SELECT locked_until FROM rate_limits WHERE key_hash=?', (key,)).fetchone()
            if row and row['locked_until']:
                left = (datetime.strptime(row['locked_until'], _TS) - now).total_seconds()
                wait = max(wait, int(left) + 1 if left > 0 else 0)
    finally: c.close()
    return wait

# Counts one event for a key; locks the key once the limit is reached within the time window.
# Returns True if now locked.
def rl_hit(key, limit, window):
    """Count one event. Locks the key for `window` seconds once `limit` events happen inside `window`.
    Returns True when the key is now locked."""
    now = datetime.now(); c = db()
    try:
        row = c.execute('SELECT hits, window_start FROM rate_limits WHERE key_hash=?', (key,)).fetchone()
        if row and (now - datetime.strptime(row['window_start'], _TS)).total_seconds() <= window:
            hits, start = row['hits'] + 1, row['window_start']
        else:
            hits, start = 1, now.strftime(_TS)
        locked = (now + timedelta(seconds=window)).strftime(_TS) if hits >= limit else None
        c.execute('INSERT INTO rate_limits(key_hash,hits,window_start,locked_until) VALUES(?,?,?,?) '
                  'ON DUPLICATE KEY UPDATE hits=VALUES(hits), window_start=VALUES(window_start), locked_until=VALUES(locked_until)',
                  (key, hits, start, locked))
        c.commit()
        return locked is not None
    finally: c.close()

# Clears a rate-limit key (used after a successful login).
def rl_reset(key):
    c = db()
    try: c.execute('DELETE FROM rate_limits WHERE key_hash=?', (key,)); c.commit()
    finally: c.close()

LOGIN_MAX_FAILS, LOGIN_IP_MAX_FAILS, LOGIN_WINDOW = 5, 30, 15 * 60

# Checks whether this email or IP is temporarily locked out from too many failed sign-ins;
# flashes a message if so.
def login_blocked(email):
    """True (and flashes a message) while this account or this address is locked out."""
    wait = rl_locked_seconds(_rl_key('login-acct', email), _rl_key('login-ip', client_ip()))
    if wait:
        flash(f'Too many failed sign-in attempts. Please wait {max(1, wait // 60 + (1 if wait % 60 else 0))} minute(s) and try again.', 'error')
        return True
    return False

# Records a failed sign-in against both the account and the IP address.
def login_failed(email, kind):
    locked = rl_hit(_rl_key('login-acct', email), LOGIN_MAX_FAILS, LOGIN_WINDOW)
    rl_hit(_rl_key('login-ip', client_ip()), LOGIN_IP_MAX_FAILS, LOGIN_WINDOW)
    if locked: app.logger.warning('Sign-in locked for %s account after repeated failures (ip %s)', kind, client_ip())

# Clears the failed-attempt counter for the account after a successful sign-in.
def login_succeeded(email):
    rl_reset(_rl_key('login-acct', email))

# Rate-limits endpoints that send email (signup, reset, resend). Returns True when the caller
# is over the limit.
def too_many_requests(scope, email=None, per_ip=10, per_email=3, window=15 * 60):
    """Rate-limit endpoints that send email (signup, password reset, resend). True = over the limit."""
    over = rl_hit(_rl_key(scope + '-ip', client_ip()), per_ip + 1, window)        # per_ip allowed, the next is blocked
    if email: over = rl_hit(_rl_key(scope + '-email', email), per_email + 1, window) or over
    if over: flash('Too many requests. Please wait a few minutes and try again.', 'error')
    return over

# Context manager for a server-wide named MySQL lock, so only one worker process does a job at
# a time.
@contextmanager
def db_lock(name, timeout=0):
    """Server-wide named lock (MySQL GET_LOCK). Yields True if acquired. Released automatically
    if the process dies, so a crashed worker can never leave the lock stuck."""
    c = db(); got = False
    try:
        got = c.execute('SELECT GET_LOCK(?,?) AS ok', (name, timeout)).fetchone()['ok'] == 1
        yield got
    finally:
        try:
            if got: c.execute('SELECT RELEASE_LOCK(?)', (name,)).fetchone()
        finally: c.close()

# Holds several named locks at once (used to make "check the slot, then insert" atomic).
@contextmanager
def db_locks(*names, timeout=5):
    """Yields True only when EVERY lock was obtained (waiting up to `timeout` s each). Locks are taken in
    sorted order so two requests can never wait on each other, and all are released on exit."""
    with ExitStack() as stack:
        yield all(stack.enter_context(db_lock(n, timeout)) for n in sorted(set(names)))

# Wraps a scheduled job so it runs in only one worker process at a time (prevents duplicate
# reminder emails).
def exclusive(name, fn):
    """Wrap a scheduled job so only ONE worker process runs it at a time (no duplicate emails)."""
    @wraps(fn)
    def run(*a, **k):
        try:
            with db_lock('hawkeye:' + name, 0) as got:
                if got: return fn(*a, **k)
        except Exception:
            app.logger.exception('Scheduled job %s failed', name)
    return run

# Scheduled job (every 6 h): deletes expired rate-limit rows to keep the table small.
def purge_stale_rows():
    c = db()
    try:
        cutoff = (datetime.now() - timedelta(days=1)).strftime(_TS)
        c.execute('DELETE FROM rate_limits WHERE window_start < ? AND (locked_until IS NULL OR locked_until < ?)', (cutoff, cutoff))
        c.commit()
    finally: c.close()


# First-run setup: creates the Main Branch, assigns existing records to it, and creates the
# starting admin (or demo accounts when SEED_DEMO_ACCOUNTS=true).
def init_db():
    ensure_schema()
    c = db()
    try:
        c.execute("INSERT IGNORE INTO branches(name,address) VALUES('Main Branch','Set branch address in administration')")
        main_branch = c.execute("SELECT id FROM branches WHERE name='Main Branch'").fetchone()[0]
        c.execute("UPDATE users SET branch_id=%s WHERE branch_id IS NULL AND role!='Admin'", (main_branch,))
        c.execute("UPDATE patients SET branch_id=%s WHERE branch_id IS NULL", (main_branch,))
        c.execute("UPDATE appointments SET branch_id=%s WHERE branch_id IS NULL", (main_branch,))
        def add_staff(name, email, pw, role):
            c.execute("INSERT IGNORE INTO users(name,email,password,role,status,email_verified,branch_id) VALUES(%s,%s,%s,%s,'Active',1,%s)",
                      (name,email,generate_password_hash(pw),role,None if role == 'Admin' else main_branch))
        if os.getenv('SEED_DEMO_ACCOUNTS', 'false').lower() == 'true':
            # Local demo only: well-known passwords. Never enable on a real deployment.
            add_staff('Andrea Reyes','andrea.reyes@example.com','admin123','Admin')
            add_staff('Dr. Paolo Garcia','paolo.garcia@example.com','doctor123','Optometrist')
            add_staff('Camille Flores','camille.flores@example.com','staff123','Clinic Staff')
        elif not c.execute("SELECT 1 FROM users WHERE role='Admin' LIMIT 1").fetchone():
            # Fresh install with no admin: create one from .env, or with a random one-time password.
            admin_email = (os.getenv('ADMIN_EMAIL') or 'admin@hawkeyes.local').strip().lower()
            admin_pw = os.getenv('ADMIN_PASSWORD') or secrets.token_urlsafe(12)
            add_staff('Administrator', admin_email, admin_pw, 'Admin')
            if not os.getenv('ADMIN_PASSWORD'):
                app.logger.warning('FIRST-RUN ADMIN CREATED. Email: %s  Password: %s  (shown once; change it under Change Password)', admin_email, admin_pw)
        c.execute("UPDATE users SET branch_id=%s WHERE branch_id IS NULL AND role!='Admin'", (main_branch,))
        c.execute("UPDATE patients SET branch_id=%s WHERE branch_id IS NULL", (main_branch,))
        c.execute("UPDATE appointments SET branch_id=%s WHERE branch_id IS NULL", (main_branch,))
        c.commit()
    except Exception:
        c.rollback(); raise
    finally: c.close()

# Scheduled job (hourly): reminds patients whose prescription review date is tomorrow, once
# per date.
def send_due_prescription_reminders():
    """Send a once-per-return-date email for prescriptions whose review date is tomorrow."""
    target=(date.today()+timedelta(days=1)).isoformat(); c=db()
    rows=c.execute("SELECT p.id,p.patient_id,p.return_date,pt.name,pt.email FROM prescriptions p JOIN patients pt ON pt.id=p.patient_id WHERE p.return_date=?",(target,)).fetchall()
    for r in rows:
        already=c.execute("SELECT 1 FROM reminders WHERE patient_id=? AND appointment_id IS NULL AND message LIKE ? AND status='Sent' LIMIT 1",(r['patient_id'],f'%prescription review date {target}%')).fetchone()
        if already: continue
        message=f"Hello {r['name']}, HawkEye Optical Clinic recommends a prescription review around {target}. Please contact the clinic to arrange a visit."
        if r['email']:
            ok,detail=send_email(r['email'],'HawkEye Optical Clinic prescription follow-up',f'<p>Hello {esc(r["name"])},</p><p>HawkEye Optical Clinic recommends a prescription review around <b>{target}</b>.</p><p>Please contact the clinic to arrange a visit.</p>',message)
            post_website_reminder(c,r['patient_id'],None,message,'Email + Website' if ok else 'Website (email failed)','Sent' if ok else 'Failed')
            if not ok: app.logger.warning('Prescription reminder email failed for patient %s: %s',r['patient_id'],detail)
        else:
            post_website_reminder(c,r['patient_id'],None,message,'Website','Sent')
    c.commit(); c.close()

# Writes an audit-log entry (who did what, to which record, when). The caller commits it.
def log_staff_action(c, action, entity, entity_id=None):
    c.execute('INSERT INTO audit_logs(user_id,action,entity,entity_id,created_at) VALUES(?,?,?,?,?)',
              (session.get('uid'), action, entity, entity_id, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))

# Decorator: only signed-in Patients may open the page; everyone else is sent to the patient
# login.
def login_required(f):
    @wraps(f)
    def w(*a,**k):
        if 'uid' not in session or session.get('role')!='Patient': return redirect(url_for('patient_login'))
        return f(*a,**k)
    return w

# Decorator: only Admin, Clinic Staff or Optometrist users may open the page; others go to the
# staff login.
def staff_required(f):
    @wraps(f)
    def w(*a,**k):
        if session.get('role') not in ['Admin','Clinic Staff','Optometrist']: return redirect(url_for('staff_login'))
        return f(*a,**k)
    return w

# Returns the patient record linked to the signed-in user account.
def patient_for_user():
    c=db(); p=c.execute('SELECT * FROM patients WHERE user_id=?',(session['uid'],)).fetchone(); c.close(); return p

# Decorator (use under @login_required): a patient login with no clinic record gets a clear page
# instead of a crash.
def patient_record_required(f):
    @wraps(f)
    def w(*a,**k):
        if not patient_for_user():
            return render_template('error.html', code=404, title='Patient record not found',
                                   message='Your account is not linked to a clinic patient record yet. Please contact the clinic so they can link it.'), 404
        return f(*a,**k)
    return w

# Creates an unguessable patient code (HK-2026-A1B2C3). Codes are an identifier, not a secret, but they
# must not be guessable one by one.
def new_patient_code(c):
    year=datetime.now().year
    while True:
        code=f'HK-{year}-{secrets.token_hex(3).upper()}'
        if not c.execute('SELECT 1 FROM patients WHERE patient_id=?',(code,)).fetchone(): return code

# The clinic record a new account may claim, or None. Patient ID + full name + birthdate must match AND
# the clinic must already hold the SAME email address on that record. The verification code is mailed to
# that address, so only its owner can finish linking; a record with no email on file cannot be
# self-claimed (the clinic adds the email first).
def linkable_patient(c, code, birthdate, name, email):
    p=c.execute('SELECT * FROM patients WHERE patient_id=? AND birthdate=? AND lower(name)=lower(?)',(code,birthdate,name)).fetchone()
    if not p or p['user_id']: return None
    on_file=(p['email'] or '').strip().lower()
    return p if on_file and on_file==(email or '').strip().lower() else None

# Public landing page.
# Route: GET /  |  Access: public
@app.route('/')
def index(): return render_template('landing.html')
# Staff sign-in. Checks email + password, requires an Active, email-verified non-patient
# account, and respects the lockout limits.
# Route: GET/POST /staff/login  |  Access: public
@app.route('/staff/login',methods=['GET','POST'])
def staff_login():
    if request.method=='POST':
        email=request.form.get('email','').strip().lower()
        if login_blocked(email): return render_template('login.html',kind='Staff')
        c=db(); u=c.execute("SELECT * FROM users WHERE lower(email)=? AND role!='Patient'",(email,)).fetchone(); c.close()
        if u and check_password_hash(u['password'],request.form.get('password','')) and u['status']=='Active' and u['email_verified']:
            login_succeeded(email); return begin_mfa_or_login(u)
        login_failed(email,'staff'); flash('Invalid staff credentials or inactive account.','error')
    return render_template('login.html',kind='Staff')
# Patient sign-in. Same checks as staff, plus tells unverified patients to verify their email
# first.
# Route: GET/POST /patient/login  |  Access: public
@app.route('/patient/login',methods=['GET','POST'])
def patient_login():
    if request.method=='POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        if login_blocked(email): return render_template('login.html',kind='Patient')
        c = db(); u = c.execute("SELECT * FROM users WHERE lower(email)=? AND role='Patient'", (email,)).fetchone(); c.close()
        if u and check_password_hash(u['password'], password) and not u['email_verified']:
            flash('Your email is not verified yet. Check your inbox or request a new verification email.', 'error')
        elif u and check_password_hash(u['password'], password) and u['status'] == 'Active':
            login_succeeded(email); return begin_mfa_or_login(u)
        else:
            login_failed(email,'patient'); flash('Invalid patient email or password.', 'error')
    return render_template('login.html',kind='Patient')
# Step 1 of patient sign-up: validates the form and privacy consent, optionally links an
# existing clinic record (patient ID + birthdate + name), then emails a 6-digit code. No
# account is created yet.
# Route: GET/POST /signup  |  Access: public
@app.route('/signup',methods=['GET','POST'])
def signup():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        existing_code = request.form.get('patient_id', '').strip()
        birthdate = request.form.get('birthdate', '').strip()

        if too_many_requests('signup', email): return render_template('signup.html')
        if not request.form.get('consent'):
            flash('Please read and accept the Privacy Notice to create an account.', 'error')
            return render_template('signup.html')
        if len(name) < 2 or len(name) > 100 or len(password) < 8 or len(email) > 190 or not _EMAIL_RE.match(email):
            flash('Enter your full name, a valid email, and a password with at least 8 characters.', 'error')
            return render_template('signup.html')
        if existing_code and not birthdate:
            flash('Enter your birthdate when linking an existing clinic patient ID.', 'error')
            return render_template('signup.html')

        c = db()
        try:
            if c.execute("SELECT 1 FROM users WHERE lower(email)=?", (email,)).fetchone():
                flash('An account with that email already exists. Sign in or request a new verification email if it is still unverified.', 'error')
                return render_template('signup.html')
            if not existing_code and c.execute('SELECT 1 FROM patients WHERE lower(email)=? LIMIT 1', (email,)).fetchone():
                flash('A clinic record may already exist for this email. Enter your patient ID and birthdate to link it, or contact the clinic.', 'error')
                return render_template('signup.html')
            if existing_code:
                if not linkable_patient(c, existing_code, birthdate, name, email):
                    flash('We could not verify that clinic record. Check your patient ID, full name and birthdate, and use the email address the clinic has on file for you. '
                          'If the clinic has no email on your record yet, ask them to add it first.', 'error')
                    return render_template('signup.html')

            code = f'{secrets.randbelow(1000000):06d}'
            expires = (datetime.now() + timedelta(minutes=10)).isoformat(timespec='seconds')
            c.execute("INSERT INTO pending_signups(email,name,password_hash,patient_id,birthdate,code_hash,expires_at,attempts,created_at) VALUES(?,?,?,?,?,?,?,?,?) ON DUPLICATE KEY UPDATE name=VALUES(name),password_hash=VALUES(password_hash),patient_id=VALUES(patient_id),birthdate=VALUES(birthdate),code_hash=VALUES(code_hash),expires_at=VALUES(expires_at),attempts=0,created_at=VALUES(created_at)",
                      (email, name, generate_password_hash(password), existing_code or None, birthdate or None,
                       generate_password_hash(code), expires, 0, datetime.now().isoformat(timespec='seconds')))
            c.commit()
        finally:
            c.close()

        ok, detail = send_email(
            email,
            'Verify your HawkEye Optical Clinic email',
            f'<p>Hello {esc(name)},</p><p>Your HawkEye Optical Clinic verification code is:</p><p style="font-size:28px;font-weight:bold;letter-spacing:5px">{code}</p><p>This code expires in 10 minutes. If you did not request this, you can ignore this email.</p>',
            f'Your HawkEye Optical Clinic verification code is {code}. It expires in 10 minutes.'
        )
        if not ok:
            app.logger.warning('Signup verification email failed: %s', detail)
            flash('We could not send the verification code. No account has been created. Check the email provider setup and try again.', 'error')
            return render_template('signup.html')
        session['pending_signup_email'] = email
        flash('We sent a 6-digit verification code to your email. Enter it to finish creating your account.', 'ok')
        return redirect(url_for('verify_signup_email'))
    return render_template('signup.html')

# Step 2 of sign-up: checks the emailed code (10-minute expiry, 5 attempts). On success
# creates the patient account and links or creates the patient record.
# Route: GET/POST /verify-signup-email  |  Access: public
@app.route('/verify-signup-email', methods=['GET', 'POST'])
def verify_signup_email():
    email = session.get('pending_signup_email', '').strip().lower()
    if not email:
        flash('Start by entering your signup details first.', 'error')
        return redirect(url_for('signup'))
    if request.method == 'POST':
        code = ''.join(ch for ch in request.form.get('code', '') if ch.isdigit())
        c = db()
        try:
            pending = c.execute('SELECT * FROM pending_signups WHERE email=?', (email,)).fetchone()
            if not pending:
                session.pop('pending_signup_email', None)
                flash('Signup verification expired. Please submit the signup form again.', 'error')
                return redirect(url_for('signup'))
            if datetime.now() > datetime.fromisoformat(pending['expires_at']):
                c.execute('DELETE FROM pending_signups WHERE email=?', (email,)); c.commit()
                session.pop('pending_signup_email', None)
                flash('That verification code expired. Please submit the signup form again.', 'error')
                return redirect(url_for('signup'))
            if pending['attempts'] >= 5:
                c.execute('DELETE FROM pending_signups WHERE email=?', (email,)); c.commit()
                session.pop('pending_signup_email', None)
                flash('Too many incorrect attempts. Please submit the signup form again.', 'error')
                return redirect(url_for('signup'))
            if len(code) != 6 or not check_password_hash(pending['code_hash'], code):
                c.execute('UPDATE pending_signups SET attempts=attempts+1 WHERE email=?', (email,)); c.commit()
                flash('Incorrect verification code. Please check the email and try again.', 'error')
                return render_template('verify_signup.html', email=email)

            if c.execute('SELECT 1 FROM users WHERE lower(email)=?', (email,)).fetchone():
                c.execute('DELETE FROM pending_signups WHERE email=?', (email,)); c.commit()
                session.pop('pending_signup_email', None)
                flash('An account with this email already exists. Please sign in.', 'error')
                return redirect(url_for('patient_login'))

            cur = c.execute("INSERT INTO users(name,email,password,role,status,email_verified,branch_id) VALUES(?,?,?,'Patient','Active',1,1)",
                            (pending['name'], email, pending['password_hash']))
            uid = cur.lastrowid
            existing_code = pending['patient_id'] or ''
            if existing_code:
                linked = linkable_patient(c, existing_code, pending['birthdate'], pending['name'], email)
                # Atomic claim: succeeds only while the record is still unclaimed (no two signups can take it).
                claimed = c.execute("UPDATE patients SET user_id=?,email=?,channel='Email' WHERE id=? AND user_id IS NULL", (uid, email, linked['id'])) if linked else None
                if not claimed or claimed.rowcount != 1:
                    c.rollback()                      # also undoes the users INSERT above
                    c.execute('DELETE FROM pending_signups WHERE email=?', (email,)); c.commit()
                    session.pop('pending_signup_email', None)
                    flash('The clinic record could not be linked. Please start signup again or contact the clinic.', 'error')
                    return redirect(url_for('signup'))
            else:
                patient_code = new_patient_code(c)
                c.execute('INSERT INTO patients(patient_id,name,email,user_id,channel,branch_id) VALUES(?,?,?,?,?,1)',
                          (patient_code, pending['name'], email, uid, 'Email'))
            c.execute('DELETE FROM pending_signups WHERE email=?', (email,))
            c.commit()
        except IntegrityError:
            c.rollback()
            flash('An account with this email already exists. Please sign in.', 'error')
            return redirect(url_for('patient_login'))
        finally:
            c.close()
        session.pop('pending_signup_email', None)
        flash('Email verified and account created. You can now sign in.', 'ok')
        return redirect(url_for('patient_login'))
    return render_template('verify_signup.html', email=email)

# Opens the emailed verification link: confirms the signed token and marks the account's email
# as verified.
# Route: GET /verify-email/<token>  |  Access: public
@app.route('/verify-email/<token>')
def verify_email(token):
    try: data=token_serializer().loads(token,max_age=86400)
    except SignatureExpired: flash('Verification link expired. Please request a new one.','error'); return redirect(url_for('resend_verification'))
    except BadSignature: flash('Invalid verification link.','error'); return redirect(url_for('patient_login'))
    c=db(); u=c.execute('SELECT * FROM users WHERE id=? AND email=?',(data.get('uid'),data.get('email'))).fetchone()
    if not u: c.close(); flash('Account not found.','error'); return redirect(url_for('patient_login'))
    c.execute("UPDATE users SET email_verified=1,status='Active' WHERE id=?",(u['id'],)); c.commit(); c.close()
    flash('Email verified. You can now sign in.','ok'); return redirect(url_for('patient_login'))

# Sends a fresh verification email to an unverified patient. The reply is the same whether or
# not the email exists.
# Route: GET/POST /resend-verification  |  Access: public
@app.route('/resend-verification',methods=['GET','POST'])
def resend_verification():
    if request.method=='POST':
        email=request.form.get('email','').strip().lower()
        if too_many_requests('resend', email): return render_template('resend_verification.html')
        c=db(); u=c.execute("SELECT * FROM users WHERE email=? AND role='Patient' AND email_verified=0",(email,)).fetchone(); c.close()
        # Avoid revealing whether an email exists.
        if u:
            link=email_verification_link(u['id'],u['email']); ok,detail=send_email(email,'Verify your HawkEye Optical Clinic account',f'<p><a href="{link}">Verify your email address</a></p><p>Link expires in 24 hours.</p>',f'Verify your email: {link}')
            if not ok: app.logger.warning('Verification email failed: %s',detail)
        flash('If an unverified account exists for that address, a verification email has been sent.','ok')
    return render_template('resend_verification.html')

# Emails a one-hour password-reset link if the account exists. The reply never reveals whether
# it does.
# Route: GET/POST /forgot-password  |  Access: public
@app.route('/forgot-password',methods=['GET','POST'])
def forgot_password():
    if request.method=='POST':
        email=request.form.get('email','').strip().lower()
        if too_many_requests('forgot', email): return render_template('forgot_password.html')
        c=db(); u=c.execute("SELECT * FROM users WHERE email=? AND status='Active'",(email,)).fetchone()
        if u:
            token=token_serializer().dumps({'uid':u['id'],'email':email,'purpose':'reset','pv':pw_fingerprint(u['password'])}); base=os.getenv('APP_BASE_URL','http://127.0.0.1:5000').rstrip('/'); link=f"{base}{url_for('reset_password',token=token)}"
            ok,detail=send_email(email,'Reset your HawkEye Optical Clinic password',f'<p><a href="{link}">Reset password</a></p><p>This link expires in one hour.</p>',f'Reset your password: {link}')
            if not ok: app.logger.warning('Password reset email failed: %s',detail)
        c.close(); flash('If the account exists, password reset instructions will be emailed.','ok')
    return render_template('forgot_password.html')

# Opens the reset link and lets the user choose a new password (min. 8 characters). The link
# stops working once the password changes.
# Route: GET/POST /reset-password/<token>  |  Access: public
@app.route('/reset-password/<token>',methods=['GET','POST'])
def reset_password(token):
    try: data=token_serializer().loads(token,max_age=3600)
    except (BadSignature,SignatureExpired): flash('Reset link is invalid or expired.','error'); return redirect(url_for('forgot_password'))
    if data.get('purpose')!='reset': flash('Invalid reset link.','error'); return redirect(url_for('forgot_password'))
    c=db(); u=c.execute('SELECT password FROM users WHERE id=? AND email=?',(data.get('uid'),data.get('email'))).fetchone(); c.close()
    if not u or data.get('pv')!=pw_fingerprint(u['password']):    # unknown account, or the password already changed since the link was sent
        flash('Reset link is invalid or has already been used. Please request a new one.','error'); return redirect(url_for('forgot_password'))
    if request.method=='POST':
        password=request.form.get('password','')
        if len(password)<8: flash('Password must be at least 8 characters.','error')
        else:
            c=db(); c.execute('UPDATE users SET password=? WHERE id=? AND email=?',(generate_password_hash(password),data['uid'],data['email'])); c.commit(); c.close()
            rl_reset(_rl_key('login-acct', data['email'])); flash('Password updated. Please sign in.','ok'); return redirect(url_for('patient_login'))
    return render_template('reset_password.html')

# Public form where a new staff member asks for access. Saved as a Pending request for an
# Admin to approve.
# Route: GET/POST /staff/request  |  Access: public
@app.route('/staff/request',methods=['GET','POST'])
def staff_request():
    if request.method=='POST':
        name=request.form.get('name','').strip(); email=request.form.get('email','').strip().lower(); password=request.form.get('password',''); requested_role=request.form.get('role','Clinic Staff')
        if len(name)<2 or len(password)<8 or '@' not in email or requested_role not in {'Clinic Staff','Optometrist'}: flash('Enter a name, valid email, password of at least 8 characters, and a permitted staff role.','error')
        else:
            c=db()
            if c.execute('SELECT 1 FROM users WHERE email=?',(email,)).fetchone() or c.execute("SELECT 1 FROM access_requests WHERE email=? AND status='Pending'",(email,)).fetchone(): flash('This email already has an account or pending request.','error')
            else: c.execute("INSERT INTO access_requests(email,password,status,name,role,created_at) VALUES(?,?,'Pending',?,?,?)",(email,generate_password_hash(password),name,requested_role,datetime.now().isoformat(timespec='seconds'))); c.commit(); flash('Staff access request submitted for administrator approval.','ok')
            c.close()
    return render_template('staff_request.html')

# Route: GET /healthz  |  Access: public
@app.route('/healthz')
def healthz():
    """Uptime-monitor endpoint: 200 when the app can reach the database, 503 otherwise."""
    try:
        c=db(); c.execute('SELECT 1').fetchone(); c.close()
    except Exception:
        app.logger.exception('Health check failed')
        return jsonify(status='error'), 503
    return jsonify(status='ok')

# Shows the Privacy Notice, with the clinic contact details from .env.
# Route: GET /privacy  |  Access: public
@app.route('/privacy')
def privacy():
    return render_template('privacy.html', clinic=os.getenv('CLINIC_NAME','HawkEye Optical Clinic'),
                           contact=os.getenv('CLINIC_CONTACT_EMAIL',''), address=os.getenv('CLINIC_ADDRESS',''))

# Signs the user out. POST only, so a stray link cannot log someone out.
# Route: GET/POST /logout  |  Access: public
@app.route('/logout',methods=['GET','POST'])
@csrf.exempt   # safe: the session cookie is SameSite=Lax, so other sites cannot POST on a visitor's behalf
def logout():
    # A plain GET (e.g. an old bookmark or a hostile <img> tag) must never sign anyone out.
    if request.method=='POST': session.clear()
    return redirect(url_for('index'))

# ---------------------------------------------------------------------------------------------
# Two-step sign-in (authenticator app + one-time backup codes) and "Sign in with Google".
# Everyone (staff and patients) can turn two-step sign-in on from the Security page. When it is on,
# a correct password (or a Google sign-in) is not enough: the person must also enter a code.
# ---------------------------------------------------------------------------------------------
MFA_PENDING_SECONDS = 5 * 60      # how long the code prompt stays open after the password step
MFA_MAX_FAILS = 5                 # wrong codes allowed per account per LOGIN_WINDOW before a lockout
MFA_ISSUER = 'HawkEye Optical Clinic'
ALL_ROLES = ('Admin', 'Clinic Staff', 'Optometrist', 'Patient')

# Decorator: any signed-in user (staff or patient) may open the page.
def any_user_required(f):
    @wraps(f)
    def w(*a, **k):
        if 'uid' not in session or session.get('role') not in ALL_ROLES: return redirect(url_for('index'))
        return f(*a, **k)
    return w

# Starts the real signed-in session for a user and sends them to their home page.
def finish_login(u, message=None):
    session.clear()
    if u['role'] == 'Patient': session.update(uid=u['id'], name=u['name'], role='Patient')
    else: session.update(uid=u['id'], name=u['name'], role=u['role'], branch_id=u['branch_id'])
    session.permanent = True
    if message: flash(message, 'ok')
    return redirect(url_for('patient_home' if u['role'] == 'Patient' else 'dashboard'))

# Called once the password (or Google) step succeeded. If the user has two-step sign-in on, they only get a
# short-lived "code pending" marker and must pass /mfa/verify; otherwise they are signed in straight away.
def begin_mfa_or_login(u, message=None):
    if u['mfa_enabled'] and u['mfa_secret']:
        session.clear(); session['mfa_pending'] = {'uid': u['id'], 'ts': int(_time.time())}
        return redirect(url_for('mfa_verify'))
    return finish_login(u, message)

# Checks a typed second-factor code for this user: a 6-digit authenticator code (each code works once) or a
# one-time backup code. Returns 'totp', 'backup' or None.
def verify_second_factor(c, u, raw):
    raw = (raw or '').strip()
    if raw and not any(ch.isalpha() for ch in raw):
        step = mfa.verify_totp(u['mfa_secret'], raw, u['mfa_last_step'])
        if step is None: return None
        # Atomic: only the first request that uses this step wins, so a code cannot be replayed.
        claimed = c.execute('UPDATE users SET mfa_last_step=? WHERE id=? AND (mfa_last_step IS NULL OR mfa_last_step<?)', (step, u['id'], step))
        c.commit()
        return 'totp' if claimed.rowcount == 1 else None
    code = mfa.normalize_backup_code(raw)
    if not code: return None
    row = c.execute('SELECT id FROM mfa_backup_codes WHERE user_id=? AND used=0 AND code_hash=?', (u['id'], mfa.hash_backup_code(u['id'], code))).fetchone()
    if not row: return None
    claimed = c.execute('UPDATE mfa_backup_codes SET used=1 WHERE id=? AND used=0', (row['id'],))
    c.commit()
    return 'backup' if claimed.rowcount == 1 else None

# True (and flashes a message) while this account or address is locked out of entering codes.
def mfa_blocked(uid):
    wait = rl_locked_seconds(_rl_key('mfa-acct', str(uid)), _rl_key('mfa-ip', client_ip()))
    if wait:
        flash(f'Too many incorrect codes. Please wait {max(1, wait // 60 + (1 if wait % 60 else 0))} minute(s) and try again.', 'error')
        return True
    return False

# Records a wrong code against the account and the IP address.
def mfa_failed(uid):
    locked = rl_hit(_rl_key('mfa-acct', str(uid)), MFA_MAX_FAILS, LOGIN_WINDOW)
    rl_hit(_rl_key('mfa-ip', client_ip()), LOGIN_IP_MAX_FAILS, LOGIN_WINDOW)
    if locked: app.logger.warning('Two-step code locked for user %s after repeated failures (ip %s)', uid, client_ip())

# Second step of sign-in: asks for the authenticator code (or a backup code) after the password was accepted.
# Route: GET/POST /mfa/verify  |  Access: only right after a correct password / Google sign-in
@app.route('/mfa/verify', methods=['GET', 'POST'])
def mfa_verify():
    pending = session.get('mfa_pending') or {}
    if not pending or _time.time() - pending.get('ts', 0) > MFA_PENDING_SECONDS:
        session.pop('mfa_pending', None)
        flash('Your sign-in expired. Please sign in again.', 'error')
        return redirect(url_for('index'))
    c = db()
    try:
        u = c.execute('SELECT * FROM users WHERE id=?', (pending.get('uid'),)).fetchone()
        if not (u and u['status'] == 'Active' and u['mfa_enabled'] and u['mfa_secret'] and (u['role'] == 'Patient' or u['email_verified'])):
            session.pop('mfa_pending', None)
            flash('Your sign-in expired. Please sign in again.', 'error')
            return redirect(url_for('index'))
        login_url = url_for('patient_login' if u['role'] == 'Patient' else 'staff_login')
        if request.method == 'POST':
            if mfa_blocked(u['id']): return render_template('mfa_verify.html', login_url=login_url)
            how = verify_second_factor(c, u, request.form.get('code', ''))
            if how:
                rl_reset(_rl_key('mfa-acct', str(u['id'])))
                note = None
                if how == 'backup':
                    left = c.execute('SELECT COUNT(*) AS n FROM mfa_backup_codes WHERE user_id=? AND used=0', (u['id'],)).fetchone()['n']
                    note = f'You signed in with a backup code. {left} backup code(s) left; you can make new ones on the Security page.'
                return finish_login(u, note)
            mfa_failed(u['id'])
            flash('That code is not correct. Try the newest code from your authenticator app, or a backup code.', 'error')
        return render_template('mfa_verify.html', login_url=login_url)
    finally:
        c.close()

# The signed-in user's own row (used by the Security page routes).
def _me(c):
    return c.execute('SELECT * FROM users WHERE id=?', (session.get('uid'),)).fetchone()

# Builds everything the Security page shows.
def _security_page(c, u, **extra):
    enabled = bool(u['mfa_enabled'] and u['mfa_secret'])
    setup_secret = session.get('mfa_setup_secret') if not enabled else None
    qr = key = None
    if setup_secret:
        qr = mfa.qr_data_uri(mfa.provisioning_uri(setup_secret, u['email'], MFA_ISSUER)); key = mfa.pretty_secret(setup_secret)
    left = c.execute('SELECT COUNT(*) AS n FROM mfa_backup_codes WHERE user_id=? AND used=0', (u['id'],)).fetchone()['n'] if enabled else 0
    patient = u['role'] == 'Patient'
    return render_template('account_security.html', u=u, mfa_enabled=enabled, setup=bool(setup_secret), qr=qr, setup_key=key,
                           codes_left=left, google_linked=bool(u['google_sub']), base='base_patient.html' if patient else 'base_staff.html',
                           p=patient_for_user() if patient else None, **extra)

# Replaces the user's backup codes with ten new ones and returns them for display (shown once, stored only hashed).
def _new_backup_codes(c, uid):
    codes = mfa.new_backup_codes()
    c.execute('DELETE FROM mfa_backup_codes WHERE user_id=?', (uid,))
    for code in codes: c.execute('INSERT INTO mfa_backup_codes(user_id,code_hash) VALUES(?,?)', (uid, mfa.hash_backup_code(uid, code)))
    return [mfa.format_backup_code(code) for code in codes]

# Records two-step changes in the audit log for staff accounts (patients are not part of the staff audit trail).
def _log_if_staff(c, text, uid):
    if session.get('role') != 'Patient': log_staff_action(c, text, 'user', uid)

# Security page: turn two-step sign-in on or off, see backup codes left, see whether Google is linked.
# Route: GET /account/security  |  Access: any signed-in user
@app.route('/account/security')
@any_user_required
def account_security():
    c = db()
    try: return _security_page(c, _me(c))
    finally: c.close()

# Begins setup: makes a fresh secret (kept only in the session until the first code is confirmed).
# Route: POST /account/mfa/start  |  Access: any signed-in user
@app.route('/account/mfa/start', methods=['POST'])
@any_user_required
def mfa_start():
    c = db()
    try:
        if _me(c)['mfa_enabled']: flash('Two-step sign-in is already on.', 'error')
        else: session['mfa_setup_secret'] = mfa.new_secret()
    finally: c.close()
    return redirect(url_for('account_security'))

# Abandons a setup that was started but not confirmed.
# Route: POST /account/mfa/cancel  |  Access: any signed-in user
@app.route('/account/mfa/cancel', methods=['POST'])
@any_user_required
def mfa_cancel():
    session.pop('mfa_setup_secret', None)
    return redirect(url_for('account_security'))

# Confirms setup with the first code from the authenticator app, switches two-step sign-in on and shows the
# backup codes once.
# Route: POST /account/mfa/enable  |  Access: any signed-in user
@app.route('/account/mfa/enable', methods=['POST'])
@any_user_required
def mfa_enable():
    secret = session.get('mfa_setup_secret'); uid = session['uid']
    if not secret:
        flash('Start the setup again.', 'error'); return redirect(url_for('account_security'))
    if mfa_blocked(uid): return redirect(url_for('account_security'))
    step = mfa.verify_totp(secret, request.form.get('code', ''))
    if step is None:
        mfa_failed(uid)
        flash('That code did not match. Make sure your phone’s date and time are set automatically, then enter the newest code.', 'error')
        return redirect(url_for('account_security'))
    c = db()
    try:
        c.execute('UPDATE users SET mfa_enabled=1, mfa_secret=?, mfa_last_step=? WHERE id=?', (secret, step, uid))
        codes = _new_backup_codes(c, uid)
        _log_if_staff(c, 'Turned on two-step sign-in', uid)
        c.commit()
        rl_reset(_rl_key('mfa-acct', str(uid)))
        session.pop('mfa_setup_secret', None)
        flash('Two-step sign-in is on.', 'ok')
        return _security_page(c, _me(c), new_codes=codes)
    finally: c.close()

# Turns two-step sign-in off. Needs a current authenticator code or a backup code.
# Route: POST /account/mfa/disable  |  Access: any signed-in user
@app.route('/account/mfa/disable', methods=['POST'])
@any_user_required
def mfa_disable():
    uid = session['uid']
    if mfa_blocked(uid): return redirect(url_for('account_security'))
    c = db()
    try:
        u = _me(c)
        if not (u['mfa_enabled'] and u['mfa_secret']): return redirect(url_for('account_security'))
        if not verify_second_factor(c, u, request.form.get('code', '')):
            mfa_failed(uid); flash('That code is not correct, so two-step sign-in was left on.', 'error'); return redirect(url_for('account_security'))
        c.execute('UPDATE users SET mfa_enabled=0, mfa_secret=NULL, mfa_last_step=NULL WHERE id=?', (uid,))
        c.execute('DELETE FROM mfa_backup_codes WHERE user_id=?', (uid,))
        _log_if_staff(c, 'Turned off two-step sign-in', uid)
        c.commit(); flash('Two-step sign-in is off.', 'ok')
    finally: c.close()
    return redirect(url_for('account_security'))

# Makes ten new backup codes (the old ones stop working). Needs a current authenticator code or a backup code.
# Route: POST /account/mfa/backup-codes  |  Access: any signed-in user
@app.route('/account/mfa/backup-codes', methods=['POST'])
@any_user_required
def mfa_backup_codes():
    uid = session['uid']
    if mfa_blocked(uid): return redirect(url_for('account_security'))
    c = db()
    try:
        u = _me(c)
        if not (u['mfa_enabled'] and u['mfa_secret']): return redirect(url_for('account_security'))
        if not verify_second_factor(c, u, request.form.get('code', '')):
            mfa_failed(uid); flash('That code is not correct, so the backup codes were not changed.', 'error'); return redirect(url_for('account_security'))
        codes = _new_backup_codes(c, uid)
        _log_if_staff(c, 'Made new two-step backup codes', uid)
        c.commit()
        return _security_page(c, _me(c), new_codes=codes)
    finally: c.close()

# Admin tool for someone locked out (lost phone and backup codes): switches their two-step sign-in off so they
# can sign in with their password and set it up again.
# Route: POST /staff/users/<int:user_id>/mfa-reset  |  Access: Admin only
@app.route('/staff/users/<int:user_id>/mfa-reset', methods=['POST'])
@staff_required
def reset_user_mfa(user_id):
    if session.get('role') != 'Admin': return 'Forbidden', 403
    if user_id == session.get('uid'):
        flash('Use the Security page to change your own two-step sign-in.', 'error'); return redirect(url_for('users'))
    c = db()
    try:
        target = c.execute('SELECT id,name,email FROM users WHERE id=?', (user_id,)).fetchone()
        if not target:
            flash('User not found.', 'error'); return redirect(url_for('users'))
        c.execute('UPDATE users SET mfa_enabled=0, mfa_secret=NULL, mfa_last_step=NULL WHERE id=?', (user_id,))
        c.execute('DELETE FROM mfa_backup_codes WHERE user_id=?', (user_id,))
        log_staff_action(c, f"Reset two-step sign-in for {target['email']}", 'user', user_id)
        c.commit(); flash(f"Two-step sign-in was switched off for {target['name']}. They can set it up again from the Security page.", 'ok')
    finally: c.close()
    return redirect(request.form.get('next') == 'patients' and url_for('patients') or url_for('users'))

# ---- Sign in / sign up with Google (patients only) ----
# The full address Google sends the visitor back to; register exactly this in Google Cloud Console.
def google_redirect_uri():
    return os.getenv('APP_BASE_URL', 'http://127.0.0.1:5000').rstrip('/') + url_for('google_callback')

# Lets templates hide the Google buttons when Google is not configured in .env.
@app.context_processor
def inject_google_enabled():
    return {'google_enabled': google_auth.configured()}

# Sends the visitor to Google. "Sign up" needs the Privacy Notice box ticked, exactly like the email sign-up.
# Route: POST /auth/google/start  |  Access: public
@app.route('/auth/google/start', methods=['POST'])
def google_start():
    intent = 'signup' if request.form.get('intent') == 'signup' else 'login'
    back = url_for('signup' if intent == 'signup' else 'patient_login')
    if not google_auth.configured():
        flash('Google sign-in is not set up on this server.', 'error'); return redirect(back)
    if too_many_requests('google', per_ip=30): return redirect(back)
    if intent == 'signup' and not request.form.get('consent'):
        flash('Please read and accept the Privacy Notice to create an account.', 'error'); return redirect(back)
    attempt = google_auth.new_attempt()
    session['google_oauth'] = {'state': attempt['state'], 'nonce': attempt['nonce'], 'verifier': attempt['verifier'],
                               'intent': intent, 'ts': int(_time.time())}
    return redirect(google_auth.authorize_url(attempt, google_redirect_uri()))

# Where Google sends the visitor back. Checks the attempt is the one we started, reads who signed in and hands
# over to google_sign_in().
# Route: GET /auth/google/callback  |  Access: public
@app.route('/auth/google/callback')
def google_callback():
    attempt = session.pop('google_oauth', None)
    if not attempt or _time.time() - attempt.get('ts', 0) > 600:
        flash('That Google sign-in expired. Please try again.', 'error'); return redirect(url_for('patient_login'))
    back = url_for('signup' if attempt['intent'] == 'signup' else 'patient_login')
    if request.args.get('error'):
        flash('Google sign-in was cancelled.', 'error'); return redirect(back)
    code = request.args.get('code', '')
    if not code or not secrets.compare_digest(request.args.get('state', '').encode(), attempt['state'].encode()):
        flash('That Google sign-in could not be verified. Please try again.', 'error'); return redirect(back)
    try:
        claims = google_auth.exchange_code(code, attempt['verifier'], google_redirect_uri())
        sub, email, name = google_auth.validate_claims(claims, attempt['nonce'])
    except google_auth.GoogleAuthError as exc:
        app.logger.warning('Google sign-in failed: %s', exc)
        flash('We could not sign you in with Google. Please try again, or use your email and password.', 'error'); return redirect(back)
    return google_sign_in(sub, email, name, attempt['intent'])

# Finds, links or creates the patient account for a verified Google identity, then continues like a normal
# sign-in (including the two-step code if that user turned it on).
# - Known Google account            -> sign in.
# - Existing patient, same email    -> link Google to it (Google has verified the address), sign in.
# - Staff account with that email   -> refused; staff use their password.
# - No account + "sign up"          -> create a patient account and an empty clinic record.
#   If the clinic already holds a record under that email, nothing is created: claiming it needs the patient ID +
#   birthdate check on the normal sign-up form, exactly as for email sign-up.
def google_sign_in(sub, email, name, intent):
    c = db()
    try:
        u = c.execute('SELECT * FROM users WHERE google_sub=?', (sub,)).fetchone()
        note = None
        if not u:
            u = c.execute('SELECT * FROM users WHERE lower(email)=?', (email,)).fetchone()
            if u:
                if u['role'] != 'Patient':
                    flash('Staff accounts sign in with their email and password.', 'error'); return redirect(url_for('staff_login'))
                if u['google_sub'] or u['status'] != 'Active':
                    flash('This account cannot use Google sign-in. Sign in with your email and password, or contact the clinic.', 'error'); return redirect(url_for('patient_login'))
                c.execute('UPDATE users SET google_sub=?, email_verified=1 WHERE id=? AND google_sub IS NULL', (sub, u['id'])); c.commit()
                note = 'Your Google account is now linked to your HawkEye account.'
            else:
                if intent != 'signup':
                    flash('No HawkEye account uses that Google email yet. Use “Sign up with Google” to create one.', 'error'); return redirect(url_for('signup'))
                if len(email) > 190 or not _EMAIL_RE.match(email):
                    flash('That Google email address cannot be used.', 'error'); return redirect(url_for('signup'))
                if c.execute('SELECT 1 FROM patients WHERE lower(email)=? LIMIT 1', (email,)).fetchone():
                    flash('A clinic record may already exist for this email. Create your account with the form below and enter your patient ID and birthdate to link it, or contact the clinic.', 'error')
                    return redirect(url_for('signup'))
                display = name[:100] if len(name) >= 2 else email.split('@')[0][:100].ljust(2, '_')
                try:
                    cur = c.execute("INSERT INTO users(name,email,password,role,status,email_verified,branch_id,google_sub) VALUES(?,?,?,'Patient','Active',1,1,?)",
                                    (display, email, generate_password_hash(secrets.token_urlsafe(32)), sub))
                    c.execute('INSERT INTO patients(patient_id,name,email,user_id,channel,branch_id) VALUES(?,?,?,?,?,1)',
                              (new_patient_code(c), display, email, cur.lastrowid, 'Email'))
                    c.commit()
                except IntegrityError:
                    c.rollback(); flash('An account with this email already exists. Please sign in.', 'error'); return redirect(url_for('patient_login'))
                u = c.execute('SELECT * FROM users WHERE id=?', (cur.lastrowid,)).fetchone()
                note = 'Welcome! Your account was created with Google.'
        elif u['status'] != 'Active':
            flash('Invalid patient email or password.', 'error'); return redirect(url_for('patient_login'))
        return begin_mfa_or_login(u, note)
    finally:
        c.close()

# Staff home: today's counts, the appointment action queue, urgent (missed/incomplete)
# patients and a clinic snapshot. Admins see all branches; others see their own.
# Route: GET /staff/dashboard  |  Access: staff only (Admin, Clinic Staff or Optometrist)
@app.route('/staff/dashboard')
@staff_required
def dashboard():
    c = db()
    today = date.today().isoformat()
    branch_id = session.get('branch_id') or 1
    scope = '' if session.get('role') == 'Admin' else ' WHERE branch_id=?'
    params = () if session.get('role') == 'Admin' else (branch_id,)

    def count(sql, values=()):
        return c.execute(sql, values).fetchone()[0]

    if session.get('role') == 'Admin':
        stats = {
            'patients': count('SELECT COUNT(*) FROM patients'),
            'appointments': count("SELECT COUNT(*) FROM appointments WHERE date=? AND status NOT IN ('Cancelled','Rejected')", (today,)),
            'pending': count("SELECT COUNT(*) FROM appointments WHERE status IN ('Pending','Requested')"),
            'followups': count("SELECT COUNT(*) FROM appointments WHERE type IN ('Follow-up','Prescription review') AND date>=? AND status NOT IN ('Cancelled','Rejected','Completed')", (today,)),
            'overdue': count("SELECT COUNT(*) FROM appointments WHERE status IN ('Pending','Requested','Missed') AND date<?", (today,)),
            'reminders': count("SELECT COUNT(*) FROM reminders WHERE status='Sent'"),
            'new_patients': count("SELECT COUNT(*) FROM patients p WHERE EXISTS (SELECT 1 FROM appointments a WHERE a.patient_id=p.id AND a.id=(SELECT MIN(a2.id) FROM appointments a2 WHERE a2.patient_id=p.id) AND a.date>=?)", ((date.today()-timedelta(days=7)).isoformat(),)),
        }
        max_id = count('SELECT COALESCE(MAX(id),0) FROM appointments')
        appts = c.execute("""SELECT a.*, p.id AS patient_pk, p.name, p.patient_id AS code,
            CASE WHEN a.id=(SELECT MIN(ax.id) FROM appointments ax WHERE ax.patient_id=a.patient_id) AND NOT EXISTS (SELECT 1 FROM patient_reviews pr WHERE pr.patient_id=a.patient_id) THEN 1 ELSE 0 END AS is_new_patient
            FROM appointments a JOIN patients p ON p.id=a.patient_id WHERE a.date=? AND a.status NOT IN ('Cancelled','Rejected','Ignored','Completed','Missed','Attended')
            ORDER BY CASE WHEN a.status IN ('Pending','Requested') AND a.date<? THEN 0
                          WHEN a.status IN ('Pending','Requested') THEN 1
                          WHEN a.status='Confirmed' AND a.date=? THEN 2
                          WHEN a.status='Confirmed' AND a.date>? THEN 3
                          WHEN a.status='Missed' THEN 4 ELSE 5 END,
                     a.date ASC, a.time ASC LIMIT 12""", (today,today,today,today)).fetchall()
    else:
        stats = {
            'patients': count('SELECT COUNT(*) FROM patients WHERE branch_id=?', (branch_id,)),
            'appointments': count("SELECT COUNT(*) FROM appointments WHERE date=? AND branch_id=? AND status NOT IN ('Cancelled','Rejected')", (today, branch_id)),
            'pending': count("SELECT COUNT(*) FROM appointments WHERE status IN ('Pending','Requested') AND branch_id=?", (branch_id,)),
            'followups': count("SELECT COUNT(*) FROM appointments WHERE type IN ('Follow-up','Prescription review') AND date>=? AND branch_id=? AND status NOT IN ('Cancelled','Rejected','Completed')", (today, branch_id)),
            'overdue': count("SELECT COUNT(*) FROM appointments WHERE status IN ('Pending','Requested','Missed') AND date<? AND branch_id=?", (today, branch_id)),
            'reminders': count("SELECT COUNT(*) FROM reminders r JOIN patients p ON p.id=r.patient_id WHERE r.status='Sent' AND p.branch_id=?", (branch_id,)),
            'new_patients': count("SELECT COUNT(*) FROM patients p WHERE p.branch_id=? AND EXISTS (SELECT 1 FROM appointments a WHERE a.patient_id=p.id AND a.id=(SELECT MIN(a2.id) FROM appointments a2 WHERE a2.patient_id=p.id) AND a.date>=?)", (branch_id, (date.today()-timedelta(days=7)).isoformat())),
        }
        max_id = count('SELECT COALESCE(MAX(id),0) FROM appointments WHERE branch_id=?', (branch_id,))
        appts = c.execute("""SELECT a.*, p.id AS patient_pk, p.name, p.patient_id AS code,
            CASE WHEN a.id=(SELECT MIN(ax.id) FROM appointments ax WHERE ax.patient_id=a.patient_id) AND NOT EXISTS (SELECT 1 FROM patient_reviews pr WHERE pr.patient_id=a.patient_id) THEN 1 ELSE 0 END AS is_new_patient
            FROM appointments a JOIN patients p ON p.id=a.patient_id WHERE a.branch_id=? AND a.date=? AND a.status NOT IN ('Cancelled','Rejected','Ignored','Completed','Missed','Attended')
            ORDER BY CASE WHEN a.status IN ('Pending','Requested') AND a.date<? THEN 0
                          WHEN a.status IN ('Pending','Requested') THEN 1
                          WHEN a.status='Confirmed' AND a.date=? THEN 2
                          WHEN a.status='Confirmed' AND a.date>? THEN 3
                          WHEN a.status='Missed' THEN 4 ELSE 5 END,
                     a.date ASC, a.time ASC LIMIT 12""", (branch_id,today,today,today,today)).fetchall()
    if session.get('role')=='Admin':
        urgent=c.execute("SELECT a.id AS appointment_id,a.status,a.date,a.time,a.type,p.id AS pid,p.name,p.email,p.phone,p.patient_id AS code FROM appointments a JOIN patients p ON p.id=a.patient_id WHERE COALESCE(a.reminder_status,'')!='Resolved' AND (a.status IN ('Missed','Incomplete') OR (a.status IN ('Pending','Requested') AND a.date<=?)) ORDER BY a.date,a.time LIMIT 30",(today,)).fetchall()
    else:
        urgent=c.execute("SELECT a.id AS appointment_id,a.status,a.date,a.time,a.type,p.id AS pid,p.name,p.email,p.phone,p.patient_id AS code FROM appointments a JOIN patients p ON p.id=a.patient_id WHERE p.branch_id=? AND COALESCE(a.reminder_status,'')!='Resolved' AND (a.status IN ('Missed','Incomplete') OR (a.status IN ('Pending','Requested') AND a.date<=?)) ORDER BY a.date,a.time LIMIT 30",(branch_id,today)).fetchall()
    c.close()
    return render_template('dashboard.html', stats=stats, appts=appts, urgent=urgent, today=today, latest_appointment_id=max_id)

# Tiny JSON endpoint the dashboard polls every 15 s to learn whether a new booking arrived.
# Route: GET /api/staff/dashboard-state  |  Access: staff only (Admin, Clinic Staff or Optometrist)
@app.route('/api/staff/dashboard-state')
@staff_required
def staff_dashboard_state():
    c = db()
    if session.get('role') == 'Admin':
        latest = c.execute('SELECT COALESCE(MAX(id),0) FROM appointments').fetchone()[0]
    else:
        latest = c.execute('SELECT COALESCE(MAX(id),0) FROM appointments WHERE branch_id=?', (session.get('branch_id') or 1,)).fetchone()[0]
    c.close()
    return jsonify(ok=True, latest_appointment_id=latest)

# Patient directory with name/ID search and a day view of clinic sessions, limited to the
# staff member's branch (Admin: all).
# Route: GET /staff/patients  |  Access: staff only (Admin, Clinic Staff or Optometrist)
@app.route('/staff/patients')
@staff_required
def patients():
    q = request.args.get('q', '').strip()
    selected = request.args.get('day', date.today().isoformat())
    try:
        datetime.strptime(selected, '%Y-%m-%d')
    except ValueError:
        selected = date.today().isoformat()
    c = db()
    branch_filter = '' if session.get('role') == 'Admin' else ' AND p.branch_id=?'
    branch_params = () if session.get('role') == 'Admin' else (session.get('branch_id') or 1,)
    todays = c.execute(
        "SELECT a.id AS appointment_id,a.patient_id,a.type,a.date,a.time,a.status,p.patient_id AS code,p.name,p.phone,p.email "
        "FROM appointments a JOIN patients p ON p.id=a.patient_id WHERE a.date=?" +
        ('' if session.get('role') == 'Admin' else ' AND a.branch_id=?') +
        " AND a.status NOT IN ('Cancelled','Rejected','Ignored') ORDER BY a.time ASC",
        (date.today().isoformat(),) + branch_params
    ).fetchall()
    if session.get('role') == 'Admin':
        directory = c.execute(
            "SELECT * FROM patients WHERE name LIKE ? OR patient_id LIKE ? ORDER BY name",
            (f'%{q}%', f'%{q}%')
        ).fetchall()
    else:
        bid = session.get('branch_id') or 1
        directory = c.execute(
            "SELECT * FROM patients WHERE branch_id=? AND (name LIKE ? OR patient_id LIKE ?) ORDER BY name",
            (bid, f'%{q}%', f'%{q}%')
        ).fetchall()
    c.close()
    return render_template('patients.html', patients=directory, q=q, todays=todays,
                           selected_day=selected, today=date.today().isoformat())

# Edits the notes/outcome of a patient's latest clinic session. Older sessions are read-only.
# Route: POST /staff/patient-session/<int:sid>/edit  |  Access: staff only (Admin, Clinic Staff or Optometrist)
@app.route('/staff/patient-session/<int:sid>/edit',methods=['POST'])
@staff_required
def patient_session_edit(sid):
    c=db(); row=c.execute('SELECT s.*,p.branch_id FROM patient_sessions s JOIN patients p ON p.id=s.patient_id WHERE s.id=?',(sid,)).fetchone()
    if not row: c.close(); flash('Clinic session not found.','error'); return redirect(url_for('patients'))
    if session.get('role')!='Admin' and row['branch_id']!=(session.get('branch_id') or 1): c.close(); return 'Forbidden',403
    latest=c.execute('SELECT MAX(id) FROM patient_sessions WHERE patient_id=?',(row['patient_id'],)).fetchone()[0]
    if latest != sid: c.close(); flash('Only the latest clinic session can be edited. Older session logs are read-only.','error'); return redirect(url_for('patients',day=row['visit_date']))
    notes=request.form.get('notes','').strip()[:2000]; outcome=request.form.get('outcome','').strip()[:500]
    c.execute('UPDATE patient_sessions SET notes=?,outcome=?,updated_at=? WHERE id=?',(notes,outcome,datetime.now().strftime('%Y-%m-%d %H:%M:%S'),sid)); log_staff_action(c,'Updated latest clinic session','patient_session',sid); c.commit(); c.close()
    flash('Clinic session updated.','ok'); return redirect(url_for('patients',day=request.form.get('day',row['visit_date'])))

# Marks a newly registered patient as reviewed by staff (clears the 'new patient' tag).
# Route: POST /staff/patient/<int:pid>/review  |  Access: staff only (Admin, Clinic Staff or Optometrist)
@app.route('/staff/patient/<int:pid>/review',methods=['POST'])
@staff_required
def mark_patient_reviewed(pid):
    c=db(); pat=c.execute('SELECT * FROM patients WHERE id=?',(pid,)).fetchone()
    if not pat: c.close(); return 'Patient not found',404
    if session.get('role')!='Admin' and pat['branch_id']!=(session.get('branch_id') or 1): c.close(); return 'Forbidden',403
    c.execute('INSERT INTO patient_reviews(patient_id,reviewed_by,reviewed_at) VALUES(?,?,?) ON DUPLICATE KEY UPDATE reviewed_by=VALUES(reviewed_by),reviewed_at=VALUES(reviewed_at)',(pid,session.get('uid'),datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    log_staff_action(c,'Reviewed new patient','patient',pid); c.commit(); c.close(); flash('Patient marked as reviewed.','ok'); return redirect(url_for('patients'))

# Registers a walk-in visit for an existing or new patient and creates the appointment and
# clinic session.
# Route: GET/POST /staff/walk-in  |  Access: staff only (Admin, Clinic Staff or Optometrist)
@app.route('/staff/walk-in',methods=['GET','POST'])
@staff_required
def walk_in():
    c=db(); bid=session.get('branch_id') or 1
    pts=c.execute('SELECT * FROM patients '+('' if session.get('role')=='Admin' else 'WHERE branch_id=? ')+ 'ORDER BY name',(() if session.get('role')=='Admin' else (bid,))).fetchall()
    if request.method=='POST':
        patient_id=request.form.get('patient_id','').strip(); now=datetime.now(); visit_type=request.form.get('type','Eye check')
        if patient_id:
            pat=c.execute('SELECT * FROM patients WHERE id=?',(patient_id,)).fetchone()
            if not pat or (session.get('role')!='Admin' and pat['branch_id']!=bid): c.close(); flash('Choose a valid patient for your branch.','error'); return redirect(url_for('walk_in'))
            pid=pat['id']
        else:
            name=request.form.get('name','').strip(); email=request.form.get('email','').strip(); phone=request.form.get('phone','').strip()
            if not name: c.close(); flash('Enter a patient name or choose an existing patient.','error'); return redirect(url_for('walk_in'))
            code=new_patient_code(c)
            cur=c.execute('INSERT INTO patients(patient_id,name,phone,email,channel,branch_id) VALUES(?,?,?,?,?,?)',(code,name,phone,email,'Email' if email else 'SMS',bid)); pid=cur.lastrowid
        stamp=now.strftime('%H:%M')
        cur=c.execute('INSERT INTO appointments(patient_id,type,date,time,status,reminder_status,notes,branch_id) VALUES(?,?,?,?,?,?,?,?)',(pid,visit_type,now.date().isoformat(),stamp,'Attended','Not required','Walk-in recorded by staff',bid))
        ts=now.strftime('%Y-%m-%d %H:%M:%S'); c.execute('INSERT INTO patient_sessions(patient_id,visit_date,visit_type,notes,outcome,recorded_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)',(pid,now.date().isoformat(),visit_type,'Walk-in visit','In progress',session.get('uid'),ts,ts)); log_staff_action(c,'Added walk-in','appointment',cur.lastrowid); c.commit(); c.close(); flash('Walk-in patient and clinic session saved.','ok'); return redirect(url_for('patients',day=now.date().isoformat()))
    c.close(); return render_template('walk_in.html',patients=pts)

# Marks a missed/incomplete appointment as resolved so it leaves the urgent list.
# Route: POST /staff/urgent/<int:aid>/resolve  |  Access: staff only (Admin, Clinic Staff or Optometrist)
@app.route('/staff/urgent/<int:aid>/resolve', methods=['POST'])
@staff_required
def resolve_urgent_appointment(aid):
    c = db()
    appt = c.execute('SELECT * FROM appointments WHERE id=?', (aid,)).fetchone()
    if not appt:
        c.close()
        flash('Appointment not found.', 'error')
        return redirect(url_for('dashboard'))
    if session.get('role') != 'Admin' and appt['branch_id'] != (session.get('branch_id') or 1):
        c.close()
        return 'Forbidden', 403
    c.execute("UPDATE appointments SET reminder_status='Resolved' WHERE id=?", (aid,))
    log_staff_action(c, 'Resolved urgent appointment item', 'appointment', aid)
    c.commit()
    c.close()
    flash('Removed from urgent patients. The appointment history was preserved.', 'ok')
    return redirect(url_for('dashboard'))


# Contacts a patient about a missed visit by email, website chat or SMS (prototype) and logs a
# reminder.
# Route: POST /staff/urgent-contact/<int:pid>/<channel>  |  Access: staff only (Admin, Clinic Staff or Optometrist)
@app.route('/staff/urgent-contact/<int:pid>/<channel>',methods=['POST'])
@staff_required
def urgent_contact(pid,channel):
    if channel not in {'email','chat','sms'}: return 'Invalid contact method',400
    c=db(); pat=c.execute('SELECT * FROM patients WHERE id=?',(pid,)).fetchone()
    if not pat: c.close(); return 'Patient not found',404
    if session.get('role')!='Admin' and pat['branch_id']!=(session.get('branch_id') or 1): c.close(); return 'Forbidden',403
    body=request.form.get('message','').strip()[:1000] or 'HawkEye Optical Clinic would like to help you arrange your follow-up visit.'
    if channel=='email':
        if not pat['email']: c.close(); flash('This patient has no email address saved.','error'); return redirect(url_for('dashboard'))
        ok,detail=send_email(pat['email'],'HawkEye Optical Clinic follow-up needed',f'<p>Hello {esc(pat["name"])},</p><p>{esc(body)}</p><p>HawkEye Optical Clinic</p>',f'Hello {pat["name"]},\n{body}\nHawkEye Optical Clinic')
        post_website_reminder(c,pid,None,body,'Email + Website' if ok else 'Website (email failed)','Sent' if ok else 'Failed')
        flash('Follow-up email sent and posted on the patient website.' if ok else 'Email failed ('+detail+'), but the reminder is on the patient website.','ok')
    elif channel=='chat':
        c.execute('INSERT INTO clinic_chat_messages(patient_id,staff_id,message,created_at,read_status) VALUES(?,?,?,?,?)',(pid,session.get('uid'),body,datetime.now().strftime('%Y-%m-%d %H:%M:%S'),'Unread')); flash('Message sent to the patient\'s Clinic Chat.','ok')
    else:
        post_website_reminder(c,pid,None,body,'Website (SMS prototype)','Prototype - Not Sent'); flash('SMS prototype saved and posted on the patient website. No SMS was sent.','ok')
    log_staff_action(c,'Contacted urgent patient via '+channel,'patient',pid); c.commit(); c.close(); return redirect(url_for('dashboard'))

# Creates a new patient (/staff/patient/new) or edits an existing one's details. Branch-
# restricted.
# Route: GET/POST /staff/patient/new , GET/POST /staff/patient/<int:pid>/edit  |  Access: staff only (Admin, Clinic Staff or Optometrist)
@app.route('/staff/patient/new',methods=['GET','POST'])
@app.route('/staff/patient/<int:pid>/edit',methods=['GET','POST'])
@staff_required
def patient_edit(pid=None):
    c=db(); p=c.execute('SELECT * FROM patients WHERE id=?',(pid,)).fetchone() if pid else None
    if p and session.get('role')!='Admin' and p['branch_id']!=(session.get('branch_id') or 1): c.close(); return 'Forbidden: patient belongs to another branch',403
    if request.method=='POST':
        vals=(request.form['patient_id'],request.form['name'],request.form['birthdate'],request.form['phone'],request.form['email'],request.form['address'],request.form['channel'])
        if pid:c.execute('UPDATE patients SET patient_id=?,name=?,birthdate=?,phone=?,email=?,address=?,channel=? WHERE id=?',vals+(pid,))
        else:c.execute('INSERT INTO patients(patient_id,name,birthdate,phone,email,address,channel,branch_id) VALUES(?,?,?,?,?,?,?,?)',vals+(session.get('branch_id') or 1,))
        c.commit(); c.close(); return redirect(url_for('patients'))
    c.close(); return render_template('patient_edit.html',p=p)
# Lists prescriptions recorded in the clinic (all branches for Admin, own branch otherwise).
# Route: GET /staff/prescriptions  |  Access: staff only (Admin, Clinic Staff or Optometrist)
@app.route('/staff/prescriptions')
@staff_required
def prescriptions():
    c=db()
    if session.get('role')=='Admin': rows=c.execute('SELECT p.*,pt.name,pt.patient_id AS code FROM prescriptions p JOIN patients pt ON pt.id=p.patient_id ORDER BY p.recorded DESC').fetchall()
    else: rows=c.execute('SELECT p.*,pt.name,pt.patient_id AS code FROM prescriptions p JOIN patients pt ON pt.id=p.patient_id WHERE pt.branch_id=? ORDER BY p.recorded DESC',(session.get('branch_id') or 1,)).fetchall()
    c.close(); return render_template('prescriptions.html',rows=rows)
# A patient's prescription history. Admins and Optometrists can add or edit entries; other
# staff can only view.
# Route: GET/POST /staff/prescription/<int:pid>  |  Access: staff only (Admin, Clinic Staff or Optometrist)
@app.route('/staff/prescription/<int:pid>', methods=['GET', 'POST'])
@staff_required
def prescription(pid):
    c = db()
    pat = c.execute('SELECT * FROM patients WHERE id=?', (pid,)).fetchone()
    if not pat:
        c.close()
        return 'Patient not found', 404
    if session.get('role') != 'Admin' and pat['branch_id'] != (session.get('branch_id') or 1):
        c.close()
        return 'Forbidden: patient belongs to another branch', 403
    if request.method == 'POST' and session.get('role') not in {'Admin', 'Optometrist'}:
        c.close()
        return 'Forbidden: only an optometrist or admin may edit prescription records', 403

    edit_id = request.args.get('edit', type=int)
    if request.method == 'POST':
        edit_id = request.form.get('rx_id', type=int) or edit_id
        data = (
            request.form.get('recorded', '').strip(),
            request.form.get('optometrist', '').strip(),
            request.form.get('od_sphere', '').strip(),
            request.form.get('od_cylinder', '').strip(),
            request.form.get('od_axis', '').strip(),
            request.form.get('od_add', '').strip(),
            request.form.get('od_pd', '').strip(),
            request.form.get('os_sphere', '').strip(),
            request.form.get('os_cylinder', '').strip(),
            request.form.get('os_axis', '').strip(),
            request.form.get('os_add', '').strip(),
            request.form.get('os_pd', '').strip(),
            request.form.get('notes', '').strip(),
            request.form.get('return_date', '').strip(),
            request.form.get('reference', '').strip() or 'RX-NEW',
        )
        if not data[0]:
            c.close()
            flash('Please enter the date recorded.', 'error')
            return redirect(url_for('prescription', pid=pid, edit=edit_id) if edit_id else url_for('prescription', pid=pid))
        if edit_id:
            existing = c.execute('SELECT id FROM prescriptions WHERE id=? AND patient_id=?', (edit_id, pid)).fetchone()
            if not existing:
                c.close()
                flash('That prescription record was not found for this patient.', 'error')
                return redirect(url_for('prescription', pid=pid))
            c.execute(
                "UPDATE prescriptions SET recorded=?,optometrist=?,od_sphere=?,od_cylinder=?,od_axis=?,od_add=?,od_pd=?,os_sphere=?,os_cylinder=?,os_axis=?,os_add=?,os_pd=?,notes=?,return_date=?,reference=? WHERE id=? AND patient_id=?",
                data + (edit_id, pid)
            )
            saved_id = edit_id
            flash('Prescription updated. Your notes and all fields were saved.', 'ok')
        else:
            c.execute(
                "INSERT INTO prescriptions(patient_id,recorded,optometrist,od_sphere,od_cylinder,od_axis,od_add,od_pd,os_sphere,os_cylinder,os_axis,os_add,os_pd,notes,return_date,reference) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (pid,) + data
            )
            saved_id = c.execute('SELECT LAST_INSERT_ID()').fetchone()[0]
            flash('New prescription saved to the patient history.', 'ok')
        c.commit()
        c.close()
        return redirect(url_for('prescription', pid=pid, edit=saved_id))

    rx = None
    if edit_id:
        rx = c.execute('SELECT * FROM prescriptions WHERE id=? AND patient_id=?', (edit_id, pid)).fetchone()
        if not rx:
            flash('Prescription record not found. Showing the latest record instead.', 'error')
    if rx is None and request.args.get('new') != '1':
        rx = c.execute('SELECT * FROM prescriptions WHERE patient_id=? ORDER BY recorded DESC,id DESC LIMIT 1', (pid,)).fetchone()
    hist = c.execute('SELECT * FROM prescriptions WHERE patient_id=? ORDER BY recorded DESC,id DESC', (pid,)).fetchall()
    c.close()
    return render_template('prescription.html', p=pat, rx=rx, hist=hist, today=date.today().isoformat(), editing=bool(rx and request.args.get('new') != '1' and (not edit_id or rx['id'] == edit_id)))


# Loads appointment rows for the staff lists, optionally only follow-ups; branch-scoped for
# non-admins.
def _staff_appointment_rows(connection, followup_only=False):
    today = date.today().isoformat()
    where = []
    values = []
    if followup_only:
        where.append("a.type IN ('Follow-up','Prescription review')")
    if session.get('role') != 'Admin':
        where.append('a.branch_id=?')
        values.append(session.get('branch_id') or 1)
    clause = (' WHERE ' + ' AND '.join(where)) if where else ''
    sql = """SELECT a.*,p.name,p.patient_id AS code,(SELECT u.name FROM users u WHERE u.id=a.doctor_id) AS doctor_name,
        CASE WHEN a.id=(SELECT MIN(ax.id) FROM appointments ax WHERE ax.patient_id=a.patient_id) AND NOT EXISTS (SELECT 1 FROM patient_reviews pr WHERE pr.patient_id=a.patient_id) THEN 1 ELSE 0 END AS is_new_patient
        FROM appointments a JOIN patients p ON p.id=a.patient_id""" + clause + """ ORDER BY
        CASE WHEN a.status IN ('Pending','Requested') AND a.date<? THEN 0
             WHEN a.status IN ('Pending','Requested') THEN 1
             WHEN a.status='Confirmed' AND a.date=? THEN 2
             WHEN a.status='Confirmed' AND a.date>? THEN 3
             WHEN a.status='Missed' THEN 4 ELSE 5 END,
        a.date ASC, a.time ASC"""
    return connection.execute(sql, values + [today, today, today]).fetchall()

# Staff list of all appointments with status actions and doctor assignment.
# Route: GET /staff/appointments  |  Access: staff only (Admin, Clinic Staff or Optometrist)
@app.route('/staff/appointments')
@staff_required
def appointments():
    c=db(); rows=_staff_appointment_rows(c); doctors=_doctors_in_scope(c); c.close()
    return render_template('appointments.html',rows=rows,title='Appointments',doctors=doctors)

# Staff list of follow-up and prescription-review appointments only.
# Route: GET /staff/followups  |  Access: staff only (Admin, Clinic Staff or Optometrist)
@app.route('/staff/followups')
@staff_required
def followups():
    c=db(); rows=_staff_appointment_rows(c, True); doctors=_doctors_in_scope(c); c.close()
    return render_template('appointments.html',rows=rows,title='Follow-Ups',doctors=doctors)
# Staff schedules an appointment for a patient (future date, no double-booking at the same
# time and branch).
# Route: GET/POST /staff/appointment/new  |  Access: staff only (Admin, Clinic Staff or Optometrist)
@app.route('/staff/appointment/new',methods=['GET','POST'])
@staff_required
def appointment_new():
    c=db()
    try:
        is_admin=session.get('role')=='Admin'; my_branch=session.get('branch_id') or 1
        if request.method=='POST':
            try: chosen=datetime.strptime(request.form.get('date','')+' '+request.form.get('time',''),'%Y-%m-%d %H:%M')
            except ValueError: flash('Invalid appointment date or time.','error'); return redirect(url_for('appointment_new'))
            if chosen < datetime.now(): flash('Appointment must be in the future.','error'); return redirect(url_for('appointment_new'))
            day,clock=chosen.strftime('%Y-%m-%d'),chosen.strftime('%H:%M')     # canonical text, whatever the browser sent ('9:30' -> '09:30')
            pid=request.form.get('patient_id',type=int)
            pat=c.execute('SELECT id,branch_id FROM patients WHERE id=?',(pid,)).fetchone() if pid else None
            # The dropdown only lists the staff member's own branch, so the POST must enforce the same rule.
            if not pat or (not is_admin and pat['branch_id']!=my_branch): flash('Select a valid patient.','error'); return redirect(url_for('appointment_new'))
            branch_id=pat['branch_id'] or 1
            appt_type=request.form.get('type','').strip()
            if not appt_type or len(appt_type)>80: flash('Choose a reason for the visit.','error'); return redirect(url_for('appointment_new'))
            doc=None; lock_names=[f'hawkeye:slot:{branch_id}:{day}:{clock}']
            if request.form.get('doctor_id'):
                doc=_doctor_or_none(c, request.form.get('doctor_id'), branch_id)
                if not doc: flash('Choose a valid doctor for this patient\'s branch.','error'); return redirect(url_for('appointment_new'))
                lock_names.append(f'hawkeye:doctor:{doc["id"]}:{day}:{_appt_hour(clock)}')
            is_followup = appt_type in {'Follow-up', 'Prescription review'}
            # Check-then-insert must be atomic across all worker processes, so hold a named DB lock for the
            # branch slot (and the doctor's hour) while we check and write.
            with db_locks(*lock_names) as got:
                if not got: flash('Another booking is being saved right now. Please try again in a moment.','error'); return redirect(url_for('appointment_new'))
                c.execute('START TRANSACTION')        # fresh snapshot: sees anything committed while we waited for the lock
                if c.execute("SELECT 1 FROM appointments WHERE date=? AND time=? AND branch_id=? AND status NOT IN ('Cancelled','Completed','Rejected') LIMIT 1",(day,clock,branch_id)).fetchone():
                    c.rollback(); flash('That time slot is already booked at this branch. Choose another time.','error'); return redirect(url_for('appointment_new'))
                if doc and _doctor_hour_busy(c, doc['id'], day, clock):
                    c.rollback(); flash(f"{doc['name']} already has a patient booked in that hour. Pick another hour or doctor.",'error'); return redirect(url_for('appointment_new'))
                cur = c.execute('INSERT INTO appointments(patient_id,type,date,time,status,reminder_status,notes,branch_id,doctor_id) VALUES(?,?,?,?,?,?,?,?,?)',
                                (pat['id'], appt_type, day, clock, 'Pending', 'Follow-up scheduled' if is_followup else 'Waiting', request.form.get('notes','').strip()[:2000], branch_id, doc['id'] if doc else None))
                if is_followup:
                    message = f"HawkEye Optical Clinic scheduled a {appt_type.lower()} for you on {day} at {clock}. Open Appointments and press Comply to acknowledge this follow-up."
                    c.execute('INSERT INTO reminders(patient_id,appointment_id,channel,message,sent_date,status,read_status) VALUES(?,?,?,?,?,?,?)',
                              (pat['id'], cur.lastrowid, 'In-app', message, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'Scheduled', 'Unread'))
                c.commit()
            flash('Follow-up scheduled and patient reminder created.' if is_followup else 'Appointment saved.', 'ok')
            return redirect(url_for('appointments'))
        pts=c.execute('SELECT * FROM patients ORDER BY name').fetchall() if is_admin else c.execute('SELECT * FROM patients WHERE branch_id=? ORDER BY name',(my_branch,)).fetchall()
        return render_template('appointment_new.html', patients=pts, today=date.today().isoformat(), doctors=_doctors_in_scope(c))
    finally:
        c.close()
# Changes an appointment's status (Confirm, Complete, Miss, Cancel, ...). Completing one also
# logs a clinic session.
# Route: POST /staff/appointment/<int:aid>/status/<status>  |  Access: staff only (Admin, Clinic Staff or Optometrist)
@app.route('/staff/appointment/<int:aid>/status/<status>',methods=['POST'])
@staff_required
def appointment_status(aid,status):
    allowed={'Pending','Requested','Confirmed','Attended','Completed','Missed','Cancelled','Rejected','Ignored','Incomplete'}
    if status not in allowed: return 'Invalid status',400
    c=db(); a=c.execute('SELECT * FROM appointments WHERE id=?',(aid,)).fetchone()
    if not a: c.close(); flash('Appointment not found.','error'); return redirect(url_for('appointments'))
    if session.get('role')!='Admin' and a['branch_id']!=(session.get('branch_id') or 1): c.close(); return 'Forbidden: appointment belongs to another branch',403
    c.execute("UPDATE appointments SET status=?,request_only=CASE WHEN ? IN ('Confirmed','Rejected') THEN 0 ELSE request_only END WHERE id=?",(status,status,aid))
    if status in {'Completed','Attended'}:
        existing=c.execute('SELECT id FROM patient_sessions WHERE patient_id=? AND visit_date=? AND visit_type=?',(a['patient_id'],a['date'],a['type'])).fetchone()
        if not existing:
            ts=datetime.now().strftime('%Y-%m-%d %H:%M:%S'); c.execute('INSERT INTO patient_sessions(patient_id,visit_date,visit_type,notes,outcome,recorded_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)',(a['patient_id'],a['date'],a['type'],a['notes'] or '',status,session.get('uid'),ts,ts))
    log_staff_action(c,'Changed appointment status to '+status,'appointment',aid); c.commit(); c.close()
    flash('Appointment status updated.','ok'); return redirect(request.referrer or url_for('appointments'))


# 'Ignore / remove' an appointment: marks it Ignored and logs it, rather than deleting
# clinical history.
# Route: POST /staff/appointment/<int:aid>/delete  |  Access: staff only (Admin, Clinic Staff or Optometrist)
@app.route('/staff/appointment/<int:aid>/delete',methods=['POST'])
@staff_required
def appointment_delete(aid):
    c=db(); a=c.execute('SELECT * FROM appointments WHERE id=?',(aid,)).fetchone()
    if not a: c.close(); flash('Appointment not found.','error'); return redirect(url_for('dashboard'))
    if session.get('role')!='Admin' and a['branch_id']!=(session.get('branch_id') or 1): c.close(); return 'Forbidden',403
    # Keep an audit record, then mark it ignored instead of destroying clinical history.
    c.execute("UPDATE appointments SET status='Ignored' WHERE id=?",(aid,)); log_staff_action(c,'Ignored appointment from today queue','appointment',aid); c.commit(); c.close(); flash('Appointment removed from today’s action queue. History was retained.','ok'); return redirect(url_for('dashboard'))


# ---------------------------------------------------------------------------
# Doctor schedule (hourly calendar overview)
# ---------------------------------------------------------------------------
CLINIC_OPEN_HOUR, CLINIC_CLOSE_HOUR = 8, 18          # grid shows 08:00 .. 17:59
INACTIVE_APPT = ('Cancelled', 'Rejected', 'Ignored')  # these never occupy a doctor's hour

def _doctors_in_scope(c):
    """Active optometrists the current staff member may view/assign (own branch; admin sees all)."""
    if session.get('role') == 'Admin':
        return c.execute("SELECT u.id,u.name,u.branch_id,b.name AS branch_name FROM users u LEFT JOIN branches b ON b.id=u.branch_id WHERE u.role='Optometrist' AND u.status='Active' ORDER BY u.name").fetchall()
    return c.execute("SELECT u.id,u.name,u.branch_id,b.name AS branch_name FROM users u LEFT JOIN branches b ON b.id=u.branch_id WHERE u.role='Optometrist' AND u.status='Active' AND u.branch_id=? ORDER BY u.name", (session.get('branch_id') or 1,)).fetchall()

# Returns the optometrist with this ID if they are active and belong to the branch, else None.
def _doctor_or_none(c, doctor_id, branch_id):
    try: did = int(doctor_id)
    except (TypeError, ValueError): return None
    return c.execute("SELECT id,name FROM users WHERE id=? AND role='Optometrist' AND status='Active' AND (branch_id=? OR branch_id IS NULL)", (did, branch_id)).fetchone()

# Extracts the hour number from a time string like '14:30' (None if it cannot be read).
def _appt_hour(t):
    try: return int(str(t).split(':')[0])
    except (ValueError, IndexError): return None

# True if the doctor already has an active appointment in the same hour on that date.
def _doctor_hour_busy(c, doctor_id, day, time_str, ignore_id=None):
    hour = _appt_hour(time_str)
    rows = c.execute("SELECT id,time FROM appointments WHERE doctor_id=? AND date=? AND status NOT IN ('Cancelled','Rejected','Ignored','Missed','Dismissed by patient')", (doctor_id, day)).fetchall()
    return any(r['id'] != ignore_id and _appt_hour(r['time']) == hour for r in rows)

# Assigns (or unassigns) an optometrist to an appointment, blocking double-booking in the same
# hour.
# Route: POST /staff/appointment/<int:aid>/assign  |  Access: staff only (Admin, Clinic Staff or Optometrist)
@app.route('/staff/appointment/<int:aid>/assign', methods=['POST'])
@staff_required
def appointment_assign_doctor(aid):
    c = db(); a = c.execute('SELECT * FROM appointments WHERE id=?', (aid,)).fetchone()
    if not a: c.close(); flash('Appointment not found.', 'error'); return redirect(url_for('appointments'))
    if session.get('role') != 'Admin' and a['branch_id'] != (session.get('branch_id') or 1): c.close(); return 'Forbidden', 403
    raw = request.form.get('doctor_id', '')
    if raw == '':
        c.execute('UPDATE appointments SET doctor_id=NULL WHERE id=?', (aid,)); log_staff_action(c, 'Unassigned doctor', 'appointment', aid); c.commit(); c.close()
        flash('Doctor unassigned.', 'ok'); return redirect(request.referrer or url_for('appointments'))
    doc = _doctor_or_none(c, raw, a['branch_id'] or 1)
    if not doc: c.close(); flash('Choose a valid doctor for this appointment\'s branch.', 'error'); return redirect(request.referrer or url_for('appointments'))
    if _doctor_hour_busy(c, doc['id'], a['date'], a['time'], ignore_id=aid):
        c.close(); flash(f"{doc['name']} already has a patient booked at that hour ({a['date']} {a['time']}).", 'error'); return redirect(request.referrer or url_for('appointments'))
    c.execute('UPDATE appointments SET doctor_id=? WHERE id=?', (doc['id'], aid)); log_staff_action(c, 'Assigned doctor ' + doc['name'], 'appointment', aid); c.commit(); c.close()
    flash(f"Assigned to {doc['name']}.", 'ok'); return redirect(request.referrer or url_for('appointments'))

# Route: GET /staff/schedule  |  Access: staff only (Admin, Clinic Staff or Optometrist)
@app.route('/staff/schedule')
@staff_required
def doctor_schedule():
    """Hourly day view for one doctor, plus a 7-day strip. Optometrists only ever see their own schedule."""
    try: day = datetime.strptime(request.args.get('date', ''), '%Y-%m-%d').date()
    except ValueError: day = date.today()
    c = db(); role = session.get('role'); doctors = _doctors_in_scope(c)
    if role == 'Optometrist':
        doctor = c.execute("SELECT id,name,branch_id FROM users WHERE id=?", (session.get('uid'),)).fetchone()
        doctors = []
    else:
        sel = request.args.get('doctor', '')
        doctor = next((d for d in doctors if str(d['id']) == sel), None) or (doctors[0] if doctors else None)
    if not doctor:
        c.close(); return render_template('schedule.html', doctor=None, doctors=doctors, day=day, hours=[], outside=[], strip=[], summary={}, unassigned=0, today=date.today())
    base = ("SELECT a.id,a.time,a.type,a.status,a.notes,p.name,p.patient_id AS code,p.phone FROM appointments a JOIN patients p ON p.id=a.patient_id "
            "WHERE a.doctor_id=? AND a.date=? AND a.status NOT IN ('Cancelled','Rejected','Ignored') ORDER BY a.time")
    rows = c.execute(base, (doctor['id'], day.isoformat())).fetchall()
    buckets = {h: [] for h in range(CLINIC_OPEN_HOUR, CLINIC_CLOSE_HOUR)}; outside = []
    for r in rows:
        h = _appt_hour(r['time'])
        (buckets[h] if h in buckets else outside).append(r)
    now = datetime.now(); hours = []
    for h, items in buckets.items():
        past = datetime(day.year, day.month, day.day, h) + timedelta(hours=1) <= now
        hours.append({'label': f'{h:02d}:00', 'end': f'{h+1:02d}:00', 'items': items, 'past': past,
                      'current': day == now.date() and h == now.hour})
    start = day - timedelta(days=day.weekday()); strip = []
    counts = {r['date']: r['n'] for r in c.execute("SELECT date,COUNT(*) AS n FROM appointments WHERE doctor_id=? AND date>=? AND date<=? AND status NOT IN ('Cancelled','Rejected','Ignored') GROUP BY date",
                                                   (doctor['id'], start.isoformat(), (start + timedelta(days=6)).isoformat())).fetchall()}
    for i in range(7):
        d = start + timedelta(days=i); strip.append({'date': d, 'n': counts.get(d.isoformat(), 0)})
    unassigned = 0
    if role != 'Optometrist':
        q = "SELECT COUNT(*) AS n FROM appointments WHERE doctor_id IS NULL AND date=? AND status NOT IN ('Cancelled','Rejected','Ignored')"; args = [day.isoformat()]
        if role != 'Admin': q += ' AND branch_id=?'; args.append(session.get('branch_id') or 1)
        unassigned = c.execute(q, args).fetchone()['n']
    c.close()
    booked_hours = sum(1 for h in hours if h['items'])
    summary = {'patients': len(rows), 'booked': booked_hours, 'free': len(hours) - booked_hours}
    return render_template('schedule.html', doctor=doctor, doctors=doctors, day=day, hours=hours, outside=outside, strip=strip,
                           summary=summary, unassigned=unassigned, today=date.today(), prev=day - timedelta(days=1), nxt=day + timedelta(days=1))

# Staff page to manually send a reminder for an appointment, and to view reminders already
# sent.
# Route: GET/POST /staff/reminders  |  Access: staff only (Admin, Clinic Staff or Optometrist)
@app.route('/staff/reminders',methods=['GET','POST'])
@staff_required
def reminders():
    c=db()
    if request.method=='POST':
        try: aid=int(request.form['appointment_id'])
        except (ValueError,KeyError): c.close(); flash('Choose an appointment.','error'); return redirect(url_for('reminders'))
        if session.get('role')!='Admin':
            branch_check=c.execute('SELECT COALESCE(a.branch_id,p.branch_id) AS branch_id FROM appointments a JOIN patients p ON p.id=a.patient_id WHERE a.id=?',(aid,)).fetchone()
            if not branch_check or branch_check['branch_id']!=(session.get('branch_id') or 1): c.close(); return 'Forbidden: appointment belongs to another branch',403
        c.close(); ok,detail=send_appointment_email(aid)
        if ok: flash('Reminder sent. '+detail,'ok')
        else: flash('Reminder failed: '+detail,'error')
        return redirect(url_for('reminders'))
    if session.get('role')=='Admin': rows=c.execute('SELECT r.*,p.name FROM reminders r JOIN patients p ON p.id=r.patient_id ORDER BY r.id DESC').fetchall(); appts=c.execute("SELECT a.*,p.name FROM appointments a JOIN patients p ON p.id=a.patient_id WHERE a.status NOT IN ('Completed','Cancelled','Rejected') ORDER BY a.date,a.time").fetchall()
    else: rows=c.execute('SELECT r.*,p.name FROM reminders r JOIN patients p ON p.id=r.patient_id LEFT JOIN appointments a ON a.id=r.appointment_id WHERE COALESCE(a.branch_id,p.branch_id)=? ORDER BY r.id DESC',(session.get('branch_id') or 1,)).fetchall(); appts=c.execute("SELECT a.*,p.name FROM appointments a JOIN patients p ON p.id=a.patient_id WHERE COALESCE(a.branch_id,p.branch_id)=? AND a.status NOT IN ('Completed','Cancelled','Rejected') ORDER BY a.date,a.time",(session.get('branch_id') or 1,)).fetchall()
    c.close(); return render_template('reminders.html',rows=rows,appts=appts)


# ---------------------------------------------------------------------------
# Clinic Chat (two-way): staff <-> patient messages stored in clinic_chat_messages.
# sender is 'Staff' or 'Patient'. Patient-sent rows use staff_id=0.
# read_status is from the recipient's point of view ('Unread' until they open the thread).
# ---------------------------------------------------------------------------
CHAT_MAX_LEN = 1000
CHAT_RATE_LIMIT = 15   # max messages per patient per minute

# Normalises a chat message (line endings, trims, caps the length).
def chat_clean(raw):
    return (raw or '').replace('\r\n', '\n').strip()[:CHAT_MAX_LEN]

# Current time as the 'YYYY-MM-DD HH:MM:SS' text the database uses.
def chat_now():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

# Converts chat rows into plain dicts for JSON responses.
def chat_json(rows):
    return [{'id': r['id'], 'sender': r['sender'] or 'Staff', 'message': r['message'],
             'created_at': (r['created_at'] or '')[:16], 'staff_name': r.get('staff_name') or ''} for r in rows]

def chat_thread(c, pid, after=0, limit=200):
    """Messages of one conversation, oldest first. With after>0 only newer ones."""
    if after:
        return c.execute("SELECT m.*,u.name AS staff_name FROM clinic_chat_messages m LEFT JOIN users u ON u.id=m.staff_id "
                         "WHERE m.patient_id=? AND m.id>? ORDER BY m.id ASC LIMIT 200", (pid, after)).fetchall()
    return c.execute("SELECT * FROM (SELECT m.*,u.name AS staff_name FROM clinic_chat_messages m LEFT JOIN users u ON u.id=m.staff_id "
                     "WHERE m.patient_id=? ORDER BY m.id DESC LIMIT ?) t ORDER BY id ASC", (pid, limit)).fetchall()

def chat_staff_patient(c, pid):
    """Return the patient row if the signed-in staff member may chat with them, else None."""
    pat = c.execute('SELECT * FROM patients WHERE id=?', (pid,)).fetchone()
    if not pat: return None
    if session.get('role') != 'Admin' and pat['branch_id'] != (session.get('branch_id') or 1): return None
    return pat

def chat_staff_conversations(c):
    """One row per patient that has messages, newest activity first, branch-scoped for non-admins."""
    scope = '' if session.get('role') == 'Admin' else 'AND p.branch_id=? '
    params = () if session.get('role') == 'Admin' else (session.get('branch_id') or 1,)
    return c.execute(
        "SELECT p.id,p.name,p.patient_id AS code,"
        "(SELECT message FROM clinic_chat_messages WHERE patient_id=p.id ORDER BY id DESC LIMIT 1) AS last_message,"
        "(SELECT created_at FROM clinic_chat_messages WHERE patient_id=p.id ORDER BY id DESC LIMIT 1) AS last_at,"
        "(SELECT sender FROM clinic_chat_messages WHERE patient_id=p.id ORDER BY id DESC LIMIT 1) AS last_sender,"
        "(SELECT COUNT(*) FROM clinic_chat_messages WHERE patient_id=p.id AND sender='Patient' AND read_status='Unread') AS unread "
        "FROM patients p WHERE EXISTS(SELECT 1 FROM clinic_chat_messages WHERE patient_id=p.id) " + scope +
        "ORDER BY last_at DESC", params).fetchall()

# Converts the conversation list into plain dicts for JSON (shortens the preview text).
def chat_conv_json(rows):
    return [{'id': r['id'], 'name': r['name'], 'code': r['code'], 'unread': int(r['unread'] or 0),
             'last_message': (r['last_message'] or '')[:90], 'last_at': (r['last_at'] or '')[:16],
             'last_sender': r['last_sender']} for r in rows]

def chat_mark_read(c, pid, sender):
    """Mark messages written by `sender` as read (called when the other side opens the thread)."""
    c.execute("UPDATE clinic_chat_messages SET read_status='Read' WHERE patient_id=? AND sender=? AND read_status='Unread'", (pid, sender))

@app.context_processor
def inject_chat_unread():
    """Unread-message count for the nav badge (patients: from staff; staff: from patients in their scope)."""
    n = 0
    role = session.get('role')
    try:
        if role == 'Patient' and 'uid' in session:
            c = db()
            n = c.execute("SELECT COUNT(*) AS n FROM clinic_chat_messages m JOIN patients p ON p.id=m.patient_id "
                          "WHERE p.user_id=? AND m.sender='Staff' AND m.read_status='Unread'", (session['uid'],)).fetchone()['n']
            c.close()
        elif role in ('Admin', 'Clinic Staff', 'Optometrist'):
            c = db()
            if role == 'Admin':
                n = c.execute("SELECT COUNT(*) AS n FROM clinic_chat_messages WHERE sender='Patient' AND read_status='Unread'").fetchone()['n']
            else:
                n = c.execute("SELECT COUNT(*) AS n FROM clinic_chat_messages m JOIN patients p ON p.id=m.patient_id "
                              "WHERE m.sender='Patient' AND m.read_status='Unread' AND p.branch_id=?", (session.get('branch_id') or 1,)).fetchone()['n']
            c.close()
    except Exception:
        n = 0
    reminder_unread = 0
    try:
        if role == 'Patient' and 'uid' in session:
            c = db()
            reminder_unread = c.execute("SELECT COUNT(*) AS n FROM reminders r JOIN patients p ON p.id=r.patient_id "
                                        "WHERE p.user_id=? AND r.read_status='Unread'", (session['uid'],)).fetchone()['n']
            c.close()
    except Exception:
        reminder_unread = 0
    return {'chat_unread': int(n or 0), 'reminder_unread': int(reminder_unread or 0)}

# ----- staff side -----
# Staff Clinic Chat page: lists patient conversations, shows one thread and sends a message
# (non-JavaScript fallback).
# Route: GET/POST /staff/chat  |  Access: staff only (Admin, Clinic Staff or Optometrist)
@app.route('/staff/chat',methods=['GET','POST'])
@staff_required
def staff_chat():
    c=db()
    if request.method=='POST':
        try: pid=int(request.form.get('patient_id',''))
        except ValueError: c.close(); flash('Choose a patient for the message.','error'); return redirect(url_for('staff_chat'))
        if not chat_staff_patient(c,pid): c.close(); return 'Patient not found or forbidden',403
        body=chat_clean(request.form.get('message',''))
        if not body: c.close(); flash('Enter a message.','error'); return redirect(url_for('staff_chat',patient_id=pid))
        c.execute("INSERT INTO clinic_chat_messages(patient_id,staff_id,message,created_at,read_status,sender) VALUES(?,?,?,?,?,?)",(pid,session.get('uid'),body,chat_now(),'Unread','Staff'))
        log_staff_action(c,'Sent clinic chat message','patient',pid); c.commit(); c.close()
        return redirect(url_for('staff_chat',patient_id=pid))
    bid=session.get('branch_id') or 1
    patients_list=c.execute('SELECT id,name,patient_id FROM patients '+('' if session.get('role')=='Admin' else 'WHERE branch_id=? ')+'ORDER BY name',(() if session.get('role')=='Admin' else (bid,))).fetchall()
    selected=None; thread=[]
    try: sel_id=int(request.args.get('patient_id',''))
    except ValueError: sel_id=None
    if sel_id:
        selected=chat_staff_patient(c,sel_id)
        if selected:
            chat_mark_read(c,sel_id,'Patient'); c.commit()
            thread=chat_thread(c,sel_id)
    conversations=chat_staff_conversations(c)
    c.close()
    last_id=thread[-1]['id'] if thread else 0
    return render_template('staff_chat.html',patients=patients_list,conversations=conversations,selected=selected,thread=thread,last_id=last_id)

# JSON: current conversation list with unread counts (polled by the staff chat page).
# Route: GET /api/staff/chat/state  |  Access: staff only (Admin, Clinic Staff or Optometrist)
@app.route('/api/staff/chat/state')
@staff_required
def api_staff_chat_state():
    c=db(); rows=chat_staff_conversations(c); c.close()
    return jsonify(ok=True,conversations=chat_conv_json(rows))

# JSON: messages in one patient thread (optionally only newer ones) and marks the patient's
# messages read.
# Route: GET /api/staff/chat/<int:pid>/messages  |  Access: staff only (Admin, Clinic Staff or Optometrist)
@app.route('/api/staff/chat/<int:pid>/messages')
@staff_required
def api_staff_chat_messages(pid):
    c=db()
    if not chat_staff_patient(c,pid): c.close(); return jsonify(ok=False,error='Patient not found or forbidden.'),403
    after=request.args.get('after',0,type=int) or 0
    rows=chat_thread(c,pid,after=after)
    if any(r['sender']=='Patient' and r['read_status']=='Unread' for r in rows): chat_mark_read(c,pid,'Patient'); c.commit()
    c.close(); return jsonify(ok=True,messages=chat_json(rows))

# JSON: staff sends a message to a patient.
# Route: POST /api/staff/chat/<int:pid>/send  |  Access: staff only (Admin, Clinic Staff or Optometrist)
@app.route('/api/staff/chat/<int:pid>/send',methods=['POST'])
@staff_required
def api_staff_chat_send(pid):
    c=db()
    if not chat_staff_patient(c,pid): c.close(); return jsonify(ok=False,error='Patient not found or forbidden.'),403
    body=chat_clean(request.form.get('message',''))
    if not body: c.close(); return jsonify(ok=False,error='Enter a message.'),400
    cur=c.execute("INSERT INTO clinic_chat_messages(patient_id,staff_id,message,created_at,read_status,sender) VALUES(?,?,?,?,?,?)",(pid,session.get('uid'),body,chat_now(),'Unread','Staff'))
    log_staff_action(c,'Sent clinic chat message','patient',pid); c.commit()
    rows=chat_thread(c,pid,after=cur.lastrowid-1); c.close()
    return jsonify(ok=True,messages=chat_json([r for r in rows if r['id']==cur.lastrowid]))

# ----- patient side -----
# Returns the signed-in patient's record, or None if the account is not linked to one.
def chat_patient_or_none():
    return patient_for_user()

def chat_patient_insert(c,p,body):
    """Insert a patient message; returns (row_id, error). Applies a simple per-minute rate limit."""
    since=(datetime.now()-timedelta(minutes=1)).strftime('%Y-%m-%d %H:%M:%S')
    recent=c.execute("SELECT COUNT(*) AS n FROM clinic_chat_messages WHERE patient_id=? AND sender='Patient' AND created_at>=?",(p['id'],since)).fetchone()['n']
    if recent>=CHAT_RATE_LIMIT: return None,'You are sending messages too quickly. Please wait a moment.'
    cur=c.execute("INSERT INTO clinic_chat_messages(patient_id,staff_id,message,created_at,read_status,sender) VALUES(?,?,?,?,?,?)",(p['id'],0,body,chat_now(),'Unread','Patient'))
    c.commit(); return cur.lastrowid,None

# Patient Messages page: shows the thread with the clinic and sends a message (non-JavaScript
# fallback).
# Route: GET/POST /patient/chat  |  Access: signed-in patients only
@app.route('/patient/chat',methods=['GET','POST'])
@login_required
def patient_chat():
    p=chat_patient_or_none()
    if not p: flash('Your account is not linked to a patient record yet. Please contact the clinic.','error'); return redirect(url_for('patient_home'))
    c=db()
    if request.method=='POST':
        body=chat_clean(request.form.get('message',''))
        if not body: flash('Enter a message.','error')
        else:
            _,err=chat_patient_insert(c,p,body)
            if err: flash(err,'error')
        c.close(); return redirect(url_for('patient_chat'))
    chat_mark_read(c,p['id'],'Staff'); c.commit()
    thread=chat_thread(c,p['id']); c.close()
    return render_template('patient_chat.html',p=p,thread=thread,last_id=thread[-1]['id'] if thread else 0)

# JSON: the patient's messages (optionally only newer ones); marks staff messages read.
# Route: GET /api/patient/chat/messages  |  Access: signed-in patients only
@app.route('/api/patient/chat/messages')
@login_required
def api_patient_chat_messages():
    p=chat_patient_or_none()
    if not p: return jsonify(ok=False,error='No patient record.'),404
    c=db(); after=request.args.get('after',0,type=int) or 0
    rows=chat_thread(c,p['id'],after=after)
    if any(r['sender']=='Staff' and r['read_status']=='Unread' for r in rows): chat_mark_read(c,p['id'],'Staff'); c.commit()
    c.close(); return jsonify(ok=True,messages=chat_json(rows))

# JSON: patient sends a message (rate-limited).
# Route: POST /api/patient/chat/send  |  Access: signed-in patients only
@app.route('/api/patient/chat/send',methods=['POST'])
@login_required
def api_patient_chat_send():
    p=chat_patient_or_none()
    if not p: return jsonify(ok=False,error='No patient record.'),404
    body=chat_clean(request.form.get('message',''))
    if not body: return jsonify(ok=False,error='Enter a message.'),400
    c=db(); new_id,err=chat_patient_insert(c,p,body)
    if err: c.close(); return jsonify(ok=False,error=err),429
    rows=[r for r in chat_thread(c,p['id'],after=new_id-1) if r['id']==new_id]; c.close()
    return jsonify(ok=True,messages=chat_json(rows))

# Clinic report counts (attended, missed, etc.), for all branches (Admin) or the staff
# member's branch.
# Route: GET /staff/reports  |  Access: staff only (Admin, Clinic Staff or Optometrist)
@app.route('/staff/reports')
@staff_required
def reports():
    c=db()
    if session.get('role')=='Admin':
        report={'attended':c.execute("SELECT COUNT(*) FROM appointments WHERE status IN ('Attended','Completed')").fetchone()[0],'missed':c.execute("SELECT COUNT(*) FROM appointments WHERE status='Missed'").fetchone()[0],'completed':c.execute("SELECT COUNT(*) FROM appointments WHERE type IN ('Follow-up','Prescription review') AND status='Completed'").fetchone()[0],'pending':c.execute("SELECT COUNT(*) FROM appointments WHERE type IN ('Follow-up','Prescription review') AND status IN ('Pending','Confirmed')").fetchone()[0],'sent':c.execute("SELECT COUNT(*) FROM reminders WHERE status='Sent'").fetchone()[0],'failed':c.execute("SELECT COUNT(*) FROM reminders WHERE status='Failed'").fetchone()[0]}
    else:
        bid=session.get('branch_id') or 1
        report={'attended':c.execute("SELECT COUNT(*) FROM appointments WHERE branch_id=? AND status IN ('Attended','Completed')",(bid,)).fetchone()[0],'missed':c.execute("SELECT COUNT(*) FROM appointments WHERE branch_id=? AND status='Missed'",(bid,)).fetchone()[0],'completed':c.execute("SELECT COUNT(*) FROM appointments WHERE branch_id=? AND type IN ('Follow-up','Prescription review') AND status='Completed'",(bid,)).fetchone()[0],'pending':c.execute("SELECT COUNT(*) FROM appointments WHERE branch_id=? AND type IN ('Follow-up','Prescription review') AND status IN ('Pending','Confirmed')",(bid,)).fetchone()[0],'sent':c.execute("SELECT COUNT(*) FROM reminders r JOIN patients p ON p.id=r.patient_id WHERE p.branch_id=? AND r.status='Sent'",(bid,)).fetchone()[0],'failed':c.execute("SELECT COUNT(*) FROM reminders r JOIN patients p ON p.id=r.patient_id WHERE p.branch_id=? AND r.status='Failed'",(bid,)).fetchone()[0]}
    c.close(); return render_template('reports.html',r=report)
# Lets a signed-in staff member change their own password (current password required, min. 8
# characters).
# Route: GET/POST /staff/password  |  Access: staff only (Admin, Clinic Staff or Optometrist)
@app.route('/staff/password', methods=['GET', 'POST'])
@staff_required
def staff_change_password():
    if request.method == 'POST':
        current = request.form.get('current_password', ''); new = request.form.get('new_password', ''); confirm = request.form.get('confirm_password', '')
        c = db(); u = c.execute('SELECT * FROM users WHERE id=?', (session.get('uid'),)).fetchone()
        if not u or not check_password_hash(u['password'], current): flash('Current password is incorrect.', 'error')
        elif len(new) < 8: flash('New password must be at least 8 characters.', 'error')
        elif new != confirm: flash('New password and confirmation do not match.', 'error')
        elif check_password_hash(u['password'], new): flash('Choose a password different from the current one.', 'error')
        else:
            c.execute('UPDATE users SET password=? WHERE id=?', (generate_password_hash(new), u['id'])); log_staff_action(c, 'Changed own password', 'user', u['id']); c.commit(); c.close()
            flash('Password changed.', 'ok'); return redirect(url_for('staff_change_password'))
        c.close()
    return render_template('staff_password.html')

STAFF_ROLES = ('Clinic Staff', 'Optometrist', 'Admin')

def _parse_user_branch(c, role, raw):
    """Return (branch_id, error). Empty value = all branches (NULL), allowed for Admin only."""
    raw = (raw or '').strip()
    if not raw:
        if role == 'Admin': return None, None
        return None, 'Only an Admin can have access to all branches. Choose a branch for this role.'
    try: bid = int(raw)
    except ValueError: return None, 'Invalid branch.'
    if not c.execute('SELECT 1 FROM branches WHERE id=?', (bid,)).fetchone(): return None, 'Branch not found.'
    return bid, None

# Admin only: edits a staff member's name, role, status or branch, with safeguards against
# locking yourself out.
# Route: POST /staff/users/<int:user_id>/edit  |  Access: staff only (Admin, Clinic Staff or Optometrist)
@app.route('/staff/users/<int:user_id>/edit', methods=['POST'])
@staff_required
def edit_user(user_id):
    if session.get('role') != 'Admin': return 'Forbidden', 403
    c = db()
    try:
        target = c.execute("SELECT * FROM users WHERE id=? AND role!='Patient'", (user_id,)).fetchone()
        if not target:
            flash('User not found.', 'error'); return redirect(url_for('users'))
        is_self = target['id'] == session.get('uid')
        role = target['role'] if is_self else request.form.get('role', '')
        if role not in STAFF_ROLES:
            flash('Invalid role.', 'error'); return redirect(url_for('users'))
        branch_id, berr = _parse_user_branch(c, role, request.form.get('branch_id'))
        if berr:
            flash(berr, 'error'); return redirect(url_for('users'))
        if target['role'] == 'Admin' and role != 'Admin' and c.execute("SELECT COUNT(*) AS n FROM users WHERE role='Admin' AND status='Active'").fetchone()['n'] <= 1:
            flash('The last active Admin cannot be changed to another role.', 'error'); return redirect(url_for('users'))
        c.execute('UPDATE users SET role=?, branch_id=? WHERE id=?', (role, branch_id, target['id']))
        if role != 'Optometrist':
            c.execute('UPDATE appointments SET doctor_id=NULL WHERE doctor_id=?', (target['id'],))
        log_staff_action(c, f"Updated {target['email']}: role {target['role']} -> {role}, branch {target['branch_id'] or 'All'} -> {branch_id or 'All'}", 'user', target['id'])
        c.commit()
        if is_self: session['branch_id'] = branch_id
        flash(f"{target['name']} updated.", 'ok')
    finally:
        c.close()
    return redirect(url_for('users'))

# Route: GET/POST /staff/users/<int:user_id>/email  |  Access: staff only (Admin, Clinic Staff or Optometrist)
@app.route('/staff/users/<int:user_id>/email', methods=['GET', 'POST'])
@staff_required
def change_user_email(user_id):
    """Step 1: an Admin enters a new login email for a staff user; a code is sent to that new address."""
    if session.get('role') != 'Admin': return redirect(url_for('dashboard'))
    c = db()
    try:
        target = c.execute("SELECT id,name,email,role FROM users WHERE id=? AND role!='Patient'", (user_id,)).fetchone()
        if not target:
            flash('User not found.', 'error'); return redirect(url_for('users'))
        if request.method == 'POST':
            new_email = request.form.get('email', '').strip().lower()
            if not _EMAIL_RE.match(new_email) or len(new_email) > 190:
                flash('Enter a valid email address.', 'error'); return render_template('change_email.html', target=target)
            if new_email == target['email'].lower():
                flash('That is already this user\'s email.', 'error'); return render_template('change_email.html', target=target)
            if c.execute('SELECT 1 FROM users WHERE lower(email)=?', (new_email,)).fetchone():
                flash('That email already has an account.', 'error'); return render_template('change_email.html', target=target)
            code = f"{secrets.randbelow(1000000):06d}"
            ok, detail = send_email(
                new_email, 'HawkEye Optical Clinic: confirm your new email',
                f'<p>Hello {esc(target["name"])},</p><p>Your HawkEye Optical Clinic login email is being changed to this address. Confirmation code:</p>'
                f'<p style="font-size:28px;font-weight:bold;letter-spacing:5px">{code}</p><p>This code expires in 10 minutes. If you did not expect this, ignore this email.</p>',
                f'Your confirmation code for the new HawkEye Optical Clinic login email is {code}. It expires in 10 minutes.')
            if not ok:
                app.logger.warning('Email change code failed: %s', detail)
                flash('Could not send the confirmation email. Check the address and email settings.', 'error')
                return render_template('change_email.html', target=target)
            session['email_change'] = {'target': target['id'], 'new_email': new_email, 'code_hash': generate_password_hash(code),
                                       'expires': (datetime.now() + timedelta(minutes=10)).isoformat(), 'attempts': 0}
            flash('A confirmation code was sent to the new email address.', 'ok')
            return redirect(url_for('confirm_user_email_change'))
        return render_template('change_email.html', target=target)
    finally:
        c.close()

# Route: GET/POST /staff/users/email/confirm  |  Access: staff only (Admin, Clinic Staff or Optometrist)
@app.route('/staff/users/email/confirm', methods=['GET', 'POST'])
@staff_required
def confirm_user_email_change():
    """Step 2: enter the code sent to the new address; only then is the email changed."""
    if session.get('role') != 'Admin': return redirect(url_for('dashboard'))
    pend = session.get('email_change')
    if not pend:
        flash('No email change is awaiting confirmation.', 'error'); return redirect(url_for('users'))
    c = db()
    try:
        target = c.execute("SELECT id,name,email,role FROM users WHERE id=? AND role!='Patient'", (pend['target'],)).fetchone()
        if not target:
            session.pop('email_change', None); flash('User not found.', 'error'); return redirect(url_for('users'))
        if request.method == 'POST':
            if datetime.now() > datetime.fromisoformat(pend['expires']):
                session.pop('email_change', None); flash('That code expired. Please start again.', 'error'); return redirect(url_for('users'))
            if pend['attempts'] >= 5:
                session.pop('email_change', None); flash('Too many incorrect attempts. Please start again.', 'error'); return redirect(url_for('users'))
            entered = ''.join(ch for ch in request.form.get('code', '') if ch.isdigit())
            if len(entered) != 6 or not check_password_hash(pend['code_hash'], entered):
                pend['attempts'] += 1; session['email_change'] = pend
                flash('Incorrect confirmation code.', 'error')
                return render_template('confirm_email_change.html', target=target, new_email=pend['new_email'])
            if c.execute('SELECT 1 FROM users WHERE lower(email)=? AND id!=?', (pend['new_email'], target['id'])).fetchone():
                session.pop('email_change', None); flash('That email already has an account.', 'error'); return redirect(url_for('users'))
            c.execute('UPDATE users SET email=? WHERE id=?', (pend['new_email'], target['id']))
            log_staff_action(c, f"Changed email {target['email']} -> {pend['new_email']}", 'user', target['id']); c.commit()
            session.pop('email_change', None)
            flash(f"{target['name']}'s login email is now {pend['new_email']}.", 'ok'); return redirect(url_for('users'))
        return render_template('confirm_email_change.html', target=target, new_email=pend['new_email'])
    finally:
        c.close()

# Cancels a pending staff email change.
# Route: POST /staff/users/email/cancel  |  Access: staff only (Admin, Clinic Staff or Optometrist)
@app.route('/staff/users/email/cancel', methods=['POST'])
@staff_required
def cancel_user_email_change():
    session.pop('email_change', None); return redirect(url_for('users'))

# Admin only: lists staff users and pending access requests; POST creates a staff account with
# a temporary password.
# Route: GET/POST /staff/users  |  Access: staff only (Admin, Clinic Staff or Optometrist)
@app.route('/staff/users',methods=['GET','POST'])
@staff_required
def users():
    if session.get('role')!='Admin': return redirect(url_for('dashboard'))
    c=db()
    if request.method=='POST':
        temp_password=secrets.token_urlsafe(12); email=request.form['email'].strip().lower(); role=request.form['role']
        branch_id,berr=_parse_user_branch(c,role,request.form.get('branch_id'))
        if role not in STAFF_ROLES or berr:
            c.close(); flash(berr or 'Invalid role.','error'); return redirect(url_for('users'))
        try:
            c.execute("INSERT INTO users(name,email,password,role,status,email_verified,branch_id) VALUES(?,?,?,? ,'Active',1,?)",(request.form['name'].strip(),email,generate_password_hash(temp_password),role,branch_id)); c.commit()
            new_user=c.execute('SELECT id,password FROM users WHERE email=?',(email,)).fetchone(); link=token_serializer().dumps({'uid':new_user['id'],'email':email,'purpose':'reset','pv':pw_fingerprint(new_user['password'])}); base=os.getenv('APP_BASE_URL','http://127.0.0.1:5000').rstrip('/'); reset_url=f"{base}{url_for('reset_password',token=link)}"; ok,_=send_email(email,'Your HawkEye Optical Clinic staff account',f'<p>Your account was created. Set your password using <a href="{reset_url}">this secure link</a>.</p>','Set your password using this link: '+reset_url)
            flash('User created.' + ('' if ok else ' Account created, but setup email failed; configure email API and use forgot password.'),'ok')
        except IntegrityError: flash('That email already has an account.','error')
    rows=c.execute("SELECT * FROM users WHERE role!='Patient'").fetchall(); reqs=c.execute('SELECT * FROM access_requests ORDER BY id DESC').fetchall(); branches=c.execute('SELECT * FROM branches WHERE active=1 ORDER BY name').fetchall(); c.close(); return render_template('users.html',rows=rows,reqs=reqs,branches=branches)

# Forgets a pending staff-removal request held in the session.
def _clear_user_removal():
    session.pop('user_removal', None)

# Route: POST /staff/users/<int:user_id>/remove  |  Access: staff only (Admin, Clinic Staff or Optometrist)
@app.route('/staff/users/<int:user_id>/remove', methods=['POST'])
@staff_required
def request_user_removal(user_id):
    """Step 1: an Admin asks to remove a staff user; a code is emailed to the admin's own address."""
    if session.get('role') != 'Admin': return 'Forbidden', 403
    c = db()
    try:
        target = c.execute("SELECT * FROM users WHERE id=? AND role!='Patient'", (user_id,)).fetchone()
        admin = c.execute("SELECT * FROM users WHERE id=? AND role='Admin'", (session.get('uid'),)).fetchone()
        if not target or not admin:
            flash('User not found.', 'error'); return redirect(url_for('users'))
        if target['id'] == admin['id']:
            flash('You cannot remove your own account.', 'error'); return redirect(url_for('users'))
        if target['role'] == 'Admin' and c.execute("SELECT COUNT(*) AS n FROM users WHERE role='Admin' AND status='Active'").fetchone()['n'] <= 1:
            flash('The last active Admin cannot be removed.', 'error'); return redirect(url_for('users'))
        code = f"{secrets.randbelow(1000000):06d}"
        ok, detail = send_email(
            admin['email'], 'HawkEye Optical Clinic: confirm user removal',
            f'<p>Hello {esc(admin["name"])},</p><p>Use this code to confirm removing <b>{esc(target["name"])}</b> ({esc(target["email"])}):</p>'
            f'<p style="font-size:28px;font-weight:bold;letter-spacing:5px">{code}</p>'
            '<p>This code expires in 10 minutes. If you did not request this, ignore this email and change your password.</p>',
            f'Your code to confirm removing {target["name"]} ({target["email"]}) is {code}. It expires in 10 minutes.')
        if not ok:
            app.logger.warning('User removal code email failed: %s', detail)
            flash('Could not send the confirmation email. Check the email settings and try again.', 'error'); return redirect(url_for('users'))
        session['user_removal'] = {'target': target['id'], 'code_hash': generate_password_hash(code),
                                   'expires': (datetime.now() + timedelta(minutes=10)).isoformat(), 'attempts': 0}
        log_staff_action(c, 'Requested removal confirmation for ' + target['email'], 'user', target['id']); c.commit()
    finally:
        c.close()
    flash('A confirmation code was sent to your email.', 'ok')
    return redirect(url_for('confirm_user_removal'))

# Route: GET/POST /staff/users/remove/confirm  |  Access: staff only (Admin, Clinic Staff or Optometrist)
@app.route('/staff/users/remove/confirm', methods=['GET', 'POST'])
@staff_required
def confirm_user_removal():
    """Step 2: the admin enters the emailed code; only then is the user removed."""
    if session.get('role') != 'Admin': return redirect(url_for('dashboard'))
    pend = session.get('user_removal')
    if not pend:
        flash('No removal is awaiting confirmation.', 'error'); return redirect(url_for('users'))
    c = db()
    try:
        target = c.execute("SELECT id,name,email,role FROM users WHERE id=? AND role!='Patient'", (pend['target'],)).fetchone()
        if not target:
            _clear_user_removal(); flash('User not found.', 'error'); return redirect(url_for('users'))
        if request.method == 'POST':
            if datetime.now() > datetime.fromisoformat(pend['expires']):
                _clear_user_removal(); flash('That code expired. Please start the removal again.', 'error'); return redirect(url_for('users'))
            if pend['attempts'] >= 5:
                _clear_user_removal(); flash('Too many incorrect attempts. Please start the removal again.', 'error'); return redirect(url_for('users'))
            code = ''.join(ch for ch in request.form.get('code', '') if ch.isdigit())
            if len(code) != 6 or not check_password_hash(pend['code_hash'], code):
                pend['attempts'] += 1; session['user_removal'] = pend
                flash('Incorrect confirmation code.', 'error')
                return render_template('confirm_user_removal.html', target=target)
            if target['role'] == 'Admin' and c.execute("SELECT COUNT(*) AS n FROM users WHERE role='Admin' AND status='Active'").fetchone()['n'] <= 1:
                _clear_user_removal(); flash('The last active Admin cannot be removed.', 'error'); return redirect(url_for('users'))
            c.execute('UPDATE appointments SET doctor_id=NULL WHERE doctor_id=?', (target['id'],))
            c.execute('DELETE FROM users WHERE id=?', (target['id'],))
            log_staff_action(c, 'Removed user ' + target['email'], 'user', target['id']); c.commit()
            _clear_user_removal()
            flash(f"{target['name']} was removed.", 'ok'); return redirect(url_for('users'))
        return render_template('confirm_user_removal.html', target=target)
    finally:
        c.close()

# Cancels a pending staff removal.
# Route: POST /staff/users/remove/cancel  |  Access: staff only (Admin, Clinic Staff or Optometrist)
@app.route('/staff/users/remove/cancel', methods=['POST'])
@staff_required
def cancel_user_removal():
    _clear_user_removal(); return redirect(url_for('users'))

# Admin only: approves or rejects a staff access request and emails the applicant.
# Route: POST /staff/access-request/<int:request_id>/<action>  |  Access: staff only (Admin, Clinic Staff or Optometrist)
@app.route('/staff/access-request/<int:request_id>/<action>',methods=['POST'])
@staff_required
def process_access_request(request_id,action):
    if session.get('role')!='Admin' or action not in {'approve','reject'}: return 'Forbidden',403
    c=db(); r=c.execute("SELECT * FROM access_requests WHERE id=? AND status='Pending'",(request_id,)).fetchone()
    if not r: c.close(); flash('Pending request not found.','error'); return redirect(url_for('users'))
    if action=='approve':
        c.execute("INSERT INTO users(name,email,password,role,status,email_verified,branch_id) VALUES(?,?,?,?,'Active',1,1)",(r['name'] or r['email'].split('@')[0],r['email'],r['password'],r['role'] or 'Clinic Staff'))
        ok,detail=send_email(r['email'],'HawkEye Optical Clinic staff access approved','<p>Your staff access request has been approved. You may now sign in.</p>','Your staff access request has been approved.')
        c.execute("UPDATE access_requests SET status='Approved' WHERE id=?",(request_id,)); flash('Request approved.' + ('' if ok else ' Notification email failed; check email settings.'),'ok')
    else: c.execute("UPDATE access_requests SET status='Rejected' WHERE id=?",(request_id,)); flash('Request rejected.','ok')
    c.commit(); c.close(); return redirect(url_for('users'))

# Admin only: lists clinic branches and creates new ones.
# Route: GET/POST /staff/branches  |  Access: staff only (Admin, Clinic Staff or Optometrist)
@app.route('/staff/branches',methods=['GET','POST'])
@staff_required
def branches():
    if session.get('role')!='Admin': return 'Forbidden',403
    c=db()
    if request.method=='POST':
        name=request.form.get('name','').strip(); address=request.form.get('address','').strip()
        if name:
            try: c.execute('INSERT INTO branches(name,address) VALUES(?,?)',(name,address)); c.commit(); flash('Branch created.','ok')
            except IntegrityError: flash('Branch name already exists.','error')
    rows=c.execute('SELECT b.*, (SELECT COUNT(*) FROM patients p WHERE p.branch_id=b.id) AS patients_count FROM branches b ORDER BY name').fetchall(); c.close(); return render_template('branches.html',branches=rows)

# Admin only: sends a test email so the Gmail settings can be checked.
# Route: POST /api/email/test  |  Access: staff only (Admin, Clinic Staff or Optometrist)
@app.route('/api/email/test',methods=['POST'])
@staff_required
def email_test():
    if session.get('role')!='Admin': return jsonify(ok=False,error='Admin only'),403
    to=request.form.get('email') or request.json.get('email') if request.is_json else request.form.get('email')
    if not to: return jsonify(ok=False,error='Email address required'),400
    ok,detail=send_email(to,'HawkEye Optical Clinic email configuration test','<p>This is a test email from HawkEye Optical Clinic.</p>','This is a test email from HawkEye Optical Clinic.')
    return jsonify(ok=ok,message=detail), (200 if ok else 502)

# Patient home: next appointment, follow-up due date and new reminders.
# Route: GET /patient/home  |  Access: signed-in patients only
@app.route('/patient/home')
@login_required
@patient_record_required
def patient_home():
    if session.get('role')!='Patient':return redirect(url_for('dashboard'))
    p=patient_for_user(); c=db(); a=c.execute("SELECT * FROM appointments WHERE patient_id=? AND date>=? AND status NOT IN ('Cancelled','Completed') ORDER BY date,time LIMIT 1",(p['id'],date.today().isoformat())).fetchone(); rx=c.execute('SELECT * FROM prescriptions WHERE patient_id=? ORDER BY recorded DESC LIMIT 1',(p['id'],)).fetchone(); new_reminders=c.execute("SELECT * FROM reminders WHERE patient_id=? AND read_status='Unread' ORDER BY id DESC LIMIT 3",(p['id'],)).fetchall(); c.close(); return render_template('patient_home.html',p=p,a=a,rx=rx,new_reminders=new_reminders)
# Route: GET /api/appointment-availability  |  Access: signed-in patients only
@app.route('/api/appointment-availability')
@login_required
def appointment_availability():
    """Return booked dates and time slots for a branch and month for the patient calendar."""
    try:
        branch_id = int(request.args.get('branch_id', ''))
        month_value = request.args.get('month', '')
        month_start = datetime.strptime(month_value + '-01', '%Y-%m-%d').date()
        next_month = date(month_start.year + (month_start.month == 12), 1 if month_start.month == 12 else month_start.month + 1, 1)
    except (TypeError, ValueError):
        return jsonify(ok=False, error='Choose a valid branch and calendar month.'), 400

    c = db()
    branch = c.execute('SELECT id FROM branches WHERE id=? AND active=1', (branch_id,)).fetchone()
    if not branch:
        c.close()
        return jsonify(ok=True, dates={}, message='Select an active clinic branch to view availability.')
    rows = c.execute(
        "SELECT date, time, COUNT(*) AS count FROM appointments "
        "WHERE branch_id=? AND date>=? AND date<? "
        "AND status NOT IN ('Cancelled','Completed','Rejected') "
        "GROUP BY date,time ORDER BY date,time",
        (branch_id, month_start.isoformat(), next_month.isoformat())
    ).fetchall()
    c.close()
    dates = {}
    for row in rows:
        dates.setdefault(row['date'], []).append(row['time'])
    return jsonify(ok=True, dates=dates, month=month_value)

# Patient appointments page: lists visits and books a new one (branch, date, time, reason).
# Only one active booking at a time and no double-booking a slot.
# Route: GET/POST /patient/appointments  |  Access: signed-in patients only
@app.route('/patient/appointments', methods=['GET', 'POST'])
@login_required
def patient_appointments():
    p = patient_for_user()
    if not p:
        flash('Your patient profile could not be found. Please contact the clinic.', 'error')
        return redirect(url_for('patient_home'))
    c = db()
    branches = c.execute("SELECT id, name, address FROM branches WHERE active=1 ORDER BY name").fetchall()

    if request.method == 'POST':
        try:
            branch_id = int(request.form.get('branch_id', ''))
            appointment_date = request.form.get('date', '').strip()
            appointment_time = request.form.get('time', '').strip()
            chosen = datetime.strptime(appointment_date + ' ' + appointment_time, '%Y-%m-%d %H:%M')
        except (ValueError, TypeError):
            c.close()
            flash('Please select a valid branch, date, and time.', 'error')
            return redirect(url_for('patient_appointments'))

        appointment_date, appointment_time = chosen.strftime('%Y-%m-%d'), chosen.strftime('%H:%M')   # canonical text ('9:30' -> '09:30')
        branch = next((b for b in branches if b['id'] == branch_id), None)
        appointment_type = request.form.get('type', '').strip()
        notes = request.form.get('notes', '').strip()
        allowed_types = {'Eye check', 'Follow-up', 'Prescription review'}
        if not branch:
            c.close(); flash('Please select an active clinic branch.', 'error')
            return redirect(url_for('patient_appointments'))
        if appointment_type not in allowed_types or len(notes) > 1000:
            c.close(); flash('Please choose a valid visit reason. Notes must be 1,000 characters or fewer.', 'error')
            return redirect(url_for('patient_appointments'))
        if chosen <= datetime.now():
            c.close(); flash('Please choose a future appointment date and time.', 'error')
            return redirect(url_for('patient_appointments'))

        try:
            # Two named DB locks make check-then-insert atomic across every worker process: one per patient
            # (one active booking at a time) and one per branch slot (no double-booking).
            with db_locks(f'hawkeye:book-patient:{p["id"]}', f'hawkeye:slot:{branch_id}:{appointment_date}:{appointment_time}') as got:
                if not got:
                    c.close()
                    flash('We are saving another booking right now. Please try again in a moment.', 'error')
                    return redirect(url_for('patient_appointments'))
                c.execute('START TRANSACTION')        # fresh snapshot: sees anything committed while we waited for the locks
                active = c.execute("""SELECT id,date,time,status FROM appointments
                    WHERE patient_id=? AND status NOT IN ('Cancelled','Completed','Rejected','Missed','Ignored','Resolved')
                    AND (request_only=1 OR status IN ('Pending','Requested','Confirmed','Attended'))
                    ORDER BY date,time LIMIT 1""", (p['id'],)).fetchone()
                if active:
                    c.rollback(); c.close()
                    flash(f"You already have an active appointment ({active['date']} at {active['time']}, {active['status']}). You cannot submit another booking until this one is cancelled, rejected, or completed.", 'error')
                    return redirect(url_for('patient_appointments'))

                conflict = c.execute("""SELECT 1 FROM appointments
                    WHERE date=? AND time=? AND branch_id=?
                    AND status NOT IN ('Cancelled','Completed','Rejected') LIMIT 1""",
                    (appointment_date, appointment_time, branch_id)).fetchone()
                if conflict:
                    c.rollback(); c.close()
                    flash('That time slot has already been requested or booked at this branch. Please choose another time.', 'error')
                    return redirect(url_for('patient_appointments'))

                cur = c.execute("""INSERT INTO appointments
                    (patient_id,type,date,time,status,reminder_status,notes,request_only,branch_id)
                    VALUES(?,?,?,?,'Requested','Waiting',?,1,?)""",
                    (p['id'], appointment_type, appointment_date, appointment_time, notes, branch_id))
                appointment_id = cur.lastrowid
                c.commit()
                c.close()
            app.logger.info('Appointment request %s saved for patient %s', appointment_id, p['id'])
            flash('Transaction saved successfully. Your appointment request has been recorded and is waiting for clinic confirmation.', 'ok')
            return redirect(url_for('patient_appointments'))
        except MySQLError:
            try: c.rollback(); c.close()
            except Exception: pass
            app.logger.exception('Could not save appointment for patient %s', p['id'])
            flash('We could not save your appointment because of a database error. Please try again.', 'error')
            return redirect(url_for('patient_appointments'))

    rows = c.execute("""SELECT a.*, b.name AS branch_name
        FROM appointments a LEFT JOIN branches b ON b.id=a.branch_id
        WHERE a.patient_id=? ORDER BY
          CASE WHEN a.status NOT IN ('Cancelled','Completed','Rejected') THEN 0 ELSE 1 END,
          CASE WHEN a.date>=? THEN 0 ELSE 1 END, a.date ASC, a.time ASC""",
        (p['id'], date.today().isoformat())).fetchall()
    active_appointment = c.execute("""SELECT a.*,b.name AS branch_name FROM appointments a
        LEFT JOIN branches b ON b.id=a.branch_id WHERE a.patient_id=?
        AND a.status NOT IN ('Cancelled','Completed','Rejected','Missed','Ignored','Resolved')
        AND (a.request_only=1 OR a.status IN ('Pending','Requested','Confirmed','Attended'))
        ORDER BY a.date,a.time LIMIT 1""", (p['id'],)).fetchone()
    followups_due = c.execute("""SELECT a.*,b.name AS branch_name FROM appointments a
        LEFT JOIN branches b ON b.id=a.branch_id WHERE a.patient_id=?
        AND a.type IN ('Follow-up','Prescription review')
        AND a.status NOT IN ('Cancelled','Completed','Rejected','Dismissed by patient')
        AND a.date>=? AND COALESCE(a.reminder_status,'')!='Acknowledged'
        ORDER BY a.date,a.time""", (p['id'], date.today().isoformat())).fetchall()
    missed_rows = c.execute("SELECT * FROM appointments WHERE patient_id=? AND status IN ('Missed','Incomplete') ORDER BY date DESC,time DESC", (p['id'],)).fetchall()
    c.close()
    return render_template('patient_appointments.html', p=p, rows=rows, branches=branches,
                           active_appointment=active_appointment, followups_due=followups_due, missed_rows=missed_rows)
# Patient actions on an appointment: acknowledge a follow-up ('comply'), 'reschedule', or
# 'dismiss' a missed one.
# Route: POST /patient/appointment/<int:aid>/<action>  |  Access: signed-in patients only
@app.route('/patient/appointment/<int:aid>/<action>', methods=['POST'])
@login_required
def patient_appointment_action(aid, action):
    if session.get('role') != 'Patient':
        return redirect(url_for('dashboard'))
    if action not in {'comply', 'reschedule', 'dismiss'}:
        return 'Invalid appointment action', 400
    patient = patient_for_user()
    if not patient:
        flash('Your patient profile could not be found.', 'error')
        return redirect(url_for('patient_home'))
    c = db()
    appt = c.execute('SELECT * FROM appointments WHERE id=? AND patient_id=?', (aid, patient['id'])).fetchone()
    if not appt:
        c.close()
        return 'Appointment not found', 404
    if action == 'comply':
        if appt['type'] not in {'Follow-up', 'Prescription review'} or appt['status'] in {'Cancelled', 'Rejected', 'Completed'}:
            c.close()
            flash('Only an active follow-up or prescription review can be acknowledged.', 'error')
            return redirect(url_for('patient_appointments'))
        c.execute("UPDATE appointments SET reminder_status='Acknowledged' WHERE id=? AND patient_id=?", (aid, patient['id']))
        c.execute("UPDATE reminders SET read_status='Read' WHERE appointment_id=? AND patient_id=?", (aid, patient['id']))
        c.commit()
        c.close()
        flash('Follow-up acknowledged. Your appointment remains scheduled; please wait for clinic confirmation if it is still pending.', 'ok')
        return redirect(url_for('patient_appointments'))
    if appt['status'] not in {'Missed', 'Incomplete'}:
        c.close()
        flash('This action is only available for missed or incomplete appointments.', 'error')
        return redirect(url_for('patient_appointments'))
    new_status = 'Reschedule requested' if action == 'reschedule' else 'Dismissed by patient'
    note = (appt['notes'] or '').strip()
    action_note = 'Patient requested rescheduling after a missed visit.' if action == 'reschedule' else 'Patient dismissed the missed appointment.'
    updated_note = (note + ('\n' if note else '') + action_note)[:2000]
    c.execute("UPDATE appointments SET status='Cancelled',reminder_status=?,notes=? WHERE id=? AND patient_id=?",
              (new_status, updated_note, aid, patient['id']))
    c.execute("UPDATE reminders SET read_status='Read' WHERE appointment_id=? AND patient_id=?", (aid, patient['id']))
    c.commit()
    c.close()
    if action == 'reschedule':
        flash('The missed appointment has been cleared from urgent items. Choose a new date below to request a replacement appointment.', 'ok')
    else:
        flash('The missed appointment was dismissed. The original record is retained in your history.', 'ok')
    return redirect(url_for('patient_appointments'))


# Shows the signed-in patient their own prescription history (read-only).
# Route: GET /patient/prescription  |  Access: signed-in patients only
@app.route('/patient/prescription')
@login_required
@patient_record_required
def patient_prescription():
    p=patient_for_user(); c=db(); rows=c.execute('SELECT * FROM prescriptions WHERE patient_id=? ORDER BY recorded DESC',(p['id'],)).fetchall(); c.close(); return render_template('patient_prescription.html',p=p,rows=rows)
# Shows the patient's reminders from the clinic, newest first.
# Route: GET /patient/reminders  |  Access: signed-in patients only
@app.route('/patient/reminders')
@login_required
@patient_record_required
def patient_reminders():
    p=patient_for_user(); c=db(); rows=c.execute('SELECT * FROM reminders WHERE patient_id=? ORDER BY id DESC',(p['id'],)).fetchall(); c.close(); return render_template('patient_reminders.html',p=p,rows=rows)
# Marks one of the patient's reminders as read.
# Route: POST /patient/reminder/<int:rid>/read  |  Access: signed-in patients only
@app.route('/patient/reminder/<int:rid>/read',methods=['POST'])
@login_required
@patient_record_required
def reminder_read(rid):
    p=patient_for_user(); c=db(); c.execute("UPDATE reminders SET read_status='Read' WHERE id=? AND patient_id=?",(rid,p['id'])); c.commit(); c.close(); return redirect(url_for('patient_reminders'))
# Lets the patient view and update their phone, email, address and preferred reminder channel.
# Route: GET/POST /patient/profile  |  Access: signed-in patients only
@app.route('/patient/profile',methods=['GET','POST'])
@login_required
@patient_record_required
def patient_profile():
    p=patient_for_user(); c=db()
    if request.method=='POST': c.execute('UPDATE patients SET phone=?,email=?,address=?,channel=? WHERE id=?',(request.form['phone'],request.form['email'],request.form['address'],request.form['channel'],p['id'])); c.commit(); p=c.execute('SELECT * FROM patients WHERE id=?',(p['id'],)).fetchone(); flash('Contact details saved.','ok')
    c.close(); return render_template('patient_profile.html',p=p)

# Background jobs: appointment reminders every 15 min, prescription follow-up emails hourly,
# and clean-up of expired rate-limit rows every 6 hours. Each job runs in one worker only (see exclusive()).
scheduler = BackgroundScheduler(daemon=True)
scheduler.add_job(exclusive('appointment_reminders', send_due_reminders), 'interval', minutes=15, id='appointment_email_reminders', replace_existing=True)
scheduler.add_job(exclusive('prescription_reminders', send_due_prescription_reminders), 'interval', hours=1, id='prescription_followup_emails', replace_existing=True)
scheduler.add_job(exclusive('purge_stale_rows', purge_stale_rows), 'interval', hours=6, id='purge_stale_rows', replace_existing=True)

def bootstrap():
    """Create/upgrade the tables and start the reminder scheduler.

    Safe to call from every worker process: table setup is serialised with a database lock, and each
    scheduled job takes its own lock so only one worker runs it (no duplicate reminder emails)."""
    with db_lock('hawkeye:init', 60) as got:
        if not got: raise RuntimeError('Could not obtain the database setup lock within 60 seconds.')
        init_db()
    if os.getenv('ENABLE_SCHEDULER','true').lower() == 'true' and not scheduler.running:
        try: scheduler.start()
        except Exception as exc: app.logger.warning('Scheduler did not start: %s', exc)

# Run directly (python app.py) for local development: prepares the database, starts the scheduler
# and launches the Flask dev server. In production use waitress/gunicorn via wsgi.py instead.
if __name__=='__main__':
    if production.is_production():
        sys.exit('APP_ENV=production: do not use the Flask development server.\n'
                 'Run:  waitress-serve --listen=127.0.0.1:8000 wsgi:app   (Windows)\n'
                 '  or: gunicorn wsgi:app                                  (Linux)   -- see DEPLOY.md')
    bootstrap()
    app.run(debug=os.getenv('FLASK_DEBUG','false').lower() == 'true', use_reloader=False)

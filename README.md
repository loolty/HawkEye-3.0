# HawkEye Optical Clinic

A web-based clinic management and patient portal system for an optical clinic. Staff manage patients, prescriptions, appointments, follow-ups and reminders across one or more branches, while patients book appointments, view their prescriptions, receive reminders and message the clinic, all from the browser.

Built with **Flask** and **MySQL / MariaDB**. Runs locally with XAMPP and deploys to a Linux or Windows server behind HTTPS.

> **Status:** academic prototype, not a certified clinical system. Back up the database and verify role permissions before entering real patient data.

---

## Table of contents

- [Features](#features)
- [Tech stack](#tech-stack)
- [Project structure](#project-structure)
- [Quick start (local, XAMPP)](#quick-start-local-xampp)
- [Configuration](#configuration)
- [First login and accounts](#first-login-and-accounts)
- [User roles](#user-roles)
- [How it works](#how-it-works)
- [Security](#security)
- [Testing](#testing)
- [Deployment](#deployment)
- [Backups](#backups)
- [Troubleshooting](#troubleshooting)
- [Further documentation](#further-documentation)

---

## Features

### Patient portal
- Sign up with email verification, or sign in / sign up with **Google**
- Book, view, reschedule and cancel appointments (Eye check, Follow-up, Prescription review) with live slot availability
- View current prescription and history
- In-app **Reminders** with unread badge; acknowledge follow-ups, or reschedule / dismiss missed appointments
- **Two-way clinic chat** with staff
- Profile, email change, password reset, and optional **two-step sign-in**

### Staff portal
- **Dashboard** with KPIs, an urgent list (with Resolve action) and a clinic snapshot
- **Patients** directory, walk-in registration, record editing and prescription history
- **Prescriptions** with editable history records (editing updates the record rather than creating a duplicate)
- **Appointments** and **Follow-ups**, with status changes and doctor assignment
- **Doctor Schedule**: hourly booked/free grid per doctor (08:00 to 17:59); optometrists see only their own
- **Reminders**: sent to the patient's in-app Reminders page, and by email when an address exists
- **Clinic Chat** with unread counts and a branch-scoped patient picker
- **Reports**: attended, missed, completed and pending follow-ups, reminders sent and failed
- **Administration** (Admin only): user management, access-request approval, branches, two-step reset, audit log

### Automation
A background scheduler (APScheduler) runs three jobs:

| Job | Frequency | Purpose |
|---|---|---|
| Appointment reminders | every 15 min | Emails patients about confirmed appointments about 24 hours away |
| Prescription reminders | hourly | Reminds patients whose prescription review date is tomorrow |
| Purge stale rows | every 6 hours | Removes expired rate-limit rows |

Each job is guarded by a database lock, so it is safe to run several worker processes.

---

## Tech stack

| Layer | Technology |
|---|---|
| Backend | Python 3, Flask 3.1, Flask-WTF (CSRF), Werkzeug |
| Database | MySQL / MariaDB via `mysql-connector-python` |
| Scheduling | APScheduler |
| Email | Gmail SMTP (optional) |
| Auth extras | TOTP two-step sign-in, Google OAuth (optional), `segno` for QR codes |
| Frontend | Server-rendered Jinja2 templates, plain CSS and JavaScript, self-hosted Instrument Sans font |
| Production serving | Waitress (Windows / Linux) or Gunicorn (Linux), behind Nginx or Caddy |

Exact versions are pinned in `requirements.txt`.

---

## Project structure

```
.
├── app.py                  Main Flask application (routes, DB helpers, scheduler jobs)
├── wsgi.py                 Production entry point (Waitress / Gunicorn)
├── production.py           Config validation, security headers, logging
├── mfa.py                  Two-step sign-in (TOTP + backup codes)
├── google_auth.py          Google OAuth sign-in for patients
├── requirements.txt        Pinned dependencies
├── .env.example            Local configuration template
├── .env.production.example Production configuration template
├── sql/
│   ├── create_database.sql Database and table schema
│   └── seed_demo_data.sql  Idempotent fictional demo records
├── templates/              Jinja2 templates (staff, patient and shared pages)
├── static/                 CSS (tokens, style, chat), JS, fonts, images
├── vendor/segno/           Bundled QR-code library
├── deploy/                 systemd unit, Nginx / Caddy examples, backup scripts, Waitress launcher
├── tests/                  smoke_test.py, test_two_step_google.py
├── DEPLOY.md               Go-live guide
└── DESIGN.md               Design system notes
```

---

## Quick start (local, XAMPP)

**Prerequisites:** Python 3.10+ and XAMPP (for MySQL/MariaDB). Apache is not needed unless you want phpMyAdmin.

### 1. Start MySQL and configure `.env`

1. Open the XAMPP Control Panel and start **MySQL**.
2. Copy the template:
   ```bat
   copy .env.example .env
   ```
3. Edit `.env`. For a default XAMPP install, `MYSQL_HOST=127.0.0.1`, `MYSQL_PORT=3306`, `MYSQL_DATABASE=hawkeye_database`, `MYSQL_USER=root` and an empty `MYSQL_PASSWORD` work.
4. Generate a secret key and put it in `FLASK_SECRET_KEY`:
   ```bat
   python -c "import secrets; print(secrets.token_hex(32))"
   ```

### 2. Create the database

From the project folder in Command Prompt:

```bat
C:\xampp\mysql\bin\mysql.exe -u root < sql\create_database.sql
```

If root has a password, add `-p`. If XAMPP is installed elsewhere, adjust the path. The app also creates and upgrades its own tables on startup.

### 3. Install dependencies

```bat
py -m venv .venv
.venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### 4. (Optional) Load demo data

```bat
C:\xampp\mysql\bin\mysql.exe -u root hawkeye_database < sql\seed_demo_data.sql
```

Adds fictional patients, appointments, prescriptions and follow-ups. It is safe to run repeatedly. Demo emails use `example.test` and are never delivered.

### 5. Run

```bat
python app.py
```

Open <http://127.0.0.1:5000>. Staff sign in at `/staff/login`, patients at `/patient/login`.

---

## Configuration

All settings come from `.env`. Never commit or share this file.

| Variable | Purpose |
|---|---|
| `FLASK_SECRET_KEY` | Signs sessions and emailed links. Random, 32+ characters. Changing it signs everyone out. |
| `FLASK_DEBUG` | Must be `false` in production |
| `COOKIE_SECURE` | `true` when served over HTTPS |
| `APP_BASE_URL` | Public address, used inside emailed links and the Google redirect URI |
| `MYSQL_HOST` / `PORT` / `DATABASE` / `USER` / `PASSWORD` | Database connection |
| `ENABLE_SCHEDULER` | `true` to run the reminder jobs |
| `ADMIN_EMAIL` / `ADMIN_PASSWORD` | First-run administrator (see below) |
| `SEED_DEMO_ACCOUNTS` | `true` only on a local demo machine |
| `GMAIL_ADDRESS` / `GMAIL_APP_PASSWORD` / `MAIL_DEFAULT_SENDER` | Optional email delivery |
| `MAIL_SERVER` / `MAIL_PORT` | SMTP host and port (default `smtp.gmail.com` / `587`) |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | Optional Google sign-in. Leave empty to hide the buttons. |

**Production-only settings** (see `.env.production.example`): `APP_ENV=production`, `TRUST_PROXY`, `PROXY_HOPS`, `CLINIC_NAME`, `CLINIC_CONTACT_EMAIL`, `CLINIC_ADDRESS`, `LOG_FILE`, `LOG_LEVEL`.

With `APP_ENV=production` the app **refuses to start** if the secret key is weak, debug is on, demo accounts are enabled, cookies are not HTTPS-only, `APP_BASE_URL` is not `https://`, the database password is empty, or the privacy contact email is missing.

### Email

Gmail delivery needs a Google **App Password** (not your normal password). Without email configured, the app still works: reminders appear in the patient's in-app Reminders page, but verification emails and email reminders are not sent.

### Google sign-in (patients)

1. Create an OAuth client of type **Web application** at <https://console.cloud.google.com/apis/credentials>.
2. Add the redirect URI `<APP_BASE_URL>/auth/google/callback` (locally `http://127.0.0.1:5000/auth/google/callback`).
3. Set `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` in `.env` and restart.

Staff accounts never use Google. A new Google sign-up must accept the Privacy Notice. An existing patient account with the same verified email is linked automatically. If the clinic already holds a record under that email, the patient claims it with the normal sign-up form (patient ID and birthdate).

---

## First login and accounts

Demo accounts with well-known passwords are **not** created by default.

- **Fresh database, no Admin:** the app creates one on first start. Set `ADMIN_EMAIL` and `ADMIN_PASSWORD` in `.env`, or leave the password empty and copy the random one-time password printed in the console. Change it after signing in.
- **Local demo only:** set `SEED_DEMO_ACCOUNTS=true` to create these accounts:

  | Role | Email |
  |---|---|
  | Admin | `andrea.reyes@example.com` |
  | Optometrist | `paolo.garcia@example.com` |
  | Clinic Staff | `camille.flores@example.com` |

  Their passwords are well known. **Never enable this on a real deployment**, and change or deactivate these accounts if they already exist in a database.
- **New staff** can request access at `/staff/request`; an Admin approves or rejects the request. Admins can also create users directly.

---

## User roles

| Role | Scope | Can do |
|---|---|---|
| **Admin** | All branches | Everything, including user management, branches, access requests, two-step reset, reports for all branches |
| **Optometrist** | Own branch | Patients, prescriptions, appointments, own doctor schedule, chat, reminders |
| **Clinic Staff** | Own branch | Patients, appointments, follow-ups, reminders, chat, reports for their branch |
| **Patient** | Own record | Booking, prescriptions, reminders, chat, profile |

Branch scoping is enforced server-side: staff cannot book for or view another branch's patients, and Admin-only routes return 403 for everyone else.

---

## How it works

- **Database:** MySQL/MariaDB, `utf8mb4`. Tables: `users`, `branches`, `patients`, `prescriptions`, `appointments`, `reminders`, `access_requests`, `audit_logs`, `patient_sessions`, `patient_reviews`, `clinic_chat_messages`, `email_tokens`, `pending_signups`, `mfa_backup_codes`, `rate_limits`.
- **Self-upgrading schema:** on startup the app adds any missing columns and tables, so existing databases upgrade automatically. `sql/create_database.sql` is for fresh installs.
- **Audit trail:** significant actions are written to `audit_logs`. Resolving an urgent item hides it from the list but keeps the appointment and its log entry.
- **Chat:** two-way, in-app only (no email or SMS). Both sides poll every few seconds, and sending also works without JavaScript. Patients are limited to 15 messages per minute and 1000 characters per message.
- **Follow-ups:** scheduling a *Follow-up* or *Prescription review* creates an in-app reminder. Patients acknowledge it, or reschedule / dismiss a missed appointment. Missed appointments stay in history.
- **Health check:** `GET /healthz` for uptime monitors and load balancers.
- **Privacy Notice:** served at `/privacy`, built from what the system stores.

---

## Security

- Passwords hashed with Werkzeug; minimum 8 characters
- CSRF protection on all forms; session cookies are HttpOnly and SameSite=Lax (Secure over HTTPS); sessions last 8 hours
- **Brute-force protection** stored in MySQL (so it holds across workers): accounts lock after 5 failed attempts and an address after 30, per 15-minute window; password-reset, signup and email-sending endpoints are rate limited
- **Two-step sign-in** (authenticator app) for staff and patients, with 10 one-time backup codes; an Admin can reset it for a locked-out user
- Security headers with a per-request CSP nonce, and no inline event handlers in templates
- Reset and verification links are signed, time-limited and single-use
- Logout is POST-only
- Uploads and request bodies capped at 2 MB

**Before sharing or deploying:**
- Keep `.env` out of ZIPs, repositories and chat. Rotate the Flask secret and revoke any Gmail App Password that may have been exposed.
- Use a dedicated database user, not `root`, in production.
- Always serve production traffic over HTTPS.

---

## Testing

The tests **drop every table** in the target database, so they only run against a database whose name ends in `_test`.

```bat
set MYSQL_DATABASE=hawkeye_test
python -m unittest tests.smoke_test -v
python -m unittest tests.test_two_step_google -v
```

Set `MYSQL_USER`, `MYSQL_PASSWORD` and `MYSQL_HOST` as well if they differ from the defaults. The suite covers production config checks, page access by role, security headers, brute-force lockouts, reset links, record linking, branch isolation, scheduler locks, email escaping and two-step sign-in.

---

## Deployment

Never use `python app.py` in production. Use the WSGI entry point:

```bash
# Linux
gunicorn --workers 3 --threads 2 --bind 127.0.0.1:8000 wsgi:app

# Windows
waitress-serve --listen=127.0.0.1:8000 wsgi:app
```

Then put **HTTPS** in front (Nginx + Let's Encrypt, or Caddy). Behind a proxy, set `TRUST_PROXY=true` and `PROXY_HOPS=1`, otherwise the login lockout treats every visitor as the same address.

Ready-made files are in `deploy/`: `hawkeye.service` (systemd), `nginx.conf.example`, `Caddyfile.example`, `run_waitress.bat`, and the backup scripts. The full walkthrough, including hosting options, email setup and the go-live checklist, is in **[DEPLOY.md](DEPLOY.md)**.

---

## Backups

Patient data lives in the database, so back it up.

- `deploy/backup.sh` (Linux) and `deploy/backup.bat` (Windows) write compressed, verified dumps and keep 14 days by default.
- Schedule nightly, for example in cron: `30 2 * * * /opt/hawkeye/deploy/backup.sh >> /opt/hawkeye/logs/backup.log 2>&1`
- **Copy backups off the server** and do one test restore.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| App won't start in production | The error lists every unsafe setting; fix each in `.env`. Check with `python -c "import app"`. |
| Can't connect to MySQL | Confirm MySQL is running in XAMPP and `.env` host, port, user and password match. |
| No emails arrive | Check the Gmail App Password and `MAIL_DEFAULT_SENDER`. Demo `example.test` addresses never deliver. |
| QR code missing on two-step setup | Install dependencies (`segno`); the setup key can be typed in instead. |
| Everyone is locked out behind a proxy | Set `TRUST_PROXY=true` and the right `PROXY_HOPS`. |
| Locked-out staff member (lost phone) | An Admin uses **Reset 2-step** on the User management page. |

---

## Further documentation

- **[DEPLOY.md](DEPLOY.md)**: production deployment, HTTPS, email, backups, go-live checklist
- **[DESIGN.md](DESIGN.md)**: design tokens, typography and UI rules

---

## Credits and licenses

- Instrument Sans font under the SIL Open Font License (`static/fonts/OFL.txt`)
- `segno` QR-code library bundled in `vendor/segno/` (see its `LICENSE`)

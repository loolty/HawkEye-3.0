# Deploying HawkEye Optical Clinic

This guide takes the system from "works on my PC" to "live on the internet for patients and staff".
Everything below was tested on Linux with MariaDB, Gunicorn, Waitress and Nginx. The two Windows
`.bat` files were written carefully but **not run on Windows** — test them once before relying on them.

## 0. The short version

1. Get a server (or hosting account), a domain name, and an email-sending service.
2. Create a database + a dedicated database user (not `root`).
3. Copy `.env.production.example` to `.env` and fill in every value.
4. Run the app with **Waitress** (Windows) or **Gunicorn** (Linux) — never `python app.py`.
5. Put **HTTPS** in front of it (Nginx + Let's Encrypt, or Caddy).
6. Schedule the nightly **backup** and do one test **restore**.
7. Work through the checklist in section 6.

The app protects you from the most common mistakes: with `APP_ENV=production` it **refuses to start**
if the secret key is weak, debug is on, demo accounts are enabled, cookies aren't HTTPS-only,
`APP_BASE_URL` isn't `https://`, the database password is empty, or the privacy contact email is missing.

## 1. Where to host

| Option | Good for | Watch out for |
|---|---|---|
| **Linux VPS** (DigitalOcean, Hetzner, Vultr, Linode…) — recommended | Full control, ~US$5–12/month, everything in this guide applies | You maintain it (updates, backups) |
| **Managed platform** (Render, Railway, Fly.io…) + managed MySQL | Least maintenance, HTTPS included | Costs more; check the MySQL add-on and its backups |
| **Windows PC with XAMPP at the clinic** | Already have the hardware | Power cuts, home/office internet, no static IP, and an exposed clinic PC is the riskiest choice. If you do this, publish through **Caddy or Cloudflare Tunnel** and never open ports 3306 or 8000 |

## 2. What you need first

- A **domain name** (e.g. `clinic.example.com`) pointing to your server.
- An **email service** for verification codes and reminders (see section 5).
- A **strong password** for the database user and one for the first admin.

## 3. Configure `.env`

```
cp .env.production.example .env      # Linux:  chmod 600 .env
```

Fill in every value. The important ones:

| Setting | Why |
|---|---|
| `FLASK_SECRET_KEY` | Random, 32+ chars: `python -c "import secrets; print(secrets.token_hex(32))"`. Keep it stable — changing it signs everyone out and breaks emailed links. |
| `APP_BASE_URL` | Your public `https://` address; used inside emailed links. |
| `TRUST_PROXY=true`, `PROXY_HOPS=1` | **Required behind Nginx/Caddy/a platform router.** Without it the login lockout thinks every visitor is the same address. Use `PROXY_HOPS=2` for Cloudflare + Nginx. |
| `MYSQL_USER` / `MYSQL_PASSWORD` | A dedicated user, not `root`. |
| `ADMIN_EMAIL` / `ADMIN_PASSWORD` | Creates the first administrator on first start. Change the password after signing in. |
| `CLINIC_CONTACT_EMAIL` | Shown on the Privacy Notice for patient requests (required). |

Check the file without starting the server:

```
.venv/bin/python -c "import app"        # Windows: .venv\Scripts\python -c "import app"
```

No output = good. Otherwise it lists exactly what to fix.

## 4A. Linux VPS (Ubuntu 22.04 / 24.04)

```bash
sudo apt update && sudo apt install -y python3-venv mariadb-server nginx certbot python3-certbot-nginx ufw
sudo mysql_secure_installation

# database + dedicated user (the app creates its own tables on first start)
sudo mysql -e "CREATE DATABASE hawkeye_database CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
  CREATE USER 'hawkeye_app'@'localhost' IDENTIFIED BY 'PUT-A-STRONG-PASSWORD-HERE';
  GRANT ALL PRIVILEGES ON hawkeye_database.* TO 'hawkeye_app'@'localhost';"

# app user + code (upload the project folder to /opt/hawkeye first)
sudo adduser --system --group --home /opt/hawkeye hawkeye
sudo chown -R hawkeye:hawkeye /opt/hawkeye
cd /opt/hawkeye
sudo -u hawkeye python3 -m venv .venv
sudo -u hawkeye .venv/bin/pip install -r requirements.txt
sudo -u hawkeye cp .env.production.example .env && sudo chmod 600 .env     # then edit it
sudo -u hawkeye mkdir -p logs
sudo -u hawkeye .venv/bin/python -c "import app"                           # config check

# run as a service
sudo cp deploy/hawkeye.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now hawkeye
curl http://127.0.0.1:8000/healthz                                          # {"status":"ok"}

# HTTPS reverse proxy
sudo cp deploy/nginx.conf.example /etc/nginx/sites-available/hawkeye        # replace clinic.example.com
sudo ln -s /etc/nginx/sites-available/hawkeye /etc/nginx/sites-enabled/
sudo certbot --nginx -d clinic.example.com
sudo nginx -t && sudo systemctl reload nginx

# firewall: only SSH and web
sudo ufw allow OpenSSH && sudo ufw allow 'Nginx Full' && sudo ufw enable

# nightly backup at 02:30
sudo -u hawkeye chmod +x deploy/backup.sh
( sudo -u hawkeye crontab -l 2>/dev/null; echo "30 2 * * * /opt/hawkeye/deploy/backup.sh >> /opt/hawkeye/logs/backup.log 2>&1" ) | sudo -u hawkeye crontab -
```

## 4B. Windows PC (XAMPP)

1. In XAMPP, set a **root password** for MySQL and run MySQL as a Windows service so it starts at boot.
2. Create the database and a dedicated user:
   `C:\xampp\mysql\bin\mysql.exe -u root -p` then
   `CREATE DATABASE hawkeye_database CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;`
   `CREATE USER 'hawkeye_app'@'localhost' IDENTIFIED BY 'STRONG-PASSWORD';`
   `GRANT ALL PRIVILEGES ON hawkeye_database.* TO 'hawkeye_app'@'localhost';`
3. `py -m venv .venv`, `.venv\Scripts\activate`, `pip install -r requirements.txt`.
4. Copy `.env.production.example` to `.env`, fill it in, and run `.venv\Scripts\python -c "import app"`.
5. Start the server: double-click `deploy\run_waitress.bat` and open `http://127.0.0.1:8000/healthz`.
6. **HTTPS:** install [Caddy](https://caddyserver.com), copy `deploy\Caddyfile.example` to `Caddyfile`, put your domain in it, run `caddy run`. (Alternative with no port-forwarding: a Cloudflare Tunnel.)
7. **Start at boot:** use [NSSM](https://nssm.cc): `nssm install HawkEye "C:\path\to\deploy\run_waitress.bat"` (do the same for `caddy run`).
8. **Backups:** Task Scheduler → daily → run `deploy\backup.bat`; copy the `backups` folder off the PC regularly.
9. Windows Firewall: allow only 80/443 inbound. Keep 8000 and 3306 closed. Set the PC to **never sleep**.

## 4C. Managed platform (Render, Railway, Fly.io…)

- **Start command:** `gunicorn wsgi:app --workers 2 --bind 0.0.0.0:$PORT`
- **Environment variables:** everything from `.env.production.example`, with `TRUST_PROXY=true`.
  Leave `LOG_FILE` empty (platform captures stdout).
- **Database:** a managed MySQL/MariaDB add-on (utf8mb4). Use its host, user and password.
- **Health check path:** `/healthz`
- The platform provides HTTPS. Several instances are fine: database locks make sure each reminder email is sent once.

## 5. Email

The app sends verification codes, password resets and reminders. Gmail with an App Password works for a
small clinic but is limited to roughly 500 emails/day, and mail from a Gmail address "on behalf of" your
domain may land in spam. For reliable delivery use a transactional provider (Brevo, Amazon SES, SendGrid,
Mailgun): set `MAIL_SERVER`, `MAIL_PORT`, `GMAIL_ADDRESS` (= SMTP username), `GMAIL_APP_PASSWORD`
(= SMTP password) and `MAIL_DEFAULT_SENDER`, and add the **SPF and DKIM** records the provider gives you.
After setup, test it: open **Forgot password** on the patient login page with your own email address and check that the reset email arrives (and is not in spam). If it doesn't, `logs/hawkeye.log` says why (wrong SMTP login, blocked sender, etc.).

### Google sign-in and two-step sign-in (optional)

- **Google:** in Google Cloud Console create an OAuth client (*Web application*) and register the redirect URI `https://YOUR-DOMAIN/auth/google/callback` (it must match `APP_BASE_URL` exactly). Set `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` in `.env`. While the OAuth consent screen is in "Testing", only listed test users can sign in; publish it for real patients. Keep the secret out of Git and chat like the other secrets.
- **Two-step sign-in:** nothing to configure. Authenticator secrets are stored in the `users` table, so protect database backups like the rest of the patient data. Staff who are locked out are reset by an Admin (User management → *Reset 2-step*). Remind staff to save their backup codes.
- The Content-Security-Policy `form-action` gains `https://accounts.google.com` automatically when `GOOGLE_CLIENT_ID` is set (browsers apply it to the redirect to Google).

## 6. Go-live checklist

**Before launch**
- [ ] `import app` prints nothing (config is valid) and `/healthz` returns `{"status":"ok"}`.
- [ ] Site opens on `https://` only; `http://` redirects; padlock shows no warnings.
- [ ] Signed in as admin: **changed the admin password**, created staff accounts for real staff.
- [ ] Walked through as a real patient: signup → verification email → sign in → patient sends an appointment request → staff confirms it → patient sees the confirmation under Reminders → reminder email → forgot-password → reset.
- [ ] Wrong password 5 times locks the account for 15 minutes (and the message appears).
- [ ] **Backup + restore drill:** run the backup, restore it into a spare database, and check the data (`gunzip -c backups/FILE.sql.gz | mysql spare_db`).
- [ ] **Privacy Notice** (`/privacy`) reviewed by someone qualified for your country's data-protection law; the retention wording adjusted to your actual policy.
- [ ] A free uptime monitor (UptimeRobot, Better Stack…) watching `https://your-domain/healthz`.
- [ ] Off-server copy of backups arranged (second machine or cloud storage).

**Run the automated checks on a spare database** (they erase it — the name must end in `_test`):
```
MYSQL_DATABASE=hawkeyes_test python -m unittest tests.smoke_test -v
```

## 7. Day to day

| Task | How |
|---|---|
| **Update the app** | Upload the new files, `pip install -r requirements.txt`, restart (`sudo systemctl restart hawkeye`). New tables/columns are added automatically on start. |
| **See logs** | `logs/hawkeye.log` (rotates itself) and `journalctl -u hawkeye` on Linux. |
| **Restore a backup** | Stop the app, then `gunzip -c backups/FILE.sql.gz \| mysql -u hawkeye_app -p hawkeye_database`, start the app. |
| **Unlock a locked-out person now** | `DELETE FROM rate_limits;` (or wait 15 minutes). A successful password reset also clears that account's lock. |
| **Rotate the secret key** | Change `FLASK_SECRET_KEY` and restart. Everyone must sign in again. |

## 8. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| App won't start: "Unsafe production configuration" | It lists the setting. Fix it in `.env`. |
| Everyone gets locked out together | `TRUST_PROXY` is not `true`, so all visitors share the proxy's address. Set it (and `PROXY_HOPS`). |
| Sign-in/forms fail with "request could not be processed" | The proxy isn't passing `Host`/`X-Forwarded-Proto` (use the provided Nginx config), or `COOKIE_SECURE=true` but you're visiting over plain `http://`. |
| No reminder emails | Check `ENABLE_SCHEDULER=true`, the mail settings, and `logs/hawkeye.log` for "email" errors. Emails also fail silently if the SMTP provider blocks the sender. |
| Links in emails point to `127.0.0.1` | `APP_BASE_URL` is wrong. |
| Nginx `unknown directive "http2"` | Old Nginx; the provided config already uses the compatible form. |
| 502 Bad Gateway | The app isn't running: `systemctl status hawkeye`, `journalctl -u hawkeye -n 50`. |

## 9. What this does *not* include (be aware)

- **Two-step sign-in is optional**, not enforced: staff and patients choose whether to turn it on (see the two-step section above). Passwords need at least 8 characters.
- **Per-account lockout can be abused**: someone who knows a staff email can keep it locked (15 minutes at a time). That is the usual trade-off; the address-level limit and logs help you spot it.
- Signed-in sessions cannot be revoked from the server side; they expire after 8 hours or on sign-out.
- **Not load-tested.** It opens one database connection per request, which is fine for a clinic (dozens of simultaneous users); revisit if you grow far beyond that.
- Backups are created on the server; **moving them off the server is up to you**.
- Privacy/legal wording is a plain-language draft built from what the system stores — it is not legal advice.

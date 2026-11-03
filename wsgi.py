"""Production entry point.

    Windows :  waitress-serve --listen=127.0.0.1:8000 wsgi:app
    Linux   :  gunicorn --workers 3 --bind 127.0.0.1:8000 wsgi:app

Importing this module creates/upgrades the database tables and starts the reminder scheduler
(see app.bootstrap). It is safe with several workers: setup and every scheduled job are guarded by
database locks, so only one process performs each task.
"""
from app import app, bootstrap

# Prepares the database tables and starts the reminder scheduler when the server loads this file.
bootstrap()

if __name__ == '__main__':
    raise SystemExit('Do not run this file directly. See DEPLOY.md.')

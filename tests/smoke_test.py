"""Deployment smoke tests. Run against a THROWAWAY database whose name ends in "_test":

    set MYSQL_DATABASE=hawkeyes_test  (and MYSQL_USER / MYSQL_PASSWORD / MYSQL_HOST as usual)
    python -m unittest tests.smoke_test -v

The tests DROP every table in that database first, so they refuse to run against anything else.
"""
import os, re, subprocess, sys, tempfile, time, unittest
from datetime import datetime, timedelta

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
DB_NAME = os.getenv('MYSQL_DATABASE', '')
if not DB_NAME.endswith('_test'):
    raise SystemExit('Refusing to run: MYSQL_DATABASE must end with "_test" (these tests wipe the database).')
os.environ.update(FLASK_SECRET_KEY='t' * 48, SEED_DEMO_ACCOUNTS='true', ENABLE_SCHEDULER='false', APP_ENV='development')

import mysql.connector
import production


def connect():
    return mysql.connector.connect(host=os.getenv('MYSQL_HOST', '127.0.0.1'), port=int(os.getenv('MYSQL_PORT', '3306')),
                                   user=os.getenv('MYSQL_USER', 'root'), password=os.getenv('MYSQL_PASSWORD', ''), database=DB_NAME)

def wipe():
    c = connect(); cur = c.cursor(); cur.execute('SET FOREIGN_KEY_CHECKS=0')
    cur.execute('SHOW TABLES'); [cur.execute(f'DROP TABLE `{r[0]}`') for r in cur.fetchall()]
    cur.execute('SET FOREIGN_KEY_CHECKS=1'); c.commit(); c.close()

wipe()
import app as A
A.bootstrap()

STAFF = ('andrea.reyes@example.com', 'admin123')
OPTOM = ('paolo.garcia@example.com', 'doctor123')
CLERK = ('camille.flores@example.com', 'staff123')
PATIENT = ('test.patient@example.com', 'Patient-pass-1')

def token(client, path):
    html = client.get(path).get_data(as_text=True)
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
    return m.group(1) if m else ''

def login(client, path, email, pw):
    return client.post(path, data=dict(email=email, password=pw, csrf_token=token(client, path)))

def clear_limits():
    c = connect(); cur = c.cursor(); cur.execute('DELETE FROM rate_limits'); c.commit(); c.close()

def make_patient():
    c = connect(); cur = c.cursor()
    cur.execute("INSERT IGNORE INTO users(name,email,password,role,status,email_verified,branch_id) VALUES(%s,%s,%s,'Patient','Active',1,1)",
                ('Test Patient', PATIENT[0], A.generate_password_hash(PATIENT[1])))
    cur.execute('SELECT id FROM users WHERE email=%s', (PATIENT[0],)); uid = cur.fetchone()[0]
    cur.execute("INSERT IGNORE INTO patients(patient_id,name,birthdate,phone,email,address,channel,user_id,branch_id) VALUES('HK-TEST-1','Test Patient','1990-01-01','0917','test.patient@example.com','Somewhere','Email',%s,1)", (uid,))
    c.commit(); c.close()
make_patient()


class Config(unittest.TestCase):
    GOOD = dict(APP_ENV='production', FLASK_SECRET_KEY='k' * 40, FLASK_DEBUG='false', SEED_DEMO_ACCOUNTS='false', COOKIE_SECURE='true',
                APP_BASE_URL='https://clinic.example.com', MYSQL_PASSWORD='pw', CLINIC_CONTACT_EMAIL='clinic@example.com')
    def check(self, **over):
        old = dict(os.environ)
        try:
            os.environ.update(self.GOOD); os.environ.update(over); production.validate_config()
        finally:
            os.environ.clear(); os.environ.update(old)
    def test_good_production_config_passes(self): self.check()
    def test_each_unsafe_setting_is_rejected(self):
        for bad in (dict(FLASK_SECRET_KEY='short'), dict(FLASK_DEBUG='true'), dict(SEED_DEMO_ACCOUNTS='true'), dict(COOKIE_SECURE='false'),
                    dict(APP_BASE_URL='http://x.com'), dict(MYSQL_PASSWORD=''), dict(CLINIC_CONTACT_EMAIL='')):
            with self.subTest(bad=bad), self.assertRaises(RuntimeError): self.check(**bad)
    def test_development_is_not_enforced(self): self.check(APP_ENV='development', FLASK_SECRET_KEY='')


class Pages(unittest.TestCase):
    def walk(self, client, label):
        bad = []
        for rule in A.app.url_map.iter_rules():
            if 'GET' in rule.methods and not rule.arguments and rule.endpoint != 'static':
                r = client.get(rule.rule)
                if r.status_code >= 500: bad.append((rule.rule, r.status_code))
        self.assertEqual(bad, [], f'{label}: pages returned a server error')
    def test_anonymous_pages(self): self.walk(A.app.test_client(), 'anonymous')
    def test_staff_pages(self):
        for who in (STAFF, OPTOM, CLERK):
            c = A.app.test_client(); self.assertEqual(login(c, '/staff/login', *who).status_code, 302); self.walk(c, who[0])
    def test_patient_pages(self):
        c = A.app.test_client(); self.assertEqual(login(c, '/patient/login', *PATIENT).status_code, 302); self.walk(c, 'patient')
    def test_admin_pages_blocked_for_clerk(self):
        c = A.app.test_client(); login(c, '/staff/login', *CLERK)
        paths = [r.rule for r in A.app.url_map.iter_rules() if r.endpoint in ('users', 'branches')]
        self.assertEqual(len(paths), 2)
        for path in paths:
            r = c.get(path); self.assertIn(r.status_code, (302, 403), path)
    def test_staff_pages_blocked_for_anonymous_and_patient(self):
        anon = A.app.test_client(); pat = A.app.test_client(); login(pat, '/patient/login', *PATIENT)
        for cl in (anon, pat):
            r = cl.get('/staff/dashboard'); self.assertEqual(r.status_code, 302); self.assertIn('/staff/login', r.headers['Location'])


class Headers(unittest.TestCase):
    def test_security_headers_and_csp_nonce(self):
        r = A.app.test_client().get('/')
        h = r.headers
        self.assertEqual(h['X-Content-Type-Options'], 'nosniff'); self.assertEqual(h['X-Frame-Options'], 'DENY')
        self.assertIn('no-store', h['Cache-Control']); self.assertIn("frame-ancestors 'none'", h['Content-Security-Policy'])
        nonce = re.search(r"'nonce-([^']+)'", h['Content-Security-Policy']).group(1)
        html = r.get_data(as_text=True)
        self.assertIn(f'nonce="{nonce}"', html)
        self.assertNotRegex(html, r'<script>')                       # no un-nonced inline script left
        self.assertNotRegex(html, r'\son(change|click|submit)=')
    def test_nonce_differs_per_request(self):
        c = A.app.test_client()
        n = [re.search(r"'nonce-([^']+)'", c.get('/').headers['Content-Security-Policy']).group(1) for _ in range(3)]
        self.assertEqual(len(set(n)), 3)
    def test_static_files_are_cacheable(self):
        r = A.app.test_client().get('/static/css/style.css'); self.assertEqual(r.status_code, 200); self.assertNotIn('no-store', r.headers.get('Cache-Control', ''))
    def test_no_inline_handlers_in_any_template(self):
        for name in os.listdir(os.path.join(ROOT, 'templates')):
            text = open(os.path.join(ROOT, 'templates', name), encoding='utf-8').read()
            self.assertNotRegex(text, r'\son(change|click|submit|load|input)="', name)
            self.assertNotIn('<script>', text.replace('<script nonce="{{ csp_nonce() }}">', ''), name)


class BruteForce(unittest.TestCase):
    def setUp(self): clear_limits()
    def test_staff_account_locks_after_five_failures_even_with_correct_password(self):
        c = A.app.test_client()
        for _ in range(5): self.assertEqual(login(c, '/staff/login', CLERK[0], 'wrong').status_code, 200)
        r = login(c, '/staff/login', CLERK[0], CLERK[1]); self.assertEqual(r.status_code, 200)
        self.assertIn('Too many failed sign-in attempts', r.get_data(as_text=True))
        self.assertEqual(c.get('/staff/dashboard').status_code, 302)           # still not signed in
        other = A.app.test_client(); self.assertEqual(login(other, '/staff/login', *OPTOM).status_code, 302)  # other accounts unaffected
    def test_lock_expires(self):
        c = A.app.test_client()
        for _ in range(5): login(c, '/staff/login', CLERK[0], 'wrong')
        cx = connect(); cur = cx.cursor(); past = (datetime.now() - timedelta(seconds=5)).strftime('%Y-%m-%d %H:%M:%S')
        cur.execute('UPDATE rate_limits SET locked_until=%s', (past,)); cx.commit(); cx.close()
        self.assertEqual(login(c, '/staff/login', *CLERK).status_code, 302)
    def test_success_resets_the_counter(self):
        c = A.app.test_client()
        for _ in range(3): login(c, '/staff/login', CLERK[0], 'wrong')
        self.assertEqual(login(c, '/staff/login', *CLERK).status_code, 302)
        c2 = A.app.test_client()
        for _ in range(3): login(c2, '/staff/login', CLERK[0], 'wrong')
        self.assertEqual(login(c2, '/staff/login', *CLERK).status_code, 302)   # 3 + 3 failures never reach 5 in a row
    def test_patient_login_locks_too(self):
        c = A.app.test_client()
        for _ in range(5): login(c, '/patient/login', PATIENT[0], 'nope')
        self.assertIn('Too many failed', login(c, '/patient/login', *PATIENT).get_data(as_text=True))
    def test_unknown_email_is_throttled_the_same_way(self):
        c = A.app.test_client()
        for _ in range(5): login(c, '/staff/login', 'nobody@example.com', 'x')
        self.assertIn('Too many failed', login(c, '/staff/login', 'nobody@example.com', 'x').get_data(as_text=True))
    def test_whole_address_locks_after_many_failures_across_accounts(self):
        c = A.app.test_client()
        for i in range(A.LOGIN_IP_MAX_FAILS): login(c, '/staff/login', f'user{i}@example.com', 'x')
        self.assertIn('Too many failed', login(c, '/staff/login', *OPTOM).get_data(as_text=True))
    def test_password_reset_requests_are_limited(self):
        c = A.app.test_client(); out = []
        for _ in range(5):
            r = c.post('/forgot-password', data=dict(email='someone@example.com', csrf_token=token(c, '/forgot-password'))); out.append('Too many requests' in r.get_data(as_text=True))
        self.assertEqual(out, [False, False, False, True, True])
    def test_signup_requires_consent_and_is_limited(self):
        c = A.app.test_client(); t = token(c, '/signup')
        r = c.post('/signup', data=dict(name='New Person', email='new@example.com', password='longenough1', csrf_token=t))
        self.assertIn('Privacy Notice', r.get_data(as_text=True)); self.assertEqual(r.status_code, 200)
        cx = connect(); cur = cx.cursor(); cur.execute("SELECT COUNT(*) FROM pending_signups WHERE email='new@example.com'"); self.assertEqual(cur.fetchone()[0], 0); cx.close()


class Session(unittest.TestCase):
    def test_get_logout_does_not_sign_out_but_post_does(self):
        c = A.app.test_client(); clear_limits(); login(c, '/staff/login', *STAFF)
        self.assertEqual(c.get('/logout').status_code, 302); self.assertEqual(c.get('/staff/dashboard').status_code, 200)
        self.assertEqual(c.post('/logout').status_code, 302); self.assertEqual(c.get('/staff/dashboard').status_code, 302)
    def test_logout_form_renders_as_post_button(self):
        c = A.app.test_client(); clear_limits(); login(c, '/staff/login', *STAFF)
        html = c.get('/staff/dashboard').get_data(as_text=True)
        self.assertRegex(html, r'<form class="inline-form" method="post" action="/logout">'); self.assertNotIn('href="/logout"', html)
    def test_healthz_and_privacy(self):
        c = A.app.test_client(); r = c.get('/healthz'); self.assertEqual((r.status_code, r.get_json()), (200, {'status': 'ok'}))
        self.assertEqual(c.get('/privacy').status_code, 200)


class Locks(unittest.TestCase):
    def test_exclusive_job_runs_once_at_a_time(self):
        ran = []
        job = A.exclusive('unit-test-job', lambda: ran.append(1))
        holder = connect(); cur = holder.cursor(); cur.execute("SELECT GET_LOCK('hawkeye:unit-test-job',0)"); cur.fetchall()
        job(); self.assertEqual(ran, [], 'job must be skipped while another process holds the lock')
        cur.execute("SELECT RELEASE_LOCK('hawkeye:unit-test-job')"); cur.fetchall(); holder.close()
        job(); self.assertEqual(ran, [1]); job(); self.assertEqual(ran, [1, 1], 'lock must be released after each run')
    def test_lock_released_when_job_raises(self):
        def boom(): raise ValueError('x')
        A.exclusive('unit-test-boom', boom)()
        ran = []; A.exclusive('unit-test-boom', lambda: ran.append(1))(); self.assertEqual(ran, [1])
    def test_concurrent_startup_is_safe(self):
        """Four workers booting at the same instant against an empty database."""
        wipe()
        code = "import os;os.environ.update(APP_ENV='development',ENABLE_SCHEDULER='false',SEED_DEMO_ACCOUNTS='false',ADMIN_EMAIL='boss@example.com',ADMIN_PASSWORD='Boss-pass-123');import wsgi;print('BOOT-OK')"
        procs = [subprocess.Popen([sys.executable, '-c', code], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=os.environ.copy()) for _ in range(4)]
        outs = [p.communicate(timeout=120) for p in procs]
        for p, (o, e) in zip(procs, outs): self.assertEqual((p.returncode, 'BOOT-OK' in o), (0, True), e[-600:])
        cx = connect(); cur = cx.cursor(); cur.execute("SELECT COUNT(*) FROM users WHERE role='Admin'"); self.assertEqual(cur.fetchone()[0], 1)
        cur.execute("SELECT COUNT(*) FROM branches WHERE name='Main Branch'"); self.assertEqual(cur.fetchone()[0], 1); cx.close()
    def tearDown(self):
        # this test starts from an empty database; put the demo data back for the other tests
        if self._testMethodName == 'test_concurrent_startup_is_safe':
            wipe(); A.bootstrap(); make_patient()


class ResetLinks(unittest.TestCase):
    def _link(self):
        c = connect(); cur = c.cursor(); cur.execute('SELECT id,password FROM users WHERE email=%s', (PATIENT[0],)); uid, pw = cur.fetchone(); c.close()
        return A.token_serializer().dumps({'uid': uid, 'email': PATIENT[0], 'purpose': 'reset', 'pv': A.pw_fingerprint(pw)})
    def test_reset_link_works_once_then_dies(self):
        clear_limits(); tok = self._link(); path = f'/reset-password/{tok}'; c = A.app.test_client()
        try:
            self.assertEqual(c.get(path).status_code, 200)
            r = c.post(path, data=dict(password='Brand-new-pass-9', csrf_token=token(c, path))); self.assertEqual(r.status_code, 302)
            self.assertEqual(login(A.app.test_client(), '/patient/login', PATIENT[0], 'Brand-new-pass-9').status_code, 302)
            r2 = c.get(path); self.assertEqual(r2.status_code, 302)                   # the same link is now rejected
            r3 = c.post(path, data=dict(password='Attacker-pass-1', csrf_token=token(c, '/forgot-password'))); self.assertEqual(r3.status_code, 302)
            self.assertEqual(login(A.app.test_client(), '/patient/login', PATIENT[0], 'Attacker-pass-1').status_code, 200)
        finally:
            cx = connect(); cur = cx.cursor(); cur.execute('UPDATE users SET password=%s WHERE email=%s', (A.generate_password_hash(PATIENT[1]), PATIENT[0])); cx.commit(); cx.close(); clear_limits()
    def test_tampered_or_old_style_links_are_rejected(self):
        c = A.app.test_client(); self.assertEqual(c.get('/reset-password/garbage').status_code, 302)
        old_style = A.token_serializer().dumps({'uid': 1, 'email': STAFF[0], 'purpose': 'reset'})   # no password fingerprint
        self.assertEqual(c.get(f'/reset-password/{old_style}').status_code, 302)
    def test_reset_clears_a_lockout(self):
        clear_limits(); c = A.app.test_client()
        for _ in range(5): login(c, '/patient/login', PATIENT[0], 'bad')
        self.assertIn('Too many failed', login(c, '/patient/login', *PATIENT).get_data(as_text=True))
        path = f'/reset-password/{self._link()}'
        try:
            c.post(path, data=dict(password='Another-pass-77', csrf_token=token(c, path)))
            self.assertEqual(login(A.app.test_client(), '/patient/login', PATIENT[0], 'Another-pass-77').status_code, 302)
        finally:
            cx = connect(); cur = cx.cursor(); cur.execute('UPDATE users SET password=%s WHERE email=%s', (A.generate_password_hash(PATIENT[1]), PATIENT[0])); cx.commit(); cx.close(); clear_limits()


class NewStaffOnboarding(unittest.TestCase):
    def test_admin_creates_user_and_new_user_sets_password_from_emailed_link(self):
        clear_limits(); sent = []
        real = A.send_email
        A.send_email = lambda to, subject, html, text=None: (sent.append((to, html)) or (True, 'captured'))
        try:
            admin = A.app.test_client(); login(admin, '/staff/login', *STAFF)
            users_path = [r.rule for r in A.app.url_map.iter_rules() if r.endpoint == 'users'][0]
            r = admin.post(users_path, data=dict(name='New Clerk', email='new.clerk@example.com', role='Clinic Staff', branch_id='1', csrf_token=token(admin, users_path)))
            self.assertLess(r.status_code, 400); self.assertEqual(len(sent), 1)
            link = re.search(r'href="https?://[^/"]+(/reset-password/[^"]+)"', sent[0][1]).group(1)
            c = A.app.test_client(); self.assertEqual(c.get(link).status_code, 200)
            self.assertEqual(c.post(link, data=dict(password='Clerk-pass-2026', csrf_token=token(c, link))).status_code, 302)
            self.assertEqual(login(A.app.test_client(), '/staff/login', 'new.clerk@example.com', 'Clerk-pass-2026').status_code, 302)
            self.assertEqual(c.get(link).status_code, 302)                       # link is single-use
        finally:
            A.send_email = real
            cx = connect(); cur = cx.cursor(); cur.execute("DELETE FROM users WHERE email='new.clerk@example.com'"); cx.commit(); cx.close(); clear_limits()


class ReminderBranches(unittest.TestCase):
    """The Reminders dropdown and Sent log must use the same branch rule (the APPOINTMENT's branch)."""
    def test_dropdown_and_log_agree_for_every_role(self):
        cx = connect(); cur = cx.cursor()
        cur.execute("INSERT IGNORE INTO branches(name,address,active) VALUES('Branch Two','x',1)")
        cur.execute("SELECT id FROM branches WHERE name='Branch Two'"); b2 = cur.fetchone()[0]
        cur.execute("INSERT IGNORE INTO users(name,email,password,role,status,email_verified,branch_id) VALUES('B2 Clerk','b2.clerk@example.com',%s,'Clinic Staff','Active',1,%s)", (A.generate_password_hash('clerk-pass-1'), b2))
        # patient filed under branch 1 (online signup), appointment booked at Branch Two
        cur.execute("INSERT INTO patients(patient_id,name,birthdate,phone,email,address,channel,branch_id) VALUES('HK-RB-1','Reminder Branch Pt','1990-01-01','0','rb@example.com','x','Email',1)"); pid = cur.lastrowid
        cur.execute("INSERT INTO appointments(patient_id,type,`date`,`time`,status,branch_id) VALUES(%s,'Eye Exam','2026-11-02','10:00','Confirmed',%s)", (pid, b2)); aid = cur.lastrowid
        cur.execute("INSERT INTO reminders(patient_id,appointment_id,channel,message,sent_date,status,read_status) VALUES(%s,%s,'Email','x','2026-10-25 09:00','Sent','Unread')", (pid, aid)); cx.commit()
        try:
            def view(email, pw):
                c = A.app.test_client(); clear_limits(); login(c, '/staff/login', email, pw); html = c.get('/staff/reminders').get_data(as_text=True)
                return ('Reminder Branch Pt' in ''.join(re.findall(r'<option value="\d+">([^<]*)</option>', html)),
                        'Reminder Branch Pt' in ''.join(m[0] for m in re.findall(r'<tr><td>([^<]*)</td><td>(\w+)</td>', html)))
            self.assertEqual(view(*STAFF), (True, True), 'admin sees it everywhere')
            self.assertEqual(view('b2.clerk@example.com', 'clerk-pass-1'), (True, True), 'the branch holding the appointment sees it in BOTH places')
            self.assertEqual(view(*CLERK), (False, False), 'another branch sees it in NEITHER place')
        finally:
            cur.execute('DELETE FROM reminders WHERE patient_id=%s', (pid,)); cur.execute('DELETE FROM appointments WHERE patient_id=%s', (pid,)); cur.execute('DELETE FROM patients WHERE id=%s', (pid,))
            cur.execute("DELETE FROM users WHERE email='b2.clerk@example.com'"); cur.execute("DELETE FROM branches WHERE name='Branch Two'"); cx.commit(); cx.close(); clear_limits()


# ---------------------------------------------------------------------------------------------
# Regression tests for: HTTP error codes, unlinked patient accounts, escaped emails, record linking,
# branch-scoped staff booking and race-free booking.
# ---------------------------------------------------------------------------------------------
import threading
from datetime import date

FIX_PW = 'Fix-pass-123'

def _sql(query, args=(), fetch=False):
    cx = connect(); cur = cx.cursor(); cur.execute(query, args)
    out = cur.fetchall() if fetch else cur.lastrowid
    cx.commit(); cx.close(); return out

def mk_patient_user(email, code, name, branch=1, with_record=True):
    uid = _sql("INSERT INTO users(name,email,password,role,status,email_verified,branch_id) VALUES(%s,%s,%s,'Patient','Active',1,%s)",
               (name, email, A.generate_password_hash(FIX_PW), branch))
    pid = _sql("INSERT INTO patients(patient_id,name,birthdate,email,channel,user_id,branch_id) VALUES(%s,%s,'1990-01-01',%s,'Email',%s,%s)",
               (code, name, email, uid, branch)) if with_record else None
    return uid, pid

def fix_cleanup():
    _sql("DELETE FROM appointments WHERE patient_id IN (SELECT id FROM patients WHERE patient_id LIKE 'HK-FIX-%' OR email LIKE '%@fix.example.com')")
    _sql("DELETE FROM reminders WHERE patient_id IN (SELECT id FROM patients WHERE patient_id LIKE 'HK-FIX-%' OR email LIKE '%@fix.example.com')")
    _sql("DELETE FROM patients WHERE patient_id LIKE 'HK-FIX-%' OR email LIKE '%@fix.example.com'")
    _sql("DELETE FROM users WHERE email LIKE '%@fix.example.com'")
    _sql("DELETE FROM pending_signups WHERE email LIKE '%@fix.example.com'")
    _sql("DELETE FROM appointments WHERE branch_id IN (SELECT id FROM branches WHERE name='Fix Branch Two')")
    _sql("DELETE FROM users WHERE email='fix.clerk@example.com'")
    _sql("DELETE FROM branches WHERE name='Fix Branch Two'"); clear_limits()

class _CaptureMail:
    def __enter__(self):
        self.sent = []; self.real = A.send_email
        A.send_email = lambda to, subject, html, text=None: (self.sent.append((to, subject, html, text or '')) or (True, 'captured'))
        return self.sent
    def __exit__(self, *exc): A.send_email = self.real

def race(calls):
    """Fire all callables at the same instant from separate threads; return their results."""
    gate = threading.Barrier(len(calls)); out = [None] * len(calls)
    def run(i): gate.wait(); out[i] = calls[i]()
    ts = [threading.Thread(target=run, args=(i,)) for i in range(len(calls))]
    [t.start() for t in ts]; [t.join(60) for t in ts]
    return out


class HttpErrors(unittest.TestCase):
    def test_wrong_method_is_405_not_500(self):
        c = A.app.test_client()
        r = c.get('/staff/urgent/1/resolve'); self.assertEqual(r.status_code, 405); self.assertIn('POST', r.headers.get('Allow', ''))
        r = c.get('/api/email/test'); self.assertEqual(r.status_code, 405); self.assertFalse(r.get_json()['ok'])
    def test_404_and_redirects_still_work(self):
        c = A.app.test_client(); self.assertEqual(c.get('/definitely/not/here').status_code, 404)
        self.assertEqual(c.get('/staff/dashboard').status_code, 302)


class UnlinkedPatientAccount(unittest.TestCase):
    def setUp(self): fix_cleanup(); clear_limits(); mk_patient_user('orphan@fix.example.com', None, 'Orphan', with_record=False)
    def tearDown(self): fix_cleanup()
    def test_pages_do_not_crash(self):
        c = A.app.test_client(); self.assertEqual(login(c, '/patient/login', 'orphan@fix.example.com', FIX_PW).status_code, 302)
        for path in ('/patient/home', '/patient/prescription', '/patient/reminders', '/patient/profile', '/patient/appointments', '/patient/chat'):
            with self.subTest(path=path): self.assertLess(c.get(path, follow_redirects=True).status_code, 500)
        self.assertEqual(c.get('/patient/home').status_code, 404)
        r = c.post('/patient/reminder/1/read', data=dict(csrf_token=token(c, '/patient/appointments'))); self.assertLess(r.status_code, 500)
        r = c.post('/patient/profile', data=dict(phone='1', email='a@b.co', address='x', channel='Email', csrf_token=token(c, '/patient/appointments'))); self.assertLess(r.status_code, 500)


class EscapedEmails(unittest.TestCase):
    def setUp(self): fix_cleanup(); clear_limits()
    def tearDown(self): fix_cleanup()
    def signup(self, c, **kw):
        d = dict(name='Eve Tester', email='eve@fix.example.com', password='longenough1', consent='on', csrf_token=token(c, '/signup')); d.update(kw)
        return c.post('/signup', data=d)
    def test_name_is_escaped_in_html_part(self):
        with _CaptureMail() as sent:
            r = self.signup(A.app.test_client(), name='<a href="http://evil.example">Click here</a>')
        self.assertEqual(r.status_code, 302); self.assertEqual(len(sent), 1)
        html = sent[0][2]
        self.assertNotIn('<a href="http://evil.example"', html); self.assertIn('&lt;a href=', html)
    def test_email_with_newline_or_junk_is_rejected(self):
        for bad in ('eve@fix.example.com\nBcc: victim@fix.example.com', 'no-at-sign', 'a b@fix.example.com'):
            with self.subTest(bad=bad), _CaptureMail() as sent:
                r = self.signup(A.app.test_client(), email=bad); self.assertEqual(r.status_code, 200); self.assertEqual(sent, [])
    def test_staff_follow_up_message_is_escaped(self):
        uid, pid = mk_patient_user('esc@fix.example.com', 'HK-FIX-ESC', 'Esc <i>Pat</i>')
        with _CaptureMail() as sent:
            c = A.app.test_client(); login(c, '/staff/login', *STAFF)
            r = c.post(f'/staff/urgent-contact/{pid}/email', data=dict(message='<script>alert(1)</script>', csrf_token=token(c, '/staff/appointment/new')))
        self.assertEqual(r.status_code, 302); self.assertEqual(len(sent), 1)
        self.assertNotIn('<script>', sent[0][2]); self.assertNotIn('<i>', sent[0][2]); self.assertIn('&lt;script&gt;', sent[0][2])


class RecordLinking(unittest.TestCase):
    def setUp(self): fix_cleanup(); clear_limits()
    def tearDown(self): fix_cleanup()
    def add(self, code, name, dob, email):
        return _sql("INSERT INTO patients(patient_id,name,birthdate,email,channel,branch_id) VALUES(%s,%s,%s,%s,'Email',1)", (code, name, dob, email))
    def signup(self, email, code, name, dob):
        c = A.app.test_client()
        return c, c.post('/signup', data=dict(name=name, email=email, password='longenough1', consent='on', patient_id=code, birthdate=dob, csrf_token=token(c, '/signup')))
    def pending(self, email): return _sql('SELECT COUNT(*) FROM pending_signups WHERE email=%s', (email,), fetch=True)[0][0]
    def test_record_without_email_cannot_be_claimed(self):
        self.add('HK-FIX-1', 'Ana Link', '1991-02-03', None)
        with _CaptureMail() as sent: _, r = self.signup('ana@fix.example.com', 'HK-FIX-1', 'Ana Link', '1991-02-03')
        self.assertEqual(r.status_code, 200); self.assertIn('could not verify', r.get_data(as_text=True)); self.assertEqual((sent, self.pending('ana@fix.example.com')), ([], 0))
    def test_record_with_other_email_cannot_be_claimed(self):
        self.add('HK-FIX-2', 'Ben Link', '1992-03-04', 'ben@fix.example.com')
        with _CaptureMail() as sent: _, r = self.signup('evil@fix.example.com', 'HK-FIX-2', 'Ben Link', '1992-03-04')
        self.assertEqual(r.status_code, 200); self.assertEqual((sent, self.pending('evil@fix.example.com')), ([], 0))
    def test_wrong_birthdate_is_rejected_even_with_right_email(self):
        self.add('HK-FIX-3', 'Cy Link', '1993-04-05', 'cy@fix.example.com')
        with _CaptureMail() as sent: _, r = self.signup('cy@fix.example.com', 'HK-FIX-3', 'Cy Link', '1999-09-09')
        self.assertEqual((r.status_code, sent), (200, []))
    def test_owner_of_the_on_file_email_can_link_once(self):
        pid = self.add('HK-FIX-4', 'Dee Link', '1994-05-06', 'dee@fix.example.com')
        with _CaptureMail() as sent: c, r = self.signup('DEE@fix.example.com', 'HK-FIX-4', 'Dee Link', '1994-05-06')
        self.assertEqual(r.status_code, 302); self.assertEqual([m[0] for m in sent], ['dee@fix.example.com'])
        code = re.search(r'is (\d{6})', sent[0][3]).group(1)
        r = c.post('/verify-signup-email', data=dict(code=code, csrf_token=token(c, '/verify-signup-email'))); self.assertEqual(r.status_code, 302)
        row = _sql('SELECT user_id FROM patients WHERE id=%s', (pid,), fetch=True)[0][0]; self.assertIsNotNone(row)
        with _CaptureMail() as sent2: _, r2 = self.signup('other@fix.example.com', 'HK-FIX-4', 'Dee Link', '1994-05-06')
        self.assertEqual((r2.status_code, sent2), (200, []), 'an already-claimed record cannot be claimed again')
    def test_claim_is_atomic_if_record_is_taken_between_steps(self):
        pid = self.add('HK-FIX-5', 'Eli Link', '1995-06-07', 'eli@fix.example.com')
        with _CaptureMail() as sent: c, r = self.signup('eli@fix.example.com', 'HK-FIX-5', 'Eli Link', '1995-06-07')
        thief = _sql("INSERT INTO users(name,email,password,role,status,email_verified,branch_id) VALUES('T','thief@fix.example.com','x','Patient','Active',1,1)")
        _sql('UPDATE patients SET user_id=%s WHERE id=%s', (thief, pid))         # someone else claims it before the code is entered
        code = re.search(r'is (\d{6})', sent[0][3]).group(1)
        r = c.post('/verify-signup-email', data=dict(code=code, csrf_token=token(c, '/verify-signup-email'))); self.assertEqual(r.status_code, 302)
        self.assertEqual(_sql("SELECT COUNT(*) FROM users WHERE email='eli@fix.example.com'", fetch=True)[0][0], 0)
        self.assertEqual(_sql('SELECT user_id FROM patients WHERE id=%s', (pid,), fetch=True)[0][0], thief)
    def test_new_patient_codes_are_random_not_sequential(self):
        codes = []
        for i in range(2):
            email = f'rand{i}@fix.example.com'
            with _CaptureMail() as sent:
                c = A.app.test_client(); c.post('/signup', data=dict(name='Rand Pat', email=email, password='longenough1', consent='on', csrf_token=token(c, '/signup')))
            code = re.search(r'is (\d{6})', sent[0][3]).group(1)
            c.post('/verify-signup-email', data=dict(code=code, csrf_token=token(c, '/verify-signup-email')))
            codes.append(_sql('SELECT patient_id FROM patients WHERE email=%s', (email,), fetch=True)[0][0])
        for code in codes: self.assertRegex(code, r'^HK-\d{4}-[0-9A-F]{6}$')
        self.assertNotEqual(codes[0], codes[1])


class StaffBooking(unittest.TestCase):
    def setUp(self):
        fix_cleanup(); clear_limits()
        self.b2 = _sql("INSERT INTO branches(name,address,active) VALUES('Fix Branch Two','x',1)")
        _sql("INSERT INTO users(name,email,password,role,status,email_verified,branch_id) VALUES('Fix Clerk','fix.clerk@example.com',%s,'Clinic Staff','Active',1,1)", (A.generate_password_hash('clerk-pass-1'),))
        _, self.p1 = mk_patient_user('own@fix.example.com', 'HK-FIX-OWN', 'Own Branch Pt', branch=1)
        _, self.p2 = mk_patient_user('far@fix.example.com', 'HK-FIX-FAR', 'Other Branch Pt', branch=self.b2)
    def tearDown(self): fix_cleanup()
    def book(self, client, pid, day, clock, **kw):
        d = dict(patient_id=pid, type='Eye check', date=day, time=clock, notes='', csrf_token=token(client, '/staff/appointment/new')); d.update(kw)
        return client.post('/staff/appointment/new', data=d)
    def rows(self, pid): return _sql('SELECT date,time,branch_id FROM appointments WHERE patient_id=%s', (pid,), fetch=True)
    def day(self, n): return (date.today() + timedelta(days=n)).isoformat()
    def test_clerk_cannot_book_for_another_branchs_patient(self):
        c = A.app.test_client(); login(c, '/staff/login', 'fix.clerk@example.com', 'clerk-pass-1')
        r = self.book(c, self.p2, self.day(20), '10:00'); self.assertEqual(r.status_code, 302)
        self.assertEqual(self.rows(self.p2), [], 'no appointment may be created for another branch')
        self.assertEqual(len(self.rows(self.p1)), 0)
        self.book(c, self.p1, self.day(20), '10:00'); self.assertEqual(len(self.rows(self.p1)), 1)
    def test_admin_can_still_book_any_branch(self):
        c = A.app.test_client(); login(c, '/staff/login', *STAFF)
        self.book(c, self.p2, self.day(21), '11:00'); self.assertEqual(self.rows(self.p2), [(self.day(21), '11:00', self.b2)])
    def test_date_and_time_are_stored_in_canonical_form(self):
        c = A.app.test_client(); login(c, '/staff/login', *STAFF); d = date.today() + timedelta(days=40)
        self.book(c, self.p1, f'{d.year}-{d.month}-{d.day}', '9:30')
        self.assertEqual(self.rows(self.p1), [(d.isoformat(), '09:30', 1)])
        self.book(c, self.p1, d.isoformat(), '09:30')                                   # same slot, other spelling -> must conflict
        self.assertEqual(len(self.rows(self.p1)), 1)
    def test_concurrent_staff_bookings_of_one_slot_make_exactly_one_appointment(self):
        clients = []
        for _ in range(6):
            c = A.app.test_client(); login(c, '/staff/login', *STAFF); clients.append((c, token(c, '/staff/appointment/new')))
        for n in (50, 51, 52):
            day = self.day(n)
            race([(lambda c=c, t=t: c.post('/staff/appointment/new', data=dict(patient_id=self.p1, type='Eye check', date=day, time='14:00', notes='', csrf_token=t))) for c, t in clients])
            self.assertEqual(len(_sql('SELECT id FROM appointments WHERE date=%s AND time=%s AND branch_id=1', (day, '14:00'), fetch=True)), 1, f'double-booked on {day}')


class PatientBookingRace(unittest.TestCase):
    def setUp(self): fix_cleanup(); clear_limits()
    def tearDown(self): fix_cleanup()
    def client(self, email):
        c = A.app.test_client(); self.assertEqual(login(c, '/patient/login', email, FIX_PW).status_code, 302); return c, token(c, '/patient/appointments')
    def post(self, c, t, day, clock): return c.post('/patient/appointments', data=dict(branch_id='1', date=day, time=clock, type='Eye check', notes='', csrf_token=t))
    def day(self, n): return (date.today() + timedelta(days=n)).isoformat()
    def test_one_patient_double_clicking_gets_a_single_active_booking(self):
        _, pid = mk_patient_user('dbl@fix.example.com', 'HK-FIX-DBL', 'Double Click')
        sessions = [self.client('dbl@fix.example.com') for _ in range(6)]
        race([(lambda c=c, t=t, i=i: self.post(c, t, self.day(30 + i), f'1{i}:00')) for i, (c, t) in enumerate(sessions)])
        self.assertEqual(len(_sql('SELECT id FROM appointments WHERE patient_id=%s', (pid,), fetch=True)), 1)
    def test_different_patients_cannot_take_the_same_slot(self):
        sessions = []
        for i in range(5):
            mk_patient_user(f'slot{i}@fix.example.com', f'HK-FIX-S{i}', f'Slot Pt {i}'); sessions.append(self.client(f'slot{i}@fix.example.com'))
        day = self.day(35)
        race([(lambda c=c, t=t: self.post(c, t, day, '15:00')) for c, t in sessions])
        self.assertEqual(len(_sql('SELECT id FROM appointments WHERE date=%s AND time=%s AND branch_id=1', (day, '15:00'), fetch=True)), 1)
    def test_non_padded_time_is_stored_canonically(self):
        _, pid = mk_patient_user('pad@fix.example.com', 'HK-FIX-PAD', 'Pad Pt'); c, t = self.client('pad@fix.example.com')
        d = date.today() + timedelta(days=33); self.post(c, t, f'{d.year}-{d.month}-{d.day}', '9:05')
        self.assertEqual(_sql('SELECT date,time FROM appointments WHERE patient_id=%s', (pid,), fetch=True), [(d.isoformat(), '09:05')])


if __name__ == '__main__':
    unittest.main(verbosity=2)

"""Tests for two-step sign-in (authenticator app + backup codes) and Sign in with Google.

Like smoke_test.py, run against a THROWAWAY MySQL database whose name ends in "_test" (it is wiped first):

    set MYSQL_DATABASE=hawkeyes_test
    python -m unittest tests.test_two_step_google -v

The first two classes need no database at all. The Google network call is replaced by a fake in every test,
so nothing here talks to Google.
"""
import os, re, sys, time, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.update(FLASK_SECRET_KEY='t' * 48, SEED_DEMO_ACCOUNTS='true', ENABLE_SCHEDULER='false', APP_ENV='development')
os.environ.pop('GOOGLE_CLIENT_ID', None); os.environ.pop('GOOGLE_CLIENT_SECRET', None)

import mfa, google_auth, production

# --- load the app: normally against the MySQL "_test" database; a prepared stand-in may be supplied by a runner ---
if os.getenv('HAWKEYE_TEST_PREPARED') == '1':
    import app as A
else:
    DB_NAME = os.getenv('MYSQL_DATABASE', '')
    if not DB_NAME.endswith('_test'):
        raise SystemExit('Refusing to run: MYSQL_DATABASE must end with "_test" (these tests wipe the database).')
    import mysql.connector
    _c = mysql.connector.connect(host=os.getenv('MYSQL_HOST', '127.0.0.1'), port=int(os.getenv('MYSQL_PORT', '3306')),
                                 user=os.getenv('MYSQL_USER', 'root'), password=os.getenv('MYSQL_PASSWORD', ''), database=DB_NAME)
    _cur = _c.cursor(); _cur.execute('SET FOREIGN_KEY_CHECKS=0'); _cur.execute('SHOW TABLES')
    for (_t,) in _cur.fetchall(): _cur.execute(f'DROP TABLE `{_t}`')
    _cur.execute('SET FOREIGN_KEY_CHECKS=1'); _c.commit(); _c.close()
    import app as A
    A.bootstrap()


def sql(statement, params=()):
    c = A.db()
    try:
        cur = c.execute(statement, params); c.commit()
        return cur
    finally: c.close()

def row(statement, params=()):
    c = A.db()
    try: return c.execute(statement, params).fetchone()
    finally: c.close()

def make_user(email, role='Patient', password='Correct-horse-1', name='Test Person'):
    sql('DELETE FROM users WHERE email=?', (email,))
    sql("INSERT INTO users(name,email,password,role,status,email_verified,branch_id) VALUES(?,?,?,?,'Active',1,1)",
        (name, email, A.generate_password_hash(password), role))
    uid = row('SELECT id FROM users WHERE email=?', (email,))['id']
    if role == 'Patient':
        sql("INSERT INTO patients(patient_id,name,email,user_id,channel,branch_id) VALUES(?,?,?,?,'Email',1)", (f'HK-T-{uid}', name, email, uid))
    return uid, password

def csrf(client, path):
    html = client.get(path).get_data(as_text=True)
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
    return m.group(1) if m else ''

def post(client, form_page, url, **data):
    return client.post(url, data=dict(data, csrf_token=csrf(client, form_page)))

def password_login(client, email, password, patient=True):
    page = '/patient/login' if patient else '/staff/login'
    return post(client, page, page, email=email, password=password)

def current_step(offset=0):
    return int(time.time() // mfa.PERIOD) + offset

def reset_limits(): sql('DELETE FROM rate_limits')


class TotpAndBackupCodes(unittest.TestCase):
    SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'     # RFC 6238 test key "12345678901234567890"

    def test_rfc6238_vectors(self):
        # RFC 6238 appendix B (SHA-1); the 8-digit values there end in these 6 digits.
        for t, expected in ((59, '287082'), (1111111109, '081804'), (1111111111, '050471'),
                            (1234567890, '005924'), (2000000000, '279037'), (20000000000, '353130')):
            with self.subTest(t=t): self.assertEqual(mfa.totp_at(self.SECRET, t // 30), expected)

    def test_verify_accepts_neighbouring_step_but_not_far_ones(self):
        now = 1111111109
        step = now // 30
        self.assertEqual(mfa.verify_totp(self.SECRET, '081804', now=now), step)
        self.assertEqual(mfa.verify_totp(self.SECRET, mfa.totp_at(self.SECRET, step - 1), now=now), step - 1)
        self.assertIsNone(mfa.verify_totp(self.SECRET, mfa.totp_at(self.SECRET, step - 3), now=now))
        self.assertIsNone(mfa.verify_totp(self.SECRET, mfa.totp_at(self.SECRET, step + 3), now=now))

    def test_a_used_step_cannot_be_replayed(self):
        now = 1111111109; step = now // 30
        self.assertIsNone(mfa.verify_totp(self.SECRET, '081804', last_step=step, now=now))
        self.assertEqual(mfa.verify_totp(self.SECRET, mfa.totp_at(self.SECRET, step + 1), last_step=step, now=now), step + 1)

    def test_garbage_is_rejected(self):
        for bad in ('', '12345', '1234567', 'abcdef', None):
            with self.subTest(bad=bad): self.assertIsNone(mfa.verify_totp(self.SECRET, bad, now=59))

    def test_spaces_in_typed_code_are_ignored(self):
        self.assertEqual(mfa.verify_totp(self.SECRET, '287 082', now=59), 1)

    def test_secret_and_uri(self):
        s = mfa.new_secret()
        self.assertRegex(s, r'^[A-Z2-7]{32}$')
        self.assertEqual(mfa.totp_at(s, 1), mfa.totp_at(s.lower(), 1))
        uri = mfa.provisioning_uri(s, 'a+b@example.com', 'HawkEye Optical Clinic')
        self.assertTrue(uri.startswith('otpauth://totp/HawkEye%20Optical%20Clinic%3Aa%2Bb%40example.com?secret=' + s))
        self.assertIn('issuer=HawkEye%20Optical%20Clinic', uri)

    def test_backup_codes(self):
        codes = mfa.new_backup_codes()
        self.assertEqual(len(codes), 10); self.assertEqual(len(set(codes)), 10)
        shown = mfa.format_backup_code(codes[0])
        self.assertRegex(shown, r'^[A-Z2-9]{5}-[A-Z2-9]{5}$')
        self.assertEqual(mfa.normalize_backup_code(shown.lower()), codes[0])
        self.assertEqual(mfa.normalize_backup_code(' ' + shown + ' '), codes[0])
        for bad in ('', 'ABC', '0000000000', 'ABCDE-FGHIJ-K', None): self.assertIsNone(mfa.normalize_backup_code(bad))
        self.assertNotEqual(mfa.hash_backup_code(1, codes[0]), mfa.hash_backup_code(2, codes[0]))   # salted per user
        self.assertEqual(mfa.hash_backup_code(1, codes[0]), mfa.hash_backup_code(1, codes[0]))
        self.assertNotIn(codes[0], mfa.hash_backup_code(1, codes[0]))


class GoogleClaims(unittest.TestCase):
    def setUp(self):
        os.environ.update(GOOGLE_CLIENT_ID='cid.apps.googleusercontent.com', GOOGLE_CLIENT_SECRET='sec')
        self.now = 1_700_000_000
        self.good = dict(iss='https://accounts.google.com', aud='cid.apps.googleusercontent.com', exp=self.now + 600, nonce='N1',
                         sub='1234', email='Pat@Example.com', email_verified=True, name='Pat Example')
    def tearDown(self): os.environ.pop('GOOGLE_CLIENT_ID', None); os.environ.pop('GOOGLE_CLIENT_SECRET', None)

    def test_good_claims(self):
        self.assertEqual(google_auth.validate_claims(self.good, 'N1', now=self.now), ('1234', 'pat@example.com', 'Pat Example'))

    def test_each_bad_claim_is_rejected(self):
        for field, value in (('iss', 'https://evil.example'), ('aud', 'someone-else'), ('exp', self.now - 1000), ('nonce', 'other'),
                             ('email_verified', False), ('email_verified', 'false'), ('sub', ''), ('email', '')):
            with self.subTest(field=field, value=value):
                with self.assertRaises(google_auth.GoogleAuthError): google_auth.validate_claims(dict(self.good, **{field: value}), 'N1', now=self.now)

    def test_missing_nonce_and_non_ascii_nonce_are_rejected_cleanly(self):
        with self.assertRaises(google_auth.GoogleAuthError): google_auth.validate_claims(self.good, '', now=self.now)
        with self.assertRaises(google_auth.GoogleAuthError): google_auth.validate_claims(dict(self.good, nonce='é'), 'N1', now=self.now)

    def test_audience_may_be_a_list(self):
        google_auth.validate_claims(dict(self.good, aud=['x', 'cid.apps.googleusercontent.com']), 'N1', now=self.now)

    def test_pkce_challenge_is_s256_of_verifier(self):
        import base64, hashlib
        a = google_auth.new_attempt()
        self.assertEqual(a['challenge'], base64.urlsafe_b64encode(hashlib.sha256(a['verifier'].encode()).digest()).rstrip(b'=').decode())
        url = google_auth.authorize_url(a, 'http://127.0.0.1:5000/auth/google/callback')
        for part in ('response_type=code', 'code_challenge_method=S256', 'state=' + a['state'], 'nonce=' + a['nonce'],
                     'redirect_uri=http%3A%2F%2F127.0.0.1%3A5000%2Fauth%2Fgoogle%2Fcallback', 'scope=openid+email+profile'):
            self.assertIn(part, url)

    def test_decode_id_token(self):
        import base64, json
        body = base64.urlsafe_b64encode(json.dumps({'sub': 'x'}).encode()).rstrip(b'=').decode()
        self.assertEqual(google_auth.decode_id_token(f'aaa.{body}.bbb'), {'sub': 'x'})
        with self.assertRaises(google_auth.GoogleAuthError): google_auth.decode_id_token('not-a-jwt')

    def test_csp_allows_google_form_redirect_only_when_configured(self):
        self.assertIn("form-action 'self' https://accounts.google.com", production.build_csp('n'))
        os.environ.pop('GOOGLE_CLIENT_ID')
        self.assertIn("form-action 'self';", production.build_csp('n') + ';')
        self.assertNotIn('accounts.google.com', production.build_csp('n'))


class TwoStepSignIn(unittest.TestCase):
    def setUp(self):
        reset_limits(); self.client = A.app.test_client()

    def enable(self, client, email, password, patient=True):
        """Sign in, turn two-step on; returns (secret, backup_codes)."""
        self.assertEqual(password_login(client, email, password, patient).status_code, 302)
        post(client, '/account/security', '/account/mfa/start')
        with client.session_transaction() as s: secret = s['mfa_setup_secret']
        r = post(client, '/account/security', '/account/mfa/enable', code=mfa.totp_at(secret, current_step()))
        self.assertEqual(r.status_code, 200)
        codes = re.findall(r'<code>([A-Z2-9]{5}-[A-Z2-9]{5})</code>', r.get_data(as_text=True))
        self.assertEqual(len(codes), 10)
        return secret, codes

    def test_signing_in_without_two_step_is_unchanged(self):
        make_user('plain@example.test')
        r = password_login(self.client, 'plain@example.test', 'Correct-horse-1')
        self.assertTrue(r.headers['Location'].endswith('/patient/home'))
        with self.client.session_transaction() as s: self.assertEqual(s['role'], 'Patient')

    def test_security_page_needs_a_login(self):
        self.assertEqual(self.client.get('/account/security').status_code, 302)
        for url in ('/account/mfa/start', '/account/mfa/enable', '/account/mfa/disable', '/account/mfa/backup-codes'):
            with self.subTest(url=url): self.assertEqual(self.client.post(url, data={'csrf_token': csrf(self.client, '/patient/login')}).status_code, 302)

    def test_enable_then_login_requires_the_code(self):
        uid, pw = make_user('p1@example.test')
        secret, codes = self.enable(self.client, 'p1@example.test', pw)
        u = row('SELECT mfa_enabled, mfa_secret FROM users WHERE id=?', (uid,))
        self.assertEqual((u['mfa_enabled'], u['mfa_secret']), (1, secret))
        stored = [r['code_hash'] for r in A.db().execute('SELECT code_hash FROM mfa_backup_codes WHERE user_id=?', (uid,)).fetchall()]
        self.assertEqual(len(stored), 10)
        self.assertFalse(any(mfa.normalize_backup_code(c) in stored for c in codes))        # only hashes are stored

        other = A.app.test_client()
        r = password_login(other, 'p1@example.test', pw)
        self.assertTrue(r.headers['Location'].endswith('/mfa/verify'))
        with other.session_transaction() as s: self.assertNotIn('uid', s)                  # not signed in yet
        self.assertEqual(other.get('/patient/home').status_code, 302)                       # protected pages stay closed
        bad = post(other, '/mfa/verify', '/mfa/verify', code='000000')
        self.assertEqual(bad.status_code, 200); self.assertIn('not correct', bad.get_data(as_text=True))
        with other.session_transaction() as s: self.assertNotIn('uid', s)
        # The code used at setup is spent; the next step's code is accepted (inside the +/-1 window).
        self.assertEqual(post(other, '/mfa/verify', '/mfa/verify', code=mfa.totp_at(secret, current_step())).status_code, 200)
        ok = post(other, '/mfa/verify', '/mfa/verify', code=mfa.totp_at(secret, current_step(1)))
        self.assertTrue(ok.headers['Location'].endswith('/patient/home'))
        with other.session_transaction() as s: self.assertEqual((s['uid'], s['role']), (uid, 'Patient'))

    def test_a_code_cannot_be_used_twice(self):
        uid, pw = make_user('p2@example.test')
        secret, _ = self.enable(self.client, 'p2@example.test', pw)
        code = mfa.totp_at(secret, current_step(1))
        first = A.app.test_client(); password_login(first, 'p2@example.test', pw)
        self.assertEqual(post(first, '/mfa/verify', '/mfa/verify', code=code).status_code, 302)
        second = A.app.test_client(); password_login(second, 'p2@example.test', pw)
        self.assertEqual(post(second, '/mfa/verify', '/mfa/verify', code=code).status_code, 200)   # replay refused

    def test_backup_code_works_once(self):
        uid, pw = make_user('p3@example.test')
        _, codes = self.enable(self.client, 'p3@example.test', pw)
        a = A.app.test_client(); password_login(a, 'p3@example.test', pw)
        r = post(a, '/mfa/verify', '/mfa/verify', code=codes[0].lower())                    # case and dash do not matter
        self.assertTrue(r.headers['Location'].endswith('/patient/home'))
        self.assertEqual(row('SELECT COUNT(*) AS n FROM mfa_backup_codes WHERE user_id=? AND used=0', (uid,))['n'], 9)
        b = A.app.test_client(); password_login(b, 'p3@example.test', pw)
        self.assertEqual(post(b, '/mfa/verify', '/mfa/verify', code=codes[0]).status_code, 200)   # already used
        self.assertEqual(post(b, '/mfa/verify', '/mfa/verify', code=codes[1]).status_code, 302)

    def test_lockout_after_repeated_wrong_codes(self):
        uid, pw = make_user('p4@example.test')
        secret, _ = self.enable(self.client, 'p4@example.test', pw)
        c = A.app.test_client(); password_login(c, 'p4@example.test', pw)
        for _ in range(A.MFA_MAX_FAILS): post(c, '/mfa/verify', '/mfa/verify', code='000000')
        r = post(c, '/mfa/verify', '/mfa/verify', code=mfa.totp_at(secret, current_step(1)))   # even the right code is refused now
        self.assertEqual(r.status_code, 200); self.assertIn('Too many incorrect codes', r.get_data(as_text=True))
        with c.session_transaction() as s: self.assertNotIn('uid', s)

    def test_verify_page_without_a_password_step_goes_nowhere(self):
        r = self.client.get('/mfa/verify'); self.assertEqual(r.status_code, 302)
        self.assertEqual(post(self.client, '/patient/login', '/mfa/verify', code='123456').status_code, 302)

    def test_pending_login_expires(self):
        uid, pw = make_user('p5@example.test'); self.enable(self.client, 'p5@example.test', pw)
        c = A.app.test_client(); password_login(c, 'p5@example.test', pw)
        with c.session_transaction() as s: s['mfa_pending'] = dict(s['mfa_pending'], ts=s['mfa_pending']['ts'] - A.MFA_PENDING_SECONDS - 5)   # reassign: Flask only saves top-level changes
        self.assertEqual(c.get('/mfa/verify').status_code, 302)

    def test_disable_needs_a_valid_code(self):
        uid, pw = make_user('p6@example.test')
        secret, codes = self.enable(self.client, 'p6@example.test', pw)
        post(self.client, '/account/security', '/account/mfa/disable', code='000000')
        self.assertEqual(row('SELECT mfa_enabled FROM users WHERE id=?', (uid,))['mfa_enabled'], 1)
        post(self.client, '/account/security', '/account/mfa/disable', code=codes[2])
        u = row('SELECT mfa_enabled, mfa_secret FROM users WHERE id=?', (uid,))
        self.assertEqual((u['mfa_enabled'], u['mfa_secret']), (0, None))
        self.assertEqual(row('SELECT COUNT(*) AS n FROM mfa_backup_codes WHERE user_id=?', (uid,))['n'], 0)
        self.assertTrue(password_login(A.app.test_client(), 'p6@example.test', pw).headers['Location'].endswith('/patient/home'))

    def test_regenerating_backup_codes_invalidates_old_ones(self):
        uid, pw = make_user('p7@example.test')
        secret, old = self.enable(self.client, 'p7@example.test', pw)
        r = post(self.client, '/account/security', '/account/mfa/backup-codes', code=old[0])
        new = re.findall(r'<code>([A-Z2-9]{5}-[A-Z2-9]{5})</code>', r.get_data(as_text=True))
        self.assertEqual(len(new), 10); self.assertFalse(set(new) & set(old))
        c = A.app.test_client(); password_login(c, 'p7@example.test', pw)
        self.assertEqual(post(c, '/mfa/verify', '/mfa/verify', code=old[1]).status_code, 200)   # old code dead
        self.assertEqual(post(c, '/mfa/verify', '/mfa/verify', code=new[1]).status_code, 302)

    def test_wrong_setup_code_does_not_enable(self):
        uid, pw = make_user('p8@example.test'); password_login(self.client, 'p8@example.test', pw)
        post(self.client, '/account/security', '/account/mfa/start')
        post(self.client, '/account/security', '/account/mfa/enable', code='000000')
        self.assertEqual(row('SELECT mfa_enabled FROM users WHERE id=?', (uid,))['mfa_enabled'], 0)

    def test_security_page_renders_for_patient_and_staff_during_setup(self):
        uid, pw = make_user('p9@example.test'); password_login(self.client, 'p9@example.test', pw)
        post(self.client, '/account/security', '/account/mfa/start')
        html = self.client.get('/account/security').get_data(as_text=True)
        self.assertIn('setup-key', html)
        staff_id, spw = make_user('s9@example.test', role='Clinic Staff', name='Clerk')
        c = A.app.test_client(); password_login(c, 's9@example.test', spw, patient=False)
        self.assertIn('Security', c.get('/account/security').get_data(as_text=True))

    def test_staff_two_step_and_admin_reset(self):
        sid, spw = make_user('s10@example.test', role='Clinic Staff', name='Clerk')
        secret, _ = self.enable(self.client, 's10@example.test', spw, patient=False)
        c = A.app.test_client(); r = password_login(c, 's10@example.test', spw, patient=False)
        self.assertTrue(r.headers['Location'].endswith('/mfa/verify'))
        r = post(c, '/mfa/verify', '/mfa/verify', code=mfa.totp_at(secret, current_step(1)))
        self.assertTrue(r.headers['Location'].endswith('/staff/dashboard'))
        with c.session_transaction() as s: self.assertEqual((s['role'], s['branch_id']), ('Clinic Staff', 1))
        self.assertGreaterEqual(row("SELECT COUNT(*) AS n FROM audit_logs WHERE user_id=? AND action LIKE '%two-step%'", (sid,))['n'], 1)

        make_user('admin10@example.test', role='Admin', name='Boss')
        admin = A.app.test_client(); password_login(admin, 'admin10@example.test', 'Correct-horse-1', patient=False)
        r = post(admin, '/staff/users', f'/staff/users/{sid}/mfa-reset')
        self.assertEqual(row('SELECT mfa_enabled FROM users WHERE id=?', (sid,))['mfa_enabled'], 0)
        # a non-admin cannot do it
        make_user('s11@example.test', role='Clinic Staff', name='Other')
        other = A.app.test_client(); password_login(other, 's11@example.test', 'Correct-horse-1', patient=False)
        self.assertEqual(post(other, '/account/security', f'/staff/users/{sid}/mfa-reset').status_code, 403)


class GoogleSignIn(unittest.TestCase):
    CID = 'cid.apps.googleusercontent.com'

    def setUp(self):
        reset_limits(); os.environ.update(GOOGLE_CLIENT_ID=self.CID, GOOGLE_CLIENT_SECRET='sec', APP_BASE_URL='http://127.0.0.1:5000')
        self.client = A.app.test_client(); self.claims = {}
        self._orig = google_auth.exchange_code
        def fake(code, verifier, redirect_uri, timeout=10):
            if code == 'boom': raise google_auth.GoogleAuthError('simulated Google failure')
            return dict(iss='https://accounts.google.com', aud=self.CID, exp=int(time.time()) + 600, nonce=self.nonce, **self.claims)
        google_auth.exchange_code = fake
    def tearDown(self):
        google_auth.exchange_code = self._orig
        for k in ('GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET'): os.environ.pop(k, None)

    def start(self, intent, consent=True, page='/signup'):
        data = dict(intent=intent, csrf_token=csrf(self.client, page))
        if consent: data['consent'] = '1'
        r = self.client.post('/auth/google/start', data=data)
        with self.client.session_transaction() as s: g = s.get('google_oauth')
        if g: self.nonce, self.state = g['nonce'], g['state']
        return r

    def callback(self, code='abc', state=None):
        return self.client.get('/auth/google/callback', query_string={'code': code, 'state': state or self.state})

    def user(self, email): return row('SELECT * FROM users WHERE lower(email)=?', (email,))

    def test_buttons_follow_configuration(self):
        self.assertIn('Continue with Google', self.client.get('/patient/login').get_data(as_text=True))
        self.assertIn('Sign up with Google', self.client.get('/signup').get_data(as_text=True))
        self.assertNotIn('Google', self.client.get('/staff/login').get_data(as_text=True))
        os.environ.pop('GOOGLE_CLIENT_ID')
        self.assertNotIn('Continue with Google', self.client.get('/patient/login').get_data(as_text=True))
        r = self.client.post('/auth/google/start', data=dict(intent='login', csrf_token=csrf(self.client, '/patient/login')))
        self.assertTrue(r.headers['Location'].endswith('/patient/login'))

    def test_start_redirects_to_google_with_state_nonce_and_pkce(self):
        r = self.start('signup')
        loc = r.headers['Location']
        self.assertTrue(loc.startswith('https://accounts.google.com/o/oauth2/v2/auth?'))
        for part in (f'client_id={self.CID}', 'code_challenge_method=S256', f'state={self.state}', f'nonce={self.nonce}',
                     'redirect_uri=http%3A%2F%2F127.0.0.1%3A5000%2Fauth%2Fgoogle%2Fcallback'): self.assertIn(part, loc)
        self.assertIn("form-action 'self' https://accounts.google.com", r.headers['Content-Security-Policy'])

    def test_signup_needs_the_privacy_box(self):
        r = self.start('signup', consent=False)
        self.assertTrue(r.headers['Location'].endswith('/signup'))
        with self.client.session_transaction() as s: self.assertNotIn('google_oauth', s)

    def test_signup_with_google_creates_patient_and_signs_in(self):
        self.claims = dict(sub='g-100', email='New.Person@Gmail.test', email_verified=True, name='New Person')
        self.start('signup'); r = self.callback()
        self.assertTrue(r.headers['Location'].endswith('/patient/home'))
        u = self.user('new.person@gmail.test')
        self.assertEqual((u['role'], u['status'], u['email_verified'], u['google_sub'], u['branch_id']), ('Patient', 'Active', 1, 'g-100', 1))
        self.assertFalse(A.check_password_hash(u['password'], ''))                          # unusable random password
        p = row('SELECT * FROM patients WHERE user_id=?', (u['id'],))
        self.assertEqual((p['name'], p['email'], p['patient_id'][:3]), ('New Person', 'new.person@gmail.test', 'HK-'))
        with self.client.session_transaction() as s: self.assertEqual((s['uid'], s['role']), (u['id'], 'Patient'))
        self.assertEqual(self.client.get('/patient/home').status_code, 200)

    def test_login_with_known_google_account(self):
        self.claims = dict(sub='g-200', email='known@gmail.test', email_verified=True, name='Known')
        self.start('signup'); self.callback()
        self.client = A.app.test_client()
        self.start('login', consent=False, page='/patient/login')
        self.assertTrue(self.callback().headers['Location'].endswith('/patient/home'))

    def test_login_intent_does_not_create_accounts(self):
        self.claims = dict(sub='g-300', email='nobody@gmail.test', email_verified=True, name='Nobody')
        self.start('login', consent=False, page='/patient/login')
        self.assertTrue(self.callback().headers['Location'].endswith('/signup'))
        self.assertIsNone(self.user('nobody@gmail.test'))

    def test_existing_patient_with_same_email_gets_linked(self):
        uid, _ = make_user('link@gmail.test')
        self.claims = dict(sub='g-400', email='link@gmail.test', email_verified=True, name='Link')
        self.start('login', consent=False, page='/patient/login')
        self.assertTrue(self.callback().headers['Location'].endswith('/patient/home'))
        self.assertEqual(row('SELECT google_sub FROM users WHERE id=?', (uid,))['google_sub'], 'g-400')
        # a different Google account claiming the same email is refused once it is linked
        self.client = A.app.test_client(); self.claims['sub'] = 'g-401'
        self.start('login', consent=False, page='/patient/login')
        self.assertTrue(self.callback().headers['Location'].endswith('/patient/login'))
        with self.client.session_transaction() as s: self.assertNotIn('uid', s)

    def test_staff_email_is_refused(self):
        make_user('staffer@gmail.test', role='Optometrist', name='Doc')
        self.claims = dict(sub='g-500', email='staffer@gmail.test', email_verified=True, name='Doc')
        self.start('login', consent=False, page='/patient/login')
        self.assertTrue(self.callback().headers['Location'].endswith('/staff/login'))
        with self.client.session_transaction() as s: self.assertNotIn('uid', s)
        self.assertIsNone(row('SELECT google_sub FROM users WHERE email=?', ('staffer@gmail.test',))['google_sub'])

    def test_unverified_google_email_is_refused(self):
        self.claims = dict(sub='g-600', email='unv@gmail.test', email_verified=False, name='Unv')
        self.start('signup'); self.assertTrue(self.callback().headers['Location'].endswith('/signup'))
        self.assertIsNone(self.user('unv@gmail.test'))

    def test_existing_clinic_record_is_not_auto_claimed(self):
        sql("DELETE FROM patients WHERE email=?", ('record@gmail.test',))
        sql("INSERT INTO patients(patient_id,name,email,channel,branch_id) VALUES('HK-OLD-1','Old Record','record@gmail.test','Email',1)")
        self.claims = dict(sub='g-700', email='record@gmail.test', email_verified=True, name='Old Record')
        self.start('signup'); self.assertTrue(self.callback().headers['Location'].endswith('/signup'))
        self.assertIsNone(self.user('record@gmail.test'))
        self.assertIsNone(row('SELECT user_id FROM patients WHERE patient_id=?', ('HK-OLD-1',))['user_id'])

    def test_bad_state_error_and_failed_exchange_are_refused(self):
        self.claims = dict(sub='g-800', email='bad@gmail.test', email_verified=True, name='Bad')
        self.start('signup'); r = self.callback(state='wrong-state')
        self.assertTrue(r.headers['Location'].endswith('/signup')); self.assertIsNone(self.user('bad@gmail.test'))
        self.assertEqual(self.client.get('/auth/google/callback', query_string={'code': 'abc', 'state': self.state}).headers['Location'][-14:], '/patient/login')   # attempt is single-use
        self.start('signup'); self.assertTrue(self.callback(code='boom').headers['Location'].endswith('/signup'))
        self.assertIsNone(self.user('bad@gmail.test'))
        self.start('signup')
        r = self.client.get('/auth/google/callback', query_string={'error': 'access_denied', 'state': self.state})
        self.assertTrue(r.headers['Location'].endswith('/signup'))
        self.assertEqual(self.client.get('/auth/google/callback').status_code, 302)           # no attempt at all

    def test_nonce_mismatch_is_refused(self):
        self.claims = dict(sub='g-900', email='nonce@gmail.test', email_verified=True, name='Nonce')
        self.start('signup'); self.nonce = 'attacker-nonce'
        self.assertTrue(self.callback().headers['Location'].endswith('/signup')); self.assertIsNone(self.user('nonce@gmail.test'))

    def test_google_sign_in_still_requires_the_two_step_code(self):
        uid, pw = make_user('g2s@gmail.test')
        c = A.app.test_client(); password_login(c, 'g2s@gmail.test', pw)
        post(c, '/account/security', '/account/mfa/start')
        with c.session_transaction() as s: secret = s['mfa_setup_secret']
        post(c, '/account/security', '/account/mfa/enable', code=mfa.totp_at(secret, current_step()))
        self.claims = dict(sub='g-1000', email='g2s@gmail.test', email_verified=True, name='G2S')
        self.start('login', consent=False, page='/patient/login')
        r = self.callback(); self.assertTrue(r.headers['Location'].endswith('/mfa/verify'))
        with self.client.session_transaction() as s: self.assertNotIn('uid', s)
        r = post(self.client, '/mfa/verify', '/mfa/verify', code=mfa.totp_at(secret, current_step(1)))
        self.assertTrue(r.headers['Location'].endswith('/patient/home'))

    def test_inactive_account_cannot_sign_in_with_google(self):
        uid, _ = make_user('inactive@gmail.test'); sql("UPDATE users SET status='Inactive' WHERE id=?", (uid,))
        self.claims = dict(sub='g-1100', email='inactive@gmail.test', email_verified=True, name='In')
        self.start('login', consent=False, page='/patient/login')
        self.assertTrue(self.callback().headers['Location'].endswith('/patient/login'))
        with self.client.session_transaction() as s: self.assertNotIn('uid', s)


if __name__ == '__main__':
    unittest.main()

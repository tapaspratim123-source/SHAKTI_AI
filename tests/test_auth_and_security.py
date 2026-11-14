import subprocess
import sys
from tests.base import BaseTestCase


class TestAuthAndSecurity(BaseTestCase):
    """Tests for authentication, password hashing, rate limiting, and CSRF protection."""

    def test_registration_success_and_password_hashing(self):
        """User registration must succeed and store securely hashed passwords in SQLite."""
        email = "hash_test@example.com"
        password = "SecurePassword123!"
        res = self.register_user(name="Hash Tester", email=email, password=password)
        self.assertEqual(res.status_code, 200)

        conn = self.get_db()
        user = conn.execute("SELECT name, email, password FROM users WHERE email = ?", (email,)).fetchone()
        conn.close()

        self.assertIsNotNone(user, "User was not saved to database")
        self.assertEqual(user["name"], "Hash Tester")
        self.assertEqual(user["email"], email)
        # Password must NOT be plaintext
        self.assertNotEqual(user["password"], password)
        self.assertTrue(user["password"].startswith("scrypt:") or user["password"].startswith("pbkdf2:"))

    def test_registration_validation_empty_fields(self):
        """Registration must reject empty fields."""
        page = self.client.get("/register")
        token = self.get_csrf_token(page)

        res = self.client.post("/register", data={
            "csrf_token": token,
            "name": "   ",
            "email": "empty@example.com",
            "password": "Password123!"
        }, follow_redirects=True)
        self.assertIn("Please fill in all fields", res.get_data(as_text=True))

    def test_registration_validation_name_length(self):
        """Registration must reject names longer than 100 characters."""
        page = self.client.get("/register")
        token = self.get_csrf_token(page)

        long_name = "A" * 105
        res = self.client.post("/register", data={
            "csrf_token": token,
            "name": long_name,
            "email": "longname@example.com",
            "password": "Password123!"
        }, follow_redirects=True)
        self.assertIn("Name must not exceed 100 characters", res.get_data(as_text=True))

    def test_registration_validation_email_format(self):
        """Registration must reject invalid email formats."""
        page = self.client.get("/register")
        token = self.get_csrf_token(page)

        invalid_emails = ["notanemail", "user@", "@domain.com", "user@domain", "user space@domain.com"]
        for bad_email in invalid_emails:
            with self.subTest(email=bad_email):
                res = self.client.post("/register", data={
                    "csrf_token": token,
                    "name": "Bad Email Tester",
                    "email": bad_email,
                    "password": "Password123!"
                }, follow_redirects=True)
                self.assertIn("Please enter a valid email address", res.get_data(as_text=True))

    def test_registration_validation_password_length(self):
        """Registration must reject passwords shorter than 8 characters."""
        page = self.client.get("/register")
        token = self.get_csrf_token(page)

        res = self.client.post("/register", data={
            "csrf_token": token,
            "name": "Short Pass Tester",
            "email": "shortpass@example.com",
            "password": "short"
        }, follow_redirects=True)
        self.assertIn("Password must contain at least 8 characters", res.get_data(as_text=True))

    def test_registration_duplicate_email(self):
        """Registration must reject duplicate email addresses."""
        email = "dup_test@example.com"
        self.register_user(name="First User", email=email, password="Password123!")

        # Attempt to register again with same email
        page = self.client.get("/register")
        token = self.get_csrf_token(page)
        res = self.client.post("/register", data={
            "csrf_token": token,
            "name": "Second User",
            "email": email,
            "password": "Password123!"
        }, follow_redirects=True)
        self.assertIn("This email is already registered", res.get_data(as_text=True))

    def test_login_success(self):
        """Valid credentials must log the user in and set session state."""
        email = "login_success@example.com"
        password = "Password123!"
        self.register_user(name="Login User", email=email, password=password)

        res = self.login_user(email=email, password=password)
        self.assertEqual(res.status_code, 200)

        with self.client.session_transaction() as sess:
            self.assertIn("user_id", sess)
            self.assertEqual(sess.get("user_name"), "Login User")

    def test_login_invalid_credentials_identical_message(self):
        """Incorrect passwords and nonexistent emails must produce identical error messages."""
        email = "real_user@example.com"
        password = "Password123!"
        self.register_user(name="Real User", email=email, password=password)

        # 1. Wrong password
        res_wrong_pw = self.login_user(email=email, password="WrongPassword999!")
        html_wrong_pw = res_wrong_pw.get_data(as_text=True)

        # 2. Non-existent email
        res_no_user = self.login_user(email="nonexistent@example.com", password="Password123!")
        html_no_user = res_no_user.get_data(as_text=True)

        # Both should warn invalid email or password without revealing which was wrong
        self.assertIn("Invalid email or password", html_wrong_pw)
        self.assertIn("Invalid email or password", html_no_user)

    def test_login_rate_limiting(self):
        """Failed login attempts must be rate limited after 5 failures in 5 minutes."""
        email = "brute_target@example.com"
        self.register_user(name="Target User", email=email, password="CorrectPassword123!")

        page = self.client.get("/login")
        token = self.get_csrf_token(page)

        # 5 failed attempts
        for attempt in range(5):
            res = self.client.post("/login", data={
                "csrf_token": token,
                "email": email,
                "password": "BadPassword!"
            }, follow_redirects=True)
            self.assertIn("Invalid email or password", res.get_data(as_text=True))

        # 6th attempt must trigger rate limiter
        res_blocked = self.client.post("/login", data={
            "csrf_token": token,
            "email": email,
            "password": "BadPassword!"
        }, follow_redirects=True)
        self.assertIn("Too many failed login attempts", res_blocked.get_data(as_text=True))

    def test_logout(self):
        """Logout must terminate user session and redirect to home."""
        email = "logout_test@example.com"
        self.register_user(name="Logout User", email=email, password="Password123!")
        self.login_user(email=email, password="Password123!")

        res = self.client.get("/logout", follow_redirects=True)
        self.assertEqual(res.status_code, 200)

        with self.client.session_transaction() as sess:
            self.assertNotIn("user_id", sess)

    def test_csrf_form_rejection(self):
        """Forms submitted without a CSRF token or with an invalid token must return HTTP 400."""
        # 1. Missing token
        res_no_token = self.client.post("/register", data={
            "name": "Attacker",
            "email": "attacker@example.com",
            "password": "Password123!"
        })
        self.assertEqual(res_no_token.status_code, 400)

        # 2. Invalid token
        res_bad_token = self.client.post("/register", data={
            "csrf_token": "malicious-fake-csrf-token",
            "name": "Attacker",
            "email": "attacker@example.com",
            "password": "Password123!"
        })
        self.assertEqual(res_bad_token.status_code, 400)

    def test_csrf_json_api_rejection(self):
        """JSON API endpoints must reject requests without the X-CSRFToken header with HTTP 400."""
        # Register and login to pass auth check first
        email = "csrf_api@example.com"
        self.create_and_login_user(name="CSRF Tester", email=email, password="Password123!")

        # 1. /api/sos/prepare without CSRF header
        res_sos = self.client.post("/api/sos/prepare", json={
            "latitude": 28.6139,
            "longitude": 77.2090,
            "accuracy": 10.0
        })
        self.assertEqual(res_sos.status_code, 400)
        self.assertIn("CSRF", res_sos.get_json().get("error", ""))

        # 2. /api/safety_assistant/analyze without CSRF header
        res_ai = self.client.post("/api/safety_assistant/analyze", json={
            "situation": "Testing CSRF rejection on assistant endpoint."
        })
        self.assertEqual(res_ai.status_code, 400)

    def test_production_secret_key_validation(self):
        """Production environment must refuse to boot without an explicit SECRET_KEY."""
        script = """
import os
os.environ['RENDER'] = 'true'
if 'SECRET_KEY' in os.environ:
    del os.environ['SECRET_KEY']
import app
"""
        proc = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("CRITICAL SECURITY CONFIGURATION ERROR: The SECRET_KEY environment variable is not set", proc.stderr)

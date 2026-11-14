import os
import re
import sys
import tempfile
import unittest
import sqlite3

# Ensure repository root is on sys.path
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

# Set test environment secret key if not already present
if "SECRET_KEY" not in os.environ:
    os.environ["SECRET_KEY"] = "shakti-test-secret-key-32bytes-secure!"

import app as shakti_app


class BaseTestCase(unittest.TestCase):
    """Base test case managing an isolated temporary database for each test class."""

    @classmethod
    def setUpClass(cls):
        # Create a unique temporary directory and database for the test suite
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.test_db = os.path.join(cls.temp_dir.name, "shakti_test.db")
        shakti_app.DATABASE = cls.test_db
        shakti_app.create_table()
        cls.app = shakti_app.app
        cls.app.config["TESTING"] = True
        cls.app.config["WTF_CSRF_ENABLED"] = True

    @classmethod
    def tearDownClass(cls):
        try:
            cls.temp_dir.cleanup()
        except Exception:
            pass

    def setUp(self):
        self.client = self.app.test_client()
        # Reset the in-memory login rate limiter attempts between individual tests
        if hasattr(shakti_app, "login_limiter"):
            with shakti_app.login_limiter._lock:
                shakti_app.login_limiter._failures.clear()

    def get_csrf_token(self, response):
        """Extract CSRF token from either a meta tag or a hidden form input in HTML."""
        html = response.get_data(as_text=True)
        m = re.search(r'<meta\s+name=["\']csrf-token["\']\s+content=["\']([^"\']+)["\']', html)
        if m:
            return m.group(1)
        m = re.search(r'<input[^>]+name=["\']csrf_token["\'][^>]+value=["\']([^"\']+)["\']', html)
        if m:
            return m.group(1)
        return None

    def register_user(self, name="Test User", email="test@example.com", password="Password123!"):
        """Helper to register a user via the registration route."""
        reg_page = self.client.get("/register")
        token = self.get_csrf_token(reg_page)
        return self.client.post("/register", data={
            "csrf_token": token,
            "name": name,
            "email": email,
            "password": password
        }, follow_redirects=True)

    def login_user(self, email="test@example.com", password="Password123!"):
        """Helper to log in a user via the login route."""
        login_page = self.client.get("/login")
        token = self.get_csrf_token(login_page)
        return self.client.post("/login", data={
            "csrf_token": token,
            "email": email,
            "password": password
        }, follow_redirects=True)

    def create_and_login_user(self, name="Test User", email="test@example.com", password="Password123!"):
        """Helper to register and immediately log in a user."""
        self.register_user(name=name, email=email, password=password)
        return self.login_user(email=email, password=password)

    def get_db(self):
        """Open a direct SQLite connection to the isolated test database."""
        conn = sqlite3.connect(self.test_db)
        conn.row_factory = sqlite3.Row
        return conn

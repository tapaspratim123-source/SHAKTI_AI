from tests.base import BaseTestCase


class TestStartupAndRoutes(BaseTestCase):
    """Tests for application startup, homepage rendering, and protected route access."""

    def test_homepage_status_and_content(self):
        """Homepage must render with HTTP 200 and include all verified feature cards."""
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        html = res.get_data(as_text=True)

        # Core branding & headings
        self.assertIn("SHAKTI", html)
        self.assertIn("Her Safety", html)

        # Feature cards & status badges
        self.assertIn("SOS History", html)
        self.assertIn("VoiceGuard", html)
        self.assertIn("SafeCircle", html)
        self.assertIn("Journey Guardian", html)
        self.assertIn("AI Safety Assistant", html)
        self.assertIn("Safety Map", html)
        self.assertIn("Available Now", html)
        self.assertIn("Interactive Demo", html)
        self.assertIn("Coming Soon", html)

        # Footer credit
        self.assertIn("Empowering Women. Building a Safer Tomorrow.", html)
        self.assertIn("Tapas Pratim Daloi", html)
        self.assertIn("© 2026 SHAKTI AI. All Rights Reserved.", html)

        # No unintended Markdown fences
        self.assertNotIn("```", html)

    def test_unauthenticated_access_restrictions(self):
        """Unauthenticated requests to protected routes must redirect to the login page."""
        protected_routes = [
            "/dashboard",
            "/safecircle",
            "/voiceguard",
            "/journey_guardian",
            "/ai_safety_assistant",
            "/profile",
            "/change_password",
            "/sos_history"
        ]
        for route in protected_routes:
            with self.subTest(route=route):
                res = self.client.get(route)
                self.assertEqual(res.status_code, 302, f"Route {route} did not redirect unauthenticated user")
                self.assertIn("/login", res.headers.get("Location", ""))

    def test_dashboard_authenticated(self):
        """Dashboard must render for logged-in users and display their name."""
        user_name = "Dashboard Tester"
        user_email = "dash_tester@example.com"
        self.create_and_login_user(name=user_name, email=user_email, password="Password123!")

        res = self.client.get("/dashboard")
        self.assertEqual(res.status_code, 200)
        html = res.get_data(as_text=True)
        self.assertIn(user_name, html)
        self.assertIn("SafeCircle", html)
        self.assertIn("VoiceGuard", html)
        self.assertIn("Journey Guardian", html)
        self.assertIn("AI Safety Assistant", html)

    def test_journey_guardian_authenticated(self):
        """Journey Guardian route must render when authenticated."""
        self.create_and_login_user(name="JG Tester", email="jg_tester@example.com", password="Password123!")
        res = self.client.get("/journey_guardian")
        self.assertEqual(res.status_code, 200)
        html = res.get_data(as_text=True)
        self.assertIn("Journey Guardian", html)
        self.assertIn("destination", html.lower())

    def test_voiceguard_authenticated(self):
        """VoiceGuard route must render when authenticated and show emergency 112 hotline."""
        self.create_and_login_user(name="VG Tester", email="vg_tester@example.com", password="Password123!")
        res = self.client.get("/voiceguard")
        self.assertEqual(res.status_code, 200)
        html = res.get_data(as_text=True)
        self.assertIn("VoiceGuard", html)
        self.assertIn("112", html)

    def test_ai_safety_assistant_authenticated(self):
        """AI Safety Assistant route must render when authenticated."""
        self.create_and_login_user(name="AI Tester", email="ai_tester@example.com", password="Password123!")
        res = self.client.get("/ai_safety_assistant")
        self.assertEqual(res.status_code, 200)
        html = res.get_data(as_text=True)
        self.assertIn("AI Safety Assistant", html)
        self.assertIn("situationInput", html)

    def test_profile_and_change_password_pages_render(self):
        """Profile and change password pages must render when authenticated."""
        self.create_and_login_user(name="Profile Tester", email="prof_tester@example.com", password="Password123!")
        
        prof_res = self.client.get("/profile")
        self.assertEqual(prof_res.status_code, 200)
        self.assertIn("prof_tester@example.com", prof_res.get_data(as_text=True))

        cp_res = self.client.get("/change_password")
        self.assertEqual(cp_res.status_code, 200)
        self.assertIn("Change Password", cp_res.get_data(as_text=True))

from tests.base import BaseTestCase


class TestAISafetyAssistant(BaseTestCase):
    """Tests for the AI Safety Assistant input validation, error handling, and security."""

    def test_ai_safety_unauthenticated_blocked(self):
        """Unauthenticated requests to analyze endpoint must be blocked with HTTP 401."""
        page = self.client.get("/login")
        token = self.get_csrf_token(page)

        res = self.client.post("/api/safety_assistant/analyze", json={
            "situation": "Someone is following me at night on a dark street."
        }, headers={"X-CSRFToken": token})

        self.assertEqual(res.status_code, 401)
        data = res.get_json()
        self.assertIsNotNone(data)
        self.assertTrue(data.get("login_required"))

    def test_ai_safety_validation_empty_situation(self):
        """Analyze API must reject empty or whitespace-only situation descriptions."""
        self.create_and_login_user(name="AI User 1", email="ai_val1@example.com", password="Password123!")

        page = self.client.get("/ai_safety_assistant")
        token = self.get_csrf_token(page)

        # 1. Empty string
        res_empty = self.client.post("/api/safety_assistant/analyze", json={
            "situation": ""
        }, headers={"X-CSRFToken": token})
        self.assertEqual(res_empty.status_code, 400)
        self.assertIn("describe your safety situation", res_empty.get_json().get("error", "").lower())

        # 2. Whitespace only
        res_spaces = self.client.post("/api/safety_assistant/analyze", json={
            "situation": "       "
        }, headers={"X-CSRFToken": token})
        self.assertEqual(res_spaces.status_code, 400)

    def test_ai_safety_validation_minimum_length(self):
        """Analyze API must require at least 10 characters of description."""
        self.create_and_login_user(name="AI User 2", email="ai_val2@example.com", password="Password123!")

        page = self.client.get("/ai_safety_assistant")
        token = self.get_csrf_token(page)

        res_short = self.client.post("/api/safety_assistant/analyze", json={
            "situation": "Help me"
        }, headers={"X-CSRFToken": token})
        self.assertEqual(res_short.status_code, 400)
        self.assertIn("at least 10 characters", res_short.get_json().get("error", "").lower())

    def test_ai_safety_validation_maximum_length(self):
        """Analyze API must reject situations exceeding 2,000 characters."""
        self.create_and_login_user(name="AI User 3", email="ai_val3@example.com", password="Password123!")

        page = self.client.get("/ai_safety_assistant")
        token = self.get_csrf_token(page)

        too_long = "Dangerous situation details. " * 80  # > 2,000 chars
        res_long = self.client.post("/api/safety_assistant/analyze", json={
            "situation": too_long
        }, headers={"X-CSRFToken": token})
        self.assertEqual(res_long.status_code, 400)
        self.assertIn("maximum 2,000 characters", res_long.get_json().get("error", "").lower())

    def test_ai_safety_unconfigured_api_key_handled_gracefully(self):
        """When GEMINI_API_KEY is not configured in the test environment, API must return a safe fallback."""
        self.create_and_login_user(name="AI User 4", email="ai_val4@example.com", password="Password123!")

        page = self.client.get("/ai_safety_assistant")
        token = self.get_csrf_token(page)

        valid_situation = "I am walking home alone from college and someone seems to be following me on a dark street."
        res = self.client.post("/api/safety_assistant/analyze", json={
            "situation": valid_situation
        }, headers={"X-CSRFToken": token})

        # Expect structured safe fallback response (HTTP 200, is_fallback=True)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIsNotNone(data, "API must return valid JSON response even when unconfigured")
        self.assertTrue(data.get("success"))
        self.assertTrue(data.get("is_fallback"))

        analysis = data.get("analysis", {})
        self.assertIn("situation_summary", analysis)
        self.assertIn("recommended_actions", analysis)
        self.assertIn("limitations_and_uncertainty", analysis)

    def test_ai_safety_fallback_guidance_content(self):
        """Fallback response must encourage moving to safety, contacting trusted people, and display helplines."""
        self.create_and_login_user(name="AI User 5", email="ai_val5@example.com", password="Password123!")

        page = self.client.get("/ai_safety_assistant")
        token = self.get_csrf_token(page)

        res = self.client.post("/api/safety_assistant/analyze", json={
            "situation": "Walking alone at night and feeling uncomfortable."
        }, headers={"X-CSRFToken": token})

        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        analysis = data.get("analysis", {})
        actions = " ".join(analysis.get("recommended_actions", []))
        limitations = analysis.get("limitations_and_uncertainty", "")

        # 1. Moving to safer public place
        self.assertTrue(any(term in actions.lower() for term in ["safer", "public", "well-lit", "secure"]))

        # 2. Contacting trusted people
        self.assertTrue(any(term in actions.lower() for term in ["trusted contact", "trusted", "family", "friend"]))

        # 3. Emergency helplines (112, 1091, 181)
        self.assertIn("112", actions)
        self.assertTrue("1091" in actions or "181" in actions)

        # 4. Avoid claiming SHAKTI AI contacts police or sends real SMS
        self.assertIn("does not automatically contact police", limitations.lower())
        self.assertIn("real sms", limitations.lower())

        # 5. Clearly state general guidance, not a substitute for emergency services
        self.assertIn("not a substitute for professional", limitations.lower())

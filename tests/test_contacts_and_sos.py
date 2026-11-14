from tests.base import BaseTestCase


class TestContactsAndSOS(BaseTestCase):
    """Tests for SafeCircle trusted contacts management and SOS emergency operations."""

    def test_safecircle_crud_operations(self):
        """User must be able to add, read, edit, and delete trusted contacts."""
        email = "sc_crud@example.com"
        self.create_and_login_user(name="SC User", email=email, password="Password123!")

        # 1. Add contact
        page = self.client.get("/safecircle")
        token = self.get_csrf_token(page)
        res_add = self.client.post("/add_contact", data={
            "csrf_token": token,
            "name": "Jane Guardian",
            "phone": "9876543210",
            "relationship": "Sister"
        }, follow_redirects=True)
        self.assertEqual(res_add.status_code, 200)

        conn = self.get_db()
        contact = conn.execute("SELECT id, name, phone, relationship FROM contacts WHERE name = 'Jane Guardian'").fetchone()
        conn.close()
        self.assertIsNotNone(contact, "Contact was not found in database")
        contact_id = contact["id"]

        # 2. View in safecircle list
        list_res = self.client.get("/safecircle")
        self.assertIn("Jane Guardian", list_res.get_data(as_text=True))
        self.assertIn("9876543210", list_res.get_data(as_text=True))

        # 3. Edit contact
        edit_page = self.client.get(f"/edit_contact/{contact_id}")
        self.assertEqual(edit_page.status_code, 200)
        edit_token = self.get_csrf_token(edit_page)

        res_edit = self.client.post(f"/edit_contact/{contact_id}", data={
            "csrf_token": edit_token,
            "name": "Jane Guardian Updated",
            "phone": "9998887776",
            "relationship": "Mother"
        }, follow_redirects=True)
        self.assertEqual(res_edit.status_code, 200)

        conn = self.get_db()
        updated = conn.execute("SELECT name, phone, relationship FROM contacts WHERE id = ?", (contact_id,)).fetchone()
        conn.close()
        self.assertEqual(updated["name"], "Jane Guardian Updated")
        self.assertEqual(updated["phone"], "9998887776")

        # 4. Delete contact
        sc_page = self.client.get("/safecircle")
        sc_token = self.get_csrf_token(sc_page)
        res_del = self.client.post(f"/delete_contact/{contact_id}", data={
            "csrf_token": sc_token
        }, follow_redirects=True)
        self.assertEqual(res_del.status_code, 200)

        conn = self.get_db()
        deleted = conn.execute("SELECT id FROM contacts WHERE id = ?", (contact_id,)).fetchone()
        conn.close()
        self.assertIsNone(deleted, "Contact was not deleted from database")

    def test_safecircle_validation_empty_fields(self):
        """SafeCircle must reject contacts with empty name or phone number."""
        email = "sc_val@example.com"
        self.create_and_login_user(name="Val User", email=email, password="Password123!")

        page = self.client.get("/safecircle")
        token = self.get_csrf_token(page)

        res = self.client.post("/add_contact", data={
            "csrf_token": token,
            "name": "",
            "phone": "9876543210",
            "relationship": "Friend"
        }, follow_redirects=True)
        self.assertIn("Name and phone number are required", res.get_data(as_text=True))

    def test_safecircle_access_control(self):
        """A user must not be able to edit or delete another user's contacts."""
        # User A creates a contact
        self.create_and_login_user(name="User A", email="user_a@example.com", password="Password123!")
        page_a = self.client.get("/safecircle")
        token_a = self.get_csrf_token(page_a)
        self.client.post("/add_contact", data={
            "csrf_token": token_a,
            "name": "User A Private Contact",
            "phone": "9111111111",
            "relationship": "Friend"
        }, follow_redirects=True)

        conn = self.get_db()
        contact = conn.execute("SELECT id FROM contacts WHERE name = 'User A Private Contact'").fetchone()
        conn.close()
        self.assertIsNotNone(contact, "Contact for User A was not created")
        contact_id = contact["id"]

        # User B logs in
        self.client.get("/logout")
        self.create_and_login_user(name="User B", email="user_b@example.com", password="Password123!")
        page_b = self.client.get("/safecircle")
        token_b = self.get_csrf_token(page_b)

        # User B attempts to edit User A's contact
        res_edit = self.client.get(f"/edit_contact/{contact_id}", follow_redirects=True)
        self.assertIn("Contact not found", res_edit.get_data(as_text=True))

        # User B attempts to delete User A's contact
        res_del = self.client.post(f"/delete_contact/{contact_id}", data={
            "csrf_token": token_b
        }, follow_redirects=True)
        self.assertEqual(res_del.status_code, 200)

        # Verify contact still exists in DB (User B could not delete User A's contact)
        conn = self.get_db()
        check = conn.execute("SELECT id FROM contacts WHERE id = ?", (contact_id,)).fetchone()
        conn.close()
        self.assertIsNotNone(check, "Unauthorized user was able to delete another user's contact")

    def test_sos_prepare_with_valid_coordinates(self):
        """SOS prepare API must process valid coordinates, simulate SMS, and record history."""
        email = "sos_valid@example.com"
        self.create_and_login_user(name="SOS User", email=email, password="Password123!")

        # Add a contact first
        sc_page = self.client.get("/safecircle")
        sc_token = self.get_csrf_token(sc_page)
        self.client.post("/add_contact", data={
            "csrf_token": sc_token,
            "name": "Trusted Parent",
            "phone": "9876543210",
            "relationship": "Parent"
        }, follow_redirects=True)

        # Trigger SOS prepare via API with valid coordinates
        vg_page = self.client.get("/voiceguard")
        vg_token = self.get_csrf_token(vg_page)

        res = self.client.post("/api/sos/prepare", json={
            "latitude": 28.6139,
            "longitude": 77.2090,
            "accuracy": 15.0
        }, headers={"X-CSRFToken": vg_token})

        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("success"))
        self.assertEqual(data.get("contact_count"), 1)
        self.assertEqual(data.get("successful_count"), 1)
        self.assertEqual(data.get("failed_count"), 0)
        self.assertIn("https://www.google.com/maps", data.get("map_url", ""))
        self.assertEqual(data.get("user_name"), "SOS User")

        # Verify record inserted into sos_history table
        conn = self.get_db()
        history = conn.execute(
            "SELECT latitude, longitude, accuracy, notification_status FROM sos_history WHERE latitude = 28.6139"
        ).fetchone()
        conn.close()

        self.assertIsNotNone(history)
        self.assertIn("SIMULATED SUCCESS", history["notification_status"])

    def test_sos_prepare_coordinate_validation(self):
        """SOS prepare API must reject invalid or out-of-range coordinates."""
        email = "sos_coords@example.com"
        self.create_and_login_user(name="Coord Tester", email=email, password="Password123!")

        page = self.client.get("/voiceguard")
        token = self.get_csrf_token(page)

        # Non-numeric coordinate
        res_str = self.client.post("/api/sos/prepare", json={
            "latitude": "invalid_latitude",
            "longitude": 77.2090
        }, headers={"X-CSRFToken": token})
        self.assertEqual(res_str.status_code, 400)

        # Missing coordinate
        res_missing = self.client.post("/api/sos/prepare", json={
            "latitude": 28.6139
        }, headers={"X-CSRFToken": token})
        self.assertEqual(res_missing.status_code, 400)

        # Out-of-bounds latitude (> 90)
        res_bounds = self.client.post("/api/sos/prepare", json={
            "latitude": 125.0,
            "longitude": 77.0
        }, headers={"X-CSRFToken": token})
        self.assertEqual(res_bounds.status_code, 400)

    def test_sos_prepare_no_contacts_returns_404(self):
        """SOS prepare API must return 404 when user has zero trusted contacts."""
        email = "no_contacts@example.com"
        self.create_and_login_user(name="No Contact User", email=email, password="Password123!")

        page = self.client.get("/voiceguard")
        token = self.get_csrf_token(page)

        res = self.client.post("/api/sos/prepare", json={
            "latitude": 28.6139,
            "longitude": 77.2090,
            "accuracy": 10.0
        }, headers={"X-CSRFToken": token})

        self.assertEqual(res.status_code, 404)
        data = res.get_json()
        self.assertFalse(data.get("success"))
        self.assertIn("No trusted contacts found", data.get("message", ""))

    def test_sos_history_table_and_actions(self):
        """SOS History page must render previous activations, permit single delete and clear all."""
        email = "history_tester@example.com"
        self.create_and_login_user(name="Hist User", email=email, password="Password123!")

        # Add contact & trigger SOS
        sc_page = self.client.get("/safecircle")
        sc_token = self.get_csrf_token(sc_page)
        self.client.post("/add_contact", data={
            "csrf_token": sc_token,
            "name": "Friend Contact",
            "phone": "9876543210",
            "relationship": "Friend"
        }, follow_redirects=True)

        vg_page = self.client.get("/voiceguard")
        vg_token = self.get_csrf_token(vg_page)
        self.client.post("/api/sos/prepare", json={
            "latitude": 19.0760,
            "longitude": 72.8777,
            "accuracy": 10.0
        }, headers={"X-CSRFToken": vg_token})

        # View SOS history page
        hist_page = self.client.get("/sos_history")
        self.assertEqual(hist_page.status_code, 200)
        html = hist_page.get_data(as_text=True)
        self.assertIn("Previous SOS Records", html)
        self.assertIn("SIMULATED SUCCESS", html)
        token = self.get_csrf_token(hist_page)

        # Query record ID
        conn = self.get_db()
        rec = conn.execute("SELECT id FROM sos_history WHERE latitude = 19.0760").fetchone()
        conn.close()
        self.assertIsNotNone(rec)
        rec_id = rec["id"]

        # Delete single SOS record
        del_res = self.client.post(f"/delete_sos/{rec_id}", data={
            "csrf_token": token
        }, follow_redirects=True)
        self.assertEqual(del_res.status_code, 200)

        conn = self.get_db()
        check = conn.execute("SELECT id FROM sos_history WHERE id = ?", (rec_id,)).fetchone()
        conn.close()
        self.assertIsNone(check, "Record was not deleted from database")

        # Insert 2 records and test Clear All
        conn = self.get_db()
        with self.client.session_transaction() as sess:
            uid = sess["user_id"]
        conn.execute(
            "INSERT INTO sos_history (user_id, latitude, longitude, accuracy, total_contacts, successful_count, failed_count, notification_status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (uid, 1.0, 1.0, 5.0, 1, 1, 0, "DEMO - SIMULATED SUCCESS")
        )
        conn.execute(
            "INSERT INTO sos_history (user_id, latitude, longitude, accuracy, total_contacts, successful_count, failed_count, notification_status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (uid, 2.0, 2.0, 5.0, 1, 1, 0, "DEMO - SIMULATED SUCCESS")
        )
        conn.commit()
        conn.close()

        hist_page2 = self.client.get("/sos_history")
        token2 = self.get_csrf_token(hist_page2)

        clear_res = self.client.post("/clear_sos_history", data={
            "csrf_token": token2
        }, follow_redirects=True)
        self.assertEqual(clear_res.status_code, 200)

        conn = self.get_db()
        count = conn.execute("SELECT COUNT(*) as cnt FROM sos_history WHERE user_id = ?", (uid,)).fetchone()["cnt"]
        conn.close()
        self.assertEqual(count, 0, "All SOS history records should have been cleared")

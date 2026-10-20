import os
import re
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

_test_storage = tempfile.TemporaryDirectory()
os.environ["DATABASE_PATH"] = os.path.join(_test_storage.name, "test.db")
os.environ["SIGNUP_INVITE_CODE"] = "test-invite-code-long-enough"
os.environ["DISABLE_SCHEDULER"] = "1"
os.environ.setdefault("SECRET_KEY", "test-secret-key-that-is-long-enough")

import app as session_monitor
from app import app, validate_public_url


class PublicUrlValidationTests(unittest.TestCase):
    def test_rejects_local_and_non_http_urls(self):
        for url in (
            "http://localhost/",
            "http://127.0.0.1/",
            "http://192.168.1.1/",
            "file:///etc/passwd",
            "https://user:password@example.com/",
            "https://example.com:8443/",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                validate_public_url(url)

    @patch("app.socket.getaddrinfo")
    def test_accepts_public_http_url(self, getaddrinfo):
        getaddrinfo.return_value = [
            (2, 1, 6, "", ("93.184.216.34", 0))
        ]
        self.assertEqual(
            validate_public_url("https://example.com/path"),
            "https://example.com/path",
        )

    @patch("app.socket.getaddrinfo")
    def test_rejects_host_resolving_to_private_address(self, getaddrinfo):
        getaddrinfo.return_value = [
            (2, 1, 6, "", ("10.0.0.5", 0))
        ]
        with self.assertRaisesRegex(ValueError, "public IP"):
            validate_public_url("https://internal.example/")


class DashboardAccessTests(unittest.TestCase):
    def setUp(self):
        app.config.update(TESTING=True, SECRET_KEY="test-secret-key")
        with session_monitor._connect_db() as connection:
            connection.execute("DELETE FROM visits")
            connection.execute("DELETE FROM jobs")
            connection.execute("DELETE FROM users")
        self.client = app.test_client()
        self.client.environ_base["HTTP_ORIGIN"] = "https://localhost"

    def _signup(self, client, email, password="correct-horse-battery-staple"):
        signup_page = client.get("/signup")
        self.assertEqual(signup_page.status_code, 200)
        csrf_token = self._csrf_from_response(signup_page)
        return client.post(
            "/signup",
            data={
                "csrf_token": csrf_token,
                "email": email,
                "password": password,
                "invite_code": os.environ["SIGNUP_INVITE_CODE"],
            },
        )

    def _csrf_from_response(self, response):
        match = re.search(
            r'name="csrf_token" value="([^"]+)"',
            response.get_data(as_text=True),
        )
        self.assertIsNotNone(match, "The page should render a CSRF token.")
        return match.group(1)

    def test_health_endpoint_is_public(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")

    def test_dashboard_requires_login(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])

    def test_signup_requires_invite_and_valid_password(self):
        signup_page = self.client.get("/signup")
        csrf_token = self._csrf_from_response(signup_page)
        response = self.client.post(
            "/signup",
            data={
                "csrf_token": csrf_token,
                "email": "new@example.com",
                "password": "correct-horse-battery-staple",
                "invite_code": "incorrect",
            },
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"invite code is invalid", response.data)

        response = self._signup(self.client, "new@example.com", "short")
        self.assertEqual(response.status_code, 400)

    def test_signup_is_disabled_without_a_strong_invite_code(self):
        signup_page = self.client.get("/signup")
        with patch.dict(os.environ, {"SIGNUP_INVITE_CODE": "short"}):
            response = self.client.post(
                "/signup",
                data={
                    "csrf_token": self._csrf_from_response(signup_page),
                    "email": "new@example.com",
                    "password": "correct-horse-battery-staple",
                    "invite_code": "short",
                },
            )
        self.assertEqual(response.status_code, 503)

    def test_signup_creates_account_and_dashboard(self):
        response = self._signup(self.client, "Person@Example.com")
        self.assertEqual(response.status_code, 302)
        dashboard = self.client.get("/")
        self.assertEqual(dashboard.status_code, 200)
        self.assertIn(b"57 times per cycle", dashboard.data)
        self.assertIn(b"person@example.com", dashboard.data)

    def test_signup_csrf_token_does_not_depend_on_session_cookie(self):
        signup_page = self.client.get("/signup")
        csrf_token = self._csrf_from_response(signup_page)
        fresh_client = app.test_client()
        fresh_client.environ_base["HTTP_ORIGIN"] = "https://localhost"
        response = fresh_client.post(
            "/signup",
            data={
                "csrf_token": csrf_token,
                "email": "fresh@example.com",
                "password": "correct-horse-battery-staple",
                "invite_code": os.environ["SIGNUP_INVITE_CODE"],
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(fresh_client.get("/").status_code, 200)

    def test_login_and_logout(self):
        self._signup(self.client, "person@example.com")
        dashboard = self.client.get("/")
        self.client.post(
            "/logout",
            data={"csrf_token": self._csrf_from_response(dashboard)},
        )
        login_page = self.client.get("/login")
        self.assertEqual(login_page.status_code, 200)
        csrf_token = self._csrf_from_response(login_page)
        response = self.client.post(
            "/login",
            data={
                "csrf_token": csrf_token,
                "email": "PERSON@example.com",
                "password": "correct-horse-battery-staple",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.client.get("/").status_code, 200)

    @patch("app.validate_public_url", return_value="https://example.com/")
    def test_job_keeps_running_after_logout_and_is_private_to_account(self, _validate):
        self._signup(self.client, "first@example.com")
        csrf_token = self._csrf_from_response(self.client.get("/"))
        response = self.client.post(
            "/api/start",
            json={"target_url": "https://example.com/"},
            headers={"X-CSRF-Token": csrf_token},
        )
        self.assertEqual(response.status_code, 202)
        self.client.post("/logout", data={"csrf_token": csrf_token})

        other = app.test_client()
        other.environ_base["HTTP_ORIGIN"] = "https://localhost"
        self._signup(other, "second@example.com")
        other_status = other.get("/api/status").get_json()
        self.assertFalse(other_status["active"])
        self.assertIsNone(other_status["target_url"])

        login_page = self.client.get("/login")
        self.client.post(
            "/login",
            data={
                "csrf_token": self._csrf_from_response(login_page),
                "email": "first@example.com",
                "password": "correct-horse-battery-staple",
            },
        )
        owner_status = self.client.get("/api/status").get_json()
        self.assertTrue(owner_status["active"])
        self.assertEqual(owner_status["target_url"], "https://example.com/")

    def test_start_rejects_private_target(self):
        self._signup(self.client, "person@example.com")
        csrf_token = self._csrf_from_response(self.client.get("/"))
        response = self.client.post(
            "/api/start",
            json={"target_url": "http://127.0.0.1/"},
            headers={"X-CSRF-Token": csrf_token},
        )
        self.assertEqual(response.status_code, 400)

    @patch("app.validate_public_url", return_value="https://example.com/")
    def test_stop_only_stops_the_signed_in_users_job(self, _validate):
        self._signup(self.client, "first@example.com")
        csrf_token = self._csrf_from_response(self.client.get("/"))
        self.client.post(
            "/api/start",
            json={"target_url": "https://example.com/"},
            headers={"X-CSRF-Token": csrf_token},
        )
        response = self.client.post(
            "/api/stop",
            json={},
            headers={"X-CSRF-Token": csrf_token},
        )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(self.client.get("/api/status").get_json()["active"])

    @patch("app.validate_public_url", return_value="https://example.com/")
    def test_stopped_job_is_skipped_when_already_queued(self, _validate):
        self._signup(self.client, "person@example.com")
        csrf_token = self._csrf_from_response(self.client.get("/"))
        self.client.post(
            "/api/start",
            json={"target_url": "https://example.com/"},
            headers={"X-CSRF-Token": csrf_token},
        )
        with session_monitor._connect_db() as connection:
            job = connection.execute("SELECT * FROM jobs").fetchone()
        self.client.post(
            "/api/stop",
            json={},
            headers={"X-CSRF-Token": csrf_token},
        )
        with patch("app._visit_target") as visit:
            session_monitor.process_due_job(job)
        visit.assert_not_called()

    @patch(
        "app._visit_target",
        return_value={
            "final_url": "https://example.com/",
            "page_title": "Example",
            "http_status": 200,
            "error": None,
            "started_at": "2026-10-20T00:00:00+00:00",
            "finished_at": "2026-10-20T00:00:01+00:00",
        },
    )
    def test_each_visit_is_scheduled_two_minutes_later(self, _visit):
        self._signup(self.client, "person@example.com")
        csrf_token = self._csrf_from_response(self.client.get("/"))
        self.client.post(
            "/api/start",
            json={"target_url": "https://example.com/"},
            headers={"X-CSRF-Token": csrf_token},
        )
        with session_monitor._connect_db() as connection:
            job = connection.execute("SELECT * FROM jobs").fetchone()

        before = datetime.now(timezone.utc)
        session_monitor.process_due_job(job)
        after = datetime.now(timezone.utc)

        status = self.client.get("/api/status").get_json()
        self.assertEqual(status["visit_number"], 2)
        scheduled = datetime.fromisoformat(status["next_run_at"])
        self.assertGreaterEqual(
            scheduled,
            before + timedelta(seconds=session_monitor.VISIT_INTERVAL_SECONDS),
        )
        self.assertLessEqual(
            scheduled,
            after + timedelta(seconds=session_monitor.VISIT_INTERVAL_SECONDS),
        )
        self.assertEqual(len(status["visits"]), 1)

    def test_completing_visit_57_advances_to_next_cycle(self):
        self._signup(self.client, "person@example.com")
        csrf_token = self._csrf_from_response(self.client.get("/"))
        self.client.post(
            "/api/start",
            json={"target_url": "https://example.com/"},
            headers={"X-CSRF-Token": csrf_token},
        )
        with session_monitor._connect_db() as connection:
            connection.execute(
                "UPDATE jobs SET visit_number = 57"
            )
            job = connection.execute("SELECT * FROM jobs").fetchone()

        result = {
            "final_url": "https://example.com/",
            "page_title": "Example",
            "http_status": 200,
            "error": None,
            "started_at": "2026-10-20T00:00:00+00:00",
            "finished_at": "2026-10-20T00:00:01+00:00",
        }
        with patch("app._visit_target", return_value=result):
            session_monitor.process_due_job(job)

        status = self.client.get("/api/status").get_json()
        self.assertEqual(status["visit_number"], 1)
        self.assertEqual(status["cycle_count"], 1)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hmac
import ipaddress
import os
from pathlib import Path
import re
import secrets
import socket
import sqlite3
import threading
import time
from typing import Iterator
from urllib.parse import urlsplit

from flask import (
    Flask,
    abort,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from itsdangerous import BadSignature, URLSafeTimedSerializer
from playwright.sync_api import Browser, BrowserContext, Route, sync_playwright
from werkzeug.security import check_password_hash, generate_password_hash

VISITS_PER_CYCLE = 57
VISIT_INTERVAL_SECONDS = 2 * 60
MAX_RECENT_VISITS = 50
MIN_INVITE_CODE_LENGTH = 24
DATABASE_PATH = Path(os.environ.get("DATABASE_PATH", "session_monitor.db"))

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=bool(os.environ.get("RENDER")),
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),
)

SCHEDULER_STOP = threading.Event()
SCHEDULER_THREAD: threading.Thread | None = None
SCHEDULER_START_LOCK = threading.Lock()


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def now_iso() -> str:
    return now_utc().isoformat()


@contextmanager
def _connect_db() -> Iterator[sqlite3.Connection]:
    connection = sqlite3.connect(DATABASE_PATH, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize_database() -> None:
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _connect_db() as connection:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS jobs (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
                target_url TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 0,
                cycle_count INTEGER NOT NULL DEFAULT 0,
                visit_number INTEGER NOT NULL DEFAULT 1,
                generation INTEGER NOT NULL DEFAULT 0,
                next_run_at TEXT,
                last_error TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS visits (
                id INTEGER PRIMARY KEY,
                job_id INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
                cycle_number INTEGER NOT NULL,
                visit_number INTEGER NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT NOT NULL,
                final_url TEXT,
                page_title TEXT,
                http_status INTEGER,
                error TEXT
            );
            CREATE INDEX IF NOT EXISTS visits_job_id_id
                ON visits(job_id, id DESC);
            CREATE INDEX IF NOT EXISTS jobs_active_next_run
                ON jobs(active, next_run_at);
            """
        )


def _host_resolves_publicly(hostname: str) -> bool:
    try:
        addresses = {
            ipaddress.ip_address(answer[4][0].split("%", 1)[0])
            for answer in socket.getaddrinfo(
                hostname,
                None,
                type=socket.SOCK_STREAM,
            )
        }
    except (OSError, ValueError):
        return False
    return bool(addresses) and all(address.is_global for address in addresses)


def validate_public_url(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 2048:
        raise ValueError("Enter a URL no longer than 2048 characters.")
    if any(character.isspace() or ord(character) < 32 for character in value):
        raise ValueError("The URL must not contain whitespace or control characters.")

    try:
        parsed = urlsplit(value.strip())
        port = parsed.port
    except ValueError as error:
        raise ValueError("Enter a valid public HTTP or HTTPS URL.") from error

    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 80, 443)
    ):
        raise ValueError("Only public HTTP or HTTPS URLs on ports 80 and 443 are allowed.")

    hostname = parsed.hostname.rstrip(".").lower()
    if hostname == "localhost" or hostname.endswith(
        (".localhost", ".local", ".internal")
    ):
        raise ValueError("Local and internal network addresses are not allowed.")

    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        if not _host_resolves_publicly(hostname):
            raise ValueError("The hostname must resolve only to public IP addresses.")
    else:
        if not address.is_global:
            raise ValueError("Private and reserved IP addresses are not allowed.")

    return value.strip()


def _require_csrf() -> None:
    supplied = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
    if not supplied:
        abort(400, description="Invalid or missing CSRF token.")
    origin = request.headers.get("Origin")
    if not origin:
        origin = request.headers.get("Referer")
    if not origin:
        abort(400, description="Missing request origin.")
    try:
        origin_url = urlsplit(origin)
    except ValueError:
        abort(400, description="Invalid request origin.")
    if (
        origin_url.scheme not in ("http", "https")
        or not origin_url.netloc
        or origin_url.netloc.casefold() != request.host.casefold()
    ):
        abort(400, description="Cross-origin requests are not allowed.")
    try:
        value = URLSafeTimedSerializer(
            app.config["SECRET_KEY"],
            salt="session-monitor-csrf",
        ).loads(supplied, max_age=3600)
    except BadSignature:
        abort(400, description="Invalid or expired CSRF token.")
    if (
        not isinstance(value, dict)
        or value.get("user_id") != session.get("user_id")
    ):
        abort(400, description="Invalid CSRF token.")


def _csrf_token() -> str:
    return URLSafeTimedSerializer(
        app.config["SECRET_KEY"],
        salt="session-monitor-csrf",
    ).dumps(
        {
            "nonce": secrets.token_urlsafe(32),
            "user_id": session.get("user_id"),
        }
    )


def _current_user() -> sqlite3.Row | None:
    user_id = session.get("user_id")
    if not isinstance(user_id, int):
        return None
    with _connect_db() as connection:
        return connection.execute(
            "SELECT id, email FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()


def _require_user() -> sqlite3.Row:
    user = _current_user()
    if user is None:
        abort(401)
    return user


@app.before_request
def enforce_access_control() -> None:
    if request.endpoint == "health":
        return
    if request.endpoint in ("login", "signup"):
        if request.method == "POST":
            _require_csrf()
        return
    if _current_user() is None:
        if request.path.startswith("/api/"):
            abort(401)
        return redirect(url_for("login"))
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        _require_csrf()


@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; object-src 'none'; "
        "base-uri 'self'; frame-ancestors 'none'"
    )
    return response


@app.get("/health")
def health():
    return {"status": "ok"}


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if _current_user() is not None:
        return redirect(url_for("index"))
    if request.method == "GET":
        return render_template("signup.html", csrf_token=_csrf_token(), error=None)

    configured_invite = os.environ.get("SIGNUP_INVITE_CODE", "")
    submitted_invite = request.form.get("invite_code", "")
    if len(configured_invite) < MIN_INVITE_CODE_LENGTH:
        return render_template(
            "signup.html",
            csrf_token=_csrf_token(),
            error="Invited registration is not configured. Contact the service owner.",
        ), 503
    if not submitted_invite or not hmac.compare_digest(
        submitted_invite,
        configured_invite,
    ):
        return render_template(
            "signup.html",
            csrf_token=_csrf_token(),
            error="The invite code is invalid.",
        ), 400

    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    if (
        len(email) > 254
        or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email)
    ):
        return render_template(
            "signup.html",
            csrf_token=_csrf_token(),
            error="Enter a valid email address.",
        ), 400
    if len(password) < 12 or len(password) > 128:
        return render_template(
            "signup.html",
            csrf_token=_csrf_token(),
            error="Use a password between 12 and 128 characters.",
        ), 400

    try:
        with _connect_db() as connection:
            cursor = connection.execute(
                "INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?)",
                (email, generate_password_hash(password), now_iso()),
            )
            user_id = cursor.lastrowid
    except sqlite3.IntegrityError:
        return render_template(
            "signup.html",
            csrf_token=_csrf_token(),
            error="An account with that email already exists.",
        ), 409

    session.clear()
    session.permanent = True
    session["user_id"] = user_id
    session["csrf_token"] = secrets.token_urlsafe(32)
    return redirect(url_for("index"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if _current_user() is not None:
        return redirect(url_for("index"))
    if request.method == "GET":
        return render_template("login.html", csrf_token=_csrf_token(), error=None)

    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    with _connect_db() as connection:
        user = connection.execute(
            "SELECT id, email, password_hash FROM users WHERE email = ?",
            (email,),
        ).fetchone()

    if user is None or not check_password_hash(user["password_hash"], password):
        return render_template(
            "login.html",
            csrf_token=_csrf_token(),
            error="Email or password is incorrect.",
        ), 401

    session.clear()
    session.permanent = True
    session["user_id"] = user["id"]
    session["csrf_token"] = secrets.token_urlsafe(32)
    return redirect(url_for("index"))


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.get("/")
def index():
    user = _require_user()
    return render_template(
        "index.html",
        csrf_token=_csrf_token(),
        email=user["email"],
    )


def _job_for_user(user_id: int) -> sqlite3.Row | None:
    with _connect_db() as connection:
        return connection.execute(
            "SELECT * FROM jobs WHERE user_id = ?",
            (user_id,),
        ).fetchone()


@app.get("/api/status")
def status():
    user = _require_user()
    job = _job_for_user(user["id"])
    if job is None:
        return jsonify(
            active=False,
            target_url=None,
            cycle_count=0,
            visit_number=None,
            next_run_at=None,
            last_error=None,
            visits=[],
        )
    with _connect_db() as connection:
        visits = connection.execute(
            """
            SELECT cycle_number, visit_number, started_at, finished_at,
                   final_url, page_title, http_status, error
            FROM visits
            WHERE job_id = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (job["id"], MAX_RECENT_VISITS),
        ).fetchall()
    return jsonify(
        active=bool(job["active"]),
        target_url=job["target_url"],
        cycle_count=job["cycle_count"],
        visit_number=job["visit_number"] if job["active"] else None,
        next_run_at=job["next_run_at"],
        last_error=job["last_error"],
        visits=[dict(visit) for visit in visits],
    )


@app.post("/api/start")
def start():
    user = _require_user()
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify(error="Send a JSON object containing target_url."), 400

    try:
        target_url = validate_public_url(payload.get("target_url"))
    except ValueError as error:
        return jsonify(error=str(error)), 400

    timestamp = now_iso()
    with _connect_db() as connection:
        connection.execute(
            """
            INSERT INTO jobs (
                user_id, target_url, active, cycle_count, visit_number,
                generation, next_run_at, last_error, created_at, updated_at
            )
            VALUES (?, ?, 1, 0, 1, 1, ?, NULL, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                target_url = excluded.target_url,
                active = 1,
                cycle_count = 0,
                visit_number = 1,
                generation = jobs.generation + 1,
                next_run_at = excluded.next_run_at,
                last_error = NULL,
                updated_at = excluded.updated_at
            """,
            (user["id"], target_url, timestamp, timestamp, timestamp),
        )
    return jsonify(
        message="Started. The first page visit is scheduled now.",
        visits_per_cycle=VISITS_PER_CYCLE,
        interval_seconds=VISIT_INTERVAL_SECONDS,
    ), 202


@app.post("/api/stop")
def stop():
    user = _require_user()
    with _connect_db() as connection:
        cursor = connection.execute(
            """
            UPDATE jobs
            SET active = 0, generation = generation + 1,
                next_run_at = NULL, updated_at = ?
            WHERE user_id = ? AND active = 1
            """,
            (now_iso(), user["id"]),
        )
    if cursor.rowcount == 0:
        return jsonify(error="There is no active run for your account."), 409
    return jsonify(message="Stopped. Any current page visit will finish first.")


def _guard_browser_request(route: Route) -> None:
    request_url = route.request.url
    scheme = urlsplit(request_url).scheme.lower()
    if scheme in ("data", "blob", "about"):
        route.continue_()
        return
    if scheme not in ("http", "https"):
        route.abort("blockedbyclient")
        return
    try:
        validate_public_url(request_url)
    except ValueError:
        route.abort("blockedbyclient")
        return
    route.continue_()


def _visit_target(job: sqlite3.Row) -> dict[str, object]:
    started_at = now_iso()
    result: dict[str, object] = {
        "final_url": None,
        "page_title": None,
        "http_status": None,
        "error": None,
    }
    context: BrowserContext | None = None

    try:
        with sync_playwright() as playwright:
            browser: Browser = playwright.chromium.launch(headless=True)
            try:
                context = browser.new_context(service_workers="block")
                context.route("**/*", _guard_browser_request)
                page = context.new_page()
                response = page.goto(
                    validate_public_url(job["target_url"]),
                    wait_until="domcontentloaded",
                    timeout=30000,
                )
                result["final_url"] = page.url
                result["page_title"] = page.title()
                if response:
                    result["http_status"] = response.status
                    if response.status >= 400:
                        result["error"] = f"HTTP request failed with status {response.status}."
            finally:
                if context is not None:
                    context.close()
                browser.close()
    except Exception as error:
        result["error"] = f"{type(error).__name__}: {str(error)[:500]}"

    finished_at = now_utc()
    result["started_at"] = started_at
    result["finished_at"] = finished_at.isoformat()
    return result


def _job_is_active(job_id: int, generation: int) -> bool:
    with _connect_db() as connection:
        current = connection.execute(
            "SELECT active, generation FROM jobs WHERE id = ?",
            (job_id,),
        ).fetchone()
    return bool(
        current
        and current["active"]
        and current["generation"] == generation
    )


def process_due_job(job: sqlite3.Row) -> None:
    if not _job_is_active(job["id"], job["generation"]):
        return
    result = _visit_target(job)
    completed_visit = int(job["visit_number"])
    cycle_number = int(job["cycle_count"]) + 1
    next_visit = completed_visit + 1
    next_cycle_count = int(job["cycle_count"])
    if next_visit > VISITS_PER_CYCLE:
        next_visit = 1
        next_cycle_count += 1
    next_run_at = (now_utc() + timedelta(seconds=VISIT_INTERVAL_SECONDS)).isoformat()

    with _connect_db() as connection:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            """
            INSERT INTO visits (
                job_id, cycle_number, visit_number, started_at, finished_at,
                final_url, page_title, http_status, error
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                job["id"],
                cycle_number,
                completed_visit,
                result["started_at"],
                result["finished_at"],
                result["final_url"],
                result["page_title"],
                result["http_status"],
                result["error"],
            ),
        )
        connection.execute(
            "DELETE FROM visits WHERE job_id = ? AND id NOT IN "
            "(SELECT id FROM visits WHERE job_id = ? ORDER BY id DESC LIMIT ?)",
            (job["id"], job["id"], MAX_RECENT_VISITS),
        )
        connection.execute(
            """
            UPDATE jobs
            SET cycle_count = ?, visit_number = ?, next_run_at = ?,
                last_error = ?, updated_at = ?
            WHERE id = ? AND active = 1 AND generation = ?
            """,
            (
                next_cycle_count,
                next_visit,
                next_run_at,
                result["error"],
                now_iso(),
                job["id"],
                job["generation"],
            ),
        )


def scheduler_loop() -> None:
    while not SCHEDULER_STOP.is_set():
        try:
            with _connect_db() as connection:
                due_jobs = connection.execute(
                    """
                    SELECT * FROM jobs
                    WHERE active = 1 AND next_run_at <= ?
                    ORDER BY next_run_at, id
                    LIMIT 1
                    """,
                    (now_iso(),),
                ).fetchall()
            if due_jobs:
                process_due_job(due_jobs[0])
                continue
        except Exception:
            app.logger.exception("Background page-check scheduler failed.")
            time.sleep(5)
            continue
        SCHEDULER_STOP.wait(1)


def start_scheduler() -> None:
    global SCHEDULER_THREAD
    with SCHEDULER_START_LOCK:
        if SCHEDULER_THREAD is not None and SCHEDULER_THREAD.is_alive():
            return
        SCHEDULER_THREAD = threading.Thread(
            target=scheduler_loop,
            name="page-check-scheduler",
            daemon=True,
        )
        SCHEDULER_THREAD.start()


initialize_database()
if os.environ.get("DISABLE_SCHEDULER") != "1":
    start_scheduler()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")))

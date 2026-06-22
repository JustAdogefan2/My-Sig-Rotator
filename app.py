#!/usr/bin/env python3
"""A small, dependency-free random image URL rotator."""

from __future__ import annotations

import hashlib
import html
import os
import secrets
import sqlite3
import sys
from contextlib import contextmanager
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlparse


APP_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("SIG_ROTATOR_DB", APP_DIR / "sig-rotator.db"))
HOST = os.environ.get(
    "SIG_ROTATOR_HOST",
    "0.0.0.0" if os.environ.get("RENDER") else "127.0.0.1",
)
PORT = int(os.environ.get("PORT", os.environ.get("SIG_ROTATOR_PORT", "8080")))
SESSIONS: dict[str, dict[str, str]] = {}


@contextmanager
def db():
    connection = sqlite3.connect(DB_PATH)
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
    with db() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                last_hit_at TEXT,
                hits INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS images (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                url TEXT NOT NULL,
                position INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS images_user_id ON images(user_id);
            """
        )


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
    return f"pbkdf2_sha256$310000${salt.hex()}${digest.hex()}"


def password_matches(password: str, stored: str) -> bool:
    try:
        algorithm, rounds, salt_hex, digest_hex = stored.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt_hex), int(rounds)
        )
        return secrets.compare_digest(actual.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


def valid_username(value: str) -> bool:
    return 3 <= len(value) <= 30 and value.replace("_", "").isalnum()


def valid_image_url(value: str) -> bool:
    try:
        parsed = urlparse(value)
        return (
            parsed.scheme in {"http", "https"}
            and bool(parsed.netloc)
            and len(value) <= 2048
        )
    except ValueError:
        return False


def page(title: str, body: str, username: str | None = None) -> bytes:
    account = (
        f'<span>Signed in as <strong>{html.escape(username)}</strong></span>'
        '<form method="post" action="/logout"><button class="quiet">Sign out</button></form>'
        if username
        else ""
    )
    document = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{html.escape(title)} · Sig Rotator</title>
  <style>
    :root {{ color-scheme: dark; font-family: Inter, ui-sans-serif, system-ui, sans-serif; }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; background: #10131a; color: #e8edf5; }}
    header, main {{ width: min(880px, calc(100% - 32px)); margin: auto; }}
    header {{ padding: 28px 0 14px; display:flex; align-items:center; justify-content:space-between; gap:16px; }}
    header div {{ display:flex; align-items:center; gap:12px; }}
    a {{ color: #8dc5ff; }}
    main {{ padding: 20px 0 64px; }}
    .card {{ background:#1a202b; border:1px solid #30394a; border-radius:16px; padding:24px; margin:16px 0; }}
    h1 {{ margin:0; font-size:1.5rem; }} h2 {{ margin-top:0; }}
    label {{ display:block; margin:14px 0 6px; font-weight:650; }}
    input {{ width:100%; padding:11px 12px; border-radius:9px; border:1px solid #465269; background:#11161f; color:inherit; }}
    button {{ margin-top:16px; padding:10px 16px; border:0; border-radius:9px; background:#62aef7; color:#07111d; font-weight:750; cursor:pointer; }}
    button.quiet {{ margin:0; background:#2a3342; color:#e8edf5; }}
    .error {{ background:#46232a; border:1px solid #91404e; padding:12px; border-radius:9px; }}
    .success {{ background:#183b30; border:1px solid #31755e; padding:12px; border-radius:9px; }}
    .hint {{ color:#aab5c7; }} code {{ overflow-wrap:anywhere; }}
    .url-row {{ margin-bottom:10px; }}
    img.preview {{ display:block; max-width:100%; max-height:260px; margin:16px auto; border-radius:10px; }}
  </style>
</head>
<body>
  <header><h1><a href="/" style="color:inherit;text-decoration:none">Sig Rotator</a></h1><div>{account}</div></header>
  <main>{body}</main>
</body>
</html>"""
    return document.encode()


class App(BaseHTTPRequestHandler):
    server_version = "SigRotator/3"

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"{self.address_string()} - {fmt % args}")

    def session(self) -> tuple[str | None, dict[str, str] | None]:
        jar = cookies.SimpleCookie(self.headers.get("Cookie"))
        morsel = jar.get("session")
        if not morsel:
            return None, None
        token = morsel.value
        return token, SESSIONS.get(token)

    def current_user(self) -> str | None:
        _, session = self.session()
        return session.get("username") if session else None

    def send_html(self, body: bytes, status: int = 200, cookie: str | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; img-src http: https:; style-src 'unsafe-inline'")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body)

    def redirect(self, location: str, status: int = 303, cookie: str | None = None) -> None:
        self.send_response(status)
        self.send_header("Location", location)
        self.send_header("Cache-Control", "no-store")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()

    def form(self) -> dict[str, list[str]]:
        try:
            length = min(int(self.headers.get("Content-Length", "0")), 100_000)
        except ValueError:
            length = 0
        return parse_qs(self.rfile.read(length).decode("utf-8", "replace"))

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/":
            self.home()
        elif path == "/manage":
            self.manage()
        elif path.startswith("/r/"):
            self.rotate(path[3:])
        elif path.endswith(".gif") and path.count("/") == 1:
            self.rotate(path[1:-4])
        else:
            self.send_html(page("Not found", '<section class="card"><h2>Not found</h2></section>'), 404)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path == "/login":
            self.login()
        elif path == "/register":
            self.register()
        elif path == "/logout":
            self.logout()
        elif path == "/images":
            self.save_images()
        else:
            self.send_html(page("Not found", '<section class="card"><h2>Not found</h2></section>'), 404)

    def home(self, message: str = "") -> None:
        username = self.current_user()
        if username:
            self.redirect("/manage")
            return
        notice = f'<p class="error">{html.escape(message)}</p>' if message else ""
        body = f"""
        {notice}
        <section class="card">
          <h2>Show a different image on every load</h2>
          <p class="hint">Store a set of image URLs, then use one permanent rotator URL anywhere that accepts an image.</p>
        </section>
        <section class="card">
          <h2>Sign in</h2>
          <form method="post" action="/login">
            <label>Username</label><input name="username" required autocomplete="username">
            <label>Password</label><input name="password" type="password" required autocomplete="current-password">
            <button>Sign in</button>
          </form>
        </section>
        <section class="card">
          <h2>Create an account</h2>
          <form method="post" action="/register">
            <label>Username</label><input name="username" required minlength="3" maxlength="30" pattern="[A-Za-z0-9_]+">
            <label>Password</label><input name="password" type="password" required minlength="8" autocomplete="new-password">
            <button>Create account</button>
          </form>
        </section>"""
        self.send_html(page("Home", body))

    def login(self) -> None:
        values = self.form()
        username = values.get("username", [""])[0].strip()
        password = values.get("password", [""])[0]
        with db() as connection:
            user = connection.execute(
                "SELECT username, password_hash FROM users WHERE username = ?", (username,)
            ).fetchone()
        if not user or not password_matches(password, user["password_hash"]):
            self.home("Incorrect username or password.")
            return
        self.start_session(user["username"])

    def register(self) -> None:
        values = self.form()
        username = values.get("username", [""])[0].strip()
        password = values.get("password", [""])[0]
        if not valid_username(username):
            self.home("Username must be 3–30 letters, numbers, or underscores.")
            return
        if len(password) < 8:
            self.home("Password must contain at least 8 characters.")
            return
        try:
            with db() as connection:
                connection.execute(
                    "INSERT INTO users(username, password_hash) VALUES (?, ?)",
                    (username, hash_password(password)),
                )
        except sqlite3.IntegrityError:
            self.home("That username is already taken.")
            return
        self.start_session(username)

    def start_session(self, username: str) -> None:
        token = secrets.token_urlsafe(32)
        SESSIONS[token] = {"username": username, "csrf": secrets.token_urlsafe(24)}
        cookie = f"session={token}; HttpOnly; SameSite=Lax; Path=/"
        self.redirect("/manage", cookie=cookie)

    def logout(self) -> None:
        token, _ = self.session()
        if token:
            SESSIONS.pop(token, None)
        self.redirect("/", cookie="session=; Max-Age=0; HttpOnly; SameSite=Lax; Path=/")

    def manage(self, message: str = "", error: bool = False) -> None:
        username = self.current_user()
        _, session = self.session()
        if not username or not session:
            self.redirect("/")
            return
        with db() as connection:
            user = connection.execute(
                "SELECT id, hits, last_hit_at FROM users WHERE username = ?", (username,)
            ).fetchone()
            images = connection.execute(
                "SELECT url FROM images WHERE user_id = ? ORDER BY position, id", (user["id"],)
            ).fetchall()
        fields = "".join(
            f'<div class="url-row"><input name="url" value="{html.escape(row["url"], quote=True)}"></div>'
            for row in images
        )
        fields += "".join(
            '<div class="url-row"><input name="url" placeholder="https://example.com/image.png"></div>'
            for _ in range(max(1, 3 - len(images)))
        )
        notice = ""
        if message:
            notice = f'<p class="{"error" if error else "success"}">{html.escape(message)}</p>'
        rotator = f"{self.headers.get('Host', f'{HOST}:{PORT}')}/r/{quote(username)}"
        body = f"""
        {notice}
        <section class="card">
          <h2>Your rotator</h2>
          <p>Use either URL:</p>
          <p><code>http://{html.escape(rotator)}</code></p>
          <p><code>http://{html.escape(self.headers.get('Host', f'{HOST}:{PORT}'))}/{quote(username)}.gif</code></p>
          <p class="hint">{user["hits"]} request(s) so far. Last request: {html.escape(user["last_hit_at"] or "never")}.</p>
        </section>
        <section class="card">
          <h2>Image URLs</h2>
          <p class="hint">Leave a field blank to remove it. Saving always adds at least one fresh empty field.</p>
          <form method="post" action="/images">
            <input type="hidden" name="csrf" value="{html.escape(session["csrf"], quote=True)}">
            {fields}
            <button>Save URLs</button>
          </form>
        </section>"""
        self.send_html(page("Manage", body, username))

    def save_images(self) -> None:
        username = self.current_user()
        _, session = self.session()
        if not username or not session:
            self.redirect("/")
            return
        values = self.form()
        if not secrets.compare_digest(values.get("csrf", [""])[0], session["csrf"]):
            self.send_html(page("Forbidden", '<section class="card"><h2>Invalid form token</h2></section>'), 403)
            return
        urls = [value.strip() for value in values.get("url", []) if value.strip()]
        if len(urls) > 100:
            self.manage("You can save up to 100 image URLs.", True)
            return
        invalid = next((url for url in urls if not valid_image_url(url)), None)
        if invalid:
            self.manage(f"Not a valid HTTP(S) URL: {invalid}", True)
            return
        with db() as connection:
            user_id = connection.execute(
                "SELECT id FROM users WHERE username = ?", (username,)
            ).fetchone()["id"]
            connection.execute("DELETE FROM images WHERE user_id = ?", (user_id,))
            connection.executemany(
                "INSERT INTO images(user_id, url, position) VALUES (?, ?, ?)",
                [(user_id, url, position) for position, url in enumerate(urls)],
            )
        self.manage("Image URLs saved.")

    def rotate(self, username: str) -> None:
        username = username.strip()
        with db() as connection:
            user = connection.execute(
                "SELECT id FROM users WHERE username = ?", (username,)
            ).fetchone()
            if not user:
                self.send_html(page("Not found", '<section class="card"><h2>Rotator not found</h2></section>'), 404)
                return
            image = connection.execute(
                "SELECT url FROM images WHERE user_id = ? ORDER BY RANDOM() LIMIT 1",
                (user["id"],),
            ).fetchone()
            if image:
                connection.execute(
                    "UPDATE users SET hits = hits + 1, last_hit_at = CURRENT_TIMESTAMP WHERE id = ?",
                    (user["id"],),
                )
        if not image:
            self.send_html(page("Empty rotator", '<section class="card"><h2>No image URLs configured</h2></section>'), 404)
            return
        self.redirect(image["url"], status=302)


def run() -> None:
    initialize_database()
    server = ThreadingHTTPServer((HOST, PORT), App)
    print(f"Sig Rotator is running at http://{HOST}:{PORT}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    run()

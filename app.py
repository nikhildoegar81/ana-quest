#!/usr/bin/env python3
import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
from datetime import date, datetime, timedelta
from http import cookies
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

DB_PATH = os.environ.get(
    "ANAQUEST_DB_PATH",
    os.path.join(os.path.dirname(__file__), "habit_tracker.db"),
)
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8000"))
SESSION_COOKIE = "anaquest_session"
SESSION_TTL_SECONDS = 60 * 60 * 12
SECRET_KEY = os.environ.get("ANAQUEST_SECRET", "dev-only-change-me-anaquest-secret").encode("utf-8")
SECURE_COOKIES = os.environ.get("SECURE_COOKIES", "0") == "1"
PWA_MANIFEST = {
    "name": "ANA-Quest",
    "short_name": "ANA-Quest",
    "start_url": "/",
    "display": "standalone",
    "background_color": "#eff6ff",
    "theme_color": "#0ea5e9",
    "icons": [
        {"src": "/icon.svg", "sizes": "192x192", "type": "image/svg+xml", "purpose": "any maskable"},
        {"src": "/icon.svg", "sizes": "512x512", "type": "image/svg+xml", "purpose": "any maskable"},
    ],
}

PWA_SW_JS = """const CACHE_NAME = 'anaquest-v2';
const APP_SHELL = ['/', '/progress', '/manifest.webmanifest', '/icon.svg'];

self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(CACHE_NAME).then((cache) => cache.addAll(APP_SHELL)));
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET') return;
  if (event.request.mode === 'navigate') {
    event.respondWith(
      fetch(event.request)
        .then((response) => {
          const copy = response.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(event.request, copy));
          return response;
        })
        .catch(() => caches.match(event.request).then((r) => r || caches.match('/')))
    );
    return;
  }
  event.respondWith(
    caches.match(event.request).then((cached) => {
      if (cached) return cached;
      return fetch(event.request)
        .then((response) => {
          const copy = response.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(event.request, copy));
          return response;
        })
        .catch(() => caches.match('/'));
    })
  );
});
"""

PWA_ICON_SVG = """<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 512 512'>
<defs>
<linearGradient id='g1' x1='0%' y1='0%' x2='100%' y2='100%'>
<stop offset='0%' stop-color='#38bdf8'/>
<stop offset='100%' stop-color='#0ea5e9'/>
</linearGradient>
<linearGradient id='g2' x1='0%' y1='0%' x2='100%' y2='100%'>
<stop offset='0%' stop-color='#f59e0b'/>
<stop offset='100%' stop-color='#ea580c'/>
</linearGradient>
</defs>
<rect width='512' height='512' rx='96' fill='url(#g1)'/>
<circle cx='170' cy='184' r='80' fill='#f8d7a9' stroke='#92400e' stroke-width='12'/>
<ellipse cx='110' cy='130' rx='30' ry='44' fill='#d97706'/>
<ellipse cx='230' cy='130' rx='30' ry='44' fill='#d97706'/>
<circle cx='145' cy='178' r='10' fill='#111827'/>
<circle cx='195' cy='178' r='10' fill='#111827'/>
<ellipse cx='170' cy='212' rx='24' ry='16' fill='#7c2d12'/>
<path d='M146 235c9 10 15 14 24 14s15-4 24-14' stroke='#7c2d12' stroke-width='8' fill='none' stroke-linecap='round'/>
<circle cx='354' cy='300' r='110' fill='#fef3c7' stroke='#f59e0b' stroke-width='16'/>
<path d='M354 220l24 48 54 8-39 38 10 54-49-26-49 26 10-54-39-38 54-8z' fill='url(#g2)'/>
<text x='76' y='430' font-family='Trebuchet MS, Arial, sans-serif' font-size='86' font-weight='800' fill='white'>ANA</text>
</svg>
"""


def db_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def utc_now_iso():
    return datetime.utcnow().replace(microsecond=0).isoformat()


def hash_password(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120_000)
    return f"{base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"


def verify_password(password, stored):
    try:
        salt_b64, digest_b64 = stored.split("$", 1)
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
    except Exception:
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120_000)
    return hmac.compare_digest(actual, expected)


def sign_payload(payload):
    return hmac.new(SECRET_KEY, payload.encode("utf-8"), hashlib.sha256).hexdigest()


def make_session_token(role):
    expires = int(datetime.utcnow().timestamp()) + SESSION_TTL_SECONDS
    payload = f"{role}|{expires}"
    signature = sign_payload(payload)
    token = f"{payload}|{signature}"
    return base64.urlsafe_b64encode(token.encode("utf-8")).decode("ascii")


def parse_session_token(token):
    try:
        decoded = base64.urlsafe_b64decode(token.encode("ascii")).decode("utf-8")
        role, expires_str, signature = decoded.split("|", 2)
        payload = f"{role}|{expires_str}"
        expected = sign_payload(payload)
        if not hmac.compare_digest(signature, expected):
            return None
        if int(expires_str) < int(datetime.utcnow().timestamp()):
            return None
        if role not in ("child", "parent"):
            return None
        return role
    except Exception:
        return None


def init_db():
    conn = db_conn()
    cur = conn.cursor()

    cur.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            role TEXT PRIMARY KEY CHECK(role IN ('child', 'parent')),
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS app_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS goals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            option1_label TEXT NOT NULL,
            option1_points INTEGER NOT NULL,
            option2_label TEXT NOT NULL,
            option2_points INTEGER NOT NULL,
            option3_label TEXT NOT NULL,
            option3_points INTEGER NOT NULL,
            option4_label TEXT NOT NULL,
            option4_points INTEGER NOT NULL,
            sort_order INTEGER NOT NULL,
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            goal_id INTEGER NOT NULL,
            day TEXT NOT NULL,
            selected_option INTEGER NOT NULL CHECK(selected_option BETWEEN 1 AND 4),
            selected_points INTEGER NOT NULL,
            child_note TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL CHECK(status IN ('pending', 'approved', 'rejected')),
            parent_note TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(goal_id) REFERENCES goals(id),
            UNIQUE(goal_id, day)
        );

        CREATE TABLE IF NOT EXISTS reward_tiers (
            level TEXT PRIMARY KEY CHECK(level IN ('bronze', 'silver', 'gold')),
            min_points INTEGER NOT NULL,
            reward_text TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        """
    )

    now = utc_now_iso()

    child_exists = cur.execute("SELECT 1 FROM users WHERE role='child'").fetchone()
    parent_exists = cur.execute("SELECT 1 FROM users WHERE role='parent'").fetchone()
    if not child_exists:
        cur.execute(
            "INSERT INTO users(role, password_hash, created_at, updated_at) VALUES ('child', ?, ?, ?)",
            (hash_password("anaaya123"), now, now),
        )
    if not parent_exists:
        cur.execute(
            "INSERT INTO users(role, password_hash, created_at, updated_at) VALUES ('parent', ?, ?, ?)",
            (hash_password("parent123"), now, now),
        )

    cur.execute(
        "INSERT OR IGNORE INTO app_settings(key, value) VALUES ('app_name', 'ANA-Quest')"
    )
    cur.execute(
        "INSERT OR IGNORE INTO app_settings(key, value) VALUES ('child_name', 'Anaaya')"
    )

    count_goals = cur.execute("SELECT COUNT(*) FROM goals").fetchone()[0]
    if count_goals == 0:
        goals = [
            (
                "Get ready on time in the morning",
                "On time",
                20,
                "After 1 reminder",
                10,
                "Tried but not done",
                0,
                "Skipped",
                -10,
                1,
            ),
            (
                "Lunch finished on time",
                "Finished in 20 mins",
                20,
                "Finished in 25 mins",
                15,
                "Finished in 30 mins",
                10,
                "More than 30 mins",
                0,
                2,
            ),
            (
                "Dinner finished on time",
                "Finished in 20 mins",
                20,
                "Finished in 25 mins",
                15,
                "Finished in 30 mins",
                10,
                "More than 30 mins",
                0,
                3,
            ),
            (
                "Sleep on time at night",
                "On time",
                20,
                "After 1 reminder",
                10,
                "Tried but not done",
                0,
                "Skipped",
                -10,
                4,
            ),
            (
                "Room clean before sleeping",
                "On time",
                20,
                "After 1 reminder",
                10,
                "Tried but not done",
                0,
                "Skipped",
                -10,
                5,
            ),
        ]
        cur.executemany(
            """
            INSERT INTO goals(
              name,
              option1_label, option1_points,
              option2_label, option2_points,
              option3_label, option3_points,
              option4_label, option4_points,
              sort_order, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [(*g, now, now) for g in goals],
        )

    count_tiers = cur.execute("SELECT COUNT(*) FROM reward_tiers").fetchone()[0]
    if count_tiers == 0:
        cur.executemany(
            "INSERT INTO reward_tiers(level, min_points, reward_text, updated_at) VALUES (?, ?, ?, ?)",
            [
                ("bronze", 200, "Small chocolate or sticker", now),
                ("silver", 300, "Frixion pen or small treat", now),
                ("gold", 400, "Ice cream, boba tea, or chocolate", now),
            ],
        )

    conn.commit()
    conn.close()


def get_setting(conn, key, default=""):
    row = conn.execute("SELECT value FROM app_settings WHERE key=?", (key,)).fetchone()
    return row[0] if row else default


def total_approved_points_for_week(conn, start_day, end_day):
    row = conn.execute(
        """
        SELECT COALESCE(SUM(selected_points), 0)
        FROM entries
        WHERE status='approved' AND day BETWEEN ? AND ?
        """,
        (start_day, end_day),
    ).fetchone()
    return int(row[0] or 0)


def current_week_range():
    today = date.today()
    start = today - timedelta(days=today.weekday())
    end = start + timedelta(days=6)
    return start.isoformat(), end.isoformat()


def weekday_name_from_iso(iso_day):
    return date.fromisoformat(iso_day).strftime("%A")


def date_with_weekday(iso_day):
    return f"{iso_day} ({weekday_name_from_iso(iso_day)})"


def today_with_weekday():
    return date_with_weekday(date.today().isoformat())


def detect_level(conn, points):
    tiers = conn.execute(
        "SELECT level, min_points FROM reward_tiers ORDER BY min_points ASC"
    ).fetchall()
    reached = "none"
    for tier in tiers:
        if points >= tier["min_points"]:
            reached = tier["level"]
    return reached


def html_escape(text):
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def level_badge_svg(level):
    safe = (level or "").lower()
    if safe == "gold":
        return """
        <svg class="tier-icon" viewBox="0 0 64 64" aria-hidden="true">
          <circle cx="32" cy="32" r="28" fill="#fde68a" stroke="#f59e0b" stroke-width="4"/>
          <path d="M32 13l6 12 14 2-10 10 2 14-12-7-12 7 2-14-10-10 14-2z" fill="#f59e0b"/>
        </svg>
        """
    if safe == "silver":
        return """
        <svg class="tier-icon" viewBox="0 0 64 64" aria-hidden="true">
          <circle cx="32" cy="32" r="28" fill="#e5e7eb" stroke="#94a3b8" stroke-width="4"/>
          <path d="M32 13l6 12 14 2-10 10 2 14-12-7-12 7 2-14-10-10 14-2z" fill="#94a3b8"/>
        </svg>
        """
    return """
    <svg class="tier-icon" viewBox="0 0 64 64" aria-hidden="true">
      <circle cx="32" cy="32" r="28" fill="#fed7aa" stroke="#c2410c" stroke-width="4"/>
      <path d="M32 13l6 12 14 2-10 10 2 14-12-7-12 7 2-14-10-10 14-2z" fill="#c2410c"/>
    </svg>
    """


def render_layout(title, role, child_name, app_name, body, notice="", celebrate=False, theme="default"):
    login_links = ""
    current = (title or "").strip().lower()

    def top_icon(kind):
        k = (kind or "").lower()
        if k == "progress":
            return """<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 20h16v1H3V3h1v17zm3-3h2V9H7v8zm4 0h2V5h-2v12zm4 0h2v-6h-2v6z"/></svg>"""
        if k == "logout":
            return """<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M10 3h8a2 2 0 012 2v14a2 2 0 01-2 2h-8v-2h8V5h-8V3z"/><path d="M13 16l1.4-1.4L12.8 13H4v-2h8.8l1.6-1.6L13 8l4 4-4 4z"/></svg>"""
        return """<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9"/></svg>"""

    if role:
        mode = "Anaaya" if role == "child" else "Parent"
        login_links = (
            f"<div class='muted'>Mode: <strong>{mode}</strong> "
            f"<a class='link-btn icon-link' href='/progress'><span class='top-icon'>{top_icon('progress')}</span><span>Progress</span></a>"
            f"<a class='link-btn icon-link' href='/logout'><span class='top-icon'>{top_icon('logout')}</span><span>Logout</span></a></div>"
        )

    notice_html = f"<div class='notice'>{html_escape(notice)}</div>" if notice else ""
    if role == "child":
        nav_items = [
            ("Child", "/child", current == "child"),
            ("Progress", "/progress", current == "progress report"),
            ("Logout", "/logout", False),
        ]
    elif role == "parent":
        nav_items = [
            ("Parent", "/parent", current == "parent"),
            ("Progress", "/progress", current == "progress report"),
            ("Logout", "/logout", False),
        ]
    else:
        nav_items = [
            ("Login", "/", current == "login"),
            ("Progress", "/progress", current == "progress report"),
        ]

    def nav_icon(label):
        key = (label or "").lower()
        if key in ("child", "parent", "login"):
            return """<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3a4 4 0 100 8 4 4 0 000-8zm-7 15c0-3.1 3.1-5 7-5s7 1.9 7 5v2H5v-2z"/></svg>"""
        if key == "progress":
            return """<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 20h16v1H3V3h1v17zm3-3h2V9H7v8zm4 0h2V5h-2v12zm4 0h2v-6h-2v6z"/></svg>"""
        if key == "logout":
            return """<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M10 3h8a2 2 0 012 2v14a2 2 0 01-2 2h-8v-2h8V5h-8V3z"/><path d="M13 16l1.4-1.4L12.8 13H4v-2h8.8l1.6-1.6L13 8l4 4-4 4z"/></svg>"""
        return """<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9"/></svg>"""

    mobile_nav = f"<nav class='mobile-nav cols-{len(nav_items)}'>" + "".join(
        f"<a href='{href}' class='{'active' if active else ''}'><span class='nav-icon'>{nav_icon(label)}</span><span>{label}</span></a>"
        for label, href, active in nav_items
    ) + "</nav>"
    logo_svg = """
    <svg class="logo-svg" viewBox="0 0 230 70" role="img" aria-label="ANA-Quest logo">
      <defs>
        <linearGradient id="aqFill" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stop-color="#f97316"/>
          <stop offset="100%" stop-color="#eab308"/>
        </linearGradient>
        <linearGradient id="aqSky" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stop-color="#f8fafc"/>
          <stop offset="100%" stop-color="#ecfeff"/>
        </linearGradient>
      </defs>
      <rect x="2" y="2" width="226" height="66" rx="18" fill="url(#aqSky)" stroke="#fed7aa"/>
      <path d="M35 12l3 9h9l-7 6 3 9-8-6-8 6 3-9-7-6h9z" fill="#fbbf24"/>
      <circle cx="34" cy="47" r="10" fill="#86efac"/>
      <text x="54" y="32" font-size="24" font-family="Trebuchet MS, Arial, sans-serif" font-weight="800" fill="url(#aqFill)">ANA</text>
      <text x="54" y="54" font-size="22" font-family="Trebuchet MS, Arial, sans-serif" font-weight="800" fill="#0f766e">Quest</text>
      <path d="M171 17c9 0 16 7 16 16s-7 16-16 16-16-7-16-16 7-16 16-16z" fill="#d1fae5" stroke="#34d399"/>
      <path d="M171 21l3.4 6.8 7.6 1.1-5.5 5.3 1.3 7.5-6.8-3.6-6.8 3.6 1.3-7.5-5.5-5.3 7.6-1.1z" fill="#22c55e"/>
      <path d="M186 10l2 5h5l-4 3 2 5-5-3-4 3 2-5-4-3h5z" fill="#60a5fa"/>
    </svg>
    """
    dog_svg = """
    <svg class="dog-svg" viewBox="0 0 74 74" role="img" aria-label="Dog mascot">
      <circle cx="37" cy="39" r="23" fill="#f8d7a9" stroke="#b45309" stroke-width="2"/>
      <ellipse cx="19" cy="23" rx="9" ry="12" fill="#d97706"/>
      <ellipse cx="55" cy="23" rx="9" ry="12" fill="#d97706"/>
      <circle cx="29" cy="36" r="3.3" fill="#1f2937"/>
      <circle cx="45" cy="36" r="3.3" fill="#1f2937"/>
      <ellipse cx="37" cy="45" rx="6" ry="4.5" fill="#92400e"/>
      <path d="M30 50c2 3 4 4 7 4s5-1 7-4" fill="none" stroke="#7c2d12" stroke-width="2" stroke-linecap="round"/>
      <circle cx="54" cy="48" r="3.8" fill="#fecaca"/>
      <path d="M23 14l3-7 7 8" fill="#d97706"/>
    </svg>
    """

    return f"""<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"UTF-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <meta name="theme-color" content="#0ea5e9" />
  <meta name="apple-mobile-web-app-capable" content="yes" />
  <meta name="apple-mobile-web-app-status-bar-style" content="default" />
  <meta name="apple-mobile-web-app-title" content="ANA-Quest" />
  <link rel="manifest" href="/manifest.webmanifest" />
  <link rel="icon" href="/icon.svg" type="image/svg+xml" />
  <link rel="apple-touch-icon" href="/icon.svg" />
  <title>{html_escape(title)}</title>
  <style>
    :root {{
      --bg-a: #eff6ff;
      --bg-b: #e0f2fe;
      --card: #ffffff;
      --text: #1f2937;
      --muted: #6b7280;
      --line: #e5e7eb;
      --accent: #0ea5e9;
      --accent-dark: #0284c7;
      --ok: #166534;
      --warn: #92400e;
      --bad: #991b1b;
      --soft: #fffaf4;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: "Nunito", "Avenir Next", "Trebuchet MS", sans-serif;
      color: var(--text);
      min-height: 100vh;
    }}
    body.theme-default {{
      background: radial-gradient(circle at 6% 10%, #bfdbfe, transparent 30%),
                  radial-gradient(circle at 95% 10%, #bae6fd, transparent 28%),
                  radial-gradient(circle at 50% 90%, #dbeafe, transparent 30%),
                  linear-gradient(180deg, var(--bg-a), var(--bg-b));
    }}
    body.theme-progress-low {{
      background: radial-gradient(circle at 20% 15%, #fecaca, transparent 36%),
                  radial-gradient(circle at 90% 18%, #fbcfe8, transparent 32%),
                  linear-gradient(180deg, #fff1f2, #ffe4e6);
    }}
    body.theme-progress-medium {{
      background: radial-gradient(circle at 18% 14%, #fde68a, transparent 34%),
                  radial-gradient(circle at 88% 18%, #fed7aa, transparent 30%),
                  linear-gradient(180deg, #fffbeb, #fff7ed);
    }}
    body.theme-progress-good {{
      background: radial-gradient(circle at 12% 14%, #bfdbfe, transparent 34%),
                  radial-gradient(circle at 92% 15%, #bae6fd, transparent 32%),
                  linear-gradient(180deg, #eff6ff, #ecfeff);
    }}
    body.theme-progress-great {{
      background: radial-gradient(circle at 10% 10%, #86efac, transparent 35%),
                  radial-gradient(circle at 92% 12%, #67e8f9, transparent 30%),
                  radial-gradient(circle at 60% 90%, #fde68a, transparent 40%),
                  linear-gradient(180deg, #f0fdf4, #ecfeff);
    }}
    .wrap {{ max-width: 1050px; margin: 0 auto; padding: 16px 20px 20px; }}
    .masthead {{
      position: relative;
      overflow: hidden;
      border: 1px solid #bfdbfe;
      border-radius: 22px;
      padding: 14px;
      margin-bottom: 16px;
      background: linear-gradient(125deg, #eff6ff 0%, #ffffff 45%, #ecfeff 100%);
      box-shadow: 0 16px 34px rgba(14, 165, 233, 0.2);
    }}
    .masthead::before {{
      content: "";
      position: absolute;
      inset: auto -80px -80px auto;
      width: 200px;
      height: 200px;
      border-radius: 50%;
      background: radial-gradient(circle, rgba(14,165,233,.22), rgba(14,165,233,0));
      pointer-events: none;
    }}
    .masthead::after {{
      content: "";
      position: absolute;
      inset: -80px auto auto -80px;
      width: 210px;
      height: 210px;
      border-radius: 50%;
      background: radial-gradient(circle, rgba(56,189,248,.26), rgba(56,189,248,0));
      pointer-events: none;
    }}
    .top {{ position: relative; z-index: 1; display: flex; justify-content: space-between; gap: 14px; align-items: center; }}
    .brand {{ display: flex; align-items: center; gap: 12px; }}
    .brand-text h1 {{ margin: 0; font-size: 1.7rem; line-height: 1.15; }}
    .brand-text .muted {{ font-weight: 700; color: #0f766e; }}
    .logo-svg {{ width: 230px; max-width: 48vw; height: auto; display: block; }}
    .dog-svg {{ width: 58px; height: 58px; display: block; filter: drop-shadow(0 5px 7px rgba(2,132,199,.2)); }}
    h1 {{ margin: 0; font-size: 1.7rem; line-height: 1.15; }}
    h2 {{ margin: 6px 0 10px; font-size: 1.2rem; line-height: 1.2; }}
    h3 {{ margin: 6px 0; font-size: 1rem; line-height: 1.25; }}
    .muted {{ color: var(--muted); }}
    .badge {{ border: 1px solid #fed7aa; color: #9a3412; background: #fff7ed; border-radius: 999px; padding: 5px 10px; font-weight: 700; font-size: .85rem; }}
    .badge-wrap {{ display: inline-flex; align-items: center; gap: 8px; border-radius: 999px; padding: 4px 10px; border: 1px solid #bae6fd; background: #f0f9ff; }}
    .badge-wrap .tier-icon {{ width: 24px; height: 24px; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 12px; }}
    .card {{ background: var(--card); border: 1px solid var(--line); border-radius: 16px; padding: 14px; box-shadow: 0 12px 24px rgba(0,0,0,.05); }}
    .hero {{
      background: linear-gradient(130deg, #fff, #fffaf0, #f0fdf4);
      border: 1px solid #fde68a;
      border-radius: 18px;
      padding: 14px;
      margin-bottom: 12px;
    }}
    .row {{ display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }}
    .row.action-row {{ justify-content: flex-end; }}
    .stack {{ display: grid; gap: 8px; }}
    label {{ font-weight: 700; font-size: .92rem; line-height: 1.2; }}
    input, select, textarea, button {{ font: inherit; }}
    input, select, textarea {{ width: 100%; border: 1px solid var(--line); border-radius: 10px; padding: 8px 9px; background: #fff; line-height: 1.3; }}
    textarea {{ min-height: 68px; resize: vertical; }}
    button {{
      border: none;
      border-radius: 10px;
      padding: 10px 13px;
      cursor: pointer;
      font-weight: 700;
      background: var(--accent);
      color: #fff;
      min-height: 44px;
      touch-action: manipulation;
    }}
    button:hover {{ background: var(--accent-dark); }}
    button.good {{ background: #16a34a; }}
    button.good:hover {{ background: #15803d; }}
    button.bad {{ background: #dc2626; }}
    button.bad:hover {{ background: #b91c1c; }}
    button.ghost {{ background: #fff; color: var(--text); border: 1px solid var(--line); }}
    .link-btn {{ margin-left: 10px; color: #2563eb; text-decoration: none; font-weight: 700; }}
    .link-btn:hover {{ text-decoration: underline; }}
    .icon-link {{ display: inline-flex; align-items: center; gap: 5px; }}
    .top-icon {{ width: 14px; height: 14px; line-height: 0; display: inline-block; }}
    .top-icon svg {{ width: 14px; height: 14px; fill: currentColor; display: block; }}
    .status {{ display: inline-block; border-radius: 999px; padding: 4px 10px; font-size: .8rem; font-weight: 700; border: 1px solid; }}
    .status.pending {{ color: var(--warn); background: #fff7ed; border-color: #fdba74; }}
    .status.approved {{ color: var(--ok); background: #dcfce7; border-color: #86efac; }}
    .status.rejected {{ color: var(--bad); background: #fee2e2; border-color: #fca5a5; }}
    .notice {{ margin: 0 0 12px; padding: 10px 12px; border-radius: 10px; border: 1px solid #bfdbfe; background: #eff6ff; color: #1d4ed8; font-weight: 700; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ text-align: left; padding: 7px 5px; border-bottom: 1px solid var(--line); vertical-align: top; }}
    .table-scroll {{ width: 100%; overflow-x: auto; }}
    .table-scroll table {{ min-width: 560px; }}
    .small {{ font-size: .86rem; line-height: 1.3; }}
    .mobile-nav {{
      display: none;
      position: fixed;
      left: 10px;
      right: 10px;
      bottom: 10px;
      z-index: 10001;
      border-radius: 16px;
      border: 1px solid #bae6fd;
      background: rgba(255, 255, 255, 0.93);
      backdrop-filter: blur(8px);
      padding: 8px;
      box-shadow: 0 10px 24px rgba(2, 132, 199, 0.16);
      gap: 8px;
    }}
    .mobile-nav.cols-2 {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
    .mobile-nav.cols-3 {{ grid-template-columns: repeat(3, minmax(0, 1fr)); }}
    .mobile-nav a {{
      text-decoration: none;
      color: #0f172a;
      text-align: center;
      font-weight: 800;
      padding: 8px 8px;
      border-radius: 11px;
      border: 1px solid transparent;
      font-size: .9rem;
      min-height: 42px;
      display: grid;
      place-items: center;
      gap: 4px;
    }}
    .mobile-nav .nav-icon {{
      width: 18px;
      height: 18px;
      display: inline-block;
      line-height: 0;
    }}
    .mobile-nav .nav-icon svg {{
      width: 18px;
      height: 18px;
      fill: currentColor;
      display: block;
    }}
    details.mobile-details {{
      border: 1px dashed #bfdbfe;
      border-radius: 10px;
      padding: 6px 8px;
      background: #f8fbff;
    }}
    details.mobile-details summary {{
      cursor: pointer;
      font-size: .84rem;
      font-weight: 800;
      color: #0369a1;
      list-style: none;
    }}
    details.mobile-details summary::-webkit-details-marker {{ display: none; }}
    details.mobile-details[open] summary {{ margin-bottom: 6px; }}
    .mobile-nav a.active {{
      color: #0369a1;
      background: #e0f2fe;
      border-color: #7dd3fc;
    }}
    .tier-line {{ display: flex; align-items: center; gap: 8px; }}
    .tier-icon {{ width: 28px; height: 28px; display: inline-block; vertical-align: middle; }}
    .kpi-grid {{ display: grid; gap: 12px; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); }}
    .kpi {{ padding: 12px; border-radius: 12px; border: 1px solid #dbeafe; background: #f8fbff; }}
    .kpi strong {{ display: block; font-size: 1.4rem; line-height: 1.2; }}
    .kpi span {{ color: var(--muted); font-size: .87rem; }}
    .progress-ring {{
      --pct: 0;
      width: 150px;
      height: 150px;
      border-radius: 50%;
      display: grid;
      place-items: center;
      background: conic-gradient(#0ea5e9 calc(var(--pct) * 1%), #e2e8f0 0);
      margin: 6px auto;
    }}
    .progress-ring-inner {{
      width: 116px;
      height: 116px;
      border-radius: 50%;
      background: #fff;
      display: grid;
      place-items: center;
      text-align: center;
      padding: 6px;
      font-weight: 700;
    }}
    .trend-grid {{
      display: grid;
      gap: 8px;
      grid-template-columns: repeat(8, minmax(32px, 1fr));
      align-items: end;
      min-height: 170px;
      margin-top: 8px;
    }}
    .trend-col {{ text-align: center; }}
    .trend-bar {{
      width: 100%;
      border-radius: 9px 9px 4px 4px;
      background: linear-gradient(180deg, #38bdf8, #0284c7);
      min-height: 6px;
    }}
    .trend-label {{ font-size: .73rem; color: var(--muted); margin-top: 4px; }}
    .daily-line {{ margin-top: 10px; display: grid; gap: 8px; }}
    .daily-row {{ display: grid; gap: 8px; grid-template-columns: 100px 1fr 42px; align-items: center; }}
    .daily-track {{ height: 14px; border-radius: 999px; background: #e2e8f0; overflow: hidden; }}
    .daily-fill {{ height: 100%; background: linear-gradient(90deg, #7dd3fc, #0ea5e9); border-radius: 999px; }}
    #confetti-layer {{
      position: fixed;
      inset: 0;
      pointer-events: none;
      overflow: hidden;
      z-index: 9999;
    }}
    .confetti-piece {{
      position: absolute;
      width: 10px;
      height: 14px;
      border-radius: 2px;
      opacity: .95;
      animation: drop 1400ms ease-out forwards;
    }}
    @keyframes drop {{
      from {{ transform: translateY(-10vh) rotate(0deg); opacity: 1; }}
      to {{ transform: translateY(105vh) rotate(560deg); opacity: 0; }}
    }}
    @keyframes popin {{
      from {{ transform: translateY(6px) scale(.98); opacity: 0; }}
      to {{ transform: translateY(0) scale(1); opacity: 1; }}
    }}
    .card, .hero {{ animation: popin .3s ease-out; }}
    @media (max-width: 640px) {{
      .top {{ flex-direction: column; align-items: flex-start; }}
      .brand {{ flex-direction: column; align-items: flex-start; }}
      .logo-svg {{ max-width: 66vw; }}
      .wrap {{ padding: 12px 12px 86px; }}
      .card {{ padding: 10px 10px 11px; border-radius: 14px; }}
      .masthead {{ padding: 10px; border-radius: 18px; margin-bottom: 12px; }}
      h1 {{ font-size: 1.28rem; }}
      h2 {{ font-size: 1rem; margin: 4px 0 8px; }}
      h3 {{ font-size: .93rem; margin: 4px 0; }}
      .muted {{ font-size: .84rem; }}
      .small {{ font-size: .8rem; }}
      label {{ font-size: .84rem; }}
      input, select, textarea {{ font-size: .92rem; padding: 7px 8px; }}
      button {{ font-size: .9rem; padding: 9px 11px; min-height: 42px; }}
      th, td {{ font-size: .84rem; padding: 6px 4px; }}
      .row {{ gap: 5px; }}
      .row input, .row select {{ min-width: 120px; flex: 1 1 100%; }}
      .daily-row {{ grid-template-columns: 82px 1fr 36px; }}
      .trend-grid {{ grid-template-columns: repeat(4, minmax(40px, 1fr)); row-gap: 14px; }}
      .kpi-grid {{ grid-template-columns: repeat(2, minmax(130px, 1fr)); }}
      .mobile-nav {{ display: grid; }}
      .mobile-nav a {{ font-size: .79rem; }}
      details.mobile-details {{ margin-top: 6px; }}
      .row.action-row {{
        position: sticky;
        bottom: 0;
        background: linear-gradient(180deg, rgba(255,255,255,0), #ffffff 38%);
        padding-top: 8px;
      }}
    }}
  </style>
</head>
<body class="theme-{html_escape(theme)}" data-celebrate="{('yes' if celebrate else 'no')}">
  <div id="confetti-layer"></div>
  <div class=\"wrap\">
    <div class=\"masthead\">
      <div class=\"top\">
        <div class=\"brand\">
          {logo_svg}
          {dog_svg}
          <div class=\"brand-text\">
            <h1>{html_escape(app_name)}: {html_escape(child_name)}'s Tracker</h1>
            <div class=\"muted\">Daily check-ins, parent approvals, and reward levels.</div>
          </div>
        </div>
        {login_links}
      </div>
    </div>
    {notice_html}
    {body}
  </div>
  {mobile_nav}
  <script>
    if ('serviceWorker' in navigator) {{
      window.addEventListener('load', function() {{
        navigator.serviceWorker.register('/sw.js').catch(function() {{}});
      }});
    }}
    (function() {{
      var celebrate = document.body.getAttribute('data-celebrate') === 'yes';
      if (!celebrate) return;
      var layer = document.getElementById('confetti-layer');
      if (!layer) return;
      var colors = ['#22c55e', '#0ea5e9', '#f59e0b', '#ef4444', '#a78bfa', '#14b8a6'];
      for (var i = 0; i < 95; i++) {{
        var piece = document.createElement('div');
        piece.className = 'confetti-piece';
        piece.style.left = (Math.random() * 100) + 'vw';
        piece.style.background = colors[Math.floor(Math.random() * colors.length)];
        piece.style.animationDelay = (Math.random() * 350) + 'ms';
        piece.style.transform = 'translateY(-10vh) rotate(' + Math.floor(Math.random() * 360) + 'deg)';
        layer.appendChild(piece);
      }}
      setTimeout(function() {{ layer.innerHTML = ''; }}, 1700);
    }})();
  </script>
</body>
</html>
"""


def login_page(conn, notice=""):
    app_name = get_setting(conn, "app_name", "ANA-Quest")
    child_name = get_setting(conn, "child_name", "Anaaya")
    today_label = today_with_weekday()
    body = f"""
    <section class=\"hero\">
      <h2>Who is opening {html_escape(app_name)}?</h2>
      <div class=\"muted\">Choose a role and enter password.</div>
      <div class=\"small muted\" style=\"margin-top:6px\">Today: {today_label}</div>
    </section>
    <div class=\"card\" style=\"max-width: 420px\">
      <form method=\"POST\" action=\"/login\" class=\"stack\">
        <div>
          <label>Role</label>
          <select name=\"role\" required>
            <option value=\"child\">I am {html_escape(child_name)}</option>
            <option value=\"parent\">I am a parent</option>
          </select>
        </div>
        <div>
          <label>Password</label>
          <input type=\"password\" name=\"password\" required />
        </div>
        <button type=\"submit\">Enter</button>
      </form>
      <details class="mobile-details">
        <summary>Show details</summary>
        <p class=\"small muted\" style=\"margin:0\">Default passwords for first run: child <code>anaaya123</code>, parent <code>parent123</code>. Parent can change these in Settings.</p>
      </details>
      <a class=\"link-btn\" href=\"/progress\" style=\"margin-left:0\">View Progress Report</a>
    </div>
    """
    return render_layout("Login", None, child_name, app_name, body, notice)


def child_page(conn, notice=""):
    app_name = get_setting(conn, "app_name", "ANA-Quest")
    child_name = get_setting(conn, "child_name", "Anaaya")
    today = date.today().isoformat()
    today_label = date_with_weekday(today)
    week_start, week_end = current_week_range()

    goals = conn.execute(
        "SELECT * FROM goals WHERE active=1 ORDER BY sort_order, id"
    ).fetchall()
    rows = conn.execute(
        "SELECT * FROM entries WHERE day=?", (today,)
    ).fetchall()
    by_goal = {r["goal_id"]: r for r in rows}
    approved_today = sum(1 for r in rows if r["status"] == "approved")

    weekly_points = total_approved_points_for_week(conn, week_start, week_end)
    level = detect_level(conn, weekly_points)

    cards = []
    for goal in goals:
        entry = by_goal.get(goal["id"])
        status_html = ""
        form_html = ""
        button_text = "Send to Parent"

        if entry:
            detail_items = []
            status_html = (
                f"<div class='row'><span class='status {entry['status']}'>{entry['status'].title()}</span>"
                f"<span class='small muted'>Your choice: option {entry['selected_option']} ({entry['selected_points']} pts)</span></div>"
            )
            if entry["child_note"]:
                detail_items.append(f"<div class='small muted'>Your note: {html_escape(entry['child_note'])}</div>")
            if entry["status"] == "rejected" and entry["parent_note"]:
                detail_items.append(f"<div class='small' style='color:#b91c1c'>Parent note: {html_escape(entry['parent_note'])}</div>")
            if detail_items:
                status_html += "<details class='mobile-details'><summary>Show details</summary>" + "".join(detail_items) + "</details>"
            button_text = "Update and Resubmit"

        options = []
        selected_option = entry["selected_option"] if entry else 1
        current_note = html_escape(entry["child_note"]) if entry and entry["child_note"] else ""
        for idx in range(1, 5):
            label = goal[f"option{idx}_label"]
            points = goal[f"option{idx}_points"]
            selected_attr = " selected" if selected_option == idx else ""
            options.append(
                f"<option value='{idx}'{selected_attr}>{html_escape(label)} ({points} pts)</option>"
            )

        form_html = f"""
        <form method=\"POST\" action=\"/child/submit\" class=\"stack\">
          <input type=\"hidden\" name=\"goal_id\" value=\"{goal['id']}\" />
          <div>
            <label>Pick what happened</label>
            <select name=\"selected_option\" required>{''.join(options)}</select>
          </div>
          <div>
            <label>Quick note (optional)</label>
            <textarea name=\"child_note\" placeholder=\"Example: I finished lunch in 24 mins\">{current_note}</textarea>
          </div>
          <div class=\"row action-row\">
            <button type=\"submit\">{button_text}</button>
          </div>
        </form>
        """

        cards.append(
            f"""
            <div class=\"card\">
              <h3>{html_escape(goal['name'])}</h3>
              <div style=\"margin-top:8px\">{status_html or '<span class="small muted">No entry yet today.</span>'}</div>
              <div style=\"margin-top:8px\">{form_html}</div>
            </div>
            """
        )

    tiers = conn.execute(
        "SELECT level, min_points, reward_text FROM reward_tiers ORDER BY min_points ASC"
    ).fetchall()
    tier_rows = "".join(
        f"<tr><td><div class='tier-line'>{level_badge_svg(t['level'])}<strong>{t['level'].title()}</strong></div></td><td>{t['min_points']}</td><td>{html_escape(t['reward_text'])}</td></tr>"
        for t in tiers
    )
    level_badge = (
        f"<div class='badge-wrap'>{level_badge_svg(level)}<span>Current level: {level.title()}</span></div>"
        if level != "none"
        else "<div class='badge'>Current level: Not yet</div>"
    )

    body = f"""
    <section class=\"hero\">
      <div class=\"row\" style=\"justify-content: space-between\">
        <div>
          <div class=\"muted\">Today: {today_label}</div>
          <div><strong>This week's approved points:</strong> {weekly_points}</div>
        </div>
        <div>{level_badge}</div>
      </div>
    </section>

    <div class=\"grid\">{''.join(cards) if cards else '<div class="card">No active goals.</div>'}</div>

    <div class=\"card\" style=\"margin-top:12px\">
      <h2>Weekly Rewards</h2>
      <div class="table-scroll">
        <table>
          <tr><th>Level</th><th>Min points</th><th>Reward ideas</th></tr>
          {tier_rows}
        </table>
      </div>
    </div>
    """
    return render_layout("Child", "child", child_name, app_name, body, notice, celebrate=(approved_today > 0))


def parent_page(conn, notice=""):
    app_name = get_setting(conn, "app_name", "ANA-Quest")
    child_name = get_setting(conn, "child_name", "Anaaya")
    today = date.today().isoformat()
    today_label = date_with_weekday(today)
    week_start, week_end = current_week_range()

    pending = conn.execute(
        """
        SELECT e.id, e.day, g.name AS goal_name, e.selected_option, e.selected_points, e.child_note
        FROM entries e
        JOIN goals g ON g.id = e.goal_id
        WHERE e.status='pending'
        ORDER BY e.day DESC, e.id DESC
        """
    ).fetchall()

    goals = conn.execute("SELECT * FROM goals WHERE active=1 ORDER BY sort_order, id").fetchall()
    tiers = conn.execute(
        "SELECT level, min_points, reward_text FROM reward_tiers ORDER BY min_points ASC"
    ).fetchall()

    weekly_points = total_approved_points_for_week(conn, week_start, week_end)
    level = detect_level(conn, weekly_points)

    pending_rows = "".join(
        f"""
        <tr>
          <td>{date_with_weekday(p['day'])}</td>
          <td>{html_escape(p['goal_name'])}</td>
          <td>Option {p['selected_option']} ({p['selected_points']} pts)<details class='mobile-details'><summary>Show details</summary><span class='small muted'>{html_escape(p['child_note'])}</span></details></td>
          <td>
            <form method=\"POST\" action=\"/parent/review\" class=\"stack\">
              <input type=\"hidden\" name=\"entry_id\" value=\"{p['id']}\" />
              <input name=\"parent_note\" placeholder=\"Optional note\" />
              <div class=\"row action-row\">
                <button class=\"good\" name=\"status\" value=\"approved\" type=\"submit\">Approve</button>
                <button class=\"bad\" name=\"status\" value=\"rejected\" type=\"submit\">Reject</button>
              </div>
            </form>
          </td>
        </tr>
        """
        for p in pending
    )

    goal_cards = []
    for goal in goals:
        goal_cards.append(
            f"""
            <div class=\"card\">
              <h3>Edit Goal</h3>
              <form method=\"POST\" action=\"/parent/update-goal\" class=\"stack\">
                <input type=\"hidden\" name=\"goal_id\" value=\"{goal['id']}\" />
                <div>
                  <label>Goal name</label>
                  <input name=\"name\" value=\"{html_escape(goal['name'])}\" required />
                </div>
                <div class=\"small muted\">Option 1</div>
                <div class=\"row\">
                  <input name=\"option1_label\" value=\"{html_escape(goal['option1_label'])}\" required />
                  <input type=\"number\" name=\"option1_points\" value=\"{goal['option1_points']}\" required />
                </div>
                <div class=\"small muted\">Option 2</div>
                <div class=\"row\">
                  <input name=\"option2_label\" value=\"{html_escape(goal['option2_label'])}\" required />
                  <input type=\"number\" name=\"option2_points\" value=\"{goal['option2_points']}\" required />
                </div>
                <div class=\"small muted\">Option 3</div>
                <div class=\"row\">
                  <input name=\"option3_label\" value=\"{html_escape(goal['option3_label'])}\" required />
                  <input type=\"number\" name=\"option3_points\" value=\"{goal['option3_points']}\" required />
                </div>
                <div class=\"small muted\">Option 4</div>
                <div class=\"row\">
                  <input name=\"option4_label\" value=\"{html_escape(goal['option4_label'])}\" required />
                  <input type=\"number\" name=\"option4_points\" value=\"{goal['option4_points']}\" required />
                </div>
                <div class=\"row\">
                  <label class=\"small\">Sort order</label>
                  <input type=\"number\" name=\"sort_order\" value=\"{goal['sort_order']}\" required />
                </div>
                <button type=\"submit\">Save Goal</button>
              </form>
            </div>
            """
        )

    tier_rows = "".join(
        f"""
        <tr>
          <td><div class='tier-line'>{level_badge_svg(tier['level'])}<strong>{tier['level'].title()}</strong></div></td>
          <td><input form='tier-{tier['level']}' type='number' name='min_points' value='{tier['min_points']}' required /></td>
          <td><input form='tier-{tier['level']}' name='reward_text' value='{html_escape(tier['reward_text'])}' required /></td>
          <td>
            <form id='tier-{tier['level']}' method='POST' action='/parent/update-tier' class='row'>
              <input type='hidden' name='level' value='{tier['level']}' />
              <button type='submit'>Save</button>
            </form>
          </td>
        </tr>
        """
        for tier in tiers
    )
    level_badge = (
        f"<div class='badge-wrap'>{level_badge_svg(level)}<span>Current level: {level.title()}</span></div>"
        if level != "none"
        else "<div class='badge'>Current level: Not yet</div>"
    )

    body = f"""
    <section class=\"hero\">
      <div class=\"row\" style=\"justify-content: space-between\">
        <div>
          <div class=\"muted\">Today: {today_label}</div>
          <div><strong>This week's approved points:</strong> {weekly_points}</div>
        </div>
        <div>{level_badge}</div>
      </div>
    </section>

    <div class=\"card\">
      <h2>Pending Submissions</h2>
      <div class="table-scroll">
        <table>
          <tr><th>Date</th><th>Goal</th><th>Anaaya chose</th><th>Action</th></tr>
          {pending_rows or "<tr><td colspan='4' class='muted'>No pending submissions.</td></tr>"}
        </table>
      </div>
    </div>

    <div class=\"card\" style=\"margin-top:12px\">
      <h2>Reward Tier Settings</h2>
      <div class="table-scroll">
        <table>
          <tr><th>Level</th><th>Min points</th><th>Reward text</th><th>Save</th></tr>
          {tier_rows}
        </table>
      </div>
    </div>

    <div class=\"card\" style=\"margin-top:12px\">
      <h2>General Settings</h2>
      <div class=\"grid\">
        <div class=\"card\" style=\"margin:0\">
          <h3>Names</h3>
          <form method=\"POST\" action=\"/parent/update-settings\" class=\"stack\">
            <label>App name</label>
            <input name=\"app_name\" value=\"{html_escape(app_name)}\" required />
            <label>Child name</label>
            <input name=\"child_name\" value=\"{html_escape(child_name)}\" required />
            <button type=\"submit\">Save Names</button>
          </form>
        </div>
        <div class=\"card\" style=\"margin:0\">
          <h3>Passwords</h3>
          <form method=\"POST\" action=\"/parent/update-password\" class=\"stack\">
            <label>Whose password to change?</label>
            <select name=\"role\" required>
              <option value=\"child\">Child password</option>
              <option value=\"parent\">Parent password</option>
            </select>
            <label>New password</label>
            <input type=\"password\" name=\"new_password\" minlength=\"4\" required />
            <button type=\"submit\">Save Password</button>
          </form>
        </div>
      </div>
    </div>

    <div class=\"card\" style=\"margin-top:12px; border-color:#fecaca; background:#fff7f7\">
      <h2>Reset Progress</h2>
      <p class=\"small muted\">This clears all submitted progress history and starts fresh. Goals, reward tiers, names, and passwords stay unchanged.</p>
      <form method=\"POST\" action=\"/parent/reset-progress\" onsubmit=\"return confirm('Reset all progress and start fresh?');\">
        <button class=\"bad\" type=\"submit\">Reset All Progress</button>
      </form>
    </div>

    <h2 style=\"margin-top:14px\">Goal Settings</h2>
    <div class=\"grid\">{''.join(goal_cards)}</div>

    <div class=\"card\" style=\"margin-top:12px\">
      <h3>Add a new goal</h3>
      <form method=\"POST\" action=\"/parent/add-goal\" class=\"stack\">
        <input name=\"name\" placeholder=\"Goal name\" required />
        <div class=\"row\"><input name=\"option1_label\" placeholder=\"Option 1 label\" required /><input type=\"number\" name=\"option1_points\" value=\"20\" required /></div>
        <div class=\"row\"><input name=\"option2_label\" placeholder=\"Option 2 label\" required /><input type=\"number\" name=\"option2_points\" value=\"10\" required /></div>
        <div class=\"row\"><input name=\"option3_label\" placeholder=\"Option 3 label\" required /><input type=\"number\" name=\"option3_points\" value=\"0\" required /></div>
        <div class=\"row\"><input name=\"option4_label\" placeholder=\"Option 4 label\" required /><input type=\"number\" name=\"option4_points\" value=\"-10\" required /></div>
        <input type=\"number\" name=\"sort_order\" value=\"99\" required />
        <button type=\"submit\">Add Goal</button>
      </form>
    </div>
    """

    return render_layout("Parent", "parent", child_name, app_name, body, notice)


def progress_page(conn, role=None, notice=""):
    app_name = get_setting(conn, "app_name", "ANA-Quest")
    child_name = get_setting(conn, "child_name", "Anaaya")
    today_label = today_with_weekday()
    week_start, week_end = current_week_range()

    goal_rows = conn.execute("SELECT * FROM goals WHERE active=1").fetchall()
    max_daily_points = 0
    for g in goal_rows:
        max_daily_points += max(
            g["option1_points"], g["option2_points"], g["option3_points"], g["option4_points"]
        )
    max_weekly_points = max(1, max_daily_points * 7)

    week_points = total_approved_points_for_week(conn, week_start, week_end)
    ratio = week_points / max_weekly_points if max_weekly_points else 0.0
    ratio = min(1.5, max(-0.5, ratio))
    ratio_for_ui = max(0.0, min(1.0, ratio))
    progress_pct = int(ratio_for_ui * 100)

    if ratio_for_ui >= 0.85:
        theme = "progress-great"
        mood = "Amazing week. Celebration mode!"
        celebrate = True
    elif ratio_for_ui >= 0.60:
        theme = "progress-good"
        mood = "Strong progress. Keep the streak going."
        celebrate = False
    elif ratio_for_ui >= 0.35:
        theme = "progress-medium"
        mood = "Good effort. One more push to level up."
        celebrate = False
    else:
        theme = "progress-low"
        mood = "Fresh start zone. Small wins build momentum."
        celebrate = False

    status_counts = conn.execute(
        """
        SELECT
          COALESCE(SUM(CASE WHEN status='approved' THEN 1 ELSE 0 END), 0) AS approved_count,
          COALESCE(SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END), 0) AS pending_count,
          COALESCE(SUM(CASE WHEN status='rejected' THEN 1 ELSE 0 END), 0) AS rejected_count
        FROM entries
        WHERE day BETWEEN ? AND ?
        """,
        (week_start, week_end),
    ).fetchone()

    day_points_rows = conn.execute(
        """
        SELECT day, COALESCE(SUM(selected_points), 0) AS pts
        FROM entries
        WHERE status='approved' AND day BETWEEN ? AND ?
        GROUP BY day
        ORDER BY day
        """,
        (week_start, week_end),
    ).fetchall()
    day_points_map = {r["day"]: int(r["pts"] or 0) for r in day_points_rows}

    monday = date.fromisoformat(week_start)
    week_days = [(monday + timedelta(days=i)).isoformat() for i in range(7)]
    max_daily_visual = max(1, max(max_daily_points, max(day_points_map.values(), default=0)))
    daily_rows_html = []
    for iso_day in week_days:
        pts = day_points_map.get(iso_day, 0)
        bar_pct = int((max(0, pts) / max_daily_visual) * 100)
        daily_rows_html.append(
            f"""
            <div class="daily-row">
              <div class="small">{weekday_name_from_iso(iso_day)}</div>
              <div class="daily-track"><div class="daily-fill" style="width:{bar_pct}%"></div></div>
              <div class="small"><strong>{pts}</strong></div>
            </div>
            """
        )

    current_monday = date.fromisoformat(week_start)
    trend_points = []
    for offset in range(7, -1, -1):
        ws = current_monday - timedelta(days=offset * 7)
        we = ws + timedelta(days=6)
        pts = total_approved_points_for_week(conn, ws.isoformat(), we.isoformat())
        trend_points.append((ws.isoformat(), pts))

    trend_max = max(1, max(p for _, p in trend_points))
    trend_cols = []
    for ws, pts in trend_points:
        h = max(6, int((max(0, pts) / trend_max) * 130))
        label = date.fromisoformat(ws).strftime("%b %d")
        trend_cols.append(
            f"""
            <div class="trend-col">
              <div class="small"><strong>{pts}</strong></div>
              <div class="trend-bar" style="height:{h}px"></div>
              <div class="trend-label">{label}</div>
            </div>
            """
        )

    prev_week_start = (current_monday - timedelta(days=7)).isoformat()
    prev_week_end = (current_monday - timedelta(days=1)).isoformat()
    prev_points = total_approved_points_for_week(conn, prev_week_start, prev_week_end)
    delta = week_points - prev_points
    delta_sign = "+" if delta >= 0 else ""

    level = detect_level(conn, week_points)
    level_badge = (
        f"<div class='badge-wrap'>{level_badge_svg(level)}<span>Current level: {level.title()}</span></div>"
        if level != "none"
        else "<div class='badge'>Current level: Not yet</div>"
    )

    body = f"""
    <section class="hero">
      <div class="row" style="justify-content: space-between">
        <div>
          <h2 style="margin:0">Progress Report</h2>
          <div class="muted">Today: {today_label}</div>
          <div class="muted">Week: {date_with_weekday(week_start)} to {date_with_weekday(week_end)}</div>
        </div>
        <div>{level_badge}</div>
      </div>
    </section>

    <div class="grid">
      <div class="card">
        <h3>Weekly Score</h3>
        <div class="progress-ring" style="--pct:{progress_pct}">
          <div class="progress-ring-inner">
            <div>{progress_pct}%</div>
            <div class="small muted">of weekly max</div>
          </div>
        </div>
        <div class="small" style="text-align:center"><strong>{week_points}</strong> / {max_weekly_points} points</div>
        <details class="mobile-details" style="margin-top:8px">
          <summary>Show details</summary>
          <div class="small muted">{mood}</div>
        </details>
      </div>

      <div class="card">
        <h3>Week Snapshot</h3>
        <div class="kpi-grid">
          <div class="kpi"><strong>{status_counts['approved_count']}</strong><span>Approved</span></div>
          <div class="kpi"><strong>{status_counts['pending_count']}</strong><span>Pending</span></div>
          <div class="kpi"><strong>{status_counts['rejected_count']}</strong><span>Rejected</span></div>
          <div class="kpi"><strong>{delta_sign}{delta}</strong><span>vs previous week</span></div>
        </div>
      </div>
    </div>

    <div class="card" style="margin-top:12px">
      <h3>This Week by Day</h3>
      <div class="daily-line">{''.join(daily_rows_html)}</div>
    </div>

    <div class="card" style="margin-top:12px">
      <h3>Week-on-Week Trend (8 weeks)</h3>
      <div class="trend-grid">{''.join(trend_cols)}</div>
    </div>
    """
    return render_layout(
        "Progress Report",
        role,
        child_name,
        app_name,
        body,
        notice,
        celebrate=celebrate,
        theme=theme,
    )


class HabitHandler(BaseHTTPRequestHandler):
    def _cookie_flags(self):
        flags = "Path=/; HttpOnly; SameSite=Lax"
        if SECURE_COOKIES:
            flags += "; Secure"
        return flags

    def _respond_bytes(self, data, content_type="text/plain; charset=utf-8", status=200, cookie_header=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        if cookie_header:
            self.send_header("Set-Cookie", cookie_header)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _respond_html(self, html, status=200, cookie_header=None):
        data = html.encode("utf-8")
        self._respond_bytes(data, "text/html; charset=utf-8", status=status, cookie_header=cookie_header)

    def _redirect(self, location, cookie_header=None):
        self.send_response(303)
        self.send_header("Location", location)
        if cookie_header:
            self.send_header("Set-Cookie", cookie_header)
        self.end_headers()

    def _parse_form(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8")
        return parse_qs(raw)

    def _session_role(self):
        raw_cookie = self.headers.get("Cookie", "")
        jar = cookies.SimpleCookie()
        jar.load(raw_cookie)
        morsel = jar.get(SESSION_COOKIE)
        if not morsel:
            return None
        return parse_session_token(morsel.value)

    def _require_role(self, required_role):
        role = self._session_role()
        if role != required_role:
            self._redirect("/")
            return None
        return role

    def _int_value(self, data, key, default=0):
        try:
            return int(data.get(key, [str(default)])[0])
        except Exception:
            return default

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        conn = db_conn()
        try:
            if path == "/manifest.webmanifest":
                self._respond_bytes(
                    json.dumps(PWA_MANIFEST).encode("utf-8"),
                    content_type="application/manifest+json; charset=utf-8",
                )
                return

            if path == "/sw.js":
                self._respond_bytes(
                    PWA_SW_JS.encode("utf-8"),
                    content_type="application/javascript; charset=utf-8",
                )
                return

            if path == "/icon.svg":
                self._respond_bytes(
                    PWA_ICON_SVG.encode("utf-8"),
                    content_type="image/svg+xml; charset=utf-8",
                )
                return

            if path == "/health":
                self._respond_bytes(b"ok", content_type="text/plain; charset=utf-8")
                return

            if path == "/":
                role = self._session_role()
                if role == "child":
                    self._redirect("/child")
                    return
                if role == "parent":
                    self._redirect("/parent")
                    return
                self._respond_html(login_page(conn))
                return

            if path == "/logout":
                clear_cookie = f"{SESSION_COOKIE}=; Max-Age=0; {self._cookie_flags()}"
                self._redirect("/", cookie_header=clear_cookie)
                return

            if path == "/child":
                if not self._require_role("child"):
                    return
                self._respond_html(child_page(conn))
                return

            if path == "/parent":
                if not self._require_role("parent"):
                    return
                self._respond_html(parent_page(conn))
                return

            if path == "/progress":
                self._respond_html(progress_page(conn, role=self._session_role()))
                return

            self._respond_html(render_layout("404", None, "Anaaya", "ANA-Quest", "<h2>Not found</h2>"), status=404)
        finally:
            conn.close()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        data = self._parse_form()

        conn = db_conn()
        cur = conn.cursor()
        now = utc_now_iso()

        try:
            if path == "/login":
                role = data.get("role", [""])[0]
                password = data.get("password", [""])[0]

                if role not in ("child", "parent"):
                    self._respond_html(login_page(conn, "Choose a valid role."), status=400)
                    return

                row = cur.execute("SELECT password_hash FROM users WHERE role=?", (role,)).fetchone()
                if not row or not verify_password(password, row["password_hash"]):
                    self._respond_html(login_page(conn, "Wrong password. Please try again."), status=401)
                    return

                token = make_session_token(role)
                cookie_header = f"{SESSION_COOKIE}={token}; Max-Age={SESSION_TTL_SECONDS}; {self._cookie_flags()}"
                self._redirect("/child" if role == "child" else "/parent", cookie_header=cookie_header)
                return

            if path == "/child/submit":
                if not self._session_role() == "child":
                    self._redirect("/")
                    return

                goal_id = self._int_value(data, "goal_id")
                selected_option = self._int_value(data, "selected_option", 1)
                child_note = data.get("child_note", [""])[0].strip()

                goal = cur.execute("SELECT * FROM goals WHERE id=? AND active=1", (goal_id,)).fetchone()
                if not goal:
                    self._redirect("/child")
                    return
                if selected_option < 1 or selected_option > 4:
                    selected_option = 1

                points = goal[f"option{selected_option}_points"]
                today = date.today().isoformat()

                cur.execute(
                    """
                    INSERT INTO entries(goal_id, day, selected_option, selected_points, child_note, status, parent_note, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, 'pending', '', ?, ?)
                    ON CONFLICT(goal_id, day) DO UPDATE SET
                      selected_option=excluded.selected_option,
                      selected_points=excluded.selected_points,
                      child_note=excluded.child_note,
                      status='pending',
                      parent_note='',
                      updated_at=excluded.updated_at
                    """,
                    (goal_id, today, selected_option, points, child_note[:500], now, now),
                )
                conn.commit()
                self._redirect("/child")
                return

            if path == "/parent/review":
                if not self._session_role() == "parent":
                    self._redirect("/")
                    return

                entry_id = self._int_value(data, "entry_id")
                status = data.get("status", [""])[0]
                parent_note = data.get("parent_note", [""])[0].strip()[:500]
                if status in ("approved", "rejected"):
                    cur.execute(
                        "UPDATE entries SET status=?, parent_note=?, updated_at=? WHERE id=?",
                        (status, parent_note, now, entry_id),
                    )
                    conn.commit()
                self._redirect("/parent")
                return

            if path == "/parent/update-goal":
                if not self._session_role() == "parent":
                    self._redirect("/")
                    return

                goal_id = self._int_value(data, "goal_id")
                name = data.get("name", [""])[0].strip()
                if not name:
                    self._redirect("/parent")
                    return

                fields = {
                    "name": name,
                    "option1_label": data.get("option1_label", [""])[0].strip() or "Option 1",
                    "option1_points": self._int_value(data, "option1_points", 20),
                    "option2_label": data.get("option2_label", [""])[0].strip() or "Option 2",
                    "option2_points": self._int_value(data, "option2_points", 10),
                    "option3_label": data.get("option3_label", [""])[0].strip() or "Option 3",
                    "option3_points": self._int_value(data, "option3_points", 0),
                    "option4_label": data.get("option4_label", [""])[0].strip() or "Option 4",
                    "option4_points": self._int_value(data, "option4_points", -10),
                    "sort_order": self._int_value(data, "sort_order", 99),
                }

                cur.execute(
                    """
                    UPDATE goals
                    SET name=?,
                        option1_label=?, option1_points=?,
                        option2_label=?, option2_points=?,
                        option3_label=?, option3_points=?,
                        option4_label=?, option4_points=?,
                        sort_order=?,
                        updated_at=?
                    WHERE id=?
                    """,
                    (
                        fields["name"],
                        fields["option1_label"],
                        fields["option1_points"],
                        fields["option2_label"],
                        fields["option2_points"],
                        fields["option3_label"],
                        fields["option3_points"],
                        fields["option4_label"],
                        fields["option4_points"],
                        fields["sort_order"],
                        now,
                        goal_id,
                    ),
                )
                conn.commit()
                self._redirect("/parent")
                return

            if path == "/parent/add-goal":
                if not self._session_role() == "parent":
                    self._redirect("/")
                    return

                name = data.get("name", [""])[0].strip()
                if not name:
                    self._redirect("/parent")
                    return

                vals = (
                    name,
                    data.get("option1_label", [""])[0].strip() or "Option 1",
                    self._int_value(data, "option1_points", 20),
                    data.get("option2_label", [""])[0].strip() or "Option 2",
                    self._int_value(data, "option2_points", 10),
                    data.get("option3_label", [""])[0].strip() or "Option 3",
                    self._int_value(data, "option3_points", 0),
                    data.get("option4_label", [""])[0].strip() or "Option 4",
                    self._int_value(data, "option4_points", -10),
                    self._int_value(data, "sort_order", 99),
                    now,
                    now,
                )
                cur.execute(
                    """
                    INSERT INTO goals(
                      name,
                      option1_label, option1_points,
                      option2_label, option2_points,
                      option3_label, option3_points,
                      option4_label, option4_points,
                      sort_order, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    vals,
                )
                conn.commit()
                self._redirect("/parent")
                return

            if path == "/parent/update-tier":
                if not self._session_role() == "parent":
                    self._redirect("/")
                    return

                level = data.get("level", [""])[0]
                min_points = self._int_value(data, "min_points", 0)
                reward_text = data.get("reward_text", [""])[0].strip()
                if level in ("bronze", "silver", "gold") and reward_text:
                    cur.execute(
                        "UPDATE reward_tiers SET min_points=?, reward_text=?, updated_at=? WHERE level=?",
                        (min_points, reward_text[:200], now, level),
                    )
                    conn.commit()
                self._redirect("/parent")
                return

            if path == "/parent/update-settings":
                if not self._session_role() == "parent":
                    self._redirect("/")
                    return

                app_name = data.get("app_name", [""])[0].strip() or "ANA-Quest"
                child_name = data.get("child_name", [""])[0].strip() or "Anaaya"
                cur.execute(
                    "INSERT INTO app_settings(key, value) VALUES('app_name', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (app_name[:80],),
                )
                cur.execute(
                    "INSERT INTO app_settings(key, value) VALUES('child_name', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (child_name[:80],),
                )
                conn.commit()
                self._redirect("/parent")
                return

            if path == "/parent/update-password":
                if not self._session_role() == "parent":
                    self._redirect("/")
                    return

                role = data.get("role", [""])[0]
                new_password = data.get("new_password", [""])[0]
                if role in ("child", "parent") and len(new_password) >= 4:
                    cur.execute(
                        "UPDATE users SET password_hash=?, updated_at=? WHERE role=?",
                        (hash_password(new_password), now, role),
                    )
                    conn.commit()
                self._redirect("/parent")
                return

            if path == "/parent/reset-progress":
                if not self._session_role() == "parent":
                    self._redirect("/")
                    return
                cur.execute("DELETE FROM entries")
                conn.commit()
                self._redirect("/parent")
                return

            self._respond_html(render_layout("404", None, "Anaaya", "ANA-Quest", "<h2>Not found</h2>"), status=404)
        finally:
            conn.close()


def main():
    init_db()
    server = HTTPServer((HOST, PORT), HabitHandler)
    print(f"ANA-Quest running on {HOST}:{PORT}")
    print(f"- Desktop: http://127.0.0.1:{PORT}")
    print("- Mobile (same Wi-Fi): http://<your-laptop-lan-ip>:8000")
    print("Default login passwords (change in Parent Settings):")
    print("- Child: anaaya123")
    print("- Parent: parent123")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

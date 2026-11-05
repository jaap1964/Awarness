from __future__ import annotations

import csv
import hashlib
import io
import os
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator
from urllib.parse import quote

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, SignatureExpired, TimestampSigner
from passlib.context import CryptContext
from starlette.middleware.sessions import SessionMiddleware

BASE = Path(__file__).resolve().parent
load_dotenv(BASE / ".env")

APP_SECRET = os.getenv("APP_SECRET", "")
ADMIN_PASSWORD_HASH = os.getenv("ADMIN_PASSWORD_HASH", "")
DATABASE_PATH = os.getenv("DATABASE_PATH", str(BASE / "data" / "awareness.db"))
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
if len(APP_SECRET) < 32:
    raise RuntimeError("APP_SECRET must be set to a random value of at least 32 characters in .env")
if not ADMIN_PASSWORD_HASH:
    raise RuntimeError("ADMIN_PASSWORD_HASH is missing. Follow the setup steps in README.md.")

app = FastAPI(title="Awareness Lab", docs_url=None, redoc_url=None)
app.add_middleware(SessionMiddleware, secret_key=APP_SECRET, session_cookie="awareness_admin",
                   https_only=COOKIE_SECURE, same_site="lax", max_age=60 * 60 * 8)
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")
templates = Jinja2Templates(directory=BASE / "templates")
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
signer = TimestampSigner(APP_SECRET)


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@contextmanager
def db() -> Iterator[sqlite3.Connection]:
    Path(DATABASE_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DATABASE_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS campaigns (
          id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
          created_at TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS participants (
          id INTEGER PRIMARY KEY AUTOINCREMENT, campaign_id INTEGER NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
          code TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL,
          UNIQUE(campaign_id, code)
        );
        CREATE TABLE IF NOT EXISTS events (
          id INTEGER PRIMARY KEY AUTOINCREMENT, participant_id INTEGER NOT NULL REFERENCES participants(id) ON DELETE CASCADE,
          kind TEXT NOT NULL CHECK(kind IN ('scanner_preview','unconfirmed_visit','confirmed')), created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS events_participant_idx ON events(participant_id);
        """)


@app.on_event("startup")
def startup() -> None:
    init_db()


def csrf_token(request: Request) -> str:
    token = request.session.get("csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf"] = token
    return token


def require_admin(request: Request) -> None:
    if request.session.get("admin") is not True:
        raise HTTPException(status_code=303, headers={"Location": "/login"})


def check_csrf(request: Request, submitted: str) -> None:
    expected = request.session.get("csrf", "")
    if not expected or not secrets.compare_digest(expected, submitted):
        raise HTTPException(status_code=403, detail="Ongeldig beveiligingstoken. Vernieuw de pagina.")


def render(request: Request, template: str, **context):
    return templates.TemplateResponse(request=request, name=template,
        context={"csrf": csrf_token(request), **context})


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    if request.session.get("admin"):
        return RedirectResponse("/admin", status_code=303)
    return RedirectResponse("/login", status_code=303)


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    if request.session.get("admin"):
        return RedirectResponse("/admin", status_code=303)
    return render(request, "login.html", error=None)


@app.post("/login", response_class=HTMLResponse)
def login(request: Request, password: str = Form(...), csrf: str = Form(...)):
    check_csrf(request, csrf)
    if len(password) > 1024 or not pwd_context.verify(password, ADMIN_PASSWORD_HASH):
        return render(request, "login.html", error="Inloggen is niet gelukt.")
    request.session.clear()
    request.session["admin"] = True
    request.session["csrf"] = secrets.token_urlsafe(32)
    return RedirectResponse("/admin", status_code=303)


@app.post("/logout")
def logout(request: Request, csrf: str = Form(...)):
    check_csrf(request, csrf)
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


@app.get("/admin", response_class=HTMLResponse, dependencies=[Depends(require_admin)])
def dashboard(request: Request):
    with db() as conn:
        campaigns = conn.execute("""
          SELECT c.id, c.name, c.created_at, c.active, COUNT(DISTINCT p.id) AS participants,
          COUNT(DISTINCT CASE WHEN e.kind='confirmed' THEN p.id END) AS confirmed,
          COUNT(DISTINCT CASE WHEN e.kind IN ('scanner_preview','unconfirmed_visit') THEN p.id END) AS previews
          FROM campaigns c LEFT JOIN participants p ON p.campaign_id=c.id
          LEFT JOIN events e ON e.participant_id=p.id GROUP BY c.id ORDER BY c.id DESC
        """).fetchall()
    return render(request, "dashboard.html", campaigns=campaigns, links=None, notice=None)


@app.post("/campaigns", dependencies=[Depends(require_admin)])
def create_campaign(request: Request, name: str = Form(...), count: int = Form(...),
                    csrf: str = Form(...)):
    check_csrf(request, csrf)
    name = name.strip()
    if not name or len(name) > 100 or not 1 <= count <= 500:
        raise HTTPException(status_code=400, detail="Gebruik een campagnenaam van 1–100 tekens en 1–500 deelnemers.")
    links = []
    with db() as conn:
        cur = conn.execute("INSERT INTO campaigns(name, created_at) VALUES(?, ?)", (name, now()))
        campaign_id = cur.lastrowid
        for number in range(1, count + 1):
            token = secrets.token_urlsafe(32)
            code = f"P{number:04d}"
            conn.execute("INSERT INTO participants(campaign_id, code, token_hash, created_at) VALUES(?,?,?,?)",
                         (campaign_id, code, digest(token), now()))
            links.append({"code": code, "url": f"{PUBLIC_BASE_URL}/r/{quote(token)}"})
        campaigns = conn.execute("""
          SELECT c.id,c.name,c.created_at,c.active,COUNT(DISTINCT p.id) participants,
          COUNT(DISTINCT CASE WHEN e.kind='confirmed' THEN p.id END) confirmed,
          COUNT(DISTINCT CASE WHEN e.kind IN ('scanner_preview','unconfirmed_visit') THEN p.id END) previews
          FROM campaigns c LEFT JOIN participants p ON p.campaign_id=c.id
          LEFT JOIN events e ON e.participant_id=p.id GROUP BY c.id ORDER BY c.id DESC
        """).fetchall()
    return render(request, "dashboard.html", campaigns=campaigns, links=links, notice="Bewaar of download deze links nu. Ze worden later niet opnieuw getoond.")


@app.post("/campaigns/{campaign_id}/toggle", dependencies=[Depends(require_admin)])
def toggle_campaign(campaign_id: int, request: Request, csrf: str = Form(...)):
    check_csrf(request, csrf)
    with db() as conn:
        conn.execute("UPDATE campaigns SET active = 1-active WHERE id=?", (campaign_id,))
    return RedirectResponse("/admin", status_code=303)


@app.get("/campaigns/{campaign_id}/export.csv", dependencies=[Depends(require_admin)])
def export_campaign(campaign_id: int):
    with db() as conn:
        campaign = conn.execute("SELECT name FROM campaigns WHERE id=?", (campaign_id,)).fetchone()
        if not campaign:
            raise HTTPException(404)
        rows = conn.execute("""
          SELECT p.code,
          MAX(CASE WHEN e.kind IN ('scanner_preview','unconfirmed_visit') THEN 1 ELSE 0 END) AS scanner_preview,
          MAX(CASE WHEN e.kind='confirmed' THEN 1 ELSE 0 END) AS confirmed_human_click
          FROM participants p LEFT JOIN events e ON e.participant_id=p.id
          WHERE p.campaign_id=? GROUP BY p.id ORDER BY p.code
        """, (campaign_id,)).fetchall()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["participant_code", "known_scanner_user_agent", "unconfirmed_page_request", "browser_confirmed_open"])
    writer.writerows((r["code"], r["scanner_preview"], r["unconfirmed_page_request"], r["confirmed_human_click"]) for r in rows)
    filename = f"awareness-campaign-{campaign_id}.csv"
    return Response(output.getvalue(), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})


def participant_for(token: str):
    with db() as conn:
        return conn.execute("""
          SELECT p.id, p.code, p.campaign_id, c.active FROM participants p
          JOIN campaigns c ON c.id=p.campaign_id WHERE p.token_hash=?
        """, (digest(token),)).fetchone()


@app.get("/r/{token}", response_class=HTMLResponse)
def redirect_link(token: str, request: Request):
    participant = participant_for(token)
    if not participant or not participant["active"]:
        raise HTTPException(404, "Deze campagnelink is niet beschikbaar.")
    ua = request.headers.get("user-agent", "").lower()
    scanner_words = ("bot", "spider", "crawler", "preview", "scanner", "headless", "curl", "wget")
    kind = "scanner_preview" if any(word in ua for word in scanner_words) else "unconfirmed_visit"
    with db() as conn:
        conn.execute("INSERT INTO events(participant_id, kind, created_at) VALUES(?,?,?)",
                     (participant["id"], kind, now()))
    beacon = f'<script src="/static/confirm.js" defer></script><span id="tracking" data-token="{token}"></span>'
    return HTMLResponse(
        '<!doctype html><html lang="nl"><meta charset="utf-8"><meta name="viewport" content="width=device-width">'
        '<link rel="stylesheet" href="/static/app.css"><title>Veiligheidsmelding</title><main class="card">'
        '<p class="eyebrow">Bewustwordingsoefening</p><h1>Je hebt een link uit een simulatie geopend</h1>'
        '<p>Er zijn geen wachtwoorden of andere gegevens gevraagd of opgeslagen. Dit was een oefening.</p>'
        '<h2>Zo herken je verdachte berichten</h2><ul><li>Controleer de afzender en het webadres.</li>'
        '<li>Wees alert op onverwachte druk of verzoeken.</li><li>Open bij twijfel de bekende website zelf.</li>'
        '<li>Meld verdachte berichten bij je organisatie.</li></ul><p class="muted">Deze pagina registreert alleen een pseudonieme campagnecode.</p>'
        + beacon + '</main></html>',
        headers={"Referrer-Policy": "no-referrer"})


@app.post("/r/{token}/confirm")
def confirm_click(token: str):
    participant = participant_for(token)
    if not participant or not participant["active"]:
        raise HTTPException(404)
    with db() as conn:
        conn.execute("INSERT INTO events(participant_id, kind, created_at) VALUES(?,?,?)",
                     (participant["id"], "confirmed", now()))
    return PlainTextResponse("ok")


@app.get("/health")
def health():
    return PlainTextResponse("ok")

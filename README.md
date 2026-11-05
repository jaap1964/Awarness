# Awareness Lab (Windows)

A local-first, Dutch phishing-awareness simulation manager. It creates campaigns and pseudonymous participant codes, displays unique links once, records privacy-minimized events, and exports aggregate-by-code CSV reports. It has **no email sending** and never asks for or stores credentials.

## Requirements

Windows 10/11, Python 3.11 or newer, and PowerShell. Keep the service on this computer or a trusted private network. Do not expose it to the internet as-is.

## Install and start

Open PowerShell in this repository:

1. Create and activate a virtual environment:

   ```powershell
   py -3 -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

   If PowerShell blocks activation, run `Set-ExecutionPolicy -Scope Process Bypass` in that same window, then activate again.

2. Install packages:

   ```powershell
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   ```

3. Create local configuration and secrets:

   ```powershell
   Copy-Item .env.example .env
   $secret = python -c "import secrets; print(secrets.token_urlsafe(48))"
   $hash = python -c "from getpass import getpass; from passlib.context import CryptContext; print(CryptContext(schemes=['argon2']).hash(getpass('New admin password: ')))"
   (Get-Content .env) -replace '^APP_SECRET=.*', "APP_SECRET=$secret" -replace '^ADMIN_PASSWORD_HASH=.*', "ADMIN_PASSWORD_HASH=$hash" | Set-Content .env
   ```

   Choose a unique password. The password is entered hidden and only its Argon2 hash is saved. Keep `.env` private; it is excluded from Git.

4. Start the local server:

   ```powershell
   .\.venv\Scripts\Activate.ps1
   python -m uvicorn app:app --host 127.0.0.1 --port 8000
   ```

5. Open [http://127.0.0.1:8000](http://127.0.0.1:8000) and sign in with your new admin password. Stop with Ctrl+C.

## Use

Create a campaign and set a participant count (1–500). The app generates pseudonymous codes (P0001…) and unique random links. Save the one-time link list from the dashboard before navigating away; it is not stored in plaintext and cannot be reconstructed. Share links manually only as part of an authorized internal exercise. Pause a campaign to disable its links. Download per-code CSV reports from the dashboard.

The event model distinguishes link previews from browser-confirmed opens. A scanner GET is recorded as a possible preview. A same-origin JavaScript POST records a confirmed open. Some security scanners execute JavaScript, and some users block it, so this is a best-effort indicator, not proof of a human click.

## Privacy and security

- No names, email addresses, passwords, IP addresses, or user-agent strings are persisted.
- Participant URLs contain random bearer tokens; only SHA-256 token digests are stored. Treat issued URLs as confidential.
- Admin password verification uses Argon2. Admin sessions are signed, HTTP-only, SameSite=Lax and expire after eight hours. CSRF tokens protect state-changing forms.
- SQLite is created at `data/awareness.db`; back up the database securely. CSV reports contain pseudonymous codes and event flags.
- Locally generated setup values are secrets. Never commit `.env`, real participant links, or database files.
- Default binding is loopback only. If you intentionally use a trusted HTTPS reverse proxy, set `PUBLIC_BASE_URL` to its HTTPS URL and `COOKIE_SECURE=true`; configure TLS and access controls at the proxy.
- This is a local awareness aid, not a production multi-tenant platform. Obtain organizational authorization and tell participants about the exercise as appropriate.

## Tests

Run the included tests from the activated virtual environment:

```powershell
pytest -q
```

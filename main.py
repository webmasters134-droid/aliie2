"""
DL Tracker - API server

Runs next to PostgreSQL on the office machine. Serves the web app and the
JSON endpoints the browser and the licence-office phone talk to.

    pip install fastapi uvicorn psycopg2-binary
    python main.py password                   # store the database password once
    python main.py check                      # is PostgreSQL reachable?
    python main.py initdb                     # creates the database and the tables
    python main.py adduser ali@x.com "Ali" Admin        # asks for a password
    python main.py serve                      # http://0.0.0.0:8000
    python main.py reset                      # wipes practice data, keeps accounts

Nothing else is required: passwords use pbkdf2 from the standard library
and sessions are opaque tokens in a table, so there is no extra crypto or
token package to install.
"""

import base64
import getpass
import hashlib
import hmac
import json
import os
import secrets
import sys
from contextlib import contextmanager
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import psycopg2
import psycopg2.extras
from psycopg2.pool import ThreadedConnectionPool

from fastapi import Body, Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

# ---------------------------------------------------------------------------
# Configuration - edit here, or set the environment variables instead
# ---------------------------------------------------------------------------

BUILD = "2026-09-07"          # printed by "check" and "serve" so the file version is never in doubt

# Settings live in dl-config.txt next to this file, so replacing main.py with a
# newer version never loses them. Create or change it with:  py main.py password
CONFIG_FILE = Path(__file__).resolve().parent / "dl-config.txt"


def load_config() -> Dict[str, str]:
    values: Dict[str, str] = {}
    if CONFIG_FILE.is_file():
        for line in CONFIG_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            values[key.strip().upper()] = val.strip()
    return values


CONFIG = load_config()


def setting(key: str, default: str) -> str:
    """Environment variable wins, then dl-config.txt, then the built-in default."""
    return os.environ.get("DL_" + key) or CONFIG.get(key) or default


DB_HOST = setting("DB_HOST", "localhost")
DB_PORT = setting("DB_PORT", "5432")
DB_NAME = setting("DB_NAME", "dltracker")
DB_USER = setting("DB_USER", "postgres")
DB_PASS = setting("DB_PASS", "postgres")

LISTEN_HOST = setting("HOST", "0.0.0.0")             # 0.0.0.0 = reachable on the LAN
LISTEN_PORT = int(setting("PORT", "8000"))

SESSION_DAYS = 30          # how long a phone stays signed in between syncs
WEB_DIR = Path(__file__).resolve().parent / "web"
SCHEMA_FILE = Path(__file__).resolve().parent / "schema.sql"

DATABASE_URL = setting("DATABASE_URL", "")
DB_SSLMODE = setting("DB_SSLMODE", "")
if DATABASE_URL:
    DSN = DATABASE_URL
else:
    ssl_part = f" sslmode={DB_SSLMODE}" if DB_SSLMODE else ""
    DSN = f"host={DB_HOST} port={DB_PORT} dbname={DB_NAME} user={DB_USER} password={DB_PASS}{ssl_part}"

# ---------------------------------------------------------------------------
# Roles
# ---------------------------------------------------------------------------

PERMISSIONS = {
    "Admin":    {"import", "approve", "pay", "schedule", "deliver", "tick", "view", "export"},
    "Approver": {"approve", "view", "export"},
    "Officer":  {"tick", "view"},          # no export: the officer does not need the register
    "Viewer":   {"view", "export"},
}

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

_pool: Optional[ThreadedConnectionPool] = None


def pool() -> ThreadedConnectionPool:
    global _pool
    if _pool is None:
        _pool = ThreadedConnectionPool(1, 12, DSN)
    return _pool


@contextmanager
def db(commit: bool = False):
    cx = pool().getconn()
    try:
        cur = cx.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        yield cur
        if commit:
            cx.commit()
        else:
            cx.rollback()
    except Exception:
        cx.rollback()
        raise
    finally:
        pool().putconn(cx)


def jsonable(value: Any) -> Any:
    """Dates and Decimals out of psycopg2 are not JSON by themselves."""
    if isinstance(value, (datetime,)):
        return value.isoformat()
    if isinstance(value, date):
        return value.isoformat()
    if hasattr(value, "quantize"):          # Decimal
        return float(value)
    if isinstance(value, memoryview):
        return base64.b64encode(value).decode()
    if isinstance(value, dict):
        return {k: jsonable(v) for k, v in value.items()}
    if isinstance(value, list):
        return [jsonable(v) for v in value]
    return value


# ---------------------------------------------------------------------------
# Passwords and sessions
# ---------------------------------------------------------------------------

PBKDF2_ROUNDS = 200_000


def hash_password(plain: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", plain.encode(), salt, PBKDF2_ROUNDS)
    return f"pbkdf2${PBKDF2_ROUNDS}${salt.hex()}${dk.hex()}"


def verify_password(plain: str, stored: str) -> bool:
    try:
        algo, rounds, salt_hex, want = stored.split("$")
        if algo != "pbkdf2":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", plain.encode(), bytes.fromhex(salt_hex), int(rounds))
        return hmac.compare_digest(dk.hex(), want)
    except Exception:
        return False


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


# ---------------------------------------------------------------------------
ROOT_PATH = setting("ROOT_PATH", "").strip().rstrip("/")
app = FastAPI(title="DL Tracker", docs_url=None, redoc_url=None, root_path=ROOT_PATH)

from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def ensure_db_initialized():
    try:
        with psycopg2.connect(DSN, connect_timeout=10) as cx:
            cx.autocommit = True
            with cx.cursor() as cur:
                cur.execute("SELECT to_regclass('public.app_user')")
                row = cur.fetchone()
                if not row or row[0] is None:
                    print("Initializing database schema...")
                    cur.execute(SCHEMA_FILE.read_text(encoding="utf-8"))
                    print("Schema applied successfully.")
                cur.execute("SELECT count(*) FROM app_user WHERE role = 'Admin' AND active = true")
                count = cur.fetchone()[0]
                if count == 0:
                    default_email = os.environ.get("DEFAULT_ADMIN_EMAIL", "admin@inciatolyesi.com")
                    default_pass = os.environ.get("DEFAULT_ADMIN_PASSWORD", "Admin12345!")
                    cur.execute("""INSERT INTO app_user (email, full_name, role, password_hash)
                                   VALUES (%s,%s,%s,%s)
                                   ON CONFLICT (email) DO NOTHING""",
                                (default_email.strip().lower(), "Yonetici", "Admin", hash_password(default_pass)))
                    print(f"Default admin account ready: {default_email}")
    except Exception as e:
        print(f"DB startup notice: {e}")


@app.on_event("startup")
def on_startup():
    ensure_db_initialized()


def current_user(authorization: str = Header(default="")) -> Dict[str, Any]:
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "Sign in first")
    th = token_hash(authorization[7:])
    with db(commit=True) as cur:
        cur.execute(
            """UPDATE app_session SET last_seen = now()
               WHERE token_hash = %s AND expires_at > now()
               RETURNING user_id""", (th,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(401, "Session expired, sign in again")
        cur.execute("SELECT id, email, full_name, role, active FROM app_user WHERE id = %s",
                    (row["user_id"],))
        user = cur.fetchone()
    if not user or not user["active"]:
        raise HTTPException(403, "This account is switched off")
    return dict(user)


def need(user: Dict[str, Any], permission: str) -> None:
    if permission not in PERMISSIONS.get(user["role"], set()):
        raise HTTPException(403, f"Your role ({user['role']}) cannot do this")


def audit(cur, user_id, action, entity, entity_id, detail=None):
    cur.execute(
        "INSERT INTO audit_log (user_id, action, entity, entity_id, detail) VALUES (%s,%s,%s,%s,%s)",
        (user_id, action, entity, entity_id, json.dumps(jsonable(detail or {}))))


@app.exception_handler(psycopg2.Error)
def db_error(request: Request, exc: psycopg2.Error):
    """Database refusals (the gates) become plain messages the UI can show."""
    msg = str(exc).strip().split("\n")[0]
    for marker in ("Appointment refused", "Delivery refused", "Refused:",
                   "Cannot remove payment"):
        if marker in msg:
            return JSONResponse({"detail": msg}, status_code=409)
    return JSONResponse({"detail": "Database error: " + msg}, status_code=500)


# ------------------------------------------------------------------ health

@app.get("/api/ping")
def ping():
    """The phone hits this to find out whether it is back on the office network."""
    return {"ok": True, "server_time": datetime.now(timezone.utc).isoformat()}


# -------------------------------------------------------------------- auth

@app.post("/api/login")
def login(payload: Dict[str, Any] = Body(...), user_agent: str = Header(default="")):
    email = (payload.get("email") or "").strip().lower()
    password = payload.get("password") or ""
    with db(commit=True) as cur:
        cur.execute("SELECT * FROM app_user WHERE lower(email) = %s", (email,))
        user = cur.fetchone()
        if not user or not user["active"] or not verify_password(password, user["password_hash"]):
            raise HTTPException(401, "Email or password is wrong")
        token = secrets.token_urlsafe(32)
        cur.execute(
            """INSERT INTO app_session (token_hash, user_id, expires_at, user_agent)
               VALUES (%s, %s, now() + %s, %s)""",
            (token_hash(token), user["id"], timedelta(days=SESSION_DAYS), user_agent[:300]))
        cur.execute("UPDATE app_user SET last_login_at = now() WHERE id = %s", (user["id"],))
    return {
        "token": token,
        "user": {"id": user["id"], "email": user["email"],
                 "full_name": user["full_name"], "role": user["role"]},
        "permissions": sorted(PERMISSIONS[user["role"]]),
    }


@app.post("/api/logout")
def logout(authorization: str = Header(default="")):
    if authorization.startswith("Bearer "):
        with db(commit=True) as cur:
            cur.execute("DELETE FROM app_session WHERE token_hash = %s",
                        (token_hash(authorization[7:]),))
    return {"ok": True}


@app.get("/api/me")
def me(user=Depends(current_user)):
    return {"user": user, "permissions": sorted(PERMISSIONS[user["role"]])}


# --------------------------------------------------------------- bootstrap

@app.get("/api/bootstrap")
def bootstrap(user=Depends(current_user)):
    """Everything the client needs in one round trip, so a phone on a weak
    link makes one request instead of six."""
    with db() as cur:
        cur.execute("SELECT * FROM batch ORDER BY id DESC")
        batches = [jsonable(dict(r)) for r in cur.fetchall()]
        cur.execute("SELECT * FROM v_application ORDER BY reg_no")
        apps = [jsonable(dict(r)) for r in cur.fetchall()]
        cur.execute("SELECT * FROM fee_reference ORDER BY license_type, application_type")
        fees = [jsonable(dict(r)) for r in cur.fetchall()]
        cur.execute("SELECT code FROM company WHERE active ORDER BY code")
        companies = [r["code"] for r in cur.fetchall()]
    return {"user": user, "permissions": sorted(PERMISSIONS[user["role"]]),
            "batches": batches, "applications": apps, "fees": fees,
            "companies": companies,
            "server_time": datetime.now(timezone.utc).isoformat()}


@app.get("/api/changes")
def changes(since: str = "", user=Depends(current_user)):
    """Delta for a phone that has been offline. Falls back to everything."""
    with db() as cur:
        if since:
            cur.execute("""SELECT v.* FROM v_application v
                           JOIN application a ON a.id = v.id
                           WHERE a.updated_at > %s ORDER BY v.reg_no""", (since,))
        else:
            cur.execute("SELECT * FROM v_application ORDER BY reg_no")
        apps = [jsonable(dict(r)) for r in cur.fetchall()]
    return {"applications": apps, "server_time": datetime.now(timezone.utc).isoformat()}


# ------------------------------------------------------------------ import

@app.post("/api/import")
def import_batch(payload: Dict[str, Any] = Body(...), user=Depends(current_user)):
    """Rows arrive already parsed and validated by the browser. The server
    still derives New/Renewal itself rather than trusting the client."""
    need(user, "import")
    name = (payload.get("batch_name") or "").strip()
    rows = payload.get("rows") or []
    if not name:
        raise HTTPException(400, "The batch needs a name")
    if not rows:
        raise HTTPException(400, "There are no rows to import")

    imported, skipped = 0, []
    with db(commit=True) as cur:
        cur.execute("SELECT id FROM batch WHERE name = %s", (name,))
        if cur.fetchone():
            raise HTTPException(409, f'A batch called "{name}" already exists')
        cur.execute(
            """INSERT INTO batch (name, source_file, imported_by) VALUES (%s,%s,%s) RETURNING id""",
            (name, payload.get("source_file"), user["id"]))
        batch_id = cur.fetchone()["id"]

        for row in rows:
            reg = (row.get("regNo") or "").strip()
            code = (row.get("company") or "").strip().upper()
            if not reg or not code:
                skipped.append({"reg_no": reg, "reason": "REG NO or company missing"})
                continue
            cur.execute("SAVEPOINT one_row")
            try:
                cur.execute("""INSERT INTO company (code) VALUES (%s)
                               ON CONFLICT (code) DO NOTHING""", (code,))
                cur.execute("SELECT id FROM company WHERE code = %s", (code,))
                company_id = cur.fetchone()["id"]

                cur.execute("""
                    INSERT INTO employee (reg_no, company_id, name, surname, department,
                                          job_title, location, national_id, date_of_birth, phone)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT (reg_no) DO UPDATE SET
                        company_id = EXCLUDED.company_id, name = EXCLUDED.name,
                        surname = EXCLUDED.surname, department = EXCLUDED.department,
                        job_title = EXCLUDED.job_title, location = EXCLUDED.location,
                        national_id = COALESCE(EXCLUDED.national_id, employee.national_id),
                        date_of_birth = COALESCE(EXCLUDED.date_of_birth, employee.date_of_birth),
                        phone = COALESCE(EXCLUDED.phone, employee.phone)
                    RETURNING id""",
                    (reg, company_id, row.get("name"), row.get("surname"),
                     row.get("department"), row.get("jobTitle"), row.get("location"),
                     row.get("nationalId") or None, row.get("dateOfBirth") or None,
                     row.get("phone") or None))
                employee_id = cur.fetchone()["id"]

                dl_no = (row.get("dlNo") or "").strip() or None
                app_type = "Renewal" if dl_no else "New"     # never taken from the client
                cur.execute("""
                    INSERT INTO application (batch_id, employee_id, license_type, application_type,
                        dl_no, dl_class, dl_expire_date, amount, process_fee, driving_test_fee,
                        eye_test_fee, bill_number, source_row, note)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (batch_id, employee_id, row.get("licenseType"), app_type, dl_no,
                     row.get("dlClass") or None, row.get("dlExpireDate") or None,
                     row.get("amount"), row.get("processFee"), row.get("drivingTestFee"),
                     row.get("eyeTestFee"), row.get("billNumber") or None,
                     row.get("index"), row.get("note") or None))
                cur.execute("RELEASE SAVEPOINT one_row")
                imported += 1
            except psycopg2.Error as exc:
                cur.execute("ROLLBACK TO SAVEPOINT one_row")
                reason = str(exc).strip().split("\n")[0]
                if "ux_application_one_open_per_employee" in reason:
                    reason = "Already has an open application"
                skipped.append({"reg_no": reg, "reason": reason})

        cur.execute("""INSERT INTO import_log (batch_id, file_name, sheet_name, rows_read,
                          rows_imported, rows_blocked, findings, imported_by)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (batch_id, payload.get("source_file"), payload.get("sheet_name"),
                     len(rows), imported, len(skipped),
                     json.dumps(jsonable(payload.get("findings") or {})), user["id"]))
        audit(cur, user["id"], "BATCH_IMPORTED", "batch", batch_id,
              {"name": name, "imported": imported, "skipped": len(skipped)})

    return {"batch_id": batch_id, "imported": imported, "skipped": skipped}


# ---------------------------------------------------------------- approval

@app.post("/api/batches/{batch_id}/approval")
def set_approval(batch_id: int, payload: Dict[str, Any] = Body(...), user=Depends(current_user)):
    need(user, "approve")
    status = payload.get("status")
    if status not in ("Approved", "Rejected", "Pending"):
        raise HTTPException(400, "Status must be Approved, Rejected or Pending")
    signed_on = payload.get("gm_signed_on")
    if status == "Approved" and not signed_on:
        raise HTTPException(400, "Give the date the General Manager signed off")
    with db(commit=True) as cur:
        cur.execute("""UPDATE batch SET approval_status=%s, gm_signed_on=%s,
                          approval_recorded_by=%s, approval_recorded_at=now(), note=%s
                       WHERE id=%s RETURNING id""",
                    (status, signed_on or None, user["id"], payload.get("note"), batch_id))
        if not cur.fetchone():
            raise HTTPException(404, "No such batch")
        audit(cur, user["id"], "BATCH_" + status.upper(), "batch", batch_id,
              {"gm_signed_on": signed_on})
    return {"ok": True}


# -------------------------------------------------- payment / booking / delivery

def _bulk(cur, user, ids: List[int], sql: str, args_for, action: str, detail: Dict):
    """Applies one statement per person, keeping the ones the database refuses
    out of the way instead of failing the whole run."""
    done, refused = [], []
    for app_id in ids:
        cur.execute("SAVEPOINT one_app")
        try:
            cur.execute(sql, args_for(app_id))
            row = cur.fetchone()
            cur.execute("RELEASE SAVEPOINT one_app")
            if row:
                done.append(app_id)
                audit(cur, user["id"], action, "application", app_id, detail)
            else:
                refused.append({"application_id": app_id, "reason": "No such application"})
        except psycopg2.Error as exc:
            cur.execute("ROLLBACK TO SAVEPOINT one_app")
            refused.append({"application_id": app_id,
                            "reason": str(exc).strip().split("\n")[0]})
    return done, refused


@app.post("/api/payments")
def record_payments(payload: Dict[str, Any] = Body(...), user=Depends(current_user)):
    need(user, "pay")
    ids = payload.get("application_ids") or []
    when = payload.get("payment_date") or date.today().isoformat()
    bill = (payload.get("bill_number") or "").strip() or None
    with db(commit=True) as cur:
        done, refused = _bulk(
            cur, user, ids,
            """UPDATE application SET payment_paid = true, bill_number = %s,
                   payment_date = %s, payment_recorded_by = %s
               WHERE id = %s RETURNING id""",
            lambda i: (bill, when, user["id"], i),
            "PAYMENT_RECORDED", {"bill_number": bill, "payment_date": when})
    return {"applied": done, "refused": refused}


@app.post("/api/appointments")
def set_appointments(payload: Dict[str, Any] = Body(...), user=Depends(current_user)):
    need(user, "schedule")
    ids = payload.get("application_ids") or []
    when = payload.get("appointment_date")
    if not when:
        raise HTTPException(400, "Pick a date")
    with db(commit=True) as cur:
        done, refused = _bulk(
            cur, user, ids,
            """UPDATE application SET appointment_date = %s, appointment_set_by = %s
               WHERE id = %s RETURNING id""",
            lambda i: (when, user["id"], i),
            "APPOINTMENT_SET", {"appointment_date": when})
    return {"applied": done, "refused": refused}


@app.post("/api/deliveries")
def record_deliveries(payload: Dict[str, Any] = Body(...), user=Depends(current_user)):
    need(user, "deliver")
    ids = payload.get("application_ids") or []
    when = payload.get("delivered_on") or date.today().isoformat()
    with db(commit=True) as cur:
        done, refused = _bulk(
            cur, user, ids,
            """UPDATE application SET delivered_on = %s, delivered_by = %s
               WHERE id = %s RETURNING id""",
            lambda i: (when, user["id"], i),
            "DELIVERED", {"delivered_on": when})
        for app_id in done:
            cur.execute("""INSERT INTO application_event (application_id, event_type, recorded_by)
                           VALUES (%s,'DELIVERED',%s)""", (app_id, user["id"]))
    return {"applied": done, "refused": refused}


@app.post("/api/self-renewals")
def self_renewals(payload: Dict[str, Any] = Body(...), user=Depends(current_user)):
    """Someone renewed their own licence while the batch was running. No company
    payment, no appointment, no visit - the application simply closes."""
    need(user, "schedule")
    ids = payload.get("application_ids") or []
    when = payload.get("self_renewed_on") or date.today().isoformat()
    note = payload.get("note")
    new_dl = (payload.get("dl_no") or "").strip()
    new_class = (payload.get("dl_class") or "").strip()
    new_expiry = payload.get("dl_expire_date") or None

    with db(commit=True) as cur:
        done, refused = _bulk(
            cur, user, ids,
            """UPDATE application
                   SET self_renewed_on = %s, self_renewed_by = %s, self_renewed_note = %s,
                       appointment_date = NULL,
                       dl_no          = COALESCE(NULLIF(%s,''), dl_no),
                       dl_class       = COALESCE(NULLIF(%s,''), dl_class),
                       dl_expire_date = COALESCE(%s, dl_expire_date)
                 WHERE id = %s AND delivered_on IS NULL AND cancelled_at IS NULL
                 RETURNING id""",
            lambda i: (when, user["id"], note, new_dl, new_class, new_expiry, i),
            "SELF_RENEWED", {"self_renewed_on": when, "dl_no": new_dl or None})
    return {"applied": done, "refused": refused}


@app.post("/api/self-renewals/undo")
def undo_self_renewal(payload: Dict[str, Any] = Body(...), user=Depends(current_user)):
    need(user, "schedule")
    ids = payload.get("application_ids") or []
    with db(commit=True) as cur:
        done, refused = _bulk(
            cur, user, ids,
            """UPDATE application SET self_renewed_on = NULL, self_renewed_by = NULL,
                                     self_renewed_note = NULL
                 WHERE id = %s RETURNING id""",
            lambda i: (i,), "SELF_RENEWED_UNDONE", {})
    return {"applied": done, "refused": refused}


# -------------------------------------------------------------------- sync

@app.post("/api/sync")
def sync(payload: Dict[str, Any] = Body(...), user=Depends(current_user)):
    """The licence-office queue arrives here after a day offline.

    Every event carries a client_event_id generated on the phone, so the same
    queue can be sent twice without creating anything twice."""
    need(user, "tick")
    accepted, duplicates, refused = [], [], []

    with db(commit=True) as cur:
        for ev in payload.get("events") or []:
            cid = ev.get("client_event_id")
            cur.execute("SAVEPOINT one_event")
            try:
                cur.execute("""
                    INSERT INTO application_event
                        (application_id, event_type, occurred_at, recorded_by, walk_in, device, note, client_event_id)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT (client_event_id) DO NOTHING
                    RETURNING id""",
                    (ev.get("application_id"), ev.get("event_type"),
                     ev.get("occurred_at") or datetime.now(timezone.utc).isoformat(),
                     user["id"], bool(ev.get("walk_in")), ev.get("device"),
                     ev.get("note"), cid))
                row = cur.fetchone()
                cur.execute("RELEASE SAVEPOINT one_event")
                if row:
                    accepted.append(cid)
                    # completion also carries the class and the new licence number
                    if ev.get("event_type") == "COMPLETED":
                        cur.execute("""UPDATE application
                                       SET dl_class = COALESCE(NULLIF(%s,''), dl_class),
                                           dl_no    = COALESCE(NULLIF(%s,''), dl_no)
                                       WHERE id = %s""",
                                    (ev.get("dl_class") or "", ev.get("dl_no") or "",
                                     ev.get("application_id")))
                else:
                    duplicates.append(cid)
            except psycopg2.Error as exc:
                cur.execute("ROLLBACK TO SAVEPOINT one_event")
                refused.append({"client_event_id": cid,
                                "reason": str(exc).strip().split("\n")[0]})

        for ph in payload.get("photos") or []:
            cur.execute("SAVEPOINT one_photo")
            try:
                raw = base64.b64decode((ph.get("data_url") or "").split(",")[-1])
                cur.execute("""
                    INSERT INTO application_photo
                        (application_id, side, mime_type, bytes, size_bytes, width, height, uploaded_by)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT (application_id, side) DO UPDATE SET
                        bytes = EXCLUDED.bytes, size_bytes = EXCLUDED.size_bytes,
                        width = EXCLUDED.width, height = EXCLUDED.height,
                        uploaded_by = EXCLUDED.uploaded_by, uploaded_at = now()
                    RETURNING id""",
                    (ph.get("application_id"), ph.get("side"),
                     ph.get("mime_type") or "image/jpeg", psycopg2.Binary(raw), len(raw),
                     ph.get("width"), ph.get("height"), user["id"]))
                cur.fetchone()
                cur.execute("RELEASE SAVEPOINT one_photo")
                accepted.append(f"photo:{ph.get('application_id')}:{ph.get('side')}")
            except psycopg2.Error as exc:
                cur.execute("ROLLBACK TO SAVEPOINT one_photo")
                refused.append({"photo": ph.get("application_id"),
                                "reason": str(exc).strip().split("\n")[0]})
            except Exception as exc:
                cur.execute("ROLLBACK TO SAVEPOINT one_photo")
                refused.append({"photo": ph.get("application_id"), "reason": str(exc)})

        cur.execute("SELECT * FROM v_application ORDER BY reg_no")
        apps = [jsonable(dict(r)) for r in cur.fetchall()]

    return {"accepted": accepted, "duplicates": duplicates, "refused": refused,
            "applications": apps,
            "server_time": datetime.now(timezone.utc).isoformat()}


def _safe_name(text: str) -> str:
    """A file name Windows will accept, keeping it readable."""
    out = "".join(ch if (ch.isalnum() or ch in "-_") else "_" for ch in (text or "").strip())
    while "__" in out:
        out = out.replace("__", "_")
    return out.strip("_") or "unknown"


@app.post("/api/photos/export")
def export_photos(payload: Dict[str, Any] = Body(...), user=Depends(current_user)):
    """Selected people's licence photographs, as one zip.

    Names look like 408004_MOSES_SULONTEH_front.jpg so a file on its own is
    still traceable to a person."""
    need(user, "export")
    ids = [int(i) for i in (payload.get("application_ids") or [])]
    if not ids:
        raise HTTPException(400, "Nobody was selected")

    with db() as cur:
        cur.execute("""
            SELECT v.id, v.reg_no, v.name, v.surname, v.company, v.batch_name,
                   p.side, p.bytes, p.mime_type, p.uploaded_at
            FROM v_application v
            LEFT JOIN application_photo p ON p.application_id = v.id
            WHERE v.id = ANY(%s)
            ORDER BY v.reg_no, p.side""", (ids,))
        rows = [dict(r) for r in cur.fetchall()]

    import io
    import zipfile

    buf = io.BytesIO()
    included, without = [], []
    seen_people = set()

    # JPEGs are already compressed, so storing beats squeezing them again
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        for r in rows:
            person = f'{r["reg_no"]} {r["name"]} {r["surname"]}'
            if not r["bytes"]:
                if r["id"] not in seen_people:
                    without.append(person)
                continue
            seen_people.add(r["id"])
            ext = "jpg" if "jpeg" in (r["mime_type"] or "") else (r["mime_type"] or "image/jpeg").split("/")[-1]
            fname = _safe_name(f'{r["reg_no"]}_{r["name"]}_{r["surname"]}_{r["side"]}') + "." + ext
            z.writestr(fname, bytes(r["bytes"]))
            included.append(f'{fname}   {person}   taken {r["uploaded_at"]:%d/%m/%Y %H:%M}')

        lines = [
            "DL Tracker - licence photographs",
            f"Exported {date.today().strftime('%d/%m/%Y')} by {user['full_name']}",
            f"People selected: {len(ids)}",
            f"Files: {len(included)}",
            "",
            "FILES",
        ] + included
        if without:
            lines += ["", "NO PHOTOGRAPH ON FILE"] + without
        z.writestr("manifest.txt", "\r\n".join(lines))

    buf.seek(0)
    fname = f"DL_Photos_{date.today().strftime('%d-%m-%Y')}.zip"
    return Response(content=buf.read(), media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="{fname}"'})


@app.get("/api/photos/{application_id}/{side}")
def get_photo(application_id: int, side: str, user=Depends(current_user)):
    with db() as cur:
        cur.execute("""SELECT bytes, mime_type FROM application_photo
                       WHERE application_id = %s AND side = %s""", (application_id, side))
        row = cur.fetchone()
    if not row:
        raise HTTPException(404, "No photo")
    return Response(content=bytes(row["bytes"]), media_type=row["mime_type"])


# ------------------------------------------------------------------ reports

@app.get("/api/funnel")
def funnel(user=Depends(current_user)):
    with db() as cur:
        cur.execute("SELECT * FROM v_funnel ORDER BY batch_id DESC")
        return {"funnel": [jsonable(dict(r)) for r in cur.fetchall()]}


@app.get("/api/expiry")
def expiry(user=Depends(current_user)):
    with db() as cur:
        cur.execute("""SELECT * FROM v_expiry_radar
                       WHERE bucket IN ('Overdue','Within 30 days','Within 90 days')
                       ORDER BY dl_expire_date NULLS LAST""")
        return {"expiring": [jsonable(dict(r)) for r in cur.fetchall()]}


# ---------------------------------------------------------------------------
# Excel reporting
# ---------------------------------------------------------------------------

HDR_FILL = "1C2126"
MONEY_FMT = '"$"#,##0.00'
DATE_FMT = "DD/MM/YYYY"


def _write_sheet(wb, title, headers, rows, money_cols=(), date_cols=(), total_cols=()):
    """One tab: bold header, frozen top row, filters, sensible widths."""
    from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
    from openpyxl.utils import get_column_letter

    ws = wb.create_sheet(title[:31])
    ws.append(headers)
    head_font = Font(bold=True, color="FFFFFF", size=10)
    fill = PatternFill("solid", fgColor=HDR_FILL)
    for cell in ws[1]:
        cell.font = head_font
        cell.fill = fill
        cell.alignment = Alignment(vertical="center", wrap_text=True)
    ws.row_dimensions[1].height = 26

    for row in rows:
        ws.append(["" if v is None else v for v in row])

    n = len(rows)
    for idx in money_cols:
        for r in range(2, n + 2):
            ws.cell(row=r, column=idx + 1).number_format = MONEY_FMT
    for idx in date_cols:
        for r in range(2, n + 2):
            ws.cell(row=r, column=idx + 1).number_format = DATE_FMT

    if total_cols and n:
        thin = Side(style="thin", color="1C2126")
        ws.append([])
        trow = n + 3
        ws.cell(row=trow, column=1, value="TOTAL").font = Font(bold=True)
        for idx in total_cols:
            col = get_column_letter(idx + 1)
            c = ws.cell(row=trow, column=idx + 1, value=f"=SUM({col}2:{col}{n + 1})")
            c.font = Font(bold=True)
            c.number_format = MONEY_FMT
            c.border = Border(top=thin)

    for i, header in enumerate(headers, start=1):
        longest = len(str(header))
        for row in rows[:400]:
            v = row[i - 1]
            if v is not None:
                longest = max(longest, len(str(v)))
        ws.column_dimensions[get_column_letter(i)].width = min(max(longest + 2, 9), 42)

    ws.freeze_panes = "A2"
    if n:
        ws.auto_filter.ref = f"A1:{get_column_letter(len(headers))}{n + 1}"
    return ws


@app.get("/api/report.xlsx")
def report_xlsx(batch_id: Optional[int] = None, user=Depends(current_user)):
    """The whole picture as one workbook, one topic per tab."""
    need(user, "export")
    try:
        from openpyxl import Workbook
    except ImportError:
        raise HTTPException(
            503, "Excel export needs openpyxl. Run: python -m pip install openpyxl")

    where = "WHERE batch_id = %s" if batch_id else ""
    args = (batch_id,) if batch_id else ()

    with db() as cur:
        cur.execute(f"SELECT * FROM v_application {where} ORDER BY company, reg_no", args)
        apps = [dict(r) for r in cur.fetchall()]
        cur.execute("SELECT * FROM v_funnel " +
                    ("WHERE batch_id = %s" if batch_id else "") + " ORDER BY batch_id DESC", args)
        funnel = [dict(r) for r in cur.fetchall()]
        cur.execute("SELECT * FROM batch " + ("WHERE id = %s" if batch_id else "") +
                    " ORDER BY id DESC", args)
        batches = [dict(r) for r in cur.fetchall()]
        cur.execute(f"""
            SELECT e.event_type, e.occurred_at, e.recorded_at, e.walk_in, e.note,
                   u.full_name AS recorded_by, v.reg_no, v.full_name AS person,
                   v.company, v.location, v.batch_name
            FROM application_event e
            JOIN v_application v ON v.id = e.application_id
            LEFT JOIN app_user u ON u.id = e.recorded_by
            {"WHERE v.batch_id = %s" if batch_id else ""}
            ORDER BY e.occurred_at DESC""", args)
        events = [dict(r) for r in cur.fetchall()]
        cur.execute("""SELECT * FROM v_expiry_radar
                       WHERE bucket IN ('Overdue','Within 30 days','Within 90 days')
                       ORDER BY dl_expire_date NULLS LAST""")
        expiring = [dict(r) for r in cur.fetchall()]

    def num(v):
        return float(v) if v is not None and hasattr(v, "quantize") else v

    wb = Workbook()
    wb.remove(wb.active)

    # ---- 1. Summary
    rows = []
    for f in funnel:
        b = next((x for x in batches if x["id"] == f["batch_id"]), {})
        rows.append([
            f["batch_name"], b.get("approval_status"), b.get("gm_signed_on"),
            f["imported"], f["paid"], f["unpaid"], f["booked"], f["arrived"],
            f["completed"], f["delivered"], f["self_renewed"], f["no_show"],
            f["still_open"], num(f["collected"]), num(f["outstanding"]),
            num(f["programme_cost"]),
        ])
    _write_sheet(wb, "Summary",
                 ["Batch", "Approval", "GM signed", "People", "Paid", "Not paid",
                  "Booked", "Arrived", "Completed", "Delivered", "Self-renewed",
                  "No show", "Still open", "Collected", "Outstanding", "Programme cost"],
                 rows, money_cols=(13, 14, 15), date_cols=(2,), total_cols=(13, 14, 15))

    # ---- 2. Register
    reg_headers = ["Batch", "Company", "REG NO", "Name", "Surname", "Department",
                   "Job title", "Location", "Category", "New / renewal", "DL NO", "Class",
                   "Licence expires", "National ID", "Date of birth", "Phone",
                   "Status", "Paid", "Bill number", "Payment date", "Appointment",
                   "Delivered", "Self-renewed", "Photos",
                   "Amount", "Process", "Driving test", "Eye test", "Total"]
    reg_rows = [[
        a["batch_name"], a["company"], a["reg_no"], a["name"], a["surname"],
        a["department"], a["job_title"], a["location"], a["license_type"],
        a["application_type"], a["dl_no"], a["dl_class"], a["dl_expire_date"],
        a["national_id"], a["date_of_birth"], a["phone"], a["status"],
        "Yes" if a["payment_paid"] else "No", a["bill_number"], a["payment_date"],
        a["appointment_date"], a["delivered_on"], a["self_renewed_on"],
        f'{a["photo_count"]}/2',
        num(a["amount"]), num(a["process_fee"]), num(a["driving_test_fee"]),
        num(a["eye_test_fee"]), num(a["total"]),
    ] for a in apps]
    _write_sheet(wb, "Register", reg_headers, reg_rows,
                 money_cols=(24, 25, 26, 27, 28), date_cols=(12, 14, 19, 20, 21, 22),
                 total_cols=(24, 25, 26, 27, 28))

    # ---- 3. Payments
    paid = [a for a in apps if a["payment_paid"]]
    _write_sheet(wb, "Payments",
                 ["Bill number", "Payment date", "Company", "REG NO", "Name",
                  "Department", "Location", "Category", "New / renewal",
                  "Amount", "Process", "Driving test", "Eye test", "Total"],
                 [[a["bill_number"], a["payment_date"], a["company"], a["reg_no"],
                   a["full_name"], a["department"], a["location"], a["license_type"],
                   a["application_type"], num(a["amount"]), num(a["process_fee"]),
                   num(a["driving_test_fee"]), num(a["eye_test_fee"]), num(a["total"])]
                  for a in paid],
                 money_cols=(9, 10, 11, 12, 13), date_cols=(1,), total_cols=(9, 10, 11, 12, 13))

    # ---- 4. Not paid
    unpaid = [a for a in apps if not a["payment_paid"] and not a["self_renewed_on"]]
    _write_sheet(wb, "Not paid",
                 ["Company", "REG NO", "Name", "Department", "Location", "Category",
                  "New / renewal", "Licence expires", "Phone", "Total owed"],
                 [[a["company"], a["reg_no"], a["full_name"], a["department"],
                   a["location"], a["license_type"], a["application_type"],
                   a["dl_expire_date"], a["phone"], num(a["total"])] for a in unpaid],
                 money_cols=(9,), date_cols=(7,), total_cols=(9,))

    # ---- 5. Appointments
    booked = sorted([a for a in apps if a["appointment_date"]],
                    key=lambda x: (x["appointment_date"], x["reg_no"]))
    _write_sheet(wb, "Appointments",
                 ["Appointment", "Company", "REG NO", "Name", "Department", "Location",
                  "Category", "New / renewal", "Bill number", "Status", "Photos"],
                 [[a["appointment_date"], a["company"], a["reg_no"], a["full_name"],
                   a["department"], a["location"], a["license_type"],
                   a["application_type"], a["bill_number"], a["status"],
                   f'{a["photo_count"]}/2'] for a in booked],
                 date_cols=(0,))

    # ---- 6. Licence office
    _write_sheet(wb, "Licence office",
                 ["Happened", "Recorded", "Event", "REG NO", "Name", "Company",
                  "Location", "Batch", "Walk-in", "Recorded by", "Note"],
                 [[e["occurred_at"].replace(tzinfo=None) if e["occurred_at"] else None,
                   e["recorded_at"].replace(tzinfo=None) if e["recorded_at"] else None,
                   e["event_type"].replace("_", " ").title(), e["reg_no"], e["person"],
                   e["company"], e["location"], e["batch_name"],
                   "Yes" if e["walk_in"] else "", e["recorded_by"], e["note"]]
                  for e in events])

    # ---- 7. Self-renewed
    selfr = [a for a in apps if a["self_renewed_on"]]
    _write_sheet(wb, "Self-renewed",
                 ["Self-renewed on", "Company", "REG NO", "Name", "Department",
                  "Location", "New DL NO", "Class", "New expiry", "Note",
                  "Cost saved"],
                 [[a["self_renewed_on"], a["company"], a["reg_no"], a["full_name"],
                   a["department"], a["location"], a["dl_no"], a["dl_class"],
                   a["dl_expire_date"], a["self_renewed_note"], num(a["total"])]
                  for a in selfr],
                 money_cols=(10,), date_cols=(0, 8), total_cols=(10,))

    # ---- 8. Expiry radar
    _write_sheet(wb, "Expiry radar",
                 ["Bucket", "Licence expires", "Company", "REG NO", "Name",
                  "Department", "Location", "Category", "DL NO", "Current status"],
                 [[e["bucket"], e["dl_expire_date"], e["company"], e["reg_no"],
                   e["full_name"], e["department"], e["location"], e["license_type"],
                   e["dl_no"], e["status"]] for e in expiring],
                 date_cols=(1,))

    import io
    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)

    label = (batches[0]["name"] if batch_id and batches else "All batches")
    safe = "".join(ch for ch in label if ch.isalnum() or ch in " -_").strip().replace(" ", "_")
    fname = f"DL_Report_{safe}_{date.today().strftime('%d-%m-%Y')}.xlsx"
    return Response(
        content=buf.read(),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'})


# --------------------------------------------------------------- web client
from fastapi.responses import FileResponse

ROOT_INDEX = Path(__file__).resolve().parent / "index.html"
WEB_INDEX = WEB_DIR / "index.html"

if WEB_INDEX.is_file():
    app.mount("/", StaticFiles(directory=str(WEB_DIR), html=True), name="web")
elif ROOT_INDEX.is_file():
    @app.get("/")
    def serve_root():
        return FileResponse(ROOT_INDEX)
    @app.get("/{full_path:path}")
    def serve_fallback(full_path: str):
        target = Path(__file__).resolve().parent / full_path
        if target.is_file():
            return FileResponse(target)
        return FileResponse(ROOT_INDEX)


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------

ADMIN_DSN = f"host={DB_HOST} port={DB_PORT} dbname=postgres user={DB_USER} password={DB_PASS}"


def explain(exc: Exception) -> str:
    """Turn a database error into something worth reading."""
    text = str(exc).lower()
    if "password authentication failed" in text:
        return (f'PostgreSQL refused the password for the user "{DB_USER}".\n'
                f"Set it once with:  py main.py password\n"
                f"It is saved in dl-config.txt and survives future updates.")
    if "could not connect to server" in text or "connection refused" in text or "could not translate" in text:
        return ("Could not reach PostgreSQL on " + DB_HOST + ":" + DB_PORT + ".\n"
                "Either the PostgreSQL server is not installed on this machine, or its\n"
                "service is stopped. Check with:  py main.py check")
    if "does not exist" in text and "database" in text:
        return (f'The database "{DB_NAME}" has not been created yet.\n'
                f"Run this first:  py main.py initdb")
    if "does not exist" in text and "role" in text:
        return (f'PostgreSQL has no user called "{DB_USER}".\n'
                f"Open main.py and correct DB_USER near the top.")
    return str(exc).strip()


def cmd_check():
    """Say plainly what is and is not working, before anything is created."""
    print("")
    print(f"  DL Tracker, build {BUILD}")
    print("")
    print("  Settings from " + ("dl-config.txt" if CONFIG_FILE.is_file() else "the defaults in main.py"))
    print(f"    host      {DB_HOST}:{DB_PORT}")
    print(f"    user      {DB_USER}")
    print(f"    password  {'(set)' if DB_PASS else '(empty)'}")
    print(f"    database  {DB_NAME}")
    print("")
    try:
        cx = psycopg2.connect(ADMIN_DSN, connect_timeout=6)
    except Exception as exc:
        print("  PostgreSQL     COULD NOT CONNECT")
        print("")
        print("  " + explain(exc).replace("\n", "\n  "))
        print("")
        return 1
    cx.autocommit = True
    with cx.cursor() as cur:
        cur.execute("SHOW server_version")
        version = cur.fetchone()[0]
        cur.execute("SELECT 1 FROM pg_database WHERE datname = %s", (DB_NAME,))
        exists = cur.fetchone() is not None
    cx.close()
    print(f"  PostgreSQL     connected, version {version}")
    print(f"  Database       {DB_NAME} " + ("exists" if exists else "not created yet"))
    if exists:
        try:
            cx2 = psycopg2.connect(DSN, connect_timeout=6)
            with cx2.cursor() as cur:
                cur.execute("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")
                tables = cur.fetchone()[0]
                cur.execute("SELECT count(*) FROM app_user" if tables else "SELECT 0")
                users = cur.fetchone()[0]
            cx2.close()
            print(f"  Tables         {tables}")
            print(f"  Users          {users}")
            print("")
            print("  Everything is ready." if users else
                  "  Now create a user:  py main.py adduser you@company.com \"Your Name\" Admin")
        except Exception as exc:
            print(f"  Tables         none yet ({explain(exc)})")
            print("")
            print("  Next:  py main.py initdb")
    else:
        print("")
        print("  Next:  py main.py initdb   (it will create the database for you)")
    print("")
    return 0


def cmd_initdb():
    """Creates the database if it is missing, then applies the schema."""
    if not SCHEMA_FILE.is_file():
        sys.exit(f"schema.sql was not found next to this script ({SCHEMA_FILE})")

    try:
        cx = psycopg2.connect(ADMIN_DSN, connect_timeout=8)
        cx.autocommit = True
        with cx.cursor() as cur:
            cur.execute("SELECT 1 FROM pg_database WHERE datname = %s", (DB_NAME,))
            if cur.fetchone():
                print(f'Database "{DB_NAME}" is already there.')
            else:
                cur.execute(f'CREATE DATABASE "{DB_NAME}"')
                print(f'Database "{DB_NAME}" created.')
        cx.close()
    except Exception:
        # If cloud DB or no CREATE DATABASE permission, proceed with DSN
        pass

    try:
        cx = psycopg2.connect(DSN, connect_timeout=8)
    except Exception as exc:
        sys.exit(explain(exc))
    cx.autocommit = True
    with cx.cursor() as cur:
        cur.execute("SELECT to_regclass('public.app_user')")
        if cur.fetchone()[0] is not None:
            cx.close()
            print("The tables are already set up. Nothing to do.")
            print("If you want to wipe everything and start again, drop the database first.")
            return
        cur.execute(SCHEMA_FILE.read_text(encoding="utf-8"))
    cx.close()
    print(f"Schema applied to {DB_NAME}. Ten tables and four views are ready.")
    print('Next:  py main.py adduser you@company.com "Your Name" Admin')


def cmd_adduser(email: str, full_name: str, role: str):
    if role not in PERMISSIONS:
        sys.exit(f"Role must be one of: {', '.join(PERMISSIONS)}")
    pw = getpass.getpass("Password: ")
    if len(pw) < 8:
        sys.exit("Use at least 8 characters.")
    if pw != getpass.getpass("Repeat: "):
        sys.exit("They do not match.")
    try:
        cx = psycopg2.connect(DSN, connect_timeout=8)
    except Exception as exc:
        sys.exit(explain(exc))
    cx.autocommit = True
    with cx.cursor() as cur:
        cur.execute("""INSERT INTO app_user (email, full_name, role, password_hash)
                       VALUES (%s,%s,%s,%s)
                       ON CONFLICT (email) DO UPDATE SET
                           full_name = EXCLUDED.full_name, role = EXCLUDED.role,
                           password_hash = EXCLUDED.password_hash, active = true""",
                    (email.strip().lower(), full_name, role, hash_password(pw)))
    cx.close()
    print(f"{email} is ready as {role}.")


DATA_TABLES = ["application_photo", "application_event", "application",
               "import_log", "audit_log", "batch", "employee"]


def cmd_reset():
    """Wipes every licence record but keeps the accounts and the settings.
    Use it to clear practice data before the real month starts."""
    try:
        cx = psycopg2.connect(DSN, connect_timeout=8)
    except Exception as exc:
        sys.exit(explain(exc))
    cx.autocommit = True
    counts = {}
    with cx.cursor() as cur:
        for t in ["batch", "employee", "application", "application_event",
                  "application_photo", "import_log", "audit_log"]:
            cur.execute(f"SELECT count(*) FROM {t}")
            counts[t] = cur.fetchone()[0]
        cur.execute("SELECT count(*) FROM app_user")
        users = cur.fetchone()[0]

    print("")
    print(f"  DL Tracker, build {BUILD}")
    print("")
    print("  THIS WILL DELETE, permanently:")
    print(f"    batches                {counts['batch']}")
    print(f"    people                 {counts['employee']}")
    print(f"    applications           {counts['application']}")
    print(f"    licence office events  {counts['application_event']}")
    print(f"    photographs            {counts['application_photo']}")
    print(f"    import history         {counts['import_log']}")
    print(f"    activity log           {counts['audit_log']}")
    print("")
    print("  THIS WILL BE KEPT:")
    print(f"    user accounts          {users}   (you will not have to sign up again)")
    print("    companies and fees")
    print("")
    print("  There is no undo. Take a backup first if you are not sure.")
    print("")
    answer = input('  Type  DELETE  in capitals to go ahead, or press Enter to stop: ')
    if answer.strip() != "DELETE":
        cx.close()
        print("\n  Nothing was deleted.\n")
        return 1

    with cx.cursor() as cur:
        cur.execute("TRUNCATE " + ", ".join(DATA_TABLES) + " RESTART IDENTITY CASCADE")
    cx.close()
    print("\n  Done. Every licence record has been removed; the accounts are untouched.")
    print("  The next import will start from an empty system.\n")
    return 0


def cmd_password(given: Optional[str] = None):
    """Asks for the database password and stores it beside main.py.

    Pass the password on the command line to see what you are typing:
        py main.py password MyPassword123
    """
    print("")
    print(f"  DL Tracker, build {BUILD}")
    print("")
    print("  These settings are saved in dl-config.txt, next to main.py.")
    print("  Replacing main.py with a newer version will not lose them.")
    print("")
    if given:
        host, port, user, pw = DB_HOST, DB_PORT, DB_USER, given
        print(f"  Using host {host}:{port}, user {user}, and the password you typed.")
    else:
        host = input(f"  PostgreSQL host [{DB_HOST}]: ").strip() or DB_HOST
        port = input(f"  Port [{DB_PORT}]: ").strip() or DB_PORT
        user = input(f"  User [{DB_USER}]: ").strip() or DB_USER
        print("")
        print("  Type the password. Nothing appears on screen, that is normal.")
        print("  If you would rather see it, press Enter here and run instead:")
        print("      py main.py password YourPasswordHere")
        pw = getpass.getpass("  Password: ")
    if not pw:
        sys.exit("  No password given, nothing was saved.")

    dsn = f"host={host} port={port} dbname=postgres user={user} password={pw}"
    try:
        cx = psycopg2.connect(dsn, connect_timeout=8)
        with cx.cursor() as cur:
            cur.execute("SHOW server_version")
            version = cur.fetchone()[0]
        cx.close()
    except Exception as exc:
        print("")
        print("  PostgreSQL did not accept that. Nothing was saved.")
        print("  " + explain(exc).replace("\n", "\n  "))
        print("")
        return 1

    CONFIG_FILE.write_text(
        "# DL Tracker settings. Keep this file next to main.py.\n"
        "# Replacing main.py with a newer version will not change this file.\n"
        f"DB_HOST={host}\n"
        f"DB_PORT={port}\n"
        f"DB_NAME={DB_NAME}\n"
        f"DB_USER={user}\n"
        f"DB_PASS={pw}\n"
        f"PORT={LISTEN_PORT}\n", encoding="utf-8")
    print("")
    print(f"  Connected to PostgreSQL {version}. Settings saved to dl-config.txt.")
    print("  Next:  py main.py check")
    print("")
    return 0


def cmd_serve():
    try:
        cx = psycopg2.connect(DSN, connect_timeout=8)
        cx.close()
    except Exception as exc:
        sys.exit(explain(exc))
    import uvicorn
    print(f"DL Tracker (build {BUILD}) on http://{LISTEN_HOST}:{LISTEN_PORT}")
    print("On the office network the phone uses this machine's IP address, not localhost.")
    uvicorn.run(app, host=LISTEN_HOST, port=LISTEN_PORT, log_level="info")


if __name__ == "__main__":
    args = sys.argv[1:]
    if not args or args[0] == "serve":
        cmd_serve()
    elif args[0] == "initdb":
        cmd_initdb()
    elif args[0] == "check":
        sys.exit(cmd_check())
    elif args[0] == "reset":
        sys.exit(cmd_reset())
    elif args[0] == "password":
        sys.exit(cmd_password(args[1] if len(args) > 1 else None))
    elif args[0] == "adduser" and len(args) == 4:
        cmd_adduser(args[1], args[2], args[3])
    else:
        print(f"DL Tracker, build {BUILD}")
        print(f'Unknown command: "{args[0]}"')
        print("Use one of:  password   check   initdb   adduser   serve   reset")
        sys.exit(1)

"""
Plumber Loyalty Program — Plumber & Distributor Portal (Phase 3, Neon Postgres Edition)
========================================================================================
"""

import os
import re
import psycopg2
from psycopg2.extras import RealDictCursor
import secrets
import string
from datetime import datetime, timezone, timedelta
from flask import Flask, request, session, redirect, url_for, render_template_string, g
from werkzeug.security import generate_password_hash, check_password_hash

from code_generator import unformat_code, validate_checksum, ALPHABET_INDEX

# Provide your Neon connection string here or in your terminal environment variables
DATABASE_URL = os.environ.get("DATABASE_URL")
REDEMPTION_REQUEST_VALID_MINUTES = 10
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 15
SECRET_KEY_PATH = os.environ.get("SECRET_KEY_PATH", "flask_secret.key")


def get_secret_key():
    env_key = os.environ.get("SECRET_KEY")
    if env_key:
        return env_key
    if os.path.exists(SECRET_KEY_PATH):
        with open(SECRET_KEY_PATH, "r") as f:
            return f.read().strip()
    key = secrets.token_hex(32)
    with open(SECRET_KEY_PATH, "w") as f:
        f.write(key)
    return key


app = Flask(__name__)
app.secret_key = get_secret_key()


# ---------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------

def get_db():
    if "db" not in g:
        if not DATABASE_URL:
            raise RuntimeError("DATABASE_URL is missing. Set it to your Neon connection string.")
        g.db = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def db_execute(conn, query, params=()):
    """Helper to execute a query and return a fetchable cursor."""
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute(query, params)
    return cur


def init_portal_tables():
    if not DATABASE_URL:
        return
        
    conn = psycopg2.connect(DATABASE_URL)
    with conn.cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS distributors (
                id SERIAL PRIMARY KEY,
                name VARCHAR(150) NOT NULL,
                phone VARCHAR(15) UNIQUE NOT NULL,
                pin_hash VARCHAR(255) NOT NULL,
                distributor_code VARCHAR(10) UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS plumbers (
                id SERIAL PRIMARY KEY,
                name VARCHAR(150) NOT NULL,
                phone VARCHAR(15) UNIQUE NOT NULL,
                pin_hash VARCHAR(255) NOT NULL,
                shop_name VARCHAR(200),
                address VARCHAR(255),
                distributor_id INTEGER REFERENCES distributors (id) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS points_ledger (
                id SERIAL PRIMARY KEY,
                plumber_id INTEGER NOT NULL,
                code_id INTEGER,
                type VARCHAR(10) NOT NULL, 
                amount INTEGER NOT NULL,
                balance_after INTEGER NOT NULL,
                note VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS redemption_requests (
                id SERIAL PRIMARY KEY,
                request_code VARCHAR(12) UNIQUE NOT NULL,
                plumber_id INTEGER NOT NULL,
                points_requested INTEGER NOT NULL,
                status VARCHAR(20) NOT NULL DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                resolved_at TIMESTAMP,
                resolved_by VARCHAR(150)
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS login_attempts (
                phone VARCHAR(15) NOT NULL,
                role VARCHAR(20) NOT NULL,
                attempt_count SMALLINT NOT NULL DEFAULT 0,
                locked_until TIMESTAMP,
                last_attempt_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (phone, role)
            )
        """)
    conn.commit()
    conn.close()


def get_points_balance(conn, plumber_id) -> int:
    row = db_execute(conn,
        "SELECT balance_after FROM points_ledger WHERE plumber_id = %s ORDER BY id DESC LIMIT 1",
        (plumber_id,)
    ).fetchone()
    return row["balance_after"] if row else 0


def add_ledger_entry(conn, plumber_id, entry_type, amount, note, code_id=None):
    current = get_points_balance(conn, plumber_id)
    new_balance = current + amount if entry_type == "credit" else current - amount
    db_execute(conn,
        """INSERT INTO points_ledger (plumber_id, code_id, type, amount, balance_after, note, created_at)
           VALUES (%s, %s, %s, %s, %s, %s, %s)""",
        (plumber_id, code_id, entry_type, amount, new_balance, note, datetime.now(timezone.utc))
    )
    return new_balance


def generate_distributor_code(conn):
    alphabet = string.ascii_uppercase + string.digits
    for _ in range(20):
        code = "".join(secrets.choice(alphabet) for _ in range(6))
        if not db_execute(conn, "SELECT id FROM distributors WHERE distributor_code = %s", (code,)).fetchone():
            return code
    raise RuntimeError("Could not generate a unique distributor code — try again.")


def generate_request_code(conn):
    for _ in range(20):
        code = "".join(secrets.choice(string.digits) for _ in range(8))
        if not db_execute(conn, "SELECT id FROM redemption_requests WHERE request_code = %s", (code,)).fetchone():
            return code
    raise RuntimeError("Could not generate a unique redemption request code — try again.")


def expire_old_requests(conn, plumber_id=None):
    now = datetime.now(timezone.utc)
    query = "SELECT * FROM redemption_requests WHERE status = 'pending' AND expires_at < %s"
    params = [now]
    if plumber_id is not None:
        query += " AND plumber_id = %s"
        params.append(plumber_id)
    
    expired = db_execute(conn, query, tuple(params)).fetchall()
    for r in expired:
        add_ledger_entry(conn, r["plumber_id"], "credit", r["points_requested"],
                          f"Refund — redemption request {r['request_code']} expired unresolved")
        db_execute(conn, "UPDATE redemption_requests SET status = 'expired', resolved_at = %s WHERE id = %s",
                      (now, r["id"]))
    if expired:
        conn.commit()


# ---------------------------------------------------------------------
# Login security helpers
# ---------------------------------------------------------------------

def check_lockout(conn, phone, role):
    row = db_execute(conn,
        "SELECT * FROM login_attempts WHERE phone = %s AND role = %s", (phone, role)
    ).fetchone()
    if not row or not row["locked_until"]:
        return None
        
    locked_until = row["locked_until"]
    if locked_until.tzinfo is None:
        locked_until = locked_until.replace(tzinfo=timezone.utc)
        
    now = datetime.now(timezone.utc)
    if now < locked_until:
        return int((locked_until - now).total_seconds() // 60) + 1
    return None


def record_failed_attempt(conn, phone, role):
    row = db_execute(conn,
        "SELECT * FROM login_attempts WHERE phone = %s AND role = %s", (phone, role)
    ).fetchone()
    now = datetime.now(timezone.utc)
    if row:
        count = row["attempt_count"] + 1
        locked_until = None
        if count >= MAX_LOGIN_ATTEMPTS:
            locked_until = now + timedelta(minutes=LOCKOUT_MINUTES)
            count = 0
        db_execute(conn,
            "UPDATE login_attempts SET attempt_count = %s, locked_until = %s, last_attempt_at = %s "
            "WHERE phone = %s AND role = %s",
            (count, locked_until, now, phone, role),
        )
    else:
        db_execute(conn,
            "INSERT INTO login_attempts (phone, role, attempt_count, locked_until, last_attempt_at) "
            "VALUES (%s, %s, %s, %s, %s)",
            (phone, role, 1, None, now),
        )
    conn.commit()


def reset_attempts(conn, phone, role):
    db_execute(conn, "DELETE FROM login_attempts WHERE phone = %s AND role = %s", (phone, role))
    conn.commit()


def current_plumber(conn):
    pid = session.get("plumber_id")
    if not pid:
        return None
    return db_execute(conn, "SELECT * FROM plumbers WHERE id = %s", (pid,)).fetchone()


def current_distributor(conn):
    did = session.get("distributor_id")
    if not did:
        return None
    return db_execute(conn, "SELECT * FROM distributors WHERE id = %s", (did,)).fetchone()


# ---------------------------------------------------------------------
# Routes — home / landing
# ---------------------------------------------------------------------

@app.route("/")
def home():
    conn = get_db()
    if current_plumber(conn):
        return redirect(url_for("dashboard"))
    if current_distributor(conn):
        return redirect(url_for("distributor_dashboard"))
    return render_template_string(LANDING_PAGE)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


# ---------------------------------------------------------------------
# Routes — plumber
# ---------------------------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():
    conn = get_db()
    if request.method == "GET":
        return render_template_string(REGISTER_PAGE)

    name = request.form.get("name", "").strip()
    phone = request.form.get("phone", "").strip()
    pin = request.form.get("pin", "").strip()
    shop_name = request.form.get("shop_name", "").strip()
    address = request.form.get("address", "").strip()
    distributor_code = request.form.get("distributor_code", "").strip().upper()

    if not name or not phone or not pin or not distributor_code:
        return render_template_string(REGISTER_PAGE, error="Name, phone, PIN, and distributor code are required.")
    if not phone.isdigit() or len(phone) != 10:
        return render_template_string(REGISTER_PAGE, error="Enter a valid 10-digit phone number.")
    if not pin.isdigit() or len(pin) != 4:
        return render_template_string(REGISTER_PAGE, error="PIN must be exactly 4 digits.")

    distributor = db_execute(conn, 
        "SELECT id FROM distributors WHERE distributor_code = %s", (distributor_code,)
    ).fetchone()
    if not distributor:
        return render_template_string(REGISTER_PAGE, error="That distributor code wasn't found. Check it with your distributor.")

    # FIX: Check BOTH tables for the phone number
    existing_plumber = db_execute(conn, "SELECT id FROM plumbers WHERE phone = %s", (phone,)).fetchone()
    existing_dist = db_execute(conn, "SELECT id FROM distributors WHERE phone = %s", (phone,)).fetchone()
    
    if existing_plumber or existing_dist:
        return render_template_string(REGISTER_PAGE, error="This phone number is already registered in our system. Please log in instead.")

    db_execute(conn,
        """INSERT INTO plumbers (name, phone, pin_hash, shop_name, address, distributor_id, created_at)
           VALUES (%s, %s, %s, %s, %s, %s, %s)""",
        (name, phone, generate_password_hash(pin), shop_name, address, distributor["id"], datetime.now(timezone.utc))
    )
    conn.commit()

    plumber = db_execute(conn, "SELECT id FROM plumbers WHERE phone = %s", (phone,)).fetchone()
    session.clear()
    session["plumber_id"] = plumber["id"]
    return redirect(url_for("dashboard"))


@app.route("/login", methods=["GET", "POST"])
def login():
    conn = get_db()
    if request.method == "GET":
        return render_template_string(LOGIN_PAGE)

    phone = request.form.get("phone", "").strip()
    pin = request.form.get("pin", "").strip()

    lock_minutes = check_lockout(conn, phone, "plumber")
    if lock_minutes:
        return render_template_string(LOGIN_PAGE, error=f"Too many failed attempts. Try again in {lock_minutes} minute(s).")

    plumber = db_execute(conn, "SELECT * FROM plumbers WHERE phone = %s", (phone,)).fetchone()
    if not plumber or not check_password_hash(plumber["pin_hash"], pin):
        record_failed_attempt(conn, phone, "plumber")
        return render_template_string(LOGIN_PAGE, error="Incorrect phone number or PIN.")

    reset_attempts(conn, phone, "plumber")
    session.clear()
    session["plumber_id"] = plumber["id"]
    return redirect(url_for("dashboard"))


@app.route("/dashboard")
def dashboard():
    conn = get_db()
    plumber = current_plumber(conn)
    if not plumber:
        return redirect(url_for("home"))

    expire_old_requests(conn, plumber["id"])

    balance = get_points_balance(conn, plumber["id"])
    history = db_execute(conn,
        "SELECT * FROM points_ledger WHERE plumber_id = %s ORDER BY id DESC LIMIT 20",
        (plumber["id"],)
    ).fetchall()
    pending_requests = db_execute(conn,
        "SELECT * FROM redemption_requests WHERE plumber_id = %s AND status = 'pending' ORDER BY id DESC",
        (plumber["id"],)
    ).fetchall()

    return render_template_string(
        DASHBOARD_PAGE, plumber=plumber, balance=balance, history=history,
        pending_requests=pending_requests, message=request.args.get("message"),
        error=request.args.get("error"),
    )


@app.route("/redeem-code", methods=["POST"])
def redeem_code():
    conn = get_db()
    plumber = current_plumber(conn)
    if not plumber:
        return redirect(url_for("home"))

    raw_input = request.form.get("codes", "") or request.form.get("code", "")
    candidates = [c for c in re.split(r"[,\s]+", raw_input.strip()) if c]

    if not candidates:
        return redirect(url_for("dashboard", error="Please enter at least one code."))

    seen = set()
    codes_to_process = []
    for c in candidates:
        raw = unformat_code(c)
        if raw not in seen:
            seen.add(raw)
            codes_to_process.append((c, raw))

    accepted_lines = []
    failed_lines = []
    total_points = 0
    now = datetime.now(timezone.utc)

    for original, raw in codes_to_process:
        if not validate_checksum(raw):
            failed_lines.append(f"{original}: mistyped / invalid code")
            continue

        code_row = db_execute(conn, "SELECT * FROM codes WHERE code = %s", (raw,)).fetchone()
        if not code_row:
            failed_lines.append(f"{original}: not found in our system")
            continue

        if code_row["status"] == "redeemed":
            failed_lines.append(f"{original}: already redeemed")
            continue

        points_earned = code_row["denomination"]
        db_execute(conn,
            "UPDATE codes SET status = 'redeemed', redeemed_by_plumber_id = %s, redeemed_at = %s WHERE id = %s",
            (plumber["id"], now, code_row["id"]),
        )
        add_ledger_entry(conn, plumber["id"], "credit", points_earned,
                          f"Redeemed code from batch {code_row['batch_id']}", code_id=code_row["id"])
        total_points += points_earned
        accepted_lines.append(f"{original}: +{points_earned} points")

    conn.commit()

    message = None
    error = None
    if accepted_lines:
        summary = f"{len(accepted_lines)} code(s) accepted! {total_points} points added."
        message = summary + "\n" + "\n".join(accepted_lines)
    if failed_lines:
        error = f"{len(failed_lines)} code(s) failed:\n" + "\n".join(failed_lines)

    return redirect(url_for("dashboard", message=message, error=error))


@app.route("/request-redemption", methods=["POST"])
def request_redemption():
    conn = get_db()
    plumber = current_plumber(conn)
    if not plumber:
        return redirect(url_for("home"))

    expire_old_requests(conn, plumber["id"])

    try:
        points_requested = int(request.form.get("points", "0"))
    except ValueError:
        return redirect(url_for("dashboard", error="Enter a valid number of points."))

    balance = get_points_balance(conn, plumber["id"])
    if points_requested <= 0:
        return redirect(url_for("dashboard", error="Enter a points amount greater than zero."))
    if points_requested > balance:
        return redirect(url_for("dashboard", error=f"You only have {balance} points available."))

    request_code = generate_request_code(conn)
    now = datetime.now(timezone.utc)
    expires = now + timedelta(minutes=REDEMPTION_REQUEST_VALID_MINUTES)

    db_execute(conn,
        """INSERT INTO redemption_requests
           (request_code, plumber_id, points_requested, status, created_at, expires_at)
           VALUES (%s, %s, %s, 'pending', %s, %s)""",
        (request_code, plumber["id"], points_requested, now, expires),
    )
    add_ledger_entry(conn, plumber["id"], "debit", points_requested,
                      f"Reserved for redemption request {request_code}")
    conn.commit()

    return redirect(url_for(
        "dashboard",
        message=f"Show this code to your distributor: {request_code} (valid {REDEMPTION_REQUEST_VALID_MINUTES} min)",
    ))


# ---------------------------------------------------------------------
# Routes — distributor
# ---------------------------------------------------------------------

@app.route("/distributor/register", methods=["GET", "POST"])
def distributor_register():
    conn = get_db()
    if request.method == "GET":
        return render_template_string(DISTRIBUTOR_REGISTER_PAGE)

    name = request.form.get("name", "").strip()
    phone = request.form.get("phone", "").strip()
    pin = request.form.get("pin", "").strip()

    if not name or not phone or not pin:
        return render_template_string(DISTRIBUTOR_REGISTER_PAGE, error="Name, phone, and PIN are required.")
    if not phone.isdigit() or len(phone) != 10:
        return render_template_string(DISTRIBUTOR_REGISTER_PAGE, error="Enter a valid 10-digit phone number.")
    if not pin.isdigit() or len(pin) != 4:
        return render_template_string(DISTRIBUTOR_REGISTER_PAGE, error="PIN must be exactly 4 digits.")

    # FIX: Check BOTH tables for the phone number
    existing_dist = db_execute(conn, "SELECT id FROM distributors WHERE phone = %s", (phone,)).fetchone()
    existing_plumber = db_execute(conn, "SELECT id FROM plumbers WHERE phone = %s", (phone,)).fetchone()
    
    if existing_dist or existing_plumber:
        return render_template_string(DISTRIBUTOR_REGISTER_PAGE, error="This phone number is already registered in our system. Please log in instead.")

    distributor_code = generate_distributor_code(conn)
    db_execute(conn,
        """INSERT INTO distributors (name, phone, pin_hash, distributor_code, created_at)
           VALUES (%s, %s, %s, %s, %s)""",
        (name, phone, generate_password_hash(pin), distributor_code, datetime.now(timezone.utc))
    )
    conn.commit()

    distributor = db_execute(conn, "SELECT id FROM distributors WHERE phone = %s", (phone,)).fetchone()
    session.clear()
    session["distributor_id"] = distributor["id"]
    return redirect(url_for("distributor_dashboard"))


@app.route("/distributor/login", methods=["GET", "POST"])
def distributor_login():
    conn = get_db()
    if request.method == "GET":
        return render_template_string(DISTRIBUTOR_LOGIN_PAGE)

    phone = request.form.get("phone", "").strip()
    pin = request.form.get("pin", "").strip()

    lock_minutes = check_lockout(conn, phone, "distributor")
    if lock_minutes:
        return render_template_string(DISTRIBUTOR_LOGIN_PAGE, error=f"Too many failed attempts. Try again in {lock_minutes} minute(s).")

    distributor = db_execute(conn, "SELECT * FROM distributors WHERE phone = %s", (phone,)).fetchone()
    if not distributor or not check_password_hash(distributor["pin_hash"], pin):
        record_failed_attempt(conn, phone, "distributor")
        return render_template_string(DISTRIBUTOR_LOGIN_PAGE, error="Incorrect phone number or PIN.")

    reset_attempts(conn, phone, "distributor")
    session.clear()
    session["distributor_id"] = distributor["id"]
    return redirect(url_for("distributor_dashboard"))


@app.route("/distributor/dashboard")
def distributor_dashboard():
    conn = get_db()
    distributor = current_distributor(conn)
    if not distributor:
        return redirect(url_for("home"))

    expire_old_requests(conn)

    pending = db_execute(conn,
        """SELECT rr.*, p.name AS plumber_name, p.phone AS plumber_phone, p.shop_name AS plumber_shop
           FROM redemption_requests rr
           JOIN plumbers p ON p.id = rr.plumber_id
           WHERE p.distributor_id = %s AND rr.status = 'pending'
           ORDER BY rr.id DESC""",
        (distributor["id"],)
    ).fetchall()
    
    resolved = db_execute(conn,
        """SELECT rr.*, p.name AS plumber_name, p.phone AS plumber_phone
           FROM redemption_requests rr
           JOIN plumbers p ON p.id = rr.plumber_id
           WHERE p.distributor_id = %s AND rr.status != 'pending'
           ORDER BY rr.id DESC LIMIT 20""",
        (distributor["id"],)
    ).fetchall()
    
    plumber_count = db_execute(conn, 
        "SELECT COUNT(*) AS c FROM plumbers WHERE distributor_id = %s", (distributor["id"],)
    ).fetchone()["c"]

    return render_template_string(
        DISTRIBUTOR_DASHBOARD_PAGE, distributor=distributor, pending=pending, resolved=resolved,
        plumber_count=plumber_count, message=request.args.get("message"), error=request.args.get("error"),
    )


@app.route("/distributor/resolve-request", methods=["POST"])
def resolve_request():
    conn = get_db()
    distributor = current_distributor(conn)
    if not distributor:
        return redirect(url_for("home"))

    try:
        request_id = int(request.form.get("request_id"))
    except (TypeError, ValueError):
        return redirect(url_for("distributor_dashboard", error="Invalid request."))
    action = request.form.get("action")

    req = db_execute(conn,
        """SELECT rr.*, p.distributor_id AS plumber_distributor_id
           FROM redemption_requests rr
           JOIN plumbers p ON p.id = rr.plumber_id
           WHERE rr.id = %s""",
        (request_id,)
    ).fetchone()

    if not req or req["plumber_distributor_id"] != distributor["id"]:
        return redirect(url_for("distributor_dashboard", error="Request not found."))
    if req["status"] != "pending":
        return redirect(url_for("distributor_dashboard", error="This request has already been resolved."))

    now = datetime.now(timezone.utc)

    if action == "approve":
        db_execute(conn,
            "UPDATE redemption_requests SET status = 'approved', resolved_at = %s, resolved_by = %s WHERE id = %s",
            (now, distributor["name"], req["id"]),
        )
        conn.commit()
        return redirect(url_for("distributor_dashboard", message=f"Approved request {req['request_code']}."))

    elif action == "reject":
        add_ledger_entry(conn, req["plumber_id"], "credit", req["points_requested"],
                          f"Refund — redemption request {req['request_code']} rejected by distributor")
        db_execute(conn,
            "UPDATE redemption_requests SET status = 'rejected', resolved_at = %s, resolved_by = %s WHERE id = %s",
            (now, distributor["name"], req["id"]),
        )
        conn.commit()
        return redirect(url_for("distributor_dashboard", message=f"Rejected request {req['request_code']}; points refunded to plumber."))

    return redirect(url_for("distributor_dashboard", error="Unknown action."))


# ---------------------------------------------------------------------
# HTML templates 
# ---------------------------------------------------------------------

BASE_STYLE = """
<style>
  * { box-sizing: border-box; }
  body { font-family: 'Segoe UI', Arial, sans-serif; background:#faf5f5; margin:0; padding:0; color:#1a1a1a; }
  .box { max-width:420px; margin:40px auto; background:#fff; padding:28px 32px; border-radius:12px; box-shadow:0 2px 10px rgba(0,0,0,0.08); }
  h2 { color:#8b0000; margin-top:0; }
  label { font-size:13px; color:#555; font-weight:600; }
  input { width:100%; padding:10px; margin:6px 0 14px 0; border:1px solid #ccc; border-radius:6px; font-size:15px; }
  button, .btn { display:inline-block; width:100%; padding:12px; background:#c0392b; color:#fff; border:none;
                 border-radius:8px; font-size:15px; font-weight:600; cursor:pointer; text-align:center; text-decoration:none; }
  button:hover, .btn:hover { background:#922b21; }
  .btn-outline { background:#fff; color:#c0392b; border:2px solid #c0392b; }
  .btn-outline:hover { background:#fdecea; }
  a { color:#c0392b; text-decoration:none; }
  .error { background:#fdecea; color:#a33; padding:10px 14px; border-radius:8px; margin-bottom:14px; font-size:14px; white-space:pre-line; }
  .message { background:#fdecea; color:#8b0000; padding:10px 14px; border-radius:8px; margin-bottom:14px; font-size:14px; white-space:pre-line; }
  .balance { font-size:34px; font-weight:bold; color:#c0392b; text-align:center; margin:10px 0; }
  table { width:100%; border-collapse:collapse; margin-top:10px; font-size:13px; }
  th, td { text-align:left; padding:8px 6px; border-bottom:1px solid #eee; }
  th { color:#666; font-size:12px; text-transform:uppercase; letter-spacing:0.03em; }
  hr { border:none; border-top:1px solid #eee; margin:22px 0; }
  .pill { display:inline-block; padding:2px 10px; border-radius:20px; font-size:12px; font-weight:600; }
  .pill-pending { background:#fff3cd; color:#8a6414; }
  .pill-approved { background:#d4edda; color:#1a7f4b; }
  .pill-rejected { background:#fdeaea; color:#a33; }
  .pill-expired { background:#eee; color:#777; }

  .hero { background:linear-gradient(135deg,#8b0000,#c0392b); color:#fff; padding:60px 20px 80px; text-align:center; }
  .hero h1 { font-size:32px; margin-bottom:10px; }
  .hero p { font-size:16px; max-width:560px; margin:0 auto; opacity:0.92; }
  .wrap { max-width:900px; margin:-50px auto 40px; padding:0 20px; }
  .how { background:#fff; border-radius:12px; box-shadow:0 2px 10px rgba(0,0,0,0.08); padding:26px 30px; margin-bottom:24px; }
  .how h3 { margin-top:0; color:#8b0000; }
  .steps { display:flex; gap:16px; flex-wrap:wrap; }
  .step { flex:1; min-width:150px; font-size:14px; color:#444; }
  .step-num { display:inline-flex; align-items:center; justify-content:center; width:26px; height:26px;
              background:#c0392b; color:#fff; border-radius:50%; font-weight:700; font-size:13px; margin-bottom:8px; }
  .cards { display:flex; gap:20px; flex-wrap:wrap; }
  .card { flex:1; min-width:260px; background:#fff; border-radius:12px; box-shadow:0 2px 10px rgba(0,0,0,0.08); padding:26px 28px; text-align:center; }
  .card .icon { font-size:34px; margin-bottom:6px; }
  .card h3 { margin:6px 0; color:#8b0000; }
  .card p { color:#666; font-size:14px; min-height:40px; }
  .card-actions { display:flex; gap:10px; margin-top:16px; }
</style>
"""

LANDING_PAGE = BASE_STYLE + """
<div class="hero">
  <h1>Plumber Rewards Program</h1>
  <p>Scratch a code, earn points, redeem them with your distributor — simple as that.</p>
</div>
<div class="wrap">
  <div class="how">
    <h3>How it works</h3>
    <div class="steps">
      <div class="step"><div class="step-num">1</div>Buy products and find a scratch code inside.</div>
      <div class="step"><div class="step-num">2</div>Enter the code in your portal to earn points.</div>
      <div class="step"><div class="step-num">3</div>Request a redemption and show the code to your distributor.</div>
      <div class="step"><div class="step-num">4</div>Your distributor approves it and settles your reward.</div>
    </div>
  </div>
  <div class="cards">
    <div class="card">
      <div class="icon">🔧</div>
      <h3>Plumber</h3>
      <p>Enter codes, track your points, and request redemptions.</p>
      <div class="card-actions">
        <a class="btn" href="/login">Log in</a>
        <a class="btn btn-outline" href="/register">Register</a>
      </div>
    </div>
    <div class="card">
      <div class="icon">🏬</div>
      <h3>Distributor</h3>
      <p>Approve redemption requests from your registered plumbers.</p>
      <div class="card-actions">
        <a class="btn" href="/distributor/login">Log in</a>
        <a class="btn btn-outline" href="/distributor/register">Register</a>
      </div>
    </div>
  </div>
</div>
"""

LOGIN_PAGE = BASE_STYLE + """
<div class="box">
  <h2>Plumber Login</h2>
  {% if error %}<div class="error">{{ error }}</div>{% endif %}
  <form method="post" action="/login">
    <label>Phone number</label>
    <input type="text" name="phone" maxlength="10" required>
    <label>4-digit PIN</label>
    <input type="password" name="pin" maxlength="4" required>
    <button type="submit">Log in</button>
  </form>
  <p style="text-align:center; margin-top:14px;">New here? <a href="/register">Register</a></p>
  <p style="text-align:center;"><a href="/">&larr; Back home</a></p>
</div>
"""

REGISTER_PAGE = BASE_STYLE + """
<div class="box">
  <h2>Plumber Registration</h2>
  {% if error %}<div class="error">{{ error }}</div>{% endif %}
  <form method="post" action="/register">
    <label>Full name</label>
    <input type="text" name="name" required>
    <label>Phone number (10 digits)</label>
    <input type="text" name="phone" maxlength="10" required>
    <label>Choose a 4-digit PIN</label>
    <input type="password" name="pin" maxlength="4" required>
    <label>Distributor code</label>
    <input type="text" name="distributor_code" maxlength="6" placeholder="Ask your distributor for this" required>
    <label>Shop name (optional)</label>
    <input type="text" name="shop_name">
    <label>Address (optional)</label>
    <input type="text" name="address">
    <button type="submit">Register</button>
  </form>
  <p style="text-align:center; margin-top:14px;">Already registered? <a href="/login">Log in</a></p>
  <p style="text-align:center;"><a href="/">&larr; Back home</a></p>
</div>
"""

DISTRIBUTOR_LOGIN_PAGE = BASE_STYLE + """
<div class="box">
  <h2>Distributor Login</h2>
  {% if error %}<div class="error">{{ error }}</div>{% endif %}
  <form method="post" action="/distributor/login">
    <label>Phone number</label>
    <input type="text" name="phone" maxlength="10" required>
    <label>4-digit PIN</label>
    <input type="password" name="pin" maxlength="4" required>
    <button type="submit">Log in</button>
  </form>
  <p style="text-align:center; margin-top:14px;">New distributor? <a href="/distributor/register">Register</a></p>
  <p style="text-align:center;"><a href="/">&larr; Back home</a></p>
</div>
"""

DISTRIBUTOR_REGISTER_PAGE = BASE_STYLE + """
<div class="box">
  <h2>Distributor Registration</h2>
  {% if error %}<div class="error">{{ error }}</div>{% endif %}
  <form method="post" action="/distributor/register">
    <label>Full name / business name</label>
    <input type="text" name="name" required>
    <label>Phone number (10 digits)</label>
    <input type="text" name="phone" maxlength="10" required>
    <label>Choose a 4-digit PIN</label>
    <input type="password" name="pin" maxlength="4" required>
    <button type="submit">Register</button>
  </form>
  <p style="text-align:center; margin-top:14px;">Already registered? <a href="/distributor/login">Log in</a></p>
  <p style="text-align:center;"><a href="/">&larr; Back home</a></p>
</div>
"""

DASHBOARD_PAGE = BASE_STYLE + """
<div class="box">
  <h2>Hello, {{ plumber['name'] }}</h2>
  {% if message %}<div class="message">{{ message }}</div>{% endif %}
  {% if error %}<div class="error">{{ error }}</div>{% endif %}

  <div>Your points balance</div>
  <div class="balance">{{ balance }}</div>

  <hr>
  <h3>Enter code(s)</h3>
  <form method="post" action="/redeem-code">
    <textarea name="codes" rows="4" placeholder="Enter one or more codes — one per line, or separated by commas/spaces&#10;e.g.&#10;XXXX-XXXX-XXXX&#10;YYYY-YYYY-YYYY" required
      style="width:100%; padding:10px; margin:6px 0 14px 0; border:1px solid #ccc; border-radius:6px; font-size:15px; font-family:inherit; resize:vertical;"></textarea>
    <button type="submit">Submit code(s)</button>
  </form>

  <hr>
  <h3>Request redemption</h3>
  <form method="post" action="/request-redemption">
    <input type="number" name="points" placeholder="Points to redeem" required>
    <button type="submit">Generate redemption request</button>
  </form>

  {% if pending_requests %}
    <h4>Pending requests</h4>
    <table>
      <tr><th>Request code</th><th>Points</th><th>Expires</th></tr>
      {% for r in pending_requests %}
      <tr><td>{{ r['request_code'] }}</td><td>{{ r['points_requested'] }}</td><td>{{ r['expires_at'].strftime('%H:%M') if r['expires_at'] else '' }} UTC</td></tr>
      {% endfor %}
    </table>
  {% endif %}

  <hr>
  <h3>Recent activity</h3>
  <table>
    <tr><th>Type</th><th>Amount</th><th>Balance after</th><th>Note</th></tr>
    {% for h in history %}
    <tr><td>{{ h['type'] }}</td><td>{{ h['amount'] }}</td><td>{{ h['balance_after'] }}</td><td>{{ h['note'] }}</td></tr>
    {% endfor %}
  </table>

  <hr>
  <p style="text-align:center;"><a href="/logout">Log out</a></p>
</div>
"""

DISTRIBUTOR_DASHBOARD_PAGE = BASE_STYLE + """
<div class="box" style="max-width:680px;">
  <h2>Welcome, {{ distributor['name'] }}</h2>
  {% if message %}<div class="message">{{ message }}</div>{% endif %}
  {% if error %}<div class="error">{{ error }}</div>{% endif %}

  <p>Your distributor code — share this with plumbers so they can register under you:</p>
  <div class="balance" style="font-size:26px; letter-spacing:3px;">{{ distributor['distributor_code'] }}</div>
  <p style="text-align:center; color:#666; font-size:13px;">{{ plumber_count }} plumber(s) registered under you</p>

  <hr>
  <h3>Pending redemption requests</h3>
  {% if pending %}
  <table>
    <tr><th>Code</th><th>Plumber</th><th>Points</th><th>Expires</th><th></th></tr>
    {% for r in pending %}
    <tr>
      <td>{{ r['request_code'] }}</td>
      <td>{{ r['plumber_name'] }}<br><span style="color:#999;">{{ r['plumber_phone'] }}</span></td>
      <td>{{ r['points_requested'] }}</td>
      <td>{{ r['expires_at'].strftime('%H:%M') if r['expires_at'] else '' }} UTC</td>
      <td>
        <form method="post" action="/distributor/resolve-request" style="display:inline;">
          <input type="hidden" name="request_id" value="{{ r['id'] }}">
          <input type="hidden" name="action" value="approve">
          <button type="submit" style="width:auto; padding:6px 12px; font-size:12px;">Approve</button>
        </form>
        <form method="post" action="/distributor/resolve-request" style="display:inline;">
          <input type="hidden" name="request_id" value="{{ r['id'] }}">
          <input type="hidden" name="action" value="reject">
          <button type="submit" style="width:auto; padding:6px 12px; font-size:12px; background:#a33;">Reject</button>
        </form>
      </td>
    </tr>
    {% endfor %}
  </table>
  {% else %}
  <p style="color:#999;">No pending requests right now.</p>
  {% endif %}

  <hr>
  <h3>Recent decisions</h3>
  {% if resolved %}
  <table>
    <tr><th>Code</th><th>Plumber</th><th>Points</th><th>Status</th></tr>
    {% for r in resolved %}
    <tr>
      <td>{{ r['request_code'] }}</td>
      <td>{{ r['plumber_name'] }}</td>
      <td>{{ r['points_requested'] }}</td>
      <td><span class="pill pill-{{ r['status'] }}">{{ r['status'] }}</span></td>
    </tr>
    {% endfor %}
  </table>
  {% else %}
  <p style="color:#999;">No decisions yet.</p>
  {% endif %}

  <hr>
  <p style="text-align:center;"><a href="/logout">Log out</a></p>
</div>
"""

init_portal_tables()

if __name__ == "__main__":
    app.run(debug=True)
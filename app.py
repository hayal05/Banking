"""
Basic Banking App - Starter Skeleton
-------------------------------------
A minimal Flask backend demonstrating core banking-app concepts:
account opening, login, account balance, money transfer, and
transaction history.

NOTE: This is a learning/prototype scaffold only.
Real banking systems require: encrypted data at rest/in transit,
MFA, fraud detection, audit logging, regulatory compliance (PCI-DSS,
SOX, KYC/AML), rate limiting, session hardening, secure/off-server
document storage, and a real database with proper transaction (ACID)
guarantees. Do not use this as-is for real money or real ID documents.
"""

import os
import re
import sqlite3
from datetime import datetime

from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeSerializer, BadSignature

app = Flask(__name__)
app.secret_key = "change-this-to-a-random-secret-in-production"
DB_PATH = "bank.db"

UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads", "ids")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "pdf"}
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 MB per upload
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

DEVICE_COOKIE = "device_account"
DEVICE_COOKIE_MAX_AGE = 60 * 60 * 24 * 180  # remember this device for 180 days
device_signer = URLSafeSerializer(app.secret_key, salt="device-remember")


# ---------- Database helpers ----------

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            phone TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
            id_document_filename TEXT,
            password_hash TEXT NOT NULL,
            balance REAL NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            type TEXT NOT NULL,
            amount REAL NOT NULL,
            note TEXT,
            counterparty TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        );
        """
    )
    # Seed demo users if none exist, so transfers/login have somewhere to go
    existing = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
    if existing == 0:
        now = datetime.now().isoformat(timespec="seconds")
        conn.execute(
            "INSERT INTO users (phone, full_name, id_document_filename, password_hash, balance, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("+15550001111", "Demo User", None, generate_password_hash("demo123"), 1000.00, now),
        )
        conn.execute(
            "INSERT INTO users (phone, full_name, id_document_filename, password_hash, balance, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("+15550002222", "Alice Example", None, generate_password_hash("alice123"), 500.00, now),
        )
    conn.commit()
    conn.close()


def current_user():
    if "user_id" not in session:
        return None
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    conn.close()
    return user


def login_required(view):
    def wrapped(*args, **kwargs):
        if current_user() is None:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    wrapped.__name__ = view.__name__
    return wrapped


def normalize_phone(raw):
    """Keep a leading + and digits only, so formatting differences don't matter."""
    raw = raw.strip()
    digits = re.sub(r"[^\d]", "", raw)
    if not digits:
        return ""
    return ("+" + digits) if raw.strip().startswith("+") else digits


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def remember_device(response, user_id):
    token = device_signer.dumps(user_id)
    response.set_cookie(
        DEVICE_COOKIE,
        token,
        max_age=DEVICE_COOKIE_MAX_AGE,
        httponly=True,
        samesite="Lax",
    )


def remembered_user():
    """Look up the account tied to this browser/device, if any."""
    token = request.cookies.get(DEVICE_COOKIE)
    if not token:
        return None
    try:
        user_id = device_signer.loads(token)
    except BadSignature:
        return None
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return user


# ---------- Routes ----------

@app.route("/")
def index():
    return redirect(url_for("dashboard") if current_user() else url_for("login"))


@app.route("/signup", methods=["GET", "POST"])
def signup():
    """Account opening: full name, phone number, and an ID document upload."""
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        phone = normalize_phone(request.form.get("phone", ""))
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        id_file = request.files.get("id_document")

        errors = []
        if not full_name:
            errors.append("Enter your full name.")
        if not phone or len(phone.lstrip("+")) < 7:
            errors.append("Enter a valid phone number.")
        if len(password) < 6:
            errors.append("Password must be at least 6 characters.")
        if password != confirm_password:
            errors.append("Passwords do not match.")
        if not id_file or id_file.filename == "":
            errors.append("Upload a photo or PDF of your ID.")
        elif not allowed_file(id_file.filename):
            errors.append("ID must be a PNG, JPG, or PDF file.")

        conn = get_db()
        if not errors and conn.execute("SELECT 1 FROM users WHERE phone = ?", (phone,)).fetchone():
            errors.append("An account with this phone number already exists.")

        if errors:
            conn.close()
            for e in errors:
                flash(e)
            return render_template("signup.html", full_name=full_name, phone=phone)

        # Save the ID document under a name tied to the account, not the
        # original filename the browser sent.
        ext = id_file.filename.rsplit(".", 1)[1].lower()
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        stored_name = secure_filename(f"{phone}_{timestamp}.{ext}")
        id_file.save(os.path.join(UPLOAD_FOLDER, stored_name))

        now = datetime.now().isoformat(timespec="seconds")
        cur = conn.execute(
            "INSERT INTO users (phone, full_name, id_document_filename, password_hash, balance, created_at) "
            "VALUES (?, ?, ?, ?, 0, ?)",
            (phone, full_name, stored_name, generate_password_hash(password), now),
        )
        conn.commit()
        user_id = cur.lastrowid
        conn.close()

        session.clear()
        session["user_id"] = user_id
        flash("Account created. Welcome to MyBank!")
        response = redirect(url_for("dashboard"))
        remember_device(response, user_id)
        return response

    return render_template("signup.html", full_name="", phone="")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Step 1: identify the account by phone number.

    If this device already has a remembered account (set at signup or a
    previous login), skip straight to the password-only step.
    """
    remembered = remembered_user()
    if remembered is not None:
        return redirect(url_for("login_password"))

    if request.method == "POST":
        phone = normalize_phone(request.form.get("phone", ""))
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE phone = ?", (phone,)).fetchone()
        conn.close()

        if user is None:
            flash("No account found for that phone number.")
        else:
            session["pending_user_id"] = user["id"]
            return redirect(url_for("login_password"))

    return render_template("login.html")


@app.route("/login/password", methods=["GET", "POST"])
def login_password():
    """Step 2: password-only sign-in for a recognized account/device."""
    remembered = remembered_user()
    pending_id = remembered["id"] if remembered is not None else session.get("pending_user_id")

    if pending_id is None:
        return redirect(url_for("login"))

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (pending_id,)).fetchone()
    conn.close()

    if user is None:
        session.pop("pending_user_id", None)
        return redirect(url_for("login"))

    if request.method == "POST":
        password = request.form.get("password", "")
        if check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            response = redirect(url_for("dashboard"))
            remember_device(response, user["id"])
            return response
        flash("Incorrect password.")

    return render_template("login_password.html", account=user)


@app.route("/login/switch-account")
def switch_account():
    """Forget this device's remembered account and go back to phone entry."""
    session.pop("pending_user_id", None)
    response = redirect(url_for("login"))
    response.delete_cookie(DEVICE_COOKIE)
    return response


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    conn = get_db()
    recent = conn.execute(
        "SELECT * FROM transactions WHERE user_id = ? ORDER BY id DESC LIMIT 5",
        (user["id"],),
    ).fetchall()
    conn.close()
    return render_template("dashboard.html", user=user, recent=recent)


@app.route("/transfer", methods=["GET", "POST"])
@login_required
def transfer():
    user = current_user()

    if request.method == "POST":
        recipient_phone = normalize_phone(request.form.get("recipient", ""))
        try:
            amount = float(request.form.get("amount", 0))
        except ValueError:
            amount = 0
        note = request.form.get("note", "").strip() or "Transfer"

        conn = get_db()
        recipient = conn.execute(
            "SELECT * FROM users WHERE phone = ?", (recipient_phone,)
        ).fetchone()

        if not recipient_phone:
            flash("Enter a recipient phone number.")
        elif recipient is None:
            flash(f"No account found for '{recipient_phone}'.")
        elif recipient["id"] == user["id"]:
            flash("You can't send funds to your own account.")
        elif amount <= 0:
            flash("Enter a valid amount greater than zero.")
        elif amount > user["balance"]:
            flash("Insufficient funds.")
        else:
            now = datetime.now().isoformat(timespec="seconds")
            try:
                conn.execute("BEGIN")
                conn.execute(
                    "UPDATE users SET balance = balance - ? WHERE id = ?",
                    (amount, user["id"]),
                )
                conn.execute(
                    "UPDATE users SET balance = balance + ? WHERE id = ?",
                    (amount, recipient["id"]),
                )
                conn.execute(
                    "INSERT INTO transactions (user_id, type, amount, note, counterparty, created_at) "
                    "VALUES (?, 'debit', ?, ?, ?, ?)",
                    (user["id"], amount, note, recipient["full_name"], now),
                )
                conn.execute(
                    "INSERT INTO transactions (user_id, type, amount, note, counterparty, created_at) "
                    "VALUES (?, 'credit', ?, ?, ?, ?)",
                    (recipient["id"], amount, note, user["full_name"], now),
                )
                conn.commit()
            except Exception:
                conn.rollback()
                conn.close()
                flash("Something went wrong. Transfer was not completed.")
                return render_template("transfer.html", user=user)

            conn.close()
            flash(f"Sent \u00b5{amount:,.2f} to {recipient['full_name']}.")
            return redirect(url_for("dashboard"))

        conn.close()

    return render_template("transfer.html", user=user)


@app.route("/transactions")
@login_required
def transactions():
    user = current_user()
    conn = get_db()
    all_tx = conn.execute(
        "SELECT * FROM transactions WHERE user_id = ? ORDER BY id DESC",
        (user["id"],),
    ).fetchall()
    conn.close()
    return render_template("transactions.html", user=user, transactions=all_tx)


if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)
else:
    # When run under a WSGI server (e.g. gunicorn app:app on Render),
    # __main__ never executes, so make sure the DB is still set up.
    init_db()

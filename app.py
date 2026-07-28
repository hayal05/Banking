"""
Basic Banking App - Starter Skeleton
-------------------------------------
A minimal Flask backend demonstrating core banking-app concepts:
login, account balance, money transfer, and transaction history.

NOTE: This is a learning/prototype scaffold only.
Real banking systems require: encrypted data at rest/in transit,
MFA, fraud detection, audit logging, regulatory compliance (PCI-DSS,
SOX, KYC/AML), rate limiting, session hardening, and a real database
with proper transaction (ACID) guarantees. Do not use this as-is
for real money.
"""

import sqlite3
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "change-this-to-a-random-secret-in-production"
DB_PATH = "bank.db"


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
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            balance REAL NOT NULL DEFAULT 0
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
    # Seed demo users if none exist, so transfers have somewhere to go
    existing = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
    if existing == 0:
        conn.execute(
            "INSERT INTO users (username, password_hash, balance) VALUES (?, ?, ?)",
            ("demo", generate_password_hash("demo123"), 1000.00),
        )
        conn.execute(
            "INSERT INTO users (username, password_hash, balance) VALUES (?, ?, ?)",
            ("alice", generate_password_hash("alice123"), 500.00),
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


# ---------- Routes ----------

@app.route("/")
def index():
    return redirect(url_for("dashboard") if current_user() else url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            return redirect(url_for("dashboard"))

        flash("Invalid username or password.")
    return render_template("login.html")


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
        recipient_username = request.form.get("recipient", "").strip()
        try:
            amount = float(request.form.get("amount", 0))
        except ValueError:
            amount = 0
        note = request.form.get("note", "").strip() or "Transfer"

        conn = get_db()
        recipient = conn.execute(
            "SELECT * FROM users WHERE username = ?", (recipient_username,)
        ).fetchone()

        if not recipient_username:
            flash("Enter a recipient username.")
        elif recipient is None:
            flash(f"No account found for '{recipient_username}'.")
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
                    (user["id"], amount, note, recipient["username"], now),
                )
                conn.execute(
                    "INSERT INTO transactions (user_id, type, amount, note, counterparty, created_at) "
                    "VALUES (?, 'credit', ?, ?, ?, ?)",
                    (recipient["id"], amount, note, user["username"], now),
                )
                conn.commit()
            except Exception:
                conn.rollback()
                conn.close()
                flash("Something went wrong. Transfer was not completed.")
                return render_template("transfer.html", user=user)

            conn.close()
            flash(f"Sent \u00b5{amount:,.2f} to {recipient['username']}.")
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


from flask import (
    Flask, render_template, request,
    redirect, url_for, session, flash
)

import sqlite3
import secrets
import os

from io import BytesIO
from flask import send_file
from reportlab.lib.pagesizes import A4
from decimal import Decimal, InvalidOperation
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "smartbank-demo-secret-change-before-deployment"
)

DATABASE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "database.db"
)


# =====================================
# DATABASE CONNECTION
# =====================================

def get_db():
    conn = sqlite3.connect(DATABASE, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


# =====================================
# DATABASE INITIALIZATION
# =====================================

def init_db():

    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            account_number TEXT UNIQUE NOT NULL,
            balance REAL DEFAULT 0,
            role TEXT DEFAULT 'customer',
            status TEXT DEFAULT 'active'
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            transaction_id TEXT UNIQUE NOT NULL,
            user_id INTEGER NOT NULL,
            type TEXT NOT NULL,
            amount REAL NOT NULL,
            description TEXT,
            date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    # Create default demo admin if it does not exist
    admin = conn.execute(
        "SELECT id FROM users WHERE email = ?",
        ("admin@smartbank.com",)
    ).fetchone()

    if not admin:
        conn.execute("""
            INSERT INTO users
            (name, email, password, account_number, balance, role, status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            "SmartBank Admin",
            "admin@smartbank.com",
            generate_password_hash("Admin@123"),
            "ADMIN000001",
            0,
            "admin",
            "active"
        ))

    conn.commit()
    conn.close()


# =====================================
# ACCOUNT NUMBER GENERATOR
# =====================================

def generate_account_number(conn):

    while True:

        number = str(secrets.randbelow(9000000000) + 1000000000)

        exists = conn.execute(
            "SELECT id FROM users WHERE account_number = ?",
            (number,)
        ).fetchone()

        if not exists:
            return number


# =====================================
# TRANSACTION ID GENERATOR
# =====================================

def generate_transaction_id():
    return "TXN" + secrets.token_hex(6).upper()


# =====================================
# AMOUNT VALIDATION
# =====================================

def get_amount(value):

    try:
        amount = Decimal(value)

        if not amount.is_finite():
            return None

        if amount <= 0 or amount > Decimal("100000000"):
            return None

        if amount != amount.quantize(Decimal("0.01")):
            return None

        return amount

    except (InvalidOperation, ValueError, TypeError):
        return None


# =====================================
# LOGIN REQUIRED DECORATORS
# =====================================

def customer_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        if "user_id" not in session:
            flash("Please login first.", "error")
            return redirect(url_for("login"))

        conn = get_db()

        user = conn.execute(
            "SELECT * FROM users WHERE id = ? AND role = 'customer'",
            (session["user_id"],)
        ).fetchone()

        conn.close()

        if not user:
            session.clear()
            flash("Please login again.", "error")
            return redirect(url_for("login"))

        if user["status"] != "active":
            session.clear()
            flash("Your account is blocked.", "error")
            return redirect(url_for("login"))

        return function(*args, **kwargs)

    return wrapper


def admin_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        if "admin_id" not in session:
            flash("Admin login required.", "error")
            return redirect(url_for("admin_login"))

        conn = get_db()

        admin = conn.execute(
            "SELECT id FROM users WHERE id = ? AND role = 'admin'",
            (session["admin_id"],)
        ).fetchone()

        conn.close()

        if not admin:
            session.clear()
            return redirect(url_for("admin_login"))

        return function(*args, **kwargs)

    return wrapper


# =====================================
# HOME PAGE
# =====================================

@app.route("/")
def index():
    return render_template("index.html")


# =====================================
# CUSTOMER REGISTRATION
# =====================================

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not name or not email or not password:
            flash("All required fields must be filled.", "error")
            return redirect(url_for("register"))

        if len(name) > 100 or len(email) > 254:
            flash("Name or email is too long.", "error")
            return redirect(url_for("register"))

        if len(password) < 8 or len(password) > 128:
            flash("Password must contain 8 to 128 characters.", "error")
            return redirect(url_for("register"))

        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return redirect(url_for("register"))

        conn = get_db()

        try:

            account_number = generate_account_number(conn)

            conn.execute("""
                INSERT INTO users
                (name, email, password, account_number, balance, role, status)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                name,
                email,
                generate_password_hash(password),
                account_number,
                0,
                "customer",
                "active"
            ))

            conn.commit()

            flash(
                "Registration successful! Your Account Number is " + account_number,
                "success"
            )

            return redirect(url_for("login"))

        except sqlite3.IntegrityError:
            flash("This email is already registered.", "error")

        finally:
            conn.close()

    return render_template("register.html")


# =====================================
# CUSTOMER AND ADMIN LOGIN
# =====================================


# =====================================
# CUSTOMER LOGIN
# =====================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        conn = get_db()

        user = conn.execute(
            "SELECT * FROM users WHERE email = ? AND role = 'customer'",
            (email,)
        ).fetchone()

        conn.close()

        if user and check_password_hash(user["password"], password):

            if user["status"] != "active":
                flash("Your account is blocked.", "error")
                return redirect(url_for("login"))

            session.clear()
            session["user_id"] = user["id"]

            flash("Login successful!", "success")
            return redirect(url_for("dashboard"))

        flash("Invalid email or password.", "error")

    return render_template("login.html")


# =====================================
# ADMIN LOGIN
# =====================================

@app.route("/admin_login", methods=["GET", "POST"])
def admin_login():

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        conn = get_db()

        admin = conn.execute(
            "SELECT * FROM users WHERE email = ? AND role = 'admin'",
            (email,)
        ).fetchone()

        conn.close()

        if admin and check_password_hash(admin["password"], password):

            session.clear()
            session["admin_id"] = admin["id"]

            flash("Admin login successful!", "success")
            return redirect(url_for("admin"))

        flash("Invalid admin email or password.", "error")

    return render_template("admin_login.html")

# =====================================
# CUSTOMER DASHBOARD
# =====================================

@app.route("/dashboard")
@customer_required
def dashboard():

    conn = get_db()

    user = conn.execute(
        "SELECT * FROM users WHERE id = ?",
        (session["user_id"],)
    ).fetchone()

    conn.close()

    return render_template(
        "dashboard.html",
        user=user
    )


# =====================================
# DOWNLOAD PDF STATEMENT
# =====================================

@app.route("/download_statement")
@customer_required
def download_statement():

    conn = get_db()

    user = conn.execute(
        "SELECT * FROM users WHERE id = ?",
        (session["user_id"],)
    ).fetchone()

    transactions = conn.execute("""
        SELECT * FROM transactions
        WHERE user_id = ?
        ORDER BY date DESC, id DESC
    """, (session["user_id"],)).fetchall()

    conn.close()

    pdf_buffer = BytesIO()

    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer,
        Table, TableStyle
    )
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import inch

    doc = SimpleDocTemplate(
        pdf_buffer,
        pagesize=A4
    )

    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph(
        "SMARTBANK - ACCOUNT STATEMENT",
        styles["Title"]
    ))

    elements.append(Spacer(1, 20))

    elements.append(Paragraph(
        f"Customer Name: {user['name']}",
        styles["Normal"]
    ))

    elements.append(Paragraph(
        f"Account Number: {user['account_number']}",
        styles["Normal"]
    ))

    elements.append(Paragraph(
        f"Current Balance: Rs. {float(user['balance']):.2f}",
        styles["Normal"]
    ))

    elements.append(Spacer(1, 20))

    data = [
        ["Transaction ID", "Type", "Amount", "Description", "Date"]
    ]

    for transaction in transactions:
        data.append([
            str(transaction["transaction_id"]),
            str(transaction["type"]),
            f"Rs. {float(transaction['amount']):.2f}",
            str(transaction["description"] or "")[:35],
            str(transaction["date"])
        ])

    table = Table(
        data,
        colWidths=[
            1.1*inch, 0.8*inch, 0.9*inch,
            1.5*inch, 1.2*inch
        ]
    )

    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0),
         colors.HexColor("#8052C7")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 6),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE")
    ]))

    elements.append(table)

    doc.build(elements)

    pdf_buffer.seek(0)

    return send_file(
        pdf_buffer,
        as_attachment=True,
        download_name="SmartBank_Statement.pdf",
        mimetype="application/pdf"
    )


# =====================================
# DEPOSIT MONEY
# =====================================

@app.route("/deposit", methods=["GET", "POST"])
@customer_required
def deposit():

    conn = get_db()

    user = conn.execute(
        "SELECT * FROM users WHERE id = ?",
        (session["user_id"],)
    ).fetchone()

    if request.method == "POST":

        amount = get_amount(request.form.get("amount", ""))

        description = request.form.get(
            "description", "Cash Deposit"
        ).strip()[:200] or "Cash Deposit"

        if amount is None:
            conn.close()
            flash("Please enter a valid amount.", "error")
            return redirect(url_for("deposit"))

        try:
            conn.execute("BEGIN IMMEDIATE")

            conn.execute("""
                UPDATE users
                SET balance = balance + ?
                WHERE id = ? AND status = 'active'
            """, (float(amount), session["user_id"]))

            conn.execute("""
                INSERT INTO transactions
                (transaction_id, user_id, type, amount, description)
                VALUES (?, ?, ?, ?, ?)
            """, (
                generate_transaction_id(),
                session["user_id"],
                "DEPOSIT",
                float(amount),
                description
            ))

            conn.commit()

            flash("Money deposited successfully!", "success")

        except Exception:
            conn.rollback()
            flash("Deposit failed. Please try again.", "error")

        finally:
            conn.close()

        return redirect(url_for("deposit"))

    conn.close()

    return render_template(
        "deposit.html",
        user=user
    )


# =====================================
# WITHDRAW MONEY
# =====================================

@app.route("/withdraw", methods=["GET", "POST"])
@customer_required
def withdraw():

    conn = get_db()

    user = conn.execute(
        "SELECT * FROM users WHERE id = ?",
        (session["user_id"],)
    ).fetchone()

    if request.method == "POST":

        amount = get_amount(request.form.get("amount", ""))

        description = request.form.get(
            "description", "Cash Withdrawal"
        ).strip()[:200] or "Cash Withdrawal"

        if amount is None:
            conn.close()
            flash("Please enter a valid amount.", "error")
            return redirect(url_for("withdraw"))

        try:
            conn.execute("BEGIN IMMEDIATE")

            result = conn.execute("""
                UPDATE users
                SET balance = balance - ?
                WHERE id = ?
                AND status = 'active'
                AND balance >= ?
            """, (
                float(amount),
                session["user_id"],
                float(amount)
            ))

            if result.rowcount == 0:
                conn.rollback()
                flash("Insufficient balance.", "error")

            else:

                conn.execute("""
                    INSERT INTO transactions
                    (transaction_id, user_id, type, amount, description)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    generate_transaction_id(),
                    session["user_id"],
                    "WITHDRAW",
                    float(amount),
                    description
                ))

                conn.commit()
                flash("Money withdrawn successfully!", "success")

        except Exception:
            conn.rollback()
            flash("Withdrawal failed. Please try again.", "error")

        finally:
            conn.close()

        return redirect(url_for("withdraw"))

    conn.close()

    return render_template(
        "withdraw.html",
        user=user
    )


# =====================================
# TRANSFER MONEY
# =====================================

@app.route("/transfer", methods=["GET", "POST"])
@customer_required
def transfer():

    conn = get_db()

    user = conn.execute(
        "SELECT * FROM users WHERE id = ?",
        (session["user_id"],)
    ).fetchone()

    if request.method == "POST":

        receiver_account = request.form.get(
            "receiver_account", ""
        ).strip()

        amount = get_amount(request.form.get("amount", ""))

        description = request.form.get(
            "description", "Money Transfer"
        ).strip()[:200] or "Money Transfer"

        if amount is None:
            conn.close()
            flash("Please enter a valid amount.", "error")
            return redirect(url_for("transfer"))

        try:
            conn.execute("BEGIN IMMEDIATE")

            receiver = conn.execute("""
                SELECT * FROM users
                WHERE account_number = ?
                AND role = 'customer'
                AND status = 'active'
            """, (receiver_account,)).fetchone()

            if not receiver:
                conn.rollback()
                flash("Receiver account not found or inactive.", "error")

            elif receiver["id"] == session["user_id"]:
                conn.rollback()
                flash("You cannot transfer money to yourself.", "error")

            else:

                result = conn.execute("""
                    UPDATE users
                    SET balance = balance - ?
                    WHERE id = ?
                    AND status = 'active'
                    AND balance >= ?
                """, (
                    float(amount),
                    session["user_id"],
                    float(amount)
                ))

                if result.rowcount == 0:
                    conn.rollback()
                    flash("Insufficient balance.", "error")

                else:

                    conn.execute("""
                        UPDATE users
                        SET balance = balance + ?
                        WHERE id = ?
                    """, (
                        float(amount),
                        receiver["id"]
                    ))

                    transaction_id = generate_transaction_id()

                    conn.execute("""
                        INSERT INTO transactions
                        (transaction_id, user_id, type, amount, description)
                        VALUES (?, ?, ?, ?, ?)
                    """, (
                        transaction_id,
                        session["user_id"],
                        "TRANSFER_SENT",
                        float(amount),
                        "To " + receiver_account + ": " + description
                    ))

                    conn.execute("""
                        INSERT INTO transactions
                        (transaction_id, user_id, type, amount, description)
                        VALUES (?, ?, ?, ?, ?)
                    """, (
                        transaction_id + "R",
                        receiver["id"],
                        "TRANSFER_RECEIVED",
                        float(amount),
                        "From " + user["account_number"] + ": " + description
                    ))

                    conn.commit()

                    flash("Money transferred successfully!", "success")

        except Exception:
            conn.rollback()
            flash("Transfer failed. Please try again.", "error")

        finally:
            conn.close()

        return redirect(url_for("transfer"))

    conn.close()

    return render_template(
        "transfer.html",
        user=user
    )


# =====================================
# TRANSACTION HISTORY
# =====================================


@app.route("/history")
@customer_required
def history():

    search = request.args.get("search", "").strip()
    transaction_type = request.args.get("type", "").strip()

    conn = get_db()

    query = """
        SELECT * FROM transactions
        WHERE user_id = ?
    """
    params = [session["user_id"]]

    if search:
        query += " AND description LIKE ?"
        params.append(f"%{search}%")

    if transaction_type:
        query += " AND type = ?"
        params.append(transaction_type)

    query += " ORDER BY date DESC, id DESC"

    transactions = conn.execute(query, params).fetchall()

    conn.close()

    return render_template(
        "history.html",
        transactions=transactions,
        search=search,
        selected_type=transaction_type
    )


# =====================================
# ADMIN DASHBOARD
# =====================================

@app.route("/admin")
@admin_required
def admin():

    conn = get_db()

    total_customers = conn.execute("""
        SELECT COUNT(*) FROM users
        WHERE role = 'customer'
    """).fetchone()[0]

    total_accounts = total_customers

    total_transactions = conn.execute("""
        SELECT COUNT(*) FROM transactions
    """).fetchone()[0]

    total_balance = conn.execute("""
        SELECT COALESCE(SUM(balance), 0)
        FROM users
        WHERE role = 'customer'
    """).fetchone()[0]

    customers = conn.execute("""
        SELECT * FROM users
        WHERE role = 'customer'
        ORDER BY id DESC
    """).fetchall()

    recent_transactions = conn.execute("""
        SELECT * FROM transactions
        ORDER BY date DESC, id DESC
        LIMIT 20
    """).fetchall()

    conn.close()

    return render_template(
        "admin.html",
        total_customers=total_customers,
        total_accounts=total_accounts,
        total_transactions=total_transactions,
        total_balance=total_balance,
        customers=customers,
        recent_transactions=recent_transactions
    )


# =====================================
# BLOCK / ACTIVATE ACCOUNT
# =====================================

@app.route("/admin/toggle/<int:user_id>", methods=["POST"])
@admin_required
def toggle_account(user_id):

    conn = get_db()

    customer = conn.execute("""
        SELECT * FROM users
        WHERE id = ? AND role = 'customer'
    """, (user_id,)).fetchone()

    if customer:

        new_status = (
            "blocked"
            if customer["status"] == "active"
            else "active"
        )

        conn.execute("""
            UPDATE users
            SET status = ?
            WHERE id = ?
        """, (new_status, user_id))

        conn.commit()

        flash("Customer account updated.", "success")

    else:
        flash("Customer not found.", "error")

    conn.close()

    return redirect(url_for("admin"))


# =====================================
# LOGOUT
# =====================================

@app.route("/logout")
def logout():

    session.clear()

    flash("You have logged out successfully.", "success")

    return redirect(url_for("index"))


# =====================================
# RUN APPLICATION
# =====================================

init_db()

if __name__ == "__main__":
    app.run(debug=True)
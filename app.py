from datetime import date, datetime, timezone
from contextlib import contextmanager
from functools import wraps
import hmac
import math
import os
from pathlib import Path
import secrets
import sqlite3

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash


BASE_DIR = Path(__file__).resolve().parent
app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
    DATABASE=os.environ.get("DATABASE_PATH", str(BASE_DIR / "expense.db")),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

CATEGORIES = [
    "Food",
    "Transport",
    "Shopping",
    "Bills",
    "Health",
    "Education",
    "Entertainment",
    "Other",
]


@contextmanager
def get_db():
    connection = sqlite3.connect(app.config["DATABASE"])
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


def init_db():
    database_path = Path(app.config["DATABASE"])
    database_path.parent.mkdir(parents=True, exist_ok=True)
    with get_db() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS expense (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                amount REAL NOT NULL,
                category TEXT NOT NULL,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                expense_date TEXT,
                created_at TEXT
            )
            """
        )
        existing_columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(expense)").fetchall()
        }
        if "user_id" not in existing_columns:
            connection.execute(
                "ALTER TABLE expense ADD COLUMN user_id INTEGER REFERENCES users(id) ON DELETE CASCADE"
            )
        if "expense_date" not in existing_columns:
            connection.execute("ALTER TABLE expense ADD COLUMN expense_date TEXT")
        if "created_at" not in existing_columns:
            connection.execute("ALTER TABLE expense ADD COLUMN created_at TEXT")
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_expense_user_date ON expense(user_id, expense_date)"
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS contact_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                message TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in to continue.", "info")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped_view


def csrf_token():
    token = session.get("_csrf_token")
    if token is None:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


@app.before_request
def protect_forms():
    if request.method == "POST":
        submitted_token = request.form.get("_csrf_token", "")
        expected_token = session.get("_csrf_token", "")
        if not submitted_token or not expected_token or not hmac.compare_digest(
            submitted_token, expected_token
        ):
            abort(400, description="Your form has expired. Please reload the page and try again.")


@app.context_processor
def inject_template_values():
    user = None
    user_id = session.get("user_id")
    if user_id:
        with get_db() as connection:
            user = connection.execute(
                "SELECT id, name, email FROM users WHERE id = ?", (user_id,)
            ).fetchone()
        if user is None:
            session.clear()
    return {
        "current_user": user,
        "csrf_token": csrf_token,
        "today_year": date.today().year,
    }


@app.route("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/home")
def home():
    return redirect(url_for("index"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not name or len(name) > 80:
            flash("Please enter your name (up to 80 characters).", "error")
        elif not email or len(email) > 254 or "@" not in email:
            flash("Please enter a valid email address.", "error")
        elif len(password) < 8:
            flash("Your password must be at least 8 characters long.", "error")
        elif password != confirm_password:
            flash("The passwords do not match.", "error")
        else:
            try:
                with get_db() as connection:
                    connection.execute(
                        """
                        INSERT INTO users (name, email, password_hash, created_at)
                        VALUES (?, ?, ?, ?)
                        """,
                        (
                            name,
                            email,
                            generate_password_hash(password),
                            datetime.now(timezone.utc).isoformat(),
                        ),
                    )
                    user = connection.execute(
                        "SELECT id, name FROM users WHERE email = ?", (email,)
                    ).fetchone()
                session.clear()
                session["user_id"] = user["id"]
                flash("Your account is ready. Welcome to Expense Tracker!", "success")
                return redirect(url_for("dashboard"))
            except sqlite3.IntegrityError:
                flash("An account with that email already exists. Please log in.", "error")

    return render_template("registar.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        with get_db() as connection:
            user = connection.execute(
                "SELECT id, password_hash FROM users WHERE email = ?", (email,)
            ).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            flash("Welcome back!", "success")
            return redirect(url_for("dashboard"))
        flash("Email or password is incorrect.", "error")

    return render_template("login.html")


@app.post("/logout")
@login_required
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("index"))


@app.route("/dashboard")
@login_required
def dashboard():
    user_id = session["user_id"]
    current_month = date.today().strftime("%Y-%m")
    search = request.args.get("q", "").strip()[:80]
    category = request.args.get("category", "").strip()

    conditions = ["user_id = ?"]
    parameters = [user_id]
    if search:
        conditions.append("(title LIKE ? OR category LIKE ?)")
        parameters.extend([f"%{search}%", f"%{search}%"])
    if category in CATEGORIES:
        conditions.append("category = ?")
        parameters.append(category)
    where_clause = " AND ".join(conditions)

    with get_db() as connection:
        expenses = connection.execute(
            f"""
            SELECT id, title, amount, category, expense_date
            FROM expense
            WHERE {where_clause}
            ORDER BY COALESCE(expense_date, '') DESC, id DESC
            LIMIT 100
            """,
            parameters,
        ).fetchall()
        totals = connection.execute(
            """
            SELECT
                COALESCE(SUM(amount), 0) AS total,
                COALESCE(SUM(CASE WHEN substr(expense_date, 1, 7) = ? THEN amount ELSE 0 END), 0) AS month_total,
                COUNT(*) AS count
            FROM expense
            WHERE user_id = ?
            """,
            (current_month, user_id),
        ).fetchone()
        category_totals = connection.execute(
            """
            SELECT category, SUM(amount) AS total
            FROM expense
            WHERE user_id = ? AND substr(expense_date, 1, 7) = ?
            GROUP BY category
            ORDER BY total DESC
            LIMIT 5
            """,
            (user_id, current_month),
        ).fetchall()

    return render_template(
        "dashboard.html",
        expenses=expenses,
        totals=totals,
        category_totals=category_totals,
        categories=CATEGORIES,
        search=search,
        selected_category=category,
    )


@app.route("/expenses/add", methods=["GET", "POST"])
@app.route("/add_expanse", methods=["GET", "POST"])
@login_required
def add_expense():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        amount_value = request.form.get("amount", "").strip()
        category = request.form.get("category", "").strip()
        expense_date = request.form.get("expense_date", "").strip()

        try:
            amount = float(amount_value)
        except ValueError:
            amount = 0
        try:
            parsed_date = date.fromisoformat(expense_date)
        except ValueError:
            parsed_date = None

        if not title or len(title) > 100:
            flash("Please enter a title (up to 100 characters).", "error")
        elif not math.isfinite(amount) or amount <= 0 or amount > 1_000_000_000:
            flash("Enter an amount greater than 0 and no more than 1,000,000,000.", "error")
        elif category not in CATEGORIES:
            flash("Please select a category from the list.", "error")
        elif parsed_date is None:
            flash("Please enter a valid expense date.", "error")
        else:
            with get_db() as connection:
                connection.execute(
                    """
                    INSERT INTO expense (title, amount, category, user_id, expense_date, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        title,
                        amount,
                        category,
                        session["user_id"],
                        parsed_date.isoformat(),
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )
            flash("Expense added successfully.", "success")
            return redirect(url_for("dashboard"))

    return render_template("add_expanse.html", categories=CATEGORIES, today=date.today().isoformat())


@app.route("/expenses/<int:expense_id>/edit", methods=["GET", "POST"])
@login_required
def edit_expense(expense_id):
    with get_db() as connection:
        expense = connection.execute(
            "SELECT * FROM expense WHERE id = ? AND user_id = ?",
            (expense_id, session["user_id"]),
        ).fetchone()
    if expense is None:
        abort(404)

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        amount_value = request.form.get("amount", "").strip()
        category = request.form.get("category", "").strip()
        expense_date = request.form.get("expense_date", "").strip()
        try:
            amount = float(amount_value)
        except ValueError:
            amount = 0
        try:
            parsed_date = date.fromisoformat(expense_date)
        except ValueError:
            parsed_date = None

        if not title or len(title) > 100:
            flash("Please enter a title (up to 100 characters).", "error")
        elif not math.isfinite(amount) or amount <= 0 or amount > 1_000_000_000:
            flash("Enter an amount greater than 0 and no more than 1,000,000,000.", "error")
        elif category not in CATEGORIES:
            flash("Please select a category from the list.", "error")
        elif parsed_date is None:
            flash("Please enter a valid expense date.", "error")
        else:
            with get_db() as connection:
                connection.execute(
                    """
                    UPDATE expense
                    SET title = ?, amount = ?, category = ?, expense_date = ?
                    WHERE id = ? AND user_id = ?
                    """,
                    (
                        title,
                        amount,
                        category,
                        parsed_date.isoformat(),
                        expense_id,
                        session["user_id"],
                    ),
                )
            flash("Expense updated successfully.", "success")
            return redirect(url_for("dashboard"))

    return render_template("edit_expanse.html", expense=expense, categories=CATEGORIES)


@app.post("/expenses/<int:expense_id>/delete")
@login_required
def delete_expense(expense_id):
    with get_db() as connection:
        result = connection.execute(
            "DELETE FROM expense WHERE id = ? AND user_id = ?",
            (expense_id, session["user_id"]),
        )
    if result.rowcount == 0:
        abort(404)
    flash("Expense deleted.", "success")
    return redirect(url_for("dashboard"))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        message = request.form.get("message", "").strip()
        if not name or len(name) > 80:
            flash("Please enter your name (up to 80 characters).", "error")
        elif not email or len(email) > 254 or "@" not in email:
            flash("Please enter a valid email address.", "error")
        elif not message or len(message) > 2000:
            flash("Please enter a message (up to 2,000 characters).", "error")
        else:
            with get_db() as connection:
                connection.execute(
                    """
                    INSERT INTO contact_messages (name, email, message, created_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (name, email, message, datetime.now(timezone.utc).isoformat()),
                )
            flash("Thanks for getting in touch. Your message has been saved.", "success")
            return redirect(url_for("contact"))
    return render_template("contact.html")


init_db()


if __name__ == "__main__":
    app.run(debug=False)

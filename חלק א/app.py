import hmac
import math
import re
import secrets
import time
from datetime import timedelta
from functools import wraps

from flask import (Flask, abort, flash, redirect, render_template, request,
                   session, url_for)

import config
import db
import mailer
import security

app = Flask(__name__)
app.secret_key = config.load_secret_key()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
)

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,30}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# --- CSRF ------------------------------------------------------------------
def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(16)
    return session["_csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token
app.jinja_env.globals["policy"] = config.PASSWORD_POLICY


@app.before_request
def check_csrf():
    if request.method == "POST":
        sent = request.form.get("csrf_token", "")
        if not sent or not hmac.compare_digest(sent, session.get("_csrf", "")):
            abort(400)


@app.errorhandler(400)
def bad_request(_):
    return render_template("error.html", message="The form expired. Go back and try again."), 400


# --- helpers ---------------------------------------------------------------
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def current_user():
    return db.get_user_by_id(session["user_id"]) if "user_id" in session else None


def password_problems(user_id, new_password, username=""):
    """Policy problems plus reuse of recent passwords."""
    problems = security.check_policy(new_password, username)
    for old in db.get_history(user_id, config.PASSWORD_POLICY["history"]):
        if security.verify_password(new_password, old["salt"], old["password_hash"]):
            n = config.PASSWORD_POLICY["history"]
            problems.append(f"You can't reuse any of your last {n} passwords.")
            break
    return problems


def set_new_password(user_id, password):
    salt = security.new_salt()
    db.update_password(user_id, security.hash_password(password, salt), salt)


# --- routes ----------------------------------------------------------------
@app.route("/")
def index():
    return redirect(url_for("system" if "user_id" in session else "login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    errors, form = {}, {"username": "", "email": ""}
    if request.method == "POST":
        form["username"] = request.form.get("username", "").strip()
        form["email"] = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        if not USERNAME_RE.match(form["username"]):
            errors["username"] = "Use 3 to 30 letters, digits, dots, dashes or underscores."
        elif db.get_user_by_username(form["username"]):
            errors["username"] = "That username is taken."
        if not EMAIL_RE.match(form["email"]) or len(form["email"]) > 120:
            errors["email"] = "Enter a valid email address."
        elif db.get_user_by_email(form["email"]):
            errors["email"] = "An account with this email already exists."
        problems = security.check_policy(password, form["username"])
        if problems:
            errors["password"] = " ".join(problems)
        elif password != confirm:
            errors["confirm"] = "The passwords don't match."

        if not errors:
            salt = security.new_salt()
            db.create_user(form["username"], form["email"],
                           security.hash_password(password, salt), salt)
            flash("Account created. Sign in to continue.", "ok")
            return redirect(url_for("login"))
    return render_template("register.html", errors=errors, form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    error, username = None, ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = db.get_user_by_username(username)
        now = int(time.time())

        if user and user["locked_until"] > now:
            minutes = math.ceil((user["locked_until"] - now) / 60)
            error = f"Too many failed attempts. Try again in {minutes} minute{'s' if minutes != 1 else ''}."
        elif user and security.verify_password(password, user["salt"], user["password_hash"]):
            db.set_login_state(user["id"], 0, 0)
            session.clear()
            session.permanent = True
            session["user_id"] = user["id"]
            return redirect(url_for("system"))
        else:
            if not user:
                # Spend the same time as a real check so timing doesn't reveal usernames.
                security.hash_password(password, "00" * 16)
                error = "Incorrect username or password."
            else:
                attempts = user["failed_attempts"] + 1
                if attempts >= config.MAX_LOGIN_ATTEMPTS:
                    db.set_login_state(user["id"], 0, now + config.LOCKOUT_MINUTES * 60)
                    error = f"Too many failed attempts. Try again in {config.LOCKOUT_MINUTES} minutes."
                else:
                    db.set_login_state(user["id"], attempts, 0)
                    error = "Incorrect username or password."
    return render_template("login.html", error=error, username=username)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/system", methods=["GET", "POST"])
@login_required
def system():
    user = current_user()
    if not user:
        session.clear()
        return redirect(url_for("login"))
    errors, form = {}, {"name": "", "email": "", "phone": "", "address": ""}
    if request.method == "POST":
        for key in form:
            form[key] = request.form.get(key, "").strip()
        if not form["name"]:
            errors["name"] = "Enter the customer's name."
        elif len(form["name"]) > 120:
            errors["name"] = "Keep the name under 120 characters."
        if form["email"] and not EMAIL_RE.match(form["email"]):
            errors["email"] = "Enter a valid email address."
        if len(form["phone"]) > 40:
            errors["phone"] = "Keep the phone number under 40 characters."
        if len(form["address"]) > 255:
            errors["address"] = "Keep the address under 255 characters."
        if not errors:
            db.add_customer(form["name"], form["email"], form["phone"],
                            form["address"], user["id"])
            flash(f"{form['name']} added to customers.", "ok")
            return redirect(url_for("system"))
    return render_template("system.html", user=user, errors=errors, form=form,
                           customers=db.list_customers())


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    user = current_user()
    errors = {}
    if request.method == "POST":
        current = request.form.get("current", "")
        new = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        if not security.verify_password(current, user["salt"], user["password_hash"]):
            errors["current"] = "That isn't your current password."
        problems = password_problems(user["id"], new, user["username"])
        if problems:
            errors["password"] = " ".join(problems)
        elif new != confirm:
            errors["confirm"] = "The passwords don't match."
        if not errors:
            set_new_password(user["id"], new)
            flash("Password changed.", "ok")
            return redirect(url_for("system"))
    return render_template("change_password.html", user=user, errors=errors, reset=False)


# --- forgot password -------------------------------------------------------
@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    error = None
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        if not EMAIL_RE.match(email):
            error = "Enter a valid email address."
        else:
            user = db.get_user_by_email(email)
            if user:
                code = security.generate_reset_code()
                ttl = config.RESET_CODE_TTL_MINUTES
                db.save_reset_code(user["id"], code, int(time.time()) + ttl * 60)
                mailer.send_mail(
                    email, "Your Comunication_LTD reset code",
                    f"Hi {user['username']},\n\nYour one-time reset code is:\n\n{code}\n\n"
                    f"It works once and expires in {ttl} minutes. "
                    "If you didn't ask for it, ignore this email.\n",
                )
            # Same response whether or not the account exists.
            session["reset_email"] = email
            return redirect(url_for("forgot_verify"))
    return render_template("forgot.html", error=error)


@app.route("/forgot/verify", methods=["GET", "POST"])
def forgot_verify():
    email = session.get("reset_email")
    if not email:
        return redirect(url_for("forgot"))
    error = None
    if request.method == "POST":
        code = request.form.get("code", "").strip().lower()
        user = db.get_user_by_email(email)
        record = db.find_valid_reset_code(user["id"], code) if user else None
        if record:
            db.use_reset_code(record["id"])
            session.pop("reset_email", None)
            session["reset_user_id"] = user["id"]
            return redirect(url_for("reset_password"))
        error = "That code is wrong or has expired."
    return render_template("forgot_verify.html", error=error, email=email,
                           dev_mail=not mailer.is_configured())


@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    user_id = session.get("reset_user_id")
    user = db.get_user_by_id(user_id) if user_id else None
    if not user:
        return redirect(url_for("forgot"))
    errors = {}
    if request.method == "POST":
        new = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        problems = password_problems(user["id"], new, user["username"])
        if problems:
            errors["password"] = " ".join(problems)
        elif new != confirm:
            errors["confirm"] = "The passwords don't match."
        if not errors:
            set_new_password(user["id"], new)
            session.clear()
            flash("Password changed. Sign in with the new one.", "ok")
            return redirect(url_for("login"))
    return render_template("change_password.html", user=user, errors=errors, reset=True)


if __name__ == "__main__":
    db.init_db()
    app.run(debug=False, port=5000)

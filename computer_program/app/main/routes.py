from flask import Blueprint, render_template, redirect, url_for, session, flash, abort, request
from werkzeug.security import generate_password_hash, check_password_hash

from app import db
from app.models import User
from app.forms import LoginForm, RegistrationForm, ChangePasswordForm

from app.security.decorators import login_required, roles_required
from app.security.repository import get_user_by_username, username_taken
from app.security.logger import security_logger
from app.security.monitoring import looks_malicious, record_failed_login


# ----------------------------
# Blueprint + logger
# ----------------------------
# Blueprint keeps routing separate from app factory.
# Logger writes security events to logs/security.log (rotating file).
main = Blueprint("main", __name__)
logger = security_logger()


# ----------------------------
# Public routes
# ----------------------------
@main.route("/")
def home():
    return render_template("home.html")


# ----------------------------
# Authentication
# ----------------------------
@main.route("/login", methods=["GET", "POST"])
def login():
    """
    Login route (WTForms + CSRF + secure session handling).
    Also logs:
    - suspicious inputs
    - failed attempts (with a simple brute-force threshold)
    """
    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        ip = request.remote_addr

        # Defense-in-depth: log obvious malicious patterns (does not block by itself)
        if looks_malicious(username):
            logger.warning(f"MALICIOUS_INPUT | route=/login | ip={ip} | username={username}")

        # ORM query via repository (centralised access, injection-safe)
        user = get_user_by_username(username)

        # Verify password hash (never compare plaintext)
        if user and check_password_hash(user.password, password):
            logger.info(f"LOGIN_SUCCESS | user={user.username} | role={user.role} | ip={ip}")

            # Mitigate session fixation by resetting session on login
            session.clear()

            # Enables PERMANENT_SESSION_LIFETIME in Config
            session.permanent = True

            # Store only what we need (no secrets, no password data)
            session["user"] = user.username
            session["role"] = user.role
            session["bio"] = user.bio

            flash("Login successful.", "success")
            return redirect(url_for("main.dashboard"))

        # Failed login attempt: record and log count in rolling window
        count = record_failed_login(ip)
        logger.warning(f"LOGIN_FAIL | username={username} | ip={ip} | count_5min={count}")

        # Brute-force suspicion threshold (coursework-scale monitoring)
        if count >= 5:
            logger.warning(
                f"BRUTE_FORCE_SUSPECTED | route=/login | ip={ip} | username={username} | count_5min={count}"
            )

        flash("Login credentials are invalid, please try again", "error")

    return render_template("login.html", form=form)


@main.route("/logout", methods=["POST"])
@login_required
def logout():
    """
    Logout must be POST to protect against CSRF.
    """
    ip = request.remote_addr
    logger.info(f"LOGOUT | user={session.get('user')} | role={session.get('role')} | ip={ip}")

    session.clear()
    flash("You have been logged out", "success")
    return redirect(url_for("main.login"))


# ----------------------------
# User dashboard
# ----------------------------
@main.route("/dashboard")
@login_required
def dashboard():
    """
    Basic authenticated dashboard.
    """
    return render_template(
        "dashboard.html",
        username=session["user"],
        bio=session.get("bio", ""),
    )


# ----------------------------
# Registration
# ----------------------------
@main.route("/register", methods=["GET", "POST"])
def register():
    """
    Registration uses WTForms validation and sanitisation.
    Logs suspicious inputs and failed registration attempts.
    """
    form = RegistrationForm()

    if form.validate_on_submit():
        ip = request.remote_addr
        username = form.username.data

        # Defense-in-depth monitoring
        if looks_malicious(username, form.bio.data):
            logger.warning(f"MALICIOUS_INPUT | route=/register | ip={ip} | username={username}")

        # Uniqueness check via repository
        if username_taken(username):
            logger.warning(f"REGISTER_FAIL_TAKEN | username={username} | ip={ip}")
            flash("Username is already taken.", "error")
            return render_template("register.html", form=form)

        # Password hashed before storage (never plaintext)
        user = User(
            username=username,
            password=generate_password_hash(form.password.data),
            role=form.role.data,
            bio=form.bio.data,
        )
        db.session.add(user)
        db.session.commit()

        logger.info(f"REGISTER_SUCCESS | user={username} | role={form.role.data} | ip={ip}")
        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("main.login"))

    return render_template("register.html", form=form)


# ----------------------------
# Role protected routes
# ----------------------------
@main.route("/admin-panel")
@roles_required("admin")
def admin():
    return render_template("admin.html")


@main.route("/moderator")
@roles_required("moderator")
def moderator():
    return render_template("moderator.html")


@main.route("/user-dashboard")
@roles_required("user")
def user_dashboard():
    return render_template("user_dashboard.html", username=session.get("user"))


# ----------------------------
# Account management
# ----------------------------
@main.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    """
    Change password flow:
    - requires login
    - verifies current password
    - prevents reusing the same password
    - logs success/failure without leaking secrets
    """
    form = ChangePasswordForm()
    username = session["user"]
    ip = request.remote_addr

    user = get_user_by_username(username)
    if not user:
        # Should not happen under normal flow, but still handled securely
        logger.warning(f"PASSWORD_CHANGE_FORBIDDEN | user={username} | ip={ip}")
        abort(403)

    if form.validate_on_submit():
        current_password = form.current_password.data
        new_password = form.new_password.data

        # Wrong current password
        if not check_password_hash(user.password, current_password):
            logger.warning(f"PASSWORD_CHANGE_FAIL | user={username} | ip={ip} | reason=bad_current")
            flash("Current password is incorrect", "error")
            return render_template("change_password.html", form=form)

        # Prevent password reuse
        if check_password_hash(user.password, new_password):
            logger.warning(f"PASSWORD_CHANGE_FAIL | user={username} | ip={ip} | reason=reuse_old")
            flash("New password must be different from the current password", "error")
            return render_template("change_password.html", form=form)

        # Update password hash and commit
        user.password = generate_password_hash(new_password)
        db.session.commit()

        logger.info(f"PASSWORD_CHANGE_SUCCESS | user={username} | ip={ip}")
        flash("Password changed successfully", "success")
        return redirect(url_for("main.dashboard"))

    return render_template("change_password.html", form=form)
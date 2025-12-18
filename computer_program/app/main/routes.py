from flask import Blueprint, render_template, redirect, url_for, session, flash, abort
from werkzeug.security import generate_password_hash, check_password_hash

from app import db
from app.models import User
from app.forms import LoginForm, RegistrationForm, ChangePasswordForm
from app.security.decorators import login_required, roles_required
from app.security.repository import get_user_by_username, username_taken

main = Blueprint("main", __name__)

@main.route("/")
def home():
    return render_template("home.html")


@main.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = get_user_by_username(username)

        if user and check_password_hash(user.password, password):
            session.clear()
            session.permanent = True

            session["user"] = user.username
            session["role"] = user.role
            session["bio"] = user.bio

            flash("Login successful.", "success")
            return redirect(url_for("main.dashboard"))

        flash("Login credentials are invalid, please try again", "error")

    return render_template("login.html", form=form)


@main.route("/dashboard")
@login_required
def dashboard():
    return render_template(
        "dashboard.html",
        username=session["user"],
        bio=session.get("bio", ""),
    )


@main.route("/register", methods=["GET", "POST"])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        if username_taken(form.username.data):
            flash("Username is already taken.", "error")
            return render_template("register.html", form=form)

        user = User(
            username=form.username.data,
            password=generate_password_hash(form.password.data),
            role=form.role.data,
            bio=form.bio.data,
        )
        db.session.add(user)
        db.session.commit()

        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("main.login"))

    return render_template("register.html", form=form)


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


@main.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    flash("You have been logged out", "success")
    return redirect(url_for("main.login"))


@main.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    form = ChangePasswordForm()
    username = session["user"]

    user = get_user_by_username(username)
    if not user:
        abort(403, description="Access denied.")

    if form.validate_on_submit():
        current_password = form.current_password.data
        new_password = form.new_password.data

        if not check_password_hash(user.password, current_password):
            flash("Current password is incorrect", "error")
            return render_template("change_password.html", form=form)

        if check_password_hash(user.password, new_password):
            flash("New password must be different from the current password", "error")
            return render_template("change_password.html", form=form)

        user.password = generate_password_hash(new_password)
        db.session.commit()

        flash("Password changed successfully", "success")
        return redirect(url_for("main.dashboard"))

    return render_template("change_password.html", form=form)
from flask import Blueprint, render_template, redirect, url_for, request, session, flash
from werkzeug.security import generate_password_hash, check_password_hash

from app import db
from app.models import User
from app.security.decorators import login_required, roles_required

security = Blueprint("security", __name__)

@security.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password, password):
            flash("Invalid credentials.", "danger")
            return render_template("login.html")

        session["user_id"] = user.id
        session["role"] = user.role
        session["username"] = user.username
        flash("Logged in.", "success")
        return redirect(url_for("main.home"))

    return render_template("login.html")

@security.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("main.home"))

@security.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role = "user"

        if User.query.filter_by(username=username).first():
            flash("Username already exists.", "warning")
            return render_template("register.html")

        user = User(
            username=username,
            password=generate_password_hash(password),
            role=role,
            bio=""
        )
        db.session.add(user)
        db.session.commit()

        flash("Account created. Please log in.", "success")
        return redirect(url_for("security.login"))

    return render_template("register.html")

@security.route("/dashboard")
@login_required
def dashboard():
    role = session.get("role")
    if role == "admin":
        return render_template("admin.html")
    if role == "moderator":
        return render_template("moderator.html")
    return render_template("user_dashboard.html")

@security.route("/admin")
@login_required
@roles_required("admin")
def admin_only():
    return render_template("admin.html")
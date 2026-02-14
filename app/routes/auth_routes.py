import secrets
from flask import Blueprint, current_app, flash, render_template, request, redirect, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from ..models.user_model import User
from ..extensions import db, oauth

auth = Blueprint("auth", __name__, url_prefix="/auth")


def get_google_client():
    if oauth is None:
        return None

    existing = oauth.create_client("google")
    if existing:
        return existing

    client_id = current_app.config.get("GOOGLE_CLIENT_ID")
    client_secret = current_app.config.get("GOOGLE_CLIENT_SECRET")
    if not client_id or not client_secret:
        return None

    oauth.register(
        name="google",
        client_id=client_id,
        client_secret=client_secret,
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile"},
    )
    return oauth.create_client("google")


@auth.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        if User.query.filter_by(email=email).first():
            flash("This email is already registered. Please login.", "error")
            return redirect(url_for("auth.login"))

        new_user = User(email=email, password=generate_password_hash(password))
        db.session.add(new_user)
        db.session.commit()

        flash("Account created successfully. Please login.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/register.html")


@auth.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        user = User.query.filter_by(email=email).first()

        if user and user.password and check_password_hash(user.password, password):
            session["user_id"] = user.id
            session["username"] = user.email
            flash("Logged in successfully.", "success")
            return redirect("/dashboard")

        # Backward-compat: agar purane accounts me plaintext password stored hai, to ek baar accept karke hash me upgrade karo
        if user and user.password == password:
            user.password = generate_password_hash(password)
            db.session.commit()
            session["user_id"] = user.id
            session["username"] = user.email
            flash("Logged in successfully.", "success")
            return redirect("/dashboard")

        flash("Invalid email or password.", "error")
        return redirect(url_for("auth.login"))

    return render_template("auth/login.html")


@auth.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth.login"))


@auth.route("/google/login")
def google_login():
    google = get_google_client()
    if not google:
        return "Google login not configured. Install Authlib and set GOOGLE_CLIENT_ID/GOOGLE_CLIENT_SECRET."

    # Previous failed attempts ka stale OAuth state/nonce remove kar rahe hain
    for key in list(session.keys()):
        if key.startswith("_state_google_") or key.startswith("_nonce_google_"):
            session.pop(key, None)

    redirect_uri = url_for("auth.google_callback", _external=True)
    return google.authorize_redirect(redirect_uri, prompt="select_account")


@auth.route("/google/callback")
def google_callback():
    google = get_google_client()
    if not google:
        return "Google login not configured. Install Authlib and set GOOGLE_CLIENT_ID/GOOGLE_CLIENT_SECRET."

    try:
        token = google.authorize_access_token()
        user_info = token.get("userinfo")
        if not user_info:
            user_info = google.parse_id_token(token)
        if not user_info:
            user_info = google.get("userinfo").json()

        email = (user_info or {}).get("email")
        if not email:
            return "Google account email not available."

        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(email=email, password=generate_password_hash(secrets.token_urlsafe(24)))
            db.session.add(user)
            db.session.commit()

        session["user_id"] = user.id
        session["username"] = user.email
        return redirect("/dashboard")
    except Exception as exc:
        current_app.logger.exception("Google OAuth callback failed")
        return (
            "Google login failed. Check redirect URI, OAuth consent/test user settings, "
            f"and client secret. Technical error: {str(exc)}"
        )

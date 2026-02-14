import os
from flask import Flask, redirect, render_template, session, url_for
from .config import Config
from .extensions import db, oauth


def create_app():

    app = Flask(__name__)

    # Static aur template folder ka correct path force kar rahe hain
    app.static_folder = os.path.join(os.path.dirname(__file__), "static")
    app.template_folder = os.path.join(os.path.dirname(__file__), "templates")

    app.config.from_object(Config)

    db.init_app(app)
    if oauth:
        oauth.init_app(app)

    from .routes.auth_routes import auth
    from .routes.dashboard_routes import dashboard
    from .routes.scan_routes import scan

    app.register_blueprint(auth)
    app.register_blueprint(dashboard)
    app.register_blueprint(scan)

    @app.route("/")
    def home():
        if "user_id" in session:
            return redirect("/dashboard")
        return render_template("index.html")

    @app.route("/about")
    def about():
        return render_template("about.html")

    @app.route("/contact")
    def contact():
        return render_template("contact.html")

    with app.app_context():
        from .models.user_model import User
        from .models.otp_model import OTP
        from .models.scan_model import Scan
        db.create_all()

    return app

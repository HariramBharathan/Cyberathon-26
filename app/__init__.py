import os
from datetime import timedelta

import click
from dotenv import load_dotenv
from flask import Flask, g, jsonify, request
from flask_wtf.csrf import CSRFError
from sqlalchemy import event

from .config import BASE_DIR, Config, ProductionConfig
from .extensions import csrf, db, limiter
from .models import User
from .services.security import normalized_email
from .services.session_service import clear_session_cookie, load_request_identity


def create_app(test_config=None):
    load_dotenv(BASE_DIR / ".env")
    app = Flask(__name__, instance_relative_config=True)
    production = os.environ.get("SENTINELPASS_ENV", "development").lower() == "production"
    selected_config = ProductionConfig if production else Config
    if production:
        selected_config.validate()
    app.config.from_object(selected_config)
    if test_config:
        app.config.update(test_config)
    os.makedirs(app.instance_path, exist_ok=True)

    db.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    with app.app_context():
        db.create_all()
        if app.config["SQLALCHEMY_DATABASE_URI"].startswith("sqlite:"):
            @event.listens_for(db.engine, "connect")
            def enable_sqlite_foreign_keys(connection, _record):
                cursor = connection.cursor()
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.close()

    from .routes.api import api
    from .routes.web import web
    app.register_blueprint(web)
    app.register_blueprint(api, url_prefix="/api")

    @app.before_request
    def identify_request():
        load_request_identity()

    @app.after_request
    def set_security_headers(response):
        if request.path.startswith(("/api", "/approve", "/login", "/register")) or g.get("user"):
            response.headers["Cache-Control"] = "no-store, max-age=0"
            response.headers["Pragma"] = "no-cache"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Permissions-Policy"] = "camera=(self), geolocation=()"
        return response

    @app.errorhandler(CSRFError)
    def csrf_error(error):
        return jsonify({"ok": False, "error": {"code": "csrf_failed", "message": "Refresh the page and try again."}}), 400

    @app.errorhandler(429)
    def rate_limit_error(_error):
        return jsonify({"ok": False, "error": {"code": "rate_limited", "message": "Too many attempts. Wait before trying again."}}), 429

    @app.errorhandler(500)
    def internal_error(_error):
        db.session.rollback()
        return jsonify({"ok": False, "error": {"code": "server_error", "message": "The request could not be completed."}}), 500

    @app.cli.command("init-db")
    def init_db_command():
        """Create the local SQLite schema."""
        db.create_all()
        click.echo("SentinelPass database initialized.")

    @app.cli.command("create-demo-user")
    @click.option("--email", default="demo@sentinelpass.local", show_default=True)
    @click.option("--name", default="SentinelPass Demo", show_default=True)
    def create_demo_user(email, name):
        """Create a verified development account without a reusable password."""
        if not app.config["DEVELOPMENT"]:
            raise click.ClickException("Demo accounts are available only in development mode.")
        normalized = normalized_email(email)
        user = User.query.filter_by(email=normalized).first()
        if user:
            click.echo(f"Demo account already exists: {normalized}")
            return
        db.session.add(User(full_name=name.strip(), email=normalized, email_verified=True, status="active"))
        db.session.commit()
        click.echo(f"Created verified demo account: {normalized}")
        click.echo("Request a sign-in code in the app; it will appear only in this development server console.")

    return app
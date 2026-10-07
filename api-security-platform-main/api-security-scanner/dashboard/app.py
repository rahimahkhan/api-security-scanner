import os
import sys
from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import SECRET_KEY, FLASK_DEBUG
from database.db import init_db

def create_app():
    """
    Flask Application Factory
    Initializes SQLite database and registers web dashboard blueprints.
    """
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static"
    )
    app.config["SECRET_KEY"] = SECRET_KEY
    app.config["DEBUG"] = FLASK_DEBUG
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.jinja_env.cache = {}

    # Trust Render's (or any) reverse proxy for scheme/host so url_for and
    # request.url_root produce correct https URLs (matters for OAuth callbacks).
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

    # Initialize Database Tables
    init_db()

    # Register Dashboard Routes Blueprint
    from dashboard.routes import dashboard_bp
    app.register_blueprint(dashboard_bp)

    # Styled error pages (JSON for /api/*, app design for browsers).
    @app.errorhandler(404)
    def not_found(error):
        from flask import request, jsonify, render_template, session
        if request.path.startswith("/api/"):
            return jsonify({"status": "error", "message": "Not found"}), 404
        base = "base_app.html" if session.get("user_id") else "base_public.html"
        return render_template("404.html", base_template=base), 404

    return app

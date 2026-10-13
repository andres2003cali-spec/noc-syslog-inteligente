"""
NOC Syslog Inteligente - fábrica de la aplicación Flask (v0.2.0).

Arquitectura (ver docs/arquitectura.md):
  Equipos -> Colector (UDP/importación) -> Normalización y política -> SQLite -> API REST -> Dashboard
"""
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from flask import Flask, jsonify

from app.config import APP_VERSION, BASE_DIR, Config
from app.db import close_db, connect, init_db, seed_demo


def _setup_app_logging(app: Flask) -> None:
    """Bitácora de la propia aplicación en logs/app.log (RNF-04), rotada a 1 MB x 3."""
    log_dir = BASE_DIR / "logs"
    log_dir.mkdir(exist_ok=True)
    handler = RotatingFileHandler(log_dir / "app.log", maxBytes=1_000_000, backupCount=3, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    handler.setLevel(logging.INFO)
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)


def create_app(overrides: dict | None = None) -> Flask:
    app = Flask(__name__, static_folder="web/static", template_folder="web/templates")
    app.config.from_object(Config)
    app.json.sort_keys = False          # conserva el orden de los diccionarios en las respuestas
    app.json.ensure_ascii = False       # tildes legibles en JSON
    if overrides:
        app.config.update(overrides)

    # Crea tablas y, si la base está vacía, el inventario SIMULADO de laboratorio
    conn = connect(app.config["DB_PATH"])
    init_db(conn)
    if app.config.get("SEED_DEMO", True):
        seed_demo(conn)
    conn.close()

    app.teardown_appcontext(close_db)
    if not app.config.get("TESTING"):
        _setup_app_logging(app)

    # ---- Registro de módulos (blueprints) ----
    from app.api.devices import bp as devices_bp          # Fase 2: inventario
    app.register_blueprint(devices_bp)

    @app.get("/api/health")
    def health():
        """Prueba rápida de vida del servicio."""
        return jsonify(status="ok", version=APP_VERSION)

    @app.errorhandler(413)
    def too_large(_e):
        return jsonify(error="Archivo demasiado grande (máximo 2 MB)."), 413

    @app.errorhandler(404)
    def not_found(_e):
        return jsonify(error="Recurso no encontrado."), 404

    @app.errorhandler(500)
    def server_error(e):
        app.logger.exception("Error interno: %s", e)
        return jsonify(error="Error interno controlado. Revise logs/app.log."), 500

    @app.after_request
    def security_headers(resp):
        """Cabeceras básicas: evita incrustar la app en iframes y ejecutar scripts externos."""
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; frame-ancestors 'none'")
        return resp

    return app

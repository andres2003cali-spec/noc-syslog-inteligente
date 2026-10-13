"""web.py - Sirve la interfaz web (dashboard de una sola página)."""
from flask import Blueprint, render_template

from app.config import APP_VERSION

bp = Blueprint("web", __name__)


@bp.get("/")
def index():
    return render_template("index.html", version=APP_VERSION)

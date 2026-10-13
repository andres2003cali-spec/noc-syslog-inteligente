"""
tools.py - Generador de configuraciones (RF-06) y consola simulada (RF-07).

POST /api/config/generate      plantilla comentada Cisco / Fortinet / Huawei
GET  /api/console/profiles     perfiles y comandos permitidos
POST /api/console/exec         ejecuta un comando SIMULADO (allowlist + auditoría)
"""
from flask import Blueprint, jsonify, request

from app.configgen.generator import ConfigError, generate
from app.console.simulator import PROFILES, run_command
from app.db import get_db
from app.security.audit import audit
from app.security.policy import current_user, require

bp = Blueprint("tools", __name__, url_prefix="/api")


@bp.post("/config/generate")
@require("read")
def config_generate():
    user, _role = current_user()
    try:
        result = generate(request.get_json(silent=True) or {})
    except ConfigError as e:
        return jsonify(error=str(e)), 400
    audit(get_db(), user, "plantilla_generada", "config", result["vendor"],
          {"severidad": result["severity"]})
    return jsonify(result)


@bp.get("/console/profiles")
@require("read")
def console_profiles():
    return jsonify({k: {"label": v["label"], "vendor": v["vendor"], "allowed": v["allowed"]}
                    for k, v in PROFILES.items()})


@bp.post("/console/exec")
@require("read")   # la consola es de solo lectura; el rol 'agente' se bloquea dentro del simulador
def console_exec():
    body = request.get_json(silent=True) or {}
    user, role = current_user()
    db = get_db()
    device = None
    if body.get("device_id"):
        device = db.execute("SELECT * FROM devices WHERE id = ?", (body["device_id"],)).fetchone()
        if not device:
            return jsonify(error="Equipo no encontrado."), 404
    return jsonify(run_command(db, str(body.get("profile", "")), str(body.get("command", "")),
                               device, user, role))

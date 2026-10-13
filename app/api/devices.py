"""
devices.py - API REST del inventario de equipos (RF-01, HU-01).

GET    /api/devices            lista con estado de comunicación calculado
POST   /api/devices            crea un equipo         (operador/administrador)
PUT    /api/devices/<id>       edita un equipo        (operador/administrador)
DELETE /api/devices/<id>       elimina un equipo      (solo administrador)
"""
import ipaddress
import re
import sqlite3
from datetime import datetime, timedelta

from flask import Blueprint, current_app, jsonify, request

from app.db import get_db, now_iso
from app.security.audit import audit
from app.security.policy import current_user, require

bp = Blueprint("devices", __name__, url_prefix="/api/devices")

VENDORS = ("Cisco", "Fortinet", "Huawei", "Otro")
STATUSES = ("activo", "inactivo", "mantenimiento")
RE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{1,39}$")


def _comm_status(row) -> str:
    """HU-01: 'sin comunicación' si no hay eventos dentro del umbral configurado."""
    if row["status"] != "activo":
        return row["status"]
    if not row["last_seen"]:
        return "sin comunicación"
    limit = datetime.now() - timedelta(minutes=current_app.config["OFFLINE_THRESHOLD_MINUTES"])
    last = datetime.strptime(row["last_seen"], "%Y-%m-%d %H:%M:%S")
    return "en línea" if last >= limit else "sin comunicación"


def _to_dict(row) -> dict:
    d = dict(row)
    d["comm_status"] = _comm_status(row)
    return d


def _validate(data: dict) -> tuple[dict | None, str]:
    """Valida y normaliza los campos del formulario. Devuelve (datos, error)."""
    name = (data.get("name") or "").strip()
    if not RE_NAME.match(name):
        return None, "Nombre inválido: 2-40 caracteres, letras, números, guion, punto o guion bajo."
    try:
        ip = str(ipaddress.IPv4Address((data.get("ip") or "").strip()))
    except ipaddress.AddressValueError:
        return None, "La IP debe ser una IPv4 válida."
    vendor = (data.get("vendor") or "").strip()
    if vendor not in VENDORS:
        return None, f"Marca inválida. Opciones: {', '.join(VENDORS)}."
    status = (data.get("status") or "activo").strip()
    if status not in STATUSES:
        return None, f"Estado inválido. Opciones: {', '.join(STATUSES)}."
    quality = (data.get("data_quality") or "confirmado").strip()
    if quality not in ("confirmado", "por_verificar"):
        return None, "Calidad del dato inválida."
    clean = {
        "name": name, "ip": ip, "vendor": vendor,
        "model": (data.get("model") or "").strip()[:60],
        "os_version": (data.get("os_version") or "").strip()[:60],
        "location": (data.get("location") or "").strip()[:80],
        "status": status, "data_quality": quality,
        "is_simulated": 0 if str(data.get("is_simulated", "1")).lower() in ("0", "false", "no") else 1,
    }
    return clean, ""


@bp.get("")
@require("read")
def list_devices():
    rows = get_db().execute("SELECT * FROM devices ORDER BY vendor, name").fetchall()
    return jsonify([_to_dict(r) for r in rows])


@bp.get("/<int:device_id>")
@require("read")
def get_device(device_id: int):
    row = get_db().execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
    if not row:
        return jsonify(error="Equipo no encontrado."), 404
    return jsonify(_to_dict(row))


@bp.post("")
@require("device_write")
def create_device():
    data, err = _validate(request.get_json(silent=True) or {})
    if err:
        return jsonify(error=err), 400
    db, (user, _role), ts = get_db(), current_user(), now_iso()
    try:
        cur = db.execute(
            """INSERT INTO devices (name, ip, vendor, model, os_version, location, status, data_quality,
                                    is_simulated, created_at, updated_at)
               VALUES (:name,:ip,:vendor,:model,:os_version,:location,:status,:data_quality,:is_simulated,
                       :ts,:ts)""", {**data, "ts": ts})
    except sqlite3.IntegrityError:
        return jsonify(error="Ya existe un equipo con ese nombre o IP."), 409
    audit(db, user, "equipo_creado", "device", cur.lastrowid, {"nombre": data["name"], "ip": data["ip"]})
    return jsonify(id=cur.lastrowid, message="Equipo registrado."), 201


@bp.put("/<int:device_id>")
@require("device_write")
def update_device(device_id: int):
    db = get_db()
    if not db.execute("SELECT 1 FROM devices WHERE id = ?", (device_id,)).fetchone():
        return jsonify(error="Equipo no encontrado."), 404
    data, err = _validate(request.get_json(silent=True) or {})
    if err:
        return jsonify(error=err), 400
    user, _role = current_user()
    try:
        db.execute(
            """UPDATE devices SET name=:name, ip=:ip, vendor=:vendor, model=:model, os_version=:os_version,
                      location=:location, status=:status, data_quality=:data_quality,
                      is_simulated=:is_simulated, updated_at=:ts WHERE id=:id""",
            {**data, "ts": now_iso(), "id": device_id})
    except sqlite3.IntegrityError:
        return jsonify(error="Ya existe otro equipo con ese nombre o IP."), 409
    audit(db, user, "equipo_actualizado", "device", device_id, {"nombre": data["name"]})
    return jsonify(message="Equipo actualizado.")


@bp.delete("/<int:device_id>")
@require("device_delete")
def delete_device(device_id: int):
    db = get_db()
    row = db.execute("SELECT name FROM devices WHERE id = ?", (device_id,)).fetchone()
    if not row:
        return jsonify(error="Equipo no encontrado."), 404
    user, _role = current_user()
    db.execute("DELETE FROM devices WHERE id = ?", (device_id,))
    audit(db, user, "equipo_eliminado", "device", device_id, {"nombre": row["name"]})
    return jsonify(message="Equipo eliminado.")

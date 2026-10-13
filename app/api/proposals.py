"""
proposals.py - Flujo obligatorio con aprobación humana.

  Evento detectado -> Validación -> PROPUESTA -> REVISIÓN HUMANA -> APROBACIÓN
  -> EJECUCIÓN AUTORIZADA (simulada en v0.2.0) -> VERIFICACIÓN -> AUDITORÍA

Reglas:
  - Cualquier operador o el agente de IA simulado puede PROPONER.
  - La política clasifica el comando: lectura / cambio / bloqueado (allowlist).
  - Solo un ADMINISTRADOR distinto a quien propuso puede aprobar (cuatro ojos).
  - Sin aprobación no existe ejecución. Lo bloqueado nunca se puede aprobar.
  - La ejecución en el MVP es SIMULADA: no hay conexión SSH a equipos.
"""
import hashlib

from flask import Blueprint, jsonify, request

from app.db import get_db, now_iso
from app.security.audit import audit
from app.security.policy import classify_action, current_user, require

bp = Blueprint("proposals", __name__, url_prefix="/api/proposals")


def _get(db, pid):
    return db.execute("""SELECT p.*, d.name AS device_name, d.vendor AS device_vendor
                         FROM action_proposals p LEFT JOIN devices d ON d.id = p.device_id
                         WHERE p.id = ?""", (pid,)).fetchone()


@bp.get("")
@require("read")
def list_proposals():
    status = request.args.get("status")
    sql = """SELECT p.*, d.name AS device_name, d.vendor AS device_vendor FROM action_proposals p
             LEFT JOIN devices d ON d.id = p.device_id"""
    params = []
    if status:
        sql += " WHERE p.status = ?"
        params.append(status)
    sql += " ORDER BY CASE p.status WHEN 'pendiente' THEN 0 ELSE 1 END, p.id DESC LIMIT 200"
    return jsonify([dict(r) for r in get_db().execute(sql, params)])


@bp.post("")
@require("propose")
def propose():
    body = request.get_json(silent=True) or {}
    user, _role = current_user()
    db = get_db()
    device = db.execute("SELECT * FROM devices WHERE id = ?", (body.get("device_id"),)).fetchone()
    if not device:
        return jsonify(error="Debe indicar un equipo del inventario."), 400
    command = " ".join(str(body.get("command", "")).split())
    category, explanation = classify_action(device["vendor"], command)
    status = "bloqueada" if category == "bloqueado" else "pendiente"
    cur = db.execute(
        """INSERT INTO action_proposals (incident_id, device_id, command, rationale, proposed_by, status,
                                         policy_check, created_at) VALUES (?,?,?,?,?,?,?,?)""",
        (body.get("incident_id") or None, device["id"], command[:200],
         str(body.get("rationale", ""))[:500], user, status, f"{category}: {explanation}", now_iso()))
    audit(db, user, "propuesta_creada", "action_proposal", cur.lastrowid,
          {"comando": command[:200], "equipo": device["name"], "clasificacion": category, "estado": status})
    code = 201 if status == "pendiente" else 422
    return jsonify(id=cur.lastrowid, status=status, policy_check=f"{category}: {explanation}"), code


@bp.post("/<int:pid>/review")
@require("approve")
def review(pid: int):
    """Revisión humana: aprobar o rechazar (solo administrador, distinto al proponente)."""
    body = request.get_json(silent=True) or {}
    user, _role = current_user()
    db = get_db()
    p = _get(db, pid)
    if not p:
        return jsonify(error="Propuesta no encontrada."), 404
    if p["status"] != "pendiente":
        return jsonify(error=f"La propuesta está '{p['status']}' y no puede revisarse."), 409
    if p["proposed_by"] == user:
        return jsonify(error="Separación de funciones: quien propone no puede aprobar su propia propuesta."), 403
    decision = body.get("decision")
    if decision not in ("aprobar", "rechazar"):
        return jsonify(error="decision debe ser 'aprobar' o 'rechazar'."), 400
    # Revalidación de política en el momento de aprobar (la política pudo cambiar)
    category, _expl = classify_action(p["device_vendor"], p["command"])
    if decision == "aprobar" and category == "bloqueado":
        return jsonify(error="La política bloquea este comando: no puede aprobarse."), 422
    new_status = "aprobada" if decision == "aprobar" else "rechazada"
    db.execute("""UPDATE action_proposals SET status = ?, reviewed_by = ?, reviewed_at = ?, review_note = ?
                  WHERE id = ?""", (new_status, user, now_iso(), str(body.get("note", ""))[:500], pid))
    audit(db, user, f"propuesta_{new_status}", "action_proposal", pid, {"comando": p["command"]})
    return jsonify(status=new_status)


@bp.post("/<int:pid>/execute")
@require("execute")
def execute(pid: int):
    """Ejecución AUTORIZADA y SIMULADA: solo propuestas aprobadas."""
    user, _role = current_user()
    db = get_db()
    p = _get(db, pid)
    if not p:
        return jsonify(error="Propuesta no encontrada."), 404
    if p["status"] != "aprobada":
        return jsonify(error="Sin aprobación humana no hay ejecución."), 409
    result = (f"[EJECUCIÓN SIMULADA] '{p['command']}' sobre {p['device_name']} ({p['device_vendor']}). "
              "No existe conexión SSH en v0.2.0; en el Corte 3 se ejecutará por backend autorizado.")
    evidence = hashlib.sha256(result.encode("utf-8")).hexdigest()
    db.execute("""UPDATE action_proposals SET status = 'ejecutada', execution_result = ?, executed_at = ?
                  WHERE id = ?""", (f"{result} sha256={evidence[:16]}", now_iso(), pid))
    audit(db, user, "propuesta_ejecutada", "action_proposal", pid, {"comando": p["command"], "sha256": evidence})
    return jsonify(status="ejecutada", result=result, sha256=evidence)


@bp.post("/<int:pid>/verify")
@require("verify")
def verify(pid: int):
    """Verificación posterior: el operador confirma el resultado observado."""
    body = request.get_json(silent=True) or {}
    user, _role = current_user()
    db = get_db()
    p = _get(db, pid)
    if not p:
        return jsonify(error="Propuesta no encontrada."), 404
    if p["status"] != "ejecutada":
        return jsonify(error="Solo se verifican propuestas ejecutadas."), 409
    note = str(body.get("verification", "")).strip()[:500]
    if len(note) < 5:
        return jsonify(error="Describa la verificación realizada (mínimo 5 caracteres)."), 400
    db.execute("""UPDATE action_proposals SET status = 'verificada', verification = ?, verified_by = ?,
                  verified_at = ? WHERE id = ?""", (note, user, now_iso(), pid))
    audit(db, user, "propuesta_verificada", "action_proposal", pid, {"verificacion": note})
    return jsonify(status="verificada")

"""
incidents.py - API de incidentes (RF-05, HU-03).

GET   /api/incidents             lista (filtros: status, priority, category)
GET   /api/incidents/<id>        detalle con seguimiento, eventos y propuestas
POST  /api/incidents             crea un incidente manual o a partir de un evento
PATCH /api/incidents/<id>        asigna, cambia estado, agrega nota, causa o resolución
"""
from flask import Blueprint, jsonify, request

from app.collector.parser import SEVERITY_NAMES
from app.db import get_db
from app.incidents.service import STATUSES, create_incident, update_incident
from app.security.policy import current_user, require

bp = Blueprint("incidents", __name__, url_prefix="/api/incidents")


def _inc(r) -> dict:
    d = dict(r)
    d["code"] = f"INC-{r['id']:04d}"
    d["severity_name"] = SEVERITY_NAMES[r["severity"]][1]
    return d


@bp.get("")
@require("read")
def list_incidents():
    a, where, params = request.args, [], []
    for field in ("status", "priority", "category"):
        if a.get(field):
            where.append(f"i.{field} = ?")
            params.append(a[field])
    if a.get("open") == "1":
        where.append("i.status NOT IN ('resuelto','cerrado')")
    sql = (f"""SELECT i.*, d.name AS device_name,
                     (SELECT COUNT(*) FROM action_proposals p WHERE p.incident_id = i.id
                       AND p.status = 'pendiente') AS pending_proposals
              FROM incidents i LEFT JOIN devices d ON d.id = i.device_id
              {' WHERE ' + ' AND '.join(where) if where else ''}
              ORDER BY CASE i.status WHEN 'cerrado' THEN 1 ELSE 0 END, i.priority, i.id DESC LIMIT 300""")
    return jsonify([_inc(r) for r in get_db().execute(sql, params).fetchall()])


@bp.get("/<int:incident_id>")
@require("read")
def get_incident(incident_id: int):
    db = get_db()
    r = db.execute("""SELECT i.*, d.name AS device_name, d.vendor AS device_vendor FROM incidents i
                      LEFT JOIN devices d ON d.id = i.device_id WHERE i.id = ?""", (incident_id,)).fetchone()
    if not r:
        return jsonify(error="Incidente no encontrado."), 404
    data = _inc(r)
    data["updates"] = [dict(u) for u in db.execute(
        "SELECT * FROM incident_updates WHERE incident_id = ? ORDER BY id", (incident_id,))]
    data["events"] = [dict(e) for e in db.execute(
        """SELECT id, event_time, severity, app_name, message, repeat_count, flags, origin_label
           FROM events WHERE incident_id = ? ORDER BY id DESC LIMIT 20""", (incident_id,))]
    data["proposals"] = [dict(p) for p in db.execute(
        "SELECT * FROM action_proposals WHERE incident_id = ? ORDER BY id", (incident_id,))]
    return jsonify(data)


@bp.post("")
@require("incident_write")
def create():
    """Crea un incidente. Si llega event_id, toma severidad y equipo del evento (vínculo HU-03)."""
    body = request.get_json(silent=True) or {}
    user, _role = current_user()
    db = get_db()
    title = (body.get("title") or "").strip()
    severity = body.get("severity", 3)
    device_id = body.get("device_id") or None
    event_id = body.get("event_id") or None
    if event_id:
        ev = db.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
        if not ev:
            return jsonify(error="Evento no encontrado."), 404
        if ev["incident_id"]:
            return jsonify(error=f"El evento ya está vinculado al incidente INC-{ev['incident_id']:04d}.",
                           incident_id=ev["incident_id"]), 409
        severity, device_id = ev["severity"], ev["device_id"]
        title = title or f"{ev['app_name'] or 'Evento'}: {ev['message'][:80]}"
    try:
        severity = int(severity)
        assert 0 <= severity <= 7
    except (TypeError, ValueError, AssertionError):
        return jsonify(error="Severidad inválida (0-7)."), 400
    if len(title) < 5:
        return jsonify(error="El título debe tener al menos 5 caracteres."), 400
    iid = create_incident(db, title, (body.get("description") or "").strip(), severity,
                          body.get("category") if body.get("category") in ("operacion", "seguridad", "seguridad-ia")
                          else "operacion", device_id, event_id, user,
                          assignee=(body.get("assignee") or "").strip()[:80])
    if event_id:
        db.execute("UPDATE events SET incident_id = ? WHERE id = ?", (iid, event_id))
    db.commit()
    return jsonify(id=iid, code=f"INC-{iid:04d}", message="Incidente creado."), 201


@bp.patch("/<int:incident_id>")
@require("incident_write")
def patch(incident_id: int):
    body = request.get_json(silent=True) or {}
    if body.get("status") and body["status"] not in STATUSES:
        return jsonify(error="Estado inválido."), 400
    user, _role = current_user()
    ok, msg = update_incident(get_db(), incident_id, user, dict(body))
    return (jsonify(message=msg), 200) if ok else (jsonify(error=msg), 400)

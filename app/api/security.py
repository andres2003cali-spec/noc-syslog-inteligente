"""
security.py - Dashboard, auditoría (RF-08) y política de defensa ante IA.

GET /api/dashboard            indicadores del tablero
GET /api/audit                bitácora general + verificación de integridad de la cadena
GET /api/audit/commands       auditoría de la consola (HU-05)
GET /api/audit/export.json    exporta evidencia de auditoría
GET /api/policy               política vigente (umbrales, reglas, allowlists)
GET /api/me                   usuario y rol de la petición
"""
import json
from datetime import datetime, timedelta

from flask import Blueprint, Response, current_app, jsonify

from app.api.devices import _comm_status
from app.config import APP_VERSION
from app.db import get_db, now_iso
from app.security import policy
from app.security.audit import verify_chain
from app.security.policy import current_user, require

bp = Blueprint("security", __name__, url_prefix="/api")


@bp.get("/me")
def me():
    user, role = current_user()
    return jsonify(user=user, role=role, permissions=sorted(policy.PERMISSIONS.get(role, [])),
                   users=policy.USERS)


@bp.get("/dashboard")
@require("read")
def dashboard():
    db = get_db()
    devices = db.execute("SELECT * FROM devices").fetchall()
    comm = {"en línea": 0, "sin comunicación": 0, "mantenimiento": 0, "inactivo": 0}
    for d in devices:
        comm[_comm_status(d)] = comm.get(_comm_status(d), 0) + 1
    since = (datetime.now() - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
    q = lambda sql, *p: db.execute(sql, p).fetchone()[0]  # noqa: E731
    recent_crit = db.execute(
        """SELECT e.id, e.event_time, e.severity, e.vendor, e.app_name, e.message, e.flags,
                  d.name AS device_name, e.incident_id
           FROM events e LEFT JOIN devices d ON d.id = e.device_id
           WHERE e.severity <= 2 ORDER BY e.id DESC LIMIT 6""").fetchall()
    return jsonify(
        version=APP_VERSION,
        generated_at=now_iso(),
        devices_total=len(devices),
        devices_comm=comm,
        events_total=q("SELECT COUNT(*) FROM events"),
        events_24h=q("SELECT COUNT(*) FROM events WHERE received_at >= ?", since),
        critical_24h=q("SELECT COUNT(*) FROM events WHERE severity <= 2 AND received_at >= ?", since),
        duplicates_absorbed=q("SELECT COALESCE(SUM(repeat_count - 1),0) FROM events"),
        incidents_open=q("SELECT COUNT(*) FROM incidents WHERE status NOT IN ('resuelto','cerrado')"),
        incidents_p1=q("SELECT COUNT(*) FROM incidents WHERE priority='P1' AND status NOT IN ('resuelto','cerrado')"),
        incidents_sla_breached=q("SELECT COUNT(*) FROM incidents WHERE status NOT IN ('resuelto','cerrado') "
                                 "AND sla_due < ?", now_iso()),
        proposals_pending=q("SELECT COUNT(*) FROM action_proposals WHERE status='pendiente'"),
        security_flags=q("SELECT COUNT(*) FROM events WHERE flags <> ''"),
        unauthorized_events=q("SELECT COUNT(*) FROM events WHERE authorized = 0"),
        injection_events=q("SELECT COUNT(*) FROM events WHERE flags LIKE '%posible_inyeccion_prompt%'"),
        blocked_commands=q("SELECT COUNT(*) FROM command_audit WHERE decision='bloqueado'"),
        recent_critical=[dict(r) for r in recent_crit],
        simulated_notice="Todos los equipos y eventos de esta instancia son SIMULADOS (laboratorio).",
    )


@bp.get("/audit")
@require("read")
def audit_list():
    db = get_db()
    rows = db.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 300").fetchall()
    return jsonify(chain=verify_chain(db), items=[dict(r) for r in rows])


@bp.get("/audit/commands")
@require("read")
def audit_commands():
    rows = get_db().execute(
        """SELECT c.*, d.name AS device_name FROM command_audit c LEFT JOIN devices d ON d.id = c.device_id
           ORDER BY c.id DESC LIMIT 300""").fetchall()
    return jsonify([dict(r) for r in rows])


@bp.get("/audit/export.json")
@require("read")
def audit_export():
    db = get_db()
    data = {
        "proyecto": "NOC Syslog Inteligente", "version": APP_VERSION, "exportado": now_iso(),
        "aviso": "Datos de laboratorio SIMULADOS",
        "integridad": verify_chain(db),
        "audit_log": [dict(r) for r in db.execute("SELECT * FROM audit_log ORDER BY id")],
        "command_audit": [dict(r) for r in db.execute("SELECT * FROM command_audit ORDER BY id")],
        "action_proposals": [dict(r) for r in db.execute("SELECT * FROM action_proposals ORDER BY id")],
    }
    return Response(json.dumps(data, ensure_ascii=False, indent=2), mimetype="application/json",
                    headers={"Content-Disposition": "attachment; filename=evidencia_auditoria.json"})


@bp.get("/policy")
@require("read")
def policy_view():
    c = current_app.config
    return jsonify(
        principio="Los logs son DATOS NO CONFIABLES: nunca se interpretan como instrucciones.",
        flujo=["Evento detectado", "Validación", "Propuesta de acción", "Revisión humana", "Aprobación",
               "Ejecución autorizada", "Verificación", "Auditoría"],
        umbrales={"incidente_severidad_max": c["INCIDENT_MAX_SEVERITY"],
                  "rate_limit_por_minuto": c["RATE_LIMIT_PER_MINUTE"],
                  "ventana_dedup_segundos": c["DEDUP_WINDOW_SECONDS"],
                  "umbral_sin_comunicacion_min": c["OFFLINE_THRESHOLD_MINUTES"],
                  "horario_laboral": f"{c['BUSINESS_HOURS_START']:02d}:00-{c['BUSINESS_HOURS_END']:02d}:00",
                  "max_linea_bytes": c["MAX_LINE_LENGTH"]},
        roles=policy.PERMISSIONS and {k: sorted(v) for k, v in policy.PERMISSIONS.items()},
        acciones_lectura=policy.READ_ACTIONS,
        acciones_cambio=policy.CHANGE_ACTIONS,
        patrones_inyeccion=policy.INJECTION_PATTERNS,
    )

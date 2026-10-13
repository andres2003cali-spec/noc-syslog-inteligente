"""
service.py - Gestión de incidentes (RF-05, HU-03).

Ciclo de vida:  abierto -> asignado -> en_progreso -> resuelto -> cerrado
Cada cambio deja un registro en incident_updates (seguimiento) y en audit_log.
"""
from datetime import datetime, timedelta

from app.db import now_iso
from app.security.audit import audit

# Prioridad y SLA (horas) según severidad Syslog
SLA_HOURS = {"P1": 1, "P2": 4, "P3": 8, "P4": 24}

STATUSES = ["abierto", "asignado", "en_progreso", "resuelto", "cerrado"]
TRANSITIONS = {
    "abierto": {"asignado", "en_progreso", "cerrado"},
    "asignado": {"en_progreso", "resuelto", "cerrado"},
    "en_progreso": {"resuelto", "asignado"},
    "resuelto": {"cerrado", "en_progreso"},   # se puede reabrir si la verificación falla
    "cerrado": set(),                          # estado final
}


def priority_for(severity: int) -> str:
    if severity <= 1:
        return "P1"
    if severity == 2:
        return "P2"
    if severity == 3:
        return "P3"
    return "P4"


def sla_due(priority: str, start: datetime | None = None) -> str:
    start = start or datetime.now()
    return (start + timedelta(hours=SLA_HOURS[priority])).strftime("%Y-%m-%d %H:%M:%S")


def add_update(conn, incident_id: int, actor: str, action: str, note: str = "") -> None:
    conn.execute(
        "INSERT INTO incident_updates (incident_id, actor, action, note, created_at) VALUES (?,?,?,?,?)",
        (incident_id, actor, action, note, now_iso()))


def create_incident(conn, title: str, description: str, severity: int, category: str,
                    device_id, event_id, actor: str, signature: str = "", assignee: str = "") -> int:
    """Crea un incidente con prioridad y SLA calculados a partir de la severidad."""
    prio = priority_for(severity)
    ts = now_iso()
    status = "asignado" if assignee else "abierto"
    cur = conn.execute(
        """INSERT INTO incidents (title, description, device_id, event_id, severity, priority, category,
                                  status, assignee, created_by, sla_due, signature, created_at, updated_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (title[:200], description[:2000], device_id, event_id, severity, prio, category, status,
         assignee, actor, sla_due(prio), signature, ts, ts))
    iid = cur.lastrowid
    add_update(conn, iid, actor, "creado", f"Prioridad {prio}, SLA {SLA_HOURS[prio]} h. Categoría: {category}.")
    if assignee:
        add_update(conn, iid, actor, "asignado", f"Responsable: {assignee}")
    audit(conn, actor, "incidente_creado", "incident", iid,
          {"titulo": title[:120], "prioridad": prio, "evento": event_id}, commit=False)
    return iid


def open_or_update_incident(conn, title, description, severity, category, device_id, event_id,
                            signature, actor) -> int:
    """
    Si ya hay un incidente ABIERTO con la misma firma, solo suma el evento (deduplicación
    de incidentes: evita inundar el tablero). Si no, crea uno nuevo.
    """
    row = conn.execute(
        "SELECT id FROM incidents WHERE signature = ? AND status NOT IN ('resuelto','cerrado') "
        "ORDER BY id DESC LIMIT 1", (signature,)).fetchone()
    if row:
        conn.execute("UPDATE incidents SET event_count = event_count + 1, updated_at = ? WHERE id = ?",
                     (now_iso(), row["id"]))
        return row["id"]
    return create_incident(conn, title, description, severity, category, device_id, event_id,
                           actor, signature=signature)


def update_incident(conn, incident_id: int, actor: str, data: dict) -> tuple[bool, str]:
    """
    Aplica cambios permitidos: assignee, status, note, cause, resolution.
    Reglas: transiciones válidas; para cerrar se exige causa y resolución.
    """
    inc = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    if not inc:
        return False, "Incidente no encontrado."
    if inc["status"] == "cerrado":
        return False, "El incidente está cerrado; no admite cambios."

    ts = now_iso()
    changes = []
    assignee = (data.get("assignee") or "").strip()[:80]
    if assignee and assignee != inc["assignee"]:
        conn.execute("UPDATE incidents SET assignee = ? WHERE id = ?", (assignee, incident_id))
        add_update(conn, incident_id, actor, "asignado", f"Responsable: {assignee}")
        changes.append("assignee")
        if inc["status"] == "abierto" and not data.get("status"):
            data["status"] = "asignado"

    for field in ("cause", "resolution"):
        value = (data.get(field) or "").strip()[:2000]
        if value:
            conn.execute(f"UPDATE incidents SET {field} = ? WHERE id = ?", (value, incident_id))
            changes.append(field)

    new_status = (data.get("status") or "").strip()
    if new_status and new_status != inc["status"]:
        if new_status not in TRANSITIONS.get(inc["status"], set()):
            conn.rollback()
            return False, f"Transición no permitida: {inc['status']} -> {new_status}."
        if new_status == "cerrado":
            cause = (data.get("cause") or inc["cause"]).strip()
            resolution = (data.get("resolution") or inc["resolution"]).strip()
            if not cause or not resolution:
                conn.rollback()
                return False, "Para cerrar el incidente se requieren causa y resolución."
            conn.execute("UPDATE incidents SET closed_at = ? WHERE id = ?", (ts, incident_id))
        conn.execute("UPDATE incidents SET status = ? WHERE id = ?", (new_status, incident_id))
        add_update(conn, incident_id, actor, "estado", f"{inc['status']} -> {new_status}")
        changes.append("status")

    note = (data.get("note") or "").strip()[:2000]
    if note:
        add_update(conn, incident_id, actor, "nota", note)
        changes.append("note")

    if not changes:
        return False, "No se enviaron cambios."
    conn.execute("UPDATE incidents SET updated_at = ? WHERE id = ?", (ts, incident_id))
    audit(conn, actor, "incidente_actualizado", "incident", incident_id, {"cambios": changes}, commit=False)
    conn.commit()
    return True, "Incidente actualizado."

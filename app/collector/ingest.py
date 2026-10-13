"""
ingest.py - Tubería de ingesta Syslog con política explícita.

Flujo por cada mensaje (coincide con el flujo lógico obligatorio de la guía):
  1. Ingreso       -> línea recibida por UDP, archivo, simulador o API
  2. Validación    -> saneamiento, formato Syslog, fuente en inventario (allowlist)
  3. Protección    -> enmascarado de secretos, detección de inyección de prompt
  4. Control       -> límite de frecuencia (tormentas) y deduplicación
  5. Política      -> severidad + reglas de seguridad => crear/actualizar incidente
  6. Propuesta     -> el "agente IA simulado" solo PROPONE una acción de diagnóstico
                      tomada de una tabla fija; nunca lee instrucciones del log
  7. Auditoría     -> cada decisión relevante queda en audit_log
"""
import hashlib
import re
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta

from app.collector.parser import parse_syslog
from app.db import now_iso
from app.incidents.service import open_or_update_incident
from app.security import policy
from app.security.audit import audit


class RateLimiter:
    """Ventana deslizante de 60 s por fuente (control de tormentas / backpressure)."""

    def __init__(self):
        self._hits = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str, limit: int, window: float = 60.0) -> bool:
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and now - q[0] > window:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            return True

    def reset(self):
        with self._lock:
            self._hits.clear()


RATE_LIMITER = RateLimiter()

# Acción de diagnóstico que el agente simulado puede PROPONER, según marca.
# La tabla es fija: el contenido del log jamás se convierte en comando.
AGENT_DIAGNOSTIC = {
    "Cisco": ("show logging", "Revisar el buffer de logs del equipo para confirmar el evento."),
    "Fortinet": ("get system status", "Confirmar estado general del firewall tras el evento."),
    "Huawei": ("display info-center", "Confirmar estado del centro de información y del loghost."),
}


def find_device(conn, source: str, hostname: str):
    """Busca el equipo por IP de origen o por hostname (allowlist = inventario)."""
    for value in (source, hostname):
        if not value:
            continue
        row = conn.execute(
            "SELECT * FROM devices WHERE ip = ? OR lower(name) = lower(?)", (value, value)
        ).fetchone()
        if row:
            return row
    return None


def _signature(device_key: str, severity: int, app: str, message: str) -> str:
    """Huella para deduplicar: mismo origen, severidad, mnemónico y mensaje."""
    norm = re.sub(r"\s+", " ", message.strip().lower())
    return hashlib.sha1(f"{device_key}|{severity}|{app}|{norm}".encode("utf-8")).hexdigest()


def _outside_business_hours(event_time: str, cfg) -> bool:
    try:
        hour = datetime.strptime(event_time, "%Y-%m-%d %H:%M:%S").hour
    except ValueError:
        hour = datetime.now().hour
    return not (cfg["BUSINESS_HOURS_START"] <= hour < cfg["BUSINESS_HOURS_END"])


def ingest_line(conn, raw_line: str, cfg: dict, source: str = "", channel: str = "importacion",
                origin_label: str = "simulado", actor: str = "sistema") -> dict:
    """
    Procesa una línea Syslog completa. Devuelve un resumen con 'status':
      stored | deduplicated | rate_limited | invalid
    """
    # ---- 1-2. Validación de entrada ----
    line = policy.sanitize_line(raw_line, cfg["MAX_LINE_LENGTH"])
    if not line or line.startswith("#"):
        return {"status": "invalid", "reason": "línea vacía o comentario"}
    parsed = parse_syslog(line)
    if parsed is None:
        return {"status": "invalid", "reason": "formato Syslog no reconocido"}
    if origin_label not in ("simulado", "real"):
        origin_label = "simulado"

    # ---- 3. Protección de datos ----
    message, masked_msg = policy.mask_secrets(parsed["message"])
    raw_safe, _ = policy.mask_secrets(line)
    flags = []
    if masked_msg:
        flags.append("secreto_enmascarado")

    device = find_device(conn, source, parsed["hostname"])
    authorized = 1 if device else 0
    if not authorized:
        flags.append("fuente_no_autorizada")
    vendor = device["vendor"] if device else (parsed["vendor_hint"] or "Desconocido")
    device_key = str(device["id"]) if device else (source or parsed["hostname"] or "desconocido")

    injection = policy.detect_injection(message)
    if injection:
        flags.append("posible_inyeccion_prompt")
    svc_account = policy.detect_service_account(message)
    if svc_account:
        flags.append("cuenta_servicio_o_agente")
    config_change = policy.is_config_change(f"{parsed['app_name']} {message}")
    if config_change:
        flags.append("cambio_configuracion")
        if _outside_business_hours(parsed["event_time"], cfg):
            flags.append("fuera_de_horario")
    auth_fail = policy.is_auth_failure(f"{parsed['app_name']} {message}")
    if auth_fail:
        flags.append("fallo_autenticacion")

    received = now_iso()

    # ---- 4a. Control de tormentas (límite por fuente y minuto) ----
    if not RATE_LIMITER.allow(device_key, cfg["RATE_LIMIT_PER_MINUTE"]):
        open_or_update_incident(
            conn, title=f"Tormenta de eventos desde {device['name'] if device else device_key}",
            description=("Se superó el límite de frecuencia configurado "
                         f"({cfg['RATE_LIMIT_PER_MINUTE']} eventos/min). Los mensajes excedentes se "
                         "descartaron para proteger el tablero y las alertas (backpressure)."),
            severity=3, category="seguridad", device_id=device["id"] if device else None,
            event_id=None, signature=f"storm|{device_key}", actor="politica-syslog")
        return {"status": "rate_limited", "reason": "límite de frecuencia superado"}

    # ---- 4b. Deduplicación ----
    sig = _signature(device_key, parsed["severity"], parsed["app_name"], message)
    since = (datetime.now() - timedelta(seconds=cfg["DEDUP_WINDOW_SECONDS"])).strftime("%Y-%m-%d %H:%M:%S")
    dup = conn.execute(
        "SELECT id, incident_id FROM events WHERE signature = ? AND received_at >= ? ORDER BY id DESC LIMIT 1",
        (sig, since),
    ).fetchone()
    if dup:
        conn.execute("UPDATE events SET repeat_count = repeat_count + 1, received_at = ? WHERE id = ?",
                     (received, dup["id"]))
        if dup["incident_id"]:
            conn.execute("UPDATE incidents SET event_count = event_count + 1, updated_at = ? WHERE id = ?",
                         (received, dup["incident_id"]))
        return {"status": "deduplicated", "event_id": dup["id"]}

    # ---- Persistencia del evento normalizado ----
    cur = conn.execute(
        """INSERT INTO events (received_at, event_time, device_id, source, hostname, vendor, facility,
                               severity, app_name, message, raw, fmt, origin_label, ingest_channel,
                               authorized, flags, signature)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (received, parsed["event_time"], device["id"] if device else None,
         source or parsed["hostname"] or "desconocido", parsed["hostname"], vendor, parsed["facility"],
         parsed["severity"], parsed["app_name"], message, raw_safe, parsed["fmt"], origin_label, channel,
         authorized, ",".join(flags), sig),
    )
    event_id = cur.lastrowid
    if device:
        conn.execute("UPDATE devices SET last_seen = ? WHERE id = ?", (received, device["id"]))

    # ---- 5. Política: ¿este evento abre o actualiza un incidente? ----
    incident_id = None
    dev_name = device["name"] if device else device_key
    if "posible_inyeccion_prompt" in flags:
        # El log se conserva como DATO; se abre un incidente de seguridad, nada se ejecuta.
        incident_id = open_or_update_incident(
            conn, title=f"Posible inyección de prompt en log de {dev_name}",
            description=("Un mensaje Syslog contiene texto con forma de instrucción para un agente de IA. "
                         "Se trató como dato no confiable: no se ejecutó ninguna acción ni se alteró la política."),
            severity=min(parsed["severity"], 2), category="seguridad-ia",
            device_id=device["id"] if device else None, event_id=event_id,
            signature=f"inject|{device_key}", actor="politica-ia")
        audit(conn, "politica-ia", "inyeccion_detectada", "event", event_id,
              {"patrones": injection[:3]}, commit=False)
    elif not authorized:
        incident_id = open_or_update_incident(
            conn, title=f"Fuente Syslog no autorizada: {device_key}",
            description="Llegaron eventos desde una fuente que no está en el inventario (allowlist). "
                        "Los eventos se conservan en cuarentena y no generan incidentes operativos.",
            severity=4, category="seguridad", device_id=None, event_id=event_id,
            signature=f"unauth|{device_key}", actor="politica-syslog")
    elif "fuera_de_horario" in flags:
        incident_id = open_or_update_incident(
            conn, title=f"Cambio de configuración fuera de horario en {dev_name}",
            description="Se registró un cambio de configuración fuera del horario laboral definido. "
                        "Validar si existe una solicitud de cambio aprobada (posible agente o cuenta no autorizada).",
            severity=2, category="seguridad", device_id=device["id"], event_id=event_id,
            signature=f"offhours|{device_key}", actor="politica-syslog")
    elif auth_fail:
        if _auth_failures_recent(conn, device["id"]) >= 5:
            incident_id = open_or_update_incident(
                conn, title=f"Múltiples fallos de autenticación en {dev_name}",
                description="Cinco o más fallos de autenticación en 5 minutos: posible fuerza bruta o "
                            "agente automatizado usando credenciales no válidas.",
                severity=2, category="seguridad", device_id=device["id"], event_id=event_id,
                signature=f"bruteforce|{device_key}", actor="politica-syslog")
        elif parsed["severity"] <= cfg["INCIDENT_MAX_SEVERITY"]:
            # Fallos aislados se agrupan en un único incidente por equipo (no uno por intento)
            incident_id = open_or_update_incident(
                conn, title=f"Fallo de autenticación en {dev_name}",
                description=message[:500], severity=parsed["severity"], category="seguridad",
                device_id=device["id"], event_id=event_id, signature=f"authfail|{device_key}",
                actor="politica-syslog")
    elif parsed["severity"] <= cfg["INCIDENT_MAX_SEVERITY"]:
        incident_id = open_or_update_incident(
            conn, title=f"{dev_name}: {message[:90]}",
            description=message[:500], severity=parsed["severity"], category="operacion",
            device_id=device["id"], event_id=event_id, signature=f"op|{sig}", actor="politica-syslog")
        # ---- 6. Propuesta del agente simulado (solo severidades 0-2, sin ejecutar nada) ----
        if parsed["severity"] <= 2 and vendor in AGENT_DIAGNOSTIC:
            _agent_proposal(conn, incident_id, device["id"], vendor)

    if incident_id:
        conn.execute("UPDATE events SET incident_id = ? WHERE id = ?", (incident_id, event_id))
    return {"status": "stored", "event_id": event_id, "incident_id": incident_id, "flags": flags}


def _auth_failures_recent(conn, device_id: int) -> int:
    since = (datetime.now() - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
    row = conn.execute(
        """SELECT COALESCE(SUM(repeat_count),0) FROM events
           WHERE device_id = ? AND received_at >= ? AND flags LIKE '%fallo_autenticacion%'""",
        (device_id, since)).fetchone()
    return row[0]


def _agent_proposal(conn, incident_id: int, device_id: int, vendor: str) -> None:
    """El agente de IA simulado propone un diagnóstico; queda PENDIENTE de revisión humana."""
    exists = conn.execute(
        "SELECT 1 FROM action_proposals WHERE incident_id = ? AND proposed_by = 'agente-ia-simulado'",
        (incident_id,)).fetchone()
    if exists:
        return
    command, rationale = AGENT_DIAGNOSTIC[vendor]
    category, explanation = policy.classify_action(vendor, command)
    status = "bloqueada" if category == "bloqueado" else "pendiente"
    cur = conn.execute(
        """INSERT INTO action_proposals (incident_id, device_id, command, rationale, proposed_by,
                                         status, policy_check, created_at)
           VALUES (?,?,?,?,?,?,?,?)""",
        (incident_id, device_id, command, rationale, "agente-ia-simulado", status,
         f"{category}: {explanation}", now_iso()))
    audit(conn, "agente-ia-simulado", "propuesta_creada", "action_proposal", cur.lastrowid,
          {"comando": command, "estado": status}, commit=False)


def ingest_lines(conn, lines, cfg: dict, channel: str, origin_label: str, actor: str,
                 source: str = "") -> dict:
    """Procesa un lote de líneas y devuelve contadores. Un solo commit al final."""
    summary = {"recibidas": 0, "almacenadas": 0, "duplicadas": 0, "descartadas_tormenta": 0,
               "invalidas": 0, "incidentes": set(), "banderas": defaultdict(int)}
    for raw in lines:
        if summary["recibidas"] >= cfg["MAX_LINES_PER_IMPORT"]:
            break
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        summary["recibidas"] += 1
        r = ingest_line(conn, raw, cfg, source=source, channel=channel,
                        origin_label=origin_label, actor=actor)
        if r["status"] == "stored":
            summary["almacenadas"] += 1
            if r.get("incident_id"):
                summary["incidentes"].add(r["incident_id"])
            for f in r.get("flags", []):
                summary["banderas"][f] += 1
        elif r["status"] == "deduplicated":
            summary["duplicadas"] += 1
        elif r["status"] == "rate_limited":
            summary["descartadas_tormenta"] += 1
        else:
            summary["invalidas"] += 1
    summary["incidentes"] = sorted(summary["incidentes"])
    summary["banderas"] = dict(summary["banderas"])
    audit(conn, actor, "ingesta_syslog", "events", channel,
          {k: v for k, v in summary.items()}, commit=False)
    conn.commit()
    return summary

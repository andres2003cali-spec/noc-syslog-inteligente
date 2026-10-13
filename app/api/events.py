"""
events.py - API de eventos Syslog (RF-02, RF-03, RF-04, HU-02).

GET  /api/events                 lista filtrada (fecha, marca, equipo, severidad, banderas)
GET  /api/events/stats           totales para el dashboard
POST /api/events/import          importa archivo .log/.txt o texto pegado
POST /api/events/simulate        genera eventos SINTÉTICOS por escenario
GET  /api/events/scenarios       escenarios disponibles
GET  /api/events/export.csv      exporta el resultado del filtro (evidencia)
"""
import csv
import io

from flask import Blueprint, Response, current_app, jsonify, request

from app.collector.ingest import ingest_lines
from app.collector.parser import FACILITY_NAMES, SEVERITY_NAMES
from app.collector.simulator import SCENARIOS, scenario_lines
from app.db import get_db
from app.security.policy import current_user, require

bp = Blueprint("events", __name__, url_prefix="/api/events")

ALLOWED_EXT = (".log", ".txt", ".syslog")


def _filters():
    """Construye la cláusula WHERE con parámetros (nunca concatenando valores)."""
    a = request.args
    where, params = [], []
    if a.get("date_from"):
        where.append("e.event_time >= ?")
        params.append(a["date_from"].replace("T", " ") + ("" if len(a["date_from"]) > 10 else " 00:00:00"))
    if a.get("date_to"):
        where.append("e.event_time <= ?")
        params.append(a["date_to"].replace("T", " ") + ("" if len(a["date_to"]) > 10 else " 23:59:59"))
    if a.get("vendor"):
        where.append("e.vendor = ?")
        params.append(a["vendor"])
    if a.get("device_id"):
        where.append("e.device_id = ?")
        params.append(int(a["device_id"]))
    if a.get("severity") not in (None, ""):
        where.append("e.severity = ?")
        params.append(int(a["severity"]))
    if a.get("sev_max") not in (None, ""):
        where.append("e.severity <= ?")
        params.append(int(a["sev_max"]))
    if a.get("facility") not in (None, ""):
        where.append("e.facility = ?")
        params.append(int(a["facility"]))
    if a.get("flag"):
        where.append("e.flags LIKE ?")
        params.append(f"%{a['flag']}%")
    if a.get("flagged") == "1":
        where.append("e.flags <> ''")
    if a.get("authorized") in ("0", "1"):
        where.append("e.authorized = ?")
        params.append(int(a["authorized"]))
    if a.get("q"):
        where.append("e.message LIKE ?")
        params.append(f"%{a['q'][:100]}%")
    return (" WHERE " + " AND ".join(where)) if where else "", params


def _row(r) -> dict:
    d = dict(r)
    d["severity_name"] = SEVERITY_NAMES[r["severity"]][1]
    d["facility_name"] = FACILITY_NAMES.get(r["facility"], str(r["facility"]))
    return d


@bp.get("")
@require("read")
def list_events():
    try:
        where, params = _filters()
        limit = min(int(request.args.get("limit", 100)), 500)
        offset = max(int(request.args.get("offset", 0)), 0)
    except ValueError:
        return jsonify(error="Parámetros de filtro inválidos."), 400
    db = get_db()
    total = db.execute(f"SELECT COUNT(*) FROM events e{where}", params).fetchone()[0]
    rows = db.execute(
        f"""SELECT e.*, d.name AS device_name FROM events e LEFT JOIN devices d ON d.id = e.device_id
            {where} ORDER BY e.event_time DESC, e.id DESC LIMIT ? OFFSET ?""",
        [*params, limit, offset]).fetchall()
    return jsonify(total=total, items=[_row(r) for r in rows])


@bp.get("/stats")
@require("read")
def stats():
    db = get_db()
    by_sev = {r[0]: r[1] for r in db.execute("SELECT severity, COUNT(*) FROM events GROUP BY severity")}
    by_vendor = {r[0]: r[1] for r in db.execute("SELECT vendor, COUNT(*) FROM events GROUP BY vendor")}
    return jsonify(by_severity={str(i): by_sev.get(i, 0) for i in range(8)}, by_vendor=by_vendor)


@bp.get("/scenarios")
@require("read")
def scenarios():
    return jsonify(SCENARIOS)


@bp.post("/import")
@require("ingest")
def import_events():
    """Acepta un archivo (multipart 'file') o JSON {'text': '...', 'origin_label': 'simulado|real'}."""
    user, _role = current_user()
    origin = "simulado"
    if "file" in request.files:
        f = request.files["file"]
        if not f.filename or not f.filename.lower().endswith(ALLOWED_EXT):
            return jsonify(error="Tipo de archivo no permitido. Use .log, .txt o .syslog."), 400
        raw = f.read(current_app.config["MAX_UPLOAD_BYTES"] + 1)
        if len(raw) > current_app.config["MAX_UPLOAD_BYTES"]:
            return jsonify(error="Archivo demasiado grande (máximo 2 MB)."), 413
        text = raw.decode("utf-8", errors="replace")
        origin = request.form.get("origin_label", "simulado")
    else:
        body = request.get_json(silent=True) or {}
        text = str(body.get("text", ""))
        origin = body.get("origin_label", "simulado")
        if len(text.encode("utf-8")) > current_app.config["MAX_UPLOAD_BYTES"]:
            return jsonify(error="Texto demasiado grande (máximo 2 MB)."), 413
    if not text.strip():
        return jsonify(error="No se recibió contenido para importar."), 400
    summary = ingest_lines(get_db(), text.splitlines(), current_app.config, channel="importacion",
                           origin_label=origin if origin in ("simulado", "real") else "simulado", actor=user)
    return jsonify(summary)


@bp.post("/simulate")
@require("ingest")
def simulate():
    user, _role = current_user()
    name = (request.get_json(silent=True) or {}).get("scenario", "mixto")
    if name not in SCENARIOS:
        return jsonify(error="Escenario desconocido."), 400
    summary = ingest_lines(get_db(), scenario_lines(name), current_app.config, channel="simulador",
                           origin_label="simulado", actor=user)
    summary["escenario"] = name
    return jsonify(summary)


@bp.get("/export.csv")
@require("read")
def export_csv():
    where, params = _filters()
    rows = get_db().execute(
        f"""SELECT e.id, e.event_time, d.name AS device, e.vendor, e.facility, e.severity, e.app_name,
                   e.message, e.origin_label, e.authorized, e.flags, e.repeat_count, e.incident_id
            FROM events e LEFT JOIN devices d ON d.id = e.device_id {where}
            ORDER BY e.event_time DESC LIMIT 5000""", params).fetchall()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "fecha", "equipo", "marca", "facility", "severidad", "app", "mensaje", "origen",
                "autorizado", "banderas", "repeticiones", "incidente"])
    for r in rows:
        # Prefijo ' evita inyección de fórmulas al abrir el CSV en Excel
        w.writerow([("'" + str(v)) if isinstance(v, str) and v[:1] in "=+-@" else v for v in r])
    return Response("\ufeff" + buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=eventos_noc.csv"})

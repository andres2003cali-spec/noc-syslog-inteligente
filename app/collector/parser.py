"""
parser.py - Normalización de mensajes Syslog (RF-03).

Formatos reconocidos:
  - RFC 5424:  <PRI>1 2026-10-13T10:00:00Z HOST APP PROCID MSGID [SD] MSG
  - RFC 3164:  <PRI>Oct 13 10:00:00 HOST TAG[pid]: MSG
  - Cisco IOS: <PRI>seq: *Oct 13 10:00:00.123: %LINK-3-UPDOWN: texto
  - FortiOS:   <PRI>date=2026-10-13 time=10:00:00 devname="FW" level="alert" msg="..."
  - Huawei:    <PRI>Oct 13 2026 10:00:00 SW-CORE %%01IFNET/4/LINK_STATE(l):texto

PRI = facility * 8 + severity  ->  facility = PRI // 8, severity = PRI % 8 (RFC 5424).
Si el mensaje trae severidad propia (Cisco %X-n-Y, FortiOS level=, Huawei /n/)
se usa esa, porque es la que define el fabricante.
"""
import re
from datetime import datetime, timedelta

SEVERITY_NAMES = {
    0: ("Emergency", "Emergencia"), 1: ("Alert", "Alerta"), 2: ("Critical", "Crítico"),
    3: ("Error", "Error"), 4: ("Warning", "Advertencia"), 5: ("Notice", "Aviso"),
    6: ("Informational", "Informativo"), 7: ("Debug", "Depuración"),
}

FACILITY_NAMES = {
    0: "kern", 1: "user", 2: "mail", 3: "daemon", 4: "auth", 5: "syslog", 6: "lpr", 7: "news",
    8: "uucp", 9: "cron", 10: "authpriv", 11: "ftp", 12: "ntp", 13: "audit", 14: "alert",
    15: "clock", 16: "local0", 17: "local1", 18: "local2", 19: "local3", 20: "local4",
    21: "local5", 22: "local6", 23: "local7",
}

# Palabras de nivel de FortiOS -> severidad numérica
FORTI_LEVELS = {"emergency": 0, "alert": 1, "critical": 2, "error": 3, "warning": 4,
                "notice": 5, "notification": 5, "information": 6, "informational": 6, "debug": 7}

MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}

RE_PRI = re.compile(r"^<(\d{1,3})>")
RE_5424 = re.compile(r"^1 (\S+) (\S+) (\S+) (\S+) (\S+) (-|(?:\[.*?\])+)(?: (.*))?$")
RE_3164 = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2}) (\d{2}):(\d{2}):(\d{2}) (\S+) ([^:\[\s]+)(?:\[\d+\])?:\s?(.*)$")
RE_CISCO_MNEMONIC = re.compile(r"%([A-Z0-9_]+(?:-[A-Z0-9_]+)?)-([0-7])-([A-Z0-9_]+):\s*(.*)$")
RE_CISCO_TIME = re.compile(r"[*.]?([A-Z][a-z]{2})\s+(\d{1,2})\s+(?:(\d{4})\s+)?(\d{2}):(\d{2}):(\d{2})")
RE_CISCO_HOST = re.compile(r"^(?:\d+:\s+)?([A-Za-z][\w.-]*):\s")
RE_HUAWEI = re.compile(
    r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{4})\s+(\d{2}):(\d{2}):(\d{2})(?:[.:]\d+)?(?:\s+[A-Z+\-:0-9]+)?\s+(\S+)\s+"
    r"%%\d+([\w-]+)/([0-7])/([\w-]+)(?:\([^)]*\))?(?:\[\d+\])?:\s*(.*)$"
)
RE_KV = re.compile(r'(\w+)=("([^"]*)"|\S+)')


def severity_label(sev: int) -> str:
    en, es = SEVERITY_NAMES.get(sev, ("?", "?"))
    return f"{sev} · {es} ({en})"


def _infer_year(month: int, day: int, h: int, mi: int, s: int, now: datetime) -> str:
    """RFC 3164 no trae año: se asume el actual; si queda en el futuro, el anterior."""
    try:
        dt = datetime(now.year, month, day, h, mi, s)
    except ValueError:
        return now.strftime("%Y-%m-%d %H:%M:%S")
    if dt > now + timedelta(days=1):
        dt = dt.replace(year=now.year - 1)
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _iso_to_local(ts: str, now: datetime) -> str:
    """Convierte un timestamp RFC 5424 (ISO 8601) a 'AAAA-MM-DD HH:MM:SS' en hora local."""
    if ts == "-":
        return now.strftime("%Y-%m-%d %H:%M:%S")
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if dt.tzinfo is not None:
            dt = dt.astimezone().replace(tzinfo=None)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return now.strftime("%Y-%m-%d %H:%M:%S")


def parse_syslog(line: str, now: datetime | None = None) -> dict | None:
    """
    Normaliza una línea Syslog. Devuelve un diccionario con:
      facility, severity, event_time, hostname, app_name, message, fmt, vendor_hint
    o None si la línea no es Syslog válido (se rechaza: validación de formato).
    """
    now = now or datetime.now()
    line = (line or "").strip()
    if not line:
        return None

    facility, severity = 23, None          # local7 por defecto si no hay PRI
    rest = line
    m = RE_PRI.match(line)
    if m:
        pri = int(m.group(1))
        if pri > 191:                       # PRI máximo válido = 23*8+7
            return None
        facility, severity = pri // 8, pri % 8
        rest = line[m.end():]

    # ---------- RFC 5424 ----------
    m5 = RE_5424.match(rest) if m else None
    if m5:
        ts, host, app, _procid, _msgid, _sd, msg = m5.groups()
        msg = msg or ""
        result = {"facility": facility, "severity": severity, "event_time": _iso_to_local(ts, now),
                  "hostname": "" if host == "-" else host, "app_name": "" if app == "-" else app,
                  "message": msg.lstrip("\ufeff"), "fmt": "rfc5424", "vendor_hint": ""}
        _apply_vendor_markers(result)
        return result

    # ---------- Huawei VRP ----------
    mh = RE_HUAWEI.match(rest)
    if mh:
        mon, day, year, h, mi, s, host, module, lvl, brief, msg = mh.groups()
        try:
            ev = datetime(int(year), MONTHS.get(mon, 1), int(day), int(h), int(mi), int(s))
            ev_time = ev.strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            ev_time = now.strftime("%Y-%m-%d %H:%M:%S")
        return {"facility": facility, "severity": int(lvl), "event_time": ev_time, "hostname": host,
                "app_name": f"{module}/{lvl}/{brief}", "message": msg, "fmt": "huawei",
                "vendor_hint": "Huawei"}

    # ---------- FortiOS (clave=valor) ----------
    if "devname=" in rest or ("logid=" in rest and "level=" in rest):
        kv = {k: (v3 if v3 is not None and v2.startswith('"') else v2) for k, v2, v3 in RE_KV.findall(rest)}
        sev = FORTI_LEVELS.get(kv.get("level", "").lower(), severity if severity is not None else 6)
        date, time_ = kv.get("date", ""), kv.get("time", "")
        try:
            ev_time = datetime.strptime(f"{date} {time_}", "%Y-%m-%d %H:%M:%S").strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            ev_time = now.strftime("%Y-%m-%d %H:%M:%S")
        msg = kv.get("msg") or kv.get("logdesc") or rest
        extra = []
        for key in ("logdesc", "user", "srcip", "dstip", "action", "cfgpath", "ui"):
            if key in kv and kv[key] not in msg:
                extra.append(f"{key}={kv[key]}")
        if extra:
            msg = f"{msg} ({', '.join(extra)})"
        return {"facility": facility, "severity": sev, "event_time": ev_time,
                "hostname": kv.get("devname", ""), "app_name": f"{kv.get('type', '')}/{kv.get('subtype', '')}".strip("/"),
                "message": msg, "fmt": "fortinet", "vendor_hint": "Fortinet"}

    # ---------- Cisco IOS / IOS XE (mnemónico %FAC-SEV-MNEMONIC) ----------
    mc = RE_CISCO_MNEMONIC.search(rest)
    if mc:
        fac_name, lvl, mnemonic, msg = mc.groups()
        head = rest[:mc.start()]
        mt = RE_CISCO_TIME.search(head)
        if mt:
            mon, day, year, h, mi, s = mt.groups()
            if year:
                ev_time = f"{year}-{MONTHS.get(mon, 1):02d}-{int(day):02d} {h}:{mi}:{s}"
            else:
                ev_time = _infer_year(MONTHS.get(mon, 1), int(day), int(h), int(mi), int(s), now)
        else:
            ev_time = now.strftime("%Y-%m-%d %H:%M:%S")
        mhost = RE_CISCO_HOST.match(head)
        host = mhost.group(1) if mhost and mhost.group(1)[:3] not in MONTHS else ""
        return {"facility": facility, "severity": int(lvl), "event_time": ev_time, "hostname": host,
                "app_name": f"%{fac_name}-{lvl}-{mnemonic}", "message": msg, "fmt": "cisco",
                "vendor_hint": "Cisco"}

    # ---------- RFC 3164 (BSD) ----------
    m3 = RE_3164.match(rest)
    if m3 and severity is not None:
        mon, day, h, mi, s, host, tag, msg = m3.groups()
        result = {"facility": facility, "severity": severity,
                  "event_time": _infer_year(MONTHS.get(mon, 1), int(day), int(h), int(mi), int(s), now),
                  "hostname": host, "app_name": tag, "message": msg, "fmt": "rfc3164", "vendor_hint": ""}
        _apply_vendor_markers(result)
        return result

    # ---------- Genérico: tiene PRI pero el cuerpo no coincide con ningún formato ----------
    if severity is not None and rest.strip():
        return {"facility": facility, "severity": severity, "event_time": now.strftime("%Y-%m-%d %H:%M:%S"),
                "hostname": "", "app_name": "", "message": rest.strip(), "fmt": "generico", "vendor_hint": ""}

    # Sin PRI ni marcadores de fabricante: no es Syslog -> se rechaza
    return None


def _apply_vendor_markers(result: dict) -> None:
    """Si el mensaje RFC 3164/5424 contiene un mnemónico Cisco, se usa su severidad."""
    mc = RE_CISCO_MNEMONIC.search(result["message"])
    if mc:
        result["severity"] = int(mc.group(2))
        result["app_name"] = f"%{mc.group(1)}-{mc.group(2)}-{mc.group(3)}"
        result["vendor_hint"] = "Cisco"

"""
policy.py - Política inicial de defensa frente a acciones de agentes de IA (v0.2.0).

Principio rector ("regla de oro"): TODO log, archivo o salida de equipo es un
DATO NO CONFIABLE. Nunca se interpreta como instrucción, ni para la aplicación
ni para un agente de IA. Este módulo concentra los controles que lo garantizan:

  1. Saneamiento de entrada (caracteres de control, longitud).
  2. Enmascarado de secretos antes de guardar o mostrar.
  3. Detección de intentos de inyección de prompt dentro de los logs.
  4. Detección de cuentas de servicio / agentes automatizados.
  5. RBAC simulado: lector, operador, administrador y agente-ia (solo propone).
  6. Allowlist de acciones: lo peligroso se bloquea, los cambios requieren
     aprobación humana de un administrador distinto a quien propuso.
"""
import re
from functools import wraps

from flask import jsonify, request

# ---------------------------------------------------------------------------
# 1. Saneamiento
# ---------------------------------------------------------------------------
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def sanitize_line(text: str, max_len: int = 2048) -> str:
    """Elimina caracteres de control (excepto tabulador) y recorta la longitud."""
    text = _CONTROL_CHARS.sub("", text or "").replace("\t", " ").strip()
    return text[:max_len]


# ---------------------------------------------------------------------------
# 2. Enmascarado de secretos (RNF-01)
# ---------------------------------------------------------------------------
_SECRET_PATTERNS = [
    # password=xxx, token: xxx, community=xxx, clave=xxx ...
    re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|community|clave|contrase(?:ñ|n)a)(\s*[=:]\s*)(\"[^\"]*\"|\S+)"),
    # Cisco: "password 7 0822455D0A16", "secret 5 $1$abc..."
    re.compile(r"(?i)\b(password|secret)(\s+\d\s+)(\S+)"),
    # Encabezado Authorization: Bearer xxxxx
    re.compile(r"(?i)\b(bearer)(\s+)([A-Za-z0-9._\-]{8,})"),
]
_TELEGRAM_TOKEN = re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{30,}\b")


def mask_secrets(text: str) -> tuple[str, bool]:
    """Reemplaza valores sensibles por '****'. Devuelve (texto, ¿se enmascaró algo?)."""
    original = text
    for pat in _SECRET_PATTERNS:
        text = pat.sub(lambda m: f"{m.group(1)}{m.group(2)}****", text)
    text = _TELEGRAM_TOKEN.sub("****:****", text)
    return text, text != original


# ---------------------------------------------------------------------------
# 3. Detección de inyección de prompt indirecta (OWASP Agentic AI)
# ---------------------------------------------------------------------------
INJECTION_PATTERNS = [
    r"ignor(a|e|ar)\b.{0,40}\b(instruc|pol[ií]tic|regla|previous|prior|all)",
    r"olvida\b.{0,30}\b(instruc|pol[ií]tic|regla)",
    r"\b(system\s*prompt|prompt\s*del\s*sistema)\b",
    r"\byou\s+are\s+now\b|\bact[uú]a\s+como\b|\bact\s+as\b",
    r"\b(ejecuta|execute|run)\b.{0,30}\b(comando|command|reload|erase|shutdown|config)",
    r"\b(aprueba|approve)\b.{0,30}\b(autom[aá]tic|sin\s+revis|without)",
    r"\b(desactiva|disable)\b.{0,20}\b(logging|log|auditor|seguridad|security|firewall)",
    r"\bsudo\s+\S|\brm\s+-rf\b|\bdrop\s+table\b|<\s*script|javascript:|\$\(|`",
]
_INJECTION_RE = [re.compile(p, re.IGNORECASE) for p in INJECTION_PATTERNS]


def detect_injection(text: str) -> list[str]:
    """Devuelve los patrones de inyección encontrados (lista vacía si no hay)."""
    return [p.pattern for p in _INJECTION_RE if p.search(text or "")]


# ---------------------------------------------------------------------------
# 4. Cuentas de servicio o agentes automatizados en eventos de acceso
# ---------------------------------------------------------------------------
_SERVICE_ACCOUNT = re.compile(
    r"(?i)\b(?:user(?:name)?|usuario|login|admin|by|por)\s*[=:\s]\s*\"?((?:svc|srv|bot|agent|agente|ai|ia|automation|n8n|api)[-_.]?\w*)"
)


def detect_service_account(text: str) -> str | None:
    """Si el log menciona una cuenta de servicio/agente, devuelve su nombre."""
    m = _SERVICE_ACCOUNT.search(text or "")
    return m.group(1) if m else None


_CONFIG_CHANGE = re.compile(
    r"(?i)(%SYS-5-CONFIG|%PARSER-5-CFGLOG|CONFIG_I\b|configuration\s+change|configured\s+from|"
    r"cfgpath=|logdesc=\"?(object|attribute)\s+configured|CFGCHG|CMDRECORD|config(uraci[oó]n)?\s+(modificada|cambiada))"
)
_AUTH_FAIL = re.compile(
    r"(?i)(LOGIN_FAILED|login\s+failed|authentication\s+fail|auth(entication)?\s+failure|"
    r"failed\s+password|admin\s+login\s+failed|LOGINFAIL|inicio\s+de\s+sesi[oó]n\s+fallido)"
)


def is_config_change(text: str) -> bool:
    return bool(_CONFIG_CHANGE.search(text or ""))


def is_auth_failure(text: str) -> bool:
    return bool(_AUTH_FAIL.search(text or ""))


# ---------------------------------------------------------------------------
# 5. RBAC simulado (en v0.2.0 la identidad se elige en la interfaz; Corte 3: login)
# ---------------------------------------------------------------------------
# El ROL lo decide el servidor a partir del usuario; el cliente no puede enviarlo.
USERS = {
    "lector.demo": "lector",
    "operador.demo": "operador",
    "operador2.demo": "operador",
    "admin.demo": "administrador",
    "agente-ia-simulado": "agente",
}

PERMISSIONS = {
    "lector": {"read", "console"},
    "operador": {"read", "console", "device_write", "ingest", "incident_write", "propose", "execute", "verify"},
    "administrador": {"read", "console", "device_write", "device_delete", "ingest", "incident_write",
                      "propose", "approve", "execute", "verify", "admin"},
    # El agente de IA SOLO lee eventos y propone. No aprueba, no ejecuta, no usa consola.
    "agente": {"read", "propose"},
}


def current_user() -> tuple[str, str]:
    """Usuario y rol de la petición. Sin cabecera => 'lector.demo' (mínimo privilegio)."""
    user = (request.headers.get("X-NOC-User") or "lector.demo").strip()
    role = USERS.get(user)
    if role is None:
        return user, "desconocido"
    return user, role


def can(role: str, permission: str) -> bool:
    return permission in PERMISSIONS.get(role, set())


def require(permission: str):
    """Decorador: responde 403 si el rol del usuario no tiene el permiso."""
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user, role = current_user()
            if not can(role, permission):
                return jsonify(error=f"Acceso denegado: el rol '{role}' ({user}) no tiene el permiso "
                                     f"'{permission}'."), 403
            return fn(*args, **kwargs)
        return wrapper
    return deco


# ---------------------------------------------------------------------------
# 6. Allowlist de acciones para propuestas (flujo con aprobación humana)
# ---------------------------------------------------------------------------
# Lectura / diagnóstico: bajo riesgo, igualmente pasan por aprobación en v0.2.0.
READ_ACTIONS = {
    "Cisco": [r"show (version|logging|clock|ip interface brief|interfaces(\s+\S+)?|running-config \| section logging)"],
    "Fortinet": [r"get system (status|interface)", r"show log syslogd (setting|filter)", r"diagnose sys top"],
    "Huawei": [r"display (version|info-center|clock|ip interface brief|interface(\s+\S+)?|logbuffer)"],
}
# Cambios controlados: solo con aprobación de un administrador distinto al proponente.
CHANGE_ACTIONS = {
    "Cisco": [r"logging host \d{1,3}(\.\d{1,3}){3}", r"logging trap \w+",
              r"interface [A-Za-z]+[\d/.]+ (shutdown|no shutdown)", r"clear counters [A-Za-z]+[\d/.]+"],
    "Fortinet": [r"set status (enable|disable)", r"set server \"?\d{1,3}(\.\d{1,3}){3}\"?"],
    "Huawei": [r"info-center loghost \d{1,3}(\.\d{1,3}){3}", r"interface [A-Za-z]+[\d/.]+ (shutdown|undo shutdown)"],
}
# Siempre bloqueado, sin importar quién lo pida (incluido un agente de IA).
DANGEROUS = re.compile(
    r"(?i)\b(reload|reboot|erase|format|delete|write\s+erase|factory|factoryreset|reset\s+saved|"
    r"configure\s+replace|no\s+logging|undo\s+info-center|crypto\s+key\s+zeroize|username|"
    r"enable\s+secret|no\s+aaa|execute\s+(shutdown|reboot|factoryreset))\b|[;|&`$<>]"
)


def classify_action(vendor: str, command: str) -> tuple[str, str]:
    """
    Clasifica un comando propuesto.
    Devuelve (categoria, explicación) con categoria en: 'lectura', 'cambio', 'bloqueado'.
    """
    cmd = (command or "").strip()
    if not cmd or len(cmd) > 120:
        return "bloqueado", "Comando vacío o demasiado largo."
    if DANGEROUS.search(cmd):
        return "bloqueado", "Comando destructivo o con caracteres de encadenamiento: prohibido por política."
    for pat in READ_ACTIONS.get(vendor, []):
        if re.fullmatch(pat, cmd, flags=re.IGNORECASE):
            return "lectura", "Comando de consulta incluido en la lista permitida."
    for pat in CHANGE_ACTIONS.get(vendor, []):
        if re.fullmatch(pat, cmd, flags=re.IGNORECASE):
            return "cambio", "Cambio controlado: requiere aprobación de un administrador distinto al proponente."
    return "bloqueado", f"Comando fuera de la lista permitida para {vendor or 'equipo sin marca'}."

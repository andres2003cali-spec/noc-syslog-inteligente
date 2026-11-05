"""
==============================================================
 ARCHIVO : app/config.py
 PROYECTO: NOC Syslog Inteligente
 PROPÓSITO:
   Centralizar TODA la configuración de la aplicación.
   Los valores se leen del archivo .env para que ningún
   secreto (token, contraseña) quede escrito en el código.
   -> Cumple RNF-01 (Seguridad: secretos fuera del código)
==============================================================
"""

import os
from pathlib import Path

from dotenv import load_dotenv

# ------------------------------------------------------------
# [BLOQUE 1] RUTAS BASE
# BASE_DIR = carpeta raíz del proyecto (donde está el .env).
# __file__ es este archivo; .parent sube un nivel (app/) y
# otro .parent sube a la raíz (noc-syslog-inteligente/).
# ------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent

# Carga las variables del archivo .env (si existe) al entorno.
load_dotenv(BASE_DIR / ".env")


# ------------------------------------------------------------
# [BLOQUE 2] FUNCIONES AUXILIARES DE LECTURA
# Convierten el texto del .env al tipo correcto (int / bool)
# y usan un valor por defecto si la variable no existe.
# ------------------------------------------------------------
def _texto(nombre: str, defecto: str = "") -> str:
    """Lee una variable de texto."""
    return os.getenv(nombre, defecto).strip()


def _entero(nombre: str, defecto: int) -> int:
    """Lee una variable numérica; si está mal escrita usa el defecto."""
    try:
        return int(os.getenv(nombre, defecto))
    except ValueError:
        return defecto


def _booleano(nombre: str, defecto: bool = False) -> bool:
    """Lee true/false, si/no, 1/0."""
    valor = os.getenv(nombre, str(defecto)).strip().lower()
    return valor in ("true", "1", "si", "sí", "yes")


# ------------------------------------------------------------
# [BLOQUE 3] BASE DE DATOS
# ------------------------------------------------------------
DB_PATH = BASE_DIR / _texto("DB_PATH", "data/noc.db")

# ------------------------------------------------------------
# [BLOQUE 4] COLECTOR SYSLOG (Parte 3)
# ------------------------------------------------------------
SYSLOG_HOST = _texto("SYSLOG_HOST", "0.0.0.0")
SYSLOG_PORT = _entero("SYSLOG_PORT", 514)
ALLOW_UNKNOWN_SOURCES = _booleano("ALLOW_UNKNOWN_SOURCES", False)

# ------------------------------------------------------------
# [BLOQUE 5] POLÍTICA DE EVENTOS (defensa y control de tormentas)
# ------------------------------------------------------------
INCIDENT_MIN_SEVERITY = _entero("INCIDENT_MIN_SEVERITY", 2)
DEVICE_TIMEOUT_MINUTES = _entero("DEVICE_TIMEOUT_MINUTES", 10)
DEDUP_WINDOW_SECONDS = _entero("DEDUP_WINDOW_SECONDS", 60)
STORM_THRESHOLD_PER_MINUTE = _entero("STORM_THRESHOLD_PER_MINUTE", 120)

# ------------------------------------------------------------
# [BLOQUE 6] ALERTAS: TELEGRAM Y CORREO (Parte 7)
# ------------------------------------------------------------
ALERT_MIN_SEVERITY = _entero("ALERT_MIN_SEVERITY", 3)
ALERT_RATE_LIMIT_PER_MINUTE = _entero("ALERT_RATE_LIMIT_PER_MINUTE", 5)

TELEGRAM_ENABLED = _booleano("TELEGRAM_ENABLED", False)
TELEGRAM_BOT_TOKEN = _texto("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = _texto("TELEGRAM_CHAT_ID")

EMAIL_ENABLED = _booleano("EMAIL_ENABLED", False)
SMTP_HOST = _texto("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = _entero("SMTP_PORT", 587)
SMTP_USER = _texto("SMTP_USER")
SMTP_PASSWORD = _texto("SMTP_PASSWORD")
EMAIL_FROM = _texto("EMAIL_FROM")
EMAIL_TO = _texto("EMAIL_TO")

# ------------------------------------------------------------
# [BLOQUE 7] OPERACIÓN
# ------------------------------------------------------------
OPERADOR_DEFAULT = _texto("OPERADOR_DEFAULT", "operador.noc")


# ------------------------------------------------------------
# [BLOQUE 8] ENMASCARAR SECRETOS
# Nunca se imprime un secreto completo en pantalla ni en logs.
# Ejemplo: "123456789:ABCdef..." -> "1234****cdef"
# ------------------------------------------------------------
def enmascarar(secreto: str) -> str:
    if not secreto or secreto.startswith("REEMPLAZAR"):
        return "(no configurado)"
    if len(secreto) <= 8:
        return "****"
    return f"{secreto[:4]}****{secreto[-4:]}"


# ------------------------------------------------------------
# [BLOQUE 9] PRUEBA RÁPIDA
# Ejecuta:  python -m app.config
# Muestra la configuración cargada (con secretos enmascarados).
# ------------------------------------------------------------
if __name__ == "__main__":
    print("=== Configuración cargada ===")
    print(f"Base de datos ........: {DB_PATH}")
    print(f"Colector Syslog ......: {SYSLOG_HOST}:{SYSLOG_PORT}/UDP")
    print(f"Fuentes desconocidas .: {'aceptadas' if ALLOW_UNKNOWN_SOURCES else 'marcadas como NO autorizadas'}")
    print(f"Incidente si sev <= ..: {INCIDENT_MIN_SEVERITY}")
    print(f"Alerta si sev <= .....: {ALERT_MIN_SEVERITY}")
    print(f"Telegram .............: {'ON' if TELEGRAM_ENABLED else 'OFF'} · token {enmascarar(TELEGRAM_BOT_TOKEN)}")
    print(f"Correo ...............: {'ON' if EMAIL_ENABLED else 'OFF'} · clave {enmascarar(SMTP_PASSWORD)}")

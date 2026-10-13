"""
config.py - Configuración central del NOC Syslog Inteligente.

Todos los parámetros se leen de variables de entorno (archivo .env local).
Así se cumple RNF-01: los secretos y valores sensibles NUNCA quedan en el código.
"""
import os
from pathlib import Path

try:  # python-dotenv es opcional: si no está, se usan solo variables del sistema
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:  # pragma: no cover
    pass

# Carpeta raíz del proyecto (dos niveles arriba de este archivo)
BASE_DIR = Path(__file__).resolve().parent.parent

APP_VERSION = "0.2.0"


def _int(name: str, default: int) -> int:
    """Lee un entero del entorno; si el valor es inválido usa el valor por defecto."""
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


def _bool(name: str, default: bool) -> bool:
    """Lee un booleano del entorno ('true', '1', 'si' => True)."""
    return str(os.getenv(name, default)).strip().lower() in ("1", "true", "si", "sí", "yes")


class Config:
    """Parámetros de la aplicación. Los valores por defecto son seguros para laboratorio."""

    # Clave de Flask: si no existe en el entorno se genera una aleatoria por ejecución
    SECRET_KEY = os.getenv("NOC_SECRET_KEY") or os.urandom(32).hex()

    # Base de datos SQLite (archivo local, excluido de Git)
    DB_PATH = os.getenv("NOC_DB_PATH", str(BASE_DIR / "data" / "noc.db"))

    # Receptor Syslog UDP de laboratorio (desactivado por defecto)
    SYSLOG_HOST = os.getenv("NOC_SYSLOG_HOST", "127.0.0.1")
    SYSLOG_PORT = _int("NOC_SYSLOG_PORT", 5514)
    SYSLOG_ENABLED = _bool("NOC_SYSLOG_ENABLED", False)

    # Política: severidades 0..N abren incidente automáticamente (por defecto 0-3)
    INCIDENT_MAX_SEVERITY = _int("NOC_INCIDENT_MAX_SEVERITY", 3)

    # Control de tormentas y deduplicación
    RATE_LIMIT_PER_MINUTE = _int("NOC_RATE_LIMIT_PER_MINUTE", 60)
    DEDUP_WINDOW_SECONDS = _int("NOC_DEDUP_WINDOW_SECONDS", 60)

    # Estado de comunicación de los equipos (HU-01)
    OFFLINE_THRESHOLD_MINUTES = _int("NOC_OFFLINE_THRESHOLD_MINUTES", 30)

    # Horario laboral para la regla "cambio fuera de horario"
    BUSINESS_HOURS_START = _int("NOC_BUSINESS_HOURS_START", 7)
    BUSINESS_HOURS_END = _int("NOC_BUSINESS_HOURS_END", 19)

    # Límites de entrada (validación, RNF-04)
    MAX_UPLOAD_BYTES = 2 * 1024 * 1024      # 2 MB por archivo importado
    MAX_LINE_LENGTH = 2048                  # bytes por mensaje Syslog
    MAX_LINES_PER_IMPORT = 5000             # líneas por importación

    # Seguridad de Flask
    MAX_CONTENT_LENGTH = MAX_UPLOAD_BYTES + 64 * 1024
    TESTING = False

"""
==============================================================
 ARCHIVO : app/database.py
 PROYECTO: NOC Syslog Inteligente
 PROPÓSITO:
   1. Crear la base de datos SQLite y sus 7 tablas.
   2. Entregar conexiones a la BD al resto de la aplicación.
   3. Cargar equipos SIMULADOS de ejemplo (claramente marcados).
   4. Registrar la auditoría general (quién hizo qué y cuándo).

 TABLAS (modelo de datos):
   devices          -> Inventario de equipos            (RF-01)
   events           -> Eventos Syslog recibidos          (RF-02, RF-03)
   incidents        -> Incidentes                        (RF-05)
   incident_updates -> Seguimiento/bitácora del incidente(RF-05)
   command_audit    -> Comandos de la consola + aprobación (RF-07, RF-08)
   notifications    -> Alertas enviadas Telegram/correo  (RF-09)
   audit_log        -> Auditoría general del sistema     (RNF-03)

 USO:  python -m app.database
==============================================================
"""

import sqlite3
from datetime import datetime

from app.config import DB_PATH


# ------------------------------------------------------------
# [BLOQUE 1] FECHA Y HORA ESTÁNDAR
# Todas las fechas se guardan en formato ISO 8601 con zona
# horaria, ej: 2026-10-23T14:05:09-05:00. Así se pueden
# ordenar y filtrar como texto. (RNF-03 Trazabilidad)
# ------------------------------------------------------------
def ahora() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


# ------------------------------------------------------------
# [BLOQUE 2] CONEXIÓN A LA BASE DE DATOS
# - row_factory = sqlite3.Row  -> las filas se leen como
#   diccionario: fila["nombre"] en vez de fila[1].
# - foreign_keys = ON -> SQLite respeta relaciones entre tablas.
# - journal_mode = WAL -> permite que el colector Syslog escriba
#   mientras el dashboard lee, sin bloquearse (RNF-07).
# ------------------------------------------------------------
def get_connection() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)  # crea data/ si no existe
    conexion = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
    conexion.row_factory = sqlite3.Row
    conexion.execute("PRAGMA foreign_keys = ON;")
    conexion.execute("PRAGMA journal_mode = WAL;")
    return conexion


# ------------------------------------------------------------
# [BLOQUE 3] ESQUEMA: DEFINICIÓN DE LAS TABLAS
# "IF NOT EXISTS" permite ejecutar el script muchas veces
# sin borrar datos. CHECK valida los valores permitidos
# directamente en la BD (defensa en profundidad).
# ------------------------------------------------------------
ESQUEMA_SQL = """
-- ==========================================================
-- [TABLA 1] devices · Inventario editable de equipos (RF-01)
-- ==========================================================
CREATE TABLE IF NOT EXISTS devices (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre              TEXT NOT NULL UNIQUE,          -- ej: R1-NOC
    ip                  TEXT NOT NULL UNIQUE,          -- IP desde la que envía Syslog
    marca               TEXT NOT NULL
                        CHECK (marca IN ('Cisco','Fortinet','Huawei','Otro')),
    modelo              TEXT,                          -- ej: ISR 4321
    version             TEXT,                          -- ej: IOS XE 17.9
    ubicacion           TEXT,                          -- ej: Rack 1 - Laboratorio
    estado              TEXT NOT NULL DEFAULT 'activo'
                        CHECK (estado IN ('activo','inactivo','mantenimiento')),
    es_simulado         INTEGER NOT NULL DEFAULT 0,    -- 1 = equipo de prueba (no real)
    ultimo_evento       TEXT,                          -- fecha del último Syslog recibido
    fecha_actualizacion TEXT NOT NULL                  -- última edición del registro
);

-- ==========================================================
-- [TABLA 2] events · Eventos Syslog normalizados (RF-02, RF-03)
-- Se guarda el mensaje ORIGINAL (raw) y el NORMALIZADO.
-- ==========================================================
CREATE TABLE IF NOT EXISTS events (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    recibido_en      TEXT NOT NULL,                    -- hora del colector (confiable)
    fecha_equipo     TEXT,                             -- hora que reporta el equipo
    ip_origen        TEXT NOT NULL,
    device_id        INTEGER REFERENCES devices(id) ON DELETE SET NULL,
    marca            TEXT,
    hostname         TEXT,
    facility         INTEGER,                          -- 0..23
    facility_nombre  TEXT,                             -- ej: local7
    severidad        INTEGER NOT NULL CHECK (severidad BETWEEN 0 AND 7),
    severidad_nombre TEXT,                             -- ej: critical
    mensaje          TEXT NOT NULL,
    raw              TEXT NOT NULL,                    -- texto tal cual llegó
    origen           TEXT NOT NULL
                     CHECK (origen IN ('real','simulado','importado')),
    autorizado       INTEGER NOT NULL DEFAULT 1,       -- 0 = IP fuera del inventario
    sospechoso       INTEGER NOT NULL DEFAULT 0,       -- 1 = posible inyección de prompt
    motivo_sospecha  TEXT,
    huella           TEXT,                             -- hash para deduplicar
    repeticiones     INTEGER NOT NULL DEFAULT 1        -- veces que se repitió
);

-- ==========================================================
-- [TABLA 3] incidents · Incidentes (RF-05)
-- Ciclo: abierto -> asignado -> en_progreso -> resuelto -> cerrado
-- ==========================================================
CREATE TABLE IF NOT EXISTS incidents (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    titulo         TEXT NOT NULL,
    descripcion    TEXT,
    severidad      INTEGER NOT NULL CHECK (severidad BETWEEN 0 AND 7),
    estado         TEXT NOT NULL DEFAULT 'abierto'
                   CHECK (estado IN ('abierto','asignado','en_progreso','resuelto','cerrado')),
    responsable    TEXT,
    device_id      INTEGER REFERENCES devices(id) ON DELETE SET NULL,
    event_id       INTEGER REFERENCES events(id)  ON DELETE SET NULL, -- evento que lo originó
    creado_por     TEXT NOT NULL,                  -- 'sistema' o el operador
    creado_en      TEXT NOT NULL,
    actualizado_en TEXT NOT NULL,
    cerrado_en     TEXT,
    causa_raiz     TEXT,
    solucion       TEXT
);

-- ==========================================================
-- [TABLA 4] incident_updates · Seguimiento del incidente
-- Cada cambio de estado o nota queda registrado.
-- ==========================================================
CREATE TABLE IF NOT EXISTS incident_updates (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id     INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    fecha           TEXT NOT NULL,
    autor           TEXT NOT NULL,
    estado_anterior TEXT,
    estado_nuevo    TEXT,
    nota            TEXT
);

-- ==========================================================
-- [TABLA 5] command_audit · Consola tipo PuTTY (RF-07, RF-08)
-- Flujo: propuesta -> revisión humana -> aprobación -> ejecución
-- ==========================================================
CREATE TABLE IF NOT EXISTS command_audit (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    fecha            TEXT NOT NULL,
    usuario          TEXT NOT NULL,
    device_id        INTEGER REFERENCES devices(id) ON DELETE SET NULL,
    marca            TEXT,
    comando          TEXT NOT NULL,
    clasificacion    TEXT NOT NULL
                     CHECK (clasificacion IN ('permitido','bloqueado','requiere_aprobacion')),
    estado           TEXT NOT NULL
                     CHECK (estado IN ('ejecutado_simulado','bloqueado','pendiente','aprobado','rechazado')),
    aprobado_por     TEXT,
    fecha_aprobacion TEXT,
    resultado        TEXT,
    huella_sha256    TEXT                             -- integridad del registro
);

-- ==========================================================
-- [TABLA 6] notifications · Alertas Telegram / correo (RF-09)
-- ==========================================================
CREATE TABLE IF NOT EXISTS notifications (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    fecha       TEXT NOT NULL,
    canal       TEXT NOT NULL CHECK (canal IN ('telegram','email')),
    incident_id INTEGER REFERENCES incidents(id) ON DELETE SET NULL,
    event_id    INTEGER REFERENCES events(id)    ON DELETE SET NULL,
    estado      TEXT NOT NULL
                CHECK (estado IN ('enviado','fallido','suprimido','deshabilitado')),
    detalle     TEXT
);

-- ==========================================================
-- [TABLA 7] audit_log · Auditoría general (RNF-03)
-- ==========================================================
CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    fecha      TEXT NOT NULL,
    actor      TEXT NOT NULL,       -- usuario o 'sistema'
    accion     TEXT NOT NULL,       -- ej: CREAR_EQUIPO, CERRAR_INCIDENTE
    entidad    TEXT,                -- ej: devices
    entidad_id INTEGER,
    detalle    TEXT
);

-- ==========================================================
-- [ÍNDICES] Aceleran los filtros del dashboard (RNF-07)
-- ==========================================================
CREATE INDEX IF NOT EXISTS idx_events_recibido  ON events(recibido_en);
CREATE INDEX IF NOT EXISTS idx_events_severidad ON events(severidad);
CREATE INDEX IF NOT EXISTS idx_events_device    ON events(device_id);
CREATE INDEX IF NOT EXISTS idx_events_huella    ON events(huella);
CREATE INDEX IF NOT EXISTS idx_incidents_estado ON incidents(estado);
"""


# ------------------------------------------------------------
# [BLOQUE 4] CREAR LA BASE DE DATOS
# executescript() ejecuta todo el bloque SQL de una vez.
# ------------------------------------------------------------
def init_db() -> None:
    with get_connection() as conexion:
        conexion.executescript(ESQUEMA_SQL)
    print(f"[OK] Base de datos lista en: {DB_PATH}")


# ------------------------------------------------------------
# [BLOQUE 5] AUDITORÍA GENERAL
# Función reutilizable: cualquier módulo la llama para dejar
# rastro de una acción. Ej:
#   registrar_auditoria("andres", "CREAR_EQUIPO", "devices", 4, "R1-LAB")
# ------------------------------------------------------------
def registrar_auditoria(actor: str, accion: str, entidad: str = None,
                        entidad_id: int = None, detalle: str = None,
                        conexion: sqlite3.Connection = None) -> None:
    sql = """INSERT INTO audit_log (fecha, actor, accion, entidad, entidad_id, detalle)
             VALUES (?, ?, ?, ?, ?, ?)"""
    valores = (ahora(), actor, accion, entidad, entidad_id, detalle)
    if conexion is not None:           # reutiliza una conexión abierta
        conexion.execute(sql, valores)
    else:
        with get_connection() as nueva:
            nueva.execute(sql, valores)


# ------------------------------------------------------------
# [BLOQUE 6] DATOS SIMULADOS DE EJEMPLO
# - Nombres con prefijo SIM- y es_simulado = 1.
# - IPs de DOCUMENTACIÓN (RFC 5737: 192.0.2.x, 198.51.100.x,
#   203.0.113.x). No existen en Internet ni en tu red: así
#   nunca se publican IPs reales de producción.
# - Solo se insertan si la tabla está vacía.
# ------------------------------------------------------------
EQUIPOS_SIMULADOS = [
    # nombre,        ip,             marca,      modelo,          version,           ubicacion
    ("SIM-R1-NOC",   "192.0.2.10",   "Cisco",    "ISR 4321",      "IOS XE 17.9",     "SIMULADO - Rack 1"),
    ("SIM-FW-EDGE",  "198.51.100.20","Fortinet", "FortiGate 60F", "FortiOS 7.2",     "SIMULADO - Perímetro"),
    ("SIM-SW-CORE",  "203.0.113.30", "Huawei",   "S5735-L",       "VRP V200R021",    "SIMULADO - Core"),
]


def seed_datos_simulados() -> None:
    with get_connection() as conexion:
        total = conexion.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
        if total > 0:
            print(f"[INFO] El inventario ya tiene {total} equipo(s); no se cargan simulados.")
            return
        for nombre, ip, marca, modelo, version, ubicacion in EQUIPOS_SIMULADOS:
            conexion.execute(
                """INSERT INTO devices (nombre, ip, marca, modelo, version, ubicacion,
                                        estado, es_simulado, fecha_actualizacion)
                   VALUES (?, ?, ?, ?, ?, ?, 'activo', 1, ?)""",
                (nombre, ip, marca, modelo, version, ubicacion, ahora()),
            )
        registrar_auditoria("sistema", "CARGAR_SIMULADOS", "devices",
                            detalle=f"{len(EQUIPOS_SIMULADOS)} equipos simulados",
                            conexion=conexion)
    print(f"[OK] Se cargaron {len(EQUIPOS_SIMULADOS)} equipos SIMULADOS.")


# ------------------------------------------------------------
# [BLOQUE 7] RESUMEN DE VERIFICACIÓN (evidencia)
# Muestra cada tabla con su número de registros.
# ------------------------------------------------------------
def mostrar_resumen() -> None:
    with get_connection() as conexion:
        tablas = conexion.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%' ORDER BY name"
        ).fetchall()
        print("\n=== Tablas creadas ===")
        for fila in tablas:
            n = conexion.execute(f"SELECT COUNT(*) FROM {fila['name']}").fetchone()[0]
            print(f"  - {fila['name']:<17} {n} registro(s)")

        print("\n=== Inventario actual ===")
        for d in conexion.execute("SELECT * FROM devices ORDER BY id"):
            etiqueta = "SIMULADO" if d["es_simulado"] else "REAL"
            print(f"  [{d['id']}] {d['nombre']:<12} {d['ip']:<15} {d['marca']:<9} ({etiqueta})")


# ------------------------------------------------------------
# [BLOQUE 8] PUNTO DE ENTRADA
# Se ejecuta solo con:  python -m app.database
# ------------------------------------------------------------
if __name__ == "__main__":
    init_db()
    seed_datos_simulados()
    mostrar_resumen()

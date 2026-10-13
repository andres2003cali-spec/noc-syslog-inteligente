"""
db.py - Acceso a la base de datos SQLite.

- Una conexión por petición HTTP (objeto g de Flask), cerrada al terminar.
- Todas las consultas usan parámetros (?) para evitar inyección SQL.
- init_db() crea las tablas desde schema.sql; seed_demo() carga inventario SIMULADO.
"""
import sqlite3
from datetime import datetime
from pathlib import Path

from flask import current_app, g

SCHEMA_FILE = Path(__file__).resolve().parent / "schema.sql"


def now_iso() -> str:
    """Fecha/hora local en formato 'AAAA-MM-DD HH:MM:SS' (ordenable como texto)."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def connect(path: str) -> sqlite3.Connection:
    """Abre una conexión con filas tipo diccionario y llaves foráneas activas."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")  # lecturas concurrentes con el receptor UDP
    return conn


def get_db() -> sqlite3.Connection:
    """Devuelve la conexión de la petición actual (la crea si no existe)."""
    if "db" not in g:
        g.db = connect(current_app.config["DB_PATH"])
    return g.db


def close_db(_exc=None) -> None:
    """Cierra la conexión al final de cada petición."""
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(conn: sqlite3.Connection) -> None:
    """Crea las tablas si no existen (idempotente)."""
    conn.executescript(SCHEMA_FILE.read_text(encoding="utf-8"))
    conn.commit()


# Inventario de laboratorio. TODOS los datos son SIMULADOS (IPs privadas de laboratorio).
DEMO_DEVICES = [
    # nombre, ip, marca, modelo, versión, ubicación, estado, calidad del dato
    ("R1-NOC", "192.168.50.1", "Cisco", "ISR 4331", "IOS XE 17.9 (simulado)", "Sala NOC - Rack A", "activo", "confirmado"),
    ("SW-ACC-01", "192.168.50.4", "Cisco", "Catalyst 9200", "IOS XE 17.6 (simulado)", "Piso 2 - Gabinete 1", "activo", "confirmado"),
    ("FW-EDGE", "192.168.50.2", "Fortinet", "FortiGate 60F", "FortiOS 7.2 (simulado)", "Perímetro - Rack A", "activo", "confirmado"),
    ("SW-CORE", "192.168.50.3", "Huawei", "S5735-L", "VRP V200R021 (simulado)", "Data center - Rack B", "activo", "confirmado"),
    ("AR-SUCURSAL", "192.168.60.1", "Huawei", "AR6120", "VRP V300R021 (simulado)", "Sucursal Norte", "mantenimiento", "por_verificar"),
    ("MX-RAMA", "192.168.70.1", "Cisco", "Meraki MX67", "MX 18.x (por verificar)", "Sucursal Sur", "activo", "por_verificar"),
]


def seed_demo(conn: sqlite3.Connection) -> int:
    """Carga el inventario simulado solo si la tabla está vacía. Devuelve filas insertadas."""
    count = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
    if count:
        return 0
    ts = now_iso()
    conn.executemany(
        """INSERT INTO devices (name, ip, vendor, model, os_version, location, status,
                                data_quality, is_simulated, created_at, updated_at)
           VALUES (?,?,?,?,?,?,?,?,1,?,?)""",
        [(*d, ts, ts) for d in DEMO_DEVICES],
    )
    conn.commit()
    return len(DEMO_DEVICES)

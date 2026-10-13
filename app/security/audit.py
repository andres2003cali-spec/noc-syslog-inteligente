"""
audit.py - Bitácora de auditoría encadenada con SHA-256.

Cada registro guarda el hash del registro anterior (prev_hash). Si alguien
modifica o borra una fila, la cadena deja de validar: verify_chain() lo detecta.
Esto materializa RNF-03 (trazabilidad) y el control de "integridad" de la
política Syslog.
"""
import hashlib
import json
import sqlite3

from app.db import now_iso

GENESIS = "0" * 64  # hash inicial de la cadena


def _digest(prev_hash: str, created_at: str, actor: str, action: str,
            entity: str, entity_id: str, detail: str) -> str:
    payload = json.dumps([prev_hash, created_at, actor, action, entity, entity_id, detail],
                         ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def audit(conn: sqlite3.Connection, actor: str, action: str, entity: str,
          entity_id="", detail="", commit: bool = True) -> str:
    """Registra una acción en audit_log y devuelve su hash."""
    row = conn.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
    prev_hash = row["hash"] if row else GENESIS
    created_at = now_iso()
    entity_id = str(entity_id)
    detail = detail if isinstance(detail, str) else json.dumps(detail, ensure_ascii=False)
    h = _digest(prev_hash, created_at, actor, action, entity, entity_id, detail)
    conn.execute(
        """INSERT INTO audit_log (created_at, actor, action, entity, entity_id, detail, prev_hash, hash)
           VALUES (?,?,?,?,?,?,?,?)""",
        (created_at, actor, action, entity, entity_id, detail, prev_hash, h),
    )
    if commit:
        conn.commit()
    return h


def verify_chain(conn: sqlite3.Connection) -> dict:
    """Recalcula toda la cadena. Devuelve {'ok': bool, 'total': n, 'broken_at': id|None}."""
    prev = GENESIS
    total = 0
    for r in conn.execute("SELECT * FROM audit_log ORDER BY id"):
        total += 1
        expected = _digest(prev, r["created_at"], r["actor"], r["action"], r["entity"],
                           r["entity_id"], r["detail"])
        if r["prev_hash"] != prev or r["hash"] != expected:
            return {"ok": False, "total": total, "broken_at": r["id"]}
        prev = r["hash"]
    return {"ok": True, "total": total, "broken_at": None}

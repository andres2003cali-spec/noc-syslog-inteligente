"""
==============================================================
 ARCHIVO : app/routers/auditoria.py
 PROYECTO: NOC Syslog Inteligente
 PROPÓSITO:
   Consultar la bitácora de auditoría (tabla audit_log):
   quién hizo qué, sobre qué registro y cuándo.  -> RNF-03, RF-08
     GET /api/auditoria?limite=50&actor=andres
   Es SOLO LECTURA: no existe endpoint para borrar o editar
   la auditoría (integridad de la evidencia).
==============================================================
"""

from typing import Optional

from fastapi import APIRouter, Query

from app.database import get_connection

router = APIRouter(prefix="/api/auditoria", tags=["9. Auditoría"])


# ------------------------------------------------------------
# [BLOQUE 1] LISTAR AUDITORÍA (más reciente primero)
# limite entre 1 y 500 para no saturar la respuesta (RNF-07)
# ------------------------------------------------------------
@router.get("", summary="Ver la bitácora de auditoría")
def listar_auditoria(
    limite: int = Query(50, ge=1, le=500, description="Cantidad de registros"),
    actor: Optional[str] = Query(None, description="Filtrar por usuario"),
    accion: Optional[str] = Query(None, description="Ej: CREAR_EQUIPO"),
):
    sql = "SELECT * FROM audit_log WHERE 1=1"
    parametros = []
    if actor:
        sql += " AND actor = ?"
        parametros.append(actor)
    if accion:
        sql += " AND accion = ?"
        parametros.append(accion)
    sql += " ORDER BY id DESC LIMIT ?"
    parametros.append(limite)

    with get_connection() as conexion:
        return [dict(f) for f in conexion.execute(sql, parametros).fetchall()]

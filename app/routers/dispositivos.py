"""
==============================================================
 ARCHIVO : app/routers/dispositivos.py
 PROYECTO: NOC Syslog Inteligente
 PROPÓSITO:
   Endpoints (direcciones de la API) del INVENTARIO   -> RF-01
     GET    /api/dispositivos        Listar (con filtros)
     GET    /api/dispositivos/{id}   Ver un equipo
     POST   /api/dispositivos        Crear equipo
     PUT    /api/dispositivos/{id}   Editar equipo
     DELETE /api/dispositivos/{id}   Eliminar equipo
   Cada cambio queda registrado en audit_log      -> RNF-03
==============================================================
"""

import sqlite3
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import APIRouter, Header, HTTPException, Query, status

from app.config import DEVICE_TIMEOUT_MINUTES, OPERADOR_DEFAULT
from app.database import ahora, get_connection, registrar_auditoria
from app.schemas import Dispositivo, DispositivoActualizar, DispositivoCrear

# ------------------------------------------------------------
# [BLOQUE 1] CREAR EL "ROUTER"
# prefix = todas las rutas de este archivo empiezan por
# /api/dispositivos.  tags = título del grupo en /docs.
# ------------------------------------------------------------
router = APIRouter(prefix="/api/dispositivos", tags=["1. Inventario de dispositivos"])


# ------------------------------------------------------------
# [BLOQUE 2] ¿QUIÉN HACE LA ACCIÓN?  (trazabilidad)
# El operador se envía en la cabecera HTTP "X-Operador".
# Si no se envía, se usa OPERADOR_DEFAULT del .env.
# (En v1.0 esto se reemplaza por inicio de sesión con roles.)
# ------------------------------------------------------------
def obtener_operador(x_operador: Optional[str]) -> str:
    return (x_operador or OPERADOR_DEFAULT).strip()[:50]


# ------------------------------------------------------------
# [BLOQUE 3] ESTADO DE COMUNICACIÓN CALCULADO   (HU-01)
# - Si el equipo está inactivo/mantenimiento -> ese estado.
# - Si nunca envió Syslog                    -> sin_datos
# - Si su último evento es más viejo que
#   DEVICE_TIMEOUT_MINUTES                   -> sin_comunicacion
# - En otro caso                             -> en_linea
# ------------------------------------------------------------
def calcular_estado_comunicacion(fila: sqlite3.Row) -> str:
    if fila["estado"] != "activo":
        return fila["estado"]
    if not fila["ultimo_evento"]:
        return "sin_datos"
    ultimo = datetime.fromisoformat(fila["ultimo_evento"])
    limite = timedelta(minutes=DEVICE_TIMEOUT_MINUTES)
    if datetime.now().astimezone() - ultimo > limite:
        return "sin_comunicacion"
    return "en_linea"


def fila_a_diccionario(fila: sqlite3.Row) -> dict:
    """Convierte una fila de SQLite en el formato de respuesta."""
    datos = dict(fila)
    datos["es_simulado"] = bool(datos["es_simulado"])
    datos["estado_comunicacion"] = calcular_estado_comunicacion(fila)
    return datos


def buscar_o_404(conexion: sqlite3.Connection, dispositivo_id: int) -> sqlite3.Row:
    """Busca un equipo; si no existe responde error 404."""
    fila = conexion.execute("SELECT * FROM devices WHERE id = ?", (dispositivo_id,)).fetchone()
    if fila is None:
        raise HTTPException(status_code=404, detail=f"No existe el equipo con id {dispositivo_id}")
    return fila


# ------------------------------------------------------------
# [BLOQUE 4] LISTAR EQUIPOS  ·  GET /api/dispositivos
# Filtros opcionales: ?marca=Cisco&estado=activo&buscar=R1
# SEGURIDAD: los valores van con "?" (consulta parametrizada),
# nunca pegados al texto SQL -> evita inyección SQL.
# ------------------------------------------------------------
@router.get("", response_model=List[Dispositivo], summary="Listar equipos del inventario")
def listar_dispositivos(
    marca: Optional[str] = Query(None, description="Cisco, Fortinet, Huawei u Otro"),
    estado: Optional[str] = Query(None, description="activo, inactivo o mantenimiento"),
    buscar: Optional[str] = Query(None, description="Texto en nombre, IP o ubicación"),
):
    sql = "SELECT * FROM devices WHERE 1=1"
    parametros = []
    if marca:
        sql += " AND marca = ?"
        parametros.append(marca)
    if estado:
        sql += " AND estado = ?"
        parametros.append(estado)
    if buscar:
        sql += " AND (nombre LIKE ? OR ip LIKE ? OR ubicacion LIKE ?)"
        patron = f"%{buscar}%"
        parametros += [patron, patron, patron]
    sql += " ORDER BY nombre"

    with get_connection() as conexion:
        filas = conexion.execute(sql, parametros).fetchall()
    return [fila_a_diccionario(f) for f in filas]


# ------------------------------------------------------------
# [BLOQUE 5] VER UN EQUIPO  ·  GET /api/dispositivos/{id}
# ------------------------------------------------------------
@router.get("/{dispositivo_id}", response_model=Dispositivo, summary="Ver un equipo")
def ver_dispositivo(dispositivo_id: int):
    with get_connection() as conexion:
        return fila_a_diccionario(buscar_o_404(conexion, dispositivo_id))


# ------------------------------------------------------------
# [BLOQUE 6] CREAR EQUIPO  ·  POST /api/dispositivos
# - Los datos ya llegan validados por DispositivoCrear.
# - Si el nombre o la IP ya existen -> error 409 (conflicto).
# - Se registra la acción en la auditoría.
# ------------------------------------------------------------
@router.post("", response_model=Dispositivo, status_code=status.HTTP_201_CREATED,
             summary="Registrar un equipo nuevo")
def crear_dispositivo(datos: DispositivoCrear, x_operador: Optional[str] = Header(None)):
    operador = obtener_operador(x_operador)
    with get_connection() as conexion:
        try:
            cursor = conexion.execute(
                """INSERT INTO devices (nombre, ip, marca, modelo, version, ubicacion,
                                        estado, es_simulado, fecha_actualizacion)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (datos.nombre, datos.ip, datos.marca, datos.modelo, datos.version,
                 datos.ubicacion, datos.estado, int(datos.es_simulado), ahora()),
            )
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=409,
                                detail="Ya existe un equipo con ese nombre o esa IP")
        nuevo_id = cursor.lastrowid
        tipo = "SIMULADO" if datos.es_simulado else "REAL"
        registrar_auditoria(operador, "CREAR_EQUIPO", "devices", nuevo_id,
                            f"{datos.nombre} {datos.ip} {datos.marca} ({tipo})", conexion)
        return fila_a_diccionario(buscar_o_404(conexion, nuevo_id))


# ------------------------------------------------------------
# [BLOQUE 7] EDITAR EQUIPO  ·  PUT /api/dispositivos/{id}
# exclude_unset=True -> solo toma los campos que se enviaron.
# Se guarda en auditoría qué cambió: valor anterior -> nuevo.
# fecha_actualizacion se renueva automáticamente (RF-01).
# ------------------------------------------------------------
@router.put("/{dispositivo_id}", response_model=Dispositivo, summary="Editar un equipo")
def editar_dispositivo(dispositivo_id: int, cambios: DispositivoActualizar,
                       x_operador: Optional[str] = Header(None)):
    operador = obtener_operador(x_operador)
    nuevos = cambios.model_dump(exclude_unset=True)
    if not nuevos:
        raise HTTPException(status_code=400, detail="No se envió ningún campo para cambiar")
    if "es_simulado" in nuevos:
        nuevos["es_simulado"] = int(nuevos["es_simulado"])

    with get_connection() as conexion:
        anterior = buscar_o_404(conexion, dispositivo_id)
        # Los nombres de columna vienen del modelo Pydantic (lista cerrada),
        # los VALORES van parametrizados con "?".
        columnas = ", ".join(f"{campo} = ?" for campo in nuevos)
        valores = list(nuevos.values()) + [ahora(), dispositivo_id]
        try:
            conexion.execute(
                f"UPDATE devices SET {columnas}, fecha_actualizacion = ? WHERE id = ?", valores)
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=409,
                                detail="Otro equipo ya usa ese nombre o esa IP")
        detalle = "; ".join(f"{c}: {anterior[c]} -> {v}" for c, v in nuevos.items())
        registrar_auditoria(operador, "EDITAR_EQUIPO", "devices", dispositivo_id, detalle, conexion)
        return fila_a_diccionario(buscar_o_404(conexion, dispositivo_id))


# ------------------------------------------------------------
# [BLOQUE 8] ELIMINAR EQUIPO  ·  DELETE /api/dispositivos/{id}
# Los eventos de ese equipo NO se borran (quedan como
# evidencia); su device_id pasa a nulo (ON DELETE SET NULL).
# ------------------------------------------------------------
@router.delete("/{dispositivo_id}", summary="Eliminar un equipo")
def eliminar_dispositivo(dispositivo_id: int, x_operador: Optional[str] = Header(None)):
    operador = obtener_operador(x_operador)
    with get_connection() as conexion:
        fila = buscar_o_404(conexion, dispositivo_id)
        conexion.execute("DELETE FROM devices WHERE id = ?", (dispositivo_id,))
        registrar_auditoria(operador, "ELIMINAR_EQUIPO", "devices", dispositivo_id,
                            f"{fila['nombre']} {fila['ip']}", conexion)
    return {"mensaje": f"Equipo {fila['nombre']} eliminado", "id": dispositivo_id}

"""
==============================================================
 ARCHIVO : app/main.py
 PROYECTO: NOC Syslog Inteligente
 PROPÓSITO:
   Punto de arranque de la aplicación web.
   1. Crea la aplicación FastAPI.
   2. Al iniciar, prepara la base de datos.
   3. Conecta los módulos (routers) de cada funcionalidad.

 EJECUTAR:  uvicorn app.main:app --reload --port 8000
   - app.main  = este archivo (app/main.py)
   - :app      = la variable "app" creada abajo
   - --reload  = reinicia solo al guardar cambios (desarrollo)
==============================================================
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import RedirectResponse

from app.database import ahora, get_connection, init_db, seed_datos_simulados
from app.routers import auditoria, dispositivos

VERSION = "1.0.0-dev"


# ------------------------------------------------------------
# [BLOQUE 1] CICLO DE VIDA (lifespan)
# Lo que está ANTES del "yield" corre al ENCENDER la app.
# Lo que está DESPUÉS corre al APAGARLA (Ctrl+C).
# En la Parte 3 aquí se encenderá el colector Syslog.
# ------------------------------------------------------------
@asynccontextmanager
async def ciclo_de_vida(app: FastAPI):
    print("[INICIO] Preparando base de datos...")
    init_db()
    seed_datos_simulados()
    print("[INICIO] NOC Syslog Inteligente listo -> http://127.0.0.1:8000/docs")
    yield
    print("[APAGADO] Aplicación detenida.")


# ------------------------------------------------------------
# [BLOQUE 2] CREAR LA APLICACIÓN
# title/description/version aparecen en la página /docs
# ------------------------------------------------------------
app = FastAPI(
    title="NOC Syslog Inteligente",
    description=(
        "API del NOC para inventario, eventos Syslog, incidentes y alertas.\n\n"
        "**Administración y Gestión de Redes · 2026-2** · Estudiante: Andrés Felipe Silva Garzón.\n\n"
        "Los equipos marcados como `es_simulado = true` son datos de prueba."
    ),
    version=VERSION,
    lifespan=ciclo_de_vida,
)

# ------------------------------------------------------------
# [BLOQUE 3] CONECTAR LOS MÓDULOS (ROUTERS)
# Cada router agrupa los endpoints de una funcionalidad.
# En las siguientes partes se agregan: eventos, incidentes,
# configuraciones, consola y alertas.
# ------------------------------------------------------------
app.include_router(dispositivos.router)
app.include_router(auditoria.router)


# ------------------------------------------------------------
# [BLOQUE 4] PÁGINA DE INICIO
# Por ahora redirige a la documentación interactiva.
# En la Parte 4 mostrará el dashboard.
# ------------------------------------------------------------
@app.get("/", include_in_schema=False)
def inicio():
    return RedirectResponse(url="/docs")


# ------------------------------------------------------------
# [BLOQUE 5] SALUD DEL SISTEMA  ·  GET /api/salud
# Permite verificar rápidamente que la app y la BD responden.
# Útil para monitoreo y para la marcha blanca.
# ------------------------------------------------------------
@app.get("/api/salud", tags=["0. Sistema"], summary="Verificar que el sistema funciona")
def salud():
    with get_connection() as conexion:
        total = conexion.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
    return {"estado": "ok", "version": VERSION, "hora_servidor": ahora(),
            "base_datos": "conectada", "equipos_en_inventario": total}

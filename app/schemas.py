"""
==============================================================
 ARCHIVO : app/schemas.py
 PROYECTO: NOC Syslog Inteligente
 PROPÓSITO:
   Definir la "forma" de los datos que entran y salen de la API
   y VALIDARLOS antes de que lleguen a la base de datos.
   Si alguien envía una IP inválida, una marca inexistente o
   un nombre con caracteres raros, la API responde error 422
   y no guarda nada.  -> Seguridad: validar todas las entradas.
==============================================================
"""

import ipaddress
import re
from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator

# ------------------------------------------------------------
# [BLOQUE 1] VALORES PERMITIDOS (listas cerradas)
# Literal = solo se aceptan exactamente estos textos.
# Coinciden con los CHECK de la tabla devices (database.py).
# ------------------------------------------------------------
Marca = Literal["Cisco", "Fortinet", "Huawei", "Otro"]
EstadoAdministrativo = Literal["activo", "inactivo", "mantenimiento"]

# Nombre de equipo: letras, números, punto, guion y guion bajo.
PATRON_NOMBRE = re.compile(r"^[A-Za-z0-9._-]{2,50}$")


# ------------------------------------------------------------
# [BLOQUE 2] FUNCIONES DE VALIDACIÓN REUTILIZABLES
# ------------------------------------------------------------
def _validar_nombre(valor: Optional[str]) -> Optional[str]:
    if valor is None:
        return valor
    valor = valor.strip()
    if not PATRON_NOMBRE.match(valor):
        raise ValueError("Use 2 a 50 caracteres: letras, números, '.', '-' o '_' (sin espacios)")
    return valor


def _validar_ip(valor: Optional[str]) -> Optional[str]:
    """ipaddress valida IPv4 e IPv6 reales (rechaza 300.1.1.1 o 'hola')."""
    if valor is None:
        return valor
    try:
        return str(ipaddress.ip_address(valor.strip()))
    except ValueError:
        raise ValueError("IP inválida. Ejemplo válido: 192.168.1.1")


def _limpiar_texto(valor: Optional[str]) -> Optional[str]:
    """Quita espacios sobrantes; texto vacío se guarda como nulo."""
    if valor is None:
        return valor
    valor = valor.strip()
    return valor or None


# ------------------------------------------------------------
# [BLOQUE 3] MODELO PARA CREAR UN EQUIPO  (POST)
# Field(...) = campo obligatorio.  examples = ejemplo en /docs
# ------------------------------------------------------------
class DispositivoCrear(BaseModel):
    nombre: str = Field(..., examples=["R1-LAB"], description="Nombre único del equipo")
    ip: str = Field(..., examples=["192.168.10.1"], description="IP desde la que envía Syslog")
    marca: Marca = Field(..., examples=["Cisco"])
    modelo: Optional[str] = Field(None, max_length=60, examples=["ISR 4321"])
    version: Optional[str] = Field(None, max_length=60, examples=["IOS XE 17.9"])
    ubicacion: Optional[str] = Field(None, max_length=100, examples=["Laboratorio - Rack 2"])
    estado: EstadoAdministrativo = Field("activo", examples=["activo"])
    es_simulado: bool = Field(False, description="true = equipo de prueba, false = equipo físico real")

    # Conecta cada campo con su función de validación
    _v_nombre = field_validator("nombre")(_validar_nombre)
    _v_ip = field_validator("ip")(_validar_ip)
    _v_textos = field_validator("modelo", "version", "ubicacion")(_limpiar_texto)


# ------------------------------------------------------------
# [BLOQUE 4] MODELO PARA EDITAR UN EQUIPO  (PUT)
# Todos los campos son opcionales: solo se cambian los que
# se envían (actualización parcial).
# ------------------------------------------------------------
class DispositivoActualizar(BaseModel):
    nombre: Optional[str] = None
    ip: Optional[str] = None
    marca: Optional[Marca] = None
    modelo: Optional[str] = Field(None, max_length=60)
    version: Optional[str] = Field(None, max_length=60)
    ubicacion: Optional[str] = Field(None, max_length=100)
    estado: Optional[EstadoAdministrativo] = None
    es_simulado: Optional[bool] = None

    _v_nombre = field_validator("nombre")(_validar_nombre)
    _v_ip = field_validator("ip")(_validar_ip)
    _v_textos = field_validator("modelo", "version", "ubicacion")(_limpiar_texto)


# ------------------------------------------------------------
# [BLOQUE 5] MODELO DE RESPUESTA  (lo que la API devuelve)
# estado_comunicacion se CALCULA (no se guarda):
#   en_linea | sin_comunicacion | sin_datos | inactivo | mantenimiento
# ------------------------------------------------------------
class Dispositivo(BaseModel):
    id: int
    nombre: str
    ip: str
    marca: str
    modelo: Optional[str]
    version: Optional[str]
    ubicacion: Optional[str]
    estado: str
    es_simulado: bool
    ultimo_evento: Optional[str]
    fecha_actualizacion: str
    estado_comunicacion: str

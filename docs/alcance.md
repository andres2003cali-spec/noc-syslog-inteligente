# Alcance - NOC Syslog Inteligente v0.2.0 (Corte 2, MVP)

**Estudiante:** Andrés Felipe Silva Garzón · **Asignatura:** Administración y Gestión de Redes (2026-2) · **Docente:** Ing. John Harold Pérez Calderón

## Problema

En una red con equipos de varios fabricantes (Cisco, Fortinet, Huawei), los eventos quedan dispersos en el buffer local de cada equipo, con formatos y relojes distintos. El operador se entera tarde de caídas, accesos fallidos o cambios de configuración, no hay un registro único de quién hizo qué, y no existe un procedimiento que impida que una herramienta automatizada (por ejemplo, un agente de IA) ejecute cambios sin control.

> El operador necesita detectar y registrar eventos de red para responder con trazabilidad.

## Objetivo general

Construir una aplicación web que centralice eventos Syslog multivendor, los normalice y clasifique por severidad (0–7), muestre el estado de la red, gestione incidentes con trazabilidad completa y aplique una política explícita de defensa frente a acciones no autorizadas de agentes de IA.

## Objetivos específicos

1. Mantener un inventario editable de equipos que sirva también como lista de fuentes autorizadas.
2. Recibir (UDP de laboratorio) o importar mensajes Syslog y normalizarlos (fecha, origen, fabricante, facility, severidad, mensaje).
3. Presentar un tablero con estado de equipos, eventos recientes, críticos e incidentes, con filtros por fecha, marca, equipo y severidad.
4. Gestionar incidentes: creación automática por política o manual, asignación, seguimiento y cierre con causa y resolución.
5. Generar configuraciones Syslog comentadas para Cisco IOS/IOS XE, Fortinet FortiOS y Huawei VRP, con verificación y rollback.
6. Ofrecer una consola simulada de solo lectura con lista de comandos permitidos y bloqueo auditado del resto.
7. Implementar la política inicial de defensa ante agentes de IA: logs como datos no confiables, allowlists, control de tormentas, deduplicación, RBAC y aprobación humana.

## Incluido en v0.2.0

| Función | Estado | Datos |
|---|---|---|
| Inventario CRUD con fecha de actualización y calidad del dato | Completo | Simulados |
| Importación de archivos y receptor UDP de laboratorio | Completo | Simulados |
| Normalización RFC 3164, RFC 5424, Cisco, FortiOS y Huawei VRP | Completo | Simulados |
| Tablero, filtros, exportación CSV | Completo | Simulados |
| Incidentes con SLA, seguimiento y cierre | Completo | Simulados |
| Flujo propuesta → aprobación → ejecución simulada → verificación → auditoría | Completo | Simulado |
| Plantillas Cisco / Fortinet / Huawei | Completo | Sin aplicar a equipos |
| Consola simulada con allowlist | Completo | Salidas simuladas |
| Auditoría encadenada SHA-256 y exportación JSON | Completo | — |

## Limitaciones y pendientes (Corte 3)

- No hay conexión SSH real: la ejecución de acciones aprobadas es **simulada**. En v1.0.0 se implementará un backend SSH (Netmiko/Paramiko) con allowlist de hosts y verificación de huella.
- La identidad es simulada (selector de usuario); el rol lo calcula el servidor, pero no hay inicio de sesión con contraseña ni MFA.
- No hay alertas por Telegram (se dejaron las variables preparadas en `.env.example`).
- El receptor UDP no cifra ni autentica (limitación de Syslog/UDP, RFC 5426). TLS (RFC 5425) queda para el Corte 3.
- Las plantillas son didácticas: deben contrastarse con la documentación oficial de cada versión antes de aplicarse.
- Ningún dato corresponde a una red de producción: todos los equipos, IPs y eventos son simulados y están rotulados como tales.

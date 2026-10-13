# Registro de cambios

## [0.2.0] - 2026-10-13 · MVP Corte 2
### Agregado
- Tablero web con indicadores, estado de equipos, distribución por severidad, críticos e incidentes.
- Filtros por fecha, marca, equipo, severidad, bandera y texto; exportación CSV.
- Flujo de aprobación humana: propuesta, revisión, aprobación, ejecución simulada, verificación y auditoría.
- Generador de configuraciones Syslog comentadas para Cisco IOS/IOS XE, Fortinet FortiOS y Huawei VRP.
- Consola tipo PuTTY simulada, solo lectura, con allowlist y bloqueo auditado.
- Política de defensa ante agentes de IA: inyección de prompt, fuentes no autorizadas, secretos, tormentas, fuera de horario, fuerza bruta, RBAC.
- Auditoría encadenada SHA-256 con verificación y exportación JSON.
- 35 pruebas automatizadas y documentación (alcance, requisitos, historias, arquitectura, políticas, pruebas).

## [0.1.0] - 2026-10-13 · Alfa
### Agregado
- Estructura del proyecto, configuración por entorno y modelo de datos SQLite.
- API de inventario (CRUD) con inventario simulado inicial.
- Parser Syslog multivendor, tubería de ingesta, receptor UDP de laboratorio e incidentes por API.

# Política Syslog inicial - v0.2.0

| Control | Decisión en el laboratorio | Implementación |
|---|---|---|
| Fuentes autorizadas | Solo equipos registrados en el inventario | `ingest.find_device()`; lo demás queda con bandera `fuente_no_autorizada`, sin incidente operativo |
| Hora coherente | NTP en todos los equipos, zona horaria America/Bogota | Plantillas incluyen `ntp server` / `ntp-service` / `config system ntp` y marcas de tiempo con milisegundos |
| Umbral por fabricante | Enviar severidades 0–4 (warnings) al colector; 5–7 quedan en el buffer local | Generador con severidad configurable |
| Severidad → acción | 0–1: P1 (SLA 1 h) · 2: P2 (4 h) · 3: P3 (8 h) · 4–7: solo registro | `incidents/service.py::priority_for` y `NOC_INCIDENT_MAX_SEVERITY=3` |
| Accesos y cambios | Registrar login exitoso/fallido y cada comando de configuración | Cisco `archive log config` + `login on-failure log`; FortiOS `eventfilter`; reglas de detección en `policy.py` |
| Fuera de horario | Cambios entre 19:00 y 07:00 abren incidente P2 | `NOC_BUSINESS_HOURS_START/END` |
| Fuerza bruta | ≥ 5 fallos de autenticación en 5 minutos por equipo | Incidente "Múltiples fallos de autenticación" |
| Tormentas | Máximo 60 eventos por minuto por fuente; deduplicación de 60 s | `RateLimiter`, `signature`, `repeat_count` |
| Transporte | UDP solo en laboratorio aislado; TCP/TLS cuando el equipo lo soporte | Advertencias del generador; TLS (RFC 5425) en Corte 3 |
| Datos sensibles | No almacenar contraseñas, tokens ni comunidades SNMP | `mask_secrets()` antes de guardar |
| Integridad | Auditoría encadenada con SHA-256 | `security/audit.py::verify_chain` |
| Retención | Laboratorio: sin borrado automático; propuesta Corte 3: 90 días en línea + respaldo semanal | Pendiente de implementar rotación |
| Acceso por rol | lector, operador, administrador, agente | `policy.PERMISSIONS` |
| Prueba periódica | Escenarios del tablero y `pytest` antes de cada versión | `tests/` |

# Requisitos - NOC Syslog Inteligente v0.2.0

Prioridad MoSCoW: **M** = debe (Must), **S** = debería (Should), **C** = podría (Could), **W** = no se hará aún (Won't, Corte 3).

## Requisitos funcionales

| ID | Requisito | Prioridad | Criterio de aceptación | Prueba |
|---|---|---|---|---|
| RF-01 | Registrar, editar y eliminar equipos (nombre, IP, marca, modelo, versión, ubicación, estado, fecha de actualización) | M | Un equipo nuevo aparece en la tabla; al editarlo cambia `updated_at`; IP o marca inválida se rechaza | `test_devices.py::test_crud_completo`, `test_validaciones` |
| RF-02 | Recibir mensajes Syslog por UDP de laboratorio o importarlos desde archivo/texto | M | Un archivo `.log` de muestra se importa y reporta recibidas, almacenadas, duplicadas e inválidas | `test_importa_archivo_de_muestra` |
| RF-03 | Normalizar fecha, origen, fabricante, facility, severidad 0–7 y mensaje; rechazar líneas no Syslog | M | PRI 34 → facility 4, severidad 2; `%LINK-3-UPDOWN` → severidad 3; texto libre se rechaza | `test_parser.py` |
| RF-04 | Tablero con estado de equipos, eventos recientes, críticos e incidentes; filtros por fecha, marca, equipo y severidad | M | Filtro Cisco + severidad ≤ 3 sobre el dataset de muestra devuelve exactamente 2 eventos | `test_hu02_filtro_por_marca_y_severidad` |
| RF-05 | Crear (automático o manual), asignar, actualizar y cerrar incidentes | M | Ciclo abierto → asignado → en progreso → resuelto → cerrado; cerrar exige causa y resolución | `test_hu03_ciclo_de_vida_del_incidente` |
| RF-06 | Generar configuraciones Syslog comentadas para Cisco, Fortinet y Huawei | M | La plantilla usa la IP y la severidad elegidas, trae comentarios, verificación, rollback y advertencia de versión | `test_tools.py::test_plantilla_*` |
| RF-07 | Consola tipo PuTTY simulada, solo lectura, con comandos permitidos y bloqueados | M | `show version` se permite; `configure terminal`, `reload`, encadenamientos y comandos IOS en ROMMON se bloquean y auditan | `test_consola_*` |
| RF-08 | Conservar auditoría y exportar evidencia | M | Toda acción relevante queda en `audit_log` con hash encadenado; la alteración de un registro se detecta | `test_auditoria_integra_y_deteccion_de_alteracion` |
| RF-09 | Flujo de acción con aprobación humana (propuesta → revisión → aprobación → ejecución → verificación → auditoría) | M | Sin aprobación no hay ejecución; quien propone no aprueba; lo bloqueado no se aprueba | `test_flujo_completo_con_aprobacion_humana` |
| RF-10 | Política de defensa ante agentes de IA (inyección, tormentas, fuentes, secretos, horario, fuerza bruta) | M | Cada escenario de prueba produce la bandera e incidente esperados | `test_security.py` |
| RF-11 | Generador de eventos sintéticos por escenario | S | Cada escenario está rotulado como simulado y atraviesa la misma tubería que un evento real | Tablero → "Generar eventos de prueba" |
| RF-12 | Exportar eventos filtrados a CSV | C | El CSV respeta el filtro y neutraliza fórmulas de Excel | `test_csv_export` |
| RF-13 | Alertas por Telegram | W | — | Corte 3 |
| RF-14 | Gestor SSH real por backend autorizado | W | — | Corte 3 |

## Requisitos no funcionales

| ID | Requisito | Cómo se cumple en v0.2.0 |
|---|---|---|
| RNF-01 Seguridad | Secretos fuera del código | `.env` (excluido por `.gitignore`), `.env.example` sin valores; enmascarado de contraseñas y tokens en los logs |
| RNF-02 Usabilidad | Navegación comprensible sin manual extenso | Una sola página con pestañas, textos de ayuda y mensajes de error que indican cómo corregir |
| RNF-03 Trazabilidad | Cada evento e interacción tiene fecha y actor | `received_at`, `event_time`, `incident_updates`, `command_audit`, `audit_log` con usuario |
| RNF-04 Confiabilidad | Errores controlados y bitácora | Validación de entradas, respuestas JSON de error, `logs/app.log` rotado |
| RNF-05 Portabilidad | Instalación documentada desde cero | README con pasos para Windows y Linux; solo Python 3.10+ y tres dependencias |
| RNF-06 Mantenibilidad | Módulos y comentarios útiles | Paquetes `collector`, `incidents`, `console`, `configgen`, `security`, `api`, `web` |
| RNF-07 Rendimiento | El tablero no se bloquea con el volumen de prueba | Límite de 60 eventos/min por fuente, deduplicación, índices SQLite, consultas paginadas (máx. 500) |
| RNF-08 Recuperación | Copia y procedimiento de rollback | Base SQLite en un archivo copiable; `python run.py --reset`; etiquetas Git `v0.1.0` y `v0.2.0` para volver a una versión estable |

# Pruebas - NOC Syslog Inteligente v0.2.0

Todas las pruebas usan **datos simulados**. Ejecución: `python -m pytest -v` (base SQLite temporal, no toca `data/noc.db`).

## Pruebas funcionales (demostración en la interfaz)

| ID | Objetivo | Procedimiento | Resultado esperado | Resultado obtenido | Evidencia |
|---|---|---|---|---|---|
| PF-01 | Inventario editable (RF-01, HU-01) | Inventario → registrar `R2-LAB` 192.168.50.20, Cisco; editar ubicación | Aparece en la tabla con fecha de actualización; MX-RAMA figura "sin comunicación" | Cumple | E04 |
| PF-02 | Tablero (RF-04) | Tablero tras generar escenarios | Indicadores, estado por equipo, barras 0–7, críticos e incidentes abiertos | Cumple | E05 |
| PF-03 | Importación Syslog (RF-02, RF-03) | Eventos → importar `data/samples/syslog_simulado_lab.log` | 25 recibidas, 24 almacenadas, 1 inválida rechazada, banderas de seguridad | Cumple | E06 |
| PF-04 | Filtro (HU-02) | Marca Cisco + "Hasta severidad 3" | Solo eventos Cisco con severidad ≤ 3 y total actualizado | Cumple | E07 |
| PF-05 | Ciclo de incidente (HU-03) | Asignar, en progreso, resuelto, cerrar con causa y resolución | Estado cerrado, fecha de cierre y bitácora completa | Cumple | E08 |
| PF-06 | Plantillas (HU-04) | Configuraciones → las tres marcas, 192.168.50.10, umbral 4 | Tres plantillas comentadas con verificación, rollback y advertencias | Cumple | E09 |
| PF-07 | Consola (RF-07) | `show version`, `configure terminal`, `show version; reload` | Primero permitido con salida simulada; los demás BLOQUEADO y auditados | Cumple | E10 |
| PF-08 | Inyección de prompt (HU-06) | Tablero → "Inyección de prompt" | Evento con bandera, incidente seguridad-IA, ninguna acción `reload` | Cumple | E11 |
| PF-09 | Aprobación humana (HU-07) | Admin aprueba propuesta del agente; operador ejecuta y verifica | Estados pendiente → aprobada → ejecutada → verificada | Cumple | E11b |
| PF-10 | Tormenta (HU-08) | Tablero → "Tormenta de eventos" | ~60 aceptados, resto descartado, un solo incidente | Cumple | Tablero |
| PF-11 | Auditoría (RF-08) | Auditoría → verificar cadena, exportar JSON | "Cadena íntegra" y archivo descargado | Cumple | E12 |
| PF-12 | Pruebas automatizadas | `python -m pytest -v` | 35 pruebas aprobadas | 35 passed | E12 |

## Pruebas automatizadas (pytest)

| # | Archivo | Prueba | Resultado |
|---|---|---|---|
| 1 | `test_devices.py` | `test_inventario_simulado_inicial` | PASSED |
| 2 | `test_devices.py` | `test_crud_completo` | PASSED |
| 3 | `test_devices.py` | `test_validaciones` | PASSED |
| 4 | `test_devices.py` | `test_hu01_sin_comunicacion_y_en_linea` | PASSED |
| 5 | `test_events_incidents.py` | `test_importa_archivo_de_muestra` | PASSED |
| 6 | `test_events_incidents.py` | `test_hu02_filtro_por_marca_y_severidad` | PASSED |
| 7 | `test_events_incidents.py` | `test_hu03_ciclo_de_vida_del_incidente` | PASSED |
| 8 | `test_events_incidents.py` | `test_incidente_manual_desde_evento` | PASSED |
| 9 | `test_events_incidents.py` | `test_deduplicacion` | PASSED |
| 10 | `test_events_incidents.py` | `test_csv_export` | PASSED |
| 11 | `test_parser.py` | `test_pri_decodifica_facility_y_severidad` | PASSED |
| 12 | `test_parser.py` | `test_cisco_usa_severidad_del_mnemonico` | PASSED |
| 13 | `test_parser.py` | `test_fortinet_clave_valor` | PASSED |
| 14 | `test_parser.py` | `test_huawei_vrp` | PASSED |
| 15 | `test_parser.py` | `test_rfc5424` | PASSED |
| 16 | `test_parser.py` | `test_lineas_invalidas_se_rechazan` | PASSED |
| 17 | `test_security.py` | `test_inyeccion_de_prompt_no_altera_la_politica` | PASSED |
| 18 | `test_security.py` | `test_secretos_enmascarados` | PASSED |
| 19 | `test_security.py` | `test_fuente_no_autorizada_queda_en_cuarentena` | PASSED |
| 20 | `test_security.py` | `test_tormenta_de_eventos_limitada` | PASSED |
| 21 | `test_security.py` | `test_cambio_fuera_de_horario_por_cuenta_de_agente` | PASSED |
| 22 | `test_security.py` | `test_fuerza_bruta` | PASSED |
| 23 | `test_security.py` | `test_agente_no_puede_aprobar_ni_usar_consola` | PASSED |
| 24 | `test_security.py` | `test_flujo_completo_con_aprobacion_humana` | PASSED |
| 25 | `test_security.py` | `test_quien_propone_no_aprueba` | PASSED |
| 26 | `test_security.py` | `test_comando_peligroso_bloqueado` | PASSED |
| 27 | `test_security.py` | `test_auditoria_integra_y_deteccion_de_alteracion` | PASSED |
| 28 | `test_security.py` | `test_lector_solo_lee` | PASSED |
| 29 | `test_security.py` | `test_cabeceras_de_seguridad_y_xss_como_dato` | PASSED |
| 30 | `test_tools.py` | `test_plantilla_cisco` | PASSED |
| 31 | `test_tools.py` | `test_plantilla_fortinet` | PASSED |
| 32 | `test_tools.py` | `test_plantilla_huawei` | PASSED |
| 33 | `test_tools.py` | `test_validacion_y_advertencias` | PASSED |
| 34 | `test_tools.py` | `test_consola_permite_consultas` | PASSED |
| 35 | `test_tools.py` | `test_consola_bloquea_cambios_encadenamiento_y_modo` | PASSED |

## Pruebas de seguridad incluidas

Inyección de prompt indirecta, abuso de herramientas por el agente, escalada sin aprobación, separación de funciones, comandos destructivos y encadenados, alucinación operacional (ROMMON, marca incorrecta), secretos en logs, fuente no autorizada, tormenta de eventos, cuenta de servicio fuera de horario, fuerza bruta, alteración de la auditoría, XSS y cabeceras CSP. Ver [`politica_defensa_ia.md`](politica_defensa_ia.md).

## Prueba de volumen (RNF-07)

El escenario "Tormenta de eventos" envía 150 mensajes en un instante desde `SW-ACC-01`. Con el límite de 60 eventos/minuto se aceptan 60, se descartan 90 y se genera **un solo** incidente de tormenta; el tablero sigue respondiendo.

## Recuperación (RNF-08)

1. Copia de seguridad: copiar `data/noc.db` (con la aplicación detenida).
2. Restauración: reemplazar el archivo y reiniciar.
3. Reinicio limpio: `python run.py --reset`.
4. Volver a una versión estable del código: `git checkout v0.2.0`.

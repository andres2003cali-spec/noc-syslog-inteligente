# Arquitectura y flujo - NOC Syslog Inteligente v0.2.0

Las imágenes están en [`docs/diagramas/`](diagramas/). Los diagramas en Mermaid se ven directamente en GitHub.

## Arquitectura de referencia

```mermaid
flowchart LR
    subgraph Equipos["Equipos (SIMULADOS en v0.2.0)"]
        C[Cisco IOS XE]
        F[FortiGate]
        H[Huawei VRP]
    end
    C & F & H -- "Syslog UDP 5514 (lab)" --> U[Receptor UDP<br>collector/udp_listener.py]
    A[Archivo .log / simulador] --> I
    U --> I[Tubería de ingesta<br>collector/ingest.py]
    I --> P[Parser<br>RFC 3164/5424 · Cisco · FortiOS · VRP]
    I --> S[Política de seguridad<br>security/policy.py]
    I --> N[Incidentes<br>incidents/service.py]
    I & N --> DB[(SQLite<br>data/noc.db)]
    DB --> API[API REST Flask<br>app/api/*]
    API --> W[Dashboard HTML/CSS/JS]
    W --> G[Generador de plantillas]
    W --> K[Consola simulada<br>allowlist + auditoría]
    W --> R[Aprobaciones<br>humano en el circuito]
```

## Flujo lógico de un evento

```mermaid
flowchart TD
    E[1. Ingreso: UDP, archivo o simulador] --> V{2. Validación<br>formato Syslog · tamaño · caracteres}
    V -- inválido --> X[Rechazado y contado]
    V -- válido --> M[3. Protección: enmascarar secretos,<br>detectar inyección, cuentas de servicio]
    M --> Q{4. Control de tormenta<br>≤ 60 eventos/min por fuente}
    Q -- excedido --> T[Descartado + 1 incidente de tormenta]
    Q -- ok --> D{Duplicado en 60 s?}
    D -- sí --> DR[repeat_count + 1]
    D -- no --> G[(Guardar evento)]
    G --> PO{5. Política}
    PO -- inyección --> SI[Incidente seguridad-IA]
    PO -- fuente no inventariada --> CU[Cuarentena + incidente seguridad]
    PO -- cambio fuera de horario --> FH[Incidente seguridad P2]
    PO -- ≥5 fallos de login en 5 min --> FB[Incidente fuerza bruta]
    PO -- severidad 0-3 --> OP[Incidente operativo P1-P3]
    OP -- severidad 0-2 --> PR[6. Agente simulado PROPONE diagnóstico<br>de una tabla fija]
    PR --> HR[Revisión humana] --> AP[Aprobación admin ≠ proponente]
    AP --> EX[Ejecución autorizada SIMULADA] --> VE[Verificación] --> AU[(7. Auditoría SHA-256)]
```

## Módulos

| Carpeta | Responsabilidad |
|---|---|
| `app/collector/` | Parser, tubería de ingesta, receptor UDP y simulador de escenarios |
| `app/incidents/` | Reglas de prioridad, SLA, transiciones y bitácora |
| `app/security/` | Política de defensa ante IA, RBAC, allowlists, auditoría encadenada |
| `app/configgen/` | Plantillas Cisco / Fortinet / Huawei con verificación y rollback |
| `app/console/` | Consola tipo PuTTY simulada, de solo lectura |
| `app/api/` | Endpoints REST (blueprints de Flask) |
| `app/web/` | Interfaz de una sola página (HTML, CSS, JavaScript sin frameworks) |
| `tests/` | 35 pruebas automatizadas con pytest |

## Decisiones de diseño

| Decisión | Valor | Justificación | Riesgo | Validación |
|---|---|---|---|---|
| Lenguaje y framework | Python 3 + Flask | Curva de aprendizaje baja, biblioteca estándar suficiente | Servidor de desarrollo no apto para producción | Corte 3: Waitress/Gunicorn detrás de proxy |
| Base de datos | SQLite (WAL) | Un solo archivo, sin instalación, respaldo por copia | Concurrencia limitada | Prueba de tormenta de 150 eventos |
| Puerto Syslog | UDP 5514 en 127.0.0.1 | 514 requiere privilegios; laboratorio aislado | Sin cifrado ni confirmación de entrega | Documentado; TLS en Corte 3 |
| Identidad | Usuario elegido en la interfaz, rol calculado en el servidor | Demuestra RBAC sin gestionar contraseñas | No es autenticación real | Pruebas 403 por rol |
| Agente de IA | Simulado y basado en reglas, solo propone | Demuestra el flujo seguro sin depender de un modelo externo | No representa un LLM real | `test_inyeccion_de_prompt_no_altera_la_politica` |

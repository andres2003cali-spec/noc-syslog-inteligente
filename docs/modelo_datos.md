# Modelo de datos (SQLite) - v0.2.0

Definición completa y comentada en [`app/schema.sql`](../app/schema.sql).

```mermaid
erDiagram
    devices ||--o{ events : "origina"
    devices ||--o{ incidents : "afecta"
    events }o--o| incidents : "se vincula a"
    incidents ||--o{ incident_updates : "seguimiento"
    incidents ||--o{ action_proposals : "propuestas"
    devices ||--o{ action_proposals : "objetivo"
    devices ||--o{ command_audit : "consola"
    devices {
        int id PK
        text name UK
        text ip UK
        text vendor
        text model
        text os_version
        text location
        text status
        text data_quality
        int is_simulated
        text last_seen
        text updated_at
    }
    events {
        int id PK
        text event_time
        text received_at
        int device_id FK
        int facility
        int severity
        text app_name
        text message
        text origin_label
        int authorized
        text flags
        int repeat_count
        int incident_id FK
    }
    incidents {
        int id PK
        text title
        int severity
        text priority
        text category
        text status
        text assignee
        text sla_due
        text cause
        text resolution
        int event_id
        text closed_at
    }
    action_proposals {
        int id PK
        text command
        text proposed_by
        text status
        text policy_check
        text reviewed_by
        text execution_result
        text verification
    }
    command_audit {
        int id PK
        text actor
        text role
        text command
        text decision
        text reason
        text output_hash
    }
    audit_log {
        int id PK
        text actor
        text action
        text entity
        text detail
        text prev_hash
        text hash
    }
```

| Tabla | Propósito |
|---|---|
| `devices` | Inventario y lista de fuentes autorizadas. `data_quality` separa dato confirmado de dato por verificar; `is_simulated` rotula el laboratorio. |
| `events` | Eventos normalizados. `flags` guarda las banderas de seguridad; `signature` y `repeat_count` implementan la deduplicación. |
| `incidents` | Incidentes con prioridad P1–P4, SLA, responsable, causa y resolución. `signature` evita incidentes duplicados. |
| `incident_updates` | Bitácora de seguimiento de cada incidente. |
| `action_proposals` | Flujo propuesta → revisión → aprobación → ejecución → verificación. |
| `command_audit` | Cada comando escrito en la consola, permitido o bloqueado, con hash SHA-256 de la salida. |
| `audit_log` | Auditoría general encadenada (cada fila guarda el hash de la anterior). |

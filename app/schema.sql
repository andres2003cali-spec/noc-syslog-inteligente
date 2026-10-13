-- =====================================================================
-- schema.sql - Modelo de datos del NOC Syslog Inteligente v0.2.0 (SQLite)
-- Tablas: devices, events, incidents, incident_updates,
--         action_proposals, command_audit, audit_log
-- =====================================================================
PRAGMA foreign_keys = ON;

-- Inventario de equipos (RF-01). is_simulated = 1 indica dato de laboratorio.
CREATE TABLE IF NOT EXISTS devices (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT    NOT NULL UNIQUE,              -- hostname, ej. R1-NOC
    ip            TEXT    NOT NULL UNIQUE,              -- IPv4 de gestión
    vendor        TEXT    NOT NULL CHECK (vendor IN ('Cisco','Fortinet','Huawei','Otro')),
    model         TEXT    NOT NULL DEFAULT '',
    os_version    TEXT    NOT NULL DEFAULT '',          -- SO / versión (IOS XE, FortiOS, VRP)
    location      TEXT    NOT NULL DEFAULT '',
    status        TEXT    NOT NULL DEFAULT 'activo'
                  CHECK (status IN ('activo','inactivo','mantenimiento')),
    data_quality  TEXT    NOT NULL DEFAULT 'confirmado'
                  CHECK (data_quality IN ('confirmado','por_verificar')),
    is_simulated  INTEGER NOT NULL DEFAULT 1,
    last_seen     TEXT,                                 -- último evento recibido (ISO 8601)
    created_at    TEXT    NOT NULL,
    updated_at    TEXT    NOT NULL                      -- fecha de actualización (RF-01)
);

-- Eventos Syslog normalizados (RF-02, RF-03)
CREATE TABLE IF NOT EXISTS events (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    received_at    TEXT    NOT NULL,                    -- hora de llegada al colector
    event_time     TEXT    NOT NULL,                    -- hora reportada por el equipo
    device_id      INTEGER REFERENCES devices(id) ON DELETE SET NULL,
    source         TEXT    NOT NULL,                    -- IP u hostname de origen
    hostname       TEXT    NOT NULL DEFAULT '',
    vendor         TEXT    NOT NULL DEFAULT 'Desconocido',
    facility       INTEGER NOT NULL CHECK (facility BETWEEN 0 AND 23),
    severity       INTEGER NOT NULL CHECK (severity BETWEEN 0 AND 7),
    app_name       TEXT    NOT NULL DEFAULT '',          -- tag / mnemónico (ej. %LINK-3-UPDOWN)
    message        TEXT    NOT NULL,                    -- mensaje saneado (secretos enmascarados)
    raw            TEXT    NOT NULL,                    -- línea original saneada
    fmt            TEXT    NOT NULL DEFAULT 'desconocido', -- rfc5424, rfc3164, cisco, fortinet, huawei
    origin_label   TEXT    NOT NULL DEFAULT 'simulado' CHECK (origin_label IN ('simulado','real')),
    ingest_channel TEXT    NOT NULL DEFAULT 'importacion', -- importacion, udp, simulador, api
    authorized     INTEGER NOT NULL DEFAULT 1,           -- 0 = fuente fuera del inventario
    flags          TEXT    NOT NULL DEFAULT '',          -- banderas de seguridad separadas por coma
    repeat_count   INTEGER NOT NULL DEFAULT 1,           -- deduplicación
    signature      TEXT    NOT NULL DEFAULT '',          -- huella para deduplicar
    incident_id    INTEGER REFERENCES incidents(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_events_time ON events(event_time);
CREATE INDEX IF NOT EXISTS idx_events_sev  ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_dev  ON events(device_id);
CREATE INDEX IF NOT EXISTS idx_events_sig  ON events(signature, received_at);

-- Incidentes (RF-05)
CREATE TABLE IF NOT EXISTS incidents (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    title         TEXT    NOT NULL,
    description   TEXT    NOT NULL DEFAULT '',
    device_id     INTEGER REFERENCES devices(id) ON DELETE SET NULL,
    event_id      INTEGER,                              -- evento original que lo originó
    severity      INTEGER NOT NULL CHECK (severity BETWEEN 0 AND 7),
    priority      TEXT    NOT NULL CHECK (priority IN ('P1','P2','P3','P4')),
    category      TEXT    NOT NULL DEFAULT 'operacion',  -- operacion, seguridad, seguridad-ia
    status        TEXT    NOT NULL DEFAULT 'abierto'
                  CHECK (status IN ('abierto','asignado','en_progreso','resuelto','cerrado')),
    assignee      TEXT    NOT NULL DEFAULT '',
    created_by    TEXT    NOT NULL DEFAULT 'sistema',
    sla_due       TEXT    NOT NULL,                     -- vencimiento del SLA
    cause         TEXT    NOT NULL DEFAULT '',
    resolution    TEXT    NOT NULL DEFAULT '',
    signature     TEXT    NOT NULL DEFAULT '',          -- evita incidentes duplicados
    event_count   INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT    NOT NULL,
    updated_at    TEXT    NOT NULL,
    closed_at     TEXT
);

-- Seguimiento (bitácora) de cada incidente
CREATE TABLE IF NOT EXISTS incident_updates (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id  INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    actor        TEXT    NOT NULL,
    action       TEXT    NOT NULL,                      -- creado, asignado, nota, estado, cerrado
    note         TEXT    NOT NULL DEFAULT '',
    created_at   TEXT    NOT NULL
);

-- Propuestas de acción: flujo propuesta -> revisión humana -> aprobación -> ejecución -> verificación
CREATE TABLE IF NOT EXISTS action_proposals (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id      INTEGER REFERENCES incidents(id) ON DELETE SET NULL,
    device_id        INTEGER REFERENCES devices(id) ON DELETE SET NULL,
    command          TEXT    NOT NULL,
    rationale        TEXT    NOT NULL DEFAULT '',
    proposed_by      TEXT    NOT NULL,                  -- operador o 'agente-ia-simulado'
    status           TEXT    NOT NULL DEFAULT 'pendiente'
                     CHECK (status IN ('pendiente','aprobada','rechazada','bloqueada','ejecutada','verificada')),
    policy_check     TEXT    NOT NULL DEFAULT '',        -- resultado de la validación de política
    reviewed_by      TEXT    NOT NULL DEFAULT '',
    reviewed_at      TEXT,
    review_note      TEXT    NOT NULL DEFAULT '',
    execution_result TEXT    NOT NULL DEFAULT '',
    executed_at      TEXT,
    verification     TEXT    NOT NULL DEFAULT '',
    verified_by      TEXT    NOT NULL DEFAULT '',
    verified_at      TEXT,
    created_at       TEXT    NOT NULL
);

-- Auditoría de la consola (HU-05): quién, qué, cuándo, equipo, decisión y resultado
CREATE TABLE IF NOT EXISTS command_audit (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at   TEXT    NOT NULL,
    actor        TEXT    NOT NULL,
    role         TEXT    NOT NULL,
    device_id    INTEGER REFERENCES devices(id) ON DELETE SET NULL,
    profile      TEXT    NOT NULL,                      -- cisco, fortinet, huawei, rommon
    command      TEXT    NOT NULL,
    decision     TEXT    NOT NULL CHECK (decision IN ('permitido','bloqueado')),
    reason       TEXT    NOT NULL DEFAULT '',
    output_hash  TEXT    NOT NULL DEFAULT ''             -- SHA-256 de la salida (evidencia)
);

-- Auditoría general encadenada con hash (integridad, RF-08 / RNF-03)
CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  TEXT    NOT NULL,
    actor       TEXT    NOT NULL,
    action      TEXT    NOT NULL,
    entity      TEXT    NOT NULL,
    entity_id   TEXT    NOT NULL DEFAULT '',
    detail      TEXT    NOT NULL DEFAULT '',
    prev_hash   TEXT    NOT NULL,
    hash        TEXT    NOT NULL
);

# NOC Syslog Inteligente

Aplicación NOC (Network Operations Center) que recibe eventos **Syslog** de equipos
Cisco, Fortinet y Huawei, los clasifica por severidad (0–7), genera incidentes y
alertas, y aplica una política de defensa frente a acciones de agentes de IA.

- **Asignatura:** Administración y Gestión de Redes · Periodo 2026-2
- **Docente:** Ing. John Harold Pérez Calderón
- **Estudiante:** Andrés Felipe Silva Garzón
- **Stack:** Python 3.12 · FastAPI · SQLite · HTML/CSS/JS

> Estado: en construcción (Parte 1 – estructura y modelo de datos).
> El README completo se termina en la Parte 8.

## Instalación rápida (Windows)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
python -m app.database
```

## Seguridad
- El archivo `.env` (tokens y contraseñas) **no** se sube a GitHub.
- Los equipos de ejemplo usan IPs de documentación (RFC 5737) y están marcados como **SIMULADO**.

"""Configuración común de pruebas: base SQLite temporal y cliente HTTP de Flask."""
from pathlib import Path

import pytest

from app import create_app
from app.collector.ingest import RATE_LIMITER

SAMPLE = Path(__file__).resolve().parent.parent / "data" / "samples" / "syslog_simulado_lab.log"
OP = {"X-NOC-User": "operador.demo"}
OP2 = {"X-NOC-User": "operador2.demo"}
ADMIN = {"X-NOC-User": "admin.demo"}
READER = {"X-NOC-User": "lector.demo"}
AGENT = {"X-NOC-User": "agente-ia-simulado"}


@pytest.fixture()
def app(tmp_path):
    RATE_LIMITER.reset()
    return create_app({"DB_PATH": str(tmp_path / "test.db"), "TESTING": True})


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def sample_text():
    return SAMPLE.read_text(encoding="utf-8")


def ingest(client, text, headers=OP):
    r = client.post("/api/events/import", json={"text": text}, headers=headers)
    assert r.status_code == 200, r.json
    return r.json

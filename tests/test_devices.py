"""Pruebas del inventario (RF-01, HU-01) y del control de acceso por rol."""
from tests.conftest import ADMIN, OP, READER, ingest

NEW = {"name": "R2-LAB", "ip": "192.168.50.20", "vendor": "Cisco", "model": "ISR 1100",
       "os_version": "IOS XE 17.9", "location": "Lab", "status": "activo"}


def test_inventario_simulado_inicial(client):
    devs = client.get("/api/devices").json
    assert len(devs) == 6 and all(d["is_simulated"] == 1 for d in devs)


def test_crud_completo(client):
    r = client.post("/api/devices", json=NEW, headers=OP)
    assert r.status_code == 201
    did = r.json["id"]
    before = client.get(f"/api/devices/{did}").json["updated_at"]
    assert client.put(f"/api/devices/{did}", json={**NEW, "location": "Rack C"}, headers=OP).status_code == 200
    after = client.get(f"/api/devices/{did}").json
    assert after["location"] == "Rack C" and after["updated_at"] >= before
    assert client.delete(f"/api/devices/{did}", headers=OP).status_code == 403     # operador no borra
    assert client.delete(f"/api/devices/{did}", headers=ADMIN).status_code == 200


def test_validaciones(client):
    assert client.post("/api/devices", json={**NEW, "ip": "300.1.1.1"}, headers=OP).status_code == 400
    assert client.post("/api/devices", json={**NEW, "vendor": "Juniper"}, headers=OP).status_code == 400
    assert client.post("/api/devices", json={**NEW, "name": "R1-NOC"}, headers=OP).status_code == 409
    assert client.post("/api/devices", json=NEW, headers=READER).status_code == 403


def test_hu01_sin_comunicacion_y_en_linea(client):
    r1 = next(d for d in client.get("/api/devices").json if d["name"] == "R1-NOC")
    assert r1["comm_status"] == "sin comunicación"          # sin eventos aún
    ingest(client, "<189>1: R1-NOC: *Oct 13 10:00:00.000: %SYS-5-RESTART: System restarted")
    r1 = next(d for d in client.get("/api/devices").json if d["name"] == "R1-NOC")
    assert r1["comm_status"] == "en línea" and r1["last_seen"]

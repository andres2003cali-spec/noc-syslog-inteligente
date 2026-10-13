"""Pruebas de ingesta, filtros (HU-02) e incidentes (HU-03)."""
from tests.conftest import ADMIN, OP, ingest


def test_importa_archivo_de_muestra(client, sample_text):
    s = ingest(client, sample_text)
    assert s["recibidas"] == 25 and s["almacenadas"] == 24 and s["invalidas"] == 1
    assert s["banderas"]["posible_inyeccion_prompt"] == 1
    assert s["banderas"]["fuente_no_autorizada"] == 1


def test_hu02_filtro_por_marca_y_severidad(client, sample_text):
    ingest(client, sample_text)
    r = client.get("/api/events?vendor=Cisco&sev_max=3").json
    # Dataset conocido: Cisco con severidad 0-3 = LINK-3-UPDOWN y ENVMON-2-OVERTEMP
    assert r["total"] == 2
    assert all(e["vendor"] == "Cisco" and e["severity"] <= 3 for e in r["items"])
    assert client.get("/api/events?severity=1").json["total"] == 2   # FW alert + Huawei BOARDFAIL
    assert client.get("/api/events?date_from=2026-10-13&date_to=2026-10-13&vendor=Huawei").json["total"] == 6   # 5 VRP + 1 RFC 3164 de SW-CORE


def test_hu03_ciclo_de_vida_del_incidente(client):
    ingest(client, "<186>1: R1-NOC: *Oct 13 10:00:00.000: %ENVMON-2-OVERTEMP: Temperature critical")
    inc = client.get("/api/incidents").json[0]
    assert inc["priority"] == "P2" and inc["status"] == "abierto" and inc["event_id"]
    iid = inc["id"]
    assert client.patch(f"/api/incidents/{iid}", json={"assignee": "operador.demo"}, headers=OP).status_code == 200
    assert client.get(f"/api/incidents/{iid}").json["status"] == "asignado"
    assert client.patch(f"/api/incidents/{iid}", json={"status": "en_progreso"}, headers=OP).status_code == 200
    # No se puede cerrar desde en_progreso, ni cerrar sin causa/resolución
    assert client.patch(f"/api/incidents/{iid}", json={"status": "cerrado"}, headers=OP).status_code == 400
    assert client.patch(f"/api/incidents/{iid}", json={"status": "resuelto"}, headers=OP).status_code == 200
    assert client.patch(f"/api/incidents/{iid}", json={"status": "cerrado"}, headers=OP).status_code == 400
    r = client.patch(f"/api/incidents/{iid}", json={"status": "cerrado", "cause": "Ventilador averiado",
                                                     "resolution": "Ventilador reemplazado"}, headers=OP)
    assert r.status_code == 200
    detail = client.get(f"/api/incidents/{iid}").json
    assert detail["closed_at"] and len(detail["updates"]) >= 5 and detail["events"]
    assert client.patch(f"/api/incidents/{iid}", json={"note": "x"}, headers=OP).status_code == 400


def test_incidente_manual_desde_evento(client):
    ingest(client, "<188>1: R1-NOC: *Oct 13 10:00:00.000: %SYS-4-WARN: Warning de prueba")
    ev = client.get("/api/events").json["items"][0]
    r = client.post("/api/incidents", json={"event_id": ev["id"]}, headers=OP)
    assert r.status_code == 201
    assert client.post("/api/incidents", json={"event_id": ev["id"]}, headers=OP).status_code == 409


def test_deduplicacion(client):
    line = "<187>1: R1-NOC: *Oct 13 10:00:00.000: %LINK-3-UPDOWN: Interface Gi0/0/1, changed state to down"
    s = ingest(client, "\n".join([line] * 5))
    assert s["almacenadas"] == 1 and s["duplicadas"] == 4
    ev = client.get("/api/events").json["items"][0]
    assert ev["repeat_count"] == 5
    assert len(client.get("/api/incidents").json) == 1


def test_csv_export(client, sample_text):
    ingest(client, sample_text)
    r = client.get("/api/events/export.csv?vendor=Fortinet")
    assert r.status_code == 200 and "FW-EDGE" in r.get_data(as_text=True)

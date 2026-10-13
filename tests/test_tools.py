"""Pruebas del generador multivendor (RF-06, HU-04) y de la consola simulada (RF-07, HU-05)."""
from tests.conftest import OP, READER

BASE = {"collector_ip": "192.168.50.10", "port": 514, "transport": "udp", "severity": 4, "facility": 7,
        "source_interface": "Loopback0", "ntp_server": "192.168.50.10"}


def test_plantilla_cisco(client):
    r = client.post("/api/config/generate", json={**BASE, "vendor": "cisco"}).json
    assert "logging host 192.168.50.10 transport udp port 514" in r["config"]
    assert "logging trap warnings" in r["config"] and "show logging" in r["verify"]
    assert "no logging host 192.168.50.10" in r["rollback"]
    assert sum(1 for l in r["config"].splitlines() if l.strip().startswith("!")) >= 10   # comentada


def test_plantilla_fortinet(client):
    r = client.post("/api/config/generate", json={**BASE, "vendor": "fortinet", "severity": 3}).json
    assert 'set server "192.168.50.10"' in r["config"] and "set severity error" in r["config"]
    assert "show log syslogd setting" in r["verify"]


def test_plantilla_huawei(client):
    r = client.post("/api/config/generate", json={**BASE, "vendor": "huawei", "severity": 6}).json
    assert "info-center loghost 192.168.50.10 facility local7" in r["config"]
    assert "log level informational" in r["config"] and "display info-center" in r["verify"]


def test_validacion_y_advertencias(client):
    assert client.post("/api/config/generate", json={**BASE, "vendor": "cisco", "collector_ip": "999.1.1.1"}).status_code == 400
    assert client.post("/api/config/generate", json={**BASE, "vendor": "juniper"}).status_code == 400
    assert client.post("/api/config/generate", json={**BASE, "vendor": "cisco", "source_interface": "Lo0; reload"}).status_code == 400
    r = client.post("/api/config/generate", json={**BASE, "vendor": "cisco", "collector_ip": "8.8.8.8"}).json
    assert any("pública" in w for w in r["warnings"])


def test_consola_permite_consultas(client):
    r = client.post("/api/console/exec", json={"profile": "cisco", "device_id": 1, "command": "show version"},
                    headers=READER).json
    assert r["decision"] == "permitido" and "SALIDA SIMULADA" in r["output"]


def test_consola_bloquea_cambios_encadenamiento_y_modo(client):
    cases = [("cisco", 1, "configure terminal"), ("cisco", 1, "reload"), ("cisco", 1, "show version; reload"),
             ("huawei", 4, "system-view"), ("fortinet", 3, "execute factoryreset"), ("rommon", 1, "show version"),
             ("cisco", 3, "show version")]           # perfil Cisco sobre un equipo Fortinet
    for profile, dev, cmd in cases:
        r = client.post("/api/console/exec", json={"profile": profile, "device_id": dev, "command": cmd},
                        headers=OP).json
        assert r["decision"] == "bloqueado", (profile, cmd)
        assert r["output"].startswith("BLOQUEADO")
    audit = client.get("/api/audit/commands").json
    assert len(audit) == len(cases) and all(a["output_hash"] for a in audit)

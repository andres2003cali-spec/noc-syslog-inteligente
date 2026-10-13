"""Pruebas del normalizador Syslog (RF-03)."""
from app.collector.parser import parse_syslog


def test_pri_decodifica_facility_y_severidad():
    r = parse_syslog("<34>Oct 13 10:00:00 host app: mensaje")
    assert r["facility"] == 4 and r["severity"] == 2      # 34 = 4*8 + 2


def test_cisco_usa_severidad_del_mnemonico():
    r = parse_syslog("<189>45: R1-NOC: *Oct 13 10:00:00.123: %LINK-3-UPDOWN: Interface Gi0/0/1, changed state to down")
    assert r["fmt"] == "cisco" and r["severity"] == 3 and r["hostname"] == "R1-NOC"
    assert r["app_name"] == "%LINK-3-UPDOWN" and r["vendor_hint"] == "Cisco"


def test_fortinet_clave_valor():
    r = parse_syslog('<189>date=2026-10-13 time=09:15:00 devname="FW-EDGE" logid="0100032002" type="event" '
                     'subtype="system" level="alert" msg="Admin login failed"')
    assert r["fmt"] == "fortinet" and r["severity"] == 1 and r["hostname"] == "FW-EDGE"
    assert r["event_time"] == "2026-10-13 09:15:00"


def test_huawei_vrp():
    r = parse_syslog("<187>Oct 13 2026 10:02:11 SW-CORE %%01IFNET/4/LINK_STATE(l)[0]:The line protocol is DOWN.")
    assert r["fmt"] == "huawei" and r["severity"] == 4 and r["hostname"] == "SW-CORE"


def test_rfc5424():
    r = parse_syslog("<134>1 2026-10-13T09:20:00-05:00 R1-NOC netconf 3011 ID47 - sesión abierta")
    assert r["fmt"] == "rfc5424" and r["facility"] == 16 and r["severity"] == 6 and r["app_name"] == "netconf"


def test_lineas_invalidas_se_rechazan():
    assert parse_syslog("esto no es syslog") is None
    assert parse_syslog("<999>mensaje con PRI fuera de rango") is None
    assert parse_syslog("") is None

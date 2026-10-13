"""
generator.py - Generador de configuraciones Syslog comentadas (RF-06, HU-04).

Produce plantillas didácticas para Cisco IOS/IOS XE, Fortinet FortiOS y Huawei VRP
con: comentario por línea, comandos de verificación y plan de reversa (rollback).

ADVERTENCIA: la sintaxis varía según modelo y versión. Antes de aplicar:
identifique equipo y versión, consulte la referencia oficial, haga backup,
pruebe en laboratorio, obtenga autorización y conserve el plan de reversa.
"""
import ipaddress
import re

from app.collector.parser import SEVERITY_NAMES

# Palabra clave de severidad que espera cada fabricante (0..7)
CISCO_LEVELS = ["emergencies", "alerts", "critical", "errors", "warnings", "notifications", "informational", "debugging"]
FORTI_LEVELS = ["emergency", "alert", "critical", "error", "warning", "notification", "information", "debug"]
HUAWEI_LEVELS = ["emergencies", "alert", "critical", "error", "warning", "notification", "informational", "debugging"]

RE_IFACE = re.compile(r"^[A-Za-z][A-Za-z\-]{1,24}[0-9][0-9/.:]{0,15}$")
RE_HOSTNAME = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,40}$")

VERSION_WARNING = ("Plantilla didáctica generada por NOC Syslog Inteligente v0.2.0. La sintaxis depende "
                   "del modelo y la versión del sistema operativo: contrástela con la documentación oficial, "
                   "haga backup y aplíquela solo en laboratorio autorizado con plan de reversa.")


class ConfigError(ValueError):
    """Error de validación de los parámetros del generador."""


def _validate(params: dict) -> dict:
    vendor = (params.get("vendor") or "").lower()
    if vendor not in ("cisco", "fortinet", "huawei"):
        raise ConfigError("Fabricante no soportado. Use cisco, fortinet o huawei.")
    try:
        ip = ipaddress.IPv4Address((params.get("collector_ip") or "").strip())
    except ipaddress.AddressValueError:
        raise ConfigError("La IP del colector debe ser una IPv4 válida.")
    if ip.is_unspecified or ip.is_multicast or ip.is_loopback:
        raise ConfigError("La IP del colector no puede ser 0.0.0.0, loopback ni multicast.")
    try:
        port = int(params.get("port") or 514)
        sev = int(params.get("severity", 4))
        fac = int(params.get("facility", 7))
    except (TypeError, ValueError):
        raise ConfigError("Puerto, severidad y facility deben ser números.")
    if not 1 <= port <= 65535:
        raise ConfigError("Puerto fuera de rango (1-65535).")
    if not 0 <= sev <= 7:
        raise ConfigError("La severidad debe estar entre 0 y 7.")
    if not 0 <= fac <= 7:
        raise ConfigError("Facility local debe estar entre 0 y 7 (local0..local7).")
    transport = (params.get("transport") or "udp").lower()
    if transport not in ("udp", "tcp"):
        raise ConfigError("Transporte permitido: udp o tcp.")
    src_if = (params.get("source_interface") or "").strip()
    if src_if and not RE_IFACE.match(src_if):
        raise ConfigError("Nombre de interfaz de origen inválido (ej. Loopback0, GigabitEthernet0/0/0, port1).")
    ntp = (params.get("ntp_server") or "").strip()
    if ntp:
        try:
            ipaddress.IPv4Address(ntp)
        except ipaddress.AddressValueError:
            raise ConfigError("El servidor NTP debe ser una IPv4 válida.")
    return {"vendor": vendor, "ip": str(ip), "port": port, "severity": sev, "facility": fac,
            "transport": transport, "source_interface": src_if, "ntp": ntp,
            "public_ip": not ip.is_private}


def _cisco(p: dict) -> tuple[list[str], list[str], list[str]]:
    lvl = CISCO_LEVELS[p["severity"]]
    c = [
        "! ==== Cisco IOS / IOS XE - Envío de Syslog al colector NOC ====",
        "! Verifique antes: show version (familia/versión) y conectividad al colector (ping).",
        "configure terminal",
    ]
    if p["ntp"]:
        c += ["! Sincroniza el reloj con NTP: sin hora coherente no hay correlación de eventos",
              f"ntp server {p['ntp']}"]
    c += [
        "! Marca de tiempo con fecha, milisegundos y zona horaria en cada mensaje",
        "service timestamps log datetime msec localtime show-timezone",
        "! Número de secuencia: permite detectar mensajes perdidos (UDP no confirma entrega)",
        "service sequence-numbers",
        "! Incluye el hostname como identificador de origen dentro del mensaje",
        "logging origin-id hostname",
    ]
    if p["source_interface"]:
        c += ["! IP de origen fija: el colector valida la fuente contra el inventario (allowlist)",
              f"logging source-interface {p['source_interface']}"]
    c += [
        f"! Facility local{p['facility']}: separa los eventos de red en el colector",
        f"logging facility local{p['facility']}",
        f"! Destino: colector NOC por {p['transport'].upper()}/{p['port']}",
        f"logging host {p['ip']} transport {p['transport']} port {p['port']}",
        f"! Umbral: envía severidades 0..{p['severity']} ({lvl})",
        f"logging trap {lvl}",
        "! Buffer local de respaldo por si el colector no está disponible",
        "logging buffered 16384 informational",
        "! Registra cada comando de configuración (detecta cambios de agentes o cuentas no autorizadas)",
        "archive",
        " log config",
        "  logging enable",
        "  notify syslog contenttype plaintext",
        "  ! Oculta contraseñas en los registros de cambios",
        "  hidekeys",
        " exit",
        "exit",
        "! Registra intentos de acceso fallidos y exitosos (algunas versiones exigen 'login block-for')",
        "login on-failure log",
        "login on-success log",
        "! Activa el logging global",
        "logging on",
        "end",
        "! Guarda la configuración SOLO después de verificar",
        "write memory",
    ]
    verify = ["show logging", "show running-config | section logging",
              "show ntp status" if p["ntp"] else "show clock",
              f"ping {p['ip']}", "send log 4 \"Prueba NOC Syslog Inteligente\"  ! mensaje de prueba"]
    rollback = ["configure terminal", f"no logging host {p['ip']}", "logging trap informational",
                "end", "! Restaure el backup previo si cambió otras líneas: copy flash:backup.cfg running-config"]
    return c, verify, rollback


def _fortinet(p: dict) -> tuple[list[str], list[str], list[str]]:
    lvl = FORTI_LEVELS[p["severity"]]
    mode = "udp" if p["transport"] == "udp" else "reliable"
    c = ["# ==== Fortinet FortiGate / FortiOS - Envío de Syslog al colector NOC ====",
         "# Verifique antes: get system status (versión de FortiOS)."]
    if p["ntp"]:
        c += ["# Sincroniza la hora con NTP para correlacionar eventos",
              "config system ntp",
              "    set ntpsync enable",
              "    set type custom",
              "    config ntpserver",
              "        edit 1",
              f"            set server \"{p['ntp']}\"",
              "        next",
              "    end",
              "end"]
    c += ["# Define el servidor Syslog remoto",
          "config log syslogd setting",
          "    # Habilita el envío",
          "    set status enable",
          "    # IP del colector NOC",
          f"    set server \"{p['ip']}\"",
          f"    # Transporte: udp o reliable (TCP, RFC 6587)",
          f"    set mode {mode}",
          "    # Puerto del colector",
          f"    set port {p['port']}",
          f"    # Facility local{p['facility']}",
          f"    set facility local{p['facility']}"]
    if p["source_interface"]:
        c += ["    # Interfaz de origen (la sintaxis puede variar: source-ip o interface)",
              "    set interface-select-method specify",
              f"    set interface \"{p['source_interface']}\""]
    c += ["end",
          "# Filtro: severidad mínima enviada al colector",
          "config log syslogd filter",
          f"    # Envía desde {lvl} hasta emergency (0..{p['severity']})",
          f"    set severity {lvl}",
          "    # Incluye tráfico reenviado y local (accesos administrativos)",
          "    set forward-traffic enable",
          "    set local-traffic enable",
          "end",
          "# Registra eventos de sistema y de usuario (logins, cambios de configuración)",
          "config log eventfilter",
          "    set system enable",
          "    set user enable",
          "end"]
    verify = ["show log syslogd setting", "show log syslogd filter",
              "diagnose log test   # genera mensajes de prueba", f"execute ping {p['ip']}"]
    rollback = ["config log syslogd setting", "    set status disable", "end",
                "# Restaure el backup: execute restore config ... (según versión)"]
    return c, verify, rollback


def _huawei(p: dict) -> tuple[list[str], list[str], list[str]]:
    lvl = HUAWEI_LEVELS[p["severity"]]
    c = ["# ==== Huawei VRP - Envío de Syslog al colector NOC ====",
         "# Verifique antes: display version (algunas plataformas requieren 'commit').",
         "system-view",
         "# Habilita el centro de información (info-center)",
         "info-center enable",
         "# Marca de tiempo con fecha y milisegundos",
         "info-center timestamp log date precision-time millisecond"]
    if p["ntp"]:
        c += ["# Sincroniza la hora con NTP", f"ntp-service unicast-server {p['ntp']}"]
    c += [f"# Filtro del canal loghost: envía severidades 0..{p['severity']} ({lvl})",
          f"info-center source default channel loghost log level {lvl}",
          f"# Destino: colector NOC con facility local{p['facility']}"]
    host_line = f"info-center loghost {p['ip']} facility local{p['facility']}"
    if p["port"] != 514:
        host_line += f" port {p['port']}"
    if p["transport"] == "tcp":
        host_line += " transport tcp"
    c.append(host_line)
    if p["source_interface"]:
        c += ["# Interfaz de origen fija para que el colector valide la fuente",
              f"info-center loghost source {p['source_interface']}"]
    c += ["quit", "# Guarda según la política del laboratorio", "save"]
    verify = ["display info-center", "display logbuffer", "display ntp-service status" if p["ntp"] else "display clock",
              f"ping {p['ip']}"]
    rollback = ["system-view", f"undo info-center loghost {p['ip']}", "quit", "save"]
    return c, verify, rollback


def generate(params: dict) -> dict:
    """Valida parámetros y devuelve la plantilla completa con verificación y rollback."""
    p = _validate(params)
    builder = {"cisco": _cisco, "fortinet": _fortinet, "huawei": _huawei}[p["vendor"]]
    config, verify, rollback = builder(p)
    warnings = [VERSION_WARNING]
    if p["public_ip"]:
        warnings.append("La IP del colector es pública: Syslog UDP viaja sin cifrar. Use VPN o TLS (RFC 5425) "
                        "y confirme autorización.")
    if p["transport"] == "udp":
        warnings.append("UDP/514 no confirma entrega ni protege el contenido (RFC 5426). Prefiera TCP/TLS "
                        "cuando el equipo lo soporte.")
    sev_en, sev_es = SEVERITY_NAMES[p["severity"]]
    return {"vendor": p["vendor"], "severity": p["severity"], "severity_name": f"{sev_es} ({sev_en})",
            "config": "\n".join(config), "verify": "\n".join(verify), "rollback": "\n".join(rollback),
            "warnings": warnings}

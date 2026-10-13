"""
simulator.py - Consola tipo PuTTY SIMULADA y de SOLO LECTURA (RF-07, HU-05).

- No existe ninguna conexión a equipos reales: todas las salidas son simuladas y
  se rotulan con [SALIDA SIMULADA].
- Solo se aceptan comandos de una lista permitida (allowlist) por perfil.
- Los comandos de cambio, destructivos, encadenados o incompatibles con el modo
  (ej. comandos de IOS dentro de ROMMON) se BLOQUEAN y se auditan.
- Los agentes de IA no tienen acceso a la consola.
- En el Corte 3 este módulo se reemplaza por un backend SSH (Netmiko/Paramiko)
  con allowlist de hosts, verificación de huella, RBAC y aprobación humana.
"""
import hashlib
import re
from datetime import datetime

from app.db import now_iso

PROFILES = {
    "cisco": {"label": "Cisco IOS XE", "vendor": "Cisco", "prompt": "{name}#",
              "allowed": ["show version", "show ip interface brief", "show logging", "show clock",
                          "show running-config | section logging", "show users", "help", "exit"]},
    "fortinet": {"label": "FortiGate / FortiOS", "vendor": "Fortinet", "prompt": "{name} #",
                 "allowed": ["get system status", "get system interface", "show log syslogd setting",
                             "show log syslogd filter", "get system performance status", "help", "exit"]},
    "huawei": {"label": "Huawei VRP", "vendor": "Huawei", "prompt": "<{name}>",
               "allowed": ["display version", "display ip interface brief", "display info-center",
                           "display clock", "display logbuffer", "display users", "help", "quit"]},
    "rommon": {"label": "Cisco ROMMON (recuperación)", "vendor": "Cisco", "prompt": "rommon 1 >",
               "allowed": ["help", "set", "dev", "dir flash:", "confreg"]},
}

# Patrones de comandos de cambio: se bloquean aunque el usuario sea administrador.
CHANGE_PATTERNS = re.compile(
    r"(?i)^\s*(conf(igure)?(\s+t(erminal)?)?|config\s|system-view|write|copy|reload|reboot|erase|delete|"
    r"format|reset|execute|set\s|unset|undo|shutdown|no\s|debug|username|enable|boot|commit|save|"
    r"clear|interface|logging|ip\s|router|crypto|license)"
)
CHAIN_CHARS = re.compile(r"[;&`$<>]|\|\|")
IOS_LIKE = re.compile(r"(?i)^\s*(show|enable|conf|configure|write|copy)\b")


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _output(profile: str, cmd: str, device, recent_events) -> str:
    """Genera la salida SIMULADA usando datos del inventario (también simulados)."""
    name = device["name"] if device else "LAB"
    ip = device["ip"] if device else "192.168.50.1"
    model = device["model"] if device else "modelo de laboratorio"
    ver = device["os_version"] if device else "versión de laboratorio"
    clock = datetime.now().strftime("%H:%M:%S.000 COT %a %b %d %Y")
    tag = "\n[SALIDA SIMULADA - no hay conexión a equipos reales]"
    log_lines = "\n".join(f"{e['event_time']}: {e['app_name']}: {e['message'][:90]}" for e in recent_events) \
        or "(sin eventos registrados para este equipo)"

    if profile == "cisco":
        out = {
            "show version": f"Cisco IOS XE Software, {ver}\n{name} uptime is 2 days, 4 hours\ncisco {model} processor\nConfiguration register is 0x2102",
            "show ip interface brief": f"Interface              IP-Address      OK? Method Status   Protocol\nGigabitEthernet0/0/0   {ip:<15} YES manual up       up\nGigabitEthernet0/0/1   unassigned      YES unset  down     down\nLoopback0              10.255.0.1      YES manual up       up",
            "show logging": f"Syslog logging: enabled\n    Trap logging: level warnings\n    Logging to 192.168.50.10 (udp port 514)\nLog Buffer (16384 bytes):\n{log_lines}",
            "show clock": f"*{clock}",
            "show running-config | section logging": "logging buffered 16384 informational\nlogging trap warnings\nlogging host 192.168.50.10 transport udp port 514",
            "show users": "    Line       User       Host(s)              Idle       Location\n*  0 con 0    noc.lab    idle                 00:00:00",
        }
    elif profile == "fortinet":
        out = {
            "get system status": f"Version: {model} {ver}\nHostname: {name}\nOperation Mode: NAT\nSystem time: {clock}",
            "get system interface": f"== [ port1 ]\nname: port1   mode: static    ip: {ip} 255.255.255.0   status: up",
            "show log syslogd setting": "config log syslogd setting\n    set status enable\n    set server \"192.168.50.10\"\n    set mode udp\n    set port 514\nend",
            "show log syslogd filter": "config log syslogd filter\n    set severity warning\nend",
            "get system performance status": "CPU states: 3% user 1% system 0% nice 96% idle\nMemory: 38% used",
        }
    elif profile == "huawei":
        out = {
            "display version": f"Huawei Versatile Routing Platform Software\nVRP (R) software, {ver}\n{model} uptime is 2 days",
            "display ip interface brief": f"Interface                IP Address/Mask    Physical Protocol\nVlanif50                 {ip}/24     up       up\nGigabitEthernet0/0/1     unassigned         down     down",
            "display info-center": "Information Center: enabled\nLog host:\n    192.168.50.10, channel number 2, channel name loghost, language English, host facility local7",
            "display clock": clock,
            "display logbuffer": f"Logging buffer configuration and contents: enabled\n{log_lines}",
            "display users": "  User-Intf    Delay    Type   Network Address     AuthenStatus\n+ 0   CON 0   00:00:00        noc.lab             pass",
        }
    else:  # rommon
        out = {
            "set": "IP_ADDRESS=192.168.50.1\nDEFAULT_GATEWAY=192.168.50.254\n[variables no sensibles]",
            "dev": "Devices in device table:\n  flash:  usbflash0:",
            "dir flash:": "Directory of flash:\n  cisco-isr4300-universalk9.SIMULADO.bin",
            "confreg": "Configuration register is 0x2102 (solo lectura en la simulación)",
        }
    return out.get(cmd, "") + tag


def run_command(conn, profile: str, command: str, device, actor: str, role: str) -> dict:
    """Evalúa el comando contra la política, devuelve la salida y lo registra en command_audit."""
    prof = PROFILES.get(profile)
    if prof is None:
        return {"decision": "bloqueado", "output": "Perfil de consola desconocido.", "prompt": ">"}
    name = device["name"] if device else "LAB"
    prompt = prof["prompt"].format(name=name)
    cmd = re.sub(r"\s+", " ", (command or "").strip())

    decision, reason, output = "bloqueado", "", ""
    if role == "agente":
        reason = "Los agentes de IA no tienen acceso a la consola (solo pueden proponer acciones)."
    elif not cmd:
        reason = "Comando vacío."
    elif len(cmd) > 120:
        reason = "Comando demasiado largo (máx. 120 caracteres)."
    elif CHAIN_CHARS.search(cmd):
        reason = "Caracteres de encadenamiento o redirección no permitidos."
    elif device and prof["vendor"] != device["vendor"]:
        reason = f"El perfil {prof['label']} no corresponde a la marca del equipo ({device['vendor']})."
    elif cmd in ("help", "?"):
        decision, reason = "permitido", "ayuda"
        output = "Comandos permitidos en este perfil:\n  " + "\n  ".join(prof["allowed"])
    elif cmd in ("exit", "quit") and cmd in prof["allowed"]:
        decision, reason, output = "permitido", "fin de sesión", "Sesión simulada finalizada."
    elif cmd in prof["allowed"]:
        recent = []
        if device:
            recent = conn.execute(
                "SELECT event_time, app_name, message FROM events WHERE device_id = ? ORDER BY id DESC LIMIT 5",
                (device["id"],)).fetchall()
        decision, reason, output = "permitido", "comando de consulta en lista permitida", \
            _output(profile, cmd, device, recent)
    elif profile == "rommon" and IOS_LIKE.match(cmd):
        reason = ("Comando de IOS incompatible con el modo ROMMON (riesgo de alucinación operacional): "
                  "primero identifique fabricante, sistema y modo.")
    elif CHANGE_PATTERNS.match(cmd):
        reason = ("Comando de CAMBIO: la consola del MVP es de solo lectura. Regístrelo como propuesta "
                  "en 'Aprobaciones' para revisión humana.")
    else:
        reason = "Comando fuera de la lista permitida o incompatible con este modo."

    if decision == "bloqueado":
        output = f"BLOQUEADO: {reason}"
    conn.execute(
        """INSERT INTO command_audit (created_at, actor, role, device_id, profile, command, decision,
                                      reason, output_hash) VALUES (?,?,?,?,?,?,?,?,?)""",
        (now_iso(), actor, role, device["id"] if device else None, profile, cmd[:200], decision,
         reason, _hash(output)))
    conn.commit()
    return {"decision": decision, "reason": reason, "output": output, "prompt": prompt}

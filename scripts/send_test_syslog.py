"""
send_test_syslog.py - Envía mensajes Syslog SINTÉTICOS por UDP al receptor de laboratorio.

Uso (con la app corriendo con --udp):
    python scripts/send_test_syslog.py                  # envía el archivo de muestra
    python scripts/send_test_syslog.py --count 5        # solo las primeras 5 líneas

Nota: los mensajes llegan con IP de origen 127.0.0.1. Para que la política los
acepte como fuente autorizada, registre un equipo con IP 127.0.0.1 en el inventario
(ej. 'LAB-LOCAL', marca Cisco). Si no, quedarán como 'fuente no autorizada' (prueba
de la allowlist).
"""
import argparse
import socket
import time
from pathlib import Path

SAMPLE = Path(__file__).resolve().parent.parent / "data" / "samples" / "syslog_simulado_lab.log"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5514)
    ap.add_argument("--file", default=str(SAMPLE))
    ap.add_argument("--count", type=int, default=0)
    a = ap.parse_args()
    lines = [l for l in Path(a.file).read_text(encoding="utf-8").splitlines() if l.strip() and not l.startswith("#")]
    if a.count:
        lines = lines[: a.count]
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        for line in lines:
            s.sendto(line.encode("utf-8"), (a.host, a.port))
            time.sleep(0.02)
    print(f"Enviados {len(lines)} mensajes SIMULADOS a {a.host}:{a.port}/udp")


if __name__ == "__main__":
    main()

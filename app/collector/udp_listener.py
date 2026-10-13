"""
udp_listener.py - Receptor Syslog UDP de LABORATORIO (RF-02).

- Escucha por defecto en 127.0.0.1:5514 (514 exige privilegios de administrador).
- Cada datagrama pasa por la MISMA tubería de validación y política (ingest.py).
- La fuente es la IP real del datagrama: solo se aceptan equipos del inventario.
- Se activa con NOC_SYSLOG_ENABLED=true en el archivo .env.
- Abra el puerto en el firewall SOLO desde las IP de los equipos autorizados.
"""
import logging
import socketserver
import threading

from app.collector.ingest import ingest_line
from app.db import connect

log = logging.getLogger("noc.udp")


class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        data, _sock = self.request
        line = data[: self.server.cfg["MAX_LINE_LENGTH"]].decode("utf-8", errors="replace")
        src_ip = self.client_address[0]
        with self.server.lock:
            try:
                r = ingest_line(self.server.conn, line, self.server.cfg, source=src_ip, channel="udp",
                                origin_label=self.server.origin_label, actor="receptor-udp")
                self.server.conn.commit()
                log.info("UDP %s -> %s", src_ip, r.get("status"))
            except Exception:  # errores controlados: el receptor no se cae por un mensaje malformado
                self.server.conn.rollback()
                log.exception("Error procesando datagrama de %s", src_ip)


class SyslogUDPServer(socketserver.ThreadingUDPServer):
    daemon_threads = True
    allow_reuse_address = True


def start_udp_listener(cfg: dict, origin_label: str = "simulado") -> SyslogUDPServer:
    """Inicia el receptor en un hilo en segundo plano y lo devuelve."""
    server = SyslogUDPServer((cfg["SYSLOG_HOST"], cfg["SYSLOG_PORT"]), _Handler)
    server.cfg = cfg
    server.conn = connect(cfg["DB_PATH"])
    server.lock = threading.Lock()
    server.origin_label = origin_label
    threading.Thread(target=server.serve_forever, name="syslog-udp", daemon=True).start()
    log.info("Receptor Syslog UDP escuchando en %s:%s", cfg["SYSLOG_HOST"], cfg["SYSLOG_PORT"])
    return server

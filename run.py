"""
run.py - Punto de entrada del NOC Syslog Inteligente.

Uso:
    python run.py                 -> dashboard en http://127.0.0.1:5000
    python run.py --udp           -> además activa el receptor Syslog UDP (127.0.0.1:5514)
    python run.py --reset         -> borra la base local y la recrea con el inventario simulado
"""
import argparse
import os

from app import create_app
from app.collector.udp_listener import start_udp_listener


def main():
    parser = argparse.ArgumentParser(description="NOC Syslog Inteligente v0.2.0")
    parser.add_argument("--host", default="127.0.0.1", help="interfaz web (por defecto solo local)")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--udp", action="store_true", help="activa el receptor Syslog UDP de laboratorio")
    parser.add_argument("--reset", action="store_true", help="reinicia la base de datos local")
    args = parser.parse_args()

    if args.reset:
        from app.config import Config
        for suffix in ("", "-wal", "-shm"):
            path = Config.DB_PATH + suffix
            if os.path.exists(path):
                os.remove(path)
        print("Base de datos local reiniciada.")

    app = create_app()
    if args.udp or app.config["SYSLOG_ENABLED"]:
        start_udp_listener(app.config)
        print(f"Receptor Syslog UDP en {app.config['SYSLOG_HOST']}:{app.config['SYSLOG_PORT']}")
    print(f"NOC Syslog Inteligente en http://{args.host}:{args.port}  (Ctrl+C para detener)")
    # debug=False: nunca exponer el depurador de Flask
    app.run(host=args.host, port=args.port, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()

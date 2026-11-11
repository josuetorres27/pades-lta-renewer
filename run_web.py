#!/usr/bin/env python3
"""Punto de entrada para iniciar la interfaz web minimalista de PAdES-LTA Renewer."""

import os
import sys
from pathlib import Path

project_root = Path(__file__).resolve().parent
sys.path.insert(0, str(project_root / "src"))

from pades_renewer.web import create_app


def main():
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5050"))
    app = create_app()
    print(f"PAdES-LTA Renewer listo en: http://{host}:{port}")
    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    main()

"""
Permite ejecutar ``pytest`` desde la raíz del repositorio sin instalar el paquete.

Sin este archivo, ``src/pades_renewer`` solo es importable con ``PYTHONPATH=src``
(o ``python -m pytest``, que añade el directorio actual a ``sys.path``), de modo que el
comando documentado en el README fallaba al recolectar las pruebas.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
for extra in (ROOT / "src", ROOT / "tests"):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))

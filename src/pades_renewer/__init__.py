"""
PAdES-LTA Renewer
Sistema automatizado para la preservación a largo plazo y renovación de sellos de tiempo
en documentos firmados digitalmente conforme a los estándares ETSI EN 319 142 y la
política del MICITT de Costa Rica.
"""

from importlib.metadata import PackageNotFoundError, version as _package_version

from .pdf_injector import RenewalResult, renew_pdf_to_lta
from .pki_inspector import inspect_pdf_public
from .tsa_client import TSASinpeClient, TimestampResult

try:
    __version__ = _package_version("pades-lta-renewer")
except PackageNotFoundError:  # ejecución desde el árbol de fuentes sin instalar
    __version__ = "0.1.0"

__all__ = [
    "TSASinpeClient",
    "TimestampResult",
    "RenewalResult",
    "renew_pdf_to_lta",
    "inspect_pdf_public",
    "__version__",
]

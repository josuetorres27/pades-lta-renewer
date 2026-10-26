"""
PAdES-LTA Renewer
Sistema automatizado para la preservación a largo plazo y renovación de sellos de tiempo
en documentos firmados digitalmente conforme a los estándares ETSI EN 319 142 y la
política del MICITT de Costa Rica.
"""

from .tsa_client import TSASinpeClient, TimestampResult

__all__ = ["TSASinpeClient", "TimestampResult"]

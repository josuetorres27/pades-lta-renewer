"""
Utilidades criptográficas y de manejo de archivos para PAdES-LTA Renewer.
"""

import hashlib
from pathlib import Path
from typing import Union


def compute_hash(data: Union[bytes, bytearray], algorithm: str = "sha256") -> bytes:
    """
    Calcula el resumen criptográfico (digest) de un conjunto de bytes en memoria.

    Args:
        data: Bytes a procesar.
        algorithm: Nombre del algoritmo (por defecto 'sha256', compatible con 'sha384', 'sha512').

    Returns:
        Bytes del digest resultante.
    """
    hasher = hashlib.new(algorithm)
    hasher.update(data)
    return hasher.digest()


def compute_file_hash(file_path: Union[str, Path], algorithm: str = "sha256", chunk_size: int = 65536) -> bytes:
    """
    Calcula el hash de un archivo leyendo en bloques para optimizar el uso de memoria.

    Args:
        file_path: Ruta al archivo.
        algorithm: Algoritmo hash a emplear.
        chunk_size: Tamaño de lectura por bloque (por defecto 64KB).

    Returns:
        Bytes del digest resultante.
    """
    hasher = hashlib.new(algorithm)
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"No se encontró el archivo: {file_path}")

    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)
    return hasher.digest()

"""
Aplicación Flask minimalista para renovación incremental PAdES-B-LTA e inspección de ramas PKI.
"""

from collections import OrderedDict
import io
from pathlib import Path
import threading
import time
from typing import Dict, Tuple
import uuid

from flask import Flask, jsonify, render_template, request, send_file

from ..pdf_injector import renew_pdf_to_lta


MAX_UPLOAD_BYTES = 50 * 1024 * 1024
MAX_CACHED_DOWNLOADS = 32


def _sanitize_download_name(original_name: str) -> str:
    clean = Path(original_name or "documento.pdf").name
    clean = "".join(ch for ch in clean if ch not in '\\/:*?"<>|\r\n\x00').strip()
    if not clean:
        clean = "documento.pdf"
    stem = clean[:-4] if clean.lower().endswith(".pdf") else clean
    if stem.lower().endswith("_lta"):
        return f"{stem}.pdf"
    return f"{stem}_LTA.pdf"


def create_app() -> Flask:
    template_dir = Path(__file__).resolve().parent / "templates"
    static_dir = Path(__file__).resolve().parent / "static"

    app = Flask(
        __name__,
        template_folder=str(template_dir),
        static_folder=str(static_dir),
    )
    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES
    app.config["JSON_AS_ASCII"] = False

    url_cache: Dict[str, Tuple[float, bytes]] = {}
    download_store: "OrderedDict[str, Tuple[str, bytes, float]]" = OrderedDict()
    store_lock = threading.Lock()

    @app.errorhandler(413)
    def handle_too_large(_err):
        return jsonify({"error": "El archivo supera el límite máximo permitido de 50 MB."}), 413

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.post("/api/renew")
    def api_renew():
        uploaded = request.files.get("file")
        if uploaded is None or not uploaded.filename:
            return jsonify({"error": "No se recibió ningún archivo PDF."}), 400

        raw_bytes = uploaded.read()
        if not raw_bytes:
            return jsonify({"error": "El archivo seleccionado está vacío."}), 400

        if not raw_bytes.lstrip().startswith(b"%PDF-"):
            return jsonify({"error": f"'{uploaded.filename}' no tiene cabecera PDF válida (%PDF-)."}), 400

        try:
            result = renew_pdf_to_lta(raw_bytes, url_cache=url_cache)
        except Exception as exc:
            return jsonify({"error": f"Error inesperado procesando el documento: {exc}"}), 500

        if not result.success or not result.output_pdf_bytes:
            return jsonify({"error": result.error_message or "No se pudo completar la renovación PAdES-B-LTA."}), 422

        file_id = uuid.uuid4().hex
        dl_name = _sanitize_download_name(uploaded.filename)
        with store_lock:
            download_store[file_id] = (dl_name, result.output_pdf_bytes, time.time())
            while len(download_store) > MAX_CACHED_DOWNLOADS:
                download_store.popitem(last=False)

        return jsonify({
            "file_id": file_id,
            "filename": Path(uploaded.filename).name,
            "download_name": dl_name,
            "download_url": f"/api/download/{file_id}",
            "original_size_bytes": len(raw_bytes),
            "renewed_size_bytes": len(result.output_pdf_bytes),
            "original_profile": result.original_profile,
            "new_profile": result.new_profile,
            "field_name": result.field_name,
            "hash_algorithm": result.hash_algorithm,
            "tsa_timestamp_utc": result.tsa_timestamp_utc,
            "tsa_policy_oid": result.tsa_policy_oid,
            "tsa_serial_number": result.tsa_serial_number,
            "dss_updated": result.dss_updated,
            "dss_counts": result.dss_counts,
            "effective_protection_until": result.effective_protection_until,
            "pre_inspection": result.pre_inspection,
            "post_inspection": result.post_inspection,
        })

    @app.get("/api/download/<file_id>")
    def api_download(file_id: str):
        with store_lock:
            entry = download_store.get(file_id)
        if entry is None:
            return jsonify({"error": "El archivo solicitado ya expiró de memoria o no existe."}), 404

        dl_name, payload, _ = entry
        return send_file(
            io.BytesIO(payload),
            mimetype="application/pdf",
            as_attachment=True,
            download_name=dl_name,
        )

    return app

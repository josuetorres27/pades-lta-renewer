"""
Inyector incremental PAdES-B-LT (/DSS) + PAdES-B-LTA (/DocTimeStamp) para PDFs.

Implementa conforme a ISO 32000-1/2, ETSI EN 319 142-1 y RFC 3161:
1. Recolección de cadenas completas hasta la CA Raíz, CRLs y respuestas OCSP
   (incluyendo las evidencias de la TSA activa que emitirá el nuevo sello).
2. Primera actualización incremental: incorporación/actualización del diccionario /DSS
   y /Extensions (ADBE ExtensionLevel 8) -> perfil PAdES-B-LT.
3. Segunda actualización incremental: creación de campo /DocTimeStamp (/ETSI.RFC3161),
   cálculo exacto de /ByteRange y digest SHA-256/SHA-512, consulta a TSA-SINPE
   e inyección binaria en /Contents sin invalidar firmas anteriores -> PAdES-B-LTA.
"""

from dataclasses import dataclass
import hashlib
import io
import struct
import time
from typing import Any, Dict, List, Optional, Tuple

import pypdf
from pypdf.generic import (
    ArrayObject,
    ByteStringObject,
    DecodedStreamObject,
    DictionaryObject,
    IndirectObject,
    NameObject,
    NumberObject,
    TextStringObject,
)
from asn1crypto import cms

from .pki_inspector import (
    CertificatePool,
    _extract_tst_details,
    build_chain_to_root,
    inspect_pdf,
    inspect_pdf_public,
)
from .tsa_client import TSASinpeClient, TimestampResult


BR_PLACEHOLDER = b"/ByteRange [0 0000000000 0000000000 0000000000]"
DEFAULT_TOKEN_BUFFER_BYTES = 8192

# Caché en memoria (solo para cadena de certificados TSA activa por URL, TTL 1h)
_TSA_CHAIN_PROBE_CACHE: Dict[str, Tuple[float, bytes]] = {}


@dataclass
class RenewalResult:
    """Resultado completo de la renovación PAdES-B-LTA sobre un PDF."""

    success: bool
    original_profile: str
    new_profile: str
    field_name: Optional[str]
    hash_algorithm: str
    tsa_timestamp_utc: Optional[str]
    tsa_policy_oid: Optional[str]
    tsa_serial_number: Optional[str]
    dss_updated: bool
    dss_counts: Dict[str, int]
    effective_protection_until: Optional[str]
    output_pdf_bytes: Optional[bytes]
    pre_inspection: Dict[str, Any]
    post_inspection: Optional[Dict[str, Any]]
    error_message: Optional[str] = None


def _get_max_object_id(reader: pypdf.PdfReader) -> int:
    max_id = max(int(reader.trailer.get("/Size", 1)) - 1, 0)
    for section in reader.xref.values():
        if section:
            max_id = max(max_id, max(section.keys()))
    if getattr(reader, "xref_free_entry", None):
        for section in reader.xref_free_entry.values():
            if section:
                max_id = max(max_id, max(section.keys()))
    return max_id


def _is_classic_xref(pdf_bytes: bytes, startxref: int) -> bool:
    if startxref < 0 or startxref >= len(pdf_bytes):
        return True
    return pdf_bytes[startxref : startxref + 64].lstrip().startswith(b"xref")


def _preserved_trailer_entries(reader: pypdf.PdfReader) -> Dict[NameObject, Any]:
    entries: Dict[NameObject, Any] = {}
    root_ref = dict.__getitem__(reader.trailer, "/Root")
    entries[NameObject("/Root")] = root_ref
    if "/Info" in reader.trailer:
        info_ref = dict.__getitem__(reader.trailer, "/Info")
        if isinstance(info_ref, IndirectObject):
            entries[NameObject("/Info")] = info_ref
    if "/ID" in reader.trailer:
        raw_id = reader.trailer["/ID"]
        id_elems = []
        for item in raw_id:
            raw_bytes = getattr(item, "original_bytes", None)
            if raw_bytes is None:
                raw_bytes = bytes(item)
            id_elems.append(ByteStringObject(raw_bytes))
        entries[NameObject("/ID")] = ArrayObject(id_elems)
    return entries


def _serialize_pdf_object(obj: Any) -> bytes:
    if isinstance(obj, (bytes, bytearray)):
        return bytes(obj)
    buf = io.BytesIO()
    obj.write_to_stream(buf)
    return buf.getvalue()


def _group_contiguous_ids(sorted_ids: List[int]) -> List[Tuple[int, List[int]]]:
    if not sorted_ids:
        return []
    groups: List[Tuple[int, List[int]]] = []
    cur_start = sorted_ids[0]
    cur_list = [sorted_ids[0]]
    for oid in sorted_ids[1:]:
        if oid == cur_list[-1] + 1:
            cur_list.append(oid)
        else:
            groups.append((cur_start, cur_list))
            cur_start = oid
            cur_list = [oid]
    groups.append((cur_start, cur_list))
    return groups


def _append_incremental_revision(
    pdf_bytes: bytes,
    objects: Dict[int, Any],
    next_free_obj_id: int,
    reader: pypdf.PdfReader,
) -> Tuple[bytes, Dict[int, int]]:
    """
    Anexa objetos actualizados/nuevos como una revisión incremental ISO 32000-1
    respetando el esquema de tabla xref clásica o flujo /Type /XRef del documento base.
    """
    out = bytearray(pdf_bytes)
    if not out.endswith((b"\n", b"\r")):
        out.extend(b"\n")

    offsets: Dict[int, int] = {}
    for oid in sorted(objects.keys()):
        offsets[oid] = len(out)
        obj_bytes = _serialize_pdf_object(objects[oid])
        out.extend(f"{oid} 0 obj\n".encode("ascii"))
        out.extend(obj_bytes)
        if not obj_bytes.endswith(b"\n"):
            out.extend(b"\n")
        out.extend(b"endobj\n")

    sorted_ids = sorted(objects.keys())
    max_written_id = max(sorted_ids) if sorted_ids else 0
    size_val = max(next_free_obj_id, max_written_id + 1, int(reader.trailer.get("/Size", 1)))
    trailer_entries = _preserved_trailer_entries(reader)

    if _is_classic_xref(pdf_bytes, reader._startxref):
        xref_offset = len(out)
        out.extend(b"xref\n")
        out.extend(b"0 1\n")
        out.extend(b"0000000000 65535 f \n")
        for start, group in _group_contiguous_ids(sorted_ids):
            out.extend(f"{start} {len(group)}\n".encode("ascii"))
            for oid in group:
                out.extend(f"{offsets[oid]:010d} 00000 n \n".encode("ascii"))

        trailer_dict = DictionaryObject(trailer_entries)
        trailer_dict[NameObject("/Size")] = NumberObject(size_val)
        trailer_dict[NameObject("/Prev")] = NumberObject(reader._startxref)

        tbuf = io.BytesIO()
        trailer_dict.write_to_stream(tbuf)
        out.extend(b"trailer\n")
        out.extend(tbuf.getvalue())
        out.extend(f"\nstartxref\n{xref_offset}\n%%EOF\n".encode("ascii"))
        return bytes(out), offsets

    # Documento con tabla de referencias cruzadas comprimida (/Type /XRef)
    xref_stm_id = max(size_val, max_written_id + 1)
    final_size = xref_stm_id + 1
    xref_offset = len(out)
    offsets[xref_stm_id] = xref_offset

    all_ids = sorted(sorted_ids + [xref_stm_id])
    groups = _group_contiguous_ids(all_ids)

    index_array = ArrayObject([NumberObject(0), NumberObject(1)])
    binary_entries = bytearray(struct.pack(">BQH", 0, 0, 65535))
    for start, group in groups:
        index_array.append(NumberObject(start))
        index_array.append(NumberObject(len(group)))
        for oid in group:
            binary_entries.extend(struct.pack(">BQH", 1, offsets[oid], 0))

    xref_stm = DecodedStreamObject()
    for k, v in trailer_entries.items():
        xref_stm[k] = v
    xref_stm[NameObject("/Type")] = NameObject("/XRef")
    xref_stm[NameObject("/Size")] = NumberObject(final_size)
    xref_stm[NameObject("/W")] = ArrayObject([NumberObject(1), NumberObject(8), NumberObject(2)])
    xref_stm[NameObject("/Index")] = index_array
    xref_stm[NameObject("/Prev")] = NumberObject(reader._startxref)
    xref_stm.set_data(bytes(binary_entries))

    stm_buf = io.BytesIO()
    xref_stm.write_to_stream(stm_buf)
    out.extend(f"{xref_stm_id} 0 obj\n".encode("ascii"))
    out.extend(stm_buf.getvalue())
    out.extend(f"\nendobj\nstartxref\n{xref_offset}\n%%EOF\n".encode("ascii"))
    return bytes(out), offsets


def _populate_active_tsa_evidence(
    tsa_client: TSASinpeClient,
    pool: CertificatePool,
    algorithm: str = "sha256",
) -> None:
    """
    Obtiene los certificados y listas de revocación de la TSA activa (p. ej. TSA SINPE v4)
    para incluirlos en el diccionario /DSS antes de sellar la revisión B-LTA.
    """
    cache_key = f"{tsa_client.tsa_url}::{algorithm}"
    cached = _TSA_CHAIN_PROBE_CACHE.get(cache_key)
    token_der: Optional[bytes] = None
    if cached is not None and (time.monotonic() - cached[0]) < 3600:
        token_der = cached[1]
    else:
        probe = tsa_client.stamp_bytes(b"pades-lta-tsa-probe", algorithm=algorithm)
        if probe.is_granted and probe.raw_token_der:
            token_der = probe.raw_token_der
            _TSA_CHAIN_PROBE_CACHE[cache_key] = (time.monotonic(), token_der)

    if not token_der:
        return

    try:
        ci = cms.ContentInfo.load(token_der)
        tst_meta = _extract_tst_details(ci, pool)
        if tst_meta.get("tsa_cert_der"):
            build_chain_to_root(tst_meta["tsa_cert_der"], pool, role_hint="tsa")
    except Exception:
        pass


def _append_dss_revision(pdf_bytes: bytes, pool: CertificatePool) -> Tuple[bytes, bool, Dict[str, int]]:
    """
    Anexa o actualiza el diccionario /DSS (PAdES-B-LT) preservando los flujos previos
    y agregando los certificados, CRLs y respuestas OCSP faltantes en la cadena.
    """
    reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
    root_ref = dict.__getitem__(reader.trailer, "/Root")
    root_obj = root_ref.get_object()
    next_id = _get_max_object_id(reader) + 1

    existing_cert_fps = set()
    existing_crl_fps = set()
    existing_ocsp_fps = set()

    certs_refs: List[Any] = []
    crls_refs: List[Any] = []
    ocsps_refs: List[Any] = []
    preserved_vri = None

    has_dss = "/DSS" in root_obj
    if has_dss:
        dss_obj = root_obj["/DSS"].get_object()
        for ref in dss_obj.get("/Certs") or []:
            certs_refs.append(ref)
            try:
                existing_cert_fps.add(hashlib.sha256(ref.get_object().get_data()).hexdigest())
            except Exception:
                pass
        for ref in dss_obj.get("/CRLs") or []:
            crls_refs.append(ref)
            try:
                existing_crl_fps.add(hashlib.sha256(ref.get_object().get_data()).hexdigest())
            except Exception:
                pass
        for ref in dss_obj.get("/OCSPs") or []:
            ocsps_refs.append(ref)
            try:
                existing_ocsp_fps.add(hashlib.sha256(ref.get_object().get_data()).hexdigest())
            except Exception:
                pass
        if "/VRI" in dss_obj:
            preserved_vri = dict.__getitem__(dss_obj, "/VRI")

    new_objects: Dict[int, Any] = {}

    def _add_streams(items: List[bytes], seen_fps: set, target_refs: List[Any]) -> int:
        nonlocal next_id
        added = 0
        for raw_bytes in items:
            fp = hashlib.sha256(raw_bytes).hexdigest()
            if fp in seen_fps:
                continue
            seen_fps.add(fp)
            stm = DecodedStreamObject()
            stm.set_data(raw_bytes)
            compressed = stm.flate_encode()
            stream_obj = compressed if len(compressed._data) < len(raw_bytes) else stm
            oid = next_id
            next_id += 1
            new_objects[oid] = stream_obj
            target_refs.append(IndirectObject(oid, 0, reader))
            added += 1
        return added

    added_certs = _add_streams(pool.all_certs_der(), existing_cert_fps, certs_refs)
    added_crls = _add_streams(pool.all_crls_der(), existing_crl_fps, crls_refs)
    added_ocsps = _add_streams(pool.all_ocsps_der(), existing_ocsp_fps, ocsps_refs)

    # Verificar si /Extensions ya declara ADBE ExtensionLevel 8
    extensions_ok = False
    if "/Extensions" in root_obj:
        ext_dict = root_obj["/Extensions"].get_object()
        if "/ADBE" in ext_dict:
            adbe = ext_dict["/ADBE"].get_object()
            if int(adbe.get("/ExtensionLevel", 0)) >= 8:
                extensions_ok = True

    counts = {
        "certs": len(certs_refs),
        "crls": len(crls_refs),
        "ocsps": len(ocsps_refs),
    }

    if has_dss and added_certs == 0 and added_crls == 0 and added_ocsps == 0 and extensions_ok:
        return pdf_bytes, False, counts

    dss_dict = DictionaryObject()
    if certs_refs:
        dss_dict[NameObject("/Certs")] = ArrayObject(certs_refs)
    if crls_refs:
        dss_dict[NameObject("/CRLs")] = ArrayObject(crls_refs)
    if ocsps_refs:
        dss_dict[NameObject("/OCSPs")] = ArrayObject(ocsps_refs)
    if preserved_vri is not None:
        dss_dict[NameObject("/VRI")] = preserved_vri

    dss_id = next_id
    next_id += 1
    new_objects[dss_id] = dss_dict

    new_root = DictionaryObject({k: dict.__getitem__(root_obj, k) for k in root_obj.keys()})
    new_root[NameObject("/DSS")] = IndirectObject(dss_id, 0, reader)

    ext_copy = DictionaryObject()
    if "/Extensions" in new_root:
        old_ext = root_obj["/Extensions"].get_object()
        for k in old_ext.keys():
            ext_copy[k] = dict.__getitem__(old_ext, k)
    adbe_dict = DictionaryObject({
        NameObject("/BaseVersion"): NameObject("/1.7"),
        NameObject("/ExtensionLevel"): NumberObject(8),
    })
    ext_copy[NameObject("/ADBE")] = adbe_dict
    new_root[NameObject("/Extensions")] = ext_copy

    new_objects[root_ref.idnum] = new_root

    updated_bytes, _ = _append_incremental_revision(pdf_bytes, new_objects, next_id, reader)
    return updated_bytes, True, counts


def _next_signature_field_name(reader: pypdf.PdfReader) -> str:
    existing = set((reader.get_fields() or {}).keys())
    idx = 1
    while f"Signature{idx}" in existing:
        idx += 1
    return f"Signature{idx}"


def _build_doctimestamp_skeleton(
    pdf_bytes: bytes,
    field_name: str,
    buffer_bytes: int,
) -> Tuple[bytearray, int, int, int, int]:
    """
    Construye la revisión incremental del sello documental (/DocTimeStamp) dejando
    espacio reservado fijo para /ByteRange y /Contents <000...>.
    """
    reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
    if len(reader.pages) == 0:
        raise ValueError("El documento PDF no contiene páginas.")

    root_ref = dict.__getitem__(reader.trailer, "/Root")
    root_obj = root_ref.get_object()
    page0 = reader.pages[0]
    page0_ref = page0.indirect_reference
    next_id = _get_max_object_id(reader) + 1

    v_id = next_id
    ap_form_id = next_id + 1
    ap_id = next_id + 2
    widget_id = next_id + 3
    next_id += 4

    contents_hex_len = buffer_bytes * 2
    v_bytes = (
        b"<<\n"
        b"/Type /DocTimeStamp\n"
        b"/Filter /Adobe.PPKLite\n"
        b"/SubFilter /ETSI.RFC3161\n"
        b"/Contents <" + (b"0" * contents_hex_len) + b">\n"
        + BR_PLACEHOLDER
        + b"\n>>"
    )

    ap_form = DecodedStreamObject()
    ap_form[NameObject("/Type")] = NameObject("/XObject")
    ap_form[NameObject("/Subtype")] = NameObject("/Form")
    ap_form[NameObject("/BBox")] = ArrayObject([
        NumberObject(0),
        NumberObject(0),
        NumberObject(0),
        NumberObject(0),
    ])
    ap_form.set_data(b"")

    ap_dict = DictionaryObject({
        NameObject("/N"): IndirectObject(ap_form_id, 0, reader),
    })

    widget_dict = DictionaryObject({
        NameObject("/FT"): NameObject("/Sig"),
        NameObject("/Type"): NameObject("/Annot"),
        NameObject("/Subtype"): NameObject("/Widget"),
        NameObject("/F"): NumberObject(132),
        NameObject("/T"): TextStringObject(field_name),
        NameObject("/V"): IndirectObject(v_id, 0, reader),
        NameObject("/P"): page0_ref,
        NameObject("/Rect"): ArrayObject([
            NumberObject(0),
            NumberObject(0),
            NumberObject(0),
            NumberObject(0),
        ]),
        NameObject("/AP"): IndirectObject(ap_id, 0, reader),
    })

    widget_ref = IndirectObject(widget_id, 0, reader)
    objects: Dict[int, Any] = {
        v_id: v_bytes,
        ap_form_id: ap_form,
        ap_id: ap_dict,
        widget_id: widget_dict,
    }

    # Actualizar /AcroForm /Fields y /SigFlags = 3
    if "/AcroForm" in root_obj:
        af_raw = dict.__getitem__(root_obj, "/AcroForm")
        af_obj = root_obj["/AcroForm"].get_object()
        af_copy = DictionaryObject({k: dict.__getitem__(af_obj, k) for k in af_obj.keys()})
        old_fields = af_obj["/Fields"].get_object() if "/Fields" in af_obj else []
        af_copy[NameObject("/Fields")] = ArrayObject(list(old_fields) + [widget_ref])
        af_copy[NameObject("/SigFlags")] = NumberObject(3)

        if isinstance(af_raw, IndirectObject):
            objects[af_raw.idnum] = af_copy
        else:
            root_copy = DictionaryObject({k: dict.__getitem__(root_obj, k) for k in root_obj.keys()})
            root_copy[NameObject("/AcroForm")] = af_copy
            objects[root_ref.idnum] = root_copy
    else:
        af_copy = DictionaryObject({
            NameObject("/Fields"): ArrayObject([widget_ref]),
            NameObject("/SigFlags"): NumberObject(3),
        })
        root_copy = DictionaryObject({k: dict.__getitem__(root_obj, k) for k in root_obj.keys()})
        root_copy[NameObject("/AcroForm")] = af_copy
        objects[root_ref.idnum] = root_copy

    # Actualizar /Annots de la primera página
    if "/Annots" in page0:
        annots_raw = dict.__getitem__(page0, "/Annots")
        annots_arr = page0["/Annots"].get_object()
        new_annots = ArrayObject(list(annots_arr) + [widget_ref])
        if isinstance(annots_raw, IndirectObject):
            objects[annots_raw.idnum] = new_annots
        else:
            p0_copy = DictionaryObject({k: dict.__getitem__(page0, k) for k in page0.keys()})
            p0_copy[NameObject("/Annots")] = new_annots
            objects[page0_ref.idnum] = p0_copy
    else:
        p0_copy = DictionaryObject({k: dict.__getitem__(page0, k) for k in page0.keys()})
        p0_copy[NameObject("/Annots")] = ArrayObject([widget_ref])
        objects[page0_ref.idnum] = p0_copy

    raw_skeleton, offsets = _append_incremental_revision(pdf_bytes, objects, next_id, reader)
    out = bytearray(raw_skeleton)
    v_start = offsets[v_id]
    header_len = len(f"{v_id} 0 obj\n".encode("ascii"))
    v_dict_start = v_start + header_len

    lt_pos = out.index(b"/Contents <", v_dict_start) + len(b"/Contents ")
    gt_pos = lt_pos + 1 + contents_hex_len
    br_pos = out.index(BR_PLACEHOLDER, v_dict_start)
    return out, lt_pos, gt_pos, br_pos, contents_hex_len


def renew_pdf_to_lta(
    pdf_bytes: bytes,
    tsa_client: Optional[TSASinpeClient] = None,
    algorithm: str = "sha256",
    url_cache: Optional[Dict[str, Tuple[float, bytes]]] = None,
    token_buffer_bytes: int = DEFAULT_TOKEN_BUFFER_BYTES,
) -> RenewalResult:
    """
    Ejecuta la renovación completa PAdES-B-LT (/DSS) + PAdES-B-LTA (/DocTimeStamp)
    sobre un PDF en memoria utilizando el cliente TSA-SINPE configurado.
    """
    client = tsa_client or TSASinpeClient()

    try:
        reader_check = pypdf.PdfReader(io.BytesIO(pdf_bytes))
        if reader_check.is_encrypted:
            try:
                if reader_check.decrypt("") == 0:
                    raise ValueError("El PDF está protegido con contraseña.")
            except Exception:
                return RenewalResult(
                    success=False,
                    original_profile="Desconocido",
                    new_profile="Desconocido",
                    field_name=None,
                    hash_algorithm=algorithm,
                    tsa_timestamp_utc=None,
                    tsa_policy_oid=None,
                    tsa_serial_number=None,
                    dss_updated=False,
                    dss_counts={"certs": 0, "crls": 0, "ocsps": 0},
                    effective_protection_until=None,
                    output_pdf_bytes=None,
                    pre_inspection={},
                    post_inspection=None,
                    error_message="El documento PDF está cifrado o protegido con contraseña; descífrelos antes de aplicar sellado PAdES-B-LTA.",
                )
        if len(reader_check.pages) == 0:
            raise ValueError("El documento PDF no contiene páginas válidas.")
    except Exception as exc:
        return RenewalResult(
            success=False,
            original_profile="Desconocido",
            new_profile="Desconocido",
            field_name=None,
            hash_algorithm=algorithm,
            tsa_timestamp_utc=None,
            tsa_policy_oid=None,
            tsa_serial_number=None,
            dss_updated=False,
            dss_counts={"certs": 0, "crls": 0, "ocsps": 0},
            effective_protection_until=None,
            output_pdf_bytes=None,
            pre_inspection={},
            post_inspection=None,
            error_message=f"No se pudo leer el documento PDF: {exc}",
        )

    effective_cache = url_cache if url_cache is not None else {}
    pre_report = inspect_pdf(pdf_bytes, fetch_remote=True, url_cache=effective_cache)
    pool: CertificatePool = pre_report.pop("_pool")
    original_profile = pre_report["pades_profile"]

    # Incorporar certificados y CRLs de la TSA activa dentro del pool antes de congelar /DSS
    _populate_active_tsa_evidence(client, pool, algorithm=algorithm)

    # Revisión 1: Incorporar o enriquecer diccionario /DSS (PAdES-B-LT)
    pdf_after_dss, dss_updated, dss_counts = _append_dss_revision(pdf_bytes, pool)

    # Revisión 2: Añadir campo /DocTimeStamp y reservar /ByteRange + /Contents
    reader_dss = pypdf.PdfReader(io.BytesIO(pdf_after_dss))
    field_name = _next_signature_field_name(reader_dss)

    buf_size = token_buffer_bytes
    ts_res: Optional[TimestampResult] = None
    final_pdf: Optional[bytes] = None

    for _attempt in range(2):
        out, lt_pos, gt_pos, br_pos, contents_hex_len = _build_doctimestamp_skeleton(
            pdf_after_dss,
            field_name=field_name,
            buffer_bytes=buf_size,
        )
        total_len = len(out)
        len1 = lt_pos
        start2 = gt_pos + 1
        len2 = total_len - start2

        br_text = f"/ByteRange [0 {len1} {start2} {len2}]"
        if len(br_text) > len(BR_PLACEHOLDER):
            raise ValueError("El tamaño del documento excede la capacidad de /ByteRange.")
        br_padded = (br_text[:-1] + (" " * (len(BR_PLACEHOLDER) - len(br_text))) + "]").encode("ascii")
        out[br_pos : br_pos + len(BR_PLACEHOLDER)] = br_padded

        h = hashlib.new(algorithm)
        h.update(out[0:len1])
        h.update(out[start2 : start2 + len2])
        digest = h.digest()

        ts_res = client.request_timestamp(digest=digest, algorithm=algorithm, cert_req=True)
        if not ts_res.is_granted or not ts_res.raw_token_der:
            return RenewalResult(
                success=False,
                original_profile=original_profile,
                new_profile=original_profile,
                field_name=field_name,
                hash_algorithm=algorithm,
                tsa_timestamp_utc=None,
                tsa_policy_oid=None,
                tsa_serial_number=None,
                dss_updated=dss_updated,
                dss_counts=dss_counts,
                effective_protection_until=pre_report.get("effective_protection_until"),
                output_pdf_bytes=None,
                pre_inspection=pre_report,
                post_inspection=None,
                error_message=ts_res.error_message or "La TSA rechazó la solicitud de estampa de tiempo.",
            )

        token_hex = ts_res.raw_token_der.hex()
        if len(token_hex) <= contents_hex_len:
            hex_bytes = token_hex.encode("ascii")
            out[lt_pos + 1 : lt_pos + 1 + len(hex_bytes)] = hex_bytes
            final_pdf = bytes(out)
            break

        # Reintentar automáticamente si el token supera el buffer inicial
        buf_size = len(ts_res.raw_token_der) + 2048

    if final_pdf is None or ts_res is None:
        return RenewalResult(
            success=False,
            original_profile=original_profile,
            new_profile=original_profile,
            field_name=field_name,
            hash_algorithm=algorithm,
            tsa_timestamp_utc=None,
            tsa_policy_oid=None,
            tsa_serial_number=None,
            dss_updated=dss_updated,
            dss_counts=dss_counts,
            effective_protection_until=pre_report.get("effective_protection_until"),
            output_pdf_bytes=None,
            pre_inspection=pre_report,
            post_inspection=None,
            error_message="El tamaño del token RFC 3161 superó el espacio reservado en /Contents.",
        )

    post_report = inspect_pdf_public(final_pdf, fetch_remote=True, url_cache=effective_cache)

    return RenewalResult(
        success=True,
        original_profile=original_profile,
        new_profile=post_report["pades_profile"],
        field_name=field_name,
        hash_algorithm=algorithm,
        tsa_timestamp_utc=ts_res.generated_time.isoformat() if ts_res.generated_time else None,
        tsa_policy_oid=ts_res.policy_oid,
        tsa_serial_number=str(ts_res.serial_number) if ts_res.serial_number is not None else None,
        dss_updated=dss_updated,
        dss_counts=dss_counts,
        effective_protection_until=post_report.get("effective_protection_until"),
        output_pdf_bytes=final_pdf,
        pre_inspection=pre_report,
        post_inspection=post_report,
        error_message=None,
    )

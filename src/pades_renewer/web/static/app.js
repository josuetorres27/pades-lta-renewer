(() => {
  const MAX_BYTES = 50 * 1024 * 1024;
  const dropzone = document.getElementById("dropzone");
  const fileInput = document.getElementById("pdf-input");
  const resultsEl = document.getElementById("results");
  const liveStatus = document.getElementById("live-status");

  let dragDepth = 0;
  const queue = [];
  let processing = false;

  function announce(msg) {
    liveStatus.textContent = "";
    window.requestAnimationFrame(() => {
      liveStatus.textContent = msg;
    });
  }

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function makeChevronSvg() {
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("class", "disclosure-chevron");
    svg.setAttribute("width", "14");
    svg.setAttribute("height", "14");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("fill", "none");
    svg.setAttribute("stroke", "currentColor");
    svg.setAttribute("stroke-width", "2.2");
    svg.setAttribute("stroke-linecap", "round");
    svg.setAttribute("stroke-linejoin", "round");
    svg.setAttribute("aria-hidden", "true");
    const poly = document.createElementNS("http://www.w3.org/2000/svg", "polyline");
    poly.setAttribute("points", "9 18 15 12 9 6");
    svg.appendChild(poly);
    return svg;
  }

  function formatDate(isoStr) {
    if (!isoStr) return "N/D";
    return isoStr.slice(0, 10);
  }

  function formatBytes(bytes) {
    if (!Number.isFinite(bytes)) return "0 B";
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  }

  function validityBadge(status) {
    if (status === "vigente") return { label: "✓ Vigente", cls: "status-ok" };
    if (status === "proximo_a_vencer") return { label: "! Próximo a vencer", cls: "status-warn" };
    if (status === "no_vigente_aun") return { label: "! No vigente aún", cls: "status-warn" };
    return { label: "✕ Vencido", cls: "status-err" };
  }

  function revocationSummary(rev) {
    if (!rev || rev.status === "not_applicable") return "Ancla raíz";
    if (rev.status === "good") return `✓ No revocado (${rev.method || "PKI"})`;
    if (rev.status === "revoked") return `✕ Revocado (${rev.method || "PKI"})`;
    if (rev.status === "unknown") return `! Estado desconocido (${rev.method || "PKI"})`;
    return "! Revocación no consultable";
  }

  function appendKv(dl, term, value, isMono = false) {
    const dt = el("dt", "", term);
    const dd = el("dd", isMono ? "mono" : "", value || "—");
    dl.append(dt, dd);
  }

  function renderNode(node) {
    const li = el("li", `node-card${node.role === "ca_raiz" ? " is-root" : ""}`);

    const head = el("div", "node-head");
    head.appendChild(el("span", "node-role", node.role_label || node.role));
    const vBadge = validityBadge(node.validity_status);
    head.appendChild(el("span", `status-text ${vBadge.cls}`, `${vBadge.label} · ${revocationSummary(node.revocation)}`));

    const cn = el("p", "node-cn", node.common_name);
    const dates = el(
      "p",
      "node-dates",
      `Vigencia: ${formatDate(node.not_before)} a ${formatDate(node.not_after)} · Firma emisor: ${
        node.signature_verified ? "✓ verificada" : "✕ sin verificar"
      }`
    );

    const nodeDetails = el("details", "node-disclosure");
    const nodeSummary = el("summary", "node-summary");
    nodeSummary.append(makeChevronSvg(), el("span", "", "Detalles técnicos, políticas y efecto ante caída"));

    const dl = el("dl", "kv-grid");
    appendKv(dl, "Sujeto (DN)", node.subject_dn);
    appendKv(dl, "Emisor (DN)", node.issuer_dn);
    appendKv(dl, "Número de serie", `${node.serial_number_hex} (${node.serial_number_dec})`, true);
    appendKv(
      dl,
      "Algoritmos",
      `${node.key_algorithm}${node.key_size_bits ? ` ${node.key_size_bits} bits` : ""} · ${node.signature_algorithm}`
    );
    if (node.key_usage && node.key_usage.length) {
      appendKv(dl, "Uso de clave", node.key_usage.join(", "));
    }
    if (node.extended_key_usage && node.extended_key_usage.length) {
      appendKv(dl, "Uso extendido", node.extended_key_usage.join(", "));
    }

    if (node.policies && node.policies.length) {
      const polDt = el("dt", "", "Políticas (OID)");
      const polDd = el("dd", "");
      const ul = el("ul", "policy-list");
      for (const pol of node.policies) {
        const pli = el("li", "");
        pli.appendChild(el("span", "mono", pol.oid));
        if (pol.explicit_text) {
          pli.appendChild(document.createTextNode(` — ${pol.explicit_text}`));
        }
        if (pol.cps_urls && pol.cps_urls.length) {
          for (const url of pol.cps_urls) {
            if (/^https?:\/\//i.test(url)) {
              pli.appendChild(document.createTextNode(" "));
              const a = el("a", "", "[CPS]");
              a.href = url;
              a.target = "_blank";
              a.rel = "noopener noreferrer";
              pli.appendChild(a);
            }
          }
        }
        ul.appendChild(pli);
      }
      polDd.appendChild(ul);
      dl.append(polDt, polDd);
    }

    if (node.revocation && node.revocation.source_url) {
      appendKv(
        dl,
        "Evidencia revocación",
        `${node.revocation.method}: ${node.revocation.source_url} (thisUpdate ${formatDate(
          node.revocation.this_update
        )}${node.revocation.next_update ? `, nextUpdate ${formatDate(node.revocation.next_update)}` : ""})`
      );
    }
    if (node.ocsp_urls && node.ocsp_urls.length) {
      appendKv(dl, "URLs OCSP", node.ocsp_urls.join(" | "), true);
    }
    if (node.crl_urls && node.crl_urls.length) {
      appendKv(dl, "URLs CRL", node.crl_urls.join(" | "), true);
    }
    if (node.aia_ca_issuers && node.aia_ca_issuers.length) {
      appendKv(dl, "AIA CA Issuers", node.aia_ca_issuers.join(" | "), true);
    }
    appendKv(dl, "Huella SHA-256", node.sha256_fingerprint, true);

    nodeDetails.append(nodeSummary, dl);

    if (node.impact_explanation) {
      nodeDetails.appendChild(
        el("p", "impact-box", `Impacto en la cadena: ${node.impact_explanation}`)
      );
    }

    li.append(head, cn, dates, nodeDetails);
    return li;
  }

  function renderBranch(branch) {
    const wrap = el("div", "branch-block");
    const kindTitle =
      branch.branch_type === "tsa"
        ? "Rama de Autoridad de Sellado de Tiempo (TSA → CA Política → CA Raíz)"
        : "Rama del Firmante (Firmante → CA Emisora → CA Política → CA Raíz)";
    const rootInfo = branch.reaches_root
      ? `✓ Alcanza ${branch.root_common_name}`
      : "✕ Cadena incompleta hasta raíz";
    wrap.appendChild(el("p", "branch-title", `${kindTitle} · ${rootInfo}`));

    const ul = el("ul", "node-list");
    for (const node of branch.nodes || []) {
      ul.appendChild(renderNode(node));
    }
    wrap.appendChild(ul);
    return wrap;
  }

  function renderSuccessCard(card, data) {
    card.className = "result-card";
    card.textContent = "";

    const top = el("div", "result-top");
    const meta = el("div", "result-meta");
    meta.appendChild(el("p", "result-filename", data.filename));

    const protDate = formatDate(data.effective_protection_until);
    const conf = el("p", "result-confirmation");
    conf.appendChild(
      el(
        "span",
        "status-text status-ok",
        `✓ Renovado (${data.original_profile} → ${data.new_profile})`
      )
    );
    conf.appendChild(
      el("span", "status-pending", `· Vigente hasta ${protDate} · ${formatBytes(data.renewed_size_bytes)}`)
    );
    meta.appendChild(conf);

    const dlLink = el("a", "download-link", "Descargar PDF");
    dlLink.href = data.download_url;
    dlLink.download = data.download_name;

    top.append(meta, dlLink);
    card.appendChild(top);

    const details = el("details", "chain-disclosure");
    const summary = el("summary", "chain-summary");
    summary.append(
      makeChevronSvg(),
      el("span", "", "Ver cadena completa hasta la raíz, políticas y detalles TSA")
    );

    const body = el("div", "chain-body");
    const dss = data.dss_counts || {};
    body.appendChild(
      el(
        "p",
        "tech-summary-line",
        `Campo inyectado: ${data.field_name} (/ETSI.RFC3161) · Evidencias /DSS: ${
          dss.certs || 0
        } certificados, ${dss.crls || 0} CRLs, ${dss.ocsps || 0} OCSPs · Serie TST: ${
          data.tsa_serial_number || "N/D"
        } · Política TSA: ${data.tsa_policy_oid || "N/D"}`
      )
    );

    const sigs = (data.post_inspection && data.post_inspection.signatures) || [];
    for (const sig of sigs) {
      const sec = el("div", "sig-section");
      const kindLabel =
        sig.kind === "doc_timestamp"
          ? "Sello documental RFC 3161 (/DocTimeStamp)"
          : "Firma digital (/Sig)";
      sec.appendChild(el("p", "sig-header", `${sig.field_name} · ${kindLabel}`));

      const tst = sig.timestamp || sig.embedded_timestamp;
      const hashStatus = sig.byterange_hash_valid ? "✓ /ByteRange íntegro" : "✕ /ByteRange inválido";
      const tstInfo = tst
        ? ` · Sello TSA: ${tst.gen_time_cr || tst.gen_time_utc} · OID ${tst.policy_oid} · ${tst.hash_algorithm}`
        : "";
      sec.appendChild(
        el("p", "sig-submeta", `${sig.subfilter || sig.type} · ${hashStatus}${tstInfo}`)
      );

      for (const br of sig.branches || []) {
        sec.appendChild(renderBranch(br));
      }
      body.appendChild(sec);
    }

    details.append(summary, body);
    card.appendChild(details);
  }

  function renderErrorCard(card, filename, errMsg) {
    card.className = "result-card is-error";
    card.setAttribute("role", "alert");
    card.textContent = "";
    const meta = el("div", "result-meta");
    meta.appendChild(el("p", "result-filename", filename));
    meta.appendChild(el("p", "result-confirmation status-text status-err", `✕ Error: ${errMsg}`));
    card.appendChild(meta);
  }

  async function processQueue() {
    if (processing) return;
    processing = true;

    while (queue.length > 0) {
      const { file, card } = queue.shift();
      announce(`Procesando ${file.name}...`);

      if (!file.name.toLowerCase().endsWith(".pdf") && file.type !== "application/pdf") {
        renderErrorCard(card, file.name, "Solo se aceptan archivos PDF.");
        announce(`Error en ${file.name}: formato no soportado.`);
        continue;
      }

      if (file.size === 0) {
        renderErrorCard(card, file.name, "El archivo está vacío.");
        announce(`Error en ${file.name}: archivo vacío.`);
        continue;
      }

      if (file.size > MAX_BYTES) {
        renderErrorCard(card, file.name, "El archivo supera el límite de 50 MB.");
        announce(`Error en ${file.name}: excede 50 MB.`);
        continue;
      }

      const fd = new FormData();
      fd.append("file", file, file.name);

      try {
        const res = await fetch("/api/renew", { method: "POST", body: fd });
        const payload = await res.json().catch(() => ({}));
        if (!res.ok) {
          const msg = payload.error || `Error del servidor (${res.status})`;
          renderErrorCard(card, file.name, msg);
          announce(`Error en ${file.name}: ${msg}`);
        } else {
          renderSuccessCard(card, payload);
          announce(`${file.name} renovado correctamente a ${payload.new_profile}.`);
        }
      } catch (_err) {
        renderErrorCard(card, file.name, "No se pudo conectar con el servicio local.");
        announce(`Error de conexión procesando ${file.name}.`);
      }
    }

    processing = false;
  }

  function enqueueFiles(fileList) {
    for (const file of Array.from(fileList)) {
      const card = el("article", "result-card");
      card.appendChild(el("p", "result-filename", file.name));
      card.appendChild(
        el("p", "result-confirmation status-pending", "Solicitando sello TSA-SINPE e inyectando /DSS…")
      );
      resultsEl.prepend(card);
      queue.push({ file, card });
    }
    processQueue();
  }

  // Evitar que soltar archivos fuera de la zona abra o navegue en la pestaña
  window.addEventListener("dragover", (e) => {
    e.preventDefault();
  });
  window.addEventListener("drop", (e) => {
    e.preventDefault();
  });

  dropzone.addEventListener("dragenter", (e) => {
    e.preventDefault();
    dragDepth += 1;
    dropzone.classList.add("is-dragover");
  });

  dropzone.addEventListener("dragover", (e) => {
    e.preventDefault();
    if (e.dataTransfer) {
      e.dataTransfer.dropEffect = "copy";
    }
  });

  dropzone.addEventListener("dragleave", (e) => {
    if (!dropzone.contains(e.relatedTarget)) {
      dragDepth = 0;
      dropzone.classList.remove("is-dragover");
    } else {
      dragDepth = Math.max(0, dragDepth - 1);
      if (dragDepth === 0) dropzone.classList.remove("is-dragover");
    }
  });

  dropzone.addEventListener("drop", (e) => {
    e.preventDefault();
    e.stopPropagation();
    dragDepth = 0;
    dropzone.classList.remove("is-dragover");
    if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length) {
      enqueueFiles(e.dataTransfer.files);
    }
  });

  fileInput.addEventListener("change", () => {
    if (fileInput.files && fileInput.files.length) {
      enqueueFiles(fileInput.files);
      fileInput.value = "";
    }
  });
})();

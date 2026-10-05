// Page-world content script. Runs at document_start in the MAIN world so
// the wrapped fetch/XHR replace the page's own globals before any app code
// reads them.
//
// HTTPS request/response bodies are NOT visible to the webRequest API; this
// wrapper is the only path by which the extension can capture them on
// modern browsers.

(function () {
  if (window.__pencheff_wrapped) return;
  window.__pencheff_wrapped = true;

  function send(flow) {
    try {
      window.postMessage({ __pencheff: true, type: "pencheff/page-flow", flow }, "*");
    } catch {}
  }

  // ── fetch wrapper ──────────────────────────────────────────────────
  const _fetch = window.fetch;
  window.fetch = async function (input, init) {
    const started = performance.now();
    let req;
    try {
      req = input instanceof Request ? input.clone() : new Request(input, init);
    } catch {
      req = null;
    }
    let body = null;
    if (init && typeof init.body === "string") body = init.body;
    if (req && body == null) {
      try { body = await req.clone().text(); } catch {}
    }
    const url = (req && req.url) || (typeof input === "string" ? input : "");
    const method = ((req && req.method) || (init && init.method) || "GET").toUpperCase();
    const headers = {};
    if (req && req.headers) {
      try { req.headers.forEach((v, k) => (headers[k] = v)); } catch {}
    }
    let resp;
    try {
      resp = await _fetch(input, init);
    } catch (e) {
      send({
        method, url, request_headers: headers, request_body: body,
        response_status: null, duration_ms: Math.round(performance.now() - started),
        captured_at: new Date().toISOString(),
      });
      throw e;
    }
    const cloned = resp.clone();
    const text = await cloned.text().catch(() => "");
    const respHeaders = {};
    try { resp.headers.forEach((v, k) => (respHeaders[k] = v)); } catch {}
    send({
      method, url, request_headers: headers, request_body: body,
      response_status: resp.status, response_headers: respHeaders,
      response_body: text, response_size: text.length,
      duration_ms: Math.round(performance.now() - started),
      captured_at: new Date().toISOString(),
    });
    return resp;
  };

  // ── XMLHttpRequest wrapper ─────────────────────────────────────────
  const X = window.XMLHttpRequest;
  function PXR() {
    const xhr = new X();
    let _method = "GET", _url = "", _started = 0, _sendBody = null;
    const _headers = {};
    const open = xhr.open;
    xhr.open = function (m, u) {
      _method = (m || "GET").toUpperCase();
      _url = u;
      return open.apply(xhr, arguments);
    };
    const setRequestHeader = xhr.setRequestHeader;
    xhr.setRequestHeader = function (k, v) {
      _headers[k] = v;
      return setRequestHeader.apply(xhr, arguments);
    };
    const send = xhr.send;
    xhr.send = function (body) {
      _started = performance.now();
      try { _sendBody = typeof body === "string" ? body : null; } catch {}
      xhr.addEventListener("loadend", function () {
        send_evt({
          method: _method, url: _url,
          request_headers: _headers, request_body: _sendBody,
          response_status: xhr.status,
          response_headers: parseHeaders(xhr.getAllResponseHeaders()),
          response_body: typeof xhr.response === "string" ? xhr.response : null,
          response_size: typeof xhr.response === "string" ? xhr.response.length : null,
          duration_ms: Math.round(performance.now() - _started),
          captured_at: new Date().toISOString(),
        });
      });
      return send.apply(xhr, arguments);
    };
    return xhr;
  }
  PXR.prototype = X.prototype;
  window.XMLHttpRequest = PXR;

  function send_evt(flow) { send(flow); }

  function parseHeaders(s) {
    const out = {};
    (s || "").trim().split(/\r?\n/).forEach((line) => {
      const idx = line.indexOf(":");
      if (idx > 0) out[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
    });
    return out;
  }

  // Forward page-world messages into the extension via a bridge — the
  // background service worker doesn't see window.postMessage directly.
  window.addEventListener("message", function (ev) {
    if (!ev.data || !ev.data.__pencheff) return;
    try {
      // chrome.runtime is exposed in MAIN world via a polyfill; on Chrome
      // we also dispatch a CustomEvent the isolated world picks up.
      if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.sendMessage) {
        chrome.runtime.sendMessage(ev.data);
      } else {
        document.dispatchEvent(new CustomEvent("pencheff:flow", { detail: ev.data }));
      }
    } catch {}
  });
})();

// Pencheff browser extension — background service worker.
//
// Captures every HTTP request (and matching response) the browser issues
// via the webRequest API. Body capture for HTTPS responses is not available
// to webRequest in MV3, so we additionally inject a content script
// (content.js) that wraps fetch/XHR in the page world. The two streams are
// merged here, batched, and POSTed to the engagement's ingest endpoint.

const FLUSH_INTERVAL_MS = 2000;
const MAX_BATCH = 50;
const REQUEST_BODY_CAP = 256 * 1024;
const RESPONSE_BODY_CAP = 1024 * 1024;

const flowsById = new Map();   // requestId → flow record
const pageBodies = new Map();  // request URL+method+ts → {req, res} (from content.js)
const queue = [];              // batched flows ready for upload
let flushTimer = null;

async function getStorage(keys) {
  return new Promise((resolve) => chrome.storage.local.get(keys, resolve));
}

async function setStorage(values) {
  return new Promise((resolve) => chrome.storage.local.set(values, resolve));
}

async function getApiState() {
  const { ingestToken, apiBase, paused } = await getStorage([
    "ingestToken",
    "apiBase",
    "paused",
  ]);
  return {
    ingestToken: ingestToken || "",
    apiBase: (apiBase || "").replace(/\/$/, ""),
    paused: !!paused,
  };
}

function _truncate(s, cap) {
  if (typeof s !== "string") return undefined;
  if (s.length <= cap) return s;
  return s.slice(0, cap);
}

function ensureFlow(requestId) {
  let f = flowsById.get(requestId);
  if (!f) {
    f = {
      method: "GET",
      url: "",
      request_headers: {},
      request_body: null,
      response_status: null,
      response_headers: {},
      response_body: null,
      duration_ms: null,
      tab_id: null,
      frame_id: null,
      initiator: null,
      body_capture: "limited",
      _started: Date.now(),
    };
    flowsById.set(requestId, f);
  }
  return f;
}

chrome.webRequest.onBeforeRequest.addListener(
  (d) => {
    const f = ensureFlow(d.requestId);
    f.method = d.method;
    f.url = d.url;
    f.tab_id = d.tabId;
    f.frame_id = d.frameId;
    f.initiator = d.initiator || null;
    if (d.requestBody && d.requestBody.raw && d.requestBody.raw[0]) {
      try {
        const decoder = new TextDecoder();
        const body = d.requestBody.raw
          .map((p) => (p.bytes ? decoder.decode(p.bytes) : ""))
          .join("");
        f.request_body = _truncate(body, REQUEST_BODY_CAP);
      } catch {}
    }
  },
  { urls: ["<all_urls>"] },
  ["requestBody"]
);

chrome.webRequest.onSendHeaders.addListener(
  (d) => {
    const f = ensureFlow(d.requestId);
    if (d.requestHeaders) {
      f.request_headers = {};
      for (const h of d.requestHeaders) f.request_headers[h.name] = h.value || "";
    }
  },
  { urls: ["<all_urls>"] },
  ["requestHeaders"]
);

chrome.webRequest.onHeadersReceived.addListener(
  (d) => {
    const f = ensureFlow(d.requestId);
    f.response_status = d.statusCode;
    if (d.responseHeaders) {
      f.response_headers = {};
      for (const h of d.responseHeaders) f.response_headers[h.name] = h.value || "";
    }
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);

chrome.webRequest.onCompleted.addListener(
  (d) => {
    const f = ensureFlow(d.requestId);
    f.duration_ms = Date.now() - (f._started || Date.now());
    f.captured_at = new Date().toISOString();
    delete f._started;
    queue.push(f);
    flowsById.delete(d.requestId);
    scheduleFlush();
  },
  { urls: ["<all_urls>"] }
);

chrome.webRequest.onErrorOccurred.addListener(
  (d) => {
    flowsById.delete(d.requestId);
  },
  { urls: ["<all_urls>"] }
);

// Receive bodies from content-script's fetch/XHR wrapper.
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || msg.type !== "pencheff/page-flow") return;
  const flow = msg.flow || {};
  flow.tab_id = sender.tab && sender.tab.id;
  flow.frame_id = sender.frameId;
  flow.body_capture = "full";
  flow.captured_at = flow.captured_at || new Date().toISOString();
  flow.request_body = _truncate(flow.request_body, REQUEST_BODY_CAP);
  flow.response_body = _truncate(flow.response_body, RESPONSE_BODY_CAP);
  queue.push(flow);
  scheduleFlush();
});

function scheduleFlush() {
  if (queue.length >= MAX_BATCH) return void flush();
  if (flushTimer) return;
  flushTimer = setTimeout(() => {
    flushTimer = null;
    flush();
  }, FLUSH_INTERVAL_MS);
}

async function flush() {
  if (queue.length === 0) return;
  const { ingestToken, apiBase, paused } = await getApiState();
  if (paused || !ingestToken || !apiBase) return;
  const batch = queue.splice(0, MAX_BATCH);
  try {
    const r = await fetch(`${apiBase}/ingest/extension/batch`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${ingestToken}`,
      },
      body: JSON.stringify({ flows: batch }),
    });
    if (r.ok) {
      await bumpCounter(batch.length);
    } else {
      // Re-queue on transient failure.
      queue.unshift(...batch);
    }
  } catch {
    queue.unshift(...batch);
  }
}

async function bumpCounter(n) {
  const { sentCount } = await getStorage(["sentCount"]);
  await setStorage({ sentCount: (sentCount || 0) + n });
}

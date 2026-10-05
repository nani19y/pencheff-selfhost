// Pencheff popup — pair with an engagement and toggle pause.

async function getStorage(keys) {
  return new Promise((r) => chrome.storage.local.get(keys, r));
}
async function setStorage(values) {
  return new Promise((r) => chrome.storage.local.set(values, r));
}

const apiBaseEl = document.getElementById("apiBase");
const pairingEl = document.getElementById("pairing");
const pairBtn = document.getElementById("pair");
const pauseBtn = document.getElementById("pause");
const statusEl = document.getElementById("status");
const sentEl = document.getElementById("sent");

async function refresh() {
  const { apiBase, ingestToken, paused, sentCount, engagementId } =
    await getStorage(["apiBase", "ingestToken", "paused", "sentCount", "engagementId"]);
  apiBaseEl.value = apiBase || "";
  if (ingestToken) {
    statusEl.textContent = `Paired ✓  Engagement ${(engagementId || "").slice(0, 8) || "—"}`;
  } else {
    statusEl.textContent = "Not paired.";
  }
  pauseBtn.textContent = paused ? "Resume" : "Pause";
  sentEl.textContent = String(sentCount || 0);
}

pairBtn.addEventListener("click", async () => {
  const apiBase = (apiBaseEl.value || "").replace(/\/$/, "");
  const token = (pairingEl.value || "").trim();
  if (!apiBase || !token) {
    statusEl.textContent = "Enter API base + ingest token.";
    return;
  }
  // Validate the token by sending a tiny no-op batch.
  try {
    const r = await fetch(`${apiBase}/ingest/extension/batch`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({ flows: [] }),
    });
    if (!r.ok) {
      statusEl.textContent = `Token rejected (${r.status}).`;
      return;
    }
    await setStorage({ apiBase, ingestToken: token, paused: false });
    pairingEl.value = "";
    refresh();
  } catch (e) {
    statusEl.textContent = `Error: ${e.message}`;
  }
});

pauseBtn.addEventListener("click", async () => {
  const { paused } = await getStorage(["paused"]);
  await setStorage({ paused: !paused });
  refresh();
});

refresh();
setInterval(refresh, 2000);

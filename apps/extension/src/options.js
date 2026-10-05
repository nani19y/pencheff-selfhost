async function getStorage(keys) {
  return new Promise((r) => chrome.storage.local.get(keys, r));
}
async function setStorage(values) {
  return new Promise((r) => chrome.storage.local.set(values, r));
}

const scope = document.getElementById("scope");
const paused = document.getElementById("paused");
const save = document.getElementById("save");
const msg = document.getElementById("msg");

(async () => {
  const s = await getStorage(["scope", "paused"]);
  scope.value = (s.scope || []).join("\n");
  paused.checked = !!s.paused;
})();

save.addEventListener("click", async () => {
  await setStorage({
    scope: scope.value.split(/\r?\n/).map((l) => l.trim()).filter(Boolean),
    paused: paused.checked,
  });
  msg.textContent = "Saved.";
  setTimeout(() => (msg.textContent = ""), 1200);
});

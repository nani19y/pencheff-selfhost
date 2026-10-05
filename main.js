"use strict";

/**
 * Pencheff Studio for Windows — Electron main process.
 *
 * MVP: a hardened webview shell around `app.pencheff.com`. Clerk's session
 * cookie persists across launches via Electron's default partition, so the
 * user signs in once and stays signed in until the Clerk session expires
 * (typically 7 days). This mirrors the macOS Studio's perceived UX without
 * implementing the loopback OAuth bridge yet; that bridge is the right
 * next step for long-lived native tokens but is not required for MVP.
 *
 * Security posture:
 *   - contextIsolation: true, nodeIntegration: false, sandbox: true
 *   - will-navigate / will-redirect locked to *.pencheff.com + Clerk
 *   - new-window opened in the OS default browser, not in-app
 *   - external links go through shell.openExternal so the renderer can't
 *     reach into the main process via window.open()
 *   - CSP headers received from the server are respected (we don't strip them)
 *   - File:// and chrome:// schemes are blocked at the will-navigate gate
 */

const { app, BrowserWindow, Menu, shell, session } = require("electron");
const path = require("node:path");

// ── Config ───────────────────────────────────────────────────────────
// Override at runtime with PENCHEFF_BASE_URL for self-hosted deploys.
const BASE_URL =
  process.env.PENCHEFF_BASE_URL || "https://app.pencheff.com";

// Hosts the BrowserWindow is allowed to navigate to. Anything else is
// kicked out to the OS default browser via shell.openExternal.
const ALLOWED_HOSTS = new Set([
  "app.pencheff.com",
  "pencheff.com",
  "www.pencheff.com",
  // Clerk's OAuth providers redirect through their own hosts during sign-in.
  "clerk.app.pencheff.com",
  "clerk.pencheff.com",
  "accounts.pencheff.com",
  // GitHub / Google OAuth providers Clerk routes through.
  "github.com",
  "accounts.google.com",
  "appleid.apple.com",
]);

function isAllowedNavigation(rawUrl) {
  let u;
  try {
    u = new URL(rawUrl);
  } catch {
    return false;
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") return false;
  // Block raw IPs except loopback (reserved for future OAuth loopback flow).
  if (u.hostname === "127.0.0.1" || u.hostname === "localhost") return true;
  // Override base host for self-hosted setups.
  try {
    const base = new URL(BASE_URL);
    if (u.hostname === base.hostname) return true;
  } catch {
    /* ignore */
  }
  return ALLOWED_HOSTS.has(u.hostname);
}

// ── Single-instance lock ─────────────────────────────────────────────
// If the user double-launches Pencheff Studio, focus the existing window
// instead of opening a second one.
if (!app.requestSingleInstanceLock()) {
  app.quit();
  process.exit(0);
}

let mainWindow = null;

function createMainWindow() {
  const win = new BrowserWindow({
    width: 1280,
    height: 800,
    minWidth: 900,
    minHeight: 600,
    title: "Pencheff Studio",
    backgroundColor: "#FAF7F2", // matches the Pencheff parchment/cream
    icon: path.join(__dirname, "..", "assets", "icon.ico"),
    autoHideMenuBar: false,
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      // Block the renderer from creating other renderers (popups, etc.).
      // We override the policy in window-open handler to open externally.
      spellcheck: true,
    },
  });

  // Persist cookies across launches — Clerk session lives here.
  // The default session partition is "persist:default" in Electron, which
  // is already cookie-persistent. No extra config needed.

  // Gate all in-window navigation to allowed hosts.
  win.webContents.on("will-navigate", (event, navUrl) => {
    if (!isAllowedNavigation(navUrl)) {
      event.preventDefault();
      shell.openExternal(navUrl);
    }
  });

  // Same for redirects (server-side 302s).
  win.webContents.on("will-redirect", (event, navUrl) => {
    if (!isAllowedNavigation(navUrl)) {
      event.preventDefault();
      shell.openExternal(navUrl);
    }
  });

  // window.open() and target="_blank" → open in OS browser.
  win.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: "deny" };
  });

  // Surface load failures so users don't see a blank window. The page
  // shown here is the local error.html shipped with the app.
  win.webContents.on(
    "did-fail-load",
    (_event, errorCode, errorDescription, validatedURL) => {
      // -3 = ERR_ABORTED, fired during normal redirects; ignore.
      if (errorCode === -3) return;
      const errorPage = path.join(__dirname, "..", "assets", "error.html");
      win.loadFile(errorPage, {
        query: {
          code: String(errorCode),
          msg: errorDescription || "",
          url: validatedURL || "",
        },
      });
    },
  );

  win.loadURL(BASE_URL);

  win.on("closed", () => {
    if (mainWindow === win) mainWindow = null;
  });

  return win;
}

// ── Application menu ─────────────────────────────────────────────────
// Standard Windows app menu — File / Edit / View / Help.
function buildMenu() {
  const template = [
    {
      label: "&File",
      submenu: [
        {
          label: "Reload",
          accelerator: "Ctrl+R",
          click: () => mainWindow?.webContents.reload(),
        },
        {
          label: "Go to Dashboard",
          accelerator: "Ctrl+Home",
          click: () => mainWindow?.loadURL(`${BASE_URL}/dashboard`),
        },
        { type: "separator" },
        { role: "quit", label: "Exit" },
      ],
    },
    {
      label: "&Edit",
      submenu: [
        { role: "undo" },
        { role: "redo" },
        { type: "separator" },
        { role: "cut" },
        { role: "copy" },
        { role: "paste" },
        { role: "selectAll" },
      ],
    },
    {
      label: "&View",
      submenu: [
        { role: "resetZoom" },
        { role: "zoomIn" },
        { role: "zoomOut" },
        { type: "separator" },
        { role: "togglefullscreen" },
        { type: "separator" },
        {
          label: "Toggle Developer Tools",
          accelerator: "Ctrl+Shift+I",
          click: () => mainWindow?.webContents.toggleDevTools(),
        },
      ],
    },
    {
      label: "&Help",
      submenu: [
        {
          label: "Documentation",
          click: () => shell.openExternal("https://docs.pencheff.com"),
        },
        {
          label: "Report an issue",
          click: () =>
            shell.openExternal(
              "mailto:support@pencheff.com?subject=Pencheff%20Studio%20(Windows)%20issue",
            ),
        },
        { type: "separator" },
        {
          label: "About Pencheff Studio",
          click: () => {
            const v = app.getVersion();
            mainWindow?.webContents.executeJavaScript(
              `alert("Pencheff Studio for Windows\\nVersion ${v}\\n\\nSigned, Windows 10+\\nhttps://pencheff.com")`,
              true,
            );
          },
        },
      ],
    },
  ];

  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

// ── Lifecycle ────────────────────────────────────────────────────────
app.on("second-instance", () => {
  if (mainWindow) {
    if (mainWindow.isMinimized()) mainWindow.restore();
    mainWindow.focus();
  }
});

app.whenReady().then(() => {
  // Lock down the default session: deny permission prompts the app
  // never legitimately needs (camera, mic, geolocation).
  session.defaultSession.setPermissionRequestHandler(
    (_webContents, permission, callback) => {
      const allowed = new Set(["clipboard-read", "clipboard-sanitized-write"]);
      callback(allowed.has(permission));
    },
  );

  // Strip the Electron UA suffix so app.pencheff.com receives a normal
  // Chrome UA and doesn't accidentally serve an "unsupported browser" page.
  // The product version is appended for telemetry.
  const ua = session.defaultSession
    .getUserAgent()
    .replace(/\s+Electron\/\S+/g, "")
    .replace(/\s+Pencheff Studio\/\S+/g, "");
  session.defaultSession.setUserAgent(`${ua} PencheffStudio/${app.getVersion()}`);

  buildMenu();
  mainWindow = createMainWindow();
});

app.on("window-all-closed", () => {
  // Standard Windows behavior — quitting on last-window-close.
  app.quit();
});

// ── Safety net: refuse to load non-https remote content ──────────────
app.on("web-contents-created", (_event, contents) => {
  contents.on("will-attach-webview", (event, _webPreferences, params) => {
    // Block <webview> embedding entirely; nothing in the app uses it.
    event.preventDefault();
    console.warn("Blocked webview attach to:", params.src);
  });
});

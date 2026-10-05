"use strict";

/**
 * Preload script — runs in an isolated world with access to a limited set
 * of Node primitives, exposed to the renderer via contextBridge.
 *
 * MVP exposes nothing — the renderer talks directly to app.pencheff.com
 * over HTTPS and doesn't need any native bridge. Reserved here so future
 * work (FileMonitor / DeviceMonitor / local-scan) has a place to land.
 */

const { contextBridge } = require("electron");

contextBridge.exposeInMainWorld("pencheffStudio", {
  platform: "win32",
  version: process.env.npm_package_version || "unknown",
});

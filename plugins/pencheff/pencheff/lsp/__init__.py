"""Pencheff Language Server Protocol implementation.

Hand-rolled LSP over stdio so VSCode, JetBrains (via LSP4IJ), Vim/Neovim,
Emacs, and any other LSP-aware editor can surface Pencheff findings as
inline diagnostics. No external dependencies — the JSON-RPC surface is
small enough that pulling in pygls would be more weight than benefit.

The server reads scan results from the user's ~/.pencheff/history/
directory (the same location written by ``pencheff.core.scan_history``)
and republishes them whenever the scan history changes on disk. That
means the IDE picks up findings the moment ``pencheff scan`` finishes —
no extra wiring required.
"""

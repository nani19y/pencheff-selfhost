# Pencheff for VSCode

Inline security findings from the [Pencheff](https://github.com/BalaSriharsha-Ch/pencheff) agent — SCA, SAST, DAST, LLM red team — surfaced as VSCode diagnostics. Powered by the `pencheff lsp` Language Server.

## Install (developer build)

```bash
cd apps/vscode
npm install
npm run compile
npm run package          # produces pencheff-vscode-0.1.0.vsix
code --install-extension pencheff-vscode-0.1.0.vsix
```

## Configure

Set the path to the `pencheff` CLI in VSCode settings if it's not on `PATH`:

```jsonc
{
  "pencheff.serverPath": "/absolute/path/to/pencheff"
}
```

## How it works

1. The extension launches `pencheff lsp` as a child process and speaks LSP over stdio.
2. The server tails `~/.pencheff/history/*.json` (where `pencheff scan` writes results) and republishes findings any time the directory changes.
3. SCA findings highlight the offending package line in your manifest. SAST findings highlight the line carrying the autofix payload. DAST findings against remote URLs are not surfaced inline (they have no local file to attach to).

## Commands

- **Pencheff: Refresh findings** — force a republish of diagnostics.
- **Pencheff: Restart language server** — kill and re-spawn the LSP process.

## Limitations (v0.1)

- No quick-fix lightbulbs yet — the data is shipped over the wire (`diagnostic.data.remediation`) but the code-action provider is not wired.
- No on-keystroke scanning. Run `pencheff scan` from your terminal to refresh findings; the LSP picks up the change within ~1 second.

## License

MIT

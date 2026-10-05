import * as path from "path";
import * as vscode from "vscode";
import {
  LanguageClient,
  LanguageClientOptions,
  ServerOptions,
  TransportKind,
  RevealOutputChannelOn,
} from "vscode-languageclient/node";

let client: LanguageClient | undefined;

export async function activate(context: vscode.ExtensionContext): Promise<void> {
  const config = vscode.workspace.getConfiguration("pencheff");
  const serverPath = config.get<string>("serverPath", "pencheff");

  // The Pencheff LSP server is launched as `pencheff lsp`. We hand it the
  // workspace root via env var as a belt-and-braces fallback for editors
  // whose LSP client doesn't pass `rootUri` (rare, but documented).
  const serverEnv: NodeJS.ProcessEnv = {
    ...process.env,
    PENCHEFF_LSP_WORKSPACE: vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? "",
  };

  const serverOptions: ServerOptions = {
    run: {
      command: serverPath,
      args: ["lsp"],
      transport: TransportKind.stdio,
      options: { env: serverEnv },
    },
    debug: {
      command: serverPath,
      args: ["lsp"],
      transport: TransportKind.stdio,
      options: { env: serverEnv },
    },
  };

  const clientOptions: LanguageClientOptions = {
    // The LSP server emits diagnostics for *any* file in the workspace, not
    // a specific language, so we register against the catch-all selector.
    documentSelector: [{ scheme: "file" }],
    diagnosticCollectionName: "pencheff",
    revealOutputChannelOn: RevealOutputChannelOn.Error,
    synchronize: {
      configurationSection: "pencheff",
      // Watch the scan-history dir so the server gets a kick on every new scan.
      fileEvents: vscode.workspace.createFileSystemWatcher("**/.pencheff/history/*.json"),
    },
  };

  client = new LanguageClient(
    "pencheff-lsp",
    "Pencheff",
    serverOptions,
    clientOptions,
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("pencheff.refresh", async () => {
      if (!client) {
        vscode.window.showWarningMessage("Pencheff LSP is not running.");
        return;
      }
      await client.sendRequest("pencheff/refresh", {});
      vscode.window.setStatusBarMessage("$(check) Pencheff findings refreshed", 2000);
    }),
    vscode.commands.registerCommand("pencheff.restart", async () => {
      if (!client) return;
      await client.stop();
      await client.start();
      vscode.window.setStatusBarMessage("$(check) Pencheff LSP restarted", 2000);
    }),
  );

  try {
    await client.start();
  } catch (err) {
    vscode.window.showErrorMessage(
      `Pencheff LSP failed to start (${path.basename(serverPath)} lsp): ${err}. ` +
      `Set 'pencheff.serverPath' to the absolute path of the pencheff CLI if it is not on PATH.`,
    );
  }
}

export async function deactivate(): Promise<void> {
  if (client) {
    await client.stop();
  }
}

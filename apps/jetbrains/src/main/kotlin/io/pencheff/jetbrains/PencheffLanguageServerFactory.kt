package io.pencheff.jetbrains

import com.intellij.openapi.project.Project
import com.redhat.devtools.lsp4ij.LanguageServerFactory
import com.redhat.devtools.lsp4ij.server.StreamConnectionProvider
import com.redhat.devtools.lsp4ij.server.ProcessStreamConnectionProvider

/**
 * LSP4IJ adapter — spawns `pencheff lsp` as a child process and lets the
 * platform handle the JSON-RPC plumbing. Configure the binary path via
 * the IDE Settings → Languages & Frameworks → Language Servers panel
 * (LSP4IJ provides this UI).
 */
class PencheffLanguageServerFactory : LanguageServerFactory {
    override fun createConnectionProvider(project: Project): StreamConnectionProvider {
        val binary = System.getenv("PENCHEFF_BIN") ?: "pencheff"
        val command = listOf(binary, "lsp")
        return ProcessStreamConnectionProvider(command, project.basePath)
    }
}

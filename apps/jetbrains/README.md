# Pencheff for JetBrains

LSP4IJ-based plugin that surfaces Pencheff findings as inline IntelliJ inspections. Works in IntelliJ IDEA, PyCharm, WebStorm, GoLand, RustRover, RubyMine, PhpStorm, and Rider.

## Build

```bash
cd apps/jetbrains
./gradlew buildPlugin
# → build/distributions/pencheff-0.1.0.zip
```

Install the produced zip via **Settings → Plugins → ⚙️ → Install plugin from disk…**

## Configure

The plugin spawns `pencheff lsp`. If `pencheff` is not on `PATH`, set `PENCHEFF_BIN=/absolute/path/to/pencheff` as an environment variable before launching the IDE, or configure the binary path in **Settings → Languages & Frameworks → Language Servers → Pencheff** (LSP4IJ provides this UI).

## v0.1 status

Scaffolded plugin — connects to the LSP and surfaces diagnostics. Quick-fix actions, settings UI, and severity colour mapping are roadmap items. The build hasn't been run in CI yet; once the gradle build is wired up in the GitHub Actions matrix, releases will be signed and uploaded to the JetBrains Marketplace.

## License

MIT

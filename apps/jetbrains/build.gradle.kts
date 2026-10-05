plugins {
  id("org.jetbrains.kotlin.jvm") version "1.9.22"
  id("org.jetbrains.intellij") version "1.17.3"
}

group = "io.pencheff"
version = "0.1.0"

repositories {
  mavenCentral()
}

intellij {
  version.set("2024.1")
  type.set("IC")
  // LSP4IJ provides the LSP client plumbing so we only need to register
  // a server definition and a settings panel — no hand-rolled JSON-RPC.
  plugins.set(listOf("com.redhat.devtools.lsp4ij:0.4.0"))
}

dependencies {
  implementation(kotlin("stdlib"))
}

tasks {
  withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile> {
    kotlinOptions.jvmTarget = "17"
  }
  patchPluginXml {
    sinceBuild.set("241")
    untilBuild.set("251.*")
  }
}

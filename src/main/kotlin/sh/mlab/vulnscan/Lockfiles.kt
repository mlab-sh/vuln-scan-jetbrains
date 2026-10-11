package sh.mlab.vulnscan

// The single source of truth for which lockfiles this plugin knows about.
// Everything else (menus, the auto scanner, the workspace sweep, the inspection)
// asks these functions, so adding a format is a one line edit.
//
// The basename to format mapping mirrors the server's supported parsers
// (vuln.mlab.sh `sbom::pick_format`), and the VS Code extension.

data class LockfileKind(val name: String, val format: String)

val LOCKFILES: List<LockfileKind> = listOf(
    LockfileKind("Cargo.lock", "cargo"),
    LockfileKind("package-lock.json", "npm"),
    LockfileKind("npm-shrinkwrap.json", "npm"),
    LockfileKind("yarn.lock", "yarn"),
    LockfileKind("pnpm-lock.yaml", "pnpm"),
    LockfileKind("composer.lock", "composer"),
    LockfileKind("Gemfile.lock", "gem"),
    LockfileKind("go.sum", "go"),
    LockfileKind("requirements.txt", "pip"),
    LockfileKind("poetry.lock", "poetry"),
    LockfileKind("uv.lock", "uv"),
    LockfileKind("pdm.lock", "pdm"),
    LockfileKind("Pipfile.lock", "pipfile"),
    LockfileKind("pom.xml", "maven"),
    LockfileKind("gradle.lockfile", "maven"),
    LockfileKind("packages.lock.json", "nuget"),
    LockfileKind("pubspec.lock", "pub"),
    LockfileKind("mix.lock", "hex"),
    LockfileKind("mise.lock", "mise"),
    // CycloneDX SBOMs under the spec's recommended names (JSON or XML).
    LockfileKind("bom.json", "cyclonedx"),
    LockfileKind("bom.xml", "cyclonedx"),
)

/** Directories skipped when sweeping a project for lockfiles. */
val SKIP_DIRS = setOf("node_modules", "vendor", "target", "dist", ".git")

val SUPPORTED_BASENAMES: List<String> = LOCKFILES.map { it.name }

private val KNOWN: Map<String, String> = LOCKFILES.associate { it.name.lowercase() to it.format }

fun basenameOf(path: String): String = path.split('/', '\\').last()

fun isSupportedLockfile(path: String): Boolean = basenameOf(path).lowercase() in KNOWN

/** Parser hint for the API, or null to let the server auto-detect. */
fun detectFormat(path: String): String? = KNOWN[basenameOf(path).lowercase()]


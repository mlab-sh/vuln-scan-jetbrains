package sh.mlab.vulnscan

// Pure logic behind the lockfile inspection, unit tested without an IDE.

enum class DiagLevel { ERROR, WARNING, INFORMATION }

val FLOOR_RANK = mapOf(
    "any" to 0, "low" to Severity.LOW.rank, "medium" to Severity.MEDIUM.rank,
    "high" to Severity.HIGH.rank, "critical" to Severity.CRITICAL.rank,
)

/**
 * At or above the floor: critical/high are errors, medium warnings, low/unknown
 * information. Below the floor everything is information. Nothing ever fails.
 */
fun levelFor(finding: Severity, floor: String): DiagLevel {
    if (finding.rank < (FLOOR_RANK[floor] ?: 0)) return DiagLevel.INFORMATION
    if (finding.rank >= Severity.HIGH.rank) return DiagLevel.ERROR
    return if (finding.rank >= Severity.MEDIUM.rank) DiagLevel.WARNING else DiagLevel.INFORMATION
}

/** Zero-based position of a package declaration inside a lockfile. */
data class Hit(val line: Int, val col: Int, val endCol: Int)

/** How far past the matching line to look for the version (Cargo.lock splits them). */
private const val WINDOW = 2

/**
 * Where `name` is declared. A line carrying both name and version (within a small
 * window) wins; else the first whole-token mention outside a comment; else the
 * start of the file, so a finding is never lost.
 */
fun locateLine(text: String, name: String, version: String): Hit {
    val lines = text.split(Regex("\r?\n"))
    val token = Regex("""(?:^|[^A-Za-z0-9_.\-/@])${Regex.escape(name)}(?:[^A-Za-z0-9_.\-]|$)""")
    var fallback = -1
    for (i in lines.indices) {
        val line = lines[i]
        val t = line.trimStart()
        if (t.startsWith("#") || t.startsWith("//")) continue
        if (!token.containsMatchIn(line)) continue
        if (version.isNotEmpty() && lines.subList(i, minOf(i + WINDOW + 1, lines.size)).joinToString("\n").contains(version)) {
            return at(lines, i, name)
        }
        if (fallback == -1) fallback = i
    }
    if (fallback != -1) return at(lines, fallback, name)
    return Hit(0, 0, minOf(lines.firstOrNull()?.length ?: 0, 200))
}

private fun at(lines: List<String>, i: Int, name: String): Hit {
    val col = lines[i].indexOf(name)
    return if (col == -1) Hit(i, 0, lines[i].length) else Hit(i, col, col + name.length)
}

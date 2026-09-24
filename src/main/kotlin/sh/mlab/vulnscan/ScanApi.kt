package sh.mlab.vulnscan

import com.google.gson.JsonObject
import com.google.gson.JsonParser

// POST /api/v2/scan: the model, the OSV normalisation, and the request.
// The normalisation is ported verbatim from mlab-sh/vuln-scan-action and the
// VS Code extension, so all three report the same thing for the same lockfile.

enum class Severity(val rank: Int) {
    CRITICAL(4), HIGH(3), MEDIUM(2), LOW(1), UNKNOWN(0);

    val id: String get() = name.lowercase()

    companion object {
        /** Highest first, the display order everywhere. */
        val ORDER = entries.toList()
        fun parse(s: String?): Severity? = entries.firstOrNull { it.id == s?.lowercase() }
    }
}

/** A single vulnerability against a single package, ready to render. */
data class Finding(
    val pkg: String,
    val name: String,
    val version: String,
    /** CVE id when available, else the OSV advisory id. */
    val cve: String,
    var severity: Severity,
    var summary: String? = null,
    var fixedVersion: String? = null,
    /** Link to the CVE page, when `cve` is a real CVE id. */
    val url: String? = null,
    /** Filled in after the scan by the CVE intelligence lookup, when available. */
    var intel: CveIntel? = null,
)

data class ScanOutcome(
    val findings: List<Finding>,
    /** `name@version` of packages the scanner could not resolve (upstream). */
    val unresolved: List<String>,
    val deps: Int,
    /** True when the manifest exceeded the 512 package scan ceiling. */
    val truncated: Boolean,
    val hash: String,
)

enum class ScanErrorKind { AUTH, RATE_LIMIT, UNPARSEABLE, TIMEOUT, CANCELLED, NETWORK, HTTP, BAD_RESPONSE }

class ScanException(message: String, val kind: ScanErrorKind, val retryAfter: String? = null) : Exception(message)

private fun bandFromCvss(score: Double): Severity = when {
    score >= 9 -> Severity.CRITICAL
    score >= 7 -> Severity.HIGH
    score >= 4 -> Severity.MEDIUM
    score > 0 -> Severity.LOW
    else -> Severity.UNKNOWN
}

/** `database_specific.severity` wins; otherwise the first scoreable CVSS entry. */
fun severityOf(v: JsonObject): Severity {
    val ds = v.o("database_specific").s("severity")?.lowercase()
    if (ds != null) return if (ds == "moderate") Severity.MEDIUM else Severity.parse(ds) ?: Severity.UNKNOWN
    for (s in v.a("severity").objects()) {
        scoreOf(s.s("score") ?: "")?.let { return bandFromCvss(it) }
    }
    return Severity.UNKNOWN
}

/** Prefer a CVE alias; fall back to the advisory id. */
fun cveOf(v: JsonObject): String =
    v.a("aliases").strings().firstOrNull { it.startsWith("CVE-") } ?: v.s("id") ?: "UNKNOWN"

/** Last non-empty `fixed` event across all affected ranges. */
fun fixedVersionOf(v: JsonObject): String? {
    var fixed: String? = null
    for (a in v.a("affected").objects()) for (r in a.a("ranges").objects()) for (e in r.a("events").objects()) {
        e.s("fixed")?.let { fixed = it }
    }
    return fixed
}

/** Turn the raw API response into deduplicated findings and unresolved packages. */
fun buildOutcome(data: JsonObject): ScanOutcome {
    val findings = mutableListOf<Finding>()
    val unresolved = mutableListOf<String>()
    val packages = data.a("packages")

    data.a("results").objects().forEachIndexed { i, r ->
        val p = packages?.takeIf { i < it.size() }?.get(i).obj()
        val pName = p.s("name")
        val version = p.s("version") ?: ""
        val pkg = if (pName != null) "$pName@$version" else "#$i"

        if (r.b("ok") != true) {
            unresolved += pkg
            return@forEachIndexed
        }
        // The same CVE can arrive as several advisories (GHSA + RUSTSEC ...).
        // Collapse per CVE, keeping the highest severity and first summary/fix.
        val byCve = LinkedHashMap<String, Finding>()
        for (v in r.a("vulns").objects()) {
            val cve = cveOf(v)
            val severity = severityOf(v)
            val existing = byCve[cve]
            if (existing != null) {
                if (severity.rank > existing.severity.rank) existing.severity = severity
                if (existing.summary == null) existing.summary = v.s("summary")
                if (existing.fixedVersion == null) existing.fixedVersion = fixedVersionOf(v)
            } else {
                byCve[cve] = Finding(
                    pkg = pkg, name = pName ?: "#$i", version = version, cve = cve, severity = severity,
                    summary = v.s("summary"), fixedVersion = fixedVersionOf(v),
                    url = if (cve.startsWith("CVE-")) "https://vuln.mlab.sh/cve/$cve" else null,
                )
            }
        }
        findings += byCve.values
    }
    return ScanOutcome(
        findings, unresolved,
        deps = data.n("count")?.toInt() ?: 0,
        truncated = data.b("truncated") == true,
        hash = data.s("hash") ?: "",
    )
}

/** Human summary line, e.g. `3 critical, 12 high across 6 packages`. */
fun summarize(outcome: ScanOutcome): String {
    val parts = Severity.ORDER.mapNotNull { s ->
        val n = outcome.findings.count { it.severity == s }
        if (n > 0) "$n ${s.id}" else null
    }
    if (parts.isEmpty()) return "No known vulnerabilities found"
    val pkgs = outcome.findings.map { it.pkg }.toSet().size
    return "${parts.joinToString(", ")} across $pkgs package${if (pkgs == 1) "" else "s"}"
}

/** Highest severity present, or null when clean. */
fun worstOf(outcome: ScanOutcome): Severity? = outcome.findings.maxByOrNull { it.severity.rank }?.severity

/** Upload one lockfile. Blocking: call from a background task. */
fun scanLockfile(
    apiUrl: String, filename: String, format: String?, body: ByteArray, token: String?, timeoutMs: Int,
): ScanOutcome {
    val url = buildString {
        append(apiUrl)
        append(if ('?' in apiUrl) '&' else '?')
        if (format != null) append("format=").append(enc(format)).append('&')
        append("filename=").append(enc(filename))
    }
    val resp = try {
        Http.request(url, "POST", body, "application/octet-stream", token, timeoutMs)
    } catch (e: HttpFailure) {
        throw ScanException(
            when (e.kind) {
                ScanErrorKind.TIMEOUT -> "Scan timed out after $timeoutMs ms."
                ScanErrorKind.CANCELLED -> "Scan cancelled."
                else -> "Could not reach ${hostOf(apiUrl)}: ${e.message}"
            },
            e.kind,
        )
    }
    when (resp.status) {
        401 -> throw ScanException("Invalid or revoked API token (401). Set a new token.", ScanErrorKind.AUTH)
        429 -> throw ScanException(
            "Rate limit reached (429). Anonymous scans are capped at 8/hour per IP; an API token raises this to 25/hour.",
            ScanErrorKind.RATE_LIMIT, resp.retryAfter,
        )
        422 -> throw ScanException(
            "No dependencies could be parsed from $filename (422). Try forcing a format.", ScanErrorKind.UNPARSEABLE,
        )
    }
    if (resp.status !in 200..299) throw ScanException("Scan failed: HTTP ${resp.status}.", ScanErrorKind.HTTP)
    val json = try {
        JsonParser.parseString(resp.body).obj()
    } catch (_: Exception) {
        null
    } ?: throw ScanException("The server returned a response that was not valid JSON.", ScanErrorKind.BAD_RESPONSE)
    return buildOutcome(json)
}

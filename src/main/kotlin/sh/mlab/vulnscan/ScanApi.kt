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

/** The next tier up (`free` or `paid`) and what it unlocks, sent with any limit that was hit. */
data class Upgrade(val tier: String, val maxPackages: Int, val cooldownSecs: Int, val message: String, val url: String)

/** The server's account of a manifest cut at the caller's tier limit. */
data class Truncation(
    val totalPackages: Int,
    val scanned: Int,
    val notScanned: Int,
    val message: String,
    val upgrade: Upgrade? = null,
)

// The fields added after 1.1.0 are nullable: cached outcomes are read back with
// Gson, which leaves a missing field null whatever the Kotlin type says.
data class ScanOutcome(
    val findings: List<Finding>,
    /** `name@version` of packages the scanner could not resolve (upstream). */
    val unresolved: List<String>,
    /** Packages scanned by the server (after any truncation). */
    val deps: Int,
    /** True when the manifest had more packages than the caller's tier scans. */
    val truncated: Boolean,
    val hash: String,
    val truncation: Truncation? = null,
    /** Entries the server parsed but could not scan (git/path deps, unpinned versions, SBOM components without purl or cpe). */
    val unscanned: List<String>? = null,
    /** `anonymous`, `free` or `paid`. */
    val tier: String? = null,
)

enum class ScanErrorKind { AUTH, RATE_LIMIT, TOO_LARGE, UNPARSEABLE, TIMEOUT, CANCELLED, NETWORK, HTTP, BAD_RESPONSE }

class ScanException(
    message: String,
    val kind: ScanErrorKind,
    /** Seconds, for a cooldown (429). */
    val retryAfter: String? = null,
    /** What the next tier unlocks, when a limit was hit. */
    val upgrade: Upgrade? = null,
) : Exception(message)

fun upgradeOf(o: JsonObject?): Upgrade? {
    o ?: return null
    return Upgrade(
        tier = o.s("tier") ?: return null,
        maxPackages = o.n("max_packages")?.toInt() ?: 0,
        cooldownSecs = o.n("cooldown_secs")?.toInt() ?: 0,
        message = o.s("message") ?: return null,
        url = o.s("url") ?: return null,
    )
}

/**
 * The exception for a refused scan. The server states the reason itself
 * (cooldown, size limit, unparseable manifest), so its `message` is shown as
 * is, followed by what the next tier unlocks when a limit was hit.
 */
fun errorFor(status: Int, body: String?, retryHeader: String?, filename: String): ScanException {
    val b = runCatching { JsonParser.parseString(body ?: "").obj() }.getOrNull()
    val upgrade = upgradeOf(b.o("upgrade"))
    fun withUpgrade(msg: String) = if (upgrade != null) "$msg ${upgrade.message}" else msg
    return when (status) {
        401 -> ScanException("Invalid or revoked API token (401). Set a new token.", ScanErrorKind.AUTH)
        429 -> {
            val retry = b.text("retry_after_secs") ?: retryHeader
            ScanException(
                withUpgrade(b.s("message") ?: "Too many scans (429).${retry?.let { " Retry in $it s." } ?: ""}"),
                ScanErrorKind.RATE_LIMIT, retry, upgrade,
            )
        }
        413 -> ScanException(withUpgrade(b.s("message") ?: "$filename is too large to scan (413)."), ScanErrorKind.TOO_LARGE, null, upgrade)
        422 -> ScanException("No dependencies could be parsed from $filename (422). Try forcing a format.", ScanErrorKind.UNPARSEABLE)
        else -> ScanException("Scan failed: HTTP $status${b.s("message")?.let { ": $it" } ?: "."}", ScanErrorKind.HTTP)
    }
}

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

private val CVE_ID = Regex("""CVE-\d{4}-\d{4,}""", RegexOption.IGNORE_CASE)

/**
 * The CVE an advisory is about, the way the server picks it: an alias first,
 * then `upstream` (Debian and Ubuntu records list their CVEs there, not in
 * aliases), then a CVE embedded in the id (`DEBIAN-CVE-2024-1234`). Falls back
 * to the advisory id when there is no CVE at all.
 */
fun cveOf(v: JsonObject): String {
    for (s in v.a("aliases").strings() + v.a("upstream").strings() + listOfNotNull(v.s("id"))) {
        CVE_ID.find(s)?.let { return it.value.uppercase() }
    }
    return v.s("id") ?: "UNKNOWN"
}

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
    val t = data.o("truncation")
    val truncation = t?.let {
        Truncation(
            totalPackages = it.n("total_packages")?.toInt() ?: 0,
            scanned = it.n("scanned")?.toInt() ?: 0,
            notScanned = it.n("not_scanned")?.toInt() ?: 0,
            message = it.s("message") ?: "",
            upgrade = upgradeOf(it.o("upgrade")),
        )
    }
    return ScanOutcome(
        findings, unresolved,
        deps = data.n("count")?.toInt() ?: 0,
        truncated = data.b("truncated") == true || truncation != null,
        hash = data.s("hash") ?: "",
        truncation = truncation,
        unscanned = data.a("unscanned").strings().takeIf { it.isNotEmpty() },
        tier = data.s("tier"),
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
    if (resp.status !in 200..299) throw errorFor(resp.status, resp.body, resp.retryAfter, filename)
    val json = try {
        JsonParser.parseString(resp.body).obj()
    } catch (_: Exception) {
        null
    } ?: throw ScanException("The server returned a response that was not valid JSON.", ScanErrorKind.BAD_RESPONSE)
    return buildOutcome(json)
}

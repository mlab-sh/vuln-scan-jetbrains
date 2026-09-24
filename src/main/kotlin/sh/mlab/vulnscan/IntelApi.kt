package sh.mlab.vulnscan

import com.google.gson.JsonArray
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import com.intellij.openapi.diagnostic.logger
import com.intellij.openapi.progress.ProcessCanceledException
import com.intellij.openapi.progress.ProgressManager
import com.intellij.util.concurrency.AppExecutorUtil
import java.util.concurrent.Callable
import kotlin.math.roundToInt

// Client for the public CVE intelligence API on vuln.mlab.sh: EPSS, KEV, CVSS.
//
// Safe to call on every finding: no authentication, no scan quota, and only a
// CVE identifier is sent, never anything about the user's code.

data class CveIntel(
    val id: String,
    val cvssScore: Double? = null,
    val cvssSeverity: String? = null,
    val cvssVector: String? = null,
    /** Probability of exploitation in the next 30 days, 0 to 1. */
    val epssScore: Double? = null,
    val epssPercentile: Double? = null,
    val inKev: Boolean = false,
    val inEuKev: Boolean = false,
    val kevDateAdded: String? = null,
    val kevDueDate: String? = null,
    /** The API's own composite score, 0 to 100. */
    val riskScore: Double? = null,
    val weaknesses: List<String> = emptyList(),
)

fun parseRecord(raw: JsonObject): CveIntel? {
    val id = raw.s("id") ?: return null
    return CveIntel(
        id = id,
        cvssScore = raw.n("cvss_score"),
        cvssSeverity = raw.s("cvss_severity")?.lowercase(),
        cvssVector = raw.s("cvss_vector"),
        epssScore = raw.n("epss_score"),
        epssPercentile = raw.n("epss_percentile"),
        inKev = raw.b("in_kev") == true,
        inEuKev = raw.b("in_eu_kev") == true,
        kevDateAdded = raw.s("kev_date_added"),
        kevDueDate = raw.s("kev_due_date"),
        riskScore = raw.n("risk_score"),
        weaknesses = raw.a("weaknesses").strings(),
    )
}

/** The endpoint is a search: pick the record that is exactly the id asked for. */
fun pickExact(id: String, records: JsonArray?): CveIntel? =
    records.objects().firstNotNullOfOrNull { r -> parseRecord(r)?.takeIf { it.id.equals(id, ignoreCase = true) } }

fun intelUrl(origin: String, id: String): String = "${origin.trimEnd('/')}/api/v1/cve?q=${enc(id)}&limit=5"

/**
 * Intelligence for one CVE, or null on any failure: enrichment is a bonus, and a
 * network hiccup must never turn a successful scan into an error.
 */
fun fetchCve(id: String, origin: String, timeoutMs: Int): CveIntel? = try {
    val resp = Http.request(intelUrl(origin, id), timeoutMs = timeoutMs)
    if (resp.status !in 200..299) null
    else pickExact(id, JsonParser.parseString(resp.body).obj().a("cves"))
} catch (e: ProcessCanceledException) {
    throw e
} catch (e: Exception) {
    logger<CveIntel>().debug("intel lookup failed for $id", e)
    null
}

/** How many CVE lookups run at once. Keeps a big report from opening 40 sockets. */
const val INTEL_CONCURRENCY = 6

private val intelPool = AppExecutorUtil.createBoundedApplicationPoolExecutor("mlab CVE intel", INTEL_CONCURRENCY)

/** Fetch several CVEs, a bounded number at a time. Failed ids are simply absent. */
fun fetchMany(ids: Collection<String>, origin: String, timeoutMs: Int): Map<String, CveIntel> {
    val futures = ids.toSet().map { id -> id to intelPool.submit(Callable { fetchCve(id, origin, timeoutMs) }) }
    val out = LinkedHashMap<String, CveIntel>()
    try {
        for ((id, f) in futures) {
            while (!f.isDone) {
                ProgressManager.checkCanceled()
                Thread.sleep(20)
            }
            runCatching { f.get() }.getOrNull()?.let { out[id] = it }
        }
    } catch (e: ProcessCanceledException) {
        futures.forEach { it.second.cancel(true) }
        throw e
    }
    return out
}

fun epssLabel(intel: CveIntel): String? {
    val pct = (intel.epssScore ?: return null) * 100
    return when {
        pct >= 10 -> "${pct.roundToInt()}%"
        pct >= 1 -> "%.1f%%".format(java.util.Locale.ROOT, pct)
        pct >= 0.01 -> "%.2f%%".format(java.util.Locale.ROOT, pct)
        else -> "<0.01%"
    }
}

enum class Urgency { EXPLOITED, LIKELY, NORMAL }

/** Being in a known-exploited catalogue means attacks are happening, not possible. */
fun urgencyOf(intel: CveIntel?): Urgency = when {
    intel == null -> Urgency.NORMAL
    intel.inKev || intel.inEuKev -> Urgency.EXPLOITED
    (intel.epssScore ?: 0.0) >= 0.1 -> Urgency.LIKELY
    else -> Urgency.NORMAL
}

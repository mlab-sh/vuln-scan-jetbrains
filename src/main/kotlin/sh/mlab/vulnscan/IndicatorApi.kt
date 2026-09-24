package sh.mlab.vulnscan

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import com.intellij.openapi.progress.ProcessCanceledException
import kotlin.math.min

// Client for the indicator endpoints on the mlab platform API.
//
// One endpoint per kind, chosen locally from Ioc.kt, so the value only ever
// reaches the endpoint that handles it. Works without a key at a reduced quota;
// the platform key is NOT the vuln.mlab.sh scan token.

const val DEFAULT_PLATFORM_URL = "https://mlab.sh/api/v1"

private val ROUTES = mapOf(
    IndicatorKind.IP to ("/scan/ip" to "ip"),
    IndicatorKind.URL to ("/scan/url" to "url"),
    IndicatorKind.EMAIL to ("/scan/email" to "email"),
    IndicatorKind.HASH to ("/scan/hash" to "hash"),
    IndicatorKind.MAC to ("/scan/mac" to "mac"),
)

/** The lookup URL for one indicator, or null when the kind has no direct route. */
fun endpointFor(base: String, kind: IndicatorKind, value: String): String? {
    val (path, param) = ROUTES[kind] ?: return null
    return "${base.trimEnd('/')}$path?$param=${enc(value)}"
}

/** The human page for an indicator. The URL page takes a `q` query, the rest a path. */
fun webUrlFor(site: String, kind: IndicatorKind, value: String): String? {
    val origin = site.trimEnd('/')
    if (kind == IndicatorKind.URL) return "$origin/url?q=${enc(value)}"
    if (!kind.isSupported) return null
    return "$origin/${kind.name.lowercase()}/${enc(value)}"
}

enum class Tone { GOOD, BAD, WARN, NEUTRAL }

data class IndicatorFinding(val severity: String, val title: String, val detail: String)
data class Fact(val label: String, val value: String, val mono: Boolean = false)
data class Verdict(val label: String, val tone: Tone)

data class IndicatorReport(
    val kind: IndicatorKind,
    val value: String,
    val verdict: Verdict?,
    val findings: List<IndicatorFinding>,
    val facts: List<Fact>,
    var webUrl: String? = null,
)

class IndicatorException(message: String, val kind: ScanErrorKind) : Exception(message)

private fun getJson(url: String, key: String?, timeoutMs: Int, method: String = "GET", body: String? = null): JsonObject {
    val resp = try {
        Http.request(url, method, body?.toByteArray(), if (body != null) "application/json" else null, key, timeoutMs)
    } catch (e: HttpFailure) {
        if (e.kind == ScanErrorKind.TIMEOUT) throw IndicatorException("Lookup timed out after $timeoutMs ms.", e.kind)
        throw IndicatorException("Could not reach the mlab platform: ${e.message}", ScanErrorKind.NETWORK)
    }
    when (resp.status) {
        401, 403 -> throw IndicatorException(
            "The mlab platform key was rejected (or this lookup needs a plan that allows it).", ScanErrorKind.AUTH,
        )
        429 -> throw IndicatorException("Daily lookup quota reached. Adding an mlab platform key raises it.", ScanErrorKind.RATE_LIMIT)
    }
    if (resp.status !in 200..299) throw IndicatorException("Lookup failed: HTTP ${resp.status}.", ScanErrorKind.HTTP)
    return try {
        JsonParser.parseString(resp.body).obj()
    } catch (_: Exception) {
        null
    } ?: throw IndicatorException("The platform returned a response that was not valid JSON.", ScanErrorKind.BAD_RESPONSE)
}

/** One direct lookup. Blocking: call from a background task. */
fun lookup(base: String, kind: IndicatorKind, value: String, key: String?, timeoutMs: Int): IndicatorReport {
    val url = endpointFor(base, kind, value) ?: throw IndicatorException("No endpoint for a ${kind.label}.", ScanErrorKind.HTTP)
    return summarizeIndicator(kind, value, getJson(url, key, timeoutMs))
}

// ── Domain, which is a scan rather than a lookup ─────────────────────────────

enum class DomainState { PENDING, SCANNING, DONE, REUSED }

fun readState(raw: JsonObject): DomainState = when (raw.s("status")) {
    "pending" -> DomainState.PENDING
    "scanning" -> DomainState.SCANNING
    else -> DomainState.DONE
}

/** Gap before the next poll, growing so a long scan does not hammer the API. */
fun pollDelay(attempt: Int): Long = min(2000L + attempt * 1000L, 8000L)

const val MAX_POLLS = 40

fun isCompleted(raw: JsonObject): Boolean =
    raw.s("status") == "completed" && raw.get("results").let { it != null && !it.isJsonNull }

/**
 * Launch a domain scan, wait for it, return the report. An existing completed
 * scan is reused first: reading it is a free GET, while `POST /scan/domain`
 * purges and relaunches and always spends one of the daily scans.
 */
fun scanDomain(base: String, domain: String, key: String?, timeoutMs: Int, onState: (DomainState) -> Unit): IndicatorReport {
    val origin = base.trimEnd('/')
    val resultsUrl = "$origin/scan/domain/results?domain=${enc(domain)}"
    val existing = try {
        getJson(resultsUrl, key, timeoutMs).takeIf(::isCompleted)
    } catch (e: ProcessCanceledException) {
        throw e
    } catch (_: IndicatorException) {
        null // no scan yet, or the read failed: launch one
    }
    if (existing != null) {
        onState(DomainState.REUSED)
        return summarizeIndicator(IndicatorKind.DOMAIN, domain, existing)
    }

    getJson("$origin/scan/domain", key, timeoutMs, "POST", """{"domain":${com.google.gson.JsonPrimitive(domain)}}""")
    val statusUrl = "$origin/scan/domain/status?domain=${enc(domain)}"
    for (i in 0 until MAX_POLLS) {
        val state = readState(getJson(statusUrl, key, timeoutMs))
        onState(state)
        if (state == DomainState.DONE) return summarizeIndicator(IndicatorKind.DOMAIN, domain, getJson(resultsUrl, key, timeoutMs))
        sleepChecked(pollDelay(i))
    }
    throw IndicatorException("The domain scan is still running. Open it on mlab to follow it there.", ScanErrorKind.TIMEOUT)
}

// ── Normalisation ────────────────────────────────────────────────────────────

private fun yesNo(v: Boolean?): String? = v?.let { if (it) "yes" else "no" }

private fun readFindings(raw: JsonObject): List<IndicatorFinding> = raw.a("findings").objects().mapNotNull { o ->
    val title = o.s("title") ?: return@mapNotNull null
    IndicatorFinding((o.s("severity") ?: "info").lowercase(), title, o.s("detail") ?: "")
}

/** Turn a raw response into the shape the panel renders, per kind. */
fun summarizeIndicator(kind: IndicatorKind, value: String, raw: JsonObject): IndicatorReport {
    val facts = mutableListOf<Fact>()
    fun push(label: String, v: String?, mono: Boolean = false) {
        if (!v.isNullOrEmpty()) facts += Fact(label, v, mono)
    }
    var verdict: Verdict? = null

    when (kind) {
        IndicatorKind.URL -> {
            push("Scheme", raw.s("scheme"), true)
            push("Host", raw.s("host"), true)
            push("Port", raw.text("port"), true)
            push("Path", raw.s("path"), true)
            push("Unicode host", raw.s("host_unicode"), true)
            push("Embedded URL", raw.s("embedded_url"), true)
            push("Decoded", raw.s("decoded"), true)
            push("Credentials in URL", yesNo(raw.b("has_userinfo")))
            push("Host is a raw IP", yesNo(raw.b("host_is_ip")))
        }
        IndicatorKind.HASH -> {
            verdict = when {
                raw.s("verdict") == "known_good" -> Verdict("Known good", Tone.GOOD)
                raw.s("verdict") == "known_malicious" -> Verdict("Known malicious", Tone.BAD)
                raw.b("found") == false -> Verdict("Unknown to every source", Tone.NEUTRAL)
                else -> null
            }
            push("Algorithm", raw.s("algorithm"))
            push("Product", raw.s("product"))
            push("File name", raw.s("file_name"), true)
            push("Source", raw.s("enrichment_source"))
            push("Sources hit", "${raw.text("sources_hit") ?: 0} of ${raw.text("sources_queried") ?: 0}")
            push("Trust", raw.text("trust"))
        }
        IndicatorKind.EMAIL -> {
            raw.o("score").s("band")?.let { band ->
                verdict = Verdict(band, if (band == "clean") Tone.GOOD else if (band == "suspect") Tone.WARN else Tone.BAD)
            }
            push("Mailbox type", raw.s("mailbox_type"))
            push("Domain", raw.s("domain"), true)
            push("Disposable", yesNo(raw.b("is_disposable")))
            push("Role address", yesNo(raw.b("is_role")))
            push("Free provider", yesNo(raw.b("is_free_provider")))
            push("Canonical", raw.s("canonical"), true)
        }
        IndicatorKind.MAC -> {
            raw.s("verdict")?.let { verdict = Verdict(it, if (raw.b("randomized") == true) Tone.WARN else Tone.NEUTRAL) }
            push("Vendor", raw.s("vendor"))
            push("OUI", raw.s("oui"), true)
            push("Cast", raw.s("cast"))
            push("Administration", raw.s("administration"))
            push("Randomized", yesNo(raw.b("randomized")))
            push("Virtualization", raw.s("virtualization"))
            push("EUI-64 IPv6", raw.s("eui64_ipv6"), true)
        }
        IndicatorKind.IP -> {
            val flags = listOfNotNull(
                "proxy or VPN".takeIf { raw.b("proxy") == true },
                "hosting provider".takeIf { raw.b("hosting") == true },
                "mobile network".takeIf { raw.b("mobile") == true },
                "reserved range".takeIf { raw.b("reserved") == true },
            )
            if (flags.isNotEmpty()) verdict = Verdict(flags.joinToString(", "), if (raw.b("proxy") == true) Tone.WARN else Tone.NEUTRAL)
            push("Organisation", raw.s("org"))
            push("ISP", raw.s("isp"))
            push("AS", raw.s("as"), true)
            push("Location", listOfNotNull(raw.s("city"), raw.s("region"), raw.s("country")).joinToString(", "))
            push("Reverse DNS", raw.o("rdns").s("name") ?: raw.o("rdns").s("ptr"), true)
            push("Abuse contact", raw.o("rdap").s("abuse_email"), true)
        }
        IndicatorKind.DOMAIN -> {
            // The payload is an envelope: { domain, scan_date, status, results: {...} }.
            val res = raw.o("results")
            val dns = res.o("dns")
            val txt = dns.o("txt")
            val suspicious = res.a("subdomains_suspicious").strings()
            val subdomains = res.a("subdomains")?.size() ?: 0
            val ssl = res.a("ssl")?.size() ?: 0
            if (suspicious.isNotEmpty()) {
                verdict = Verdict("${suspicious.size} suspicious subdomain${if (suspicious.size == 1) "" else "s"}", Tone.WARN)
            }
            push("Scanned", raw.s("scan_date"))
            val resolve = dns.a("resolve")?.firstOrNull().obj()
            push("A records", resolve.a("a").strings().joinToString(", "), true)
            push("AAAA records", resolve.a("aaaa").strings().joinToString(", "), true)
            push("SPF", if (txt.s("spf") != null) "present" else "absent")
            push("DMARC", if (txt.s("dmarc") != null) "present" else "absent")
            push("DKIM", if ((txt.a("dkim")?.size() ?: 0) > 0) "present" else "absent")
            push("Subdomains", if (subdomains > 0) subdomains.toString() else null)
            if (suspicious.isNotEmpty()) push("Suspicious", suspicious.joinToString(", "), true)
            push("security.txt", if (res.o("files").s("security_txt") == "not found") "not found" else "present")
            push("SSL issues", if (ssl > 0) ssl.toString() else "none")
        }
        IndicatorKind.UNKNOWN -> Unit
    }
    return IndicatorReport(kind, value, verdict, readFindings(raw), facts)
}

private val FINDING_RANK = mapOf("critical" to 4, "high" to 3, "medium" to 2, "low" to 1, "info" to 0)

/** Highest severity among findings, for the panel's headline. */
fun worstIndicatorSeverity(findings: List<IndicatorFinding>): String? =
    findings.maxByOrNull { FINDING_RANK[it.severity] ?: 0 }?.severity

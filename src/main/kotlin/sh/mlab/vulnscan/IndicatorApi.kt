package sh.mlab.vulnscan

import com.google.gson.JsonObject
import com.google.gson.JsonParser

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
    if (!kind.isSupported && !kind.opensInBrowser) return null
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
    /** What is left of the key's quota, from the X-RateLimit-* headers. */
    var quota: Quota? = null,
)

/** The platform quota as reported on a key call that spends it. */
data class Quota(val limit: Int, val remaining: Int, val resource: String?, val windowSecs: Int?)

/** Read the X-RateLimit-* headers (names lowercased), or null when the call spent no quota. */
fun readQuota(headers: Map<String, String>): Quota? {
    val limit = headers["x-ratelimit-limit"]?.toIntOrNull() ?: return null
    val remaining = headers["x-ratelimit-remaining"]?.toIntOrNull() ?: return null
    return Quota(limit, remaining, headers["x-ratelimit-resource"], headers["x-ratelimit-window"]?.toIntOrNull()?.takeIf { it > 0 })
}

/** One line for the panel and the log. */
fun quotaLine(q: Quota): String =
    "${q.remaining} of ${q.limit}${q.resource?.let { " $it" } ?: ""} lookups left${if (q.windowSecs == 86400) " per rolling 24 h" else ""}"

class IndicatorException(message: String, val kind: ScanErrorKind, val retryAfter: String? = null) : Exception(message)

/**
 * The error for a refused lookup, worded for someone who has to act on it.
 *
 * The platform answers 401 to a key it does not know: mistyped, revoked, or
 * expired (keys expire after 90 days unless set otherwise). 403 means the key is
 * valid but lacks the permission, and the server's own message names it. 429 is
 * the quota, which refills over a rolling 24 hours.
 */
fun indicatorErrorFor(status: Int, body: String, withKey: Boolean, retryAfter: String? = null): IndicatorException {
    val said = runCatching { JsonParser.parseString(body).obj()?.s("error") }.getOrNull()
    return when (status) {
        401 -> IndicatorException(
            if (withKey) "The mlab platform key was not accepted: it is mistyped, revoked or expired (keys expire after 90 days by default). Create a new one in your organization settings on mlab.sh."
            else "The mlab platform refused the anonymous lookup (401).",
            ScanErrorKind.AUTH,
        )
        403 -> IndicatorException(said ?: "The mlab platform key is not allowed to make this lookup.", ScanErrorKind.AUTH)
        else -> {
            val base = if (said != null && said != "limit") said.trimEnd('.') + "." else "Lookup quota reached."
            IndicatorException(
                "$base The quota refills over a rolling 24 hours${if (withKey) "" else "; an mlab platform key raises it"}.",
                ScanErrorKind.RATE_LIMIT,
                retryAfter,
            )
        }
    }
}

/** One direct lookup. Blocking: call from a background task. */
fun lookup(base: String, kind: IndicatorKind, value: String, key: String?, timeoutMs: Int): IndicatorReport {
    val url = endpointFor(base, kind, value) ?: throw IndicatorException("No endpoint for a ${kind.label}.", ScanErrorKind.HTTP)
    val resp = try {
        Http.request(url, bearer = key, timeoutMs = timeoutMs)
    } catch (e: HttpFailure) {
        if (e.kind == ScanErrorKind.TIMEOUT) throw IndicatorException("Lookup timed out after $timeoutMs ms.", e.kind)
        throw IndicatorException("Could not reach the mlab platform: ${e.message}", ScanErrorKind.NETWORK)
    }
    return reportFrom(kind, value, resp, key != null)
}

/** A response turned into a report, or the mapped error. Split out to be unit tested. */
fun reportFrom(kind: IndicatorKind, value: String, resp: HttpResponse, withKey: Boolean): IndicatorReport {
    if (resp.status == 401 || resp.status == 403 || resp.status == 429) {
        throw indicatorErrorFor(resp.status, resp.body, withKey, resp.retryAfter)
    }
    if (resp.status !in 200..299) throw IndicatorException("Lookup failed: HTTP ${resp.status}.", ScanErrorKind.HTTP)
    val raw = try {
        JsonParser.parseString(resp.body).obj()
    } catch (_: Exception) {
        null
    } ?: throw IndicatorException("The platform returned a response that was not valid JSON.", ScanErrorKind.BAD_RESPONSE)
    return summarizeIndicator(kind, value, raw).also { if (withKey) it.quota = readQuota(resp.headers) }
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
        IndicatorKind.DOMAIN, IndicatorKind.UNKNOWN -> Unit
    }
    return IndicatorReport(kind, value, verdict, readFindings(raw), facts)
}

private val FINDING_RANK = mapOf("critical" to 4, "high" to 3, "medium" to 2, "low" to 1, "info" to 0)

/** Highest severity among findings, for the panel's headline. */
fun worstIndicatorSeverity(findings: List<IndicatorFinding>): String? =
    findings.maxByOrNull { FINDING_RANK[it.severity] ?: 0 }?.severity

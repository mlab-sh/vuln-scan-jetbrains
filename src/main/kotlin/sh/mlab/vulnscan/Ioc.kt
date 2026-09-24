package sh.mlab.vulnscan

// Local recognition of what a selected string is.
//
// The type is worked out here, on the machine, and only then is the value sent
// to the endpoint that handles that type. Nothing is uploaded to find out what
// something is.

enum class IndicatorKind(val label: String) {
    IP("IP address"), URL("URL"), EMAIL("email address"), HASH("file hash"),
    MAC("MAC address"), DOMAIN("domain"), UNKNOWN("indicator");

    /** A domain is scanned, not looked up: it contacts the target and must be polled. */
    val isActive get() = this == DOMAIN
    val isSupported get() = this != UNKNOWN
    /** Kinds that spend a daily, organisation wide quota. */
    val costsQuota get() = this == IP || this == DOMAIN
}

/** A selection longer than this is not an indicator; refuse rather than upload it. */
const val MAX_INDICATOR_LENGTH = 2048

/** Characters people select by accident: quotes, brackets, trailing punctuation. */
private val TRIM = Regex("""^[\s'"`<(\[{,;]+|[\s'"`>)\]},;.]+$""")

fun cleanIndicator(raw: String): String = raw.trim().replace(TRIM, "").trim()

private val URL_RE = Regex("""^[a-z][a-z0-9+.-]*://\S+$""", RegexOption.IGNORE_CASE)
private val EMAIL_RE = Regex("""^[^\s@]+@[^\s@]+\.[^\s@]{2,}$""")
private val MAC_RE = Regex("""^[0-9a-f]{2}([:-])[0-9a-f]{2}(\1[0-9a-f]{2}){4}$""", RegexOption.IGNORE_CASE)
private val MAC_BARE = Regex("""^[0-9a-f]{12}$""", RegexOption.IGNORE_CASE)
private val MAC_CISCO = Regex("""^[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}$""", RegexOption.IGNORE_CASE)
private val HASH_RE = Regex("""^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}|[0-9a-f]{128})$""", RegexOption.IGNORE_CASE)
private val IPV4 = Regex("""^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$""")
private val IPV6 = Regex("""^(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}$""", RegexOption.IGNORE_CASE)
private val DOMAIN_RE = Regex(
    """^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$""",
    RegexOption.IGNORE_CASE,
)

/**
 * Classify a selection. Order matters: a 12 hex digit string is a bare MAC, not
 * a short hash; a MAC with colons resembles IPv6. `UNKNOWN` beats a wrong guess,
 * since sending a value to the wrong endpoint is worse than saying so.
 */
fun detectKind(value: String): IndicatorKind {
    val v = cleanIndicator(value)
    if (v.isEmpty()) return IndicatorKind.UNKNOWN
    if (URL_RE.matches(v)) return IndicatorKind.URL
    if (EMAIL_RE.matches(v)) return IndicatorKind.EMAIL
    if (MAC_RE.matches(v) || MAC_CISCO.matches(v)) return IndicatorKind.MAC
    if (HASH_RE.matches(v)) return IndicatorKind.HASH
    if (MAC_BARE.matches(v)) return IndicatorKind.MAC
    if (IPV4.matches(v)) return IndicatorKind.IP
    if (':' in v && IPV6.matches(v) && v.split(':').size >= 3) return IndicatorKind.IP
    // A domain needs a non-numeric last label, or 256.0.0.1 would be sent to a
    // domain scan when the user selected a broken IP.
    if (DOMAIN_RE.matches(v) && v.substringAfterLast('.').any { !it.isDigit() }) return IndicatorKind.DOMAIN
    return IndicatorKind.UNKNOWN
}

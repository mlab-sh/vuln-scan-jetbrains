package sh.mlab.vulnscan

import kotlin.math.floor
import kotlin.math.min
import kotlin.math.pow
import kotlin.math.roundToLong

// CVSS v3.x base score, from the v3.1 specification section 8.
//
// OSV advisories very often carry their severity only as a vector string. Without
// scoring it those findings fall through to `unknown`.

private val AV = mapOf("N" to 0.85, "A" to 0.62, "L" to 0.55, "P" to 0.2)
private val AC = mapOf("L" to 0.77, "H" to 0.44)
private val UI = mapOf("N" to 0.85, "R" to 0.62)
private val CIA = mapOf("H" to 0.56, "L" to 0.22, "N" to 0.0)
private val PR_UNCHANGED = mapOf("N" to 0.85, "L" to 0.62, "H" to 0.27)
private val PR_CHANGED = mapOf("N" to 0.85, "L" to 0.68, "H" to 0.5)

/** The spec's Roundup, which works in hundred-thousandths to dodge float noise. */
fun roundUp(input: Double): Double {
    val i = (input * 100000).roundToLong()
    if (i % 10000 == 0L) return i / 100000.0
    return (floor(i / 10000.0) + 1) / 10
}

/** Base score of a v3.0/v3.1 vector, or null when it is not one or is incomplete. */
fun baseScoreV3(vector: String): Double? {
    if (!Regex("^CVSS:3\\.[01]/", RegexOption.IGNORE_CASE).containsMatchIn(vector)) return null
    val m = vector.split('/').drop(1).mapNotNull { part ->
        val kv = part.split(':')
        if (kv.size >= 2 && kv[0].isNotEmpty() && kv[1].isNotEmpty()) kv[0].uppercase() to kv[1].uppercase() else null
    }.toMap()

    val changed = m["S"] == "C"
    val av = AV[m["AV"]] ?: return null
    val ac = AC[m["AC"]] ?: return null
    val pr = (if (changed) PR_CHANGED else PR_UNCHANGED)[m["PR"]] ?: return null
    val ui = UI[m["UI"]] ?: return null
    val c = CIA[m["C"]] ?: return null
    val i = CIA[m["I"]] ?: return null
    val a = CIA[m["A"]] ?: return null
    if (m["S"] == null) return null

    val iss = 1 - (1 - c) * (1 - i) * (1 - a)
    val impact = if (changed) 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).pow(15) else 6.42 * iss
    if (impact <= 0) return 0.0
    val exploitability = 8.22 * av * ac * pr * ui
    val raw = if (changed) min(1.08 * (impact + exploitability), 10.0) else min(impact + exploitability, 10.0)
    return roundUp(raw)
}

/**
 * A numeric score out of an OSV `severity[].score`, whatever its shape. v2 and v4
 * vectors give null, so the caller falls through instead of guessing.
 */
fun scoreOf(raw: String): Double? {
    val text = raw.trim()
    if (text.isEmpty()) return null
    text.toDoubleOrNull()?.takeIf { it.isFinite() }?.let { return it }
    baseScoreV3(text)?.let { return it }
    return text.substringAfterLast('/').toDoubleOrNull()?.takeIf { it.isFinite() }
}

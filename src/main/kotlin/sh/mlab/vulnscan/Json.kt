package sh.mlab.vulnscan

import com.google.gson.JsonArray
import com.google.gson.JsonElement
import com.google.gson.JsonObject

// Tolerant readers over Gson's tree (Gson ships with the IDE, nothing bundled).
// Every API field is treated as optional: a missing or mistyped field reads as
// null, never as a crash.

fun JsonElement?.obj(): JsonObject? = if (this != null && isJsonObject) asJsonObject else null
fun JsonElement?.arr(): JsonArray? = if (this != null && isJsonArray) asJsonArray else null

fun JsonObject?.o(key: String): JsonObject? = this?.get(key).obj()
fun JsonObject?.a(key: String): JsonArray? = this?.get(key).arr()

/** Non-blank string, or null. */
fun JsonObject?.s(key: String): String? {
    val e = this?.get(key) ?: return null
    if (!e.isJsonPrimitive || !e.asJsonPrimitive.isString) return null
    return e.asString.takeIf { it.isNotBlank() }
}

fun JsonObject?.b(key: String): Boolean? {
    val e = this?.get(key) ?: return null
    return if (e.isJsonPrimitive && e.asJsonPrimitive.isBoolean) e.asBoolean else null
}

fun JsonObject?.n(key: String): Double? {
    val e = this?.get(key) ?: return null
    return if (e.isJsonPrimitive && e.asJsonPrimitive.isNumber) e.asDouble.takeIf { it.isFinite() } else null
}

/** Any primitive as text (numbers included), or null for null/absent/objects. */
fun JsonObject?.text(key: String): String? {
    val e = this?.get(key) ?: return null
    if (!e.isJsonPrimitive) return null
    val p = e.asJsonPrimitive
    return if (p.isNumber) p.asNumber.toString().removeSuffix(".0") else p.asString
}

fun JsonArray?.objects(): List<JsonObject> = this?.mapNotNull { it.obj() } ?: emptyList()

fun JsonArray?.strings(): List<String> =
    this?.mapNotNull { if (it.isJsonPrimitive && it.asJsonPrimitive.isString) it.asString else null } ?: emptyList()

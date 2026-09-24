package sh.mlab.vulnscan

import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import com.intellij.openapi.application.PathManager
import com.intellij.openapi.components.Service
import com.intellij.openapi.components.service
import com.intellij.openapi.diagnostic.logger
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.security.MessageDigest

// Two content caches, kept in the IDE's system directory (a cache, not a
// setting: never synced, safe to delete).
//
// Scan cache, keyed by lockfile path, holding the SHA-256 of the bytes scanned.
// The same bytes always resolve to the same advisories, so an unchanged lockfile
// never goes back to the network until its freshness runs out. Two bounds:
//   - FRESHNESS (7 days): how long a hit is trusted, so new CVEs are eventually seen.
//   - RETENTION (30 days): how long an entry is kept at all, so storage is bounded.
//
// Intel cache, keyed by CVE id: EPSS is recomputed daily, so a day of freshness.

const val DAY_MS = 24L * 60 * 60 * 1000
const val SCAN_MAX_AGE_MS = 7 * DAY_MS
const val RETENTION_MS = 30 * DAY_MS
const val INTEL_MAX_AGE_MS = DAY_MS

data class CacheEntry(
    val hash: String,
    val path: String,
    val filename: String,
    val findingCount: Int,
    val worstSeverity: Severity?,
    val outcome: ScanOutcome,
    val at: Long,
)

data class IntelEntry(val intel: CveIntel, val at: Long)

fun sha256Hex(bytes: ByteArray): String =
    MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

/** Keys of every entry older than `retentionMs`. */
fun <T> expiredKeys(entries: Map<String, T>, now: Long, retentionMs: Long = RETENTION_MS, at: (T) -> Long): List<String> =
    entries.filterValues { now - at(it) > retentionMs }.keys.toList()

/** A small JSON backed map. `file == null` keeps it in memory (tests). */
open class JsonStore<T>(private val file: Path?, type: TypeToken<Map<String, T>>, private val at: (T) -> Long) {
    protected val entries: MutableMap<String, T> = LinkedHashMap()

    init {
        if (file != null && Files.isRegularFile(file)) {
            try {
                Files.newBufferedReader(file).use { r -> Gson().fromJson(r, type)?.let { entries.putAll(it) } }
            } catch (e: Exception) {
                logger<JsonStore<*>>().warn("mlab: ignoring unreadable cache $file", e)
            }
        }
    }

    @Synchronized
    fun prune(now: Long = System.currentTimeMillis()): Int {
        val gone = expiredKeys(entries, now, RETENTION_MS, at)
        if (gone.isNotEmpty()) {
            gone.forEach(entries::remove)
            save()
        }
        return gone.size
    }

    @Synchronized
    protected fun save() {
        file ?: return
        try {
            Files.createDirectories(file.parent)
            val tmp = file.resolveSibling(file.fileName.toString() + ".tmp")
            Files.writeString(tmp, Gson().toJson(entries))
            Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
        } catch (e: Exception) {
            logger<JsonStore<*>>().warn("mlab: could not write cache $file", e)
        }
    }

    val size: Int @Synchronized get() = entries.size
}

class ScanCache(file: Path?) : JsonStore<CacheEntry>(file, object : TypeToken<Map<String, CacheEntry>>() {}, { it.at }) {
    /** Cached result for this exact content, if fresh enough. */
    @Synchronized
    fun lookup(path: String, hash: String, now: Long = System.currentTimeMillis()): CacheEntry? =
        entries[path]?.takeIf { it.hash == hash && now - it.at <= SCAN_MAX_AGE_MS }

    /** Whatever we last knew about this path, regardless of current content. */
    @Synchronized
    fun peek(path: String): CacheEntry? = entries[path]

    @Synchronized
    fun put(path: String, filename: String, hash: String, outcome: ScanOutcome, now: Long = System.currentTimeMillis()): CacheEntry {
        val entry = CacheEntry(hash, path, filename, outcome.findings.size, worstOf(outcome), outcome, now)
        entries[path] = entry
        // Prune on write rather than on a timer: no background work, bounded storage.
        expiredKeys(entries, now, RETENTION_MS) { it.at }.forEach(entries::remove)
        save()
        return entry
    }

    @Synchronized
    fun forget(path: String) {
        if (entries.remove(path) != null) save()
    }

    @Synchronized
    fun clearAll() {
        entries.clear()
        save()
    }

    @Synchronized
    fun paths(): List<String> = entries.keys.toList()
}

class IntelCache(file: Path?) : JsonStore<IntelEntry>(file, object : TypeToken<Map<String, IntelEntry>>() {}, { it.at }) {
    @Synchronized
    fun get(id: String, now: Long = System.currentTimeMillis()): CveIntel? =
        entries[id]?.takeIf { now - it.at <= INTEL_MAX_AGE_MS }?.intel

    /** Split ids into what is known and what has to be fetched (each asked once). */
    @Synchronized
    fun partition(ids: Collection<String>, now: Long = System.currentTimeMillis()): Pair<MutableMap<String, CveIntel>, List<String>> {
        val known = LinkedHashMap<String, CveIntel>()
        val missing = mutableListOf<String>()
        for (id in ids.toSet()) get(id, now)?.let { known[id] = it } ?: missing.add(id)
        return known to missing
    }

    @Synchronized
    fun putAll(intel: Map<String, CveIntel>, now: Long = System.currentTimeMillis()) {
        if (intel.isEmpty()) return
        intel.forEach { (id, v) -> entries[id] = IntelEntry(v, now) }
        expiredKeys(entries, now, RETENTION_MS) { it.at }.forEach(entries::remove)
        save()
    }
}

/** Application wide holder: the caches outlive any one project, like in VS Code. */
@Service(Service.Level.APP)
class MlabCaches {
    private val dir: Path = PathManager.getSystemDir().resolve("mlab")
    val scans = ScanCache(dir.resolve("scan-cache.v1.json")).also { it.prune() }
    val intel = IntelCache(dir.resolve("cve-intel.v1.json")).also { it.prune() }

    companion object {
        fun get(): MlabCaches = service()
    }
}

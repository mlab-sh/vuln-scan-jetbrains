package sh.mlab.vulnscan

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import com.intellij.openapi.components.BaseState
import com.intellij.openapi.components.Service
import com.intellij.openapi.components.SimplePersistentStateComponent
import com.intellij.openapi.components.State
import com.intellij.openapi.components.Storage
import com.intellij.openapi.components.service
import com.intellij.openapi.diagnostic.logger
import com.intellij.openapi.project.Project
import com.intellij.openapi.project.guessProjectDir
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.ConcurrentHashMap

// Layered configuration, the same files the VS Code extension, the CLI and the
// GitHub Action read. Highest priority first:
//   1. <project>/.mlab/config.json   committed with the repo, team wide
//   2. ~/.mlab/config.json           personal, every project
//   3. IDE settings (Settings | Tools | mlab)
//   4. built in defaults
//
// The files are re-read whenever their modification time changes, so editing
// one by hand takes effect immediately, without a watcher or a restart.

enum class Layer(val label: String) { PROJECT_FILE("project .mlab"), USER_FILE("~/.mlab"), IDE("IDE"), DEFAULT("default") }

data class Resolved<T>(val value: T, val layer: Layer)

class MlabState : BaseState() {
    var autoScan by property(true)
    var cveHover by property(true)
    var analyzeSelection by property(true)
    var apiUrl by string(DEFAULTS.apiUrl)
    var platformUrl by string(DEFAULTS.platformUrl)
    var severityFloor by string(DEFAULTS.severityFloor)
    var timeoutMs by property(DEFAULTS.timeoutMs)
}

/** Built in defaults, one place. */
object DEFAULTS {
    const val apiUrl = "https://vuln.mlab.sh/api/v2/scan"
    const val platformUrl = DEFAULT_PLATFORM_URL
    const val severityFloor = "any"
    const val timeoutMs = 30000
}

val FLOORS = listOf("any", "low", "medium", "high", "critical")

@Service(Service.Level.APP)
@State(name = "MlabSettings", storages = [Storage("mlab.xml")])
class MlabSettings : SimplePersistentStateComponent<MlabState>(MlabState()) {
    companion object {
        fun get(): MlabSettings = service()
    }
}

object MlabConfig {
    const val DIR = ".mlab"
    const val FILE = "config.json"

    private data class Snapshot(val mtime: Long, val json: JsonObject?)
    private val snapshots = ConcurrentHashMap<Path, Snapshot>()

    fun userFile(): Path = Path.of(System.getProperty("user.home"), DIR, FILE)
    fun projectFile(project: Project?): Path? =
        project?.guessProjectDir()?.takeIf { it.isInLocalFileSystem }?.toNioPath()?.resolve(DIR)?.resolve(FILE)

    /** Parse a config file, tolerating absence. Malformed JSON is logged and ignored. */
    private fun read(path: Path?): JsonObject? {
        if (path == null || !Files.isRegularFile(path)) return null
        val mtime = Files.getLastModifiedTime(path).toMillis()
        snapshots[path]?.takeIf { it.mtime == mtime }?.let { return it.json }
        val json = try {
            JsonParser.parseString(Files.readString(path)).obj()
        } catch (e: Exception) {
            logger<MlabConfig>().warn("mlab: $path is not valid JSON and was ignored", e)
            null
        }
        snapshots[path] = Snapshot(mtime, json)
        return json
    }

    private fun <T> resolve(project: Project?, key: String, fromJson: (JsonObject, String) -> T?, ide: T, default: T): Resolved<T> {
        read(projectFile(project))?.let { j -> fromJson(j, key)?.let { return Resolved(it, Layer.PROJECT_FILE) } }
        read(userFile())?.let { j -> fromJson(j, key)?.let { return Resolved(it, Layer.USER_FILE) } }
        return Resolved(ide, if (ide == default) Layer.DEFAULT else Layer.IDE)
    }

    private val state get() = MlabSettings.get().state

    fun autoScan(p: Project?) = resolve(p, "autoScan", JsonObject::b, state.autoScan, true)
    fun cveHover(p: Project?) = resolve(p, "cveHover", JsonObject::b, state.cveHover, true)
    fun analyzeSelection(p: Project?) = resolve(p, "analyzeSelection", JsonObject::b, state.analyzeSelection, true)
    fun apiUrl(p: Project?) = resolve(p, "apiUrl", JsonObject::s, state.apiUrl ?: DEFAULTS.apiUrl, DEFAULTS.apiUrl)
    fun platformUrl(p: Project?) =
        resolve(p, "platformUrl", JsonObject::s, state.platformUrl ?: DEFAULTS.platformUrl, DEFAULTS.platformUrl)
    fun severityFloor(p: Project?) = resolve(
        p, "severityFloor", { j, k -> j.s(k)?.takeIf { it in FLOORS } },
        state.severityFloor ?: DEFAULTS.severityFloor, DEFAULTS.severityFloor,
    )
    fun timeoutMs(p: Project?) =
        resolve(p, "timeoutMs", { j, k -> j.n(k)?.toInt()?.takeIf { it >= 1000 } }, state.timeoutMs, DEFAULTS.timeoutMs)
}

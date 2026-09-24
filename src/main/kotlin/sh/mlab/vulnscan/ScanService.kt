package sh.mlab.vulnscan

import com.intellij.codeInsight.daemon.DaemonCodeAnalyzer
import com.intellij.ide.BrowserUtil
import com.intellij.ide.impl.isTrusted
import com.intellij.ide.projectView.ProjectView
import com.intellij.ide.util.PropertiesComponent
import com.intellij.notification.NotificationAction
import com.intellij.notification.NotificationGroupManager
import com.intellij.notification.NotificationType
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.application.ModalityState
import com.intellij.openapi.application.ReadAction
import com.intellij.openapi.components.Service
import com.intellij.openapi.components.service
import com.intellij.openapi.diagnostic.thisLogger
import com.intellij.openapi.options.ShowSettingsUtil
import com.intellij.openapi.progress.ProcessCanceledException
import com.intellij.openapi.progress.ProgressIndicator
import com.intellij.openapi.progress.Task
import com.intellij.openapi.project.Project
import com.intellij.openapi.roots.ProjectFileIndex
import com.intellij.openapi.ui.MessageDialogBuilder
import com.intellij.openapi.ui.Messages
import com.intellij.openapi.vfs.LocalFileSystem
import com.intellij.openapi.vfs.VirtualFile
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList

// ─────────────────────────────────────────────────────────────────────────────
// Non-negotiable rule: NOTHING is uploaded without the user's agreement.
// Every path to the network goes through performScan(), which checks consent
// after the content cache and before any request. Automatic scans never show a
// dialog: without prior consent they do nothing at all. Opening a project makes
// zero network calls, and a cached result never re-uploads anything.
// ─────────────────────────────────────────────────────────────────────────────

private const val CONSENT_KEY = "sh.mlab.vulnscan.privacyConsent"
const val TOKENS_URL = "https://vuln.mlab.sh/me/tokens"

/** One scanned lockfile, as the findings tool window shows it. */
data class ScanRecord(val path: String, val filename: String, val outcome: ScanOutcome, val at: Long)

sealed interface ScanResult {
    data class Cached(val outcome: ScanOutcome, val at: Long) : ScanResult
    data class Scanned(val outcome: ScanOutcome) : ScanResult
    data class Skipped(val reason: String) : ScanResult
    data class Failed(val error: Throwable) : ScanResult
}

fun notify(project: Project?, content: String, type: NotificationType, vararg actions: NotificationAction) {
    NotificationGroupManager.getInstance().getNotificationGroup("mlab")
        .createNotification(content, type)
        .apply { actions.forEach(::addAction) }
        .notify(project)
}

fun openSettings(project: Project?) = ApplicationManager.getApplication().invokeLater {
    ShowSettingsUtil.getInstance().showSettingsDialog(project, MlabConfigurable::class.java)
}

@Service(Service.Level.PROJECT)
class ScanService(private val project: Project) {
    private val log = thisLogger()
    private val cache get() = MlabCaches.get().scans

    // ── Results shown in the tool window ────────────────────────────────────
    private val records = ConcurrentHashMap<String, ScanRecord>()
    private val listeners = CopyOnWriteArrayList<() -> Unit>()

    fun records(): List<ScanRecord> = records.values.sortedByDescending { it.at }
    fun addListener(l: () -> Unit) = listeners.add(l)
    fun removeListener(l: () -> Unit) = listeners.remove(l)

    /** Push one outcome to every surface that shows results. */
    private fun publish(path: String, filename: String, outcome: ScanOutcome) {
        records[path] = ScanRecord(path, filename, outcome, System.currentTimeMillis())
        refreshSurfaces()
    }

    private fun refreshSurfaces() {
        listeners.forEach { it() }
        ApplicationManager.getApplication().invokeLater({
            ProjectView.getInstance(project).refresh()
            // The inspection reads the cache, so re-highlighting is all it takes.
            DaemonCodeAnalyzer.getInstance(project).restart()
        }, project.disposed)
    }

    fun isTrusted(): Boolean = project.isTrusted()

    // ── Startup: restore from cache, no network ─────────────────────────────

    /**
     * Repopulate the tool window, Explorer colors and inspection from the cache.
     * The cache is global, so entries are filtered to this project; entries whose
     * lockfile is gone from it are pruned.
     */
    fun rehydrate() {
        val base = project.basePath ?: return
        var restored = 0
        for (path in cache.paths()) {
            if (!path.startsWith("$base/")) continue
            val file = LocalFileSystem.getInstance().findFileByPath(path)
            if (file == null || !file.isValid) {
                cache.forget(path)
                continue
            }
            if (!ReadAction.compute<Boolean, Throwable> { ProjectFileIndex.getInstance(project).isInContent(file) }) continue
            val entry = cache.peek(path) ?: continue
            records[path] = ScanRecord(path, entry.filename, entry.outcome, entry.at)
            restored++
        }
        if (restored > 0) {
            log.info("mlab: restored $restored previous result(s) without scanning")
            refreshSurfaces()
        }
    }

    // ── The one scan primitive ──────────────────────────────────────────────

    /**
     * Every caller goes through this: the action, the auto scanner and the
     * sweep. Runs on a background thread under [indicator].
     *
     * @param auto triggered by a file change, not the user: silent, never prompts.
     * @param batch part of a sweep: no report tab, no per file notification.
     * @param consented the sweep already asked once for this run.
     */
    fun performScan(file: VirtualFile, indicator: ProgressIndicator, auto: Boolean = false, batch: Boolean = false, consented: Boolean = false): ScanResult {
        val filename = file.name
        if (!isSupportedLockfile(filename)) return ScanResult.Skipped("unsupported")
        if (!isTrusted()) return ScanResult.Skipped("untrusted")

        // Read first: the cache is keyed on content, so an unchanged lockfile
        // costs nothing, no consent prompt and no request.
        val body = try {
            file.contentsToByteArray()
        } catch (e: Exception) {
            log.warn("mlab: $filename unreadable", e)
            return ScanResult.Skipped("unreadable")
        }
        val hash = sha256Hex(body)
        cache.lookup(file.path, hash)?.let { hit ->
            publish(file.path, filename, hit.outcome)
            log.info("mlab: $filename ${summarize(hit.outcome)} (unchanged since last scan)")
            return ScanResult.Cached(hit.outcome, hit.at)
        }

        // Only now does anything leave the machine, so this is where consent belongs.
        if (auto) {
            if (!hasConsent()) return ScanResult.Skipped("no-consent")
        } else if (!consented && !ensureConsent()) {
            return ScanResult.Skipped("no-consent")
        }

        val quiet = auto || batch
        val token = if (quiet) null else MlabViews.get(project).beginScan(filename, indicator)
        indicator.text = "mlab: scanning $filename"
        return try {
            val apiUrl = MlabConfig.apiUrl(project).value
            val scanToken = Secret.SCAN_TOKEN.get()
            log.info("mlab: ${if (auto) "auto" else if (batch) "sweep" else "scan"} $filename -> $apiUrl (${if (scanToken != null) "token" else "anonymous"})")
            val outcome = scanLockfile(apiUrl, filename, detectFormat(filename), body, scanToken, MlabConfig.timeoutMs(project).value)
            indicator.text2 = "Fetching exploitation data"
            enrich(outcome)
            cache.put(file.path, filename, hash, outcome)
            publish(file.path, filename, outcome)
            if (!quiet) MlabViews.get(project).finishScan(token, "Report · $filename", reportHtml(filename, outcome, MlabViews.get(project).opts()))
            log.info("mlab: $filename ${summarize(outcome)}")
            ScanResult.Scanned(outcome)
        } catch (e: ProcessCanceledException) {
            if (!quiet) MlabViews.get(project).finishScan(token, "Report · $filename", errorHtml(filename, "Scan cancelled.", ScanErrorKind.CANCELLED, MlabViews.get(project).opts()))
            throw e
        } catch (e: Exception) {
            handleScanError(e, filename, quiet, token)
            ScanResult.Failed(e)
        }
    }

    /**
     * Attach EPSS / KEV / CVSS to each finding. Best effort: a failure here never
     * fails a scan, and cached ids cost nothing.
     */
    private fun enrich(outcome: ScanOutcome) {
        val ids = outcome.findings.map { it.cve }.filter { it.startsWith("CVE-") }
        if (ids.isEmpty()) return
        val intelCache = MlabCaches.get().intel
        val (known, missing) = intelCache.partition(ids)
        if (missing.isNotEmpty()) {
            val fetched = fetchMany(missing, originOf(MlabConfig.apiUrl(project).value), minOf(MlabConfig.timeoutMs(project).value, 10000))
            intelCache.putAll(fetched)
            known.putAll(fetched)
        }
        outcome.findings.forEach { f -> known[f.cve]?.let { f.intel = it } }
    }

    private fun handleScanError(e: Exception, filename: String, quiet: Boolean, token: Int?) {
        val kind = (e as? ScanException)?.kind
        val message = if (e is ScanException) e.message ?: "Scan failed." else "Unexpected error: ${e.message}"
        log.warn("mlab: $filename ${kind ?: "error"}: $message", e.takeIf { e !is ScanException })
        if (token != null) MlabViews.get(project).finishScan(token, "Report · $filename", errorHtml(filename, message, kind, MlabViews.get(project).opts()))
        // A background scan never interrupts: a rate limit would otherwise pop
        // on every debounced write for the rest of the hour.
        if (quiet) return
        when (kind) {
            ScanErrorKind.RATE_LIMIT -> {
                val retry = (e as ScanException).retryAfter?.let { " Retry after ${it}s." } ?: ""
                notify(
                    project, "Rate limit reached.$retry Use an API token for 25 scans/hour.", NotificationType.WARNING,
                    NotificationAction.createSimpleExpiring("Get a token") { BrowserUtil.browse(TOKENS_URL) },
                    NotificationAction.createSimpleExpiring("Add token…") { openSettings(project) },
                )
            }
            ScanErrorKind.CANCELLED -> Unit
            else -> notify(project, message, NotificationType.ERROR)
        }
    }

    // ── Consent ─────────────────────────────────────────────────────────────

    fun hasConsent() = PropertiesComponent.getInstance().getBoolean(CONSENT_KEY, false)

    /**
     * Shown before the first upload. "Scan and don't ask again" is remembered
     * application wide. Callable from a background thread.
     */
    fun ensureConsent(): Boolean {
        if (hasConsent()) return true
        var choice = Messages.CANCEL
        ApplicationManager.getApplication().invokeAndWait({
            choice = MessageDialogBuilder.yesNoCancel(
                "Scan this lockfile with vuln.mlab.sh?",
                "The contents of the selected lockfile are uploaded to vuln.mlab.sh to resolve known CVEs. " +
                    "Only the lockfile is sent, never your source code. Nothing is uploaded until you trigger a scan.",
            ).yesText("Scan Now").noText("Scan and Don't Ask Again").cancelText("Cancel").show(project)
        }, ModalityState.defaultModalityState())
        if (choice == Messages.NO) PropertiesComponent.getInstance().setValue(CONSENT_KEY, true)
        return choice == Messages.YES || choice == Messages.NO
    }

    // ── Entry points ────────────────────────────────────────────────────────

    /** Scan one lockfile. `auto` runs silently in the status bar. */
    fun checkLockfile(file: VirtualFile, auto: Boolean = false) {
        if (!auto && !isTrusted()) {
            notify(project, "Scanning is disabled in this untrusted project because it uploads the lockfile. Trust the project to scan.", NotificationType.WARNING)
            return
        }
        object : Task.Backgroundable(project, "mlab: checking ${file.name}", true) {
            override fun run(indicator: ProgressIndicator) {
                val result = performScan(file, indicator, auto = auto)
                if (auto) return
                when (result) {
                    is ScanResult.Skipped -> if (result.reason == "unreadable") notify(project, "Could not read ${file.name}.", NotificationType.ERROR)
                    is ScanResult.Failed -> Unit
                    is ScanResult.Cached -> {
                        showReport(file.path)
                        announce(file.name, result.outcome)
                    }
                    is ScanResult.Scanned -> announce(file.name, result.outcome)
                }
            }
        }.queue()
    }

    private fun announce(filename: String, outcome: ScanOutcome) {
        if (outcome.findings.isEmpty()) notify(project, "No known vulnerabilities in $filename.", NotificationType.INFORMATION)
        else notify(project, "${summarize(outcome)} in $filename.", NotificationType.WARNING)
    }

    /** Open the stored report for a lockfile. Cache only: no network, no quota. */
    fun showReport(path: String) {
        val entry = cache.peek(path)
        if (entry == null) {
            val file = LocalFileSystem.getInstance().findFileByPath(path)
            notify(
                project, "No results for ${basenameOf(path)} yet.", NotificationType.INFORMATION,
                *listOfNotNull(file?.let { f -> NotificationAction.createSimpleExpiring("Scan now") { checkLockfile(f) } }).toTypedArray(),
            )
            return
        }
        val views = MlabViews.get(project)
        views.finishScan(null, "Report · ${entry.filename}", reportHtml(entry.filename, entry.outcome, views.opts(), entry.at))
        log.info("mlab: ${entry.filename} shown from cache, scanned ${Instant.ofEpochMilli(entry.at)}")
    }

    /** Rescan every lockfile in the tool window. Only reachable by an explicit click. */
    fun rescan() {
        val files = records.values.sortedBy { it.at }.mapNotNull { LocalFileSystem.getInstance().findFileByPath(it.path) }
        if (files.isEmpty()) {
            notify(project, "Nothing to rescan yet. Run a scan first.", NotificationType.INFORMATION)
            return
        }
        files.forEach { checkLockfile(it) }
    }

    /** Clearing results also drops the cache, which is what removes the colors. */
    fun clearResults() {
        records.clear()
        ApplicationManager.getApplication().executeOnPooledThread {
            cache.clearAll()
            refreshSurfaces()
        }
    }

    // ── Scan every lockfile in the project ──────────────────────────────────

    /** Supported lockfiles in the project content, skipping vendored directories. */
    fun findLockfiles(): List<VirtualFile> = ReadAction.compute<List<VirtualFile>, Throwable> {
        val out = mutableListOf<VirtualFile>()
        ProjectFileIndex.getInstance(project).iterateContent(
            { f -> if (!f.isDirectory && isSupportedLockfile(f.name)) out += f; true },
            { f -> !(f.isDirectory && f.name in SKIP_DIRS) },
        )
        out
    }

    /**
     * Quota aware: cached lockfiles cost nothing, so the sweep first works out
     * how many files would really hit the network, and asks before spending.
     */
    fun scanWorkspace() {
        if (!isTrusted()) {
            notify(project, "Scanning is disabled in this untrusted project because it uploads the lockfile. Trust the project to scan.", NotificationType.WARNING)
            return
        }
        object : Task.Backgroundable(project, "mlab: scanning project lockfiles", true) {
            override fun run(indicator: ProgressIndicator) {
                val found = findLockfiles()
                if (found.isEmpty()) {
                    notify(project, "No supported lockfile found in this project.", NotificationType.INFORMATION)
                    return
                }
                val (cached, fresh) = found.partition { f ->
                    runCatching { cache.lookup(f.path, sha256Hex(f.contentsToByteArray())) != null }.getOrDefault(false)
                }
                var consented = false
                if (fresh.size > 1) {
                    val cachedNote = if (cached.isNotEmpty()) " ${cached.size} already cached and free." else ""
                    var go = false
                    ApplicationManager.getApplication().invokeAndWait({
                        go = MessageDialogBuilder.okCancel(
                            "mlab: ${fresh.size} lockfiles need a fresh scan",
                            "That spends ${fresh.size} of your hourly quota (8 anonymous, 25 with a token).$cachedNote",
                        ).yesText("Scan ${fresh.size}").ask(project)
                    }, ModalityState.defaultModalityState())
                    if (!go) return
                    if (!ensureConsent()) return
                    consented = true
                }

                val order = cached + fresh
                var scanned = 0
                var reused = 0
                var vulnerable = 0
                var stopped: String? = null
                indicator.isIndeterminate = false
                for ((i, f) in order.withIndex()) {
                    indicator.checkCanceled()
                    indicator.fraction = i.toDouble() / order.size
                    indicator.text2 = "${f.name} (${i + 1}/${order.size})"
                    when (val r = performScan(f, indicator, batch = true, consented = consented)) {
                        is ScanResult.Cached -> { reused++; if (r.outcome.findings.isNotEmpty()) vulnerable++ }
                        is ScanResult.Scanned -> { scanned++; consented = true; if (r.outcome.findings.isNotEmpty()) vulnerable++ }
                        is ScanResult.Skipped -> if (r.reason == "no-consent") { stopped = "no-consent"; break }
                        // A rate limit hits every remaining file too: stop, do not burn the run.
                        is ScanResult.Failed -> if ((r.error as? ScanException)?.kind == ScanErrorKind.RATE_LIMIT) { stopped = "rate-limit"; break }
                    }
                }
                val line = "$scanned scanned, $reused from cache. $vulnerable lockfile${if (vulnerable == 1) "" else "s"} with known vulnerabilities."
                log.info("mlab: sweep $line")
                when {
                    stopped == "rate-limit" -> notify(project, "$line Stopped early: hourly quota reached.", NotificationType.WARNING)
                    stopped == "no-consent" -> Unit
                    vulnerable > 0 -> notify(project, line, NotificationType.WARNING)
                    else -> notify(project, line, NotificationType.INFORMATION)
                }
            }
        }.queue()
    }

    companion object {
        fun get(project: Project): ScanService = project.service()
    }
}

/** Is `file` a lockfile this project should auto scan (in content, not vendored)? */
fun isWatchedLockfile(project: Project, file: VirtualFile): Boolean {
    if (!isSupportedLockfile(file.name)) return false
    return ReadAction.compute<Boolean, Throwable> {
        val index = ProjectFileIndex.getInstance(project)
        val root = index.getContentRootForFile(file) ?: return@compute false
        generateSequence(file.parent) { it.parent }.takeWhile { it != root }.none { it.name in SKIP_DIRS }
    }
}

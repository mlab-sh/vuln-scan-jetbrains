package sh.mlab.vulnscan

import com.intellij.codeInsight.daemon.DaemonCodeAnalyzer
import com.intellij.openapi.Disposable
import com.intellij.openapi.components.Service
import com.intellij.openapi.components.service
import com.intellij.openapi.project.Project
import com.intellij.openapi.startup.ProjectActivity
import com.intellij.openapi.vfs.VirtualFile
import com.intellij.openapi.vfs.newvfs.BulkFileListener
import com.intellij.openapi.vfs.newvfs.events.VFileContentChangeEvent
import com.intellij.openapi.vfs.newvfs.events.VFileCreateEvent
import com.intellij.openapi.vfs.newvfs.events.VFileEvent
import com.intellij.util.ui.update.MergingUpdateQueue
import com.intellij.util.ui.update.Update

// Rescans a lockfile when its content changes on disk.
//
// This does NOT weaken the consent rule: the listener only calls back into the
// normal scan path, which is gated on the one time privacy consent, so until it
// is given this produces no traffic at all. Writes are debounced because one
// `npm install` rewrites the lockfile several times and each scan costs quota.

const val DEBOUNCE_MS = 4000

@Service(Service.Level.PROJECT)
class AutoScanQueue(private val project: Project) : Disposable {
    private val queue = MergingUpdateQueue("mlab.autoscan", DEBOUNCE_MS, true, null, this, null, false)
        .apply { setRestartTimerOnAdd(true) }

    /** Coalesce a burst of writes to the same file into one scan. */
    fun schedule(file: VirtualFile) {
        queue.queue(Update.create(file.path) {
            if (!project.isDisposed && file.isValid) ScanService.get(project).checkLockfile(file, auto = true)
        })
    }

    override fun dispose() = Unit
}

/** Registered as a project listener in plugin.xml, so it lives and dies with the project. */
class LockfileChangeListener(private val project: Project) : BulkFileListener {
    override fun after(events: List<VFileEvent>) {
        if (project.isDisposed) return
        var configChanged = false
        for (e in events) {
            if (e !is VFileContentChangeEvent && e !is VFileCreateEvent) continue
            val file = e.file ?: continue
            if (file.name == MlabConfig.FILE && file.parent?.name == MlabConfig.DIR) configChanged = true
            if (!isSupportedLockfile(file.name)) continue
            // Read per event, so toggling autoScan (in any layer) applies at once.
            if (MlabConfig.autoScan(project).value && isWatchedLockfile(project, file)) {
                project.service<AutoScanQueue>().schedule(file)
            }
        }
        // `.mlab/config.json` edited by hand: severityFloor may have moved.
        if (configChanged) DaemonCodeAnalyzer.getInstance(project).restart()
    }
}

/** On project open: restore previous results from the cache. Zero network calls. */
class MlabStartup : ProjectActivity {
    override suspend fun execute(project: Project) {
        ScanService.get(project).rehydrate()
    }
}

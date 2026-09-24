package sh.mlab.vulnscan

import com.intellij.notification.NotificationAction
import com.intellij.notification.NotificationType
import com.intellij.openapi.actionSystem.ActionUpdateThread
import com.intellij.openapi.actionSystem.AnAction
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.actionSystem.CommonDataKeys
import com.intellij.openapi.progress.ProgressIndicator
import com.intellij.openapi.progress.Task
import com.intellij.openapi.project.DumbAware
import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.VirtualFile

// Every action is an explicit user gesture. Menu entries on files only appear
// on recognized lockfiles, never on other files.

abstract class MlabAction : AnAction(), DumbAware {
    override fun getActionUpdateThread() = ActionUpdateThread.BGT
}

/** The lockfile under the gesture: selected in the Project view, or the open editor's file. */
private fun AnActionEvent.lockfile(): VirtualFile? =
    getData(CommonDataKeys.VIRTUAL_FILE)?.takeIf { !it.isDirectory && isSupportedLockfile(it.name) }

class CheckLockfileAction : MlabAction() {
    override fun update(e: AnActionEvent) {
        e.presentation.isEnabledAndVisible = e.project != null && e.lockfile() != null
    }

    override fun actionPerformed(e: AnActionEvent) {
        val project = e.project ?: return
        ScanService.get(project).checkLockfile(e.lockfile() ?: return)
    }
}

class ShowReportAction : MlabAction() {
    override fun update(e: AnActionEvent) {
        e.presentation.isEnabledAndVisible = e.project != null && e.lockfile() != null
    }

    override fun actionPerformed(e: AnActionEvent) {
        val project = e.project ?: return
        ScanService.get(project).showReport(e.lockfile()?.path ?: return)
    }
}

class ScanWorkspaceAction : MlabAction() {
    override fun update(e: AnActionEvent) {
        e.presentation.isEnabled = e.project != null
    }

    override fun actionPerformed(e: AnActionEvent) {
        ScanService.get(e.project ?: return).scanWorkspace()
    }
}

class RescanAction : MlabAction() {
    override fun update(e: AnActionEvent) {
        e.presentation.isEnabled = e.project?.let { ScanService.get(it).records().isNotEmpty() } == true
    }

    override fun actionPerformed(e: AnActionEvent) {
        ScanService.get(e.project ?: return).rescan()
    }
}

class ClearResultsAction : MlabAction() {
    override fun update(e: AnActionEvent) {
        e.presentation.isEnabled = e.project?.let { ScanService.get(it).records().isNotEmpty() } == true
    }

    override fun actionPerformed(e: AnActionEvent) {
        ScanService.get(e.project ?: return).clearResults()
    }
}

class OpenSettingsAction : MlabAction() {
    override fun actionPerformed(e: AnActionEvent) = openSettings(e.project)
}

// ── Analyze the selected indicator ───────────────────────────────────────────
// The type is worked out locally, then the value alone reaches the endpoint for
// that type. Selecting text and running the action is itself the explicit act,
// so this needs no separate consent: nothing is read beyond the selection.

private fun Char.isDelim() = isWhitespace() || this in "'\"`<>()[]{},;"

class AnalyzeSelectionAction : MlabAction() {
    override fun update(e: AnActionEvent) {
        val editor = e.getData(CommonDataKeys.EDITOR)
        e.presentation.isEnabledAndVisible = e.project != null && editor != null &&
            MlabConfig.analyzeSelection(e.project).value
    }

    override fun actionPerformed(e: AnActionEvent) {
        val project = e.project ?: return
        val editor = e.getData(CommonDataKeys.EDITOR) ?: return
        // Fall back to the token under the caret, so a double click is enough.
        val raw = editor.selectionModel.selectedText ?: run {
            val text = editor.document.charsSequence
            val at = editor.caretModel.offset
            var s = at
            var t = at
            while (s > 0 && !text[s - 1].isDelim()) s--
            while (t < text.length && !text[t].isDelim()) t++
            text.subSequence(s, t).toString()
        }
        analyze(project, cleanIndicator(raw))
    }
}

fun analyze(project: Project, value: String) {
    if (value.isEmpty()) {
        notify(project, "Nothing selected to analyse.", NotificationType.INFORMATION)
        return
    }
    if (value.length > MAX_INDICATOR_LENGTH) {
        notify(project, "That selection is ${value.length} characters. Select a single indicator, not a block of the file.", NotificationType.WARNING)
        return
    }
    if (!ScanService.get(project).isTrusted()) {
        notify(project, "Analysis is disabled in this untrusted project because it sends the selected value. Trust the project to use it.", NotificationType.WARNING)
        return
    }
    val kind = detectKind(value)
    if (!kind.isSupported) {
        val short = if (value.length <= 40) value else value.take(39) + "…"
        notify(project, "Could not tell what \"$short\" is, so nothing was sent. Supported: URL, IP, email, file hash, MAC address, domain.", NotificationType.INFORMATION)
        return
    }

    val views = MlabViews.get(project)
    val title = "mlab · ${if (value.length <= 30) value else value.take(29) + "…"}"
    views.show("indicator", title, indicatorLoadingHtml(kind, value, views.opts()))

    object : Task.Backgroundable(project, "mlab: looking up ${kind.label}", true) {
        override fun run(indicator: ProgressIndicator) {
            try {
                val key = Secret.PLATFORM_KEY.get()
                val base = MlabConfig.platformUrl(project).value
                val timeout = MlabConfig.timeoutMs(project).value
                val report = if (kind.isActive) {
                    // A domain is launched, polled, then read, and it contacts the target.
                    scanDomain(base, value, key, timeout) { state ->
                        indicator.text2 = when (state) {
                            DomainState.REUSED -> "reusing the existing scan, no quota spent"
                            DomainState.DONE -> "collecting results"
                            else -> "${state.name.lowercase()}…"
                        }
                    }
                } else {
                    lookup(base, kind, value, key, timeout)
                }
                // Always offer the full result in a browser: the view is a summary.
                report.webUrl = webUrlFor(originOf(base), kind, value)
                views.show("indicator", title, indicatorHtml(report, views.opts()))
            } catch (ex: IndicatorException) {
                views.show("indicator", title, indicatorErrorHtml(kind, value, ex.message ?: "Lookup failed.", views.opts()))
                if (ex.kind == ScanErrorKind.RATE_LIMIT) {
                    notify(project, ex.message ?: "", NotificationType.WARNING,
                        NotificationAction.createSimpleExpiring("Add a platform key") { openSettings(project) })
                } else {
                    notify(project, ex.message ?: "Lookup failed.", NotificationType.ERROR)
                }
            }
        }

        override fun onCancel() {
            views.show("indicator", title, indicatorErrorHtml(kind, value, "Cancelled.", views.opts()))
        }
    }.queue()
}


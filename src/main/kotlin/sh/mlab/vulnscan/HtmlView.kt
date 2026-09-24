package sh.mlab.vulnscan

import com.intellij.ide.BrowserUtil
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.application.ModalityState
import com.intellij.openapi.components.Service
import com.intellij.openapi.components.service
import com.intellij.openapi.fileEditor.FileEditor
import com.intellij.openapi.fileEditor.FileEditorManager
import com.intellij.openapi.fileEditor.FileEditorPolicy
import com.intellij.openapi.fileEditor.FileEditorProvider
import com.intellij.openapi.fileEditor.FileEditorState
import com.intellij.openapi.fileEditor.impl.EditorTabTitleProvider
import com.intellij.openapi.progress.ProgressIndicator
import com.intellij.openapi.project.DumbAware
import com.intellij.openapi.project.Project
import com.intellij.openapi.util.Disposer
import com.intellij.openapi.util.UserDataHolderBase
import com.intellij.openapi.vfs.VirtualFile
import com.intellij.testFramework.LightVirtualFile
import com.intellij.ui.JBColor
import com.intellij.ui.components.JBLabel
import com.intellij.ui.jcef.JBCefApp
import com.intellij.ui.jcef.JBCefBrowser
import com.intellij.util.ui.JBUI
import org.cef.browser.CefBrowser
import org.cef.browser.CefFrame
import org.cef.handler.CefRequestHandlerAdapter
import org.cef.network.CefRequest
import java.beans.PropertyChangeListener
import javax.swing.JComponent
import javax.swing.SwingConstants

// The report and indicator views: an editor tab holding an embedded browser.
// Two reusable tabs ("slots"), like the two VS Code webview panels, so an
// indicator lookup never wipes a scan report the user is still reading.

class MlabHtmlFile(val slot: String) : LightVirtualFile("mlab $slot") {
    @Volatile var title: String = "mlab"
    @Volatile var html: String = ""
    val listeners = mutableListOf<() -> Unit>()

    init {
        isWritable = false
    }
}

class MlabHtmlEditorProvider : FileEditorProvider, DumbAware {
    override fun accept(project: Project, file: VirtualFile) = file is MlabHtmlFile
    override fun createEditor(project: Project, file: VirtualFile): FileEditor = MlabHtmlEditor(file as MlabHtmlFile)
    override fun getEditorTypeId() = "mlab-html"
    override fun getPolicy() = FileEditorPolicy.HIDE_DEFAULT_EDITOR
}

class MlabHtmlTabTitleProvider : EditorTabTitleProvider, DumbAware {
    override fun getEditorTabTitle(project: Project, file: VirtualFile): String? = (file as? MlabHtmlFile)?.title
}

private class MlabHtmlEditor(private val file: MlabHtmlFile) : UserDataHolderBase(), FileEditor {
    private val browser: JBCefBrowser? = if (JBCefApp.isSupported()) JBCefBrowser() else null

    // Without JCEF (some remote and embedded setups) the same results stay
    // available in the mlab tool window and the Problems view.
    private val component: JComponent = browser?.component ?: JBLabel(
        "<html><center>The embedded browser is not available in this IDE.<br>" +
            "Results are in the mlab tool window and in the Problems view.</center></html>",
        SwingConstants.CENTER,
    ).apply { border = JBUI.Borders.empty(24) }

    private val reload: () -> Unit = { browser?.loadHTML(file.html) }

    init {
        browser?.let { b ->
            Disposer.register(this, b)
            // Links open in the system browser; the view itself never navigates.
            b.jbCefClient.addRequestHandler(object : CefRequestHandlerAdapter() {
                override fun onBeforeBrowse(cb: CefBrowser?, frame: CefFrame?, request: CefRequest?, userGesture: Boolean, isRedirect: Boolean): Boolean {
                    if (!userGesture) return false
                    request?.url?.takeIf { it.startsWith("https://") || it.startsWith("http://") }?.let(BrowserUtil::browse)
                    return true
                }
            }, b.cefBrowser)
        }
        file.listeners += reload
        reload()
    }

    override fun getComponent() = component
    override fun getPreferredFocusedComponent() = component
    override fun getName() = "mlab"
    override fun getFile(): VirtualFile = file
    override fun setState(state: FileEditorState) = Unit
    override fun isModified() = false
    override fun isValid() = true
    override fun addPropertyChangeListener(listener: PropertyChangeListener) = Unit
    override fun removePropertyChangeListener(listener: PropertyChangeListener) = Unit
    override fun dispose() {
        file.listeners -= reload
    }
}

@Service(Service.Level.PROJECT)
class MlabViews(private val project: Project) {
    private val files = HashMap<String, MlabHtmlFile>()

    /** Incremented per scan; a stale generation may no longer write to the report. */
    private var generation = 0
    private var running: ProgressIndicator? = null

    fun opts() = RenderOpts(dark = !JBColor.isBright())

    /** Show (or refresh) a slot. Safe from any thread; never steals focus. */
    fun show(slot: String, title: String, html: String) {
        ApplicationManager.getApplication().invokeLater({
            val f = files.getOrPut(slot) { MlabHtmlFile(slot) }
            f.title = title
            f.html = html
            f.listeners.toList().forEach { it() }
            val fem = FileEditorManager.getInstance(project)
            fem.openFile(f, false)
            fem.updateFilePresentation(f)
        }, ModalityState.nonModal(), project.disposed)
    }

    /**
     * Claim the report for a new scan. Whatever scan was showing is cancelled,
     * since it just lost the only surface it could report on. The returned token
     * is how later calls prove they still own the report.
     */
    @Synchronized
    fun beginScan(filename: String, indicator: ProgressIndicator): Int {
        running?.takeIf { it !== indicator }?.cancel()
        running = indicator
        generation++
        show("report", "Scanning $filename…", loadingHtml(filename, opts()))
        return generation
    }

    @Synchronized
    fun finishScan(token: Int?, title: String, html: String) {
        if (token != null && token != generation) return
        if (token != null) running = null
        show("report", title, html)
    }

    companion object {
        fun get(project: Project): MlabViews = project.service()
    }
}

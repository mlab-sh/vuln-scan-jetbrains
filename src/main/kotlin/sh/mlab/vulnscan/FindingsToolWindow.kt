package sh.mlab.vulnscan

import com.intellij.icons.AllIcons
import com.intellij.ide.BrowserUtil
import com.intellij.openapi.actionSystem.ActionManager
import com.intellij.openapi.actionSystem.DefaultActionGroup
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.project.DumbAware
import com.intellij.openapi.project.Project
import com.intellij.openapi.ui.SimpleToolWindowPanel
import com.intellij.openapi.util.Disposer
import com.intellij.openapi.vfs.LocalFileSystem
import com.intellij.openapi.wm.ToolWindow
import com.intellij.openapi.wm.ToolWindowFactory
import com.intellij.ui.ColoredTreeCellRenderer
import com.intellij.ui.DoubleClickListener
import com.intellij.ui.JBColor
import com.intellij.ui.ScrollPaneFactory
import com.intellij.ui.SimpleTextAttributes
import com.intellij.ui.content.ContentFactory
import com.intellij.ui.treeStructure.Tree
import com.intellij.util.ui.tree.TreeUtil
import java.awt.Color
import java.awt.event.MouseEvent
import javax.swing.JTree
import javax.swing.tree.DefaultMutableTreeNode
import javax.swing.tree.DefaultTreeModel
import javax.swing.tree.TreeSelectionModel

// The results surface: lockfile -> severity -> advisory. Pure state plus
// rendering, it never scans anything itself; ScanService pushes results in.

private sealed interface Node
private data class FileNode(val record: ScanRecord) : Node
private data class SeverityNode(val severity: Severity, val count: Int) : Node
private data class FindingNode(val finding: Finding) : Node
private data object CleanNode : Node

/** Severity colors, from the site's SEVCOLOR map, light and dark. */
fun severityColor(s: Severity?): Color = when (s) {
    Severity.CRITICAL -> JBColor(0xDC2626, 0xF87171)
    Severity.HIGH -> JBColor(0xEA580C, 0xFB923C)
    Severity.MEDIUM -> JBColor(0xD97706, 0xFBBF24)
    Severity.LOW -> JBColor(0x2563EB, 0x60A5FA)
    else -> JBColor(0x6B7280, 0x9CA3AF)
}

class FindingsToolWindowFactory : ToolWindowFactory, DumbAware {
    override fun createToolWindowContent(project: Project, toolWindow: ToolWindow) {
        val panel = FindingsPanel(project)
        val content = ContentFactory.getInstance().createContent(panel, "Vulnerabilities", false)
        Disposer.register(content, panel)
        toolWindow.contentManager.addContent(content)
        panel.onTotal = { n -> content.displayName = if (n > 0) "Vulnerabilities ($n)" else "Vulnerabilities" }
        panel.rebuild()
    }
}

private class FindingsPanel(private val project: Project) : SimpleToolWindowPanel(true, true), com.intellij.openapi.Disposable {
    private val root = DefaultMutableTreeNode()
    private val model = DefaultTreeModel(root)
    private val tree = Tree(model)
    private val service = ScanService.get(project)
    private val listener: () -> Unit = { ApplicationManager.getApplication().invokeLater({ rebuild() }, project.disposed) }
    var onTotal: (Int) -> Unit = {}

    init {
        tree.isRootVisible = false
        tree.showsRootHandles = true
        tree.selectionModel.selectionMode = TreeSelectionModel.SINGLE_TREE_SELECTION
        tree.cellRenderer = Renderer()
        tree.emptyText.apply {
            clear()
            appendLine("No scan has been run yet.")
            appendLine("Nothing is sent to vuln.mlab.sh until you agree once.", SimpleTextAttributes.GRAYED_ATTRIBUTES, null)
            appendLine("Scan all lockfiles in project", SimpleTextAttributes.LINK_PLAIN_ATTRIBUTES) { service.scanWorkspace() }
            appendLine("Open mlab settings", SimpleTextAttributes.LINK_PLAIN_ATTRIBUTES) { openSettings(project) }
            appendLine("Supported: ${SUPPORTED_BASENAMES.joinToString(", ")}", SimpleTextAttributes.GRAYED_SMALL_ATTRIBUTES, null)
        }
        object : DoubleClickListener() {
            override fun onDoubleClick(event: MouseEvent): Boolean {
                activate(TreeUtil.getLastUserObject(tree.selectionPath))
                return true
            }
        }.installOn(tree)
        TreeUtil.installActions(tree)

        val am = ActionManager.getInstance()
        val group = DefaultActionGroup(
            am.getAction("sh.mlab.vulnscan.OpenSettings"),
            am.getAction("sh.mlab.vulnscan.ScanWorkspace"),
            am.getAction("sh.mlab.vulnscan.Rescan"),
            am.getAction("sh.mlab.vulnscan.ClearResults"),
        )
        toolbar = am.createActionToolbar("mlab.findings", group, true).apply { targetComponent = tree }.component
        setContent(ScrollPaneFactory.createScrollPane(tree))
        service.addListener(listener)
    }

    /** A lockfile shows its report (cache only); an advisory opens its CVE page. */
    private fun activate(node: Any?) {
        when (node) {
            is FileNode -> service.showReport(node.record.path)
            is FindingNode -> node.finding.url?.let(BrowserUtil::browse)
            else -> Unit
        }
    }

    fun rebuild() {
        val expanded = TreeUtil.collectExpandedUserObjects(tree).filterIsInstance<FileNode>().map { it.record.path }.toSet()
        root.removeAllChildren()
        val records = service.records()
        for (rec in records) {
            val fileNode = DefaultMutableTreeNode(FileNode(rec))
            val findings = rec.outcome.findings
            if (findings.isEmpty()) fileNode.add(DefaultMutableTreeNode(CleanNode))
            for (s in Severity.ORDER) {
                val group = findings.filter { it.severity == s }.sortedWith(compareBy({ it.pkg }, { it.cve }))
                if (group.isEmpty()) continue
                val sevNode = DefaultMutableTreeNode(SeverityNode(s, group.size))
                group.forEach { sevNode.add(DefaultMutableTreeNode(FindingNode(it))) }
                fileNode.add(sevNode)
            }
            root.add(fileNode)
        }
        model.reload()
        // Lockfiles open by default, severity groups collapsed, as in VS Code.
        for (i in 0 until root.childCount) {
            val child = root.getChildAt(i) as DefaultMutableTreeNode
            val path = (child.userObject as FileNode).record.path
            if (expanded.isEmpty() || path in expanded) tree.expandPath(javax.swing.tree.TreePath(child.path))
        }
        onTotal(records.sumOf { it.outcome.findings.size })
    }

    override fun dispose() {
        service.removeListener(listener)
    }

    private class Renderer : ColoredTreeCellRenderer() {
        override fun customizeCellRenderer(tree: JTree, value: Any?, selected: Boolean, expanded: Boolean, leaf: Boolean, row: Int, hasFocus: Boolean) {
            when (val node = (value as? DefaultMutableTreeNode)?.userObject) {
                is FileNode -> {
                    val rec = node.record
                    icon = LocalFileSystem.getInstance().findFileByPath(rec.path)?.fileType?.icon ?: AllIcons.FileTypes.Any_type
                    append(rec.filename)
                    append("  ${summarize(rec.outcome)}", SimpleTextAttributes.GRAYED_ATTRIBUTES)
                    toolTipText = "${rec.path}\n${rec.outcome.deps} dependencies scanned"
                }
                is SeverityNode -> {
                    icon = AllIcons.Nodes.Folder
                    append(node.severity.id, SimpleTextAttributes(SimpleTextAttributes.STYLE_BOLD, severityColor(node.severity)))
                    append("  ${node.count}", SimpleTextAttributes.GRAYED_ATTRIBUTES)
                }
                is FindingNode -> {
                    val f = node.finding
                    icon = if (f.severity.rank >= Severity.HIGH.rank) AllIcons.General.Error else if (f.severity == Severity.MEDIUM) AllIcons.General.Warning else AllIcons.General.Information
                    append(f.cve, SimpleTextAttributes(SimpleTextAttributes.STYLE_PLAIN, severityColor(f.severity)))
                    if (urgencyOf(f.intel) == Urgency.EXPLOITED) append("  exploited", SimpleTextAttributes.ERROR_ATTRIBUTES)
                    append("  ${f.pkg}${f.fixedVersion?.let { " (fix: $it)" } ?: ""}", SimpleTextAttributes.GRAYED_ATTRIBUTES)
                    toolTipText = listOfNotNull(f.summary, f.fixedVersion?.let { "Fixed in $it" } ?: "No fixed version published").joinToString("\n")
                }
                CleanNode -> {
                    icon = AllIcons.RunConfigurations.TestPassed
                    append("No known vulnerabilities", SimpleTextAttributes.GRAYED_ATTRIBUTES)
                }
                else -> Unit
            }
        }
    }
}


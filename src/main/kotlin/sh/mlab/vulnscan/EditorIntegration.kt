package sh.mlab.vulnscan

import com.intellij.codeInspection.InspectionManager
import com.intellij.codeInspection.LocalInspectionTool
import com.intellij.codeInspection.LocalQuickFix
import com.intellij.codeInspection.ProblemDescriptor
import com.intellij.codeInspection.ProblemHighlightType
import com.intellij.ide.BrowserUtil
import com.intellij.ide.impl.isTrusted
import com.intellij.ide.projectView.PresentationData
import com.intellij.ide.projectView.ProjectViewNode
import com.intellij.ide.projectView.ProjectViewNodeDecorator
import com.intellij.lang.documentation.AbstractDocumentationProvider
import com.intellij.lang.documentation.DocumentationMarkup
import com.intellij.openapi.editor.Editor
import com.intellij.openapi.project.Project
import com.intellij.openapi.util.TextRange
import com.intellij.psi.PsiElement
import com.intellij.psi.PsiFile
import com.intellij.psi.impl.FakePsiElement
import com.intellij.ui.SimpleTextAttributes

// ── Problems view: one problem per finding, on the line declaring the package ──
// Reads the cache only, so highlighting never touches the network.

class VulnerableDependencyInspection : LocalInspectionTool() {
    override fun checkFile(file: PsiFile, manager: InspectionManager, isOnTheFly: Boolean): Array<ProblemDescriptor>? {
        val vf = file.virtualFile ?: return null
        if (!isSupportedLockfile(vf.name)) return null
        val entry = MlabCaches.get().scans.peek(vf.path) ?: return null
        if (entry.outcome.findings.isEmpty()) return null

        val text = file.text
        val lineStarts = IntArray(text.count { it == '\n' } + 1).also { starts ->
            var n = 1
            text.forEachIndexed { i, c -> if (c == '\n') starts[n++] = i + 1 }
        }
        val floor = MlabConfig.severityFloor(file.project).value
        return entry.outcome.findings.map { f ->
            val hit = locateLine(text, f.name, f.version)
            val start = (lineStarts.getOrElse(hit.line) { 0 } + hit.col).coerceIn(0, text.length)
            val end = (lineStarts.getOrElse(hit.line) { 0 } + hit.endCol).coerceIn(start, text.length)
            val fix = f.fixedVersion?.let { " Fixed in $it." } ?: " No fixed version published."
            val type = when (levelFor(f.severity, floor)) {
                DiagLevel.ERROR -> ProblemHighlightType.GENERIC_ERROR
                DiagLevel.WARNING -> ProblemHighlightType.WARNING
                DiagLevel.INFORMATION -> ProblemHighlightType.WEAK_WARNING
            }
            val fixes = listOfNotNull(f.url?.let { OpenAdvisoryFix(f.cve, it) }).toTypedArray()
            manager.createProblemDescriptor(
                file, TextRange(start, end), "mlab: ${f.cve} (${f.severity.id}) in ${f.pkg}.$fix${f.summary?.let { " $it" } ?: ""}",
                type, isOnTheFly, *fixes,
            )
        }.toTypedArray()
    }
}

private class OpenAdvisoryFix(private val cve: String, private val url: String) : LocalQuickFix {
    override fun getFamilyName() = "Open advisory on vuln.mlab.sh"
    override fun getName() = "Open $cve on vuln.mlab.sh"
    override fun startInWriteAction() = false
    override fun applyFix(project: Project, descriptor: ProblemDescriptor) = BrowserUtil.browse(url)
}

// ── Project view: vulnerable lockfiles colored by their worst severity ─────────
// Driven by the content-keyed cache, so a lockfile stays red until it is patched.

private val BADGE = mapOf(Severity.CRITICAL to "C", Severity.HIGH to "H", Severity.MEDIUM to "M", Severity.LOW to "L")

class LockfileDecorator : ProjectViewNodeDecorator {
    override fun decorate(node: ProjectViewNode<*>, data: PresentationData) {
        val file = node.virtualFile ?: return
        if (file.isDirectory || !isSupportedLockfile(file.name)) return
        val entry = MlabCaches.get().scans.peek(file.path) ?: return
        val n = entry.findingCount
        if (n == 0) return
        val sev = entry.worstSeverity
        data.clearText()
        data.addText(file.name, SimpleTextAttributes(SimpleTextAttributes.STYLE_PLAIN, severityColor(sev)))
        data.addText("  ${BADGE[sev] ?: "?"} · $n", SimpleTextAttributes.GRAYED_SMALL_ATTRIBUTES)
        data.tooltip = "mlab: $n known vulnerabilit${if (n == 1) "y" else "ies"}, worst is ${sev?.id ?: "unknown"}"
    }
}

// ── Hover a CVE id anywhere for CVSS, EPSS and known-exploited status ─────────
// Only the identifier is sent, never the surrounding code, which is why this
// needs no privacy consent of its own. Lookups are cached for a day.

val CVE_PATTERN = Regex("CVE-\\d{4}-\\d{4,7}", RegexOption.IGNORE_CASE)

class CveElement(private val parent: PsiElement, val id: String) : FakePsiElement() {
    override fun getParent() = parent
    override fun getName() = id
    override fun getPresentableText() = id
    override fun isValid() = parent.isValid
}

class CveDocumentationProvider : AbstractDocumentationProvider() {
    override fun getCustomDocumentationElement(editor: Editor, file: PsiFile, contextElement: PsiElement?, targetOffset: Int): PsiElement? {
        if (!MlabConfig.cveHover(file.project).value) return null
        val text = editor.document.charsSequence
        // Scan a small window around the caret; a CVE id is at most 18 chars.
        val from = (targetOffset - 20).coerceAtLeast(0)
        val to = (targetOffset + 20).coerceAtMost(text.length)
        val match = CVE_PATTERN.findAll(text.subSequence(from, to))
            .firstOrNull { targetOffset - from in it.range.first..it.range.last + 1 } ?: return null
        return CveElement(contextElement ?: file, match.value.uppercase())
    }

    override fun generateDoc(element: PsiElement?, originalElement: PsiElement?): String? {
        val cve = element as? CveElement ?: return null
        val project = cve.project
        // Hovering triggers a request, so untrusted projects stay quiet.
        if (!project.isTrusted()) return null
        val cache = MlabCaches.get().intel
        val intel = cache.get(cve.id) ?: fetchCve(cve.id, originOf(MlabConfig.apiUrl(project).value), 4000)
            ?.also { cache.putAll(mapOf(cve.id to it)) }
            ?: return null
        return cveDoc(intel)
    }
}

fun cveDoc(intel: CveIntel): String {
    val sev = intel.cvssSeverity?.uppercase() ?: "unrated"
    val score = intel.cvssScore?.let { " $it" } ?: ""
    val sb = StringBuilder(DocumentationMarkup.DEFINITION_START)
        .append("<b>").append(esc(intel.id)).append("</b> ").append(esc(sev + score))
        .append(DocumentationMarkup.DEFINITION_END).append(DocumentationMarkup.CONTENT_START)
    if (intel.inKev || intel.inEuKev) {
        val which = if (intel.inKev) "CISA" else "EU"
        val since = intel.kevDateAdded?.let { ", added $it" } ?: ""
        val due = intel.kevDueDate?.let { ", remediation due $it" } ?: ""
        sb.append("<p><b>⚠ Actively exploited</b> (${esc("$which known exploited catalogue$since$due")})</p>")
    }
    epssLabel(intel)?.let { epss ->
        val pct = intel.epssPercentile?.let { " (higher than ${Math.round(it * 100)}% of all CVEs)" } ?: ""
        sb.append("<p>Exploitation likelihood: <b>$epss</b> in the next 30 days$pct</p>")
    }
    intel.riskScore?.let { sb.append("<p>mlab risk score: <b>${"%.1f".format(java.util.Locale.ROOT, it)}</b> / 100</p>") }
    if (intel.weaknesses.isNotEmpty()) sb.append("<p>Weaknesses: ${esc(intel.weaknesses.joinToString(", "))}</p>")
    intel.cvssVector?.let { sb.append("<p><code>${esc(it)}</code></p>") }
    sb.append("<p><a href=\"https://vuln.mlab.sh/cve/${esc(intel.id)}\">Open on vuln.mlab.sh</a></p>")
    return sb.append(DocumentationMarkup.CONTENT_END).toString()
}

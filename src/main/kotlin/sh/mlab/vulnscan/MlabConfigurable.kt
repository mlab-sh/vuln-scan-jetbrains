package sh.mlab.vulnscan

import com.intellij.codeInsight.daemon.DaemonCodeAnalyzer
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.application.ModalityState
import com.intellij.openapi.options.BoundConfigurable
import com.intellij.openapi.project.Project
import com.intellij.openapi.ui.DialogPanel
import com.intellij.openapi.ui.ValidationInfo
import com.intellij.ui.components.JBLabel
import com.intellij.ui.components.JBPasswordField
import com.intellij.ui.dsl.builder.AlignX
import com.intellij.ui.dsl.builder.bindIntText
import com.intellij.ui.dsl.builder.bindItem
import com.intellij.ui.dsl.builder.bindSelected
import com.intellij.ui.dsl.builder.bindText
import com.intellij.ui.dsl.builder.columns
import com.intellij.ui.dsl.builder.panel
import com.intellij.ui.dsl.builder.COLUMNS_LARGE
import java.net.URI

// Settings | Tools | mlab: quota status, both credentials, and every setting.
//
// Settings edited here are the IDE layer. A `.mlab/config.json` in the project
// or the home directory wins over them, and each row says so when it happens,
// so the page never shows a value that is not the one in effect.
//
// Credentials go to the IDE password safe only. The fields start empty and are
// written on Apply only when something was typed.

class MlabConfigurable(private val project: Project) : BoundConfigurable("mlab") {
    private val state get() = MlabSettings.get().state
    private val tokenField = JBPasswordField()
    private val keyField = JBPasswordField()
    private val tokenStatus = JBLabel(" ")
    private val keyStatus = JBLabel(" ")

    private fun overridden(layer: Layer): String? = when (layer) {
        Layer.PROJECT_FILE -> "Overridden by ${MlabConfig.projectFile(project)}"
        Layer.USER_FILE -> "Overridden by ${MlabConfig.userFile()}"
        else -> null
    }

    override fun createPanel(): DialogPanel = panel {
        row {
            comment(
                "On demand CVE scanning for your lockfiles. Nothing leaves your machine until you ask: " +
                    "the first scan asks for consent, and only the lockfile is ever uploaded, never your source code.",
            )
        }
        group("vuln.mlab.sh scan token") {
            row { cell(tokenStatus) }
            row("Token:") {
                cell(tokenField).columns(COLUMNS_LARGE).comment("Leave empty to keep the current token.")
                button("Remove") { clear(Secret.SCAN_TOKEN) }
            }
            row {
                browserLink("Generate a token at vuln.mlab.sh/me/tokens", TOKENS_URL)
            }
            row { comment("Anonymous scans are capped at 8/hour per IP; a token raises this to 25/hour. Stored in the IDE password safe, never in settings or the project.") }
        }
        group("mlab platform key") {
            row { cell(keyStatus) }
            row("Key:") {
                cell(keyField).columns(COLUMNS_LARGE).comment("Leave empty to keep the current key.")
                button("Remove") { clear(Secret.PLATFORM_KEY) }
            }
            row { browserLink("Create a key in your mlab.sh account", "https://mlab.sh/account/subscription") }
            row { comment("A separate credential from the scan token: it is for Analyze Selection lookups on the mlab platform, which also work without it at a reduced daily quota.") }
        }
        group("Behaviour") {
            row {
                checkBox("Scan automatically when a lockfile changes").bindSelected(state::autoScan)
                    .comment(overridden(MlabConfig.autoScan(project).layer)
                        ?: "Results are cached per content, so an unchanged file is never re-uploaded, and nothing is uploaded before you accept the privacy prompt.")
            }
            row {
                checkBox("Offer Analyze Selection in the editor context menu").bindSelected(state::analyzeSelection)
                    .comment(overridden(MlabConfig.analyzeSelection(project).layer)
                        ?: "Look up a selected URL, IP, email, file hash, MAC address or domain. Only the selected value is sent.")
            }
            row {
                checkBox("Show CVE details on hover").bindSelected(state::cveHover)
                    .comment(overridden(MlabConfig.cveHover(project).layer)
                        ?: "CVSS, exploitation likelihood and known-exploited status. Only the identifier is looked up.")
            }
            row("Severity floor:") {
                comboBox(FLOORS).bindItem({ state.severityFloor ?: DEFAULTS.severityFloor }, { state.severityFloor = it ?: DEFAULTS.severityFloor })
                    .comment(overridden(MlabConfig.severityFloor(project).layer)
                        ?: "Lowest severity reported as a warning or error in the Problems view. Below it, findings are weak warnings. Never fails anything.")
            }
        }
        group("Endpoints") {
            row("Scan endpoint:") {
                textField().bindText({ state.apiUrl ?: DEFAULTS.apiUrl }, { state.apiUrl = it.trim() })
                    .align(AlignX.FILL).validationOnApply { validateUrl(it.text) }
                    .comment(overridden(MlabConfig.apiUrl(project).layer) ?: "Point this at a self-hosted vuln.mlab.sh instance to keep lockfiles inside your network.")
            }
            row("Platform API:") {
                textField().bindText({ state.platformUrl ?: DEFAULTS.platformUrl }, { state.platformUrl = it.trim() })
                    .align(AlignX.FILL).validationOnApply { validateUrl(it.text) }
                    .comment(overridden(MlabConfig.platformUrl(project).layer) ?: "Used by Analyze Selection.")
            }
            row("Request timeout (ms):") {
                intTextField(1000..600_000, 1000).bindIntText(state::timeoutMs)
                    .comment(overridden(MlabConfig.timeoutMs(project).layer))
            }
        }
        row {
            comment("Supported lockfiles: ${SUPPORTED_BASENAMES.joinToString(", ")}. Settings in <code>.mlab/config.json</code> (project, then home directory) take precedence over this page.")
        }
    }.also { refreshStatus() }

    private fun validateUrl(text: String): ValidationInfo? {
        val ok = runCatching { URI(text.trim()).scheme in setOf("http", "https") && URI(text.trim()).host != null }.getOrDefault(false)
        return if (ok) null else ValidationInfo("Enter an http(s) URL.")
    }

    override fun isModified(): Boolean =
        super.isModified() || tokenField.password.isNotEmpty() || keyField.password.isNotEmpty()

    override fun apply() {
        super.apply()
        val token = String(tokenField.password).trim()
        val key = String(keyField.password).trim()
        tokenField.text = ""
        keyField.text = ""
        ApplicationManager.getApplication().executeOnPooledThread {
            if (token.isNotEmpty()) Secret.SCAN_TOKEN.set(token)
            if (key.isNotEmpty()) Secret.PLATFORM_KEY.set(key)
            refreshStatus()
        }
        // severityFloor may have moved: re-highlight open lockfiles.
        DaemonCodeAnalyzer.getInstance(project).restart()
    }

    private fun clear(secret: Secret) {
        ApplicationManager.getApplication().executeOnPooledThread {
            secret.set(null)
            refreshStatus()
        }
    }

    /** The password safe can block on the OS keychain, so read it off the EDT. */
    private fun refreshStatus() {
        // Headless (searchable options indexing, tests): no keychain to ask.
        if (ApplicationManager.getApplication().isHeadlessEnvironment) return
        ApplicationManager.getApplication().executeOnPooledThread {
            val hasToken = Secret.SCAN_TOKEN.get() != null
            val hasKey = Secret.PLATFORM_KEY.get() != null
            ApplicationManager.getApplication().invokeLater({
                tokenStatus.text = if (hasToken) "Token set: 25 scans/hour." else "Anonymous: 8 scans/hour per IP. Add a token for 25/hour."
                keyStatus.text = if (hasKey) "Platform key set: lookups run against your plan quota." else "No platform key: lookups still work, at the anonymous quota."
            }, ModalityState.any())
        }
    }
}


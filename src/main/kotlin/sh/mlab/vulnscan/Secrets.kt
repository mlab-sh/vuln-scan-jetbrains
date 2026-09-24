package sh.mlab.vulnscan

import com.intellij.credentialStore.CredentialAttributes
import com.intellij.credentialStore.generateServiceName
import com.intellij.ide.passwordSafe.PasswordSafe

// Both credentials live ONLY in the IDE's password safe (the OS keychain by
// default). Never in settings files, never in the project, never logged.
// PasswordSafe can block on the keychain, so call these off the EDT.

enum class Secret(key: String) {
    /** vuln.mlab.sh scan token: raises lockfile scans from 8 to 25 per hour. */
    SCAN_TOKEN("apiToken"),
    /** mlab platform key, a different credential: indicator lookups. */
    PLATFORM_KEY("platformKey");

    private val attrs = CredentialAttributes(generateServiceName("mlab", key))

    fun get(): String? = PasswordSafe.instance.getPassword(attrs)?.takeIf { it.isNotBlank() }

    /** Blank clears. */
    fun set(value: String?) = PasswordSafe.instance.setPassword(attrs, value?.trim()?.takeIf { it.isNotEmpty() })
}

package sh.mlab.vulnscan

import java.util.Base64

// Pure HTML for the report and indicator views, rendered in the IDE's embedded
// browser (JCEF). Same layout and design language as vuln.mlab.sh and the VS
// Code extension. No script at all, no remote resource: fonts and logo are
// inlined as data URIs, and the CSP forbids anything else.

data class RenderOpts(val dark: Boolean, val embedAssets: Boolean = true)

fun esc(text: String): String =
    text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")

private object Assets {
    private fun b64(path: String): String? =
        Assets::class.java.getResourceAsStream(path)?.use { Base64.getEncoder().encodeToString(it.readBytes()) }

    val inter by lazy { b64("/fonts/inter-latin.woff2") }
    val mono by lazy { b64("/fonts/jetbrains-mono-latin.woff2") }
    val logo by lazy { b64("/icons/logo.png") }
}

// Lucide icons (ISC), inlined.
private val ICON = mapOf(
    "octagon" to """<polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>""",
    "shield" to """<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="m9 12 2 2 4-4"/>""",
    "info" to """<circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/>""",
    "triangle" to """<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>""",
)

private fun icon(name: String, size: Int = 18) =
    """<svg class="ico" width="$size" height="$size" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICON[name]}</svg>"""

private fun brand(opts: RenderOpts): String {
    val logo = if (opts.embedAssets) Assets.logo else null
    val tile = if (logo != null) """<img class="tile" src="data:image/png;base64,$logo" alt="" width="20" height="20" />""" else """<span class="tile"></span>"""
    return """<div class="brand">$tile<span>vuln.mlab.sh</span></div>"""
}

private fun fontFaces(opts: RenderOpts): String {
    if (!opts.embedAssets) return ""
    val inter = Assets.inter ?: return ""
    val mono = Assets.mono ?: return ""
    return "@font-face { font-family: 'Inter'; font-weight: 100 900; src: url(data:font/woff2;base64,$inter) format('woff2'); }\n" +
        "@font-face { font-family: 'JetBrains Mono'; font-weight: 100 800; src: url(data:font/woff2;base64,$mono) format('woff2'); }\n"
}

private fun shell(body: String, opts: RenderOpts, style: String): String = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; font-src data:; style-src 'unsafe-inline';">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>${fontFaces(opts)}$MLAB_CSS$style</style>
</head>
<body class="${if (opts.dark) "dark" else "light"}"><main>$body</main></body>
</html>"""

private fun header(opts: RenderOpts, eyebrow: String, title: String, meta: String) = """<header class="top">
  <div>
    <div class="eyebrow">${esc(eyebrow)}</div>
    <h1 class="title">$title</h1>
    <p class="meta"><span class="live-dot"></span>$meta</p>
  </div>
  ${brand(opts)}
</header>"""

fun loadingHtml(filename: String, opts: RenderOpts): String = shell(
    """${header(opts, "Lockfile scan", esc(filename), "Resolving known vulnerabilities")}
    <div class="card loading">
      <div class="progress"><div class="bar"></div></div>
      <p class="mono muted small">Uploading the lockfile to vuln.mlab.sh and resolving CVEs.</p>
      <p class="muted small">Only this lockfile is sent, never your source code. Cancel from the progress bar in the status bar.</p>
    </div>""",
    opts, REPORT_STYLE,
)

private fun agoLabel(ms: Long, now: Long): String {
    val mins = (now - ms) / 60000
    if (mins < 1) return "just now"
    if (mins < 60) return "$mins minute${if (mins == 1L) "" else "s"} ago"
    val hours = mins / 60
    if (hours < 24) return "$hours hour${if (hours == 1L) "" else "s"} ago"
    val days = hours / 24
    return "$days day${if (days == 1L) "" else "s"} ago"
}

private fun plural(n: Int, one: String, many: String) = "$n ${if (n == 1) one else many}"

private fun stat(n: Int, label: String, tone: String = "") =
    """<div class="stat"><span class="n${if (tone.isNotEmpty()) " $tone" else ""}">$n</span><span class="l">$label</span></div>"""

fun reportHtml(filename: String, outcome: ScanOutcome, opts: RenderOpts, scannedAt: Long? = null, now: Long = System.currentTimeMillis()): String {
    val findings = outcome.findings
    val clean = findings.isEmpty()
    val bySeverity = Severity.ORDER.mapNotNull { s -> findings.count { it.severity == s }.takeIf { it > 0 }?.let { "$it ${s.id}" } }
        .joinToString(", ")
    val vulnerable = findings.map { it.pkg }.toSet().size
    val exploited = findings.filter { urgencyOf(it.intel) == Urgency.EXPLOITED }
    val deps = outcome.deps
    val whenLabel = if (scannedAt == null) "scanned just now" else "cached, scanned ${esc(agoLabel(scannedAt, now))}"
    val meta = "${plural(deps, "dependency", "dependencies")} · $whenLabel"

    val verdict = if (clean) """<div class="verdict ok">${icon("shield", 30)}<div>
        <div class="verdict-num">No known vulnerabilities</div>
        <div class="verdict-sub">${plural(deps, "package", "packages")} checked, all clear</div></div></div>"""
    else """<div class="verdict bad">${icon("octagon", 30)}<div>
        <div class="verdict-num">${plural(vulnerable, "vulnerable package", "vulnerable packages")}</div>
        <div class="verdict-sub">${plural(findings.size, "advisory", "advisories")} across your dependencies: $bySeverity</div></div></div>"""

    val stats = """<div class="stats">
      ${stat(deps, "Packages")}
      ${stat(vulnerable, "Vulnerable", if (vulnerable > 0) "bad" else "")}
      ${stat(findings.size, "Advisories")}
      ${if (exploited.isNotEmpty()) stat(exploited.size, "Exploited", "bad") else ""}
      ${if (outcome.unresolved.isNotEmpty()) stat(outcome.unresolved.size, "Not scanned", "warn") else ""}
    </div>"""

    val banners = buildList {
        if (exploited.isNotEmpty()) {
            val list = exploited.take(8).joinToString(", ") { esc(it.cve) }
            add(
                """<div class="banner danger">${icon("triangle")}<span><strong>${exploited.size} ${if (exploited.size == 1) "advisory is" else "advisories are"} actively exploited</strong> """ +
                    """according to a known exploited vulnerabilities catalogue: <span class="mono">$list</span>${if (exploited.size > 8) " and more" else ""}. Treat these first, whatever their CVSS band says.</span></div>""",
            )
        }
        if (scannedAt != null) {
            add("""<div class="banner info">${icon("info")}<span>Cached result. The lockfile has not changed since it was scanned, so nothing was re-uploaded.</span></div>""")
        }
        if (outcome.truncated) {
            add("""<div class="banner warn">${icon("triangle")}<span>This manifest exceeds the 512 package scan ceiling; only the first 512 packages were scanned.</span></div>""")
        }
        if (outcome.unresolved.isNotEmpty()) {
            val n = outcome.unresolved.size
            add(
                """<div class="banner warn">${icon("info")}<span>${plural(n, "package", "packages")} could not be resolved by the scanner (upstream) and ${if (n == 1) "is" else "are"} <strong>not</strong> counted as clean: """ +
                    """<span class="mono">${esc(outcome.unresolved.take(20).joinToString(", "))}${if (n > 20) ", ..." else ""}</span></span></div>""",
            )
        }
    }

    val table = if (clean) "" else {
        // Known exploited first: the only signal that says attacks are happening.
        val rows = findings.sortedWith(
            compareByDescending<Finding> { if (urgencyOf(it.intel) == Urgency.EXPLOITED) 1 else 0 }
                .thenByDescending { it.severity.rank }
                .thenByDescending { it.intel?.epssScore ?: 0.0 }
                .thenBy { it.pkg },
        ).joinToString("") { rowHtml(it) }
        """<div class="card table-card"><table>
          <thead><tr><th>Package</th><th>Advisory</th><th>Severity</th><th>Exploitation</th><th>Fixed in</th><th>Summary</th></tr></thead>
          <tbody>$rows</tbody></table></div>"""
    }

    return shell(
        """${header(opts, "Lockfile scan", esc(filename), meta)}
        $verdict
        $stats
        ${banners.joinToString("")}
        $table
        <footer class="muted small">Only this lockfile was sent to vuln.mlab.sh, never your source code. Nothing is uploaded without your agreement.</footer>""",
        opts, REPORT_STYLE,
    )
}

private fun exploitCell(f: Finding): String {
    val intel = f.intel ?: return """<span class="muted">n/a</span>"""
    val bits = mutableListOf<String>()
    if (intel.inKev || intel.inEuKev) {
        val which = if (intel.inKev) "CISA KEV" else "EU KEV"
        val since = intel.kevDateAdded?.let { " since ${esc(it)}" } ?: ""
        bits += """<span class="kev" title="Actively exploited$since">$which</span>"""
    }
    epssLabel(intel)?.let {
        val hot = if ((intel.epssScore ?: 0.0) >= 0.1) " hot" else ""
        bits += """<span class="epss$hot" title="Probability of exploitation in the next 30 days">EPSS $it</span>"""
    }
    return if (bits.isEmpty()) """<span class="muted">n/a</span>""" else bits.joinToString(" ")
}

private fun rowHtml(f: Finding): String {
    val cve = f.url?.let { """<a class="adv" href="${esc(it)}">${esc(f.cve)}</a>""" } ?: """<span class="adv">${esc(f.cve)}</span>"""
    val fixed = f.fixedVersion?.let { """<span class="fixed">&rarr; ${esc(it)}</span>""" } ?: """<span class="muted">no fix yet</span>"""
    val summary = f.summary?.let(::esc) ?: """<span class="muted">no summary</span>"""
    val score = f.intel?.cvssScore?.let { """<span class="score">${"%.1f".format(java.util.Locale.ROOT, it)}</span>""" } ?: ""
    val ver = if (f.version.isNotEmpty()) """<span class="ver">${esc(f.version)}</span>""" else ""
    return """<tr>
      <td><span class="pkg">${esc(f.name.ifEmpty { f.pkg })}</span>$ver</td>
      <td>$cve</td>
      <td class="nowrap">$score<span class="sev sev-${f.severity.id}">${f.severity.id}</span></td>
      <td class="nowrap">${exploitCell(f)}</td>
      <td class="nowrap">$fixed</td>
      <td class="sum">$summary</td>
    </tr>"""
}

fun errorHtml(filename: String, message: String, kind: ScanErrorKind?, opts: RenderOpts): String {
    val benign = kind == ScanErrorKind.UNPARSEABLE || kind == ScanErrorKind.CANCELLED
    val hint = when (kind) {
        ScanErrorKind.RATE_LIMIT -> "Add an API token in <code>Settings | Tools | mlab</code> to raise your quota to 25 scans/hour."
        ScanErrorKind.AUTH -> "Update your token in <code>Settings | Tools | mlab</code>."
        ScanErrorKind.NETWORK, ScanErrorKind.TIMEOUT -> "Check your connection and try again. Previous results, if any, are kept."
        else -> ""
    }
    return shell(
        """${header(opts, "Lockfile scan", esc(filename), if (benign) "Scan stopped" else "Scan failed")}
        <div class="verdict ${if (benign) "neutral" else "bad"}">${icon(if (benign) "info" else "octagon", 30)}<div>
          <div class="verdict-num small-num">${esc(message)}</div>
          ${if (hint.isNotEmpty()) """<div class="verdict-sub">$hint</div>""" else ""}
        </div></div>""",
        opts, REPORT_STYLE,
    )
}

// ── Indicator view ───────────────────────────────────────────────────────────

private fun truncate(v: String, n: Int) = if (v.length <= n) v else v.take(n - 1) + "…"

fun indicatorLoadingHtml(kind: IndicatorKind, value: String, opts: RenderOpts): String = shell(
    """<div class="center"><div class="spinner"></div>
      <h2>Looking up this ${esc(kind.label)}</h2>
      <code class="val">${esc(truncate(value, 120))}</code></div>""",
    opts, INDICATOR_STYLE,
)

fun indicatorErrorHtml(kind: IndicatorKind, value: String, message: String, opts: RenderOpts): String = shell(
    """<header class="top"><span class="kind">${esc(kind.label)}</span><code class="val">${esc(truncate(value, 120))}</code></header>
    <div class="verdict bad"><strong>${esc(message)}</strong></div>""",
    opts, INDICATOR_STYLE,
)

fun indicatorHtml(r: IndicatorReport, opts: RenderOpts): String {
    val worst = worstIndicatorSeverity(r.findings)
    val verdict = r.verdict?.let { """<div class="verdict ${it.tone.name.lowercase()}"><strong>${esc(it.label)}</strong></div>""" } ?: ""
    val findings = if (r.findings.isNotEmpty()) {
        "<section><h3>Findings</h3>" + r.findings.joinToString("") { f ->
            """<div class="finding"><div class="fh"><span class="sev sev-${esc(f.severity)}">${esc(f.severity)}</span>
              <span class="ft">${esc(f.title)}</span></div>
              ${if (f.detail.isNotEmpty()) """<p class="muted">${esc(f.detail)}</p>""" else ""}</div>"""
        } + "</section>"
    } else {
        """<div class="banner ok"><span>&#10003;</span><span>Nothing flagged on this ${esc(r.kind.label)}.</span></div>"""
    }
    val facts = if (r.facts.isEmpty()) "" else "<section><h3>Details</h3><table>" + r.facts.joinToString("") { f ->
        """<tr><th>${esc(f.label)}</th><td${if (f.mono) " class=\"mono\"" else ""}>${esc(f.value)}</td></tr>"""
    } + "</table></section>"
    val headline = worst?.let {
        """<span class="sev sev-${esc(it)}">${r.findings.size} finding${if (r.findings.size == 1) "" else "s"}</span>"""
    } ?: ""
    val link = r.webUrl?.let { """<div class="actions"><a class="btn" href="${esc(it)}">See the full scan on mlab</a></div>""" } ?: ""
    return shell(
        """<header class="top"><span class="kind">${esc(r.kind.label)}</span>$headline</header>
        <code class="val big">${esc(truncate(r.value, 200))}</code>
        $verdict $findings $facts $link
        <footer class="muted small">Looked up on the mlab platform. Only the value above was sent.</footer>""",
        opts, INDICATOR_STYLE,
    )
}

// ── Styles ───────────────────────────────────────────────────────────────────

private const val MLAB_CSS = """
:root {
  --mlab-accent: #d97706; --mlab-accent-rgb: 217, 119, 6; --mlab-tint-rgb: 62, 96, 213;
  --mlab-radius-sm: 8px; --mlab-radius-md: 12px; --mlab-radius-pill: 100px;
  --mlab-mono: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace;
  --mlab-sans: 'Inter', system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif;
  --sev-critical: #dc2626; --sev-high: #ea580c; --sev-medium: #d97706; --sev-low: #2563eb; --sev-unknown: #9ca3af;
  --mlab-success: #22c55e; --mlab-danger: #ef4444; --mlab-warning: #f59e0b;
  --mlab-canvas: #f4f5f7; --mlab-card: #ffffff; --mlab-muted-bg: #eef1f5;
  --mlab-ink: #0a0a0a; --mlab-ink-2: #111827; --mlab-ink-3: #6b7280;
  --mlab-line: rgba(15, 23, 42, 0.08);
  --mlab-primary: #0a0a0a; --mlab-primary-fg: #ffffff;
  --mlab-success-fg: #15803d; --mlab-danger-fg: #b91c1c;
  --mlab-shadow: 0 8px 24px rgba(var(--mlab-tint-rgb), 0.08), 0 2px 6px rgba(17, 24, 39, 0.05);
  --mlab-hairline: 1px solid var(--mlab-line);
}
body.dark {
  --mlab-canvas: #050506; --mlab-card: #121316; --mlab-muted-bg: #202329;
  --mlab-ink: #f8fafc; --mlab-ink-2: #f8fafc; --mlab-ink-3: #8b9099;
  --mlab-line: rgba(255, 255, 255, 0.08);
  --mlab-primary: #fafafa; --mlab-primary-fg: #0a0a0a;
  --mlab-success-fg: #4ade80; --mlab-danger-fg: #f87171;
  --mlab-shadow: 0 10px 30px rgba(0, 0, 0, 0.40), 0 2px 6px rgba(0, 0, 0, 0.35);
}
* { box-sizing: border-box; }
body {
  font-family: var(--mlab-sans); font-feature-settings: 'cv11', 'ss01'; font-size: 14px;
  color: var(--mlab-ink-2); background: var(--mlab-canvas); line-height: 1.55; margin: 0; min-height: 100vh;
}
code, .mono { font-family: var(--mlab-mono); font-feature-settings: 'zero', 'ss01'; font-size: 0.92em; }
a { color: var(--mlab-ink); text-decoration: underline; text-decoration-color: var(--mlab-line); text-underline-offset: 3px; }
a:hover { text-decoration-color: var(--mlab-accent); }
.muted { color: var(--mlab-ink-3); }
.small { font-size: 0.85em; }
.brand { display: flex; align-items: center; gap: 8px; font-weight: 800; letter-spacing: -0.02em; color: var(--mlab-ink); }
.brand .tile { width: 20px; height: 20px; border-radius: 6px; flex: none; background: var(--mlab-ink); }
.brand img.tile { background: none; }
body.dark .brand img.tile { filter: invert(1); }
.eyebrow { display: inline-flex; align-items: center; gap: 0.7rem; font-size: 0.68rem; font-weight: 500; letter-spacing: 0.2em; text-transform: uppercase; color: var(--mlab-ink-3); }
.eyebrow::before { content: ""; width: 24px; height: 2px; border-radius: 2px; background: var(--mlab-accent); }
.live-dot { display: inline-block; width: 7px; height: 7px; border-radius: 50%; background: var(--mlab-accent); box-shadow: 0 0 0 3px rgba(var(--mlab-accent-rgb), 0.15); vertical-align: middle; margin-right: 0.5rem; }
.sev {
  display: inline-flex; align-items: center; gap: 6px; font-family: var(--mlab-sans);
  font-size: 0.62rem; font-weight: 700; letter-spacing: 0.06em; text-transform: uppercase;
  padding: 3px 10px 3px 8px; border-radius: var(--mlab-radius-pill); border: 1px solid currentColor; white-space: nowrap;
}
.sev::before { content: ""; width: 6px; height: 6px; border-radius: 50%; background: currentColor; }
.sev-critical { color: var(--sev-critical); background: rgba(220, 38, 38, 0.08); }
.sev-high { color: var(--sev-high); background: rgba(234, 88, 12, 0.08); }
.sev-medium { color: var(--sev-medium); background: rgba(217, 119, 6, 0.08); }
.sev-low { color: var(--sev-low); background: rgba(37, 99, 235, 0.08); }
.sev-unknown, .sev-info { color: var(--sev-unknown); background: rgba(156, 163, 175, 0.10); }
.card { background: var(--mlab-card); border: var(--mlab-hairline); border-radius: var(--mlab-radius-md); box-shadow: var(--mlab-shadow); overflow: hidden; }
.banner { display: flex; gap: 10px; align-items: flex-start; padding: 12px 16px; border-radius: var(--mlab-radius-md); margin: 12px 0; border: 1px solid transparent; font-size: 0.85rem; }
.banner.warn { background: rgba(245, 158, 11, 0.10); border-color: rgba(245, 158, 11, 0.30); }
.banner.info { background: var(--mlab-card); border-color: var(--mlab-line); }
.banner.ok { background: rgba(34, 197, 94, 0.10); border-color: rgba(34, 197, 94, 0.30); }
.banner.danger { background: rgba(239, 68, 68, 0.06); border-color: rgba(239, 68, 68, 0.50); }
.banner .ico { flex: none; margin-top: 1px; }
.banner.danger .ico { color: var(--mlab-danger); }
.banner.warn .ico { color: var(--mlab-warning); }
.banner.info .ico { color: var(--mlab-ink-3); }
"""

private const val REPORT_STYLE = """
main { padding: 28px 28px 40px; max-width: 1080px; margin: 0 auto; }
.top { display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; margin-bottom: 22px; }
.title { font-family: var(--mlab-sans); font-weight: 800; letter-spacing: -0.035em; line-height: 1; font-size: clamp(1.6rem, 4vw, 2.4rem); color: var(--mlab-ink); margin: 0.45rem 0 0.7rem; word-break: break-all; }
.meta { font-size: 0.68rem; font-weight: 500; letter-spacing: 0.06em; text-transform: uppercase; color: var(--mlab-ink-3); margin: 0; line-height: 1.6; }
.top .brand { font-size: 0.95rem; padding-top: 2px; white-space: nowrap; }
.verdict { display: flex; align-items: center; gap: 1rem; border-radius: 14px; padding: 1.25rem 1.5rem; margin-bottom: 1.25rem; border: 1px solid; }
.verdict .ico { flex: none; }
.verdict.bad { border-color: rgba(239, 68, 68, 0.5); background: rgba(239, 68, 68, 0.06); color: var(--mlab-danger); }
.verdict.ok { border-color: rgba(34, 197, 94, 0.5); background: rgba(34, 197, 94, 0.07); color: var(--mlab-success-fg); }
.verdict.neutral { border-color: var(--mlab-line); background: var(--mlab-card); color: var(--mlab-ink-2); }
.verdict-num { font-weight: 800; font-size: 1.75rem; line-height: 1.1; letter-spacing: -0.02em; }
.verdict-num.small-num { font-size: 1.1rem; letter-spacing: -0.01em; }
.verdict-sub { font-size: 0.85rem; opacity: 0.85; margin-top: 4px; }
.stats { display: flex; flex-wrap: wrap; gap: 1.5rem 2rem; margin: 0 0 1.25rem; }
.stat { display: flex; flex-direction: column; gap: 3px; }
.stat .n { font-weight: 800; font-size: 1.6rem; line-height: 1; color: var(--mlab-ink); letter-spacing: -0.02em; }
.stat .n.bad { color: var(--mlab-danger); }
.stat .n.warn { color: #b45309; }
body.dark .stat .n.warn { color: var(--mlab-warning); }
.stat .l { font-family: var(--mlab-mono); font-size: 0.6rem; letter-spacing: 0.16em; text-transform: uppercase; color: var(--mlab-ink-3); }
.table-card { margin-top: 1.25rem; overflow-x: auto; }
table { border-collapse: collapse; width: 100%; font-size: 0.825rem; }
th, td { text-align: left; padding: 0.7rem 0.85rem; vertical-align: middle; }
thead th { font-size: 0.8125rem; font-weight: 500; color: var(--mlab-ink-3); border-bottom: var(--mlab-hairline); white-space: nowrap; }
tbody tr { border-bottom: var(--mlab-hairline); }
tbody tr:last-child { border-bottom: none; }
tbody tr:hover { background: var(--mlab-muted-bg); }
td.nowrap { white-space: nowrap; }
td.sum { min-width: 220px; max-width: 46ch; color: var(--mlab-ink-3); }
.pkg { font-family: var(--mlab-mono); font-weight: 700; color: var(--mlab-ink); display: block; white-space: nowrap; }
.ver { font-family: var(--mlab-mono); font-size: 0.75rem; color: var(--mlab-ink-3); }
.adv { font-family: var(--mlab-mono); font-weight: 700; white-space: nowrap; }
.score { font-weight: 800; margin-right: 8px; color: var(--mlab-ink); }
.fixed { font-family: var(--mlab-mono); font-size: 0.78rem; color: var(--mlab-success-fg); }
.kev { display: inline-block; padding: 3px 9px; border-radius: var(--mlab-radius-pill); background: var(--sev-critical); color: #fff; font-size: 0.6rem; font-weight: 700; letter-spacing: 0.06em; text-transform: uppercase; }
.epss { display: inline-block; padding: 2px 8px; border-radius: var(--mlab-radius-pill); border: 1px solid var(--mlab-line); color: var(--mlab-ink-3); font-family: var(--mlab-mono); font-size: 0.7rem; font-weight: 600; }
.epss.hot { border-color: var(--sev-high); color: var(--sev-high); }
footer { margin-top: 24px; padding-top: 14px; border-top: var(--mlab-hairline); }
.loading { padding: 22px 24px; display: flex; flex-direction: column; gap: 10px; align-items: flex-start; }
.loading p { margin: 0; }
.progress { width: 100%; height: 6px; border-radius: 100px; background: var(--mlab-muted-bg); overflow: hidden; margin-bottom: 6px; }
.progress .bar { width: 100%; height: 100%; border-radius: 100px; background-color: var(--mlab-ink);
  background-image: linear-gradient(45deg, rgba(255,255,255,.18) 25%, transparent 25%, transparent 50%, rgba(255,255,255,.18) 50%, rgba(255,255,255,.18) 75%, transparent 75%, transparent);
  background-size: 1rem 1rem; animation: stripes 1s linear infinite; }
@keyframes stripes { from { background-position: 1rem 0; } to { background-position: 0 0; } }
@media (prefers-reduced-motion: reduce) { .progress .bar { animation: none; } }
@media (max-width: 560px) { main { padding: 20px 16px 32px; } .top { flex-direction: column-reverse; } }
"""

private const val INDICATOR_STYLE = """
main { padding: 22px 26px 34px; max-width: 760px; margin: 0 auto; display: flex; flex-direction: column; gap: 16px; }
.top { display: flex; align-items: center; gap: 10px; }
.kind { font-family: var(--mlab-mono); font-size: 0.68rem; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase; color: var(--mlab-ink-3); }
.val { font-family: var(--mlab-mono); word-break: break-all; color: var(--mlab-ink); }
.val.big { font-size: 1.02rem; }
h3 { font-family: var(--mlab-mono); font-size: 0.68rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.06em; color: var(--mlab-ink-3); margin: 0 0 9px; padding-bottom: 7px; border-bottom: var(--mlab-hairline); }
section { margin: 0; }
.verdict { padding: 11px 15px; border-radius: var(--mlab-radius-md); border: 1px solid transparent; }
.verdict.good { background: rgba(34, 197, 94, 0.12); border-color: rgba(34, 197, 94, 0.25); color: #22c55e; }
.verdict.bad { background: rgba(220, 38, 38, 0.12); border-color: rgba(220, 38, 38, 0.28); color: var(--sev-critical); }
.verdict.warn { background: rgba(217, 119, 6, 0.12); border-color: rgba(217, 119, 6, 0.28); color: var(--sev-medium); }
.verdict.neutral { background: rgba(127, 127, 127, 0.10); border-color: var(--mlab-line); }
.finding { padding: 11px 0; border-bottom: var(--mlab-hairline); }
.finding:last-child { border-bottom: none; }
.fh { display: flex; align-items: center; gap: 9px; margin-bottom: 5px; flex-wrap: wrap; }
.ft { font-weight: 600; }
.finding p { margin: 0; font-size: 0.94em; }
table { border-collapse: collapse; width: 100%; }
th, td { text-align: left; padding: 6px 10px 6px 0; vertical-align: top; font-weight: 400; }
th { color: var(--mlab-ink-3); white-space: nowrap; width: 1%; padding-right: 20px; }
td { word-break: break-all; }
tr + tr th, tr + tr td { border-top: var(--mlab-hairline); }
.actions { display: flex; gap: 8px; }
a.btn { display: inline-block; text-decoration: none; color: var(--mlab-primary-fg); background: var(--mlab-primary); padding: 8px 16px; border-radius: var(--mlab-radius-sm); font-size: 0.92em; font-weight: 500; }
a.btn:hover { opacity: 0.88; }
footer { margin-top: 6px; padding-top: 12px; border-top: var(--mlab-hairline); }
.center { text-align: center; margin-top: 14vh; display: flex; flex-direction: column; align-items: center; gap: 10px; }
.center h2 { font-weight: 600; margin: 4px 0 0; font-size: 1.05rem; }
.spinner { width: 38px; height: 38px; border: 3px solid rgba(var(--mlab-accent-rgb), 0.18); border-top-color: var(--mlab-accent); border-radius: 50%; animation: spin 0.85s cubic-bezier(0.16, 1, 0.3, 1) infinite; }
@keyframes spin { to { transform: rotate(360deg); } }
"""

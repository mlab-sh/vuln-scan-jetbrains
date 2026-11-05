# mlab security for JetBrains IDEs

Scan your lockfiles for known CVEs from inside any IntelliJ based IDE (IntelliJ
IDEA, PyCharm, GoLand, WebStorm, PhpStorm, RubyMine, RustRover, CLion, Rider,
Android Studio...), powered by [mlab](https://vuln.mlab.sh). Parsing and
vulnerability resolution happen server side: the plugin uploads only the
lockfile you pick and shows the result. No local database, no bundled library.

This is the JetBrains counterpart of
[vuln-scan-vscode](https://github.com/mlab-sh/vuln-scan-vscode), with the same
behaviour, the same API normalisation and the same `.mlab/config.json` files.

## Consent first, then automatic

Nothing is uploaded until you agree, once. The first scan asks, and **opening a
project makes no network call**. After that, a lockfile is rescanned when its
contents change (turn it off in **Settings | Tools | mlab**), and:

- results are **cached per file content**, so an unchanged lockfile is never
  re-uploaded (trusted 7 days, kept 30);
- writes are **debounced**, so an `npm install` costs one scan, not several;
- automatic scans are silent: status bar progress only, no popup.

## Where things are

| VS Code | JetBrains |
| --- | --- |
| Explorer / editor right-click | Project view / editor right-click: **Check for Lock Vulnerabilities**, **See Vuln Report** |
| Command Palette | **Tools \| mlab** menu, or *Find Action* |
| Report webview | Report editor tab (embedded browser) |
| Activity Bar findings tree | **mlab** tool window (right), toolbar: settings, scan all, rescan, clear |
| Explorer colors | Project view: vulnerable lockfiles colored by worst severity |
| Problems panel | *Vulnerable dependency (mlab)* inspection, in the editor and the Problems view |
| CVE hover | Quick documentation on any `CVE-YYYY-NNNN`, in any file |
| Analyze selection | Editor right-click: **Analyze Selection with mlab** |
| mlab page | **Settings \| Tools \| mlab** |
| SecretStorage | IDE password safe |
| Restricted Mode | Untrusted projects: scanning and lookups disabled |

## Supported lockfiles

`Cargo.lock`, `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`,
`pnpm-lock.yaml`, `composer.lock`, `Gemfile.lock`, `go.sum`, `requirements.txt`,
`poetry.lock`, `uv.lock`, `pdm.lock`, `Pipfile.lock`, `pom.xml`,
`gradle.lockfile`, `packages.lock.json`, `pubspec.lock`, `mix.lock`, `mise.lock`,
and CycloneDX SBOMs named `bom.json` or `bom.xml`. One line each in
`Lockfiles.kt`; the fixtures in `src/test/fixtures` are shared with the VS Code
extension.

## API token and limits

| | Packages per scan | Request size | Cooldown between scans |
| --- | --- | --- | --- |
| Anonymous (per IP) | 512 | 4 MiB | 10 s |
| Free account, with a token | 1024 | 8 MiB | 5 s |
| Paid plan, with a token | 4096 | 32 MiB | none |

Get a token at [vuln.mlab.sh/me/tokens](https://vuln.mlab.sh/me/tokens) and
paste it in **Settings | Tools | mlab**. Background, batch and Rescan runs wait
out the cooldown and retry once; an explicit scan shows the server's message
(how long to wait, what the next tier unlocks). A manifest with more packages
than your tier scans is cut, and the report says how many were left out and that
they are not counted as clean. Indicator lookups use a separate mlab platform
key, optional.

## Settings

Highest priority first:

1. `<project>/.mlab/config.json`, committed so a team shares one configuration
2. `~/.mlab/config.json`, personal
3. **Settings | Tools | mlab**
4. built in defaults

The settings page says when a file overrides a value. Keys: `autoScan`,
`analyzeSelection`, `cveHover`, `apiUrl`, `platformUrl`, `severityFloor`,
`timeoutMs`, as documented in the VS Code extension.

## Privacy

- Only the lockfile you scan goes to `vuln.mlab.sh` (or your `apiUrl`).
- CVE details send only the identifier; Analyze Selection only the selected
  value, and nothing it does contacts the indicator. A selected domain is never
  scanned from the IDE: its page on mlab.sh opens in the browser (showing the
  latest report, or a button to start a scan there).
- With a platform key, the lookup panel shows the quota left, read from the
  `X-RateLimit-*` headers (only IP lookups spend it, over a rolling 24 hours).
- All requests go through the IDE's HTTP stack, so its proxy settings apply.
- No telemetry.

## Development

Requires JDK 21.

```bash
./gradlew test          # unit tests (shared fixtures in src/test/fixtures)
./gradlew runIde        # sandbox IDE with the plugin
./gradlew buildPlugin   # build/distributions/*.zip
./gradlew verifyPlugin  # Plugin Verifier against every IDE since sinceBuild
```

Publishing needs `PUBLISH_TOKEN` and the signing variables `CERTIFICATE_CHAIN`,
`PRIVATE_KEY`, `PRIVATE_KEY_PASSWORD`, then `./gradlew publishPlugin`.

Adding a lockfile format: append it to `LOCKFILES` in
[`Lockfiles.kt`](src/main/kotlin/sh/mlab/vulnscan/Lockfiles.kt); every menu,
the sweep and the auto scanner derive from it.

## License

[MIT](LICENSE). Inter and JetBrains Mono fonts under the SIL OFL 1.1, see
[NOTICE](src/main/resources/fonts/NOTICE.txt).

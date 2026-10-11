# Changelog

All notable changes to this plugin are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.2.0] - 2026-10-11

Follows the vuln.mlab.sh scan API changes, like the VS Code extension 1.3.0.

### Added

- **More lockfiles**: `yarn.lock`, `pnpm-lock.yaml`, `poetry.lock`, `uv.lock`,
  `pdm.lock`, `Pipfile.lock`, `pom.xml`, `gradle.lockfile`, `packages.lock.json`,
  `pubspec.lock`, `mix.lock`, and CycloneDX SBOMs named `bom.json` / `bom.xml`.
- **Not scanned entries**: what the server parsed but could not scan (git or path
  dependency, unpinned version, SBOM component without purl or CPE) is listed in
  the report and never counted as clean.

### Changed

- **Limits follow your tier**: anonymous 512 packages and a 10 s cooldown, free
  account 1024 and 5 s, paid plan 4096 and none, instead of the hourly quotas (8
  and 25 scans) every text used to quote.
- **Cooldown (429)**: background, batch and Rescan runs wait out the delay the
  server gives and retry once; Rescan runs as one batch instead of one scan and
  notification per file. An explicit scan shows the server's message and what
  the next tier unlocks, with an action to it.
- **Truncation**: the report shows how many packages were left out and the next
  tier's limit, instead of a fixed "512 package ceiling".
- **Distro advisories** (Debian, Ubuntu) show their CVE, read from `upstream` and
  from ids like `DEBIAN-CVE-…`.
- A Maven finding is placed on its `artifactId` line in a `pom.xml`.

### Fixed

- A file over the size limit (413) is reported with the server's message instead
  of a bare "HTTP 413".

## [1.1.0] - 2026-09-24

First release for JetBrains IDEs, at parity with the VS Code extension 1.1.0.
The version number is shared so both clients can be talked about as one.

### Added

- **Check for Lock Vulnerabilities** on `Cargo.lock`, `package-lock.json`,
  `npm-shrinkwrap.json`, `composer.lock`, `Gemfile.lock`, `go.sum`,
  `requirements.txt` and `mise.lock`, from the Project view, the editor and
  **Tools | mlab**. **Scan All Lockfiles in Project** is quota aware.
- One time privacy consent before the first upload; nothing is uploaded before it.
- Content cache (SHA-256 of the lockfile): 7 days of freshness, 30 days of
  retention, stored in the IDE system directory.
- Automatic rescans when a lockfile changes, debounced, silent, and gated on the
  consent.
- Exploitation intelligence (EPSS, CISA / EU KEV, CVSS) on every finding.
- Report tab (embedded browser), **mlab** tool window, Project view colors, the
  *Vulnerable dependency (mlab)* inspection, CVE quick documentation, and
  **Analyze Selection with mlab**.
- Layered settings: `<project>/.mlab/config.json`, then `~/.mlab/config.json`,
  then **Settings | Tools | mlab**, then defaults. Credentials in the IDE
  password safe.

[1.2.0]: https://github.com/mlab-sh/vuln-scan-jetbrains/releases/tag/v1.2.0
[1.1.0]: https://github.com/mlab-sh/vuln-scan-jetbrains/releases/tag/v1.1.0

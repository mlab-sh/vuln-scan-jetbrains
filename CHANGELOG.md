# Changelog

All notable changes to this plugin are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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

[1.1.0]: https://github.com/mlab-sh/vuln-scan-jetbrains/releases/tag/v1.1.0

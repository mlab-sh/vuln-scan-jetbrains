# Test workspace

Shared verbatim with the VS Code extension. `./gradlew runIde`, then open this
folder in the sandbox IDE. Everything here exists to exercise one behaviour.

## Lockfiles, one per supported format

| File | Resolves to | Exercises |
| --- | --- | --- |
| `Cargo.lock` | `time 0.1.43` | Cargo parsing, and a comment line naming the crate so the diagnostic must land on the declaration and not on the comment |
| `package-lock.json` | `lodash 4.17.11` | npm parsing, ~7 advisories |
| `npm-shrinkwrap.json` | `minimist`, `handlebars` | the second npm basename |
| `composer.lock` | guzzle, symfony, monolog | Packagist |
| `Gemfile.lock` | `rack`, `nokogiri` | the 4-space `specs:` indent rule |
| `go.sum` | `golang.org/x/text` and others | Go, plus the `/go.mod` duplicate that must be collapsed |
| `requirements.txt` | PyYAML, urllib3, Django, requests, jinja2 | PyPI. **Heavy on purpose**: Django 2.2.0 alone carries 85 advisories, so this is the stress case for report rendering, sorting and enrichment concurrency |
| `mise.lock` | `lodash` only | mise, where `node` must be skipped because a core tool has no OSV coordinates |

## Structure

- `nested/deep/Cargo.lock` — the workspace sweep must find it at depth.
- `node_modules/leftpad/package-lock.json` — the sweep must **not** find it. If
  it shows up, the exclude glob is broken.
- `not-a-lockfile.txt` — the context menu must not offer to scan it.
- `.mlab/config.json` — sets `severityFloor`, so the mlab page must show that
  setting as coming from the **workspace** layer. Edit it by hand to check the
  file watcher picks it up without a reload.

## Hover

- `cve-playground.md` — known-exploited ids, a quiet one for contrast, and the
  edge cases (lower case, nonexistent, malformed).
- `cve-in-code.ts` — the same thing inside comments, since the provider is
  registered for every file rather than for lockfiles only.

## Indicators

- `iocs.txt` — select any value in here and run **Analyze selection** from the
  right-click menu. Public or reserved values only, nothing live. Worth trying:
  the `xn--` domain (a real domain scan now, so it contacts the target and spends
  a daily scan), `256.0.0.1`-style malformed addresses (refused rather than guessed at),
  the credentials-in-URL line (seven findings), and `throwaway@mailinator.com`
  (verdict "suspect"). The IP lines spend a daily lookup; the rest are free.

## A word on quota

Scanning is capped at 8 per hour anonymously and 25 with a token, and
`mlab.autoScan` is on. Editing several lockfiles in a row here will spend that
budget quickly. `.mlab/config.json` is the place to set `"autoScan": false` while
working on something else.

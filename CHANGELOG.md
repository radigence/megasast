# Changelog

Notable changes to megasast are documented here. Released versions are
tagged `v<version>` and published as
[GitHub Releases](https://github.com/radigence/megasast/releases) with full
verification details; the entries below are summaries.

## [0.1.4] — 2026-11-07

### Added

- Five new rule families from the bundled language-pack grammars, each with
  positive and negative test cases and matching testbed samples:
  - **YAML** (3): GitHub Action refs not pinned to a commit SHA,
    `pull_request_target` workflow triggers, and privileged Kubernetes
    containers.
  - **Dockerfile** (3): `RUN` piping `curl`/`wget` straight into a shell,
    `FROM` without an immutable digest, and `ADD` of a remote URL.
  - **Shell/bash** (3): `eval`, piped remote scripts, and `source` of a
    variable-taken path.
  - **Ruby** (2): `eval` and `Marshal.load`.
  - **C#** (2): `Process.Start` and `ProcessStartInfo.UseShellExecute=true`.
- `megasast/py-yaml-unsafe-load` — `yaml.unsafe_load()` arbitrary code
  execution.
- Extended `megasast/rust-transmute` to also catch the turbofish
  generic-call form `transmute::<u32, i32>(x)`, which was previously missed.

### Improved

- `.tsx` files now parse with the dedicated `tsx` grammar instead of
  `typescript` (which error-recovers on JSX and silently drops findings
  inside JSX); TypeScript rules apply to `.tsx` via an alias so no per-rule
  language change was needed.
- Closed extension-map gaps: `.pyi`, `.mjs`, `.cjs`, `.hpp`, `.hh`, `.hxx`,
  and `Dockerfile` files by name are now scanned; `.h` headers are scanned
  under both the C and C++ grammars with findings deduplicated.
- Suppression is now anchored to real comment nodes in the parse tree rather
  than raw text, so a string literal that contains the `megasast:ignore`
  token can no longer silence a finding, and a trailing comment on one
  statement no longer leaks onto the next line. A preceding-line
  suppression must be the only content on that line.
- CONTRIBUTING.md now explains that a testbed failure caused by a grammar
  release is a genuine drift signal to re-derive the affected queries —
  not a reason to delete test cases.

### Maintenance

- Catalog is now **121 rules** (121 testbed files, 122 findings). Removed the
  hardcoded-credential detection rules (`megasast/aws-access-key`,
  `megasast/hardcoded-secret`) — secrets scanning is comprehensively served
  by dedicated tools (gitleaks, trufflehog, platform-native secret scanning)
  and is out of megasast's scope. `insecure-rand` remains as a weak-crypto
  rule, moved to `rules/crypto_rules.py`. Teams that prefer in-tree secrets
  rules can add them via the `megasast.rules` entry-point plugin mechanism.
- Bumped the `tree-sitter` floor 0.23 → 0.26.0. The runtime change is
  additive (grammars are ABI 13–15 in both); `tree-sitter-language-pack`
  declares no upper bound, so pip resolves cleanly and no rule queries need
  rework.
- Cached compiled tree-sitter queries per (language, pattern) — rules are
  compiled once per scan process instead of once per scanned file.
- SARIF `helpUri`/`informationUri` now point at the real repo
  (`radigence/megasast`); per-rule links anchor into the generated
  `RULES.md` catalog (test-locked).
- Version single-sourced from package metadata (`--version`, SARIF driver
  version); `pyproject.toml` now carries full package metadata (readme,
  license, authors, classifiers, project URLs), and the package version
  tracks tags again.
- Line-anchored suppression: `megasast:ignore` applies only to the finding's
  own line or the line immediately above (was any comment within 5 lines).
- SARIF report reflects the active rule set when `--rule`/`--no-rule`/severity
  filters are used; removed unused `originalUriBaseIds` with empty URI.
- Baseline diffs (`--baseline`) also match on the shift-stable SARIF
  fingerprint, not just (rule, path, line, column), so moved code is no
  longer re-reported.
- Docker default command scans `/scan-target` instead of erroring; removed
  the stray `EXPOSE 8080`. Dropped `docker-compose.yml` (single-service CLI
  scanner; the default `CMD` makes plain `docker run` with two mounts the
  suggested path).
- CI: ruff lint job, Python 3.13 in the matrix, and a generated-freshness
  job that regenerates `RULES.md` + testbed and fails on drift.
- Tag-triggered PyPI publish workflow (trusted publishing). In-repo
  `CHANGELOG.md`. Third-party rules via `megasast.rules` entry points
  documented in CONTRIBUTING.md; README documents `megasast.toml`,
  suppression semantics, and the baseline workflow.

## [0.1.3] — 2026-11-07

HTML coverage: 6 new rules for a language that's in every monorepo
([#2](https://github.com/radigence/megasast/pull/2)).

### Added

- HTML as a scanned language (`tree-sitter-html` grammar via
  `tree-sitter-language-pack`). Case-insensitive tag/attribute matching;
  value checks ship quoted + unquoted patterns (HTML attribute values parse
  three ways).
- 6 HTML rules — `html-js-url` (HIGH), `html-event-handler` (MEDIUM),
  `html-target-blank` (LOW, review-grade heuristic), `html-insecure-script-src`
  (MEDIUM), `html-insecure-iframe-src` (MEDIUM), `html-meta-refresh-js`
  (MEDIUM). Catalog is now 109 rules.
- `testbed/html/` — 6 true-positive samples; testbed covers 109 files / 109
  rules (110 findings, `go_exec_shell.go` double-fires by design).

## [0.1.2] — 2026-09-19

Prove-it testbed with one vulnerable file per rule.

### Added

- `testbed/` — 103 minimal true-positive samples across 9 languages +
  3 cross-language secrets, with `manifest.json` (machine-checkable
  expectations), regeneration script, and a manifest-driven pytest harness
  (104 tests).
- CI status badge in README.

### Fixed

- `scan --format json` crashed with `UnboundLocalError: RULES` (a
  function-level re-import under the `rules` branch shadowed the module
  import).

### Hardened

- `.dockerignore` excludes the intentionally-vulnerable testbed/ corpus and
  tests from the Docker image.

## [0.1.1] — 2026-09-12

- 15 high-confidence security rules across Python, JavaScript/TypeScript,
  Java, Go, C/C++, and PHP; remediation guidance on all built-in rules.
- JSON and SARIF output with descriptions, remediation, severity, and tags;
  SARIF help text and result properties for platforms like DefectDojo.
- Docker and Docker Compose documentation for read-only source scans.

# megasast testbed

Synthetic vulnerable-by-design corpus: **one file per rule** (103 files,
103 rules). Each file contains a minimal true positive and a header comment
with the expected rule id(s).

Intentionally vulnerable — do not deploy, do not copy patterns into
production code.

## Run

```bash
megasast scan testbed --format text
megasast scan testbed -o report.sarif --format sarif
```

Expected: every file fires its documented rule. `go/go_exec_shell.go`
fires twice (`go-exec-cmd` + `go-exec-shell`) by design, so 103 files
yield 104 findings. `manifest.json` records the per-file expectation.

## Regenerate

```bash
python scripts/generate_testbed.py
```

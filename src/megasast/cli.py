import argparse
import os
import sys
import json
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed

from megasast.discovery import discover
from megasast.engine import scan_file
from megasast.parser import TreeSitterParser
from megasast.sarif import findings_to_sarif

# Worker-scoped parser to avoid re-initialising per file
_worker_parser = TreeSitterParser()

def _worker_scan(path_str):
    path = Path(path_str)
    try:
        return scan_file(path, _worker_parser)
    except Exception as e:
        print(f"Error scanning {path_str}: {e}", file=sys.stderr)
        return []

def main():
    parser = argparse.ArgumentParser(prog="megasast", description="Simple SAST scanner with SARIF output")
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    scan_parser = subparsers.add_parser("scan", help="Scan a path for issues")
    scan_parser.add_argument("path", nargs="?", default=".", help="Root path to scan")
    scan_parser.add_argument("-o", "--output", default=None, help="Output file (.sarif)")
    scan_parser.add_argument("--format", choices=["sarif", "text", "json"], default="sarif")
    scan_parser.add_argument("--workers", type=int, default=None, help="Parallel workers (default: cpu_count)")
    scan_parser.add_argument("--fail-on", choices=["high", "medium", "low"], default=None)
    scan_parser.add_argument("--no-gitignore", action="store_true")
    scan_parser.add_argument("--rule", action="append", default=[], help="Only include specific rule(s)")
    scan_parser.add_argument("--no-rule", action="append", default=[], help="Exclude specific rule(s)")
    scan_parser.add_argument("--severity", nargs="+", choices=["high", "medium", "low"], default=None, help="Severity levels to report")
    scan_parser.add_argument("--baseline", default=None, help="Baseline SARIF file to diff against")
    scan_parser.add_argument("--version", action="store_true", help="Show version")
    
    rules_parser = subparsers.add_parser("rules", help="List available rules")
    
    args = parser.parse_args()
    
    if args.command == "rules":
        from megasast.rules.registry import RULES
        print(f"{'ID':<30} {'Severity':<8} {'Languages':<25} Name")
        print("-" * 80)
        for r in RULES:
            langs = ",".join(r.languages)
            print(f"{r.id:<30} {r.severity:<8} {langs:<25} {r.name}")
        sys.exit(0)
    
    if getattr(args, "version", False):
        print("megasast 0.1.0")
        sys.exit(0)
    
    # normalize args for scan
    path = args.path

    root = Path(args.path).resolve()
    from megasast.config import load_config
    config = load_config(root)
    # config overrides CLI args
    cli_allowed = set(args.rule) if args.rule else None
    cli_excluded = set(args.no_rule) if args.no_rule else None
    cli_severities = set(args.severity) if args.severity else None
    
    allowed_rules = set(config.get("rules", {}).get("only", [])) if config.get("rules", {}).get("only") else cli_allowed
    excluded_rules = set(config.get("rules", {}).get("exclude", [])) if config.get("rules", {}).get("exclude") else cli_excluded
    # config can specify severities as list
    config_severities = config.get("rules", {}).get("severity")
    if config_severities:
        allowed_severities = set(config_severities)
    else:
        allowed_severities = cli_severities
    
    files = discover(root, respect_gitignore=not args.no_gitignore)
    workers = args.workers or os.cpu_count() or 1
    
    findings = []
    total = len(files)
    if workers > 1:
        # Worker-scoped parser
        _worker_parser = TreeSitterParser()
        def _worker_scan(path_str):
            from pathlib import Path
            from megasast.engine import scan_file
            p = Path(path_str)
            try:
                return scan_file(p, _worker_parser, allowed_rules, excluded_rules, allowed_severities)
            except Exception:
                return []
        
        batch_size = 100
        from concurrent.futures import ProcessPoolExecutor, as_completed
        # Worker needs allowed_severities picklable
        with ProcessPoolExecutor(max_workers=workers) as ex:
            for i in range(0, len(files), batch_size):
                batch = files[i:i+batch_size]
                futures = {ex.submit(_worker_scan, str(f)): f for f in batch}
                for fut in as_completed(futures):
                    findings.extend(fut.result())
                if total > 0 and (i + batch_size) % max(1, total // 20) == 0:
                    print(f"Scanned {min(i+batch_size, total)}/{total} files...", file=sys.stderr)
    else:
        parser = TreeSitterParser()
        for i, f in enumerate(files, 1):
            findings.extend(scan_file(f, parser, allowed_rules, excluded_rules, allowed_severities))
            if total > 0 and i % max(1, total // 20) == 0:
                print(f"Scanned {i}/{total} files...", file=sys.stderr)
    
    # Baseline diff
    if args.baseline:
        try:
            import json
            baseline_data = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
            baseline_results = set()
            for run in baseline_data.get("runs", []):
                for res in run.get("results", []):
                    rule_id = res.get("ruleId", "")
                    loc = res.get("locations", [{}])[0].get("physicalLocation", {})
                    uri = loc.get("artifactLocation", {}).get("uri", "")
                    region = loc.get("region", {})
                    key = (rule_id, uri, region.get("startLine"), region.get("startColumn"))
                    baseline_results.add(key)
            # Filter findings to only new ones
            new_findings = []
            for f in findings:
                uri = str(Path(f.path).relative_to(root)).replace("\\", "/")
                key = (f.rule_id, uri, f.start_line, f.start_column)
                if key not in baseline_results:
                    new_findings.append(f)
            findings = new_findings
            print(f"Baseline comparison: {len(findings)} new findings")
        except Exception as e:
            print(f"Warning: could not load baseline {args.baseline}: {e}", file=sys.stderr)

    if args.format == "sarif":
        sarif = findings_to_sarif(findings, root)
        out = args.output or "results.sarif"
        Path(out).write_text(json.dumps(sarif, indent=2), encoding="utf-8")
        print(f"Wrote {len(findings)} findings to {out}")
    elif args.format == "json":
        out_data = {
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "message": f.message,
                    "path": f.path,
                    "start_line": f.start_line,
                    "start_column": f.start_column,
                    "end_line": f.end_line,
                    "end_column": f.end_column,
                    "snippet": f.snippet,
                    "severity": f.severity,
                }
                for f in findings
            ]
        }
        out = args.output or "results.json"
        Path(out).write_text(json.dumps(out_data, indent=2), encoding="utf-8")
        print(f"Wrote {len(findings)} findings to {out}")
    else:
        for f in findings:
            print(f"{f.path}:{f.start_line}:{f.start_column} {f.rule_id} {f.message}")

    # exit code
    if args.fail_on:
        # severity order: HIGH > MEDIUM > LOW > INFO
        severity_order = {"high": 3, "medium": 2, "low": 1}
        fail_level = severity_order.get(args.fail_on, 1)
        # check if any finding meets or exceeds threshold
        def finding_severity_level(f):
            return severity_order.get(str(f.severity).lower(), 0)
        has_match = any(finding_severity_level(f) >= fail_level for f in findings)
        if has_match:
            sys.exit(1)
    sys.exit(0)

if __name__ == "__main__":
    main()

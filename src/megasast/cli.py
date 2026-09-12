import argparse
import os
import sys
import json
from pathlib import Path
from multiprocessing import Pool

from megasast.discovery import discover
from megasast.engine import scan_file
from megasast.parser import TreeSitterParser
from megasast.sarif import findings_to_sarif
from megasast.rules.registry import RULES
from megasast.console import print_banner

_worker_parser = None
_worker_allowed_rules = None
_worker_excluded_rules = None
_worker_allowed_severities = None

def _init_worker(allowed_rules=None, excluded_rules=None, allowed_severities=None):
    global _worker_parser, _worker_allowed_rules, _worker_excluded_rules, _worker_allowed_severities
    _worker_parser = TreeSitterParser()
    _worker_allowed_rules = allowed_rules
    _worker_excluded_rules = excluded_rules
    _worker_allowed_severities = allowed_severities

def _worker_scan(path_str):
    path = Path(path_str)
    try:
        return scan_file(path, _worker_parser, _worker_allowed_rules, _worker_excluded_rules, _worker_allowed_severities)
    except Exception as e:
        print(f"Error scanning {path_str}: {e}", file=sys.stderr)
        return []


def _positive_int(value):
    value = int(value)
    if value < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return value


def _flatten_worker_results(results):
    """Flatten the list of per-file finding lists returned by Pool.map."""
    return [finding for file_findings in results for finding in file_findings]


def _finding_to_json(finding, rule):
    """Serialize a finding with the rule context needed by downstream tools."""
    description = rule.description if rule else ""
    remediation = rule.remediation if rule else ""
    tags = rule.tags if rule else []
    return {
        "rule_id": finding.rule_id,
        "rule_name": rule.name if rule else finding.rule_id,
        "message": finding.message,
        "description": description,
        "remediation": remediation,
        "suggested_fix": remediation,
        "tags": tags,
        "path": finding.path,
        "start_line": finding.start_line,
        "start_column": finding.start_column,
        "end_line": finding.end_line,
        "end_column": finding.end_column,
        "snippet": finding.snippet,
        "severity": finding.severity,
    }

def main():
    parser = argparse.ArgumentParser(prog="megasast", description="Simple SAST scanner with SARIF output")
    parser.add_argument("--version", action="version", version="megasast 0.1.0")
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    scan_parser = subparsers.add_parser("scan", help="Scan a path for issues")
    scan_parser.add_argument("path", nargs="?", default=".", help="Root path to scan")
    scan_parser.add_argument("-o", "--output", default=None, help="Output file (.sarif)")
    scan_parser.add_argument("--format", choices=["sarif", "text", "json"], default="sarif")
    scan_parser.add_argument("--workers", type=_positive_int, default=None, help="Parallel workers (default: cpu_count)")
    scan_parser.add_argument("--fail-on", choices=["high", "medium", "low"], default=None)
    scan_parser.add_argument("--no-gitignore", action="store_true")
    scan_parser.add_argument("--rule", action="append", default=[], help="Only include specific rule(s)")
    scan_parser.add_argument("--no-rule", action="append", default=[], help="Exclude specific rule(s)")
    scan_parser.add_argument("--severity", nargs="+", choices=["high", "medium", "low"], default=None, help="Severity levels to report")
    scan_parser.add_argument("--baseline", default=None, help="Baseline SARIF file to diff against")
    
    rules_parser = subparsers.add_parser("rules", help="List available rules")
    
    args = parser.parse_args()
    print_banner()
    
    if args.command == "rules":
        from megasast.rules.registry import RULES
        print(f"{'ID':<30} {'Severity':<8} {'Languages':<25} Name")
        print("-" * 80)
        for r in RULES:
            langs = ",".join(r.languages)
            print(f"{r.id:<30} {r.severity:<8} {langs:<25} {r.name}")
        sys.exit(0)
    
    root = Path(args.path).resolve()
    from megasast.config import load_config
    config = load_config(root)
    # Explicit CLI values override project configuration.
    cli_allowed = set(args.rule) if args.rule else None
    cli_excluded = set(args.no_rule) if args.no_rule else None
    cli_severities = set(args.severity) if args.severity else None
    
    config_rules = config.get("rules", {})
    config_allowed = set(config_rules.get("only", [])) or None
    config_excluded = set(config_rules.get("exclude", [])) or None
    config_severities = {str(value).lower() for value in config_rules.get("severity", [])} or None
    allowed_rules = cli_allowed if cli_allowed is not None else config_allowed
    excluded_rules = cli_excluded if cli_excluded is not None else config_excluded
    allowed_severities = cli_severities if cli_severities is not None else config_severities
    
    files = discover(root, respect_gitignore=not args.no_gitignore)
    workers = args.workers if args.workers is not None else (os.cpu_count() or 1)
    
    findings = []
    total = len(files)
    if workers > 1:
        batch_size = 100
        with Pool(processes=workers, initializer=_init_worker,
                  initargs=(allowed_rules, excluded_rules, allowed_severities)) as pool:
            for i in range(0, len(files), batch_size):
                batch = files[i:i+batch_size]
                results = pool.map(_worker_scan, [str(f) for f in batch])
                findings.extend(_flatten_worker_results(results))
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
        rule_lookup = {rule.id: rule for rule in RULES}
        out_data = {
            "findings": [
                _finding_to_json(f, rule_lookup.get(f.rule_id))
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

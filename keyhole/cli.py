"""keyhole command line.

    keyhole scan REPO [--policy FILE] [--format text|json|sarif|html] [--out FILE] [--air-dir DIR]
    keyhole explain REPO "GET /api/v1/documents/{doc_id}"
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

from . import adapters, air, report
from .checker import check_endpoints
from .policy import load_policy
from .summaries import load_summaries


def _load(args):
    repo = Path(args.repo).resolve()
    policy_path = Path(args.policy) if args.policy else repo / "keyhole.policy.yaml"
    if not policy_path.exists():
        raise SystemExit(f"no policy file at {policy_path}")
    policy = load_policy(policy_path)
    adapter = adapters.pick(repo, args.adapter)
    endpoints = adapter.extract(
        repo,
        load_summaries(repo),
        include_tests=getattr(args, "include_tests", False),
        policy=policy,
    )
    return repo, policy, endpoints


def cmd_scan(args) -> int:
    repo, policy, endpoints = _load(args)
    if args.air_dir:
        d = Path(args.air_dir)
        d.mkdir(parents=True, exist_ok=True)
        for ep in endpoints:
            name = "".join(c if c.isalnum() else "_" for c in ep.key.lower()).strip("_")
            (d / f"{name}.json").write_text(json.dumps(ep.to_json(), indent=2))
    results = check_endpoints(endpoints, policy)
    if args.format == "json":
        text = report.json_report(results)
    elif args.format == "sarif":
        text = report.sarif_report(results)
    elif args.format == "html":
        text = report.html_report(results, policy, title=f"Keyhole security report — {repo.name}")
    else:
        text = report.text_report(results, policy, verbose=args.verbose)
    if args.out:
        Path(args.out).write_text(text)
    else:
        print(text)
    if args.stats:
        Path(args.stats).write_text(report.stats_report(results))
    failing = {"violation"}
    if args.fail_on == "possible":
        failing.add("possible_violation")
    return 1 if any(r.verdict in failing for r in results) else 0


def cmd_explain(args) -> int:
    repo, policy, endpoints = _load(args)
    matches = [ep for ep in endpoints if ep.key == args.endpoint]
    if not matches:
        print(f"no endpoint {args.endpoint!r}; found:\n  " + "\n  ".join(e.key for e in endpoints))
        return 2
    res = check_endpoints(matches, policy)[0]
    ep = res.endpoint
    print(f"{ep.key}  ({ep.file}:{ep.line})  -> {report.LABEL[res.verdict]}\n")
    print("AIR:")
    print(json.dumps(ep.to_json(), indent=2))
    for er in res.effects:
        e = er.effect
        print(f"\neffect: {e.kind} {e.resource} (line {e.line})")
        print(f"  touches rows where: {air.show_pred(air.and_(*e.guards, e.selector))}")
        print(f"  policy allows:      {air.show_pred(policy.rule(e.resource, e.kind))}")
        print(f"  verdict:            {er.verdict}" + (f" ({er.why})" if er.why else ""))
        if er.verdict == "violation":
            for line in report.describe_violation(ep, er):
                print(f"  {line}")
    return 0


def cmd_validate_policy(args) -> int:
    path = Path(args.policy)
    if not path.exists():
        print(f"no policy file at {path}", file=sys.stderr)
        return 2
    try:
        policy = load_policy(path)
    except (OSError, ValueError, TypeError, AttributeError, yaml.YAMLError) as exc:
        print(f"invalid policy: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({
        "valid": True,
        "metadata": policy.metadata,
        "resources": len(policy.confirmed),
        "rules": len(policy.rules),
        "principal_dependencies": sorted(policy.principal_dependencies),
        "principal_types": sorted(policy.principal_types),
        "trusted_helpers": sorted(policy.helper_guards),
    }, indent=2))
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="keyhole", description="Lean-verified IDOR detector")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("scan", "explain"):
        sp = sub.add_parser(name)
        sp.add_argument("repo")
        if name == "explain":
            sp.add_argument("endpoint", help='e.g. "GET /api/v1/documents/{doc_id}"')
        sp.add_argument("--policy")
        sp.add_argument("--adapter")
        if name == "scan":
            sp.add_argument("--format", choices=["text", "json", "sarif", "html"], default="text")
            sp.add_argument("--out")
            sp.add_argument("--air-dir", help="write each endpoint's AIR JSON here")
            sp.add_argument("--include-tests", action="store_true", help="include tests/ and test_*.py routes")
            sp.add_argument("--stats", metavar="PATH", help="write coverage statistics JSON to PATH")
            sp.add_argument("--fail-on", choices=["violation", "possible"], default="violation",
                            help="exit 1 on definite violations, or on possible violations too")
            sp.add_argument("-v", "--verbose", action="store_true")
    validate = sub.add_parser("validate-policy", help="validate an externally generated policy")
    validate.add_argument("policy")
    args = p.parse_args(argv)
    if args.cmd == "scan":
        return cmd_scan(args)
    if args.cmd == "explain":
        return cmd_explain(args)
    return cmd_validate_policy(args)


if __name__ == "__main__":
    sys.exit(main())

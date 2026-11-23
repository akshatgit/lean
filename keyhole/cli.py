"""keyhole command line.

    keyhole scan REPO [--policy FILE] [--format text|json|sarif|html] [--out FILE] [--air-dir DIR]
    keyhole explain REPO "GET /api/v1/documents/{doc_id}"
    keyhole worklist REPO --policy FILE [--assumptions FILE] [--format text|json] [--prompt-pack DIR]
    keyhole review REPO ID --assumptions FILE --by NAME      (a human runs this)
    keyhole migrate-assumptions REPO --policy FILE [--out FILE]
"""
from __future__ import annotations

import argparse
import ast
import json
import sys
from collections import Counter
from pathlib import Path

import yaml

from . import adapters, air, report, worklist
from .assumptions import AssumptionError, load_assumptions, write_review
from .checker import check_endpoints
from .policy import load_policy
from .summaries import load_summaries


def _load(args):
    repo = Path(args.repo).resolve()
    policy_path = Path(args.policy) if args.policy else repo / "keyhole.policy.yaml"
    if not policy_path.exists():
        raise SystemExit(f"no policy file at {policy_path}")
    policy = load_policy(policy_path)
    assumptions = _assumptions(args, repo)
    adapter = adapters.pick(repo, getattr(args, "adapter", None))
    endpoints = adapter.extract(
        repo,
        load_summaries(repo),
        include_tests=getattr(args, "include_tests", False),
        policy=policy,
        assumptions=assumptions,
    )
    args._adapter, args._assumptions = adapter, assumptions
    return repo, policy, endpoints


def _assumptions(args, repo):
    explicit = getattr(args, "assumptions", None)
    path = Path(explicit) if explicit else repo / "keyhole.assumptions.yaml"
    if not path.exists():
        if explicit:
            raise SystemExit(f"no assumptions file at {path}")
        return load_assumptions(None)
    try:
        return load_assumptions(path)
    except (AssumptionError, yaml.YAMLError) as exc:
        raise SystemExit(f"invalid assumptions file {path}: {exc}")


def cmd_scan(args) -> int:
    repo, policy, endpoints = _load(args)
    if args.air_dir:
        d = Path(args.air_dir)
        d.mkdir(parents=True, exist_ok=True)
        # Stable even if filesystem traversal order changes. A hyphen cannot
        # occur in the normalized stem, so suffixes cannot collide with stems.
        occurrences = Counter()
        for ep in sorted(endpoints, key=lambda e: (e.key, e.file, e.line)):
            name = "".join(c if c.isalnum() else "_" for c in ep.key.lower()).strip("_")
            occurrences[name] += 1
            if occurrences[name] > 1:
                name = f"{name}--{occurrences[name]}"
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
    locations = sorted({f"{ep.file}:{ep.line}" for ep in matches})
    if args.source:
        matches = [ep for ep in matches if f"{ep.file}:{ep.line}" == args.source]
    if len(matches) != 1:
        print(f"Select a handler for {args.endpoint!r} with --source FILE:LINE:\n  "
              + "\n  ".join(locations), file=sys.stderr)
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


def cmd_worklist(args) -> int:
    _repo, policy, endpoints = _load(args)
    results = check_endpoints(endpoints, policy)
    purity = args._adapter.last_index.purity
    data = worklist.build(results, purity, top=args.top, include_possible=args.include_possible)
    if args.prompt_pack:
        directory = Path(args.prompt_pack)
        directory.mkdir(parents=True, exist_ok=True)
        for i, pack in enumerate(worklist.prompt_packs(data, purity, limit=args.top), 1):
            (directory / f"{i:03d}.json").write_text(json.dumps(pack, indent=2))
    output = worklist.dumps(data) if args.format == "json" else worklist.text(data, top=args.top)
    if args.out:
        Path(args.out).write_text(output)
    else:
        print(output)
    return 0


def cmd_review(args) -> int:
    """Record that a human reviewed one assumption: digests over the claim as written and
    over the target as it is now.  Editing either afterwards voids the review."""
    from datetime import datetime, timezone

    _repo, _policy, _endpoints = _load(args)
    entries = args._assumptions
    entry = entries.get(args.id)
    if entry is None:
        print(f"no assumption {args.id}", file=sys.stderr)
        return 2
    if entry.target_sha256 is None:
        print(f"cannot review {entry.id}: {entry.reason}", file=sys.stderr)
        return 2
    print(f"{entry.id}: {entry.kind} of {entry.target_text}")
    print(f"  claim:      {json.dumps(entry.claim)}")
    print(f"  evidence:   {json.dumps(entry.evidence)}")
    print(f"  entry  sha: {entry.entry_sha256}")
    print(f"  target sha: {entry.target_sha256} ({entry.target_kind})")
    write_review(entries.path, entry, args.by, datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    print(f"recorded review by {args.by} in {entries.path}")
    return 0


def cmd_migrate(args) -> int:
    """Turn policy `adapter.ignore_calls` into UNREVIEWED assumption entries.  The policy
    keeps working unchanged; this only writes the file a human can then review."""
    repo, policy, _endpoints = _load(args)
    purity = args._adapter.last_index.purity
    entries, skipped = [], []
    # Every function body in the repository, to find what each declared name is bound to.
    bodies = [(module, node, None) for module, node in purity.toplevel_funcs.values()]
    for module, cls in purity.class_defs.values():
        bodies += [(module, item, cls.name) for item in cls.body
                   if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))]
    for n, name in enumerate(sorted(policy.ignored_calls), 1):
        symbols = set()
        for module, fn, owner in bodies:
            ctx = purity.ctx_for(module, fn, owner)
            for call in (c for c in ast.walk(fn) if isinstance(c, ast.Call)):
                if purity.binding_key(ctx, call, {name}) is not None:
                    symbol = purity.call_symbol(ctx, call)
                    if symbol:
                        symbols.add(symbol)   # the resolved identity the declaration binds to
        symbols = sorted(symbols)
        if not symbols:
            skipped.append(f"ignore_calls: {name} (binds to no call with a resolvable identity; "
                           f"write the fully qualified symbol or a call site by hand)")
        for i, symbol in enumerate(symbols):
            entries.append({
                "id": f"M-{n:03d}" + (f"-{i + 1}" if len(symbols) > 1 else ""),
                "target": {"symbol": symbol},
                "claim": {"effects": []},
                "evidence": {"note": f"migrated from policy adapter.ignore_calls: {name}"},
                "drafted_by": {"tool": "keyhole migrate-assumptions"},
            })
    for name in sorted(policy.helper_guards):
        skipped.append(f"helpers: {name} (an `ensures` claim needs the formal that receives the row "
                       f"and the formal that receives the caller; write it by hand)")
    for name in sorted(policy.principal_dependencies | policy.superuser_dependencies):
        skipped.append(f"principal dependency: {name} (move to a `principal: true` entry in a later phase)")
    text = yaml.safe_dump({"schema": 1, "assumptions": entries}, sort_keys=False, width=100)
    text += "".join(f"# not migrated - {line}\n" for line in skipped)
    if args.out:
        Path(args.out).write_text(text)
    else:
        print(text)
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
            sp.add_argument("--source", metavar="FILE:LINE", help="select the handler location shown in the report")
        sp.add_argument("--policy")
        sp.add_argument("--assumptions", help="assumptions file (default: REPO/keyhole.assumptions.yaml)")
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
    for name, helptext in (("worklist", "rank unmodeled targets by the endpoints they free"),
                           ("review", "record a human review of one assumption"),
                           ("migrate-assumptions", "convert policy ignore_calls into unreviewed assumptions")):
        sp = sub.add_parser(name, help=helptext)
        sp.add_argument("repo")
        if name == "review":
            sp.add_argument("id")
            sp.add_argument("--by", required=True, help="who reviewed it")
        sp.add_argument("--policy")
        sp.add_argument("--assumptions")
        sp.add_argument("--adapter")
        if name == "worklist":
            sp.add_argument("--include-possible", action="store_true",
                            help="also rank effect-capable blockers on POSSIBLE VIOLATION endpoints")
            sp.add_argument("--format", choices=["text", "json"], default="text")
            sp.add_argument("--out")
            sp.add_argument("--top", type=int, default=25)
            sp.add_argument("--prompt-pack", metavar="DIR", help="write one JSON packet per target")
        if name == "migrate-assumptions":
            sp.add_argument("--out")
    args = p.parse_args(argv)
    if args.cmd == "scan":
        return cmd_scan(args)
    if args.cmd == "explain":
        return cmd_explain(args)
    if args.cmd == "worklist":
        return cmd_worklist(args)
    if args.cmd == "review":
        return cmd_review(args)
    if args.cmd == "migrate-assumptions":
        return cmd_migrate(args)
    return cmd_validate_policy(args)


if __name__ == "__main__":
    sys.exit(main())

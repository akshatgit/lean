#!/usr/bin/env python3
"""End-to-end IDOR hunt: fetch -> scan -> triage/rank -> report, in one command.

No human gate runs *before* a scan.  The pipeline derives nothing it cannot
justify, ranks every flagged effect by how likely it is a genuine object-level
authorization bug, and writes a report the human confirms *afterward*
(PoC the top leads; `keyhole review` the surfaced assumptions).

    python benchmarks/hunt/run_hunt.py \
        [--targets benchmarks/hunt/targets.yaml] [--only langflow] \
        [--fetch] [--scratch DIR] [--out DIR]

Ranking (nothing is discarded -- rank, so the human audits everything):
  R1 confirmed   verdict == violation
  R2 lead        possible_violation, attacker-controlled selector, empty guards,
                 NO hidden ownership/admin check in the blockers   <- the real leads
  R3 coverage    possible_violation whose blockers reference an owner field or an
                 admin gate -> authorization is present but unmodeled (false alarm)
  R4 other       anything else flagged (e.g. empty-selector writes, no by-id)

Exit code: number of R1+R2 leads (0 == clean), capped at 250, so CI can gate on it.

Known limitation: admin-gate detection is text-based (OWNER_TOKENS over the effect's
blockers), so an endpoint gated only by `Depends(get_admin_user)` with no owner-token
in its blockers can land in R2. The scan JSON does not yet surface which principal
dependency gated each endpoint; emitting that (adapter) and matching it against an
`admin_gates:` list in targets.yaml is the next precision step.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
CORE = REPO_ROOT / "core/.lake/build/bin/keyhole-core"

FLAGGED = {"violation", "possible_violation"}
# Tokens that, appearing in a blocking/unmodeled check, mean authorization IS present
# but the extractor could not model it -> the finding is a coverage gap, not a bug.
OWNER_TOKENS = re.compile(
    r"\b(user_id|owner_id|created_by|author_id|account_id|user\.id|current_user|"
    r"has_access|_access|permission|is_admin|role\b|get_admin_user|ensure_\w*permission)\b",
    re.IGNORECASE,
)


def sh(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(args, check=check, capture_output=True, text=True)


def resolve_ref(clone: Path, ref: str, fetch: bool) -> tuple[str, str]:
    """(sha, label) for `ref` in `clone`.  Fetching updates refs only, never the
    working tree, and is best-effort: offline falls back to the local ref."""
    if fetch:
        r = sh("git", "-C", str(clone), "fetch", "--quiet", "origin", check=False)
        if r.returncode:
            print(f"  ! fetch failed ({r.stderr.strip()[:80]}); using local {ref}", file=sys.stderr)
    sha = sh("git", "-C", str(clone), "rev-parse", ref).stdout.strip()
    label = sh("git", "-C", str(clone), "log", "-1", "--format=%h %s", sha).stdout.strip()
    return sha, label


def export_commit(clone: Path, sha: str, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    proc = subprocess.Popen(["git", "-C", str(clone), "archive", sha], stdout=subprocess.PIPE)
    subprocess.run(["tar", "-x", "-C", str(dest)], stdin=proc.stdout, check=True)
    proc.wait()
    if proc.returncode:
        raise RuntimeError(f"git archive {sha} failed in {clone}")


def scan(export_root: Path, policy: Path, assumptions: Path | None) -> list[dict]:
    with tempfile.NamedTemporaryFile("w+", suffix=".json", delete=False) as tf:
        out = Path(tf.name)
    cmd = [sys.executable, "-m", "keyhole", "scan", str(export_root),
           "--policy", str(policy), "--format", "json", "--out", str(out)]
    if assumptions:
        cmd += ["--assumptions", str(assumptions)]
    env = dict(os.environ)
    env.setdefault("KEYHOLE_CORE", str(CORE))
    # `keyhole scan` writes --out first, then exits 1 when any endpoint is a
    # `violation` (CI semantics). That is success-with-findings, not a crash;
    # only a missing/empty output file or a crash signal (<0, or >1) is fatal.
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env, cwd=REPO_ROOT)
    if proc.returncode not in (0, 1) or not out.exists() or out.stat().st_size == 0:
        raise RuntimeError(f"keyhole scan failed (exit {proc.returncode}):\n{proc.stderr[-2000:]}")
    data = json.loads(out.read_text())
    out.unlink(missing_ok=True)
    return data


def _selector_params(sel) -> set[str]:
    """Every `param` term appearing anywhere in an AIR selector predicate."""
    found: set[str] = set()
    stack = [sel]
    while stack:
        n = stack.pop()
        if isinstance(n, dict):
            if "param" in n and isinstance(n["param"], str):
                found.add(n["param"])
            for v in n.values():
                stack.append(v)
        elif isinstance(n, list):
            stack.extend(n)
    return found


def classify_effect(ep: dict, checked: dict, air_effect: dict | None) -> tuple[str, str]:
    """(rank, reason) for one flagged effect. rank in R1..R4."""
    if checked["verdict"] == "violation":
        return "R1", "definite counterexample (no opaque demotion)"

    params = ep.get("air", {}).get("params", {}) or {}
    selector = (air_effect or {}).get("selector", None)
    guards = (air_effect or {}).get("guards", []) or []
    sel_params = _selector_params(selector)
    attacker_sel = (selector is True) or any(
        params.get(p, {}).get("attacker_controlled") for p in sel_params
    )

    # Hidden authorization: a blocker / unmodeled check that names an owner field,
    # an access helper, or an admin gate -> the endpoint IS guarded, just not modeled.
    blockers = list(checked.get("blocking_calls") or [])
    if checked.get("why"):
        blockers.append(checked["why"])
    blockers += [c.get("expression", "") if isinstance(c, dict) else str(c)
                 for c in (ep.get("air", {}).get("unmodeled_checks") or [])]
    hidden_authz = next((b for b in blockers if OWNER_TOKENS.search(b or "")), None)

    if hidden_authz:
        return "R3", f"authorization present but unmodeled: {hidden_authz[:140]}"
    if attacker_sel and not guards:
        where = "unconstrained selector (all rows)" if selector is True \
            else f"attacker-controlled selector ({', '.join(sorted(sel_params)) or '?'})"
        return "R2", f"{where}, no guard, no hidden check found -> genuine lead"
    if not guards:
        return "R4", "flagged, but selector is not attacker-controlled by id"
    return "R4", "flagged with partial guards"


def triage(endpoints: list[dict], policy: dict) -> list[dict]:
    owner_scoped = set((policy.get("resources") or {}).keys())
    rows = []
    for ep in endpoints:
        checked_effects = ep.get("effects") or []
        air_effects = ep.get("air", {}).get("effects") or []
        for j, checked in enumerate(checked_effects):
            if checked.get("verdict") not in FLAGGED:
                continue
            if owner_scoped and checked.get("resource") not in owner_scoped:
                continue
            air_effect = air_effects[j] if j < len(air_effects) else None
            rank, reason = classify_effect(ep, checked, air_effect)
            rows.append({
                "rank": rank,
                "endpoint": ep.get("endpoint"),
                "source": ep.get("air", {}).get("source"),
                "kind": checked.get("kind"),
                "resource": checked.get("resource"),
                "verdict": checked.get("verdict"),
                "reason": reason,
            })
    rows.sort(key=lambda r: (r["rank"], r["endpoint"] or ""))
    return rows


def write_report(target: str, label: str, policy_path: Path, endpoints: list[dict],
                 rows: list[dict], out_dir: Path) -> dict:
    by_rank = {k: [r for r in rows if r["rank"] == k] for k in ("R1", "R2", "R3", "R4")}
    verdicts: dict[str, int] = {}
    for ep in endpoints:
        verdicts[ep.get("verdict", "?")] = verdicts.get(ep.get("verdict", "?"), 0) + 1
    assumptions = {}
    for ep in endpoints:
        for a in (ep.get("provenance") or []):
            if isinstance(a, dict) and a.get("id"):
                assumptions.setdefault(a["id"], a.get("reason", ""))
            elif isinstance(a, str):
                assumptions.setdefault(a, "")
    assumptions = sorted(assumptions.items())

    (out_dir / f"{target}-candidates.json").write_text(json.dumps(rows, indent=2))
    lines = [f"# Hunt: {target}", "",
             f"- commit: `{label}`", f"- policy: `{policy_path}`",
             f"- endpoints: {len(endpoints)}  ·  verdicts: "
             + ", ".join(f"{k}={v}" for k, v in sorted(verdicts.items())),
             f"- leads (R1+R2): **{len(by_rank['R1']) + len(by_rank['R2'])}**  ·  "
             f"coverage-gap (R3): {len(by_rank['R3'])}  ·  other (R4): {len(by_rank['R4'])}", ""]
    titles = {"R1": "R1 — confirmed violations (PoC immediately)",
              "R2": "R2 — genuine leads (PoC these)",
              "R3": "R3 — coverage gaps (authorization present but unmodeled; verify if time)",
              "R4": "R4 — other flagged effects"}
    for rank in ("R1", "R2", "R3", "R4"):
        group = by_rank[rank]
        if not group:
            continue
        lines += [f"## {titles[rank]} ({len(group)})", ""]
        for r in group[:200]:
            lines.append(f"- `{r['endpoint']}` — {r['kind']} {r['resource']} "
                         f"({r['source']})\n  - {r['reason']}")
        if len(group) > 200:
            lines.append(f"- … {len(group) - 200} more (see candidates.json)")
        lines.append("")
    if assumptions:
        lines += ["## Assumptions to confirm after the run", "",
                  "Each clean/assumed verdict rests on these; confirm with `keyhole review`:", ""]
        lines += [f"- `{aid}` — {reason}" if reason else f"- `{aid}`"
                  for aid, reason in assumptions] + [""]
    (out_dir / f"{target}-report.md").write_text("\n".join(lines))
    return {"target": target, "endpoints": len(endpoints),
            "leads": len(by_rank["R1"]) + len(by_rank["R2"]),
            "coverage_gap": len(by_rank["R3"]), "other": len(by_rank["R4"])}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--targets", default=str(Path(__file__).with_name("targets.yaml")))
    ap.add_argument("--only", help="run a single target by name")
    ap.add_argument("--fetch", action="store_true", help="git fetch origin before resolving the ref")
    ap.add_argument("--scratch", help="export directory (default: a temp dir)")
    ap.add_argument("--out", default=str(Path(__file__).parent), help="where reports are written")
    args = ap.parse_args()

    targets = yaml.safe_load(Path(args.targets).read_text())["targets"]
    if args.only:
        targets = [t for t in targets if t["name"] == args.only]
        if not targets:
            print(f"no target named {args.only!r}", file=sys.stderr)
            return 2
    scratch = Path(args.scratch) if args.scratch else Path(tempfile.mkdtemp(prefix="keyhole-hunt-"))
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    total_leads, summaries = 0, []
    for t in targets:
        name, clone = t["name"], Path(t["clone"]).expanduser()
        policy_path = (REPO_ROOT / t["policy"]) if not Path(t["policy"]).is_absolute() else Path(t["policy"])
        assumptions = t.get("assumptions")
        assumptions_path = (REPO_ROOT / assumptions) if assumptions else None
        ref = t.get("ref", "origin/HEAD")
        print(f"[{name}] resolving {ref} in {clone} …")
        sha, label = resolve_ref(clone, ref, args.fetch)
        export_root = scratch / name
        print(f"[{name}] export {sha[:12]} ({label[:60]})")
        export_commit(clone, sha, export_root)
        print(f"[{name}] scanning …")
        endpoints = scan(export_root, policy_path, assumptions_path)
        rows = triage(endpoints, yaml.safe_load(policy_path.read_text()))
        summary = write_report(name, label, policy_path, endpoints, rows, out_dir)
        total_leads += summary["leads"]
        summaries.append(summary)
        print(f"[{name}] {summary['endpoints']} endpoints · "
              f"LEADS {summary['leads']} · coverage-gap {summary['coverage_gap']} · "
              f"other {summary['other']}  -> {out_dir / (name + '-report.md')}")

    print("\n=== hunt summary ===")
    for s in summaries:
        print(f"  {s['target']:16} leads={s['leads']:<4} coverage_gap={s['coverage_gap']:<5} "
              f"other={s['other']:<5} endpoints={s['endpoints']}")
    print(f"\nTotal genuine leads (R1+R2): {total_leads}  "
          f"(human confirms these after the run; 0 == clean)")
    return min(total_leads, 250)


if __name__ == "__main__":
    sys.exit(main())

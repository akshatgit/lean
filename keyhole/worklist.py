"""Worklist: which unmodeled targets stand between the scan and decisive verdicts.

Deterministic.  An endpoint is "blocked" while it has an effect-capable opaque; each such
opaque names a target (the callee's resolved symbol, or a call site).  An endpoint is
freed only when EVERY target blocking it is covered, so the list reports

  * presence      - endpoints on which the target appears,
  * sole blocker  - endpoints it frees by itself,
  * a greedy cover - the order in which covering targets frees the most endpoints,
  * the tail      - what remains blocked after the cover's first N steps.

"Covered" here means "an assumption (or better modeling) accounts for the call".  It says
nothing about the verdict the endpoint then gets: freeing an endpoint from UNKNOWN very
often lands it in POSSIBLE VIOLATION, not SAFE.
"""
from __future__ import annotations

import ast
import json
from collections import defaultdict


def _target_of(opaque) -> str:
    return opaque.target or f"<{opaque.reason}> {opaque.call}"


def build(results, purity=None, top: int = 25) -> dict:
    blocked = [r for r in results if r.verdict == "unknown"]
    # per endpoint: the distinct "cover sets" -- an opaque is accounted for when ANY
    # symbol in its set is (its own target, or a helper call it was reached through)
    per_endpoint: dict[str, set] = {}
    presence: dict[str, set] = defaultdict(set)
    sites: dict[str, set] = defaultdict(set)
    reasons: dict[str, set] = defaultdict(set)
    for res in blocked:
        key = f"{res.endpoint.key} ({res.endpoint.file}:{res.endpoint.line})"
        sets = set()
        for opaque in res.endpoint.opaque:
            if not opaque.may_have_effects:
                continue
            leaf = _target_of(opaque)
            cover = frozenset({leaf, *opaque.via})
            sets.add(cover)
            for target in cover:
                presence[target].add(key)
            reasons[leaf].add(opaque.reason)
            if opaque.origin:
                sites[leaf].add(opaque.origin)
        per_endpoint[key] = sets

    def kind(target: str) -> str:
        if target.startswith("<"):
            return "untargeted"
        if " :: " in target:
            return "site"
        if purity is not None:
            from .assumptions import target_definitions
            if target_definitions(purity, target):
                return "repository"
            if target.split(".")[0] in purity.repo_tops:
                return "repository (unresolved)"
        return "external"

    def common(sets):
        return frozenset.intersection(*sets) if sets else frozenset()

    sole = defaultdict(list)
    for endpoint, sets in per_endpoint.items():
        for target in common(sets):
            sole[target].append(endpoint)
    items = sorted(
        ({"target": t, "kind": kind(t), "reasons": sorted(reasons.get(t, ())),
          "endpoints_present": len(presence[t]), "sole_blocker_of": len(sole.get(t, ())),
          "call_sites": sorted(sites.get(t, ()))[:20], "blocked_endpoints": sorted(presence[t])}
         for t in presence),
        key=lambda item: (-item["sole_blocker_of"], -item["endpoints_present"], item["target"]))

    # Greedy cover.  A target frees an endpoint when it lies in every still-uncovered set
    # of that endpoint; ties go to the target that accounts for the most opaques.
    remaining = {e: set(sets) for e, sets in per_endpoint.items()}
    covered: list = []
    cover = []
    freed_total = 0
    while len(cover) < max(top, 1):
        gain: dict[str, int] = defaultdict(int)
        weight: dict[str, int] = defaultdict(int)
        for sets in remaining.values():
            if not sets:
                continue
            for target in common(sets):
                gain[target] += 1
            for one in sets:
                for target in one:
                    weight[target] += 1
        if not weight:
            break
        best = max(sorted(weight), key=lambda t: (gain[t], weight[t]))
        covered.append(best)
        freed = 0
        for endpoint, sets in remaining.items():
            if not sets:
                continue
            left = {one for one in sets if best not in one}
            if not left:
                freed += 1
            remaining[endpoint] = left
        freed_total += freed
        cover.append({"step": len(cover) + 1, "target": best, "kind": kind(best),
                      "frees": freed, "freed_total": freed_total})
    still = {e: sets for e, sets in remaining.items() if sets}
    return {
        "blocked_endpoints": len(blocked),
        "distinct_targets": len(presence),
        "targets": items,
        "greedy_cover": cover,
        "tail": {
            "after_steps": len(cover),
            "endpoints_still_blocked": len(still),
            "opaques_still_unaccounted": sum(len(sets) for sets in still.values()),
            "median_unaccounted_per_blocked_endpoint": (
                sorted(len(sets) for sets in still.values())[len(still) // 2] if still else 0),
        },
    }


def text(worklist: dict, top: int = 25) -> str:
    out = [f"{worklist['blocked_endpoints']} UNKNOWN endpoints are blocked by "
           f"{worklist['distinct_targets']} distinct targets.", ""]
    out.append("Greedy cover (cover these in order; an endpoint is freed when ALL its targets are covered):")
    for step in worklist["greedy_cover"][:top]:
        out.append(f"  {step['step']:>3}. +{step['frees']:<3} (total {step['freed_total']:<3}) "
                   f"[{step['kind']}] {step['target']}")
    tail = worklist["tail"]
    out += ["", f"Tail: after {tail['after_steps']} targets, {tail['endpoints_still_blocked']} endpoints are "
                f"still blocked, with {tail['opaques_still_unaccounted']} unaccounted operations "
                f"(median {tail['median_unaccounted_per_blocked_endpoint']} per endpoint).", "",
            "Targets by sole-blocker count:"]
    for item in worklist["targets"][:top]:
        out.append(f"  sole {item['sole_blocker_of']:<3} present {item['endpoints_present']:<4} "
                   f"[{item['kind']}] {item['target']}")
    return "\n".join(out)


def prompt_packs(worklist: dict, purity, limit: int = 25) -> list:
    """One self-contained packet per target for the drafting step (phase B): what the
    target is, its source if we have it, where it is called, and what it blocks."""
    from .assumptions import target_definitions

    packs = []
    wanted = [step["target"] for step in worklist["greedy_cover"]][:limit]
    by_target = {item["target"]: item for item in worklist["targets"]}
    for target in wanted:
        item = by_target[target]
        source = None
        if purity is not None and item["kind"] == "repository":
            defs = target_definitions(purity, target) or []
            source = "\n\n".join("\n".join(ast.unparse(d).splitlines()[:80]) for d in defs[:4])
        packs.append({
            "target": target, "kind": item["kind"], "reasons": item["reasons"],
            "source_excerpt": source, "call_sites": item["call_sites"],
            "blocked_endpoints": item["blocked_endpoints"][:50],
            "endpoints_present": item["endpoints_present"],
            "sole_blocker_of": item["sole_blocker_of"],
            "allowed_claims": ["returns_type", "effects", "ensures", "principal"],
        })
    return packs


def dumps(worklist: dict) -> str:
    return json.dumps(worklist, indent=2)

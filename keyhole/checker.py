"""Bridge to the verified Lean checker (core/, binary `keyhole-core`).

Python never decides safety. It sends AIR effects + policy as JSON and reads
back verdicts that come from `Keyhole.check`, which is proven sound in Lean.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from .air import Endpoint
from .policy import Policy

RANK = {"no_effects": 0, "safe": 0, "no_effects_assumed": 1, "safe_assumed": 1, "unknown": 2,
        "possible_violation": 3, "violation": 4}


def core_binary() -> str:
    env = os.environ.get("KEYHOLE_CORE")
    if env:
        return env
    local = Path(__file__).resolve().parent.parent / "core" / ".lake" / "build" / "bin" / "keyhole-core"
    if local.exists():
        return str(local)
    found = shutil.which("keyhole-core")
    if found:
        return found
    raise SystemExit("keyhole-core not found: build it with `cd core && lake build`, "
                     "or set KEYHOLE_CORE")


@dataclass
class EffectResult:
    effect: object
    verdict: str              # safe | safe_assumed | violation | possible_violation | unknown
    witness: dict | None = None
    why: str | None = None
    blocking_calls: list[str] = field(default_factory=list)


@dataclass
class EndpointResult:
    endpoint: Endpoint
    effects: list = field(default_factory=list)
    assumptions: list = field(default_factory=list)   # human-readable, one per provenance id
    # Assumption provenance set: id -> reason.  The union of everything the adapter
    # assumed while extracting this endpoint and every unconfirmed policy it was checked
    # against.  A clean green verdict requires this to be empty.
    provenance: dict = field(default_factory=dict)
    verdict: str = "safe"


def check_endpoints(endpoints: list, policy: Policy) -> list:
    effects_json = []
    for i, ep in enumerate(endpoints):
        for j, e in enumerate(ep.effects):
            effects_json.append({"id": f"{i}:{j}", "kind": e.kind, "resource": e.resource,
                                 "selector": e.selector, "guards": e.guards})
    verdicts = {}
    if effects_json:
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump({"policy": policy.to_json(), "effects": effects_json}, f)
            path = f.name
        try:
            out = subprocess.run([core_binary(), path], capture_output=True, text=True, check=True)
        except subprocess.CalledProcessError as ex:
            raise SystemExit(f"keyhole-core failed: {ex.stderr.strip()}")
        finally:
            os.unlink(path)
        verdicts = {r["id"]: r for r in json.loads(out.stdout)["results"]}

    results = []
    for i, ep in enumerate(endpoints):
        res = EndpointResult(ep)
        res.provenance = dict(ep.assumptions)
        for e in ep.effects:
            if e.assumed_from and not ep.assumptions:
                # Defensive: an effect labelled by a path that recorded no id.
                res.provenance[f"assumed:{e.assumed_from}"] = (
                    f"trusted helper/summary for {e.assumed_from} (not reviewed)")
            if not policy.is_confirmed(e.resource):
                res.provenance[f"policy-unconfirmed:{e.resource}"] = (
                    f"policy for {e.resource} is inferred, not confirmed")
        # Assumptions that SUPPRESSED code (a call declared irrelevant) may have removed
        # a denial, so a counterexample past them is only a lead.  Assumptions that add
        # a guard or an identity fact can only make a counterexample harder to find; a
        # violation that survives them needs no demotion.
        suppressions = sorted(key for key in res.provenance
                              if key.startswith(("ignore:", "declared-free:", "assume:")))
        for j, e in enumerate(ep.effects):
            r = verdicts[f"{i}:{j}"]
            verdict = r["verdict"]
            if verdict == "safe" and e.assumed_from and e.assumed_from.startswith("helper-guard:"):
                verdict = "safe_assumed"
            blockers = []
            if verdict == "violation":
                blockers = sorted({
                    o.call for o in ep.opaque
                    if o.may_block and o.line <= e.line
                })
                blockers.extend(
                    f"unmodelled check at line {check.line}: {check.expression}"
                    for check in ep.unmodeled_checks
                    if check.line <= e.line
                )
                # A hard VIOLATION is only reportable against a confirmed policy. An
                # inferred/auto-generated policy may itself be wrong, so an unconfirmed
                # policy demotes the counterexample to a lead, never a finding.
                if not policy.is_confirmed(e.resource):
                    blockers.append(f"policy for {e.resource} is not confirmed")
                # Likewise a counterexample over a model from which a call was removed
                # by declaration is a lead, not a finding.
                blockers.extend(f"rests on assumption {key}" for key in suppressions)
                blockers = sorted(set(blockers))
                if blockers:
                    verdict = "possible_violation"
            res.effects.append(EffectResult(
                e, verdict, r.get("witness"), r.get("why"), blockers
            ))
            if e.assumed_from:
                res.assumptions.append(f"trusted helper/summary for {e.assumed_from} (not reviewed)")
        res.assumptions = sorted(set(res.assumptions) | set(res.provenance.values()))
        res.verdict = _aggregate(res, ep)
        results.append(res)
    return results


def _aggregate(res: EndpointResult, ep: Endpoint) -> str:
    # Only opacity that may hide a read/write makes the extracted effects incomplete.
    # Opacity that can merely hide a guard (may_block only) never blocks SAFE: losing
    # a guard widens the modeled row set, so a proof over it still covers the code.
    incomplete = any(o.may_have_effects for o in ep.opaque)
    # No modeled object access at all. If something effect-capable was left
    # unmodeled the adapter *failed* to model it -> UNKNOWN. Otherwise there is
    # genuinely nothing to check, but that is still not a proof of safety, so it
    # is reported as its own `no_effects` state and never counted as SAFE.
    # The provenance set gates every green verdict, effects or not: "nothing to check"
    # that holds only because a call was declared irrelevant is not a clean result.
    # A REVIEWED assumption (digests over claim and target still match) has the standing
    # of a confirmed policy: it is recorded and shown, but it does not make a result amber.
    unreviewed = [key for key in res.provenance if not key.startswith("reviewed:")]
    if not res.effects:
        if incomplete:
            return "unknown"
        return "no_effects_assumed" if unreviewed else "no_effects"
    worst = "safe"
    for er in res.effects:
        if RANK[er.verdict] > RANK[worst]:
            worst = er.verdict
    if incomplete and RANK[worst] < RANK["unknown"]:
        worst = "unknown"
    if worst == "safe" and unreviewed:
        worst = "safe_assumed"
    return worst

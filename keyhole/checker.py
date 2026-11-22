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

RANK = {"safe": 0, "safe_assumed": 1, "unknown": 2, "possible_violation": 3, "violation": 4}


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
    verdict: str              # safe | violation | unknown
    witness: dict | None = None
    why: str | None = None
    blocking_calls: list[str] = field(default_factory=list)


@dataclass
class EndpointResult:
    endpoint: Endpoint
    effects: list = field(default_factory=list)
    assumptions: list = field(default_factory=list)   # e.g. LLM summaries, inferred policy
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
        for j, e in enumerate(ep.effects):
            r = verdicts[f"{i}:{j}"]
            verdict = r["verdict"]
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
                blockers = sorted(set(blockers))
                if blockers:
                    verdict = "possible_violation"
            res.effects.append(EffectResult(
                e, verdict, r.get("witness"), r.get("why"), blockers
            ))
            if e.assumed_from:
                res.assumptions.append(f"trusted helper/summary for {e.assumed_from} (not reviewed)")
            if not policy.is_confirmed(e.resource):
                res.assumptions.append(f"policy for {e.resource} is inferred, not confirmed")
        res.assumptions = sorted(set(res.assumptions))
        res.verdict = _aggregate(res, ep)
        results.append(res)
    return results


def _aggregate(res: EndpointResult, ep: Endpoint) -> str:
    worst = "safe"
    for er in res.effects:
        if RANK[er.verdict] > RANK[worst]:
            worst = er.verdict
    if ep.opaque and RANK[worst] < RANK["unknown"]:
        worst = "unknown"
    if worst == "safe" and res.assumptions:
        worst = "safe_assumed"
    return worst

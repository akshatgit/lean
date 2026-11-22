"""Text, JSON and SARIF reports."""
from __future__ import annotations

import json
import re

from . import air

LABEL = {"safe": "SAFE", "safe_assumed": "SAFE (assumed)", "violation": "VIOLATION", "unknown": "UNKNOWN"}


def _pretty_values(witness: dict) -> dict:
    """Group witness values by kind, renaming internal placeholders (#w3) to <v3>."""
    out = {"param": {}, "principal": {}, "field": {}}
    for term, value in witness.get("values", []):
        (kind, name), = term.items()
        if kind == "const":
            continue
        out[kind][name] = re.sub(r"#w(\d+|\?)", r"<v\1>", value) if value.startswith("#") else repr(value)
    return out


def describe_violation(ep: air.Endpoint, er) -> list:
    v = _pretty_values(er.witness)
    who = ", ".join(f"{k}={x}" for k, x in v["principal"].items()) or "any caller"
    row = ", ".join(f"{k}={x}" for k, x in v["field"].items())
    path = ep.path
    for name, val in v["param"].items():
        path = path.replace("{" + name + "}", val)
    body = {k.split(".", 1)[1]: x for k, x in v["param"].items() if "." in k}
    lines = [f"caller ({who}) can {er.effect.kind} a {er.effect.resource} row ({row})",
             f"repro: as that caller, {ep.method} {path}" + (f" with body {body}" if body else "")]
    if ep.principal_binding is None:
        lines.append("note: route has no authenticated user dependency")
    return lines


def text_report(results, policy, verbose: bool = False) -> str:
    out = []
    counts = {}
    for res in sorted(results, key=lambda r: (r.endpoint.file, r.endpoint.line)):
        ep = res.endpoint
        counts[res.verdict] = counts.get(res.verdict, 0) + 1
        out.append(f"{LABEL[res.verdict]:<15} {ep.key}   ({ep.file}:{ep.line})")
        for er in res.effects:
            if er.verdict == "violation":
                for line in describe_violation(ep, er):
                    out.append(f"    {line}")
                out.append(f"    policy: {air.show_pred(policy.rule(er.effect.resource, er.effect.kind))}")
            elif verbose:
                out.append(f"    {er.effect.kind} {er.effect.resource}: {er.verdict}")
        for o in ep.opaque:
            out.append(f"    opaque: {o.call} ({o.reason}, line {o.line})")
        for a in res.assumptions:
            out.append(f"    assumes: {a}")
    summary = ", ".join(f"{counts.get(k, 0)} {LABEL[k]}" for k in LABEL)
    out.append("")
    out.append(f"{len(results)} endpoints: {summary}")
    return "\n".join(out)


def json_report(results) -> str:
    data = []
    for res in results:
        data.append({
            "endpoint": res.endpoint.key, "verdict": res.verdict,
            "air": res.endpoint.to_json(),
            "effects": [{"kind": er.effect.kind, "resource": er.effect.resource,
                         "verdict": er.verdict, "witness": er.witness, "why": er.why}
                        for er in res.effects],
            "assumptions": res.assumptions,
        })
    return json.dumps(data, indent=2)


def sarif_report(results) -> str:
    sarif_results = []
    for res in results:
        if res.verdict not in ("violation", "unknown"):
            continue
        ep = res.endpoint
        msg = f"{LABEL[res.verdict]}: {ep.key}"
        for er in res.effects:
            if er.verdict == "violation":
                msg += " - " + "; ".join(describe_violation(ep, er))
                break
        sarif_results.append({
            "ruleId": "keyhole/idor" if res.verdict == "violation" else "keyhole/unknown",
            "level": "error" if res.verdict == "violation" else "warning",
            "message": {"text": msg},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": ep.file},
                "region": {"startLine": ep.line}}}],
        })
    return json.dumps({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{"tool": {"driver": {"name": "keyhole", "rules": [
            {"id": "keyhole/idor", "shortDescription": {"text": "Object-level authorization violation (IDOR)"}},
            {"id": "keyhole/unknown", "shortDescription": {"text": "Endpoint could not be fully modelled"}}]}},
            "results": sarif_results}],
    }, indent=2)

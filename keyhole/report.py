"""Text, JSON, SARIF, and self-contained HTML reports."""
from __future__ import annotations

import html
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone

from . import air

LABEL = {
    "safe": "SAFE",
    "safe_assumed": "SAFE (assumed)",
    "no_effects": "NO EFFECTS",
    "no_effects_assumed": "NO EFFECTS (assumed)",
    "possible_violation": "POSSIBLE VIOLATION",
    "violation": "VIOLATION",
    "unknown": "UNKNOWN",
}

MODEL_TRUST_NOTICE = "Verdicts are proven for the extracted model; extraction and policy are trusted inputs."


def _review_reasons(res) -> list[str]:
    """Explain why a human should not treat a result as a final finding."""
    reasons = []
    if res.assumptions:
        reasons.append("The result depends on an unconfirmed policy or helper summary.")
    effect_opaque = [o for o in res.endpoint.opaque if o.may_have_effects]
    guard_opaque = [o for o in res.endpoint.opaque if not o.may_have_effects]
    if effect_opaque:
        reasons.append(
            f"{len(effect_opaque)} analysis records describe unmodeled operations that may "
            "read or write data. Repeated helper paths can refer to the same operation."
        )
    if guard_opaque:
        reasons.append(
            f"{len(guard_opaque)} value-only operation(s) were not modeled; they cannot touch "
            "data but may hide a check, so a counterexample past them is only a lead."
        )
    if res.endpoint.unmodeled_checks:
        reasons.append(
            f"{len(res.endpoint.unmodeled_checks)} check or query condition(s) were dropped "
            "to keep the model conservative; this can cause false alarms."
        )
    if res.endpoint.effects and res.endpoint.principal_binding is None:
        reasons.append(
            "No authenticated principal was modeled. Check for dependency aliases, "
            "middleware, or route-level authentication."
        )
    if not res.endpoint.effects:
        reasons.append(
            "No database effects were modeled. This is not an object-authorization proof "
            "if the route reaches storage indirectly."
        )
    return reasons


def _display_status(res) -> tuple[str, str]:
    """Return a report label and a stable CSS/filter key."""
    labels = {
        "violation": "VIOLATION (modeled)",
        "possible_violation": "Possible violation",
        "unknown": "Unknown",
        "safe_assumed": "Safe (assumed)",
        "no_effects": "No modeled effects",
        "no_effects_assumed": "No modeled effects (assumed)",
        "safe": "Verified safe",
    }
    return labels[res.verdict], res.verdict


def _status_explanation(res) -> str:
    label, _ = _display_status(res)
    if res.verdict == "possible_violation":
        causes = set()
        for effect in res.effects:
            if effect.verdict != "possible_violation":
                continue
            for blocker in effect.blocking_calls:
                if blocker.startswith("policy for ") and blocker.endswith(" is not confirmed"):
                    causes.add("unconfirmed resource policy")
                elif blocker.startswith("rests on assumption "):
                    causes.add("assumptions used during extraction")
                elif blocker.startswith("unmodelled check at line "):
                    causes.add("omitted checks or query filters")
                else:
                    causes.add("unresolved calls")
        explanation = "Lean found a counterexample in the extracted model."
        if causes:
            explanation += " Review the " + ", ".join(sorted(causes)) + " listed with the counterexamples."
        return explanation
    if res.verdict == "unknown":
        if not res.effects:
            return "No access was extracted. Unresolved operations could still read or write protected data."
        if all(e.verdict == "safe" for e in res.effects):
            return ("Every extracted access satisfies the supplied policy. Unresolved operations "
                    "could introduce additional reads or writes.")
        return "At least one access or operation still requires analysis."
    explanations = {
        "VIOLATION (modeled)": (
            "Lean found a concrete counterexample: the modeled endpoint can touch a row that the confirmed policy denies."
        ),
        "Safe (assumed)": (
            "Lean proved the extracted effect follows the supplied policy, but that policy or a helper summary has not been confirmed."
        ),
        "No modeled effects (assumed)": (
            "The adapter found no object read or write to check, but only because one or more calls were "
            "declared irrelevant or otherwise assumed. Nothing here is verified until those assumptions are reviewed."
        ),
        "No modeled effects": (
            "The adapter found no object read or write to check. This may be expected for health checks and redirects, "
            "but helper-based storage access still needs review."
        ),
        "Verified safe": (
            "For every row the modeled endpoint can touch, Lean proved that the confirmed policy allows the operation."
        ),
    }
    return explanations[label]


def _pretty_values(witness: dict) -> dict:
    """Group witness values by kind, renaming internal placeholders (#w3) to <v3>."""
    out = {"param": {}, "principal": {}, "field": {}}
    for term, value in witness.get("values", []):
        (kind, name), = term.items()
        if kind == "const":
            continue
        out[kind][name] = (re.sub(r"#w(\d+|\?)", r"<v\1>", value)
                           if isinstance(value, str) and value.startswith("#") else repr(value))
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
    out = [MODEL_TRUST_NOTICE, ""]
    if policy.metadata:
        provenance = ", ".join(f"{key}={value}" for key, value in policy.metadata.items())
        out.extend([f"Policy provenance: {provenance}", ""])
    counts = {}
    for res in sorted(results, key=lambda r: (r.endpoint.file, r.endpoint.line)):
        ep = res.endpoint
        counts[res.verdict] = counts.get(res.verdict, 0) + 1
        out.append(f"{LABEL[res.verdict]:<15} {ep.key}   ({ep.file}:{ep.line})")
        for er in res.effects:
            if er.verdict in ("violation", "possible_violation"):
                for line in describe_violation(ep, er):
                    out.append(f"    {line}")
                if er.blocking_calls:
                    out.append(f"    may be blocked by: {', '.join(er.blocking_calls)}")
                out.append(f"    policy: {air.show_pred(policy.rule(er.effect.resource, er.effect.kind))}")
            elif verbose:
                out.append(f"    {er.effect.kind} {er.effect.resource}: {er.verdict}")
        for o in ep.opaque:
            kind = "opaque" if o.may_have_effects else "opaque (value only)"
            out.append(f"    {kind}: {o.call} ({o.reason}, line {o.line})")
        for key in sorted(res.provenance):
            out.append(f"    assumes [{key}]: {res.provenance[key]}")
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
                         "verdict": er.verdict, "witness": er.witness, "why": er.why,
                         "blocking_calls": er.blocking_calls}
                        for er in res.effects],
            "assumptions": res.assumptions,
            "provenance": [{"id": key, "reason": res.provenance[key]}
                           for key in sorted(res.provenance)],
        })
    return json.dumps(data, indent=2)


_HTML_STYLE = """
<style>
  :root {
    color-scheme: light;
    --bg: #f5f7fb;
    --panel: #ffffff;
    --ink: #18212f;
    --muted: #647084;
    --line: #dfe4ec;
    --safe: #087f5b;
    --assumed: #8a5a00;
    --unknown: #5f3dc4;
    --violation: #c92a2a;
    --possible: #d97706;
    --neutral: #52606d;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    background: var(--bg);
    color: var(--ink);
    font: 14px/1.5 ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  }
  header {
    padding: 34px clamp(20px, 5vw, 72px) 28px;
    color: white;
    background: linear-gradient(125deg, #18212f, #273b58);
  }
  header h1 { margin: 0 0 8px; font-size: clamp(25px, 4vw, 38px); }
  header p { margin: 3px 0; color: #d9e2ef; }
  main { width: min(1420px, calc(100% - 32px)); margin: 24px auto 56px; }
  .notice {
    margin-bottom: 18px;
    padding: 14px 16px;
    border: 1px solid #f2cc8f;
    border-left: 5px solid #d97706;
    border-radius: 9px;
    background: #fff8e8;
  }
  .guide {
    margin-bottom: 18px;
    padding: 4px 18px 15px;
    border: 1px solid var(--line);
    border-radius: 10px;
    background: var(--panel);
  }
  .guide > summary { padding: 13px 0 8px; cursor: pointer; font-size: 16px; font-weight: 750; }
  .guide-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 9px; }
  .legend-item { padding: 10px 12px; border-radius: 7px; background: #f6f8fb; }
  .reading-order { margin: 10px 0 0; padding-left: 21px; }
  .summary {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(155px, 1fr));
    gap: 12px;
    margin: 0 0 18px;
  }
  .metric {
    padding: 15px;
    border: 1px solid var(--line);
    border-radius: 10px;
    background: var(--panel);
  }
  .metric strong { display: block; font-size: 26px; }
  .metric span { color: var(--muted); }
  .toolbar {
    position: sticky;
    top: 0;
    z-index: 5;
    display: grid;
    grid-template-columns: minmax(180px, 2fr) repeat(4, minmax(120px, 1fr));
    gap: 10px;
    padding: 13px;
    border: 1px solid var(--line);
    border-radius: 10px;
    background: rgba(255, 255, 255, .96);
    box-shadow: 0 5px 18px rgba(24, 33, 47, .08);
    backdrop-filter: blur(8px);
  }
  input, select {
    width: 100%;
    padding: 9px 10px;
    border: 1px solid #c9d1dc;
    border-radius: 7px;
    color: var(--ink);
    background: white;
  }
  .result-count { margin: 13px 2px; color: var(--muted); }
  .finding {
    margin: 10px 0;
    overflow: hidden;
    border: 1px solid var(--line);
    border-left: 5px solid var(--neutral);
    border-radius: 9px;
    background: var(--panel);
  }
  .finding.violation { border-left-color: var(--violation); }
  .finding.possible_violation { border-left-color: var(--possible); }
  .finding.unknown { border-left-color: var(--unknown); }
  .finding.safe { border-left-color: var(--safe); }
  .finding.safe_assumed { border-left-color: var(--assumed); }
  .finding.no_effects { border-left-color: var(--neutral); }
  .finding.no_effects_assumed { border-left-color: var(--assumed); }
  .finding > summary {
    display: grid;
    grid-template-columns: minmax(125px, 175px) 1fr auto;
    gap: 12px;
    align-items: center;
    padding: 14px 16px;
    cursor: pointer;
  }
  .finding summary:hover { background: #f8fafc; }
  .detail details > summary { cursor: pointer; padding: 4px 0; }
  .status { font-weight: 750; }
  .violation .status { color: var(--violation); }
  .possible_violation .status { color: var(--possible); }
  .unknown .status { color: var(--unknown); }
  .safe .status { color: var(--safe); }
  .safe_assumed .status { color: var(--assumed); }
  .endpoint { font-weight: 650; overflow-wrap: anywhere; }
  .source { color: var(--muted); font: 12px/1.4 ui-monospace, SFMono-Regular, Consolas, monospace; }
  .detail { padding: 0 16px 18px; border-top: 1px solid var(--line); }
  .detail h3 { margin: 18px 0 7px; font-size: 14px; }
  .review {
    margin-top: 14px;
    padding: 10px 13px;
    border-radius: 7px;
    background: #fff8e8;
  }
  .review ul, .compact { margin: 6px 0; padding-left: 20px; }
  table { width: 100%; border-collapse: collapse; }
  th, td { padding: 8px; border: 1px solid var(--line); text-align: left; vertical-align: top; }
  th { background: #f1f4f8; }
  code, pre { font: 12px/1.5 ui-monospace, SFMono-Regular, Consolas, monospace; }
  code { overflow-wrap: anywhere; }
  pre { margin: 7px 0; padding: 10px; overflow-x: auto; border-radius: 6px; background: #f1f4f8; }
  .pill {
    display: inline-block;
    margin: 2px 4px 2px 0;
    padding: 2px 7px;
    border-radius: 999px;
    color: #415064;
    background: #eaf0f6;
    font-size: 12px;
  }
  [hidden] { display: none !important; }
  @media (max-width: 850px) {
    .toolbar { position: static; grid-template-columns: 1fr 1fr; }
    .finding > summary { grid-template-columns: 1fr; }
  }
  @media (max-width: 520px) { .toolbar { grid-template-columns: 1fr; } }
</style>
"""


_HTML_SCRIPT = """
<script>
(() => {
  const cards = [...document.querySelectorAll('.finding')];
  const search = document.querySelector('#filter-search');
  const verdict = document.querySelector('#filter-verdict');
  const resource = document.querySelector('#filter-resource');
  const review = document.querySelector('#filter-review');
  const accesses = document.querySelector('#filter-accesses');
  const count = document.querySelector('#result-count');

  function applyFilters() {
    const q = search.value.trim().toLowerCase();
    let shown = 0;
    for (const card of cards) {
      const visible = (!q || card.dataset.search.includes(q))
        && (!verdict.value || card.dataset.verdict === verdict.value)
        && (!resource.value || card.dataset.resources.split('|').includes(resource.value))
        && (!review.value || card.dataset.review === review.value)
        && (!accesses.value || card.dataset.accesses === accesses.value);
      card.hidden = !visible;
      if (visible) shown += 1;
    }
    count.textContent = `${shown} of ${cards.length} endpoints shown`;
  }

  for (const control of [search, verdict, resource, review, accesses]) {
    control.addEventListener(control === search ? 'input' : 'change', applyFilters);
  }
  applyFilters();
})();
</script>
"""


def _h(value) -> str:
    return html.escape(str(value), quote=True)


def _html_effect_rows(res, policy) -> str:
    rows = []
    for er in res.effects:
        touched = air.show_pred(air.and_(*er.effect.guards, er.effect.selector))
        allowed = air.show_pred(policy.rule(er.effect.resource, er.effect.kind))
        rows.append(
            "<tr>"
            f"<td>{_h(er.effect.kind)}</td>"
            f"<td>{_h(er.effect.resource)}</td>"
            f"<td>{_h(er.verdict)}</td>"
            f"<td><code>{_h(touched)}</code></td>"
            f"<td><code>{_h(allowed)}</code></td>"
            "</tr>"
        )
    return "".join(rows)


def _html_helper_trace(res):
    ep = res.endpoint
    operations = defaultdict(Counter)
    checks = defaultdict(Counter)
    effects = defaultdict(list)
    for op in ep.opaque:
        key = (op.call, op.reason, op.origin, op.line, op.may_have_effects, op.may_block, op.via, op.target)
        operations[op.helper_site][key] += 1
    for check in ep.unmodeled_checks:
        checks[check.helper_site][check.expression, check.origin or f"{ep.file}:{check.line}"] += 1
    for er in res.effects:
        effects[er.effect.helper_site].append(er)

    groups = []
    sites = sorted(ep.helper_sites)
    if None in operations or None in checks or None in effects:
        sites.append(None)
    for site in sites:
        label = f"{site[2]} · line {site[0]}" if site else "Other endpoint or dependency evidence"
        ops = operations[site]
        capable = sum(count for key, count in ops.items() if key[4])
        locations = {key[2] for key in ops if key[4] and key[2]}
        value_only = sum(ops.values()) - capable
        rows = []
        for er in effects[site]:
            rows.append(f"<li>{_h(er.effect.kind)} {_h(er.effect.resource)} · {_h(er.verdict)}</li>")
        for (expr, origin), count in checks[site].items():
            rows.append(f"<li>Dropped check: {_h(expr)} · {_h(origin)} × {count}</li>")
        for (call, reason, origin, line, may_effect, may_block, via, target), count in ops.items():
            path = " → ".join(reversed(via))
            location = origin or f"reported at {ep.file}:{line}"
            rows.append(f"<li>{_h(call)} · {_h(reason)} · {_h(location)} · "
                        f"{'effect-capable' if may_effect else 'value only'}"
                        f"{' · may block' if may_block else ''} · {_h(path)} · {_h(target or '')} × {count}</li>")
        groups.append(f"<details><summary>{_h(label)} · {len(effects[site])} modeled effects · "
                      f"{capable} effect-capable records ({len(locations)} distinct known source lines) · "
                      f"{value_only} value-only records · "
                      f"{sum(checks[site].values())} dropped checks</summary>"
                      f"<ul class=\"compact\">{''.join(rows)}</ul></details>")
    return "<h3>Helper trace</h3>" + "".join(groups) if groups else ""


def _access_state(res):
    if not res.effects:
        return "none"
    if all(er.verdict == "safe" for er in res.effects):
        return "all_proved"
    return "unproved"


def _access_stats(results):
    verdicts = Counter(er.verdict for res in results for er in res.effects)
    states = Counter(_access_state(res) for res in results)
    return {
        "total": sum(verdicts.values()),
        "by_verdict": dict(sorted(verdicts.items())),
        "endpoints_by_access_state": {key: states[key] for key in ("none", "all_proved", "unproved")},
    }


def _html_finding(res, policy) -> str:
    ep = res.endpoint
    label, status_key = _display_status(res)
    reasons = _review_reasons(res)
    resources = sorted({er.effect.resource for er in res.effects})
    searchable = " ".join([ep.key, ep.file, label, *resources]).lower()
    review_value = "yes" if reasons else "no"

    review_html = ""
    if reasons:
        items = "".join(f"<li>{_h(reason)}</li>" for reason in reasons)
        review_html = f'<div class="review"><strong>Needs review</strong><ul>{items}</ul></div>'

    effects_html = ""
    if res.effects:
        effects_html = (
            "<h3>Modeled effects</h3>"
            "<table><thead><tr><th>Kind</th><th>Resource</th><th>Access verdict</th>"
            "<th>Rows touched when</th><th>Policy allows when</th></tr></thead>"
            f"<tbody>{_html_effect_rows(res, policy)}</tbody></table>"
        )

    violations = []
    for er in res.effects:
        if er.verdict in ("violation", "possible_violation"):
            description = describe_violation(ep, er)
            if er.blocking_calls:
                description.append("may be blocked by: " + ", ".join(er.blocking_calls))
            violations.append("<li>" + "<br>".join(_h(line) for line in description) + "</li>")
    violation_html = ""
    if violations:
        violation_html = "<h3>Counterexample</h3><ul class=\"compact\">" + "".join(violations) + "</ul>"


    assumptions_html = ""
    if res.assumptions:
        assumptions_html = "<h3>Assumptions</h3>" + "".join(
            f'<span class="pill">{_h(res.provenance[key])} [{_h(key)}]</span>'
            for key in sorted(res.provenance)
        )


    principal = ep.principal_binding or "none modeled"
    return (
        f'<details class="finding {_h(status_key)}" data-verdict="{_h(status_key)}" '
        f'data-resources="{_h("|".join(resources))}" data-review="{review_value}" '
        f'data-accesses="{_access_state(res)}" data-search="{_h(searchable)}">'
        "<summary>"
        f'<span class="status">{_h(label)}</span>'
        f'<span class="endpoint">{_h(ep.key)}</span>'
        f'<span class="source">{_h(ep.file)}:{ep.line}</span>'
        "</summary>"
        '<div class="detail">'
        f"<p><strong>What this means:</strong> {_h(_status_explanation(res))}</p>"
        f"<p><strong>Principal:</strong> {_h(principal)} via {_h(ep.principal_via)}</p>"
        f"{review_html}{_html_helper_trace(res)}{effects_html}{violation_html}{assumptions_html}"
        "</div></details>"
    )


def html_report(results, policy, title: str = "Keyhole security report") -> str:
    """Build a portable report with client-side filters and no dependencies."""
    ordered = sorted(
        results,
        key=lambda r: (
            {"violation": 0, "possible_violation": 1, "unknown": 2,
             "safe_assumed": 3, "no_effects_assumed": 3, "safe": 4, "no_effects": 5}[r.verdict],
            r.endpoint.file,
            r.endpoint.line,
        ),
    )
    raw_counts = {key: sum(r.verdict == key for r in results) for key in LABEL}
    accesses = _access_stats(results)
    states = accesses["endpoints_by_access_state"]
    incomplete = sum(any(o.may_have_effects for o in r.endpoint.opaque) for r in results)
    proof_complete = sum(
        bool(r.endpoint.effects) and r.verdict == "safe" for r in results
    )
    resources = sorted({er.effect.resource for r in results for er in r.effects})
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    provenance = ", ".join(
        f"{key}={value}" for key, value in policy.metadata.items()
    ) or "not declared"

    metrics = [
        (len(results), "Endpoints"),
        (raw_counts["violation"], "VIOLATION (modeled)"),
        (raw_counts["possible_violation"], "Possible violations"),
        (raw_counts["unknown"], "Unknown"),
        (proof_complete, "Proof-complete"),
        (f'{accesses["by_verdict"].get("safe", 0)} / {accesses["total"]}', "Modeled accesses proved under the supplied policy"),
        (states["all_proved"], "Endpoints with every modeled access proved"),
        (states["none"], "Endpoints with zero extracted accesses"),
        (incomplete, "Partial models"),
    ]
    metrics_html = "".join(
        f'<div class="metric"><strong>{number}</strong><span>{_h(label)}</span></div>'
        for number, label in metrics
    )
    resource_options = "".join(f'<option value="{_h(r)}">{_h(r)}</option>' for r in resources)
    findings = "".join(_html_finding(res, policy) for res in ordered)
    unknown_rate = (100 * incomplete / len(results)) if results else 0
    notice = (
        f"{incomplete} of {len(results)} endpoints ({unknown_rate:.1f}%) contain unmodeled operations. "
        "A Lean verdict proves the extracted AIR, not that extraction from the application was complete."
    )
    guide = """
      <details class="guide" open>
        <summary>How to read this report</summary>
        <p>Start with coverage, then inspect findings. A proof applies to the extracted model (AIR), so a green result is
        meaningful only when the endpoint is fully modeled and its policy is confirmed.</p>
        <div class="guide-grid">
          <div class="legend-item"><strong>Possible violation</strong><br>Lean found a model counterexample. Its listed blockers explain why the endpoint requires review.</div>
          <div class="legend-item"><strong>VIOLATION (modeled)</strong><br>A modeled effect has a Lean-checked counterexample. Extraction and policy remain trusted inputs.</div>
          <div class="legend-item"><strong>Unknown</strong><br>Unsupported code prevented a complete authorization decision. This is not safe and not a vulnerability claim.</div>
          <div class="legend-item"><strong>Safe (assumed)</strong><br>The proof works only if an unconfirmed policy or helper summary is accurate.</div>
          <div class="legend-item"><strong>Verified safe</strong><br>Every modeled row access is allowed by the confirmed policy, with no unmodeled operations in the route.</div>
          <div class="legend-item"><strong>No modeled effects</strong><br>No database object access was extracted. Check whether the endpoint is a redirect/health route or hides access behind helpers.</div>
        </div>
        <ol class="reading-order">
          <li>Filter to <strong>VIOLATION (modeled)</strong>, then <strong>Possible violations</strong>, and expand a result.</li>
          <li>Read <strong>Needs review</strong>. These gaps explain why the finding may be a false positive.</li>
          <li>Compare <strong>Rows touched when</strong> with <strong>Policy allows when</strong>. A violation means the first condition does not guarantee the second.</li>
          <li>Use the counterexample as a source-review or test lead; do not treat placeholder values such as <code>&lt;v0&gt;</code> as real IDs.</li>
          <li>Then filter to <strong>Unknown</strong>; these endpoints need adapter support or reviewed helper summaries before they can be assessed.</li>
        </ol>
      </details>
    """

    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>{_h(title)}</title>{_HTML_STYLE}</head><body>"
        f"<header><h1>{_h(title)}</h1><p>Generated {_h(generated)}</p>"
        f"<p>Policy provenance: {_h(provenance)}</p>"
        f"<p>{_h(MODEL_TRUST_NOTICE)}</p></header>"
        f'<main><div class="notice"><strong>Coverage warning:</strong> {_h(notice)}</div>'
        f"{guide}"
        f'<section class="summary">{metrics_html}</section>'
        '<section class="toolbar" aria-label="Report filters">'
        '<input id="filter-search" type="search" placeholder="Search endpoint, file, or resource…">'
        '<select id="filter-verdict"><option value="">All results</option>'
        '<option value="violation">VIOLATION (modeled)</option>'
        '<option value="possible_violation">Possible violations</option><option value="unknown">Unknown</option>'
        '<option value="safe_assumed">Safe (assumed)</option><option value="safe">Verified safe</option>'
        '<option value="no_effects_assumed">No modeled effects (assumed)</option>'
        '<option value="no_effects">No modeled effects</option></select>'
        f'<select id="filter-resource"><option value="">All resources</option>{resource_options}</select>'
        '<select id="filter-review"><option value="">All review states</option>'
        '<option value="yes">Needs review</option><option value="no">No review flags</option></select>'
        '<select id="filter-accesses" aria-label="Modeled access proofs"><option value="">All access states</option>'
        '<option value="all_proved">Every modeled access proved</option>'
        '<option value="unproved">Has an unproved access</option><option value="none">Zero modeled accesses</option></select>'
        '</section><p id="result-count" class="result-count"></p>'
        f'<section id="findings">{findings}</section></main>{_HTML_SCRIPT}</body></html>'
    )


def sarif_report(results) -> str:
    sarif_results = []
    for res in results:
        if res.verdict not in ("violation", "possible_violation", "unknown"):
            continue
        ep = res.endpoint
        msg = f"{LABEL[res.verdict]}: {ep.key}"
        for er in res.effects:
            if er.verdict in ("violation", "possible_violation"):
                msg += " - " + "; ".join(describe_violation(ep, er))
                if er.blocking_calls:
                    msg += "; may be blocked by: " + ", ".join(er.blocking_calls)
                break
        is_violation = res.verdict == "violation"
        is_possible = res.verdict == "possible_violation"
        sarif_results.append({
            "ruleId": "keyhole/idor" if is_violation else (
                "keyhole/possible-idor" if is_possible else "keyhole/unknown"
            ),
            "level": "error" if is_violation else "warning",
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
            {"id": "keyhole/possible-idor", "shortDescription": {"text": "Possible IDOR blocked by opaque code"}},
            {"id": "keyhole/unknown", "shortDescription": {"text": "Endpoint could not be fully modelled"}}]}},
            "results": sarif_results}],
    }, indent=2)


def stats_report(results) -> str:
    """Coverage statistics for reproducible evaluations and papers."""
    verdict_counts = {label: sum(r.verdict == label for r in results) for label in LABEL}
    by_reason = {}
    by_call = {}
    combined = {}
    for res in results:
        if res.verdict != "unknown":
            continue
        for opaque in res.endpoint.opaque:
            if not opaque.may_have_effects:
                continue  # value-only opacity is not why the endpoint is UNKNOWN
            call = opaque.call.split("(", 1)[0].strip() or "<unknown>"
            by_reason[opaque.reason] = by_reason.get(opaque.reason, 0) + 1
            by_call[call] = by_call.get(call, 0) + 1
            combined[(opaque.reason, call)] = combined.get((opaque.reason, call), 0) + 1

    def ordered(mapping):
        return dict(sorted(mapping.items(), key=lambda item: (-item[1], item[0])))

    top = [
        {"reason": reason, "call": call, "count": count}
        for (reason, call), count in sorted(
            combined.items(), key=lambda item: (-item[1], item[0][0], item[0][1])
        )[:10]
    ]
    return json.dumps({
        "endpoints": len(results),
        "verdict_counts": verdict_counts,
        "modeled_accesses": _access_stats(results),
        "unknown_causes": {
            "by_reason": ordered(by_reason),
            "by_call": ordered(by_call),
            "top_10": top,
        },
    }, indent=2)

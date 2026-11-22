"""Helper summaries (step 2b).

When the parser cannot see inside a call (for example a compiled or installed
package), a summary describes what the call does in AIR terms. Summaries are
normally drafted once by an LLM and then committed, so every later run reads
the same file and results are deterministic. This MVP only *reads* summaries;
see README for the planned `keyhole summarize` command.

File: .keyhole/summaries/<dotted.call.name>.yaml

    call: storage.load_doc
    args: [db, doc_id]            # positional parameter names
    status: assumed               # or: reviewed
    evidence: "SELECT * FROM documents WHERE id = :doc_id"   # quoted source, optional
    returns:
      kind: read
      resource: Document
      selector: {eq: [{field: id}, {arg: doc_id}]}
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml


@dataclass
class Summary:
    call: str
    args: list
    status: str
    kind: str
    resource: str
    selector: object
    evidence: str | None = None

    @property
    def reviewed(self) -> bool:
        return self.status == "reviewed"


def load_summaries(repo: Path) -> dict:
    out = {}
    d = Path(repo) / ".keyhole" / "summaries"
    if not d.is_dir():
        return out
    for f in sorted(d.glob("*.yaml")):
        data = yaml.safe_load(f.read_text()) or {}
        ret = data.get("returns") or {}
        s = Summary(call=data["call"], args=list(data.get("args") or []),
                    status=str(data.get("status", "assumed")),
                    kind=ret.get("kind", "read"), resource=ret["resource"],
                    selector=ret.get("selector", True), evidence=data.get("evidence"))
        out[s.call] = s
    return out


def instantiate(pred, bind):
    """Replace {"arg": name} terms in a summary predicate using bind(name) -> term|None."""
    if pred is True or pred is False:
        return pred
    (k, v), = pred.items()
    if k in ("and", "or"):
        parts = [instantiate(p, bind) for p in v]
        return None if any(p is None for p in parts) else {k: parts}
    if k == "eq":
        terms = [_term(t, bind) for t in v]
        return None if None in terms else {"eq": terms}
    if k == "member":
        terms = [_term(t, bind) for t in v[1:]]
        return None if None in terms else {"member": [v[0], *terms]}
    return None


def _term(t, bind):
    if isinstance(t, dict) and "arg" in t:
        return bind(t["arg"])
    return t

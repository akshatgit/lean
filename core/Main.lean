/-
  keyhole-core: reads AIR + policy JSON, runs the verified checker, writes verdicts.

  Input  (file path argument):
    { "policy":  [ {"resource": "Document", "kind": "read", "allow": PRED}, ... ],
      "effects": [ {"id": "...", "kind": "read", "resource": "Document",
                    "selector": PRED, "guards": [PRED, ...]}, ... ] }
  PRED := true | false | {"eq": [TERM, TERM]} | {"member": [REL, TERM, TERM]}
        | {"and": [PRED, ...]} | {"or": [PRED, ...]}
  TERM := {"param": NAME} | {"principal": ATTR} | {"field": NAME} | {"const": VALUE}

  Output (stdout): { "results": [ {"id": ..., "verdict": "safe" | "violation" | "unknown", ...} ] }
  The parsing here is plumbing; correctness of verdicts comes from Keyhole.Check.
-/
import Lean.Data.Json
import Keyhole

open Lean Keyhole

def parseTerm (j : Json) : Except String Keyhole.Term := do
  if let .ok v := j.getObjValAs? String "param" then return .param v
  if let .ok v := j.getObjValAs? String "principal" then return .principal v
  if let .ok v := j.getObjValAs? String "field" then return .field v
  if let .ok v := j.getObjValAs? String "const" then return .const v
  throw s!"bad term: {j.compress}"

partial def parsePred (j : Json) : Except String Pred := do
  if let .ok b := j.getBool? then return (if b then .tt else .ff)
  if let .ok arr := j.getObjValAs? (Array Json) "eq" then
    if h : arr.size = 2 then
      return .eq (← parseTerm arr[0]) (← parseTerm arr[1])
    else throw "eq needs 2 terms"
  if let .ok arr := j.getObjValAs? (Array Json) "member" then
    if h : arr.size = 3 then
      return .member (← fromJson? arr[0]) (← parseTerm arr[1]) (← parseTerm arr[2])
    else throw "member needs [rel, subj, obj]"
  if let .ok arr := j.getObjValAs? (Array Json) "and" then
    let ps ← arr.toList.mapM parsePred
    return match ps with
      | [] => .tt
      | p :: rest => rest.foldl Pred.and p
  if let .ok arr := j.getObjValAs? (Array Json) "or" then
    let ps ← arr.toList.mapM parsePred
    return match ps with
      | [] => .ff
      | p :: rest => rest.foldl Pred.or p
  throw s!"bad predicate: {j.compress}"

def parseKind : String → Except String Kind
  | "read" => pure .read
  | "update" => pure .update
  | "delete" => pure .delete
  | "create" => pure .create
  | k => throw s!"bad kind: {k}"

def parseRule (j : Json) : Except String Rule := do
  return { resource := ← j.getObjValAs? String "resource",
           kind := ← parseKind (← j.getObjValAs? String "kind"),
           allow := ← parsePred (← j.getObjVal? "allow") }

def parseEffect (j : Json) : Except String (String × Effect) := do
  let id ← j.getObjValAs? String "id"
  let guards ← (← j.getObjValAs? (Array Json) "guards").toList.mapM parsePred
  return (id, { kind := ← parseKind (← j.getObjValAs? String "kind"),
                resource := ← j.getObjValAs? String "resource",
                selector := ← parsePred (← j.getObjVal? "selector"),
                guards := guards })

def termJson : Keyhole.Term → Json
  | .param n => Json.mkObj [("param", n)]
  | .principal a => Json.mkObj [("principal", a)]
  | .field f => Json.mkObj [("field", f)]
  | .const v => Json.mkObj [("const", v)]

def verdictJson (id : String) : Verdict → Json
  | .safe => Json.mkObj [("id", id), ("verdict", "safe")]
  | .unknown why => Json.mkObj [("id", id), ("verdict", "unknown"), ("why", why)]
  | .violation w => Json.mkObj [
      ("id", id), ("verdict", "violation"),
      ("witness", Json.mkObj [
        ("values", Json.arr (w.vals.toArray.map fun (t, v) =>
          Json.arr #[termJson t, Json.str v])),
        ("facts", Json.arr (w.facts.toArray.map fun (r, a, b) =>
          Json.arr #[Json.str r, Json.str a, Json.str b]))])]

def run (input : String) : Except String Json := do
  let j ← Json.parse input
  let pol ← (← j.getObjValAs? (Array Json) "policy").toList.mapM parseRule
  let effs ← (← j.getObjValAs? (Array Json) "effects").toList.mapM parseEffect
  let results := effs.map fun (id, e) => verdictJson id (check e pol)
  return Json.mkObj [("results", Json.arr results.toArray)]

def main (args : List String) : IO UInt32 := do
  match args with
  | [path] =>
    match run (← IO.FS.readFile path) with
    | .ok out => IO.println out.compress; return 0
    | .error err => IO.eprintln s!"keyhole-core: {err}"; return 2
  | _ => IO.eprintln "usage: keyhole-core INPUT.json"; return 2

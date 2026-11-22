/-
  Authorization Intermediate Representation (AIR): syntax and semantics.

  An endpoint is a list of effects. Each effect touches rows of one resource
  type; the rows it may touch are those satisfying its guards and selector.
  The safety property: every row an effect can touch is allowed by the policy.
-/
namespace Keyhole

abbrev Value := String

/-- A value an AIR predicate can mention. -/
inductive Term where
  | param (name : String)       -- request value (attacker controlled)
  | principal (attr : String)   -- authenticated caller attribute
  | field (name : String)       -- column of the row being touched
  | const (v : Value)
  deriving DecidableEq, Repr, Inhabited

/-- The predicate language shared by selectors, guards and policies. -/
inductive Pred where
  | tt
  | ff
  | eq (a b : Term)
  | member (rel : String) (subj obj : Term)
  | and (p q : Pred)
  | or (p q : Pred)
  deriving DecidableEq, Repr, Inhabited

/-- One concrete request evaluated against one row. -/
structure Env where
  params    : String → Value
  principal : String → Value
  row       : String → Value
  rels      : String → Value → Value → Bool

def Term.eval (env : Env) : Term → Value
  | .param n     => env.params n
  | .principal a => env.principal a
  | .field f     => env.row f
  | .const v     => v

def Pred.eval (env : Env) : Pred → Bool
  | .tt           => true
  | .ff           => false
  | .eq a b       => decide (a.eval env = b.eval env)
  | .member r s o => env.rels r (s.eval env) (o.eval env)
  | .and p q      => p.eval env && q.eval env
  | .or p q       => p.eval env || q.eval env

inductive Kind where
  | read | update | delete | create
  deriving DecidableEq, Repr, Inhabited

structure Effect where
  kind     : Kind
  resource : String
  selector : Pred
  guards   : List Pred
  deriving Repr, Inhabited

/-- Guards and selector as one predicate. -/
def Effect.hyp (e : Effect) : Pred := e.guards.foldr Pred.and e.selector

/-- Can this effect touch the row described by `env`? -/
def Effect.touches (e : Effect) (env : Env) : Bool := e.hyp.eval env

structure Rule where
  resource : String
  kind     : Kind
  allow    : Pred
  deriving Repr, Inhabited

abbrev Policy := List Rule

/-- The allow-predicate for a resource and kind; deny by default. -/
def Policy.rule (pol : Policy) (res : String) (k : Kind) : Pred :=
  match pol.find? (fun r => r.resource == res && r.kind == k) with
  | some r => r.allow
  | none   => .ff

/-- The safety property: every row the effect can touch is allowed. -/
def Safe (e : Effect) (pol : Policy) : Prop :=
  ∀ env, e.touches env = true → (pol.rule e.resource e.kind).eval env = true

end Keyhole

/-
  The checker and its correctness proofs.

  Strategy (proof by reflection, proven once):
  1. Put the effect's hypothesis (guards ∧ selector) and the policy rule in
     disjunctive normal form (DNF).
  2. SAFE if every hypothesis conjunct entails some policy conjunct, using
     equality reasoning over the conjunct's own equalities. Proven sound by
     `check_sound`.
  3. Otherwise build a candidate counterexample (one value per equality
     class) and evaluate it. Report VIOLATION only if evaluation confirms it,
     so every reported witness is real (`check_witness`).
  4. Anything else is UNKNOWN. The checker never guesses SAFE.
-/
import Keyhole.Air

namespace Keyhole

/-! ## Atoms and DNF -/

inductive Atom where
  | tt
  | ff
  | eq (a b : Term)
  | member (rel : String) (s o : Term)
  deriving DecidableEq, Repr, Inhabited

def Atom.eval (env : Env) : Atom → Bool
  | .tt           => true
  | .ff           => false
  | .eq a b       => decide (a.eval env = b.eval env)
  | .member r s o => env.rels r (s.eval env) (o.eval env)

def dnf : Pred → List (List Atom)
  | .tt           => [[.tt]]
  | .ff           => []
  | .eq a b       => [[.eq a b]]
  | .member r s o => [[.member r s o]]
  | .or p q       => dnf p ++ dnf q
  | .and p q      => (dnf p).flatMap (fun c => (dnf q).map (fun d => c ++ d))

theorem dnf_iff (env : Env) (p : Pred) :
    p.eval env = true ↔ ∃ c ∈ dnf p, ∀ a ∈ c, a.eval env = true := by
  induction p with
  | tt => simp [Pred.eval, dnf, Atom.eval]
  | ff => simp [Pred.eval, dnf]
  | eq a b => simp [Pred.eval, dnf, Atom.eval]
  | member r s o => simp [Pred.eval, dnf, Atom.eval]
  | or p q ihp ihq =>
    simp only [Pred.eval, Bool.or_eq_true, ihp, ihq, dnf, List.mem_append]
    constructor
    · rintro (⟨c, hc, h⟩ | ⟨c, hc, h⟩)
      · exact ⟨c, Or.inl hc, h⟩
      · exact ⟨c, Or.inr hc, h⟩
    · rintro ⟨c, hc | hc, h⟩
      · exact Or.inl ⟨c, hc, h⟩
      · exact Or.inr ⟨c, hc, h⟩
  | and p q ihp ihq =>
    simp only [Pred.eval, Bool.and_eq_true, ihp, ihq, dnf, List.mem_flatMap, List.mem_map]
    constructor
    · rintro ⟨⟨c, hc, hca⟩, ⟨d, hd, hda⟩⟩
      refine ⟨c ++ d, ⟨c, hc, d, hd, rfl⟩, fun a ha => ?_⟩
      rcases List.mem_append.mp ha with h | h
      · exact hca a h
      · exact hda a h
    · rintro ⟨x, ⟨c, hc, d, hd, rfl⟩, hx⟩
      exact ⟨⟨c, hc, fun a ha => hx a (List.mem_append.mpr (Or.inl ha))⟩,
             ⟨d, hd, fun a ha => hx a (List.mem_append.mpr (Or.inr ha))⟩⟩

/-! ## Equality reasoning inside one conjunct -/

def eqEdges : List Atom → List (Term × Term)
  | [] => []
  | .eq a b :: rest => (a, b) :: eqEdges rest
  | _ :: rest => eqEdges rest

/-- `a` and `b` are connected by a chain of at most `n` equalities. -/
def conn : Nat → List (Term × Term) → Term → Term → Bool
  | 0, _, a, b => decide (a = b)
  | n + 1, E, a, b =>
    decide (a = b) ||
      E.any (fun e => (decide (e.1 = a) && conn n E e.2 b) ||
                      (decide (e.2 = a) && conn n E e.1 b))

theorem conn_sound (env : Env) (E : List (Term × Term))
    (hE : ∀ e ∈ E, e.1.eval env = e.2.eval env) :
    ∀ n a b, conn n E a b = true → a.eval env = b.eval env := by
  intro n
  induction n with
  | zero =>
    intro a b h
    simp only [conn, decide_eq_true_eq] at h
    rw [h]
  | succ n ih =>
    intro a b h
    simp only [conn, Bool.or_eq_true, decide_eq_true_eq, List.any_eq_true,
      Bool.and_eq_true] at h
    rcases h with h | ⟨e, he, ⟨h1, h2⟩ | ⟨h1, h2⟩⟩
    · rw [h]
    · rw [← h1, hE e he]; exact ih _ _ h2
    · rw [← h1, ← hE e he]; exact ih _ _ h2

theorem eqEdges_sound (env : Env) :
    ∀ c : List Atom, (∀ a ∈ c, a.eval env = true) →
      ∀ e ∈ eqEdges c, e.1.eval env = e.2.eval env := by
  intro c
  induction c with
  | nil => intro _ e he; simp [eqEdges] at he
  | cons x rest ih =>
    intro hc e he
    have hrest : ∀ a ∈ rest, a.eval env = true :=
      fun a ha => hc a (List.mem_cons_of_mem _ ha)
    cases x with
    | eq a b =>
      simp only [eqEdges, List.mem_cons] at he
      rcases he with rfl | he
      · have := hc (.eq a b) (List.mem_cons_self ..)
        simpa [Atom.eval] using this
      · exact ih hrest e he
    | tt => exact ih hrest e (by simpa [eqEdges] using he)
    | ff => exact ih hrest e (by simpa [eqEdges] using he)
    | member r s o => exact ih hrest e (by simpa [eqEdges] using he)

/-! ## Entailment -/

def fuel (c : List Atom) : Nat := (eqEdges c).length + 1

/-- Does hypothesis atom `h` establish `member r s o` (up to equalities)? -/
def memberMatch (c : List Atom) (r : String) (s o : Term) : Atom → Bool
  | .member r' s' o' =>
    decide (r = r') && conn (fuel c) (eqEdges c) s s' && conn (fuel c) (eqEdges c) o o'
  | _ => false

def entailsAtom (c : List Atom) : Atom → Bool
  | .tt           => true
  | .ff           => false
  | .eq a b       => conn (fuel c) (eqEdges c) a b
  | .member r s o => c.any (memberMatch c r s o)

theorem entailsAtom_sound (env : Env) (c : List Atom)
    (hc : ∀ a ∈ c, a.eval env = true) :
    ∀ g, entailsAtom c g = true → g.eval env = true := by
  have hE := eqEdges_sound env c hc
  have hconn := conn_sound env (eqEdges c) hE (fuel c)
  intro g hg
  cases g with
  | tt => rfl
  | ff => simp [entailsAtom] at hg
  | eq a b =>
    simp only [Atom.eval, decide_eq_true_eq]
    exact hconn a b hg
  | member r s o =>
    simp only [entailsAtom, List.any_eq_true] at hg
    obtain ⟨h, hmem, hm⟩ := hg
    cases h with
    | member r' s' o' =>
      simp only [memberMatch, Bool.and_eq_true, decide_eq_true_eq] at hm
      obtain ⟨⟨hr, hs⟩, ho⟩ := hm
      have hh := hc _ hmem
      simp only [Atom.eval] at hh ⊢
      rw [hr, hconn s s' hs, hconn o o' ho]
      exact hh
    | tt => simp [memberMatch] at hm
    | ff => simp [memberMatch] at hm
    | eq _ _ => simp [memberMatch] at hm

/-- Every hypothesis conjunct entails some goal conjunct. -/
def entails (hyp goal : Pred) : Bool :=
  (dnf hyp).all (fun c => (dnf goal).any (fun g => g.all (entailsAtom c)))

theorem entails_sound (hyp goal : Pred) (h : entails hyp goal = true) :
    ∀ env, hyp.eval env = true → goal.eval env = true := by
  intro env hh
  obtain ⟨c, hc, hca⟩ := (dnf_iff env hyp).mp hh
  simp only [entails, List.all_eq_true, List.any_eq_true] at h
  obtain ⟨g, hg, hga⟩ := h c hc
  apply (dnf_iff env goal).mpr
  refine ⟨g, hg, fun a ha => ?_⟩
  exact entailsAtom_sound env c hca a (hga a ha)

/-! ## Counterexample construction (checked by evaluation, not trusted) -/

structure Witness where
  vals  : List (Term × Value)
  facts : List (String × Value × Value)
  deriving Repr, Inhabited

def Witness.lookup (w : Witness) (t : Term) : Value :=
  match w.vals.find? (fun p => p.1 == t) with
  | some p => p.2
  | none   => "#unset"

def Witness.toEnv (w : Witness) : Env where
  params n    := w.lookup (.param n)
  principal a := w.lookup (.principal a)
  row f       := w.lookup (.field f)
  rels r a b  := w.facts.any (fun x => x.1 == r && x.2.1 == a && x.2.2 == b)

def Atom.terms : Atom → List Term
  | .eq a b       => [a, b]
  | .member _ s o => [s, o]
  | _             => []

def Pred.terms : Pred → List Term
  | .eq a b       => [a, b]
  | .member _ s o => [s, o]
  | .and p q      => p.terms ++ q.terms
  | .or p q       => p.terms ++ q.terms
  | _             => []

def isConst : Term → Bool
  | .const _ => true
  | _        => false

def firstIdx (p : Term → Bool) : List Term → Nat → Option Nat
  | [], _ => none
  | t :: ts, i => if p t then some i else firstIdx p ts (i + 1)

/-- One value per equality class; constants keep their own value. -/
def classVal (c : List Atom) (ts : List Term) (t : Term) : Value :=
  match t with
  | .const v => v
  | _ =>
    let linked := fun u => conn (fuel c) (eqEdges c) t u
    match ts.find? (fun u => isConst u && linked u) with
    | some (.const v) => v
    | _ =>
      match firstIdx linked ts 0 with
      | some i => "#w" ++ toString i
      | none   => "#w?"

def mkWitness (c : List Atom) (goal : Pred) : Witness :=
  let ts := (c.flatMap Atom.terms) ++ goal.terms
  let val := classVal c ts
  { vals  := ts.map (fun t => (t, val t)),
    facts := c.filterMap (fun a => match a with
      | .member r s o => some (r, val s, val o)
      | _ => none) }

/-- Try each hypothesis conjunct; keep the first candidate that evaluation confirms. -/
def findWitness (hyp goal : Pred) : List (List Atom) → Option Witness
  | [] => none
  | c :: cs =>
    let w := mkWitness c goal
    if hyp.eval w.toEnv = true ∧ goal.eval w.toEnv = false then some w
    else findWitness hyp goal cs

theorem findWitness_spec (hyp goal : Pred) :
    ∀ cs w, findWitness hyp goal cs = some w →
      hyp.eval w.toEnv = true ∧ goal.eval w.toEnv = false := by
  intro cs
  induction cs with
  | nil => intro w h; simp [findWitness] at h
  | cons c cs ih =>
    intro w h
    simp only [findWitness] at h
    split at h
    · rename_i hcond
      simp only [Option.some.injEq] at h
      subst h
      exact hcond
    · exact ih w h

/-! ## The checker -/

inductive Verdict where
  | safe
  | violation (w : Witness)
  | unknown (why : String)
  deriving Repr, Inhabited

def check (e : Effect) (pol : Policy) : Verdict :=
  if entails e.hyp (pol.rule e.resource e.kind) then .safe
  else
    match findWitness e.hyp (pol.rule e.resource e.kind) (dnf e.hyp) with
    | some w => .violation w
    | none   => .unknown "not entailed, and no counterexample was confirmed"

/-- If the checker says SAFE, the effect is safe for every request and row. -/
theorem check_sound (e : Effect) (pol : Policy) (h : check e pol = .safe) :
    Safe e pol := by
  unfold check at h
  split at h
  · rename_i hent
    intro env ht
    exact entails_sound _ _ hent env ht
  · split at h <;> simp at h

/-- Every reported violation is a real counterexample in the semantics. -/
theorem check_witness (e : Effect) (pol : Policy) (w : Witness)
    (h : check e pol = .violation w) :
    e.touches w.toEnv = true ∧ (pol.rule e.resource e.kind).eval w.toEnv = false := by
  unfold check at h
  split at h
  · simp at h
  · split at h
    · rename_i w' hw
      simp only [Verdict.violation.injEq] at h
      subst h
      exact findWitness_spec _ _ _ _ hw
    · simp at h

end Keyhole

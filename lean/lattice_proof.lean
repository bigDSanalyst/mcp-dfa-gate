structure LatticeState where
  taint  : BitVec 64
  halted : Bool
  deriving Repr, DecidableEq

structure Rule where
  taint     : BitVec 64
  clearance : BitVec 64
  deriving Repr, DecidableEq

def step (s : LatticeState) (r : Rule) : LatticeState × Bool :=
  if s.halted then
    ({ s with halted := true }, false)
  else if (s.taint &&& ~~~r.clearance) != 0#64 then
    ({ s with halted := true }, false)
  else
    ({ taint := s.taint ||| r.taint, halted := false }, true)

def run_trace (s : LatticeState) : List Rule → LatticeState × Bool
  | [] => (s, true)
  | r :: rest =>
    let (s', ok) := step s r
    let (sf, ok_rest) := run_trace s' rest
    (sf, ok && ok_rest)

theorem halted_rejects_nonempty (t : BitVec 64) (r : Rule) (rest : List Rule) :
    (run_trace { taint := t, halted := true } (r :: rest)).2 = false := by
  simp [run_trace, step]

theorem violation_nonzero (t c : BitVec 64) (i : Fin 64)
    (ht : t[i.val] = true) (hc : c[i.val] = false) :
    ((t &&& ~~~c) != 0#64) = true := by
  have hne : (t &&& ~~~c) ≠ 0#64 := by
    intro heq
    have hbit := congrArg (fun v : BitVec 64 => v[i.val]) heq
    simp [BitVec.getElem_and, BitVec.getElem_not, ht, hc] at hbit
  simp [hne]

theorem universal_non_interference :
    ∀ (trace : List Rule) (s : LatticeState) (i : Fin 64),
      s.taint[i.val] = true →
      (∃ r ∈ trace, r.clearance[i.val] = false) →
      (run_trace s trace).2 = false := by
  intro trace
  induction trace with
  | nil =>
    intro _ _ _ h
    rcases h with ⟨_, hc, _⟩
    cases hc
  | cons head tail ih =>
    intro s i ht h
    cases hhalt : s.halted with
    | true =>
      simp [run_trace, step, hhalt]
    | false =>
      cases hviol : ((s.taint &&& ~~~head.clearance) != 0#64) with
      | true =>
        simp [run_trace, step, hhalt, hviol]
      | false =>
        have hhead_ok : head.clearance[i.val] = true := by
          cases hc : head.clearance[i.val]
          · have hv := violation_nonzero s.taint head.clearance i ht hc
            simp [hv] at hviol
          · rfl
        have htail : ∃ r ∈ tail, r.clearance[i.val] = false := by
          rcases h with ⟨r, hmem, hclr⟩
          cases hmem with
          | head => simp [hhead_ok] at hclr
          | tail _ hmem' => exact ⟨r, hmem', hclr⟩
        have ht_next : (s.taint ||| head.taint)[i.val] = true := by
          simp [BitVec.getElem_or, ht]
        have hrec := ih { taint := s.taint ||| head.taint, halted := false } i ht_next htail
        simp [run_trace, step, hhalt, hviol, hrec]

#print axioms halted_rejects_nonempty
#print axioms universal_non_interference

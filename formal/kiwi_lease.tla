------------------------------ MODULE kiwi_lease ------------------------------
(***************************************************************************)
(* A tiny, bounded TLA+ model of the Kiwi lease/commit protocol: one        *)
(* logical run, a bounded set of jobs, 1-2 runners, per-job generations,    *)
(* cancel and infrastructure retry. It exists to state the fencing          *)
(* invariants independently of the implementation language and to stay      *)
(* aligned with the executable evidence:                                   *)
(*                                                                          *)
(*   internal/scheduler/model_property_test.go                              *)
(*     TestPropertySchedulerModelMachine (leases, completes, cancellations, *)
(*     recovery and stale-generation probes over a reference model)        *)
(*     TestPropertySchedulerStaleGenerationRefused                          *)
(*   internal/server/lease_fence_chaos_test.go                              *)
(*     TestLeaseFenceChaosMatrixStaleGenerationRejected                     *)
(*                                                                          *)
(* The model is deliberately hand-written TLA+ (no PlusCal toolchain        *)
(* required). See formal/README.md for how to run TLC, the abstraction      *)
(* boundaries and the mirror mapping.                                       *)
(*                                                                          *)
(* Abstraction: `Complete` carries the same fence the store evaluates at    *)
(* commit time (status + holder + generation inside the locked row);        *)
(* `StaleAttempt` models a late request that passed the request-start gate  *)
(* and is then refused by the commit-time fence. Clocks, tokens, network    *)
(* reordering, crashes and concurrent transactions are NOT modeled; the     *)
(* executable tests cover those (see formal/README.md).                     *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Jobs,      \* bounded set of job identifiers, e.g. {"job-a", "job-b"}
    Runners    \* bounded set of runner identifiers, e.g. {"runner-1"}

\* MaxGen bounds the model: at most MaxGen attempts per job, so TLC's state
\* space is finite. Cancel may bump a generation once past the last attempt,
\* hence CancelRun is guarded by the same bound.
MaxGen == 3

VARIABLES
    gen,          \* gen[j]: newest issued generation of job j (attempt identity)
    lease,        \* lease[j]: runner holding the live lease of j, or "none"
    status,       \* status[j]: "queued" | "running" | "success" | "failure" | "cancelled"
    commits,      \* authoritative ledger: committed [job, runner, gen, outcome] records
    refused,      \* commit-time refusals: stale attempts the fence rejected
    runCancelled  \* run-level cancel flag (terminal)

vars == <<gen, lease, status, commits, refused, runCancelled>>

Live == {"queued", "running"}
Terminal == {"success", "failure", "cancelled"}
Outcomes == {"success", "failure"}
CommitRec == [job: Jobs, runner: Runners, gen: 0..MaxGen, outcome: Outcomes]

(***************************************************************************)
(* TypeOK: every variable stays inside its declared domain.                 *)
(***************************************************************************)
TypeOK ==
    /\ gen \in [Jobs -> 0..MaxGen]
    /\ lease \in [Jobs -> Runners \cup {"none"}]
    /\ status \in [Jobs -> Live \cup Terminal]
    /\ commits \subseteq CommitRec
    /\ refused \subseteq CommitRec
    /\ runCancelled \in BOOLEAN

Init ==
    /\ gen = [j \in Jobs |-> 0]
    /\ lease = [j \in Jobs |-> "none"]
    /\ status = [j \in Jobs |-> "queued"]
    /\ commits = {}
    /\ refused = {}
    /\ runCancelled = FALSE

(***************************************************************************)
(* Lease: a queued job in a non-cancelled run is claimed by a runner under  *)
(* a NEW generation. The generation is the attempt identity, so every lease *)
(* invalidates every earlier claim.                                         *)
(***************************************************************************)
Lease(j, r) ==
    /\ status[j] = "queued"
    /\ ~runCancelled
    /\ gen[j] < MaxGen
    /\ status' = [status EXCEPT ![j] = "running"]
    /\ lease' = [lease EXCEPT ![j] = r]
    /\ gen' = [gen EXCEPT ![j] = gen[j] + 1]
    /\ UNCHANGED <<commits, refused, runCancelled>>

(***************************************************************************)
(* Complete: the commit-time fence. A completion commits an outcome ONLY    *)
(* when the locked row still shows status=running, holder=r and             *)
(* generation=g. This is the single-winner fence every authoritative        *)
(* mutation shares (I1/I3).                                                 *)
(***************************************************************************)
Complete(j, r, g, o) ==
    /\ o \in Outcomes
    /\ status[j] = "running"
    /\ lease[j] = r
    /\ gen[j] = g
    /\ status' = [status EXCEPT ![j] = o]
    /\ lease' = [lease EXCEPT ![j] = "none"]
    /\ commits' = commits \cup {[job |-> j, runner |-> r, gen |-> g, outcome |-> o]}
    /\ UNCHANGED <<gen, refused, runCancelled>>

(***************************************************************************)
(* StaleAttempt: a superseded owner still sends its completion/heartbeat;   *)
(* the fence refuses it (nothing authoritative changes) and the refusal is  *)
(* recorded so StaleOwnerCannotCommit can state that it can never later     *)
(* appear in the committed ledger.                                          *)
(*                                                                          *)
(* `g <= gen[j]` is the attempt-identity abstraction: a request can only    *)
(* carry a generation that was already issued. Forged FUTURE generations    *)
(* are refused by the same fence in the implementation but are out of this  *)
(* model's abstraction (like token hashes): recording them would let a      *)
(* future lease legitimately issue the same generation and make a refused   *)
(* record later commit, which is an artifact of the abstraction, not of the *)
(* protocol.                                                                *)
(***************************************************************************)
StaleAttempt(j, r, g, o) ==
    /\ o \in Outcomes
    /\ g <= gen[j]
    /\ ~(status[j] = "running" /\ lease[j] = r /\ gen[j] = g)
    /\ refused' = refused \cup {[job |-> j, runner |-> r, gen |-> g, outcome |-> o]}
    /\ UNCHANGED <<gen, lease, status, commits, runCancelled>>

(***************************************************************************)
(* Retry: infrastructure retry is allowed ONLY for a failed attempt, never  *)
(* for a success and never for a cancelled job/run, and it issues a NEW     *)
(* generation, so the failed attempt's record is immutable history.         *)
(***************************************************************************)
Retry(j) ==
    /\ status[j] = "failure"
    /\ ~runCancelled
    /\ gen[j] < MaxGen
    /\ status' = [status EXCEPT ![j] = "queued"]
    /\ gen' = [gen EXCEPT ![j] = gen[j] + 1]
    /\ lease' = [lease EXCEPT ![j] = "none"]
    /\ UNCHANGED <<commits, refused, runCancelled>>

(***************************************************************************)
(* CancelRun: terminal. Every non-terminal job becomes "cancelled" and      *)
(* every outstanding lease is voided (generation bump when the bound        *)
(* allows) so no stale owner can commit afterwards. Committed outcomes are  *)
(* untouched.                                                               *)
(***************************************************************************)
CancelRun ==
    /\ ~runCancelled
    /\ runCancelled' = TRUE
    /\ LET cancelled(j) == status[j] \in Live IN
       /\ status' = [j \in Jobs |-> IF cancelled(j) THEN "cancelled" ELSE status[j]]
       /\ gen' = [j \in Jobs |-> IF cancelled(j) /\ gen[j] < MaxGen
                                    THEN gen[j] + 1 ELSE gen[j]]
       /\ lease' = [j \in Jobs |-> IF cancelled(j) THEN "none" ELSE lease[j]]
    /\ UNCHANGED <<commits, refused>>

Next ==
    \/ \E j \in Jobs, r \in Runners : Lease(j, r)
    \/ \E j \in Jobs, r \in Runners, g \in 0..MaxGen, o \in Outcomes : Complete(j, r, g, o)
    \/ \E j \in Jobs, r \in Runners, g \in 0..MaxGen, o \in Outcomes : StaleAttempt(j, r, g, o)
    \/ \E j \in Jobs : Retry(j)
    \/ CancelRun

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* INVARIANTS (state predicates; declared under INVARIANT in the .cfg).     *)
(***************************************************************************)

NoTwoWinners ==
    \* At most ONE authoritative successful completion per job, across all   *)
    \* retries and cancellations.                                            *)
    \A j \in Jobs :
        Cardinality({rec \in commits : rec.job = j /\ rec.outcome = "success"}) <= 1

StaleOwnerCannotCommit ==
    \* A refused (stale-owner) attempt can never later appear in the         *)
    \* committed ledger, and every committed record names a generation that  *)
    \* was already issued (generations never regress).                       *)
    /\ commits \cap refused = {}
    /\ \A rec \in commits : rec.gen <= gen[rec.job]

OneCommitPerGeneration ==
    \* One attempt (job, generation) commits at most one outcome.            *)
    \A rec1, rec2 \in commits :
        rec1.job = rec2.job /\ rec1.gen = rec2.gen => rec1 = rec2

(***************************************************************************)
(* PROPERTIES (temporal formulas; declared under PROPERTY in the .cfg).     *)
(***************************************************************************)

TerminalityMonotonic ==
    \* The committed ledger only grows, and a successful completion is       *)
    \* absorbing: once a job reports success it can never leave success       *)
    \* (Retry requires "failure"), so a terminal record is never rewritten.  *)
    /\ [][commits \subseteq commits']_vars
    /\ \A j \in Jobs : [](status[j] = "success" => [](status[j] = "success"))

CancelCannotResurrect ==
    \* Cancellation is terminal at both levels: once the run is cancelled    *)
    \* it stays cancelled, and once a job is cancelled it stays cancelled.   *)
    \* Together with Retry (allowed only from "failure") and Lease (allowed  *)
    \* only from "queued"), a cancelled job cannot run or commit again.      *)
    /\ [](runCancelled => [](runCancelled))
    /\ \A j \in Jobs : [](status[j] = "cancelled" => [](status[j] = "cancelled"))

=============================================================================

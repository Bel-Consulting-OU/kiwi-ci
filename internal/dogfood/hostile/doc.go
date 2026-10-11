// Package hostile models a runner that misbehaves deterministically against
// the Kiwi runner protocol. Each Mode is one named adversarial behavior from
// the audit's runner threat surface; New builds the exact protocol traffic
// that mode emits so a scenario can feed it through the control-plane gate
// and prove the gate rejects it WITHOUT losing liveness for the honest
// holder.
//
// Hostile traffic is data, not execution: this package never talks to a
// network, never spawns a process and never mutates system state. The
// harness decides what to do with the produced claims.
package hostile

# Prometheus operator provision

Date: 20 August 2026.

This document is for Jason Gale. This package is laboratory code under PolicyLab-2. This package is not Sanctum. This package is not a Cyera product.

This document uses ASD-STE100 Simplified Technical English. Technical names appear in full words.

## Directory enroll versus this kernel

A directory enroll does this work:

1. Create a name.
2. Add groups to that name.
3. Issue a password or a certificate.
4. Login enumerates the groups.

Prometheus does this work instead:

1. `init` creates the issuer record and the empty store.
2. `agent-type add` writes one agent type.
3. `birth` writes one instance, the first capability, and one holder key. The holder key is written once.
4. `challenge` plus `check` allow or refuse one tool act.
5. Optional `spawn` writes a narrower child instance and a narrower child capability.
6. `instance kill` plus `kill export` write a signed death bundle.

Store B is a verifier. Store B does `issuer accept`, then `act accept`, then `kill accept`. Store B does not mint. Store B does not create instance records. Store B does not append a second issuance.log line.

## Five records

1. agent type
2. instance
3. capability
4. chain
5. issuer

A sixth identity record is refused. A presentation, a decision receipt, a Merkle inclusion proof, a signed tree head, and an act bundle are artifacts. They are not records.

## Five kernel system calls

1. mint
2. verify
3. attenuate
4. present
5. kill

Birth and spawn are market commands. They sit on mint. Check sits on verify.

Present may emit a laboratory X.509-SVID wrap. Present may also emit a laboratory Workload Identity Token plus Content-Digest. Both wraps are artifacts. The instance identifier is not a distinguished name and is not a token subject. Short life is not kill.

## Visible walks

Run `scripts/demo_walkthrough.sh` for one store: init, birth, check, present, act accept, and one refuse.

Run `scripts/demo_kill_accept.sh` for two stores: parent act, child spawn, parent kill, and store B kill accept. Store B does not mint.

Run `scripts/demo_svid_kill_accept.sh` for two stores: a laboratory X.509-SVID wrap of present, store B verify-svid, parent kill accept, then refuse of the parent wrap and of the child wrap.

`status` and these scripts do not print secrets. Do not copy `issuer.secret`, `biscuit.secret`, holder secrets, or member-two secrets.

The 20 August 2026 judge walk lives in `see-walk/judge-rung6`. `JUDGE.md` holds the five answers.

Open `BROWSER-WALK.md` to start two loopback hosts and test act and kill without the command line after init. The issuance-threshold birth walk lives in `see-walk/threshold-two-store`.

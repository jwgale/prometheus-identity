# Prometheus morning brief

Date: 19 August 2026. Time for the reader: about 08:00 America/Chicago.

This document is for Jason Gale. This package is Jason Gale side-project laboratory code under PolicyLab-2. This package is not Sanctum. This package is not a Cyera product. This package is not Oasis. Findings in this directory are not Sanctum product source of truth.

This brief uses ASD-STE100 Simplified Technical English. Technical names appear in full words on first use.

## 1. Result

A laboratory agent-identity kernel exists now at `/workspace/Prometheus`. The Rust package name is `prometheus_identity`. The command-line interface (CLI) binary name is `prometheus`. The kernel stores five closed records and refuses a sixth record type. A name is not a key. An instance identifier is not the holder public key. `cargo test --quiet` on this tree completed with 233 tests passed, 0 failed, and 0 ignored. The directory holds 24 focused demonstration scripts plus one walkthrough under `scripts/`. `prometheus status` prints a laboratory operator view. `bash scripts/demo_walkthrough.sh` walks init, status, birth, check, present, act, status, and one fail-closed refuse. The program writes JavaScript Object Notation (JSON) files under a data directory. The laboratory issuer profile name is `lab-ml-dsa-65-hybrid-biscuit-ed25519`. The identity root is Module-Lattice Digital Signature Algorithm 65. The Biscuit envelope is still laboratory Ed25519. This is not a production FIPS module. This is not a post-quantum Biscuit. This is a working side-project kernel. This is not a production issuer.

PROGRESS: The issuer identity root is Module-Lattice Digital Signature Algorithm 65 (`fips204`, FIPS 204 parameter set ML-DSA-65). Issuer init refuses a classical-only root. Rotate changes the Module-Lattice current key only and keeps the Biscuit envelope Ed25519 key. Instance, capability, agent type, and chain records carry laboratory issuer signatures. Rotate must not launder a planted file. This laboratory now ships multi-signature issuance: a mint, birth, spawn, save-sign, log-append, receipt, or tree-head is valid only when at least `threshold_n` distinct Module-Lattice Digital Signature Algorithm 65 signatures from trusted issuer member keys verify over the same documented concatenation. Init still writes `threshold_n` 1. When `threshold_n` is 1, one current key signs, the same as before. This is not a Shamir split of `issuer.secret`. This is not FROST or threshold Edwards-curve Digital Signature Algorithm on Curve 25519 as the identity root. This is not Federal Information Processing Standard 204 threshold Module-Lattice Digital Signature Algorithm.

## 2. How this is not the other products

This comparison is honest. Prometheus is laboratory code. Prometheus does not replace those products.

Microsoft Entra Agent ID names and catalogs agents next to users and applications, then a token can arrive later. Prometheus treats identity as an authorized act. The `birth` command writes the instance and the first capability as one issuance event. A directory row that later receives a token is not the Prometheus model. Prometheus does not use Microsoft catalog names.

Oasis non-human identity (NHI) products inventory machine identities. Prometheus is a kernel that a host can ask before a tool action. The market hook is allow or refuse. The market hook is not a directory listing.

Open Authorization (OAuth) on an agent issues a bearer access token. Prometheus refuses a capability token that is presented without a holder proof that answers a one-time challenge. A capability token is not accepted as a bearer token. This laboratory holder challenge is not a production proof of possession.

## 3. Five records, five system calls, and market commands

### Decided: five records. There is no sixth record type.

1. **agent type**: identifier string (not a key), owner, allowed intents, authorization limit, maximum delegation depth, cryptographic profile, lifetime in seconds, laboratory issuer public key, laboratory issuer signature.
2. **instance**: identifier (not a key), agent type identifier, owner, born time, expires time, holder public key (hexadecimal bytes; written once at birth or spawn and never replaced), status (`live` or `revoked`), optional parent instance identifier, attributes map, laboratory issuer public key, laboratory issuer signature.
3. **capability**: identifier, instance identifier, act authority (`on_behalf_of`: a user identifier or the exact word `autonomous`), intent, audience, caveats, issued time, expires time (frozen after the first write), revoke identifier, capability token bytes, laboratory issuer public key, laboratory issuer signature.
4. **chain**: capability identifier, optional parent capability identifier, hop index, who attenuated, revoke-from-here flag, laboratory issuer public key, laboratory issuer signature.
5. **issuer**: current public key (Module-Lattice hexadecimal), public keys, previous issuer keys with a kill date, accepted issuer public keys, Biscuit envelope public key (`biscuit_public_key_hex`; this is not the identity root), cryptographic profile (`lab-ml-dsa-65-hybrid-biscuit-ed25519`), optional store-wide `kill_date`, `threshold_n` (init default `1`; a mint is valid only when at least this many distinct trusted Module-Lattice member signatures verify; lowering is refused), issuance log path.

`current_public_key`, `previous_issuer_keys`, `accepted_issuer_public_keys`, and `kill_date` are fields on the issuer record. They are not a sixth identity record. The issuer signature fields live on the existing instance, capability, agent type, and chain records. They are not a sixth identity record.

### Decided: five kernel system calls.

1. **mint** — issue a capability for a live instance inside the type authorization limit.
2. **verify** — allow or refuse a capability against audience, intent, act authority, holder proof, and a one-time challenge.
3. **attenuate** — reduce audience, intent, lifetime, or depth. Attenuation cannot widen rights.
4. **present** — write a signed presentation document from the existing instance, capability, and issuer records. Present is a document, not a name. Present is not a bearer document.
5. **kill** — revoke a capability or an instance. A parent kill stops the parent, all child instances, and all capabilities in those chains.

### Market commands that sit on those calls.

- **birth** — one write that creates the instance and the first capability. Identity starts as an authorized act.
- **spawn** — one write that creates a child instance and a narrower capability. The child cannot gain rights that the parent does not have.
- **check** — allow or refuse a named tool action. The caller must name the capability identifier and `on_behalf_of`. The kernel does not guess.
- **host** — listen on a loopback address only (default `127.0.0.1:18765`) and answer `POST /check`. Binding to all interfaces is not permitted.
- **act export** and **act accept** — export or accept a local bundle of three existing artifacts: the signed decision receipt, a Merkle inclusion proof, and a signed tree head. Accept is verify-only. The second store does not become a second identity kernel.

Related store commands that exist in the CLI and are not a sixth system call: `init`, `status`, `challenge`, `agent-type add`, `agent-type raise` (always refuses), `agent-type add-intent` (always refuses), `instance show`, `instance rebind` (always refuses), `capability extend` (always refuses), `log show`, `log verify`, `log root`, `log prove`, `log check-proof`, `log sign-root`, `log check-root`, `receipt verify`, `issuer accept`, `issuer rotate`, `issuer seal`, `issuer member add`, `issuer threshold`, `present verify`.

## 4. What the overnight work completed

### Kernel fail-closed locks (decided)

The kernel refuses when a required check fails. There is no force-allow command and no debug bypass.

- Mint, check, and spawn enforce the authorization limit. Destination is a prefix class. Intent must sit in `allowed_intents`. The instance cannot raise the type limit.
- After the first write of an agent type, `authorization_limit` must not increase. `prometheus agent-type raise` always refuses. Narrowing to a child of the stored limit may persist.
- After the first write of an agent type, `allowed_intents` must not gain a new intent string. `prometheus agent-type add-intent` always refuses. Removing an intent may persist. The same set may persist.
- After the first write of an agent type, `max_delegation_depth` must not increase. A lower depth may persist. The same depth may persist.
- After the first write of a capability identifier, `expires` must not move later. `prometheus capability extend` always refuses. An attenuated child must not expire after the parent.
- The holder public key is written once at birth or spawn. A later persist that replaces `holder_public_key` is refused. `prometheus instance rebind` always refuses. Kill, revoke, expire, and parent-kill do not rewrite the first binder.
- Verify, check, spawn, present, and the local host require a holder proof that answers a one-time challenge nonce. Re-use of a spent nonce fails. A challenge past its time window fails. A static laboratory challenge is not accepted.
- Check and verify must name `on_behalf_of`. Empty is not autonomous. The exact word `autonomous` is required. The value must match the capability token fact.
- A parent on behalf of a named user cannot birth an autonomous child. The child must keep that same user.
- Chain records store hop index. A hop past `max_delegation_depth` fails.
- A parent kill stops child instances and the capabilities in those chains.
- The check host binds to a loopback address only.
- After store-wide issuer death, mint, birth, spawn, rotate, accept, sign-root, present, attenuation, verify, check, and host refuse. Historical receipt verify and historical present verify of already-written documents may still succeed.

### Decided fail-closed lock: laboratory issuer signatures on store records

Instance, capability, agent type, and chain records now carry `issuer_signature_hex` and `issuer_public_key_hex`. This is a laboratory Module-Lattice Digital Signature Algorithm signature over a documented concatenation. This is not a Merkle tree of the whole store. This is not a database. This is not a transparency log of records. This is not a production FIPS module. This is not a post-quantum Biscuit.

The kernel re-signs with the current issuer secret on every successful save of those records. Freeze raises still refuse before a signature is written. A caller cannot persist an arbitrary signature. Rotate re-signs every stored instance, capability, agent type, and chain so an old record still verifies after the previous-key `kill_date`.

Evaluate, verify, check, host, present, mint, birth, spawn, and attenuate recompute the documented bytes after load. A missing signature refuses. A wrong signature refuses. The signature key must be the current key or a previous key still before `kill_date`. A file planted in the data directory cannot act. The store JSON is not enough.

### Decided fail-closed lock: multi-signature issuance

A mint, birth, spawn, save-sign, log-append, receipt, or tree-head is valid only when at least `threshold_n` distinct Module-Lattice Digital Signature Algorithm 65 signatures from trusted issuer member keys verify over the same documented concatenation. Init writes `threshold_n` 1. When `threshold_n` is 1, one current key signs. `prometheus issuer member add` writes `issuer-member-*.secret` under the data directory. `prometheus issuer threshold --n K` refuses K less than 1, refuses K greater than the trusted member count, and refuses lowering. The Biscuit envelope key is not a member. For n=2, one valid signature refuses evaluate.

This is multi-signature issuance. This is not a Shamir split of `issuer.secret`. This is not FROST. This is not Federal Information Processing Standard 204 threshold Module-Lattice Digital Signature Algorithm.

### Decided: laboratory operator status and one walkthrough

`prometheus status` prints a derived operator view of this store. The view includes the cryptographic profile, the current issuer public key, the honest identity-root line, `threshold_n`, member count, sealed or not, record counts, issuance-log leaf count, Merkle root, and the loopback host reminder. Status refuses if the issuer is missing. Status does not print secrets. Status is not a sixth identity record.

`scripts/demo_walkthrough.sh` is one short walkthrough. It is not a graphical user interface. It is not Sanctum.

### Overnight holes that are now locked

These holes were found in the store files and the act paths. They are locked now. They are not still open.

- **Biscuit `starts_with` sibling prefix.** The capability token used a Biscuit `starts_with` check. That check treated `internal/payroll` as inside `internal/pay`, and `readwrite` as inside `read`. Those strings are not child paths. Evaluate now requires `is_narrower_or_equal` on the requested intent and audience against the capability record. Verify, check, and host share that choke point.
- **Token versus record.** A later persist could replace the capability token or widen the record fields. After the token signature check, verify, check, host, and present compare token facts to the capability record. The store record is the source for identity fields. The token must not exceed or contradict it. After the first write, intent and audience must stay narrower or equal. `on_behalf_of`, `instance_id`, and token bytes must not change.
- **Persist-raises on issuer, capability, instance, and chain.** A later save that grants more rights than the first write is refused at the save choke point. Locked on the issuer: postpone or clear of realm `kill_date`; swap of `current_public_key` without rotate; growth of `public_keys` with a foreign key; remove or postpone of a previous issuer key. Locked on the instance: later `expires`; change of `agent_type_id`; clear or swap of `parent_instance_id`; un-revoke to live. Locked on the chain: decrease of `hop_index`; clear or swap of `parent_capability_id`; clear of `revoke_from_here`. Type `lifetime_seconds` cannot increase.
- **Seal postpone.** `save_issuer` did not freeze realm `issuer.kill_date`. A later persist could move death later or clear it, then mint at the original seal time. First seal may set the time. Shorten may persist. Postpone and clear are refused.
- **Planted files.** A JSON file written into the data directory used to act if it parsed. A planted instance, capability, agent type, or chain without a trusted issuer signature now refuses. A planted type with a wider limit cannot mint. A planted chain with a lower hop index cannot grant more hops. A planted chain that clears `revoke_from_here` cannot revive a killed chain. Rotate must not re-sign that planted file.
- **Single-signature mint after n=2.** A record or mint with only one valid Module-Lattice member signature is refused when `threshold_n` is 2. A Biscuit envelope key used as a member signature does not count. Lowering `threshold_n` is refused.

### Receipts and log (decided as local laboratory artifacts)

After every verify or check, allow or refuse, the kernel signs a decision receipt with the issuer private key. The receipt includes `issuance_log_line`: the exact JSON line of that event as written to `issuance.log`. A valid signature is not enough if that line is missing or altered.

Each issuance-log JSON line includes `previous_line_hash` and `line_hash`. Both values are Secure Hash Algorithm 256-bit (SHA-256) hexadecimal digests. `prometheus log verify` walks the file and fails closed on a missing field, a wrong previous hash, or a wrong line hash. Each log line carries `issuer_signature_hex` over the documented concatenation of `line_hash` and `issuer_public_key_hex`. A hash-chain-only append without `issuer.secret` fails log verify and receipt-line bind. This is still a local log. This is not Certificate Transparency.

The store can compute a local Merkle root over the sequence of `line_hash` values. `prometheus log root` prints the root and the leaf count. `prometheus log prove` writes an inclusion proof. `prometheus log check-proof` recomputes the root.

`prometheus log sign-root` signs that current Merkle root with the current issuer secret only. The signed bytes are a documented concatenation. That concatenation is not JSON. `prometheus log check-root` verifies the signature against this store accept list.

This is a local JSON line log with a local SHA-256 hash chain, a local Merkle tree, a locally signed tree head, and a laboratory Module-Lattice receipt. This is not a public transparency log. This is not Certificate Transparency. This is not a gossip protocol.

### Second-store verify without a second kernel (decided)

The issuer record stores `accepted_issuer_public_keys`. Init always includes this store own public key. `prometheus issuer accept --public-key-hex` adds a foreign key. Empty is refused.

A second Prometheus store can accept the first issuer public key and then:

- verify a first-store receipt against the first `issuance.log`, or
- accept a local act bundle (`receipt.json`, `proof.json`, `tree-head.json`) without copying the full log, or
- verify a signed presentation after the same accept-list step.

Accept does not mint. Accept does not create instance records. Accept does not write a second `issuance.log` line. This is an accept list. This is not a global name system. This is not Secure Production Identity Framework For Everyone (SPIFFE) federation.

### Death and rotate (decided as laboratory single-key controls)

`prometheus issuer rotate [--kill-after-seconds N]` creates a new laboratory issuer key pair. `issuer.secret` becomes the new key only. New mint, birth, spawn, and receipts sign with the current key only. The old public key stays on the accept list until its `kill_date`. Old capabilities verify until capability expiry. Rotate does not revoke already-issued capabilities. After `kill_date`, a new signature from the old key that is not in the issuance log is refused even if the signature is valid. Rotate re-signs every stored instance, capability, agent type, and chain with the new current secret.

`prometheus issuer seal --after-seconds N` sets store-wide `issuer.kill_date` to now plus N seconds. N must be greater than zero. A later seal cannot postpone death. A later seal that only shortens remaining life is allowed. Realm `issuer.kill_date` is this issuer record own death. A previous-key `kill_date` remains "this old key cannot mint."

Rotate still rotates the current Module-Lattice key only. `threshold_n` is unchanged. The previous key remains a trusted member until `kill_date`. The Biscuit envelope key stays and is not a member. This is laboratory multi-signature issuance over Module-Lattice Digital Signature Algorithm 65 plus a pre-committed issuer death. This is not a Shamir split. This is not FROST. This is not Federal Information Processing Standard 204 threshold Module-Lattice Digital Signature Algorithm. This is not a production FIPS module. This is not a post-quantum Biscuit. This is not a network partition detector.

## 5. How to run

From `/workspace/Prometheus`:

```
cargo test
bash scripts/demo.sh
bash scripts/demo_birth.sh
bash scripts/demo_depth.sh
bash scripts/demo_spawn_child.sh
bash scripts/demo_internal_versus_public.sh
bash scripts/demo_host.sh
bash scripts/demo_parent_kill.sh
bash scripts/demo_tool_loop.sh
bash scripts/demo_on_behalf.sh
bash scripts/demo_spawn_authority.sh
bash scripts/demo_receipt.sh
bash scripts/demo_log_chain.sh
bash scripts/demo_accept_issuer.sh
bash scripts/demo_issuer_rotate.sh
bash scripts/demo_log_proof.sh
bash scripts/demo_sign_root.sh
bash scripts/demo_first_binder.sh
bash scripts/demo_issuer_seal.sh
bash scripts/demo_act_bundle.sh
bash scripts/demo_present.sh
bash scripts/demo_limit_freeze.sh
bash scripts/demo_expiry_freeze.sh
bash scripts/demo_intent_freeze.sh
bash scripts/demo_threshold.sh
bash scripts/demo_walkthrough.sh
```

`prometheus --data-directory ./data status` prints the laboratory operator view after `init`.

Optional: `just demo` if the `just` command is installed. `just test` runs `cargo test`. `just build` runs `cargo build`.

This tree is not a git repository. There is no GitHub remote. There is no continuous integration (CI) workflow in this directory.

## 6. Honest open gaps

Mark these as **open**. Do not treat them as completed work.

- **Shamir, FROST, and Federal Information Processing Standard 204 threshold Module-Lattice Digital Signature Algorithm remain open.** This laboratory ships multi-signature issuance: at least `threshold_n` distinct trusted Module-Lattice member signatures over the same documented concatenation. That is not a Shamir split of `issuer.secret`. That is not FROST. That is not FIPS 204 threshold Module-Lattice Digital Signature Algorithm.
- **A production FIPS module is open.** The laboratory identity root is Module-Lattice Digital Signature Algorithm 65. The Biscuit envelope is still laboratory Ed25519. This is not a production FIPS module. This is not a post-quantum Biscuit.
- **A public transparency log is open.** The JSON line log is local only. The hash chain, the Merkle tree, the signed tree head, the receipt, and the act bundle are local laboratory artifacts. They are not a public append-only service. The record signatures are not a store Merkle tree and are not a transparency log of records.
- **A production proof of possession is open.** The holder challenge is a local nonce with a time window. This is not a remote challenge protocol.
- **A SPIFFE presenter is open.** This package does not issue a SPIFFE document, a SPIFFE Verifiable Identity Document (SVID), an X.509 certificate, a Workload Identity in Multi-System Environments (WIMSE) token, or a Transaction Token. Present is a signed presentation document, not a name. The instance identifier must not become a certificate subject.
- **A secrets store is out of scope by design.** The laboratory writes a holder secret file under `holders/`. A production secret holder is not implemented. This brief does not assign that work to Sanctum as product source of truth.
- **There is no GitHub remote.** This directory is not a git repository.
- **There is no CI.** Tests and demonstrations run on this machine only.

Also decided as out of scope, not a defect: a global name system, a second identity kernel, Certificate Transparency gossip, a network partition detector, a liveness probe, a multi-witness clock, and network identity outside the local loopback check host.

## 7. What you can approve next (side project only)

These choices are for this laboratory only. They are not Sanctum work. They are not Cyera work. They are not Oasis work.

1. **Approve a production FIPS module or a post-quantum Biscuit.** Keep the five records. Do not make X.509 the instance name. The laboratory hybrid profile is already in this tree.
2. **Status and the walkthrough are in this tree.** Keep five records. Do not add a sixth record. Do not start a secrets-store design. Do not add a graphical user interface.
3. **Stop here and use this tree as the kernel.** The fail-closed locks, the local log, the accept-list second-store path, rotate, seal, the laboratory issuer signatures, and multi-signature issuance on instance, capability, agent type, and chain records are in place. The open gaps above stay open until you approve more work.

Do not start a public transparency log, a SPIFFE presenter, a secrets store, a GitHub remote, or CI unless you approve that work as a later side-project step. Those items are open. They are not implied by this overnight build.

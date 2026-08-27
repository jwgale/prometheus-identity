# Prometheus source of truth

Date: 22 August 2026.

This document is for Jason Gale. This package is Jason Gale side-project laboratory code under PolicyLab-2.

This page is the product source of truth for Prometheus. Later work may not reverse a lock on this page without Jason Gale. Anatomy is the closed kernel shape. Vision is the order of work. Judge is evidence. Provision is operator verbs. NAMING.md is the locked product names. JUDGE-NON-CLI.md is proof without the command line.

This document uses ASD-STE100 Simplified Technical English. Technical names appear in full words.

## 1. What this product is

Prometheus is an agent-identity kernel. Create Agent Principal. Assertion Act. A consumer can check that Assertion Act. Decommission.

Jason Gale locked these product names on 21 August 2026 and 22 August 2026. Create Agent Principal is the product name for the laboratory act called birth. Assertion Act is the product name for the laboratory act called present. Decommission is the product name for the laboratory act called death. Decommission is the end-of-life workflow for the identity. Check keeps the laboratory name until Jason Gale locks a new word. Kernel system calls and host paths stay mapped: birth_write, present, kill, POST /birth, POST /present-svid, POST /present-wimse, POST /kill, POST /kill-export, POST /kill-accept. Product pages and colleague briefs use the locked names.

This product is not Sanctum. This product is not a Cyera product. This product is not Oasis. Findings here are not Sanctum product source of truth. Do not open pull requests on SanctumSec/sanctum for this work. Do not mix this work with Trawsome.

## 2. The inversion

Today’s identity provider creates a name, then a login, then groups or roles, then a review, then a standing secret. An agent cannot attest intent the way a human can. That order fails at Create Agent Principal.

Prometheus inverts that order.

1. Create Agent Principal is the privilege. One persist writes the instance, the first capability, the holder key, and the Decommission path. The laboratory write remains birth_write.
2. Assertion Act is a document of one act. A second party verifies the document. A second party does not look up a name and enumerate groups. The laboratory call remains present.
3. Decommission is portable end of life. A verifier accepts a signed Decommission bundle. The verifier does not copy the inode. The laboratory call remains kill.
4. Spawn writes a narrower child of that act. Spawn is not a role catalog.

Records persist. Bearer credentials do not. The holder key is proof of possession for one challenge. The holder key is not the instance identifier.

## 3. Closed kernel

Five identity records exist: agent type, instance, capability, chain, issuer. Artifacts are not records. A presentation, a decision receipt, a Merkle proof, a signed tree head, an act bundle, a kill bundle, and a laboratory X.509-SVID wrap are artifacts.

Five kernel system calls exist: mint, verify, attenuate, present, kill. Create Agent Principal and spawn sit on mint. The laboratory names stay mapped. Check sits on verify. Host sits on check.

The identity root is Module-Lattice Digital Signature Algorithm. A new birth write refuses a classical-only root. The Biscuit token is a laboratory envelope. The Biscuit token is not the inode.

Store B is a verifier. Store B does not mint. Store B does not receive issuer.secret. Threshold is a property of one issuer. Member two is not a second store. Unsigned issuer.json threshold_n is not live when a signed issuance.log line already raised n. Unsigned issuer.json kill_date is not live when a signed issuer_seal issuance.log line already exists. Unsigned issuer.json kill_date is not live when it is later than the earliest signed issuer.kill_date on an issuer_seal issuance.log line. Unsigned issuer.json previous_issuer_keys kill_date is not live when it is later than the earliest signed kill_date on an issuer_rotate issuance.log line for that previous public key. Unsigned issuer.json previous_issuer_keys is not live when a signed issuer_rotate issuance.log line already records that previous public key. Unsigned issuer.json accepted_previous_issuer_keys kill date is not live when a signed previous_key_accept issuance.log line already recorded that key. Unsigned issuer.json verify_threshold_n is not live when a signed issuer_verify_threshold issuance.log line already raised n. Unsigned issuer.json public_keys extras are not live when they are not the current public key and not a signed issuer_member_add public key.

Jason Gale locked one kernel, restorable on 26 August 2026. Create Agent Principal has one birth authority. A second live issuer is a second identity kernel and is refused. Recovery is restore of that same issuer after the issuing computer is dead. Restore is not copying issuer.secret onto a live Store B. Laboratory cold restore with a backup is started. Restore is key plus ledger onto an empty issuing store after the old mint is dead. Member two is not in the backup. After restore at issuance threshold_n 2 the outside member is still required. After restore at laboratory issuance threshold_n 3 both outside members are still required. Backup still excludes member two and member three. Standing data-a stays n=2. After restore the issuer public key is unchanged. A verifier that pinned that public key can still allow an honest present. After restore, WIMSE on-ramp still verifies against the original issuer pin. Restore is restore. Restore is disaster recovery of the same issuer. Restore is not a separate product. Self-healing after failure is internal diagnostics that run after restore and indicate whether restore succeeded and operation returned to normal. Those diagnostics do not invent issuer.secret and do not start a second issuer. Jason Gale locked this on 27 August 2026. Do not reverse one kernel, restorable. The two-host cold-restore operator walk lives in see-walk/cold-restore-two-host.

Authorization limit is the highest intent and destination an agent type may hold. A child cannot exceed its parent. An instance cannot raise its own authorization limit.

See ANATOMY.md for the field-level closed set.

## 4. Presentation

X.509 and SPIFFE are a presentation on-ramp. The instance identifier must not become a distinguished name. The Uniform Resource Identifier subject alternative name names the presentation, not the instance. Short certificate life is not kill. WIMSE HTTP token plus Content-Digest is a second on-ramp artifact. The loopback host consumes that WIMSE on-ramp artifact at POST /present-wimse and POST /check-wimse; the instance identifier stays inside the present. The loopback WIMSE check binds HTTP method, request-target, and content-digest; this is still not a full header-coverage stack. This is still an on-ramp artifact, not a sixth record.

The loopback check host consumes the wrap at POST /check-svid. The host is a check. The host is not a directory. The host binds to a loopback address only. GET /.well-known/prometheus-check is a laboratory discovery artifact, not a sixth record, and not a public listener. On a public check-only host that document names check paths and allowed operator pins. That public document omits write and export verbs. The same host also answers GET /instances, POST /challenge, POST /verifier-challenge, POST /sign-holder-nonce, and POST /present-svid. Birth, local kill, kill export, agent-type add, spawn, issuer seal, and issuer rotate may be invoked on the loopback host. POST /kill-export returns the three public kill artifacts after local kill. POST /kill-accept on a verifier host reuses Kernel kill accept for those artifacts, and POST /issuer-accept pins a foreign issuer public key hex only; the verifier does not copy the inode. POST /seal-export returns the three public seal artifacts after local seal. A live issuer is refused. POST /seal-accept pins accepted seal on the existing issuer record. POST /rotate is on the loopback host and still cannot drop a previous key. POST /member-two and POST /set-verify-threshold are on the same loopback host; the operator types a local outside path, secret bytes are not returned, and verify_threshold_n cannot be raised before that member public key is persisted. The laboratory proven outside path is a remote file on prometheus-member-two, reached from the issuing computer as a typed path over the laboratory site-to-site tunnel. issuer.secret stays on the issuing computer. Who holds member two in a later market stays open. POST /set-issuer-threshold is on the same loopback host; the confirm field must equal the exact word issuer-threshold, issuance threshold_n cannot be raised before that member public key is persisted, and n=3 is allowed on a laboratory issuer with three outside-capable members. Standing data-a stays issuance threshold_n 2. SPIRE stays parked. POST /backup, POST /restore, and POST /diagnose are issuing-loopback writes. They reuse Kernel export_issuer_backup, restore_from_backup, and restore_diagnostics. Confirm must equal the exact word backup or restore. Diagnose takes a from path. Check-only and the public well-known document omit those writes. Backup path must live outside the data directory. Restore onto a dest that already has an issuer is refused. An issuing host with empty --data may start so restore can write. Standing data-a is not the restore dest. Secret bytes are not returned. This is not a sixth identity record. This is not Sanctum. After issuance threshold_n is 2, POST /birth, POST /agent-type, POST /spawn, POST /present-svid, POST /present-wimse, POST /kill, POST /rotate, POST /seal, POST /kill-export, POST /act-export, POST /check, POST /challenge, POST /seal-export, POST /set-verify-threshold, and issuing-store POST /check-svid and POST /check-wimse require member_secret_path on the live host body. A live host that already registered member two still requires that path on those bodies. Present signs. Check signs a receipt and appends issuance.log. Challenge appends a signed issuance.log line. A holder challenge after instance Decommission is refused on the kernel, not only the host. Set-verify-threshold appends a signed issuance.log line. Kill needs two signatures. Export signs a tree head. Those writes are not verify-only. Raising issuance threshold_n to 2 is a signed persist at the new n. That raise refuses when the outside member secret is not presented. A refused raise does not persist the new n and does not append a new signed line. POST /set-issuer-threshold after n=2 is a same-n no-op and does not append a new signed line. Store B check-svid and check-wimse have no instance and must not require issuer member material. After issuer seal that write is refused. Previous-key kill travels as issuer-record verifier state through POST /previous-key-export and POST /previous-key-accept, not as a sixth record. After seal accept, Store B refuses present-verify, check-svid, check-wimse, and act-accept for that issuer pin. Seal accept is issuer death for verify. Historical receipt verify may stay as audit. This store writes no instance record and does not copy issuer.secret. POST /act-export returns receipt, proof, and tree_head after a successful check, and POST /act-accept on a verifier host reuses Kernel act accept for those artifacts without copying the inode. POST /check-wimse on a verifier host allows an honest Workload Identity Token after present-verify without looking up the issuing inode, then refuses after kill accept. That allow still requires holder proof. Store B holder proof is a signature over a verifier nonce against the present holder public key. The holder secret does not live on the verifier. POST /verifier-challenge issues that nonce in this host process only. POST /sign-holder-nonce signs that nonce on the issuing host or the operator workstation and returns the signature only. Secret bytes are not returned. This store must already hold the matching local live instance. A verifier store with no instance is refused and does not open the typed path. A revoked local instance is refused and does not open the typed path. After issuer seal this sign is refused. Signing a nonce is holder-key use, not mint. Source of truth names seal refuse for mint, birth, spawn, present, check, and agent-type add. Source of truth was silent on that sign. This store refuses after seal to stay fail-closed. POST /check-svid on a verifier host uses the same allow-from-present path. A small operator page on that same loopback host is allowed so a person can test without the command line. A later full user interface has started on the same loopback host and still binds 127.0.0.1 only. GET / is the later user interface on the issuing store and still binds 127.0.0.1 only. GET /laboratory is the laboratory operator page. The laboratory public check name is check.prestigeworldwide.digital. That lock is a name only. A public listener is still refused until that name has a DNS address record and a single-name certificate. The later public listener is check only. Create Agent Principal, issuer.secret, holder secret paths, rotate, and seal stay on 127.0.0.1. www.prestigeworldwide.digital is not the check name. The apex prestigeworldwide.digital is not the check listener. The laboratory runtime is a consumer of the well-known document, not an issuer, not a directory.

## 5. Invariants that later work may not reverse

- Enforcement fails closed. There is no force-allow.
- Unknown does not mean live.
- After birth, a later instance file must not rebind the holder public key.
- Do not copy issuer secrets, biscuit secrets, holder secrets, or member-two secrets between stores.
- One kernel, restorable. Create Agent Principal has one birth authority. A second live issuer is a second identity kernel and is refused. Recovery is restore of that same issuer after the issuing computer is dead. Restore is not copying issuer.secret onto a live Store B. Laboratory cold restore with a backup is started. Restore is key plus ledger onto an empty issuing store after the old mint is dead. Member two is not in the backup. After restore at issuance threshold_n 2 the outside member is still required. Backup still excludes member two. Standing data-a stays n=2. After restore, WIMSE on-ramp still verifies against the original issuer pin. Restore is restore. Restore is disaster recovery of the same issuer. Restore is not a separate product. Self-healing after failure is internal diagnostics that run after restore and indicate whether restore succeeded and operation returned to normal. Those diagnostics do not invent issuer.secret and do not start a second issuer. Jason Gale locked this on 27 August 2026. Do not reverse one kernel, restorable. Jason Gale locked this on 26 August 2026.
- The laboratory member-two custody path is an outside file. That file may live on prometheus-member-two and be reached from the issuing computer as a typed path over the laboratory site-to-site tunnel. issuer.secret stays on the issuing computer. Member two is not a second store. A missing member-two secret path is refused. The kernel does not write issuer-member-*.secret under the data directory. Who holds member two in a later market stays open.
- Do not put instance identifiers into public key infrastructure names.
- Do not bind the check host to all interfaces.
- The laboratory public check name is check.prestigeworldwide.digital. A later public listener uses that name only. www.prestigeworldwide.digital is not the check name. The apex prestigeworldwide.digital is not the check listener.
- Do not treat short certificate life as kill.
- After issuer seal, mint, birth, spawn, present, check, agent-type add, sign-holder-nonce, challenge, rotate, member-two, set-verify-threshold, and set-issuer-threshold are refused. Challenge appends a signed issuance.log line. That write is not verify-only. Signing a nonce is holder-key use, not mint. Source of truth was silent on that sign. This store refuses after seal to stay fail-closed. Kill after seal is intended. Kill is death, not mint.
- After Store B accepts a previous issuer key and its kill date, a wrap or act signed only by that previous key after that kill date is refused on Store B. This is verifier state on the issuer record. This is not a sixth identity record. This is not a public transparency log.
- After Store B accepts a seal for a foreign issuer public key, present verify and act accept for that issuer pin are refused on Store B. Seal accept is verifier state on the issuer record. This is not a sixth identity record. This is not a public transparency log.
- Stolen issuer secret can still mint a present that Store B allows until Store B accepts that seal or a previous-key kill. After Store B accepts the seal, a stolen issuer secret is no longer enough. The stolen-issuer window is remaining life until Store B accepts seal or a previous-key kill. After Store B accepts the seal, a stolen issuer secret is no longer enough. This is not a kernel leftover to invent a close. A later market may require seal-accept on each verifier that pinned that issuer before issuer Decommission is complete. The operator carries the seal bundle. The kernel does not push it. This laboratory does not start a public transparency log. Jason Gale locked this on 26 August 2026.
- GET / is the later user interface on the issuing store and still binds 127.0.0.1 only. GET /laboratory is the laboratory operator page.
- GET /.well-known/prometheus-check on a public check-only host names check paths and allowed operator pins. That public document omits write and export verbs.
- GET /.well-known/prometheus-check is the well-known check path in the laboratory and in a later market. That path is a protocol constant. A later market may name the host and may later lock a product word for Check. A later market does not rename this path. Check keeps the laboratory name until Jason Gale locks a new word.
- SPIRE starts only as a consumer, and only when a real mesh or runtime will not call loopback /check-svid or https://check.prestigeworldwide.digital. Do not start SPIRE until that condition is true.
- Do not plan the human identity provider replacement in this tree.

A later identity record, SPIRE as a consumer, and a secrets provider may start only when the conditions in VISION.md section 7 are true. WIMSE HTTP token plus Content-Digest has started as an on-ramp artifact. Those start conditions are direction. The invariants in this section stay locked after those additions start.

## 6. What is decided about success

On 20 August 2026 a visible walk answered five questions yes. See JUDGE.md. See JUDGE-NON-CLI.md for what a person can prove without the command line.

1. Birth writes the instance, the first capability, and death in one persist.
2. A second party can verify an act without copying the inode.
3. Death can travel to that second party and refuse a later present.
4. A runtime can consume that present without becoming a directory.
5. A stolen or resigned wrap fails closed after kill.

The kernel is testable. This page does not say the bet is won. Jason Gale decides whether this agent identity is worth pursuing.

## 7. What is not source of truth

VISION.md is the completion ladder and the start conditions. That page may move as rungs close.

ANATOMY.md open items, parked leftovers, and research briefs are not product locks.

A weekday pulse, a demonstration script, and a see-walk directory are evidence. They are not locks.

## 8. How a lock changes

Jason Gale changes a lock on this page in ordinary sentences. PolicyLab-2 does not silently reverse a lock to ship a feature.

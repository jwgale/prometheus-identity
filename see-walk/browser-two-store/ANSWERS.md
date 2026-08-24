# Prometheus two-store loopback answers

Date: 20 August 2026.

This page is for Jason Gale. This package is laboratory code under PolicyLab-2. This package is not Sanctum. This package is not a Cyera product.

This document uses ASD-STE100 Simplified Technical English. Technical names appear in full words.

The visible walk lives in `see-walk/browser-two-store`. The two stores lived under `/tmp/prometheus-browser-two-store-a` and `/tmp/prometheus-browser-two-store-b`. That walk directory holds public artifacts only. It does not hold `issuer.secret`, `biscuit.secret`, holder secrets, or member-two secrets.

Store A listened on `127.0.0.1:18765` only. Store B listened on `127.0.0.1:18766` only. Both hosts are stopped.

Init used the command line once for each store. The rest of the walk used HTTP against the loopback hosts.

Store B never received a holder secret path. The sequence was Store B POST /verifier-challenge, then Store A POST /sign-holder-nonce with the nonce and the local holder secret path, then Store B POST /check-svid with the nonce and the holder signature.

## What each HTTP call returned

All paths below sit under `see-walk/browser-two-store` unless the line names a `/tmp` store file.

1. GET `http://127.0.0.1:18765/health` returned HTTP 200. File: `a-health.json`.
2. GET `http://127.0.0.1:18766/health` returned HTTP 200. File: `b-health.json`.
3. POST `/agent-type` on store A returned HTTP 200. Agent type identifier `01M0FVF410E04PXSSSN7W9S853`. Allowed intent `read`. File: `a-agent-type.json`.
4. POST `/birth` on store A returned HTTP 200. Instance identifier `01M0FVF417VJBS4CP2JX374VMG`. Capability identifier `01M0FVF418W3GFJGTYQCKKN8C8`. The response named a holder secret path only. Secret bytes were not returned. File: `a-birth.json`.
5. POST `/challenge` on store A for present returned HTTP 200. File: `a-challenge-present.json`.
6. POST `/present-svid` on store A returned HTTP 200. The body held `presentation_json` and `certificate_pem`. Files: `a-present-svid.json`, `presentation.json`, `presentation.json.svid.pem`.
7. POST `/challenge` on store A for check returned HTTP 200. Present spends the first nonce. File: `a-challenge-check.json`.
8. POST `/check-svid` on store A returned HTTP 200. Result `allowed`. Intent `read`. Audience `internal`. The body held a signed receipt. Files: `a-check-svid-allow.json`, `check-svid-allowed-summary.json`.
9. POST `/act-export` on store A returned HTTP 200. The body held `receipt`, `proof`, and `tree_head`. File: `a-act-export.json`.
10. GET `/instances` on store B before accept returned HTTP 200. Body `{"instances":[]}`. File: `b-instances-before.json`.
11. GET `/issuer-public` on store A returned HTTP 200. Full public key hex is 3904 characters. File: `a-issuer-public.json`, `a-issuer-public-key.hex`.
12. POST `/issuer-accept` on store B returned HTTP 200. The body returned the same 3904-character public key hex. File: `b-issuer-accept.json`.
13. POST `/verifier-challenge` on store B returned HTTP 200. The body held `challenge_nonce` and `challenge_message`. The message is `prometheus-verifier-challenge|{nonce}`. This store wrote no instance. File: `b-verifier-challenge.json`.
14. POST `/sign-holder-nonce` on store A returned HTTP 200. The body held `holder_proof` only. Secret bytes were not returned. File: `a-sign-holder-nonce.json`.
15. POST `/sign-holder-nonce` on store B with the issuing holder secret path returned HTTP 403. Reason: this store has no matching local instance. Store B did not open that path as a signer. File: `b-sign-holder-nonce-refuse.json`.
16. POST `/check-svid` on store B of the honest wrap returned HTTP 200. Result `allowed`. Intent `read`. Audience `internal`. The request body held the nonce and the holder signature. The request body did not hold `holder_secret_path`. The body did not hold a new decision receipt. Store B did not look up the issuing inode. Files: `b-check-svid-allow.json`, `b-check-svid-allow-summary.json`, `b-check-svid-request-keys.json`.
17. GET `/instances` on store B after the honest allow returned HTTP 200. Body `{"instances":[]}`. File: `b-instances-after-allow.json`.
18. POST `/act-export` on store B with an empty body returned HTTP 400. Reason: missing field `receipt`. File: `b-act-export-empty.json`.
19. POST `/act-export` on store B with the store A receipt returned HTTP 403. Reason: the issuance-log line is not present in this store log. Store B did not mint a receipt, a log line, or a tree head. File: `b-act-export-foreign.json`.
20. POST `/act-accept` on store B returned HTTP 200. Body `{"result":"accepted"}`. File: `b-act-accept.json`.
21. GET `/instances` on store B after act-accept returned HTTP 200. Body `{"instances":[]}`. Store B wrote no instance record. File: `b-instances-after-act.json`.
22. POST `/kill` on store A returned HTTP 200. Status `revoked`. File: `a-kill.json`.
23. POST `/sign-holder-nonce` on store A after local kill returned HTTP 403. Reason: this store's own records say this instance is revoked. File: `a-sign-holder-nonce-after-kill.json`.
24. POST `/kill-export` on store A returned HTTP 200. The body held `event`, `proof`, and `tree_head`. File: `a-kill-export.json`.
25. POST `/kill-accept` on store B returned HTTP 200. Accepted killed instance identifier `01M0FVF417VJBS4CP2JX374VMG`. File: `b-kill-accept.json`.
26. POST `/check-svid` on store B of the historical wrap returned HTTP 403. Result `refused`. Reason: this store accepted a kill for this instance. Death wins. Files: `b-check-svid-after-kill.json`, `b-check-svid-after-kill-summary.json`.
27. POST `/check-svid` on store A of the historical wrap returned HTTP 403. Result `refused`. Reason: this store's own records say this instance is revoked. File: `a-check-svid-after-kill.json`.
28. GET `/instances` on store B after kill-accept returned HTTP 200. Body `{"instances":[]}`. File: `b-instances-after-kill.json`.
29. GET `/instances` on store A after kill returned HTTP 200. The instance status is `revoked`. File: `a-instances-after-kill.json`.

## Whether the walk succeeded

All HTTP steps succeeded. Honest check on store B returned 200 allowed. Death refuse returned 403. The refuse named kill accept, not expiry and not a missing inode. Store B stayed empty of instance records. Store B did not copy `issuer.secret`. Store B did not receive or read a holder secret path for the allow. Store B POST /act-export after that allow refused. Store B did not become a second issuer.

## Hole that was locked

POST /sign-holder-nonce on a live local instance used to sign after local kill. The kernel now refuses that sign and does not open the typed path. The kernel test `sign_holder_nonce_for_a_revoked_local_instance_is_refused` fails before that lock.

POST /sign-holder-nonce after issuer seal used to sign. Source of truth names seal refuse for mint, birth, spawn, present, check, and agent-type add. Signing a nonce is holder-key use, not mint. Source of truth was silent on that sign. This store refuses after seal to stay fail-closed. The kernel test `sign_holder_nonce_after_issuer_seal_is_refused` fails before that lock.

A path that is not this instance holder secret was already refused. No new test.

Store B POST /act-export after allow-from-present already refused. No new test. No lock.

## Blocked work

A first start of store B with `cargo run --release -- host` was delayed once by Auto-review target change. The same host started on retry. No `scripts/*.sh` file was executed. No `python3 -c` command was used for the walk. No `target/release/prometheus host` command was used.

# Prometheus two-store loopback WIMSE answers

Date: 20 August 2026.

This page is for Jason Gale. This package is laboratory code under PolicyLab-2. This package is not Sanctum. This package is not a Cyera product.

This document uses ASD-STE100 Simplified Technical English. Technical names appear in full words.

The visible walk lives in `see-walk/wimse-two-store`. The two stores lived under `/tmp/prometheus-wimse-two-store-a` and `/tmp/prometheus-wimse-two-store-b`. That walk directory holds public artifacts only. It does not hold `issuer.secret`, `biscuit.secret`, holder secrets, or member-two secrets.

Store A listened on `127.0.0.1:18767` only. Store B listened on `127.0.0.1:18768` only. Both hosts are stopped.

Init used the command line once for each store. The rest of the walk used HTTP against the loopback hosts.

Store B never received a holder secret path. The sequence was Store B POST /verifier-challenge, then Store A POST /sign-holder-nonce with the nonce and the local holder secret path, then Store B POST /check-wimse with the nonce and the holder signature.

## What each HTTP call returned

All paths below sit under `see-walk/wimse-two-store` unless the line names a `/tmp` store file.

1. GET `http://127.0.0.1:18767/health` returned HTTP 200. File: `a-health.json`.
2. GET `http://127.0.0.1:18768/health` returned HTTP 200. File: `b-health.json`.
3. GET `http://127.0.0.1:18767/.well-known/prometheus-check` returned HTTP 200. The document names POST /check-svid, POST /check-wimse, and POST /verifier-challenge. The document says a Store B check needs a holder signature over that nonce. File: `a-well-known.json`.
4. GET `/instances` on store B before accept returned HTTP 200. Body `{"instances":[]}`. File: `b-instances-before.json`.
5. POST `/agent-type` on store A returned HTTP 200. Agent type identifier `01M0FTTGFWMFXSEVC6Y727VSK6`. Allowed intent `read`. File: `a-agent-type.json`.
6. POST `/birth` on store A returned HTTP 200. Instance identifier `01M0FTTGG46MS29SYXNJ2KWMX3`. Capability identifier `01M0FTTGG506TRFX6ZAEHF50AJ`. The response named a holder secret path only. Secret bytes were not returned. File: `a-birth.json`.
7. POST `/challenge` on store A for present returned HTTP 200. File: `a-challenge-present.json`.
8. POST `/present-wimse` on store A returned HTTP 200. The body held `presentation_json`, `workload_identity_token`, `content_digest`, `signature_input`, and `signature`. The HTTP Message Signature covers `@method` and `@request-target`. File: `a-present-wimse.json`.
9. GET `/issuer-public` on store A returned HTTP 200. Full public key hex is 3904 characters. That truncated GET /status key is not enough for issuer-accept. File: `a-issuer-public.json`, `a-issuer-public-key.hex`.
10. POST `/issuer-accept` on store B returned HTTP 200. The body returned the same 3904-character public key hex. File: `b-issuer-accept.json`.
11. POST `/verifier-challenge` on store B returned HTTP 200. The body held `challenge_nonce` and `challenge_message`. The message is `prometheus-verifier-challenge|{nonce}`. This store wrote no instance. File: `b-verifier-challenge.json`.
12. POST `/sign-holder-nonce` on store A returned HTTP 200. The body held `holder_proof` only. Secret bytes were not returned. File: `a-sign-holder-nonce.json`.
13. POST `/sign-holder-nonce` on store B with the issuing holder secret path returned HTTP 403. Reason: this store has no matching local instance. Store B did not open that path as a signer. File: `b-sign-holder-nonce-refuse.json`.
14. POST `/check-wimse` on store B of the honest present returned HTTP 200. Result `allowed`. Intent `read`. Audience `internal`. The request body held the nonce and the holder signature. The request body did not hold `holder_secret_path`. The body did not hold a new decision receipt. Store B did not look up the issuing inode. Files: `b-check-wimse-allow.json`, `b-check-wimse-allow-summary.json`, `b-check-wimse-request-keys.json`.
15. GET `/instances` on store B after the honest allow returned HTTP 200. Body `{"instances":[]}`. File: `b-instances-after-allow.json`.
16. POST `/kill` on store A returned HTTP 200. Status `revoked`. File: `a-kill.json`.
17. POST `/kill-export` on store A returned HTTP 200. The body held `event`, `proof`, and `tree_head`. File: `a-kill-export.json`.
18. POST `/kill-accept` on store B returned HTTP 200. Accepted killed instance identifier `01M0FTTGG46MS29SYXNJ2KWMX3`. File: `b-kill-accept.json`.
19. POST `/check-wimse` on store B of the historical present returned HTTP 403. Result `refused`. Reason: this store accepted a kill for this instance. Death wins. Files: `b-check-wimse-after-kill.json`, `b-check-wimse-after-kill-summary.json`.
20. GET `/instances` on store B after kill-accept returned HTTP 200. Body `{"instances":[]}`. File: `b-instances-after-kill.json`.
21. GET `/instances` on store A after kill returned HTTP 200. The instance status is `revoked`. File: `a-instances-after-kill.json`.

## Whether the walk succeeded

All HTTP steps succeeded. Honest check on store B returned 200 allowed. Death refuse returned 403. The refuse named kill accept, not expiry and not a missing inode. Store B stayed empty of instance records. Store B did not copy `issuer.secret`. Store B did not receive or read a holder secret path for the allow.

## Hole that was locked

POST /sign-holder-nonce on a verifier store with no matching local instance used to open the typed path and return a holder signature. An operator could drop a holder secret onto Store B and sign there. The kernel now refuses that sign and does not open the typed path. The host test `store_b_sign_holder_nonce_is_refused_when_this_store_has_no_instance` and the kernel test `sign_holder_nonce_on_a_verifier_store_with_no_instance_is_refused` fail before that lock.

A spent verifier nonce still refuses. That refuse already existed. No new test.

The verifier nonce is not bound to a present hash. Birth and spawn always write a new holder key. First-binder refuses a later rebind. Two live presents cannot share a holder public key by construction. No present-hash bind.

## Blocked work

A first start of store B with `cargo run --release -- host` was delayed once by Auto-review target change. The same host started on retry. No `scripts/*.sh` file was executed. No `python3 -c` command was used for the walk. No `target/release/prometheus host` command was used.

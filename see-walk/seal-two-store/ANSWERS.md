# Prometheus two-store loopback seal answers

Date: 20 August 2026.

This page is for Jason Gale. This package is laboratory code under PolicyLab-2. This package is not Sanctum. This package is not a Cyera product.

This document uses ASD-STE100 Simplified Technical English. Technical names appear in full words.

The visible walk lives in `see-walk/seal-two-store`. The two stores lived under `/tmp/prometheus-seal-two-store-a` and `/tmp/prometheus-seal-two-store-b`. That walk directory holds public artifacts only. It does not hold `issuer.secret`, `biscuit.secret`, holder secrets, or member-two secrets.

Store A listened on `127.0.0.1:18769` only. Store B listened on `127.0.0.1:18770` only. Both hosts are stopped.

Init used the command line once for each store. The rest of the walk used HTTP against the loopback hosts.

Store B never received a holder secret path. The sequence was Store B POST /verifier-challenge, then Store A POST /sign-holder-nonce with the nonce and the local holder secret path, then Store B POST /check-wimse with the nonce and the holder signature.

## What each HTTP call returned

All paths below sit under `see-walk/seal-two-store` unless the line names a `/tmp` store file.

1. GET `http://127.0.0.1:18769/health` returned HTTP 200. File: `a-health.json`.
2. GET `http://127.0.0.1:18770/health` returned HTTP 200. File: `b-health.json`.
3. GET `http://127.0.0.1:18769/.well-known/prometheus-check` returned HTTP 200. The document names POST /check-svid, POST /check-wimse, and POST /verifier-challenge. The document names POST /seal-export and POST /seal-accept as operator pin paths. The document says a Store B check needs a holder signature over that nonce. File: `a-well-known.json`.
4. GET `/instances` on store B before accept returned HTTP 200. Body `{"instances":[]}`. File: `b-instances-before.json`.
5. POST `/agent-type` on store A returned HTTP 200. Agent type identifier `01M0FYC2S5MPDN3M6JRPXTBG17`. Allowed intent `read`. File: `a-agent-type.json`.
6. POST `/birth` on store A returned HTTP 200. Instance identifier `01M0FYC2SDBVE4Q7WXMX606TV1`. Capability identifier `01M0FYC2SE24C8HZ8BH54BF5BY`. The response named a holder secret path only. Secret bytes were not returned. File: `a-birth.json`.
7. POST `/challenge` on store A for present returned HTTP 200. File: `a-challenge-present.json`.
8. POST `/present-wimse` on store A returned HTTP 200. The body held `presentation_json`, `workload_identity_token`, `content_digest`, `signature_input`, and `signature`. The HTTP Message Signature covers `@method`, `@request-target`, and `content-digest`. File: `a-present-wimse.json`.
9. GET `/issuer-public` on store A returned HTTP 200. Full public key hex is 3904 characters. That truncated GET /status key is not enough for issuer-accept. File: `a-issuer-public.json`, `a-issuer-public-key.hex`.
10. POST `/issuer-accept` on store B returned HTTP 200. The body returned the same 3904-character public key hex. File: `b-issuer-accept.json`.
11. POST `/verifier-challenge` on store B returned HTTP 200. The body held `challenge_nonce` and `challenge_message`. The message is `prometheus-verifier-challenge|{nonce}`. This store wrote no instance. File: `b-verifier-challenge.json`.
12. POST `/sign-holder-nonce` on store A returned HTTP 200. The body held `holder_proof` only. Secret bytes were not returned. File: `a-sign-holder-nonce.json`.
13. POST `/check-wimse` on store B of the honest present returned HTTP 200. Result `allowed`. Intent `read`. Audience `internal`. The request body held the nonce and the holder signature. The request body did not hold `holder_secret_path`. The HTTP Message Signature covers `@method`, `@request-target`, and `content-digest`. Store B did not look up the issuing inode. Files: `b-check-wimse-allow.json`, `b-check-wimse-allow-summary.json`, `b-check-wimse-request-keys.json`.
14. GET `/instances` on store B after the honest allow returned HTTP 200. Body `{"instances":[]}`. File: `b-instances-after-allow.json`.
15. POST `/seal` on store A with confirm `seal` and `after_seconds` 3600 returned HTTP 200. Status `sealed`. Kill date `2026-08-20T17:00:02Z` (12:00 CT). File: `a-seal.json`.
16. POST `/sign-holder-nonce` on store A after local seal returned HTTP 200. Remaining life had not been reached. The existing kernel lock refuses this sign after remaining life. File: `a-sign-holder-nonce-after-seal.json`.
17. POST `/seal-export` on store A returned HTTP 200. The body held `event`, `proof`, and `tree_head`. File: `a-seal-export.json`.
18. POST `/seal-accept` on store B returned HTTP 200. The body held the same 3904-character public key hex and the same kill date. File: `b-seal-accept.json`.
19. GET `/instances` on store B after seal-accept returned HTTP 200. Body `{"instances":[]}`. File: `b-instances-after-seal.json`.
20. POST `/check-wimse` on store B of the historical present returned HTTP 403. Result `refused`. Reason: this store accepted a seal for this issuer public key. Seal accept is issuer death for verify. Files: `b-check-wimse-after-seal.json`, `b-check-wimse-after-seal-summary.json`.
21. GET `/instances` on store A after seal returned HTTP 200. The instance status is `live`. Remaining life had not been reached. File: `a-instances-after-seal.json`.

## Whether the walk succeeded

All required HTTP steps succeeded. Honest check on store B returned 200 allowed. Seal-accept refuse returned 403. The refuse named accepted seal, not expiry and not a missing inode. Store B stayed empty of instance records. Store B did not copy `issuer.secret`. Store B did not receive or read a holder secret path for the allow.

A first POST /check-wimse construction used a shell substitution that dropped a trailing newline from the present bytes. Store B refused that swapped body. The walk rebuilt the request from the present JSON so the present bytes stayed exact. That refuse was operator construction. That refuse was not a host hole.

## Hole that was locked

Store B did not still allow after seal-accept. No new failing-first test.

POST /sign-holder-nonce on store A after local seal still signed because remaining life had not been reached. The kernel test `sign_holder_nonce_after_issuer_seal_is_refused` already locks refuse after remaining life. No new test.

## Blocked work

A first start of store B with `cargo run --release -- host` was delayed once by Auto-review target change. The same host started on retry. No `scripts/*.sh` file was executed. No `python3 -c` command was used for the walk. No `target/release/prometheus host` command was used.

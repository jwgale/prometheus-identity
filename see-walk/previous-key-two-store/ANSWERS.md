# Prometheus two-store loopback previous-key answers

Date: 20 August 2026.

This page is for Jason Gale. This package is laboratory code under PolicyLab-2. This package is not Sanctum. This package is not a Cyera product.

This document uses ASD-STE100 Simplified Technical English. Technical names appear in full words.

The visible walk lives in `see-walk/previous-key-two-store`. The two stores lived under `/tmp/prometheus-previous-key-two-store-a` and `/tmp/prometheus-previous-key-two-store-b`. That walk directory holds public artifacts only. It does not hold `issuer.secret`, `biscuit.secret`, holder secrets, or member-two secrets.

Store A listened on `127.0.0.1:18771` only. Store B listened on `127.0.0.1:18772` only. Both hosts are stopped.

Init used the command line once for each store. Rotate stayed on the command line. The rest of the walk used HTTP against the loopback hosts.

Store B never received a holder secret path. The sequence was Store B POST /verifier-challenge, then Store A POST /sign-holder-nonce with the nonce and the local holder secret path, then Store B POST /check-wimse with the nonce and the holder signature.

## What each HTTP call returned

All paths below sit under `see-walk/previous-key-two-store` unless the line names a `/tmp` store file.

1. GET `http://127.0.0.1:18771/health` returned HTTP 200. File: `a-health.json`.
2. GET `http://127.0.0.1:18772/health` returned HTTP 200. File: `b-health.json`.
3. GET `http://127.0.0.1:18771/.well-known/prometheus-check` returned HTTP 200. The document names POST /check-svid, POST /check-wimse, and POST /verifier-challenge. The document names POST /previous-key-export and POST /previous-key-accept as operator pin paths. The document says a Store B check needs a holder signature over that nonce. File: `a-well-known.json`.
4. GET `/instances` on store B before accept returned HTTP 200. Body `{"instances":[]}`. File: `b-instances-before.json`.
5. POST `/agent-type` on store A returned HTTP 200. Agent type identifier `01M0FZ5J9WXFM4CKYRHGBX3RCK`. Allowed intent `read`. File: `a-agent-type.json`.
6. POST `/birth` on store A returned HTTP 200. Instance identifier `01M0FZ5JA3TZSA1G8EP1X636AX`. Capability identifier `01M0FZ5JA4JKPV0SPBV0PAY7TM`. The response named a holder secret path only. Secret bytes were not returned. File: `a-birth.json`.
7. POST `/challenge` on store A for present returned HTTP 200. File: `a-challenge-present.json`.
8. POST `/present-wimse` on store A returned HTTP 200. The body held `presentation_json`, `workload_identity_token`, `content_digest`, `signature_input`, and `signature`. The HTTP Message Signature covers `@method`, `@request-target`, and `content-digest`. This present was signed by the old issuer key before rotate. File: `a-present-wimse.json`.
9. GET `/issuer-public` on store A returned HTTP 200. Full public key hex is 3904 characters. That truncated GET /status key is not enough for issuer-accept. File: `a-issuer-public.json`, `a-issuer-public-key.hex`.
10. POST `/issuer-accept` on store B returned HTTP 200. The body returned the same 3904-character public key hex. File: `b-issuer-accept.json`.
11. POST `/verifier-challenge` on store B returned HTTP 200. The body held `challenge_nonce` and `challenge_message`. The message is `prometheus-verifier-challenge|{nonce}`. This store wrote no instance. File: `b-verifier-challenge.json`.
12. POST `/sign-holder-nonce` on store A returned HTTP 200. The body held `holder_proof` only. Secret bytes were not returned. File: `a-sign-holder-nonce.json`.
13. POST `/check-wimse` on store B of the honest present returned HTTP 200. Result `allowed`. Intent `read`. Audience `internal`. The request body held the nonce and the holder signature. The request body did not hold `holder_secret_path`. The HTTP Message Signature covers `@method`, `@request-target`, and `content-digest`. Store B did not look up the issuing inode. Files: `b-check-wimse-allow.json`, `b-check-wimse-allow-summary.json`, `b-check-wimse-request-keys.json`.
14. GET `/instances` on store B after the honest allow returned HTTP 200. Body `{"instances":[]}`. File: `b-instances-after-allow.json`.
15. Command-line `issuer rotate --kill-after-seconds 15` on store A succeeded. The previous public key matches the old GET /issuer-public key. The current public key differs. Previous-key kill date `2026-08-20T16:13:48Z` (11:13 CT). File: `a-rotate-summary.json`.
16. POST `/previous-key-export` on store A returned HTTP 200. The body held `public_key_hex` and `kill_date` only. The public key hex is 3904 characters. The public key matches the old issuer key. File: `a-previous-key-export.json`, `previous-key-export-keys.json`.
17. POST `/previous-key-accept` on store B returned HTTP 200. The body held the same 3904-character public key hex and the same kill date. File: `b-previous-key-accept.json`.
18. GET `/instances` on store B after previous-key-accept returned HTTP 200. Body `{"instances":[]}`. File: `b-instances-after-accept.json`.
19. POST `/verifier-challenge` on store B after the kill date returned HTTP 200. File: `b-verifier-challenge-after.json`.
20. POST `/sign-holder-nonce` on store A after rotate returned HTTP 200. The body held `holder_proof` only. File: `a-sign-holder-nonce-after-rotate.json`.
21. POST `/check-wimse` on store B of the historical present after previous-key accept and after the kill date returned HTTP 403. Result `refused`. Reason: the previous issuer key is past its kill date. A present signed only by that previous key is refused. Files: `b-check-wimse-after-previous-key.json`, `b-check-wimse-after-previous-key-summary.json`.
22. GET `/instances` on store B after the refuse returned HTTP 200. Body `{"instances":[]}`. File: `b-instances-after-previous-key.json`.
23. GET `/instances` on store A after rotate returned HTTP 200. The instance status is `live`. File: `a-instances-after-rotate.json`.

## Whether the walk succeeded

All required HTTP steps succeeded. Honest check on store B returned 200 allowed. Previous-key refuse returned 403. The refuse named the previous issuer key past its kill date, not expiry and not a missing inode. Store B stayed empty of instance records. Store B did not copy `issuer.secret`. The store A issuer.secret digest and the store B issuer.secret digest differ. Store B did not receive or read a holder secret path for the allow.

## Hole that was locked

Store B did not still allow after previous-key accept past the kill date. No new failing-first test.

The host test `store_b_allows_a_present_on_the_old_key_before_previous_key_accept_and_refuses_after` already proves allow then refuse. This walk documents that same path on two loopback hosts with present-wimse.

## Blocked work

A first start of store B with `cargo run --release -- host` was delayed once by Auto-review target change. The same host started on retry. No `scripts/*.sh` file was executed. No `python3 -c` command was used for the walk. No `target/release/prometheus host` command was used.

# Prometheus two-store loopback issuance-threshold birth answers

Date: 20 August 2026.

This page is for Jason Gale. This package is laboratory code under PolicyLab-2. This package is not Sanctum. This package is not a Cyera product.

This document uses ASD-STE100 Simplified Technical English. Technical names appear in full words.

The visible walk lives in `see-walk/threshold-two-store`. The two stores lived under `/tmp/prometheus-threshold-two-store-a` and `/tmp/prometheus-threshold-two-store-b`. The outside member lived under `/tmp/prometheus-threshold-two-store-custody/member-two.secret`. That walk directory holds public artifacts only. It does not hold `issuer.secret`, `biscuit.secret`, holder secrets, or member-two secrets.

Store A listened on `127.0.0.1:18773` only. Store B listened on `127.0.0.1:18774` only. Both hosts are stopped.

Init used the command line once for each store. The rest of the walk used HTTP against the loopback hosts.

Store B never received a holder secret path. The sequence was Store B POST /verifier-challenge, then Store A POST /sign-holder-nonce with the nonce and the local holder secret path, then Store B POST /check-wimse with the nonce and the holder signature.

Who holds member two in a later market stays open. This laboratory used an outside file path. Store B did not receive that path.

## What each HTTP call returned

All paths below sit under `see-walk/threshold-two-store` unless the line names a `/tmp` store file.

1. GET `http://127.0.0.1:18773/health` returned HTTP 200. File: `a-health.json`.
2. GET `http://127.0.0.1:18774/health` returned HTTP 200. File: `b-health.json`.
3. GET `http://127.0.0.1:18773/.well-known/prometheus-check` returned HTTP 200. The document names POST /check-svid, POST /check-wimse, and POST /verifier-challenge. The document says a Store B check needs a holder signature over that nonce. File: `a-well-known.json`.
4. GET `/instances` on store B before accept returned HTTP 200. Body `{"instances":[]}`. File: `b-instances-before.json`.
5. POST `/member-two` on store A returned HTTP 200. The body held `public_key_hex` only. The host wrote the member secret at `/tmp/prometheus-threshold-two-store-custody/member-two.secret`. Secret bytes were not returned. File: `a-member-two.json`.
6. POST `/set-issuer-threshold` on store A with confirm `issuer-threshold` returned HTTP 200. Body `{"threshold_n":2}`. File: `a-set-issuer-threshold.json`.
7. POST `/set-verify-threshold` on store A with confirm `verify-threshold` returned HTTP 200. Body `{"verify_threshold_n":2}`. File: `a-set-verify-threshold.json`. Store B stayed at verify_threshold_n 1. Store B uses verify_threshold_n, not Store B issuance threshold.
8. POST `/agent-type` on store A after that raise returned HTTP 200. Agent type identifier `01M0G1E6RK9CMQ57WRRN8VWBA8`. Allowed intent `read`. File: `a-agent-type.json`.
9. POST `/birth` on store A without `member_secret_path` returned HTTP 403. Result `refused`. Reason: after issuance threshold_n is 2, the birth path requires member_secret_path on the live host body. File: `a-birth-without-member.json`.
10. POST `/birth` on store A with the outside member secret path returned HTTP 200. Instance identifier `01M0G1E6S3H4FWWFBQ6MP95YEW`. Capability identifier `01M0G1E6S5HC601MQQ37E883SG`. The response named a holder secret path only. Secret bytes were not returned. File: `a-birth.json`.
11. POST `/challenge` on store A for present returned HTTP 200. File: `a-challenge-present.json`.
12. POST `/present-wimse` on store A returned HTTP 200. The body held `presentation_json`, `workload_identity_token`, `content_digest`, `signature_input`, and `signature`. The HTTP Message Signature covers `@method`, `@request-target`, and `content-digest`. File: `a-present-wimse.json`.
13. GET `/issuer-public` on store A returned HTTP 200. Full public key hex is 3904 characters. That truncated GET /status key is not enough for issuer-accept. File: `a-issuer-public.json`, `a-issuer-public-key.hex`.
14. POST `/issuer-accept` on store B returned HTTP 200. The body returned the same 3904-character public key hex. File: `b-issuer-accept.json`.
15. POST `/verifier-challenge` on store B returned HTTP 200. The body held `challenge_nonce` and `challenge_message`. The message is `prometheus-verifier-challenge|{nonce}`. This store wrote no instance. File: `b-verifier-challenge.json`.
16. POST `/sign-holder-nonce` on store A returned HTTP 200. The body held `holder_proof` only. Secret bytes were not returned. File: `a-sign-holder-nonce.json`.
17. POST `/check-wimse` on store B of the honest present returned HTTP 200. Result `allowed`. Intent `read`. Audience `internal`. The request body held the nonce and the holder signature. The request body did not hold `holder_secret_path`. The HTTP Message Signature covers `@method`, `@request-target`, and `content-digest`. Store B did not look up the issuing inode. Files: `b-check-wimse-allow.json`, `b-check-wimse-allow-summary.json`, `b-check-wimse-request-keys.json`.
18. GET `/instances` on store B after the honest allow returned HTTP 200. Body `{"instances":[]}`. File: `b-instances-after-allow.json`.
19. GET `/instances` on store A after birth returned HTTP 200. The instance status is `live`. File: `a-instances-after.json`.

GET `/status` on store A after the walk showed threshold_n 2, verify_threshold_n 2, member_count 2, and one live instance. GET `/status` on store B showed threshold_n 1, verify_threshold_n 1, member_count 1, and zero instances. Files: `a-status-after.json`, `b-status-after.json`.

## Whether the walk succeeded

All required HTTP steps succeeded. Birth without the outside member on the live host returned 403 refused. Birth with that path returned 200. Honest check on store B returned 200 allowed. Store B stayed empty of instance records. Store B did not copy `issuer.secret`. The store A issuer.secret digest and the store B issuer.secret digest differ. Store B did not receive or read a holder secret path for the allow. Store B did not receive the outside member secret.

## Hole that was locked

POST /birth at issuance threshold_n 2 on the live host used to succeed without `member_secret_path` in the body. POST /member-two had already registered that outside path in the host process. A new process with only the data directory was already refused. The live host birth body now requires that path.

The host test `the_host_birth_path_at_issuance_threshold_two_refuses_without_the_outside_member_on_the_live_host` fails before that lock. The host test `the_host_birth_path_at_issuance_threshold_two_succeeds_with_the_outside_member` proves the allow with the outside path.

n=3 stays parked.

## Blocked work

A first start of store B with `cargo run --release -- host` was delayed once by Auto-review target change. The same host started on retry. A first `cargo test --lib` was delayed once the same way. The same test command passed on retry. No `scripts/*.sh` file was executed. No `python3 -c` command was used for the walk. No `target/release/prometheus host` command was used.

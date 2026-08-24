# Prometheus two-store later user interface answers

Date: 20 August 2026.

This page is for Jason Gale. This package is laboratory code under PolicyLab-2. This package is not Sanctum. This package is not a Cyera product.

This document uses ASD-STE100 Simplified Technical English. Technical names appear in full words.

The visible walk lives in `see-walk/later-ui-two-store`. The two stores lived under `/tmp/prometheus-later-ui-two-store-a` and `/tmp/prometheus-later-ui-two-store-b`. That walk directory holds public artifacts only. It does not hold `issuer.secret`, `biscuit.secret`, holder secrets, or member-two secrets.

Store A listened on `127.0.0.1:18775` only. Store B listened on `127.0.0.1:18776` only. Both hosts are stopped.

Init used the command line once for each store. The rest of the walk used HTTP against GET / on the loopback hosts. The laboratory operator page at GET /laboratory was not used.

Store B never received a holder secret path or a member secret path. The sequence was Store B POST /verifier-challenge with an empty JSON object, then Store A POST /sign-holder-nonce with the nonce and the local holder secret path, then Store B POST /check-svid with the nonce and the holder signature. Store B GET / check used an empty live-instance field. Store B did not invent an instance identifier.

## What each HTTP call returned

All paths below sit under `see-walk/later-ui-two-store` unless the line names a `/tmp` store file.

1. GET `http://127.0.0.1:18775/` returned HTTP 200. The page is the later user interface. The page names bind `127.0.0.1`. The page says this is not a public listener. The page says an empty live-instance field is correct. File: `a-get-root-proof.txt`.
2. GET `http://127.0.0.1:18776/` returned HTTP 200. The same later user interface. File: `b-get-root-proof.txt`.
3. GET `http://127.0.0.1:18775/health` returned HTTP 200. File: `a-health.json`.
4. GET `http://127.0.0.1:18776/health` returned HTTP 200. File: `b-health.json`.
5. GET `/instances` on store B before accept returned HTTP 200. Body `{"instances":[]}`. File: `b-instances-before.json`.
6. POST `/agent-type` on store A returned HTTP 200. Agent type identifier `01M0GMXGW2T4K8ST20H7QKW0D9`. Allowed intent `read`. File: `a-agent-type.json`.
7. POST `/birth` on store A returned HTTP 200. Instance identifier `01M0GMXGW37RP2V3MTWX9K34QY`. Capability identifier `01M0GMXGW35VWENEF2Q4WAQN1V`. The response named a holder secret path only. Secret bytes were not returned. File: `a-birth.json`.
8. POST `/challenge` on store A for present returned HTTP 200. File: `a-challenge-present.json`.
9. POST `/present-svid` on store A returned HTTP 200. The body held `presentation_json` and `certificate_pem`. Files: `a-present-svid.json`, `presentation.json`, `presentation.json.svid.pem`.
10. GET `/issuer-public` on store A returned HTTP 200. Full public key hex is 3904 characters. File: `a-issuer-public.json`, `a-issuer-public-key.hex`.
11. POST `/issuer-accept` on store B returned HTTP 200. The request body held `public_key_hex` only. File: `b-issuer-accept.json`, `b-issuer-accept-request-keys.json`.
12. POST `/verifier-challenge` on store B returned HTTP 200. The request body was `{}`. The response held `challenge_nonce` and `challenge_message`. This store wrote no instance. File: `b-verifier-challenge.json`, `b-verifier-challenge-request-keys.json`.
13. POST `/sign-holder-nonce` on store A returned HTTP 200. The body held `holder_proof` only. Secret bytes were not returned. File: `a-sign-holder-nonce.json`.
14. POST `/check-svid` on store B of the honest wrap returned HTTP 200. Result `allowed`. Intent `read`. Audience `internal`. The request body held the nonce and the holder signature. The request body did not hold `holder_secret_path`, `member_secret_path`, or `instance_id`. The body did not hold a new decision receipt. Store B did not look up the issuing inode. Files: `b-check-svid-allow.json`, `b-check-svid-allow-summary.json`, `b-check-svid-request-keys.json`.
15. GET `/instances` on store B after the honest allow returned HTTP 200. Body `{"instances":[]}`. File: `b-instances-after-allow.json`.
16. POST `/kill` on store A returned HTTP 200. Status `revoked`. File: `a-kill.json`.
17. POST `/kill-export` on store A returned HTTP 200. The body held `event`, `proof`, and `tree_head`. File: `a-kill-export.json`, `kill-export-keys.json`.
18. POST `/kill-accept` on store B returned HTTP 200. The request body held `event`, `proof`, and `tree_head` only. Accepted killed instance identifier `01M0GMXGW37RP2V3MTWX9K34QY`. File: `b-kill-accept.json`, `b-kill-accept-request-keys.json`.
19. POST `/check-svid` on store B of the same historical wrap returned HTTP 403. Result `refused`. Reason: this store accepted a kill for this instance. Death wins. Files: `b-check-svid-after-kill.json`, `b-check-svid-after-kill-summary.json`.
20. GET `/instances` on store B after kill-accept returned HTTP 200. Body `{"instances":[]}`. File: `b-instances-after-kill.json`. File: `b-no-inode.txt`.
21. GET `/instances` on store A after kill returned HTTP 200. The instance status is `revoked`. File: `a-instances-after-kill.json`.

## Whether the walk succeeded

All HTTP steps succeeded. Honest check on store B returned 200 allowed. Death refuse returned 403. The refuse named kill accept, not expiry and not a missing inode. Store B stayed empty of instance records. Store B did not copy `issuer.secret`. Store B did not receive a holder secret path or a member secret path. GET / Check on store B used an empty live-instance field. Both hosts bound `127.0.0.1` only.

## Hole that was locked

GET / Check used to send `holder_secret_path` as a JSON null, and it used to add `member_secret_path` whenever the issuing-store member field was filled. A verifier store with no live instance must not send those keys. The GET / script now omits `holder_secret_path` and `member_secret_path` when this store has no local live instance. The host tests `the_later_user_interface_script_checks_a_verifier_without_birth` and `the_later_user_interface_two_store_walk_allows_then_refuses_after_kill_accept` fail before that lock.

## Blocked work

No `scripts/*.sh` file was executed. No public bind. No SPIRE. No secrets provider. No sixth record. Issuer threshold n=3 stayed parked.

# Prometheus laboratory runtime act answers

Date: 21 August 2026.

This page is for Jason Gale. This package is laboratory code under PolicyLab-2. This package is not Sanctum. This package is not a Cyera product.

This document uses ASD-STE100 Simplified Technical English. Technical names appear in full words.

The visible walk lives in `see-walk/runtime-act`. The two stores lived under `/tmp/prometheus-runtime-act-a` and `/tmp/prometheus-runtime-act-b`. That walk directory holds public artifacts only. It does not hold `issuer.secret`, `biscuit.secret`, holder secrets, or member-two secrets.

Store A listened on `127.0.0.1:18777` only. Store B listened on `127.0.0.1:18778` only. Both hosts are stopped.

Init used the command line once for each store. Birth and present used the loopback host paths. The check used `prometheus runtime-check act`. That command is one process. File: `command-help.txt`.

Store B never received a holder secret path. The act process connected to Store B, followed GET `/.well-known/prometheus-check`, requested a verifier challenge, and posted the documented X.509-SVID check with a caller-supplied holder signature. Sign stayed on Store A at POST `/sign-holder-nonce`. Store B wrote no instance record.

## What each step returned

All paths below sit under `see-walk/runtime-act` unless the line names a `/tmp` store file.

1. GET `http://127.0.0.1:18777/health` returned HTTP 200. File: `a-health.json`.
2. GET `http://127.0.0.1:18778/health` returned HTTP 200. File: `b-health.json`.
3. GET `/.well-known/prometheus-check` on store A returned HTTP 200. The document names bind `127.0.0.1`, POST `/check-svid`, POST `/check-wimse`, and POST `/verifier-challenge`. File: `a-well-known.json`.
4. GET `/.well-known/prometheus-check` on store B returned HTTP 200. The same document. File: `b-well-known.json`.
5. GET `/instances` on store B before accept returned HTTP 200. Body `{"instances":[]}`. File: `b-instances-before.json`.
6. POST `/agent-type` on store A returned HTTP 200. Agent type identifier `01M0J90ERKSHPJ28YJKCZYCRN0`. Allowed intent `read`. File: `a-agent-type.json`.
7. POST `/birth` on store A returned HTTP 200. Instance identifier `01M0J90ESWKSY6MW8A0MT2E2V1`. Capability identifier `01M0J90ETDJZ7NCY564AW8JC0K`. The response named a holder secret path only. Secret bytes were not returned. File: `a-birth.json`.
8. POST `/challenge` on store A for present returned HTTP 200. File: `a-challenge-present.json`.
9. POST `/present-svid` on store A returned HTTP 200. The body held `presentation_json` and `certificate_pem`. Files: `a-present-svid.json`, `presentation.json`, `presentation.json.svid.pem`.
10. GET `/issuer-public` on store A returned HTTP 200. Full public key hex is 3904 characters. File: `a-issuer-public.json`, `a-issuer-public-key.hex`.
11. POST `/issuer-accept` on store B returned HTTP 200. The request body held `public_key_hex` only. File: `b-issuer-accept.json`, `b-issuer-accept-request-keys.json`.
12. `prometheus runtime-check act --base-url http://127.0.0.1:18778 --presentation-json presentation.json --certificate-pem presentation.json.svid.pem` returned exit 0. Result `allowed`. Intent `read`. Audience `internal`. The process requested a verifier challenge on store B. The holder signature came from store A POST `/sign-holder-nonce`. Store B did not receive a holder secret path. The documented check body keys are audience, certificate_pem, challenge_nonce, holder_proof, intent, on_behalf_of, and presentation_json. Files: `act-allow.json`, `act-allow-summary.json`, `act-allow.exit`, `act-request-keys.json`, `command-help.txt`.
13. GET `/instances` on store B after the honest allow returned HTTP 200. Body `{"instances":[]}`. File: `b-instances-after-allow.json`.
14. POST `/kill` on store A returned HTTP 200. Status `revoked`. File: `a-kill.json`.
15. POST `/kill-export` on store A returned HTTP 200. The body held `event`, `proof`, and `tree_head`. File: `a-kill-export.json`, `kill-export-keys.json`.
16. POST `/kill-accept` on store B returned HTTP 200. Accepted killed instance identifier `01M0J90ESWKSY6MW8A0MT2E2V1`. File: `b-kill-accept.json`, `b-kill-accept-request-keys.json`.
17. The same `prometheus runtime-check act` command on the historical present returned exit 1. Result `refused`. Reason: this store accepted a kill for this instance. Death wins. Files: `act-after-kill.json`, `act-after-kill-summary.json`, `act-after-kill.exit`.
18. GET `/instances` on store B after kill-accept returned HTTP 200. Body `{"instances":[]}`. File: `b-instances-after-kill.json`. File: `b-no-inode.txt`.
19. GET `/instances` on store A after kill returned HTTP 200. The instance status is `revoked`. File: `a-instances-after-kill.json`.

## Whether the walk succeeded

The documented command exists. Honest act on store B returned exit 0 and result allowed. Death refuse returned exit 1. The refuse named kill accept, not expiry and not a missing inode. Store B stayed empty of instance records. Store B did not copy `issuer.secret`. Store B did not receive a holder secret path. Both hosts bound `127.0.0.1` only. Both hosts are stopped.

## Hole that was locked

The laboratory runtime helper already completed the documented X.509-SVID check as a library call. The command line had no one-process verb. `prometheus runtime-check act` now connects, requests a verifier challenge, and posts the documented check. Exit 0 only on allowed. Any refuse or transport failure is non-zero. The tests `laboratory_runtime_act_allows_an_honest_svid_present` and `laboratory_runtime_act_refuses_after_kill_accept` fail before that lock.

## Blocked work

No `scripts/*.sh` file was executed. No public bind. No SPIRE. No secrets provider. No sixth record. Issuer threshold n=3 stayed parked. GET `/` was not restyled.

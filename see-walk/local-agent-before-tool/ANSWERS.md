# Prometheus local agent before-tool answers

Date: 22 August 2026.

This page is for Jason Gale. This package is laboratory code under PolicyLab-2. This package is not Sanctum. This package is not a Cyera product.

This document uses ASD-STE100 Simplified Technical English. Technical names appear in full words.

The visible walk lives in `see-walk/local-agent-before-tool`. The two stores lived under `/tmp/prometheus-local-agent-a` and `/tmp/prometheus-local-agent-b`. That walk directory holds public artifacts only. It does not hold `issuer.secret`, `biscuit.secret`, holder secrets, or member-two secrets.

Store A listened on `127.0.0.1:18780` only. Store B listened on `127.0.0.1:18781` only. Both hosts are stopped.

Init used the command line once for each store. Create Agent Principal used POST `/birth`. Assertion Act used POST `/present-svid`. The gate used `prometheus runtime-check before-tool`. That command is one process. File: `command-help.txt`.

Store B never received a holder secret path. The before-tool process connected to Store B, followed GET `/.well-known/prometheus-check`, requested a verifier challenge, and posted the documented X.509-SVID check with a caller-supplied holder signature. Sign stayed on Store A at POST `/sign-holder-nonce`. Store B wrote no instance record.

## What each step returned

All paths below sit under `see-walk/local-agent-before-tool` unless the line names a `/tmp` store file.

1. GET `http://127.0.0.1:18780/` returned HTTP 200. The page names Create Agent Principal, Assertion Act, and Decommission. Check stays Check. The page does not use `<h2>Birth</h2>` or `<h2>Death</h2>` as product headings. File: `get-root-proof.txt`.
2. GET `http://127.0.0.1:18780/health` returned HTTP 200. File: `a-health.json`.
3. GET `http://127.0.0.1:18781/health` returned HTTP 200. File: `b-health.json`.
4. GET `/.well-known/prometheus-check` on store A returned HTTP 200. The document names bind `127.0.0.1`, POST `/check-svid`, POST `/check-wimse`, and POST `/verifier-challenge`. File: `a-well-known.json`.
5. GET `/.well-known/prometheus-check` on store B returned HTTP 200. The same document. File: `b-well-known.json`.
6. GET `/instances` on store B before accept returned HTTP 200. Body `{"instances":[]}`. File: `b-instances-before.json`.
7. POST `/agent-type` on store A returned HTTP 200. Agent type identifier `01M0MV7PNY3YDQK2HZDXAKTDEZ`. Allowed intent `read`. File: `a-agent-type.json`.
8. POST `/birth` on store A returned HTTP 200. Instance identifier `01M0MV7PQBVR6XEPZWY8Q96D7P`. Capability identifier `01M0MV7PQR2X68GDFPV96P64K2`. The response named a holder secret path only. Secret bytes were not returned. File: `a-birth.json`.
9. POST `/challenge` on store A for the Assertion Act returned HTTP 200. File: `a-challenge-present.json`.
10. POST `/present-svid` on store A returned HTTP 200. The body held `presentation_json` and `certificate_pem`. Files: `a-present-svid.json`, `presentation.json`, `presentation.json.svid.pem`.
11. GET `/issuer-public` on store A returned HTTP 200. Full public key hex is 3904 characters. File: `a-issuer-public.json`, `a-issuer-public-key.hex`.
12. POST `/issuer-accept` on store B returned HTTP 200. The request body held `public_key_hex` only. File: `b-issuer-accept.json`, `b-issuer-accept-request-keys.json`.
13. `prometheus runtime-check before-tool --base-url http://127.0.0.1:18781 --presentation-json presentation.json --certificate-pem presentation.json.svid.pem --tool` wrote `ALLOWED` and exit 0. The tool wrote `TOOL_RAN`. The process requested a verifier challenge on store B. The holder signature came from store A POST `/sign-holder-nonce`. Store B did not receive a holder secret path. Files: `before-tool-allow.stdout`, `before-tool-allow.exit`, `before-tool-allow-summary.json`, `tool-allow.txt`, `command-help.txt`.
14. GET `/instances` on store B after the honest allow returned HTTP 200. Body `{"instances":[]}`. File: `b-instances-after-allow.json`.
15. POST `/kill` on store A returned HTTP 200. Status `revoked`. File: `a-kill.json`.
16. POST `/kill-export` on store A returned HTTP 200. The body held `event`, `proof`, and `tree_head`. File: `a-kill-export.json`, `kill-export-keys.json`.
17. POST `/kill-accept` on store B returned HTTP 200. Accepted killed instance identifier `01M0MV7PQBVR6XEPZWY8Q96D7P`. File: `b-kill-accept.json`, `b-kill-accept-request-keys.json`.
18. The same `prometheus runtime-check before-tool` command on the historical Assertion Act wrote `REFUSED` and exit 1. Reason: this store accepted a kill for this instance. Death wins. The tool file `tool-after-refuse.txt` is missing. Files: `before-tool-after-decommission.stdout`, `before-tool-after-decommission.stderr`, `before-tool-after-decommission.exit`, `before-tool-after-decommission-summary.json`, `tool-after-refuse.missing`.
19. GET `/instances` on store B after kill-accept returned HTTP 200. Body `{"instances":[]}`. File: `b-instances-after-kill.json`. File: `b-no-inode.txt`.
20. GET `/instances` on store A after kill returned HTTP 200. The instance status is `revoked`. File: `a-instances-after-kill.json`.

## Whether the walk succeeded

The documented command exists. Honest before-tool on store B returned exit 0 and printed ALLOWED. The tool ran. Death refuse returned exit 1 and printed REFUSED. The refuse named kill accept, not expiry and not a missing inode. The tool did not run after refuse. Store B stayed empty of instance records. Store B did not copy `issuer.secret`. Store B did not receive a holder secret path. Both hosts bound `127.0.0.1` only. Both hosts are stopped.

## Hole that was locked

`prometheus runtime-check act` was already the gate. The command line had no before-tool process that prints ALLOWED or REFUSED and that can run a tool only when the act is allowed. `prometheus runtime-check before-tool` now reuses that act gate. Exit 0 only when the tool may run. Any refuse or transport failure is non-zero. Unknown is not live. This process does not override a refuse. The tests `laboratory_runtime_before_tool_prints_allowed_and_may_run_the_tool` and `laboratory_runtime_before_tool_refuses_after_kill_accept_and_does_not_run_the_tool` fail before that lock.

## Blocked work

No `scripts/*.sh` file was executed. No public bind. No SPIRE. No secrets provider. No sixth record. Issuer threshold n=3 stayed parked. GET / chrome was not restyled.

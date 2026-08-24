# Prometheus later user interface spawn answers

Date: 21 August 2026.

This page is for Jason Gale. This package is laboratory code under PolicyLab-2. This package is not Sanctum. This package is not a Cyera product.

This document uses ASD-STE100 Simplified Technical English. Technical names appear in full words.

The visible walk lives in `see-walk/later-ui-spawn`. The issuing store lived under `/tmp/prometheus-later-ui-spawn`. That walk directory holds public artifacts only. It does not hold `issuer.secret`, `biscuit.secret`, holder secrets, or member-two secrets.

The issuing store listened on `127.0.0.1:18779` only. The host is stopped.

Init used the command line once. The rest of the walk used HTTP against GET / on the loopback host. The laboratory operator page at GET /laboratory was not used. This is one issuing store. This is not a two-store walk.

Spawn is not a role catalog. The child is what was presented and killed. Identifiers came from host responses. This walk did not invent identifiers.

## What each HTTP call returned

All paths below sit under `see-walk/later-ui-spawn` unless the line names a `/tmp` store file.

1. GET `http://127.0.0.1:18779/` returned HTTP 200. The page is the later user interface. The page names bind `127.0.0.1`. The page says this is not a public listener. The page names Spawn in the kernel story. The page says spawn is not a role catalog. File: `get-root-proof.txt`.
2. GET `/health` returned HTTP 200. File: `health.json`.
3. GET `/instances` before birth returned HTTP 200. Body `{"instances":[]}`. File: `instances-before.json`.
4. POST `/agent-type` returned HTTP 200. Agent type identifier `01M0K658AJCC5SBTG2CGFM4NRH`. Allowed intent `read`. File: `agent-type.json`.
5. POST `/birth` returned HTTP 200. Instance identifier `01M0K658AMW435S0084JVDEXEB`. Capability identifier `01M0K658AMV0D5NFM07DX3K7ST`. Intent `read`. Audience `internal/prod`. The response named a holder secret path only. Secret bytes were not returned. File: `birth.json`.
6. POST `/challenge` for the parent, then POST `/spawn` with audience `internal`, returned HTTP 403. Result `refused`. Reason: the child audience `internal` exceeds the parent audience `internal/prod`. A child cannot gain rights that the parent does not have. GET `/instances` still listed one live parent. Files: `challenge-wider.json`, `spawn-wider-refuse.json`, `spawn-wider-request-keys.json`, `instances-after-wider.json`.
7. POST `/challenge` for the parent, then POST `/spawn` with audience `internal/prod`, returned HTTP 200. Child instance identifier `01M0K658AVK6452E9ZY4S8FJGR`. Child capability identifier `01M0K658AWTP90PQ1M8JHXT95W`. The response named a holder secret path only. Secret bytes were not returned. Files: `challenge-spawn.json`, `spawn.json`, `spawn-request-keys.json`.
8. GET `/instances` after spawn returned HTTP 200. The child listing includes `parent_instance_id` `01M0K658AMW435S0084JVDEXEB`. That value equals the birth instance identifier. The parent listing omits `parent_instance_id`. File: `instances-after-spawn.json`.
9. POST `/challenge` for the child, then POST `/present-svid` of the child, returned HTTP 200. The body held `presentation_json` and `certificate_pem`. The present instance identifier is the child. The signed ancestor set names the parent. Files: `challenge-present.json`, `present-svid.json`, `present-svid-request-keys.json`, `presentation.json`, `presentation.json.svid.pem`.
10. POST `/challenge` for the child, then POST `/check-svid` of that present, returned HTTP 200. Result `allowed`. Intent `read`. Audience `internal/prod`. Instance identifier `01M0K658AVK6452E9ZY4S8FJGR`. Files: `challenge-check.json`, `check-svid-allow.json`, `check-svid-allow-summary.json`, `check-svid-request-keys.json`.
11. POST `/kill` of the child returned HTTP 200. Status `revoked`. Confirm equalled the child instance identifier. Files: `kill.json`, `kill-request-keys.json`.
12. POST `/check-svid` of the same historical child present returned HTTP 403. Result `refused`. Reason: this store's own records say this instance is revoked. Present verify is refused after local kill. Death wins. The refuse names local kill, not expiry. Files: `check-svid-after-kill.json`, `check-svid-after-kill-summary.json`.
13. GET `/instances` after kill returned HTTP 200. The child status is `revoked`. The child listing still includes `parent_instance_id` `01M0K658AMW435S0084JVDEXEB`. The parent status is `live`. File: `instances-after-kill.json`.
14. GET `/status` after kill returned HTTP 200. Live instance count 1. Revoked instance count 1. Check host bind `127.0.0.1` only. File: `status-after.json`.

HTTP status codes for the walk live in `http-codes.json`.

## Whether the walk succeeded

All HTTP steps succeeded. Wider spawn returned 403. Narrower spawn returned 200. Honest check of the child returned 200 allowed. Death refuse returned 403. The refuse named local kill, not expiry and not a missing inode. GET `/instances` locked the parent identifier on the child listing. The child is what was presented and killed. The host bound `127.0.0.1` only. The host is stopped.

## Hole that was locked

GET `/instances` already returns `parent_instance_id` on a spawn child. The host test `the_host_instances_path_includes_parent_instance_id_for_a_spawn_child` locks that field. The host test `the_later_user_interface_spawn_walk_allows_then_refuses_after_child_kill` locks the GET / walk: birth, wider spawn refuse, narrower child, present the child, check allow, kill the child, check refuse. This walk answers page names the same parent identifier on the child listing. Do not invent identifiers.

## Blocked work

No `scripts/*.sh` file was executed. No public bind. No SPIRE. No secrets provider. No sixth record. Issuer threshold n=3 stayed parked. GET / was not restyled.

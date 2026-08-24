# Prometheus judge page

Date: 20 August 2026.

This page is for Jason Gale. This package is laboratory code under PolicyLab-2. This package is not Sanctum. This package is not a Cyera product.

This document uses ASD-STE100 Simplified Technical English. Technical names appear in full words.

The visible walk lives in `see-walk/judge-rung6`. The two stores lived under `/tmp/prometheus-judge-rung6`. That walk directory holds public artifacts only. It does not hold `issuer.secret`, `biscuit.secret`, holder secrets, or member-two secrets.

The host listened on `127.0.0.1:18771` only. The host is stopped.

## Five questions

1. Can birth write the instance, the first capability, and death in one persist? **yes**
2. Can a second party verify an act without copying the inode? **yes**
3. Can death travel to that second party and refuse a later present? **yes**
4. Can a runtime consume that present without becoming a directory? **yes**
5. Does a stolen or resigned wrap fail closed after kill? **yes**

All five answers are yes. The kernel is now testable. This page does not say the bet is won.

## One sentence each

1. One `birth` persist wrote the live instance, the first capability, the revoke identifier, and one `birth_write` issuance-log line.
2. Store B accepted the store A public key and the act bundle. Store B wrote no instance record and no issuance-log line.
3. Store B accepted the kill bundle. Store B then refused `present verify-svid` of the historical wrap. The store A host also refused that wrap after local kill.
4. The loopback host allowed POST `/check-svid` for the honest wrap. The host is a check. The host is not a directory.
5. After kill, a wrap resigned with a foreign Ed25519 key was posted to the same host. The host returned HTTP 403 and signed no receipt.

## Artifact paths

All paths below sit under `see-walk/judge-rung6`.

- Question 1: `birth.json`, `issuance-after-birth.log`, `capability-public.json`
- Question 2: `b-issuer-accept.json`, `b-act-accept.json`, `b-no-mint.txt`, `act-receipt.json`, `act-proof.json`, `act-tree-head.json`
- Question 3: `a-kill.json`, `kill-event.json`, `b-kill-accept.json`, `check-svid-after-kill.json`, `b-verify-svid-after-kill.txt`, `instance-after-kill.json`
- Question 4: `presentation.json`, `presentation.json.svid.pem`, `check-svid-allowed.json`, `present-emit.json`
- Question 5: `resigned.pem`, `check-svid-resigned.json`

## Blocked work

No command was blocked. A first openssl empty-subject config failed. A second openssl command with matching NotAfter failed. The live resign used a foreign Ed25519 key and a one-day NotAfter. The host refused that wrap after kill. The tests were not re-run.

# Prometheus judge page: proof without the command line

Date: 23 August 2026.

This page is for Jason Gale. This package is laboratory code under PolicyLab-2. This package is not Sanctum. This package is not a Cyera product.

This document uses ASD-STE100 Simplified Technical English. Technical names appear in full words.

This page lists what a person can now prove on `127.0.0.1` GET `/` and GET `/laboratory` against the public check name `https://check.prestigeworldwide.digital` without a command-line check verb. Each line names a walk path and a rung. This page is evidence. This page is not chrome.

This page does not say the bet is won.

## What without the command line means

Init stays on the command line. Host start is a listen command so the page exists. After that, the person uses the loopback page or the same HTTP JSON that the page posts. The person does not run `prometheus check`, `prometheus present`, `prometheus kill`, or `prometheus runtime-check`.

The issuing-store host does not spawn AgentProcess. Holder secret bytes are not uploaded. `issuer.secret` is not copied onto the public host. The public name stays check-only JSON.

## Still command line

- Init. Rung 17 locked this. See BROWSER-WALK.md section 1 and see-walk/judge-rung6. A store does not exist until init writes it.
- Host start. The person starts `prometheus host --listen-address 127.0.0.1:<port>` so GET `/` or GET `/laboratory` answers.
- Hermes AgentProcess walks. Those stay a runtime command. See rungs 51, 54, 55, 56, 57, 59, and 60.
- AgentProcess on hostname 5090 with a remote member-secret path. That stay a runtime command. Rung 104. see-walk/member-two-agent-process.

## GET / against the public check name

GET `/` is the later user interface on the issuing store. The page types a check base. Off-origin Check posts POST `/runtime-check`. Off-origin pins post POST `/well-known-follow` then POST `/operator-pin`. The browser does not fetch the public name.

A person can prove:

1. Honest laboratory X.509-SVID Check allows. Rung 75. see-walk/later-ui-public-runtime-check.
2. After Decommission and public kill-accept, that same present refuses because this store accepted a kill, not because of expiry. Rung 75 and Rung 82. see-walk/later-ui-public-runtime-check and see-walk/later-ui-public-operator-pin.
3. Honest WIMSE Check allows, then the same present refuses after Decommission and public kill-accept. Rung 78. see-walk/later-ui-public-wimse-runtime-check.
4. After local seal and public seal-accept, Check refuses because this store accepted a seal. A stolen issuer mint for that pin also refuses. Rung 76. see-walk/later-ui-public-seal-accept.
5. After rotate and public previous-key-accept, an old-key present refuses after the kill date. A current-key present still allows. Rung 77. see-walk/later-ui-public-previous-key.
6. Public act-accept of an honest X.509-SVID act returns 200. The public host writes no instance. Public GET `/instances` stays 403. Rung 79. see-walk/later-ui-public-act-accept.
7. Public act-accept of an honest WIMSE act via operator-pin returns 200. The public host writes no instance. Rung 83. see-walk/later-ui-public-wimse-act-accept.
8. Operator-pin kill-accept follows the public well-known document. The walk does not hardcode public `/kill-accept` as the accept URL. Rung 81 and Rung 82. see-walk/later-ui-public-operator-pin.
9. Live POST `/runtime-check`, POST `/operator-pin`, and POST `/well-known-follow` on the public name stay 403 check-only. Rungs 75, 82, 83, 88, 89, 90, and 91.
12. Honest laboratory X.509-SVID Check again of that same present also allows. After Decommission and operator-pin kill-accept, Check again refuses because this store accepted a kill, not because of expiry. A following public POST `/check-svid` also refuses from accepted kill. Rung 88. see-walk/later-ui-public-check-again.
13. Honest WIMSE Check again of that same present also allows. After Decommission and operator-pin kill-accept, Check again refuses because this store accepted a kill, not because of expiry. A following public POST `/check-wimse` also refuses from accepted kill. Rung 89. see-walk/later-ui-public-wimse-check-again.
14. Check both parent and child laboratory X.509-SVID presents allows. Two `/runtime-check` hits. After parent Decommission and operator-pin kill-accept, Check both refuses because this store accepted a kill cascade, not because of expiry. A named check of the child also refuses from that cascade. A following public POST `/check-svid` of the child also refuses from accepted kill. Rung 90. see-walk/later-ui-public-check-both.
15. Named check of an independent live act allows after the first dies. Two independent Create Agent Principal presents. Check both allows. After first Decommission and operator-pin kill-accept, Check both refuses. A named check of the live second act still allows. A named check of the first act refuses because this store accepted a kill, not a cascade. Rung 91. see-walk/later-ui-public-named-act.
16. Create Agent Principal and Assertion Act through a remote member-secret path, then public Check allows, then after Decommission and public kill-accept the same present refuses because this store accepted a kill, not expiry. Rung 99. GET / on 127.0.0.1:18834. Holder-sign is local. see-walk/later-ui-member-two-public.
17. Create Agent Principal and WIMSE Assertion Act through a remote member-secret path, then public POST /check-wimse allows, then after Decommission and public kill-accept the same present refuses because this store accepted a kill, not expiry. Rung 100. GET / on 127.0.0.1:18836. Holder-sign is local. see-walk/later-ui-member-two-public-wimse.

Check again on GET `/` is locked. Check both and a named act on GET `/` are locked. Each click hits the host. ALLOWED is not stored. Rung 66 locked the JavaScript against Store B. The live public Check-again walks are items 12 and 13. The live public Check-both cascade is item 14. The live public named-act sibling is item 15. Do not add more presenter pairs on the public name.

## GET /laboratory against the public check name

GET `/laboratory` is the laboratory operator page on the issuing store. Check types the same accepted bases. Off-origin Check posts POST `/runtime-check`. Off-origin pins post POST `/well-known-follow` then POST `/operator-pin`. The browser does not fetch the public name. Check again posts the last present. GET `/laboratory` does not claim Check both or a named act.

A person can prove:

10. Honest laboratory X.509-SVID Check allows. Check again of that same present also allows. After Decommission and operator-pin kill-accept, Check again refuses because this store accepted a kill, not because of expiry. A following public POST `/check-svid` also refuses from accepted kill. Rung 86. see-walk/later-ui-laboratory-public-check.
11. Honest WIMSE Check allows. Check again of that same present also allows. After Decommission and operator-pin kill-accept, Check again refuses because this store accepted a kill, not because of expiry. A following public POST `/check-wimse` also refuses from accepted kill. Rung 87. see-walk/later-ui-laboratory-public-wimse.
18. Create Agent Principal and WIMSE Assertion Act through a remote member-secret path, then public POST /check-wimse allows, then after Decommission and public kill-accept the same present refuses because this store accepted a kill, not expiry. Rung 103. GET /laboratory on 127.0.0.1:18844. Holder-sign is local. see-walk/later-ui-laboratory-member-two-public-wimse.

GET `/laboratory` well-known operator-pin follow and typed check base are locked. Rung 84 and Rung 85. Those rungs reused Store B allow-then-refuse. The live public Check-again walks are items 10 and 11.

## Loopback only, not the public name

These proofs use GET `/` against Store B on 127.0.0.1. They do not use the public check name.

- Typed check base allow then refuse. Rung 65. The public-name sibling is item 1.
- Check again of the same present. Rung 66. The public-name sibling is item 12.
- WIMSE typed-base Check again. Rung 68. The public-name sibling is item 13.
- Check both parent and child. Rung 69. The public-name sibling is item 14.
- Named check of an independent live act. Rung 70. The public-name sibling is item 15.
- Check both X.509-SVID and independent WIMSE. Rung 71. Stay loopback. Do not add that pairing on the public name.
- Check both live X.509-SVID plus dead WIMSE is not ALLOWED. Rung 72. Stay loopback. Do not add that pairing on the public name.
- Check both two independent WIMSE acts. Rung 73. Stay loopback. Do not add that pairing on the public name.
- Check both parent X.509-SVID and child WIMSE. Rung 74. Stay loopback. Do not add that pairing on the public name.
- Create Agent Principal and Assertion Act with a remote member-secret path. Rung 98. GET / on 127.0.0.1. POST /birth refuses without the path and refuses when the SSHFS mount is gone. POST /birth and POST /present-svid allow after remount. see-walk/later-ui-member-two-remote. The public-name sibling is item 16, Rung 99. The WIMSE public-name sibling is item 17, Rung 100.
- Create Agent Principal and Assertion Act with a remote member-secret path on GET /laboratory. Rung 101. GET /laboratory on 127.0.0.1:18838 is the laboratory operator page. GET / on the same host is a different page. POST /birth refuses without the path and refuses when the SSHFS mount is gone. POST /birth and POST /present-svid allow after remount with two issuer member signatures. see-walk/later-ui-laboratory-member-two-remote. The public-name sibling is Rung 102, see-walk/later-ui-laboratory-member-two-public. The WIMSE public-name sibling is Rung 103, see-walk/later-ui-laboratory-member-two-public-wimse.
- Create Agent Principal and Assertion Act with a remote member-secret path on GET /laboratory, then public allow then refuse. Rung 102. GET /laboratory on 127.0.0.1:18842. POST /check-svid allowed. After Decommission and public kill-accept the same present refused because this store accepted a kill. see-walk/later-ui-laboratory-member-two-public.
- Create Agent Principal and WIMSE Assertion Act with a remote member-secret path on GET /laboratory, then public allow then refuse. Rung 103. GET /laboratory on 127.0.0.1:18844. POST /check-wimse allowed. After Decommission and public kill-accept the same present refused because this store accepted a kill. see-walk/later-ui-laboratory-member-two-public-wimse.

The first two-store loopback operator walk is Rung 17. see-walk/browser-two-store. Init stayed on the command line.

## Not claimed

- Check both and a named act on GET `/laboratory`. That page does not claim those controls. Do not invent them.
- Birth, Present, and Death headings on GET `/laboratory`. Those labels stay parked polish.
- A public listener for Create Agent Principal. Birth stays on 127.0.0.1.
- SPIRE. Do not start SPIRE.
- A sixth identity record.
- Sanctum locks. This package is not Sanctum.

## The five judge questions stay yes

See JUDGE.md. All five answers stay yes. The kernel is testable. This page does not say the bet is won.

## Open items that are not coding slices

- Who holds member two in a later market.
- GitHub publication.
- How a later market names the well-known check.
- Stolen issuer secret can still mint a present that a verifier allows until that verifier accepts the seal or a previous-key kill.

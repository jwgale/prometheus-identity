# Prometheus two-store loopback operator walk

Date: 20 August 2026.

This page is for Jason Gale. This package is laboratory code under PolicyLab-2. This package is not Sanctum. This package is not a Cyera product.

This document uses ASD-STE100 Simplified Technical English. Technical names appear in full words.

This page shows how to start two loopback hosts and test act and kill without living in the command line after init. Init remains a command-line step. The hosts bind to `127.0.0.1` only. This is not a public listener.

The visible walk artifacts live in `see-walk/browser-two-store`. That folder does not hold `issuer.secret`, `biscuit.secret`, holder secrets, or member-two secrets.

## 1. Init each store on the command line

Use two empty store directories. Do not copy secrets between stores.

```
cd /home/jason/Projects/Prometheus
cargo run --release -- --data-directory /tmp/prometheus-store-a init
cargo run --release -- --data-directory /tmp/prometheus-store-b init
```

## 2. Start the two hosts

Start store A on `127.0.0.1:18765`. Start store B on `127.0.0.1:18766`. Use two terminals.

```
cargo run --release -- --data-directory /tmp/prometheus-store-a host --listen-address 127.0.0.1:18765
```

```
cargo run --release -- --data-directory /tmp/prometheus-store-b host --listen-address 127.0.0.1:18766
```

Open http://127.0.0.1:18765/ in a browser. Open http://127.0.0.1:18766/ in a second tab.

## 3. Store A issues

On http://127.0.0.1:18765/ do this work:

1. Add an agent type. Allowed intent `read`. Authorization limit `internal`.
2. Birth an instance. Intent `read`. Audience `internal`. Act authority `autonomous`.
3. Copy the holder secret path from the birth result. Paste that path into the holder secret path field. The page does not upload secret file bytes.
4. Request a challenge. Emit the laboratory X.509-SVID wrap.
5. Submit the check. The host must allow.
6. Export the act bundle. The page shows receipt, proof, and tree_head.

Store A status shows a truncated issuer public key. That truncated key is not enough for issuer-accept.

On store A, open GET /issuer-public or copy the full public key from This store issuer public key. That path returns `current_issuer_public_key_hex` and `crypto_profile` only. Do not read `issuer.json`. Do not open `issuer.secret`. Do not copy `biscuit.secret`. Do not copy holder secret files.

## 4. Store B verifies

On http://127.0.0.1:18766/ do this work:

1. Paste the full store A public key from GET /issuer-public on A into Accept an issuer public key.
2. Request a verifier challenge on store B. Copy the nonce and the challenge message.
3. On store A, paste that nonce or message and the local holder secret path. Sign the verifier nonce. Copy the holder signature only.
4. On store B, paste the wrap, the nonce, and the holder signature. Submit POST /check-svid. Do not paste a holder secret path on store B. The host must allow.
5. Paste the act-export JSON into Accept an act bundle.
6. Refresh instances. Store B must show no instance records. Store B does not mint.

## 5. Kill travels

On store A: pick the live instance. Type the same identifier to confirm. Kill the instance. Export the kill bundle.

On store B: paste the kill-export JSON into Accept a kill bundle.

On store A: a later POST /sign-holder-nonce for that instance is refused. The instance is revoked.

On store B: submit the historical wrap to check. The host must refuse. Death wins. Store B does not need a new holder signature. Present-verify already refuses after kill accept.

On store A: submit the same historical wrap. The host must refuse.

## 6. Stop both hosts

Stop both host processes. Do not leave listeners. A public bind is refused.

## One walk that already ran

A walk on 20 August 2026 used these ports and these host paths. All HTTP steps succeeded. Answers live in `see-walk/browser-two-store/ANSWERS.md`.

## 7. Two-store WIMSE death walk

The same two-store death proof for the WIMSE on-ramp lives in `see-walk/wimse-two-store`. Init stays on the command line. The rest uses host HTTP on `127.0.0.1` only.

Store A listens on `127.0.0.1:18767`. Store B listens on `127.0.0.1:18768`.

1. Store B pins Store A issuer public key via GET /issuer-public then POST /issuer-accept. Use the full hex. Do not use GET /status. Do not use the envelope key.
2. Store A POST /present-wimse. Store B POST /verifier-challenge. Store A POST /sign-holder-nonce with that nonce and the local holder secret path. Store B POST /check-wimse of the present with the HTTP Message Signature over `@method` and `@request-target`, plus the nonce and the holder signature. Store B never receives a holder secret path. Honest check allows.
3. Store A local kill, POST /kill-export. Store B POST /kill-accept. Store B writes no instance record and does not copy issuer.secret.
4. Store B POST /check-wimse of the historical present refuses. Death wins.

Answers live in `see-walk/wimse-two-store/ANSWERS.md`.

## 8. Two-store seal walk

The same two-store proof for traveling seal lives in `see-walk/seal-two-store`. Init stays on the command line. The rest uses host HTTP on `127.0.0.1` only.

Store A listens on `127.0.0.1:18769`. Store B listens on `127.0.0.1:18770`.

1. Store B pins Store A issuer public key via GET /issuer-public then POST /issuer-accept. Use the full hex. Do not use GET /status. Do not use the envelope key.
2. Store A POST /present-wimse. Store B POST /verifier-challenge. Store A POST /sign-holder-nonce with that nonce and the local holder secret path. Store B POST /check-wimse of the present with the HTTP Message Signature over `@method`, `@request-target`, and `content-digest`, plus the nonce and the holder signature. Store B never receives a holder secret path. Honest check allows.
3. Store A POST /seal with confirm `seal`. Store A POST /seal-export. Store B POST /seal-accept. Store B writes no instance record and does not copy issuer.secret.
4. Store B POST /check-wimse of the historical present refuses. Seal accept is issuer death for verify.

Answers live in `see-walk/seal-two-store/ANSWERS.md`.

## 9. Two-store previous-key walk

The same two-store proof for traveling previous-key kill lives in `see-walk/previous-key-two-store`. Init stays on the command line. Rotate stays on the command line. The rest uses host HTTP on `127.0.0.1` only.

Store A listens on `127.0.0.1:18771`. Store B listens on `127.0.0.1:18772`.

1. Store A POST /birth and POST /present-wimse before rotate. That present is signed by the old issuer key.
2. Store B pins Store A issuer public key via GET /issuer-public then POST /issuer-accept. Use the full hex. Do not use GET /status. Do not use the envelope key.
3. Store A POST /present-wimse. Store B POST /verifier-challenge. Store A POST /sign-holder-nonce with that nonce and the local holder secret path. Store B POST /check-wimse of the present with the HTTP Message Signature over `@method`, `@request-target`, and `content-digest`, plus the nonce and the holder signature. Store B never receives a holder secret path. Honest check allows.
4. On the command line, rotate store A so the previous key gets a kill date. Store A POST /previous-key-export. Store B POST /previous-key-accept. Store B writes no instance record and does not copy issuer.secret.
5. After that kill date, Store B POST /check-wimse of the historical present refuses. The refuse names the previous issuer key past its kill date.

Answers live in `see-walk/previous-key-two-store/ANSWERS.md`.

## 10. Two-store issuance-threshold birth walk

The same two-store proof for birth at issuance threshold_n 2 lives in `see-walk/threshold-two-store`. Init stays on the command line. The rest uses host HTTP on `127.0.0.1` only.

Store A listens on `127.0.0.1:18773`. Store B listens on `127.0.0.1:18774`.

1. Store A POST /member-two with a local outside member secret path. Who holds member two in a later market stays open. The laboratory uses that outside file path.
2. Store A POST /set-issuer-threshold with confirm `issuer-threshold`. The response returns threshold_n 2. Store A may POST /set-verify-threshold. Store B uses verify_threshold_n, not Store B issuance threshold.
3. Store A POST /agent-type after that raise. A class written at n=1 has one member signature. Birth at n=2 verifies the class at the current issuance threshold.
4. Store A POST /birth without the outside member secret path is refused. A live host that already registered member two still requires that path on the birth body.
5. Store A POST /birth with the outside member secret path is allowed. The response names a holder secret path only.
6. Store A POST /present-wimse. Store B pins Store A issuer public key via GET /issuer-public then POST /issuer-accept. Use the full hex. Do not use GET /status. Do not use the envelope key.
7. Store B POST /verifier-challenge. Store A POST /sign-holder-nonce with that nonce and the local holder secret path. Store B POST /check-wimse of the present with the HTTP Message Signature over `@method`, `@request-target`, and `content-digest`, plus the nonce and the holder signature. Store B never receives a holder secret path, a member secret, or issuer.secret. Honest check allows. Store B writes no instance record.

Answers live in `see-walk/threshold-two-store/ANSWERS.md`.

## 11. Two-store later user interface death walk

The same two-store death proof on GET / lives in `see-walk/later-ui-two-store`. Init stays on the command line. The rest uses host HTTP on `127.0.0.1` only. A person uses GET /, not GET /laboratory.

Store A listens on `127.0.0.1:18775`. Store B listens on `127.0.0.1:18776`.

1. Store A GET / births and presents. Copy the holder secret path from the birth result on store A only.
2. Store B GET / pins Store A issuer public key via GET /issuer-public then Accept an issuer public key. Use the full hex. Do not use GET /status. Do not use the envelope key.
3. Store B requests a verifier challenge. Store A signs the nonce with the local holder secret path. Store B pastes the wrap, the nonce, and the holder signature. Store B Check uses an empty live-instance field. Do not birth on store B. Do not invent an instance identifier. Store B never receives a holder secret path or a member secret path. Honest check allows.
4. Store A kills the instance and exports the kill bundle. Store B accepts the kill bundle. Store B writes no instance record and does not copy issuer.secret.
5. Store B GET / check of the same historical present refuses. Death wins. Store B GET /instances stays empty.

Answers live in `see-walk/later-ui-two-store/ANSWERS.md`.

## 12. Later user interface spawn walk

The GET / spawn walk lives in `see-walk/later-ui-spawn`. Init stays on the command line. The rest uses host HTTP on `127.0.0.1` only. A person uses GET /, not GET /laboratory. One issuing store. This is not a two-store walk.

The issuing store listens on `127.0.0.1:18779`.

1. GET / births a live instance. Intent `read`. Audience `internal/prod`.
2. GET / spawn of a child whose audience is wider than the parent is refused.
3. GET / spawn writes a narrower child. GET /instances shows `parent_instance_id` on that child. Do not invent identifiers.
4. GET / presents the child. GET / check of that present allows.
5. GET / kills the child. GET / check of the same historical present refuses. Death wins. Short certificate life is not kill.

Answers live in `see-walk/later-ui-spawn/ANSWERS.md`.

## 13. Local agent before a tool

The local agent before-tool walk lives in `see-walk/local-agent-before-tool. A later public walk lives in see-walk/public-check-before-tool and uses https://check.prestigeworldwide.digital.`. Init stays on the command line. Create Agent Principal and Assertion Act use host HTTP on `127.0.0.1` only. The agent process is `prometheus runtime-check before-tool`. This is not a public listener.

Store A listens on `127.0.0.1:18780`. Store B listens on `127.0.0.1:18781`.

1. GET / on store A names Create Agent Principal, Assertion Act, and Decommission. Check stays Check. The page does not use `<h2>Birth</h2>` or `<h2>Death</h2>` as product headings.
2. Store A POST `/birth` then POST `/present-svid`. Copy the holder secret path from the birth result on store A only.
3. Store B pins Store A issuer public key via GET `/issuer-public` then POST `/issuer-accept`. Use the full hex. Do not use GET `/status`. Do not use the envelope key.
4. `prometheus runtime-check before-tool` connects to store B. The process follows GET `/.well-known/prometheus-check`. Sign stays on store A POST `/sign-holder-nonce`. Store B never receives a holder secret path. The process prints ALLOWED and may run the tool.
5. Store A POST `/kill` then POST `/kill-export`. Store B POST `/kill-accept`. Store B writes no instance record and does not copy issuer.secret.
6. The same `prometheus runtime-check before-tool` command on the historical Assertion Act prints REFUSED and does not run the tool. Death wins.

Answers live in `see-walk/local-agent-before-tool/ANSWERS.md`.

# Prometheus progress

This file is PolicyLab-2 laboratory notes. This package is not affiliated with Sanctum. This package is not a Cyera product.

## What shipped tonight

1. Authorization limit enforcement on mint, check, and spawn. The destination uses a prefix class. The intent uses the allowed intents list.
2. Holder proof on verify, check, spawn, and the local host. A capability token is not accepted as a bearer token.
3. Intent decrease on attenuate. A wider intent is refused.
4. One birth write. The `birth` command creates an instance and the first capability as one `birth_write` issuance event.
5. Delegation depth. Chain records are stored. A fourth hop fails when `max_delegation_depth` is 3.
6. Agent-to-agent spawn. A live instance with a capability can birth a child and a narrower capability in one write. The parent pointer is set. A wider child is refused.
7. Tool-boundary host. `prometheus host` listens on `127.0.0.1` only and answers `POST /check`.
8. Act audit. Every allowed or refused check appends an identity event. `prometheus log show` prints issuances and checks.
9. Expiry. A capability past `expires` fails verify and check. The unit test injects a clock and does not sleep.
10. One-time holder challenge. `prometheus challenge --instance` writes a nonce, an issued time, and an expiry as a log line. Verify, check, spawn, and `POST /check` must answer that challenge. Re-use of a spent nonce fails. A challenge past its time window fails. The static laboratory challenge is removed.
11. Parent kill cascade. `prometheus instance kill` on a parent stops the parent, all child instances, and all capabilities in those chains (`revoke_from_here`). Verify and check on a child capability after the parent kill fail.
12. Named capability on check. `prometheus check` and `POST /check` require `capability_id`. A check that only names instance, intent, and audience is refused. The kernel does not guess which capability.
13. Tool-loop host. `scripts/demo_tool_loop.sh` starts `prometheus host` on `127.0.0.1`, births one agent, then runs three `POST /check` calls: an internal tool is accepted, a public destination is refused, and a spent challenge is refused. The script stops the host. A trap stops the host if the script fails.
14. Act authority on check. Autonomous and `on_behalf_of` a named user are first-class capability fields. A named value must match the capability exactly. A mismatch fails closed. `scripts/demo_on_behalf.sh` checks both capabilities and then asks for the wrong act authority.
15. Expired capability on the host path. The unit test injects a clock into the same `POST /check` body path the host uses. The test does not sleep.
16. Required act authority on check. `prometheus check` and `POST /check` require `on_behalf_of`. A missing field is refused. An empty string is not autonomous. The exact word `autonomous` is required.
17. Act authority in the capability token. Mint writes an `on_behalf_of` Biscuit fact. Verify and check fail when the token fact does not match the request, even if the JSON record was changed.
18. Spawn act authority. The child `on_behalf_of` must stay compatible with the parent capability. A parent on behalf of a named user cannot birth a child whose token says autonomous. The child must keep that same user. An autonomous parent may birth an autonomous child or a child on behalf of a named user. The child token stores the child act authority as an `on_behalf_of` fact. A refused widen does not write a child. `scripts/demo_spawn_authority.sh` shows the refused widen.
19. Signed decision receipt. After every verify or check, allow or refuse, the kernel signs a receipt with the issuer private key. The receipt names the instance, the capability, the intent, the audience, the act authority, the result, the reason when refused, the challenge nonce, and the issued time. The receipt is returned on the check command JSON, on verify command JSON, and on `POST /check`. `prometheus receipt verify --receipt <file>` checks the signature against the issuer public key and that the fields parse. A tampered result fails. A missing signature fails. A receipt signed by a foreign key fails. Holder secrets are not written into the receipt. The receipt is a signed document, not a sixth identity record. This is a laboratory Ed25519 signature. This is not a public transparency log. This is not threshold issuance.
20. Receipt binds to the local issuance log (STE100). Every decision receipt includes `issuance_log_line`, the exact JSON line of that check or verify event as written to `issuance.log`. `prometheus receipt verify` still requires a valid issuer signature. It also fail-closes when that line is missing from `issuance.log` or when the stored line was altered. A valid signature is not enough. This is still a local log. This is not a public transparency log.
21. Issuance log hash chain (STE100). Each `issuance.log` JSON line includes `previous_line_hash` (SHA-256 of the previous raw line, or the documented empty-hash for the first line) and `line_hash` (SHA-256 of the compact JSON with `line_hash` omitted). `prometheus log verify` walks the file and fail-closes on a missing field, a wrong previous hash, or a wrong line hash. Receipt verify walks the same chain first. A deleted or inserted middle line is detectable. This is a local hash chain. This is not a public append-only service.
22. Issuer accept list (STE100). The issuer record stores `accepted_issuer_public_keys`. Init always includes this store's own public key. `prometheus issuer accept --public-key-hex <hex>` adds a key and persists `issuer.json`. Empty is refused. `prometheus receipt verify` accepts a signature only when the key is on that list. A second store can verify a first-store receipt by accepting the first public key and pointing `--issuance-log` at the first `issuance.log`. The second store does not become a second identity kernel. This is an accept list. This is not a global name system. This is not SPIFFE federation.
23. Issuer key rotation with a kill date (STE100). The issuer record stores `current_public_key` and `previous_issuer_keys: [{public_key_hex, kill_date}]`. `prometheus issuer rotate [--kill-after-seconds N]` creates a new laboratory key pair, sets the old key's `kill_date` to now plus a short laboratory window (or the given seconds), and writes `issuer.secret` as the new key only. New mint, birth, spawn, and receipts sign with the current key only. The old public key stays on the accept list until `kill_date`. Old capabilities verify until capability expiry. After `kill_date`, a new signature from the old key that is not in the issuance log is refused even if the signature is valid. This is laboratory single-key rotate. This is not threshold issuance. This is not a production FIPS module. This is not a post-quantum Biscuit.
24. Local Merkle inclusion proof for the issuance log (STE100). After each append the store can compute a Merkle root over the sequence of `line_hash` values. The Merkle leaf is the existing `line_hash` (already SHA-256 of the documented canonical line). This is not a third hash chain. `prometheus log root` prints the root and the leaf count. `prometheus log prove --line-hash HEX` writes a proof (`line_hash`, `leaf_index`, `sibling_hashes` in order, `root`). `prometheus log check-proof --proof FILE [--root HEX]` recomputes the root and fail-closes on a mismatch, an empty proof, a truncated sibling list, or a leaf that is not the claimed `line_hash`. A second store can check one logged mint against a known root without copying the log and without becoming a second identity kernel. The decision receipt does not carry `issuance_log_root`; prove and check-proof are the surface. This is a local Merkle tree over the hash-chained issuance log. This is not a public transparency log. This is not Certificate Transparency. This is not a gossiped signed tree head across the internet. Proofs are derived from the existing `issuance.log` lines. This is not a sixth record.
25. Locally signed Merkle tree head (STE100). `prometheus log sign-root` signs the current Merkle root with the current issuer secret only and writes `merkle_root`, `leaf_count`, `signed_at`, `issuer_public_key_hex`, and `signature_hex`. The signed bytes are the documented concatenation `prometheus-signed-tree-head|{merkle_root}|{leaf_count}|{signed_at}|{issuer_public_key_hex}`. That is not JSON. Field reorder in the JSON container cannot change the signed bytes. `prometheus log check-root --tree-head FILE` verifies the signature with the key in the file and requires that key to be this issuer's current key, a previous key, or a key on the accept list. A tree head signed before a previous key's `kill_date` remains a historical pin. A previous key used to sign after its `kill_date` is refused. `--require-current-root` also requires this store's current root and leaf count. Default check is signature plus accept list so a second store can pin a foreign tree head without becoming a second identity kernel. Previous keys past `kill_date` cannot sign a new tree head. This is a locally signed Merkle root. This is not Certificate Transparency. This is not a gossip protocol. This is not a public log. This is not a multi-witness signed tree head. This is not a sixth record.
26. First-binder invariant (STE100). The `holder_public_key` on an instance record is written once at birth or spawn. `save_instance` refuses any later persist whose `holder_public_key` differs from the stored value. An empty holder public key is refused. `prometheus instance rebind --instance ID --public-key-hex HEX` always refuses. There is no holder-key rotate and no holder-key reset. Kill, revoke, expire, and parent-kill do not rewrite `holder_public_key`. `prometheus instance show` prints the first binder so a later persist can be compared. This is not a remote proof-of-possession protocol. Challenge remains a local nonce. This is not SPIFFE. X.509 must not become the instance name. This is not a sixth record.
27. Issuer seal (STE100). `prometheus issuer seal --after-seconds N` sets `issuer.kill_date` to now plus N seconds on the existing issuer record. N of zero or missing is refused. A later seal cannot postpone death. A later seal that only shortens remaining life is allowed. After `now >= kill_date` this store refuses new mint, birth, spawn, issuer rotate, issuer accept, and `log sign-root`. Attenuation is also refused because it issues a new capability. Verify, check, and host refuse even if the capability is unexpired. The store does not sign a new decision receipt after death. `prometheus receipt verify` of an already-written receipt still succeeds. That is historical audit. Realm `issuer.kill_date` is this issuer record's own death. Previous-key `kill_date` remains "this old key cannot mint." This is a pre-committed issuer death. This is not a network partition detector. This is not a liveness probe. This is not a multi-witness clock. This is not threshold issuance. This is not a production FIPS module. This is not a post-quantum Biscuit. This is not a sixth record.
28. Local act bundle (STE100). `prometheus act export --receipt FILE --output-directory DIR` writes `DIR/receipt.json` (copy of the signed receipt), `DIR/proof.json` (`log prove` for the receipt bound `line_hash`), and `DIR/tree-head.json` (`log sign-root` as of now). Refuse if the receipt line is not in this store's log. Refuse if the issuer is sealed (`sign-root` already refuses). `prometheus act accept --bundle-directory DIR` loads the three files and refuses any missing file. It runs `check-root` on the tree head without `--require-current-root` (a foreign pin), `check-proof` against the tree-head `merkle_root` (not this store's current root), and receipt signature verify against this store's accept list. Refuse if `proof.line_hash` does not match the receipt bound line. Refuse if `proof.root` does not match `tree-head.merkle_root`. Accept is verify-only: it does not mint, does not create instance records, and does not write a second `issuance.log` line. The second store must already have the first issuer public key on its accept list. The second store does not become a second identity kernel. This is a local export of three existing artifacts. This is not a global name system. This is not SPIFFE federation. This is not Certificate Transparency gossip. This is not a sixth record.
29. Signed presentation document (STE100). `prometheus present --instance ID --capability ID --output FILE --challenge-nonce HEX --holder-secret-path PATH` writes a signed presentation from the existing instance, capability, and issuer records. Present is a document, not a name. This is not a SPIFFE SVID, not an X.509 certificate, not a WIMSE token, and not a Transaction Token. The instance identifier must not become a certificate subject. This is not a sixth record. Present requires a live instance, an unexpired capability that belongs to that instance, an unsealed issuer, and a one-time holder challenge. Present is not a bearer document. `expires_at` is the earlier of the capability expiry and a 60-second presentation window. The signed bytes are the documented concatenation `prometheus-presentation|{instance_id}|{agent_type_id}|{capability_id}|{on_behalf_of}|{intent}|{audience}|{holder_public_key}|{issuer_public_key_hex}|{presented_at}|{expires_at}`. That is not JSON. `prometheus present verify --presentation FILE` reconstructs those bytes, checks the issuer signature, requires the key on this store accept list, and refuses if now is at or after `expires_at`. Verify-only: do not mint and do not write instance records. A second store can verify after accepting the first public key. A missing key, a tampered field, a spent nonce, a wrong instance and capability pair, a revoked instance, and a sealed issuer refuse.
30. Authorization-limit freeze (STE100). The authorization limit is the highest intent and destination an agent type may hold. After the first write of an agent type, that type's `authorization_limit` must not increase. A later persist whose new limit is not allowed by the stored limit is a raise. The comparison is `audience_within_authorization_limit`, the same function mint and spawn use. A shorter prefix or a new prefix that is not a child of the stored limit is a raise. Raise is refused even when no instance of that type exists. Narrowing (a child of the stored limit) may persist. The same value may persist. First write on create still sets the limit. The instance still cannot raise its own limit above the type. `prometheus agent-type raise --agent-type ID --authorization-limit VALUE` always refuses. This is not a sixth record.
31. Capability-expiry freeze (STE100). The first persist of a new capability sets `expires`. Any later save of that capability identifier whose `expires` is later than the stored value is refused. Earlier (shorten) may persist. Equal may persist. An extension is a golden-ticket-class extension: the capability must not outlive the mint. Attenuation creates a new capability identifier, so its own first persist may set a shorter expiry; the child must not expire after the parent. `prometheus capability extend --capability ID --expires-at TIME` always refuses. This uses the existing capability `expires` field and the existing kernel clock. This is not a second clock. This is not a sixth record.
32. Token-record fact consistency (STE100). After the capability token signature check, verify, check, host, and present compare token facts to the capability record. The store record is the source for identity fields. The token must not exceed or contradict it. This is not a new record type.
33. Allowed-intents freeze (STE100). After the first write of an agent type, `allowed_intents` must not gain a new intent string. A later persist that adds any intent not in the stored set is refused. Removing an intent may persist. The same set may persist. In the same `save_agent_type` choke point, `max_delegation_depth` must not increase. `prometheus agent-type add-intent` always refuses. This is not a sixth record.
34. Persist-raise hunt (STE100). A later save that grants more rights than the first write is refused at the save choke point. Locked: instance `expires` cannot move later; instance `agent_type_id` cannot change; instance `parent_instance_id` cannot clear or swap; a revoked instance cannot return to live; type `lifetime_seconds` cannot increase; chain `hop_index` cannot decrease; chain `parent_capability_id` cannot clear or swap; chain `revoke_from_here` cannot return to false. Hunt found no working raise on capability `instance_id` (token-record already refuses), capability `revoke_identifier` (kill uses the log and the token), or issuer `threshold_n` (stored as 1, not a bypass). No force-allow leftover. No sixth record. No new always-refuse command-line interface. No twenty-fourth demonstration.
35. Evaluate request-vs-record sibling-prefix lock (STE100). The capability token uses a Biscuit `starts_with` check. That check treated `internal/payroll` as inside `internal/pay`, and `readwrite` as inside `read`. Those strings are not child paths. `evaluate_capability` now requires `is_narrower_or_equal` on the requested intent and audience against the capability record, the same helper mint and spawn use. Verify, check, and host share that choke point. An honest child path still allows. An honest attenuated child still verifies. Hunt of mint, birth, spawn, present, holder proof, empty `on_behalf_of`, host bind, attenuate identifier, token-record, injected clock, and force-allow found no other working raise. No sixth record. No new always-refuse command-line interface. No twenty-fourth demonstration.
36. Receipt / log / Merkle / act / issuer hunt (STE100). `save_issuer` did not freeze realm `issuer.kill_date`. A later persist could move death later or clear it, then mint at the original seal time. The check now lives on `save_issuer`. First seal may set the time. Shorten may persist. The same time may persist. Postpone and clear are refused. After a refused postpone, mint still fails at the original `kill_date`. Hunt of receipt verify log-line bind, unknown issuer key, empty accept-list as allow-all, check-proof empty or truncated siblings, proof leaf versus claimed `line_hash`, check-root tampered root, act accept missing file, act accept wrong current-root pin, rotate leftover `issuer.secret`, and log verify on a broken chain found no other working bypass. No sixth record. No new command-line interface. No twenty-fourth demonstration.
37. Issuer-record persist hunt (STE100). `save_issuer` did not freeze current_public_key, public_keys, or previous_issuer_keys. A later persist could swap current to a foreign key, grow public_keys with an attacker key, postpone or drop a previous-key kill_date, or add a foreign previous key, then verify would accept that foreign or stolen key. The checks now live on `save_issuer`. Rotate writes the new issuer secret first, then persists the new current and records the old key. A shorter previous-key kill_date may persist. Emptying accepted_issuer_public_keys is not allow-all: verify still uses the current key and refuses a foreign signature. threshold_n, crypto_profile, and issuance_log do not skip verify; changing them is not a lock. Hunt found no working raise on those unused fields. No sixth record. No new command-line interface. No twenty-fourth demonstration.
38. Capability-record persist hunt (STE100). `save_capability` froze only `expires`. A later persist could widen intent or audience on the same capability identifier and keep the original narrow token. Token-versus-record already refuses a wider token. Present copies intent and audience from the record, so the widened record presented those wider fields. A later persist that also replaced biscuit with a wider token and matched the record fields made verify and check allow the wider request. A later persist that changed `on_behalf_of` from a named user to autonomous and swapped in an autonomous token also allowed. The checks now live on `save_capability`. After the first write, intent and audience must stay narrower or equal (`is_narrower_or_equal`; the reverse is a raise). `on_behalf_of` and `instance_id` must not change. Token bytes must not change. Narrowing may persist. The same values may persist. Hunt found no working raise on moving `issued` earlier, changing `revoke_identifier` (kill uses the log and the token), or clearing `caveats` (evaluate does not honor that map). No sixth record. No new command-line interface. No twenty-fourth demonstration.
39. Issuer signatures on instance and capability records (STE100). Instance and capability records gain `issuer_signature_hex` and `issuer_public_key_hex`. The kernel re-signs with the current issuer secret on every successful `save_instance` and `save_capability`. A caller cannot persist an arbitrary signature. Evaluate, verify, check, host, and present recompute the documented concatenation and refuse a missing, wrong, or untrusted signature. The signature key must be the current key or a previous key still before `kill_date`. Rotate re-signs every stored instance and capability so an old capability still verifies after the previous-key `kill_date`. A file planted in the data directory cannot act. This is not a sixth record. No twenty-fourth demonstration.
40. Issuer signatures on agent type records (STE100). Agent type records gain `issuer_signature_hex` and `issuer_public_key_hex`. The kernel re-signs with the current issuer secret on every successful `save_agent_type`. Freeze raises still refuse before a signature is written. Mint, birth, spawn, and evaluate recompute the documented concatenation and refuse a missing, wrong, or untrusted signature. The signature key must be the current key or a previous key still before `kill_date`. Rotate re-signs every stored agent type with the instances and capabilities. A planted type with a wider `authorization_limit` or an extra intent cannot mint. This is not a sixth record. No twenty-fourth demonstration.
41. Issuer signatures on chain records (STE100). The hunt found that evaluate, attenuate, and spawn trust `hop_index` and `revoke_from_here` from disk as an authorization input. A planted chain with a lower hop index would grant more hops. A planted chain that clears `revoke_from_here` would revive a killed chain. Chain records gain `issuer_signature_hex` and `issuer_public_key_hex`. The kernel re-signs with the current issuer secret on every successful `save_chain`. Freeze raises still refuse before a signature is written. Evaluate, verify, check, host, present, attenuate, and spawn recompute the documented concatenation and refuse a missing, wrong, or untrusted signature. Rotate re-signs every stored chain with the agent types, instances, and capabilities. A planted chain cannot act. This is not a sixth record. No twenty-fourth demonstration.
42. Issuer signatures on issuance-log lines (STE100). Each log line carries `issuer_signature_hex` over a documented concatenation of the line fields excluding the signature itself. The kernel signs with the current issuer secret on append. `line_hash` excludes the signature. log verify checks the hash chain and the signature. A hash-chain-only append without `issuer.secret` fails log verify and receipt-line bind. This is still a local log. This is not Certificate Transparency. This is not a sixth record. No new command-line interface. No twenty-fourth demonstration.
43. Rotate must not launder a planted file (STE100). `save_*` of an existing record now requires the stored issuer signature to already be trusted. A planted unsigned or forged file cannot be persisted or re-signed. Rotate skips those files instead of giving them a current-key signature. A planted wider agent type still cannot mint after rotate. A planted chain that clears `revoke_from_here` still cannot revive a child after rotate. Honest records still re-sign. This is not a sixth record. No new command-line interface. No twenty-fourth demonstration.
44. Remaining launder / re-sign / copy hunt (STE100). Hunt of spawn, attenuate, kill, birth, mint, present, and first-write save found no path that writes a current-key signature onto on-disk JSON without first verifying the stored issuer signature. Spawn and attenuate verify the parent instance, capability, chain, and type before they write a signed child. Birth and mint verify the type. Kill of a planted file is refused at save and would not be a raise if it only wrote revoked. Rotate still skips untrusted files. No sixth record. No new command-line interface. No twenty-fourth demonstration.

45. Laboratory Module-Lattice Digital Signature Algorithm issuer profile (STE100). Issuer init creates an ML-DSA-65 current key (`fips204` crate, FIPS 204 parameter set ML-DSA-65) and a laboratory Biscuit Ed25519 envelope key stored as `biscuit_public_key_hex` plus `biscuit.secret`. Profile `lab-ed25519` as the only issuer signature algorithm is refused. Birth and mint refuse a classical-only current root. Rotate changes the Module-Lattice current key only and keeps the Biscuit envelope key. Accept-list keys are Module-Lattice hexadecimal public keys. Record, log-line, receipt, and tree-head signatures verify Module-Lattice. Biscuit tokens still verify with the envelope Ed25519 key. The Biscuit key must not sign records, log lines, receipts, or tree heads. Present stays a document. The instance identifier must not become an X.509 name. This is not a sixth identity record. This is not a production FIPS module. This is not a post-quantum Biscuit. No twenty-fourth demonstration.

46. Multi-signature issuance (STE100). A mint, birth, spawn, save-sign, log-append, receipt, or tree-head is valid only when at least `threshold_n` distinct Module-Lattice Digital Signature Algorithm 65 signatures from trusted issuer member keys verify over the same documented concatenation. Init still writes `threshold_n` 1. When `threshold_n` is 1, one current key signs, the same as before. `prometheus issuer member add` installs a second Module-Lattice key pair and writes `issuer-member-*.secret` under the data directory (gitignored). Trusted signing members are the current Module-Lattice public key plus additional member public keys stored on `public_keys`. `prometheus issuer threshold --n K` refuses K less than 1, refuses K greater than the trusted member count, and refuses lowering. Raising is allowed. Need two members before `--n 2`. The Biscuit envelope key is not a member. Rotate still rotates the current Module-Lattice key only. `threshold_n` is unchanged. The previous key remains a member until `kill_date`. Planted files and rotate-launder still refuse untrusted stored signatures. For n=2, a record with only one valid signature refuses evaluate. Honest cryptographic bound: this is not a Shamir split of `issuer.secret` (that reconstitutes one key on one host; not threshold). This is not FROST or threshold Edwards-curve Digital Signature Algorithm on Curve 25519 as the identity root (that root would be classical). This is not Federal Information Processing Standard 204 threshold Module-Lattice Digital Signature Algorithm (that scheme is not what this laboratory ships). This is multi-signature issuance. This is not a sixth identity record. `scripts/demo_threshold.sh` is the twenty-fourth demonstration.

47. Laboratory operator status and one walkthrough (STE100). `prometheus status` prints a derived operator view of this store: `crypto_profile`, the current issuer public key (first eight and last eight hexadecimal characters plus length), the honest line that the identity root is Module-Lattice Digital Signature Algorithm 65 and the Biscuit envelope is laboratory Ed25519 and is not a threshold member, `threshold_n`, member count, sealed or not (`kill_date`), counts of agent types, instances (live and revoked), capabilities, and chains, issuance-log leaf count, Merkle root (the existing log root), and the loopback reminder that the check host must bind to 127.0.0.1 only. Status refuses if the issuer is missing. Status does not print secrets. Status is a view. Status is not a sixth identity record. `scripts/demo_walkthrough.sh` is one short walkthrough: init, status, agent-type add plus birth, challenge plus check, present plus present verify, act export plus act accept, status again, and one fail-closed refuse. This is not a graphical user interface. This is not Sanctum.

## What is evidenced

- `cargo test` covers authorization limit, missing holder proof, stolen token without the holder key, missing challenge nonce, spent nonce, expired challenge window, intent decrease, birth write, hop depth, spawn, check audit, named capability, parent kill cascade, expiry, loopback bind refusal, act authority match and mismatch, a missing `on_behalf_of`, an empty `on_behalf_of`, a tampered record whose token still names the original act authority, expired capability on the host check path, a refused autonomous child from a named-user parent, an accepted child of that same user, an accepted autonomous child from an autonomous parent, an allowed receipt that verifies, a refused receipt that verifies, a tampered receipt result that fails, a receipt signed by a foreign key that fails, a receipt whose bound issuance-log line was deleted or altered that fails while the signature stays valid, an intact issuance-log hash chain that verifies, a deleted middle log line that fails, an altered log field that fails, an own-key receipt that verifies, an unknown issuer key that fails, an accepted foreign key plus the foreign issuance log that succeeds, an accepted foreign key without the foreign log line that fails, an empty accept that fails, issuer rotate that replaces issuer.secret with the new key only and stores the old public key with a kill_date, an old receipt that verifies before kill_date and still verifies after kill_date because rotate only kills new minting, an old capability that verifies after rotate until capability expiry, a new birth after rotate that signs with the current key only, and a forged-not-in-log token or receipt signed with a stolen old secret after kill_date that fails. An injected three-leaf proof checks against its root, a tampered sibling fails, a missing line_hash fails to prove, an old proof still checks against the old root and fails against the new root after a new append, an empty proof fails, and a truncated sibling list fails. A signed tree head verifies with the current issuer key, a tampered Merkle root fails, an unknown issuer key fails, a second store can pin a foreign tree head after accepting the key, rotate then a new signed tree head uses the new key only while the old tree head still checks as a historical pin after `kill_date`, a previous key used to sign after `kill_date` fails, `--require-current-root` fails after a new append, and an empty signature, a missing `leaf_count`, and an empty document fail closed. Birth then a mutated `holder_public_key` save is refused. A spawned child has its own holder key; changing the child key later is refused. Changing the parent holder key is refused. Kill and revoke leave `holder_public_key` unchanged. A new instance with a holder key still succeeds. `prometheus instance rebind` always refuses. Seal 60 seconds; at T+30 mint works; at T+60 mint, birth, spawn, rotate, accept, and sign-root refuse; verify and check refuse even if the capability is unexpired and do not sign a new receipt; `receipt verify` of a pre-seal receipt still succeeds. After-seconds of zero is refused. A later seal cannot postpone death. A later seal that only shortens remaining life is allowed. Realm `issuer.kill_date` is not written onto `previous_issuer_keys`. Export after a real check receipt then accept on a second store that accepted the first public key succeeds. A second store without that accept-list key refuses. A tampered receipt in the bundle refuses. A proof sibling tamper refuses. A tree-head root tamper refuses. A missing proof file refuses. A `line_hash` mismatch between the receipt bound line and the proof refuses. Accept does not write a second `issuance.log` line and does not create instance records. Present then verify succeeds. A capability that does not belong to the named instance refuses. A spent challenge nonce refuses. An expired presentation refuses when the test injects a clock to `expires_at`. A tampered intent refuses. A second store that accepted the first public key verifies the presentation and does not write instance records or a second `issuance.log` line. A second store without that accept-list key refuses. A revoked instance refuses. A sealed issuer refuses present. A missing challenge nonce refuses. Create an agent type then persist a raised `authorization_limit` is refused. The same raise after an instance exists is refused. A shorter prefix is a raise and is refused. Narrowing to a child of the stored limit may persist. The same limit may persist. `prometheus agent-type raise` always refuses, with zero instances and after an instance exists. After a refused raise the instance still cannot mint above the stored type limit and can still mint a child destination of that limit. Mint then a mutated later `expires` save is refused. A shorter `expires` may persist. The same `expires` may persist. `prometheus capability extend` always refuses. Attenuation creates a new capability identifier whose `expires` does not exceed the parent. A child expiry after the parent is refused. Mint a narrow capability then swap in a token with a wider audience: verify and present refuse. Swap in a token with a wider intent: check refuses. Swap in a token with a different `on_behalf_of` or a different `instance_id`: verify refuses. An honest attenuated child still verifies against its narrower record. The evaluate-boundary helper refuses a constructed wider-audience token, a wider-intent token, a different act authority, and a different instance identifier, and still accepts an attenuated token whose checks constrain the parent facts. Create a type with two intents then persist a third is refused. Persist with one of the two may persist. Mint of the removed intent then fails. The same set may persist. `prometheus agent-type add-intent` always refuses. A later persist that raises `max_delegation_depth` is refused. A lower depth may persist. The same depth may persist. Birth then a mutated later instance `expires` save is refused. A shorter instance `expires` may persist. The same instance `expires` may persist. After a refused instance expiry extension, mint past the original expiry still fails. Swapping `agent_type_id` to a more powerful type is refused. The same type may persist. After a refused swap, mint still uses the original type. Clearing a child `parent_instance_id` is refused. Setting a revoked instance back to live is refused. After a refused un-revoke, mint still fails. A later persist that raises `lifetime_seconds` is refused. A lower lifetime may persist. The same lifetime may persist. A later persist that decreases chain `hop_index` is refused. The same hop index may persist. Clearing `revoke_from_here` after kill is refused. The child still refuses verify. Clearing chain `parent_capability_id` is refused. Mint `internal/pay` then check `internal/payroll` is refused. Mint `read` then verify `readwrite` is refused. Check `internal/pay/refunds` against `internal/pay` is allowed. The host `POST /check` path refuses the same sibling-prefix audience. Seal then a mutated later `issuer.kill_date` save is refused. Clearing `issuer.kill_date` is refused. A shorter `issuer.kill_date` may persist. After a refused postpone, mint at the original seal time still fails. Swapping `current_public_key` without rotate is refused; a foreign receipt still fails and an honest receipt still verifies. Growing `public_keys` with an attacker key is refused; a token signed by that key still fails verify. Postponing a previous-key `kill_date` is refused; a stolen old key still fails check-root after the original kill_date. Removing a previous issuer key is refused; the stolen old key is still previous. Adding a foreign previous key is refused. A shorter previous-key `kill_date` may persist. Emptying `accepted_issuer_public_keys` is not allow-all. Changing `threshold_n`, `crypto_profile`, or `issuance_log` does not skip verify. Mint a narrow capability then persist a widened intent is refused; present still copies the original intent. Persist a widened audience is refused; present still copies the original audience. A narrower intent or audience may persist. The same intent or audience may persist. Changing `on_behalf_of` from a named user to autonomous is refused. Changing `on_behalf_of` from user A to user B is refused. The same `on_behalf_of` may persist. Swapping `instance_id` is refused. The same `instance_id` may persist. Swapping biscuit for a wider token is refused. Swapping biscuit and widening the matching record fields is refused; verify of the wider request still fails and present still copies the original audience. Changing `on_behalf_of` to autonomous and swapping in an autonomous token is refused; check of autonomous still fails. Birth and mint persist instance and capability records with valid issuer signatures. Stripping a signature refuses verify, check, and present. Flipping one signature hexadecimal nibble refuses verify. Planting a new capability JSON with no signature in the store directory refuses check. Changing the instance or capability identifier in memory fails the recomputed signature. Persist-raise tests still refuse before a signature is written. Add an agent type persists a valid issuer signature. Stripping that signature refuses mint, verify, and check. Planting a type JSON with a wider limit and no signature refuses birth and mint. A forged type signature refuses mint. Flipping one type signature hexadecimal nibble refuses mint and evaluate. Birth and mint persist a chain with a valid issuer signature. Attenuation persists a signed child chain. Stripping a chain signature refuses verify, check, and present. Flipping one chain signature hexadecimal nibble refuses verify and attenuate. Planting a killed parent chain with `revoke_from_here` cleared and no signature refuses the child verify and check. Planting a lower `hop_index` with no signature refuses attenuate and spawn. Rotate re-signs stored chains with the current secret. Rotate does not write a trusted signature onto a planted wider agent type or a planted chain that clears revoke-from-here. Persist of a planted unsigned existing type or chain is refused. Spawn, attenuate, birth, and mint refuse a planted parent or type before a signed child is written. Kill of a planted file is refused at save. Honest issuance-log append verifies the hash chain and each line issuer signature. Stripping a line signature refuses log verify. Flipping one line signature hexadecimal nibble refuses log verify. A well-hashed append without a valid issuer signature refuses log verify. A receipt bound to an unsigned line refuses. Issuer init with profile `lab-ed25519` refuses. Default init writes a Module-Lattice current key and a Biscuit envelope Ed25519 key. A planted Ed25519-only current root refuses birth. A stripped or flipped Module-Lattice signature refuses. A Biscuit token still verifies with the envelope Ed25519 key. Init still writes `threshold_n` 1. Setting n=2 with only one member is refused. Adding a second member then setting n=2 succeeds. Mint and birth with one secret when n=2 are refused. Mint with two member secrets when n=2 succeeds and the record verifies. Stripping one of two signatures refuses evaluate. A Biscuit envelope key used as a member signature does not count. `threshold_n` cannot be lowered. A classical-only root is still refused. Persist-raise and planted-file tests still pass. `prometheus status` refuses a missing issuer. Status after init shows an empty store with `threshold_n` 1, one member, zero records, and the empty-log Merkle root. Status after birth counts one type, one live instance, one capability, and one chain. Status does not include `issuer.secret` or `biscuit.secret`. `cargo test` covers 233 tests. All twenty-four focused demonstrations and the one walkthrough still pass.
- `scripts/demo.sh` shows mint inside the limit, mint above the limit, verify with a holder proof and a one-time challenge, verify without a holder proof, attenuate, and kill.
- `scripts/demo_birth.sh` shows one `birth_write` event and no separate mint event.
- `scripts/demo_depth.sh` shows three hops and a refused fourth hop.
- `scripts/demo_spawn_child.sh` shows a parent check, a narrower child, and a refused wider child.
- `scripts/demo_internal_versus_public.sh` shows the same intent allowed for `internal` and refused for `public`.
- `scripts/demo_host.sh` shows `POST /check` on `127.0.0.1`, a refused bind to all interfaces, and a refused check that omits `capability_id`.
- `scripts/demo_parent_kill.sh` shows a live child check, a parent kill, and a refused child check and child verify.
- `scripts/demo_tool_loop.sh` shows a live host, an accepted internal tool, a refused public destination, and a refused spent challenge.
- `scripts/demo_on_behalf.sh` shows an autonomous capability, a capability on behalf of `jordan`, matching checks, refused wrong act authorities, and a refused check that omits `on_behalf_of`.
- `scripts/demo_spawn_authority.sh` shows a parent on behalf of `jordan`, a refused autonomous child, and an accepted child that keeps `jordan` in the child token.
- `scripts/demo_receipt.sh` shows an allowed check, a saved receipt that verifies, a copy of the store with the matching issuance-log line removed that fails receipt verify, and a receipt whose result field was changed that fails verify.
- `scripts/demo_log_chain.sh` shows several issuance events, a successful `log verify`, an altered line, and a refused `log verify`.
- `scripts/demo_accept_issuer.sh` shows two stores, the second accepting the first public key, the second verifying the first receipt against the first issuance.log, a refused verify without that foreign log line, and a refused third issuer key that was never accepted.
- `scripts/demo_issuer_rotate.sh` shows rotate, a new birth that works, an old capability that still verifies before kill_date, an old receipt that still verifies, and a forged-not-in-log receipt that fails.
- `scripts/demo_log_proof.sh` shows birth, `log root`, prove the birth line, check-proof accepted, a tampered sibling refused, a second birth that changes the root, and the old proof refused against the new root and accepted against the old root.
- `scripts/demo_sign_root.sh` shows birth, `log sign-root`, check-root accepted, a tampered Merkle root refused, rotate then a new sign-root that uses the new key, and the old signed tree head still accepted as a historical pin.
- `scripts/demo_first_binder.sh` shows birth, `instance show` of the first binder, a refused `instance rebind`, an unchanged `holder_public_key`, and a kill that leaves the first binder in place.
- `scripts/demo_issuer_seal.sh` shows birth, a saved receipt, `issuer seal --after-seconds 2`, a refused birth after death, a refused verify after death, and `receipt verify` of the earlier receipt still accepted.
- `scripts/demo_act_bundle.sh` shows store A birth plus check plus export, store B issuer init plus accept of A's public key plus `act accept` succeeding, and a tampered receipt in the bundle refusing.
- `scripts/demo_present.sh` shows challenge, present, present verify accepted, a spent challenge refused, and a tampered intent refused. Expiry is covered by the injected-clock unit test.
- `scripts/demo_limit_freeze.sh` shows agent-type add, a refused raise with zero instances, an unchanged stored limit, birth, a refused raise after an instance exists, mint inside the stored type limit accepted, and mint above the stored type limit refused.
- `scripts/demo_expiry_freeze.sh` shows birth (first persist sets `expires`), a refused `capability extend`, an unchanged stored `expires`, and an attenuated child whose expiry does not exceed the parent.
- `scripts/demo_intent_freeze.sh` shows agent-type add with two intents, a refused `agent-type add-intent` with zero instances, an unchanged stored set, birth, a refused add-intent after an instance exists, mint of a stored intent accepted, and mint of an unstored intent refused.
- `scripts/demo_threshold.sh` shows init `threshold_n` 1, a refused `--n 2` with one member, a second member, `--n 2` accepted, a refused birth with one secret, a birth with two member secrets, and a refused evaluate after one of two signatures is stripped.
- `scripts/demo_walkthrough.sh` shows init, empty-store status, one birth write, an allowed check, present plus present verify, act export plus act accept on the same store, status after issuance, and a refused check with the wrong act authority.
- The host-path unit test refuses an expired capability without a long sleep. The kernel check path already did this. The host path now does the same.

## What is new versus other agent identity products

- **Microsoft Entra Agent ID**: Entra names and catalogs agents next to users and applications. Prometheus treats identity as an authorized act: the first capability is issued in the same write as the instance. A name is not a key. Prometheus does not use Microsoft catalog names.
- **Oasis NHI / non-human identity catalogs**: those products inventory machine identities. Prometheus is a kernel that a host can ask before a tool action. The market hook is allow or refuse, not a directory listing.
- **OAuth on agents**: OAuth issues bearer access tokens. Prometheus refuses a capability token presented without a holder proof that answers a one-time challenge. That choice keeps room for later proof of possession. This laboratory holder challenge is not a production proof of possession.

This comparison is honest. Prometheus is laboratory code. Prometheus does not replace those products.

## What is still open

- Shamir split of `issuer.secret`, FROST or threshold Edwards-curve Digital Signature Algorithm on Curve 25519 as the identity root, and Federal Information Processing Standard 204 threshold Module-Lattice Digital Signature Algorithm. This laboratory ships multi-signature issuance: at least `threshold_n` distinct trusted Module-Lattice member signatures over the same documented concatenation. That is not a Shamir split, not FROST, and not FIPS 204 threshold Module-Lattice Digital Signature Algorithm.
- A production FIPS module and a post-quantum Biscuit. The laboratory identity root is now Module-Lattice Digital Signature Algorithm 65 (`fips204`, profile `lab-ml-dsa-65-hybrid-biscuit-ed25519`). The Biscuit envelope is still laboratory Ed25519. This is not a production FIPS module. This is not a post-quantum Biscuit.
- A public transparency log. The JSON line log is local only. The hash chain is a local SHA-256 chain, not a public append-only service. The Merkle tree is a local inclusion index over those line_hash values. The signed tree head is a locally signed Merkle root, not Certificate Transparency, not a gossip protocol, not a public log, and not a multi-witness signed tree head. The decision receipt is a laboratory signature bound to that local log line. The receipt is not a public transparency log. STE100 does not make this a public transparency log.
- A remote challenge protocol. The nonce and the time window are local. This is not a production proof of possession.
- A secret holder. A secret holder is out of scope. Sanctum can hold secrets later.
- SPIFFE as a thin presenter only. SPIFFE is not identity in this package.
- A global name system or SPIFFE federation. The accept list is local to one store. A second store can verify a foreign receipt, or accept a local act bundle after that same accept-list step. That second store is not a second identity kernel. The act bundle is not a global name system and not Certificate Transparency gossip.

## How to run every demonstration

```
cargo test
bash scripts/demo.sh
bash scripts/demo_birth.sh
bash scripts/demo_depth.sh
bash scripts/demo_spawn_child.sh
bash scripts/demo_internal_versus_public.sh
bash scripts/demo_host.sh
bash scripts/demo_parent_kill.sh
bash scripts/demo_tool_loop.sh
bash scripts/demo_on_behalf.sh
bash scripts/demo_spawn_authority.sh
bash scripts/demo_receipt.sh
bash scripts/demo_log_chain.sh
bash scripts/demo_accept_issuer.sh
bash scripts/demo_issuer_rotate.sh
bash scripts/demo_log_proof.sh
bash scripts/demo_sign_root.sh
bash scripts/demo_first_binder.sh
bash scripts/demo_issuer_seal.sh
bash scripts/demo_act_bundle.sh
bash scripts/demo_present.sh
bash scripts/demo_limit_freeze.sh
bash scripts/demo_expiry_freeze.sh
bash scripts/demo_intent_freeze.sh
bash scripts/demo_threshold.sh
bash scripts/demo_walkthrough.sh
```

`prometheus --data-directory ./data status` prints the laboratory operator view. Status refuses if the issuer is missing. Status does not print secrets.

## Security rules that this package keeps closed

- Missing holder proof, missing challenge nonce, spent nonce, challenge past its window, missing capability identifier, missing `on_behalf_of`, empty `on_behalf_of`, missing issuance-log line, expired, revoked, over authorization limit, over hop depth, a wrong act authority, a token act authority that does not match the request, and a child act authority that widens the parent to autonomous are refused.
- A parent kill stops child instances and the capabilities in those chains.
- There is no force-allow command and no debug bypass.
- The check host binds to a loopback address only.
- Secret material is not written to the issuance log.
- Secret material is not written to the decision receipt.
- A tampered decision receipt, a receipt with no signature, a receipt signed by a key that is not on `accepted_issuer_public_keys`, and a receipt whose issuance-log line is missing or altered are refused. A signature alone is not enough.
- A broken issuance-log hash chain is refused. A missing `previous_line_hash`, a missing `line_hash`, a wrong previous hash, and a wrong line hash fail closed.
- An empty issuer public key cannot be added to the accept list. A foreign receipt without the foreign issuance-log line is refused even when the foreign key was accepted.
- After rotate, `issuer.secret` holds the new key only. A previous issuer key after `kill_date` cannot mint. A new capability or receipt signed with a stolen old secret is refused because it is not in the issuance log and because the signature key is a previous key past `kill_date`, even if the signature is valid.
- A Merkle inclusion proof for a `line_hash` that is not in this log is refused. An empty proof, a truncated sibling list, a leaf that is not the claimed `line_hash`, and a proof whose recomputed root does not match the expected root are refused. An old proof is accepted only against the old root.
- A signed tree head with an empty `leaf_count`, a missing Merkle root, or a missing signature is refused. A tampered Merkle root with valid-looking other fields is refused. An unknown issuer key is refused. A previous issuer key used to sign after its `kill_date` is refused. A new signed tree head uses the current issuer secret only.
- A later persist that replaces `holder_public_key` is refused. An empty holder public key is refused. `prometheus instance rebind` always refuses. Kill, revoke, expire, and parent-kill do not rewrite the first binder.
- After `issuer.kill_date` this store refuses new mint, birth, spawn, issuer rotate, issuer accept, `log sign-root`, present, attenuation, and act (verify, check, host). Historical `receipt verify` of an already-written receipt still succeeds. Historical `present verify` of an already-written presentation still succeeds. A later seal cannot postpone death. After-seconds of zero is refused.
- An act bundle missing `receipt.json`, `proof.json`, or `tree-head.json` is refused. A receipt whose bound line is not in this store's log cannot be exported. A sealed issuer cannot export because `sign-root` refuses. Accept refuses a second store that did not accept the first public key, a tampered receipt, a tampered proof sibling, a tampered tree-head root, and a `line_hash` mismatch between the receipt bound line and the proof. Accept does not mint and does not write a second `issuance.log` line.
- A presentation from a revoked instance, an expired capability, a capability that does not belong to the instance, a sealed issuer, or a missing or spent challenge is refused. A presentation with a missing signature, a tampered field, an unknown issuer key, or `now >= expires_at` is refused. Present verify does not mint and does not write instance records. Present is a document, not a name.
- A later persist that raises an existing agent type `authorization_limit` is refused, instances or not. A shorter prefix or a new prefix that is not a child of the stored limit is a raise. The comparison is the same function mint and spawn use. `prometheus agent-type raise` always refuses. The instance still cannot mint above the stored type limit.
- A later persist that moves an existing capability `expires` later is refused. A shorter expiry may persist. The same expiry may persist. `prometheus capability extend` always refuses. An attenuated child must not expire after the parent.
- A capability token whose facts exceed or contradict the capability record is refused on verify, check, host, and present. A wider intent, a wider audience, a different `on_behalf_of`, or a different `instance_id` is a golden-ticket-class lie. An honest attenuated child whose checks constrain the parent facts still verifies.
- A later persist that adds an intent string to an existing agent type `allowed_intents` is refused. Removing an intent may persist. The same set may persist. `prometheus agent-type add-intent` always refuses. A later persist that raises `max_delegation_depth` is refused. A lower depth may persist.
- A later persist that moves an existing instance `expires` later is refused. A shorter instance expiry may persist. The same instance expiry may persist. A later persist that replaces `agent_type_id` is refused. A later persist that clears or replaces `parent_instance_id` is refused. A later persist that sets a revoked instance back to live is refused.
- A later persist that raises an existing agent type `lifetime_seconds` is refused. A lower lifetime may persist. The same lifetime may persist.
- A later persist that decreases an existing chain `hop_index` is refused. The same hop index may persist. A later persist that clears or replaces `parent_capability_id` is refused. A later persist that clears `revoke_from_here` after it is true is refused.
- A requested intent or audience that is a string prefix of the capability but not a child path is refused on verify, check, and host. `internal/payroll` is not inside `internal/pay`. `readwrite` is not inside `read`. A true child path still allows.
- A later persist that moves an existing issuer `kill_date` later is refused. A later persist that clears `issuer.kill_date` is refused. A shorter issuer death may persist. The same death time may persist. After a refused postpone, mint still fails at the original seal time.
- A later persist that swaps `current_public_key` without rotate is refused. Rotate writes the new issuer secret first. A later persist that grows `public_keys` with a foreign key is refused. A later persist that removes a previous issuer key is refused. A later persist that moves a previous-key `kill_date` later is refused. A later persist that adds a previous key that was never this store current key is refused. A shorter previous-key `kill_date` may persist. Emptying `accepted_issuer_public_keys` is not allow-all. `threshold_n`, `crypto_profile`, and `issuance_log` do not skip verify.
- A later persist that widens an existing capability `intent` is refused. A later persist that widens an existing capability `audience` is refused. A narrower intent or audience may persist. The same values may persist. A later persist that replaces `on_behalf_of` is refused. A later persist that replaces `instance_id` is refused. A later persist that replaces `biscuit` is refused. Present copies intent and audience from the record, so those fields must not widen after the first write.
- An instance or capability record whose issuer signature is missing, wrong, or not from the current key or a previous key still before `kill_date` is refused on evaluate, verify, check, host, and present. A planted file in the data directory cannot act. The store JSON is not enough. The kernel overwrites any caller-supplied signature on a successful save. Rotate re-signs stored records with the current secret.
- An agent type record whose issuer signature is missing, wrong, or not from the current key or a previous key still before `kill_date` is refused on mint, birth, spawn, and evaluate. A planted type with a wider `authorization_limit` or an extra intent cannot mint. Freeze raises still refuse before a signature is written. Rotate re-signs stored agent types with the current secret.
- A chain record whose issuer signature is missing, wrong, or not from the current key or a previous key still before `kill_date` is refused on evaluate, verify, check, host, present, attenuate, and spawn. A planted chain with a lower `hop_index` cannot grant more hops. A planted chain that clears `revoke_from_here` cannot revive a killed chain. Freeze raises still refuse before a signature is written. Rotate re-signs stored chains with the current secret.
- A hash-chain-only issuance-log append without `issuer.secret` is refused. Each log line carries `issuer_signature_hex` over `line_hash` and `issuer_public_key_hex`. `prometheus log verify` checks the hash chain and the signature. Receipt verify still requires the bound line to match and that line's signature to verify. This is still a local log. This is not Certificate Transparency.
- A later persist of an existing agent type, instance, capability, or chain whose stored issuer signature is missing, wrong, or untrusted is refused. Rotate skips that file. Rotate must not launder a planted record. A planted wider type still cannot mint. A planted cleared revoke-from-here still cannot revive a child.
- A mint, birth, spawn, save-sign, log-append, receipt, or tree-head with fewer than `threshold_n` distinct trusted Module-Lattice member signatures is refused. Missing, untrusted, duplicate-key, and Biscuit-envelope signatures do not count. Setting `threshold_n` less than 1 is refused. Setting `threshold_n` greater than the trusted member count is refused. Lowering `threshold_n` is refused. Mint with one secret when `threshold_n` is 2 is refused. The Biscuit envelope key is not a member.




## STE100 — Receipt binds to the issuance log

A decision receipt used to verify by signature alone. A third party could accept a signed allow after the matching check or verify line was deleted from `issuance.log`. That made later transparency enforcement harder.

Every decision receipt now includes `issuance_log_line`: the exact JSON line of that check or verify event as written to `issuance.log`. `prometheus receipt verify` still requires a valid issuer signature. It also fail-closes when that line is missing from `issuance.log` or when the stored line does not match. Deleting or altering the log line refuses the receipt. Keeping the signature and omitting the log line refuses the receipt.

This is still a local JSON line log. This is not a public transparency log. This is not threshold issuance.

## STE100 — Issuance log hash chain

A receipt already binds to one exact issuance-log line. A third party could still delete or insert a middle line and keep a later bound line present. That made later public transparency harder to enforce.

Each `issuance.log` JSON line now includes `previous_line_hash` and `line_hash`. Both are SHA-256 hexadecimal digests. The first line uses the documented empty-hash: SHA-256 of empty input. `line_hash` is the digest of the compact JSON serialization with the `line_hash` field omitted. `prometheus log verify` walks the file and fail-closes on a missing field, a wrong previous hash, or a wrong line hash. `prometheus receipt verify` walks the same chain first, then requires the bound line to still be present.

This is a local hash chain. This is not a public append-only service. This is not a public transparency log. This is not threshold issuance.

## STE100 — Issuer accept list

A decision receipt used to verify only against this store's own issuer public key. A second Prometheus store could not check a first-store receipt without copying the first issuer secret or becoming a second identity kernel. That made later federation harder to keep honest.

The issuer record now stores `accepted_issuer_public_keys`. Init always includes this store's own public key. `prometheus issuer accept --public-key-hex <hex>` adds a key and persists `issuer.json`. Empty is refused. The field lives on the existing issuer record. It is not a sixth identity record.

`prometheus receipt verify --receipt FILE [--issuance-log PATH]` uses that accept list. If `--issuance-log` is omitted, this store's `issuance.log` is used. The signing key must be on the list. The chosen issuance log must hash-chain verify and contain the bound line. A receipt signed by an unknown key fails. A receipt signed by an accepted foreign key fails unless the foreign log line is present in the chosen log.

A second store can verify a first-store receipt without holding the first issuer secret and without issuing identities for the first store. The second store does not become a second identity kernel.

This is an accept list. This is not a global name system. This is not SPIFFE federation. This is not a public transparency log. This is not threshold issuance.

## STE100 — Issuer key rotation with a kill date

A stolen old issuer key used to mint forever. That is the golden-ticket class: rotate the store secret and the old key still signs new capabilities that later verify.

`prometheus issuer rotate [--kill-after-seconds N]` creates a new laboratory key pair. The old public key is stored on `previous_issuer_keys` with `kill_date` equal to now plus a short laboratory window, or the given seconds. `issuer.secret` is the new key only. New mint, birth, spawn, and receipts sign with the current key only. The old public key stays on the accept list until `kill_date`.

Fail-closed design:

- After rotate, new acts use the new key.
- Old capabilities verify until capability expiry. Rotate does not revoke already-issued capabilities.
- `kill_date` on an old key means that key must not sign new mint, birth, or spawn. The store no longer has that secret.
- If an attacker stole the old secret after rotate, they cannot mint through this store because `issuer.secret` is the new key only.
- If they mint offline, verify fail-closes because the new capability is not in the issuance log, and because the signature key is a previous key past `kill_date`.
- Receipt verify: the current key is always accepted if it is on the accept list. A previous key is accepted only when now is before `kill_date`. After `kill_date`, a new signature from the old key is refused even if the signature is valid. An old receipt that is already bound to an issuance-log line still verifies, because rotate only kills new minting.

This is laboratory single-key rotate. This is not threshold issuance. This is not a production FIPS module. This is not a post-quantum Biscuit. This is not a sixth identity record.

## STE100 — Local Merkle inclusion proof

Honest bound:

- This is a local Merkle tree over the hash-chained issuance log. It is not a public transparency log, not Certificate Transparency, not a gossiped signed tree head across the internet.
- It does not add a sixth record. Proofs are derived from the existing `issuance.log` lines.

A second store used to need the whole foreign issuance log to check that one mint existed. That pushed the accept-list path toward copying the log or becoming a second identity kernel.

After each append the store can compute a Merkle root over the sequence of `line_hash` values. The hash chain is unchanged. Merkle is an inclusion index on top of it.

Leaf choice: `line_hash` is already SHA-256 of the documented canonical line (compact JSON with the `line_hash` field omitted). The Merkle leaf is that existing `line_hash`. The leaf is not SHA-256 of the line_hash hexadecimal text. This is not a third hash chain.

Internal node: SHA-256 hexadecimal digest of the UTF-8 bytes of the left digest concatenated with the right digest. A single leaf is its own root and is not padded. Two or more leaves are padded to the next power of two with the documented empty-hash so a verifier can walk `sibling_hashes` from `leaf_index` without a stored tree.

`prometheus log root` prints the current Merkle root hexadecimal and the leaf count. An empty log uses the documented empty-hash and leaf count 0.

`prometheus log prove --line-hash HEX` writes a proof JSON with `line_hash`, `leaf_index`, `sibling_hashes` in order, and `root`. Fail closed if the line is not in this log.

`prometheus log check-proof --proof FILE [--root HEX]` recomputes the root from the proof. If `--root` is omitted, this store's current root is used. A supplied root lets a second store check one logged mint without copying the log and without becoming a second identity kernel. Refuse an empty proof, a truncated sibling list, a proof whose leaf is not the claimed `line_hash`, or a recomputed root that does not match.

The decision receipt does not carry `issuance_log_root`. Adding that field would change the signed receipt message. Prove and check-proof are the smaller honest surface.

This is a local Merkle tree. This is not a public transparency log. This is not Certificate Transparency. This is not a gossiped signed tree head. This is not a sixth identity record.

## STE100 — Locally signed Merkle tree head

Honest bound:

- This is a locally signed Merkle root. It is not Certificate Transparency, not a gossip protocol, not a public log, and not a multi-witness signed tree head.
- It does not add a sixth record. The signed tree head is a signed statement derived from the issuer and `issuance.log`.

A second store used to need an unsigned Merkle root string to pin one issuer's log. That string can be swapped. A locally signed tree head lets that second store pin "this issuer attested this root at this leaf count" without becoming a second identity kernel.

`prometheus log sign-root [--output FILE]` signs the current Merkle root with the current issuer secret only. Previous keys past `kill_date` cannot sign a new tree head. The JSON container holds `merkle_root`, `leaf_count`, `signed_at` (RFC3339), `issuer_public_key_hex` (current key only), and `signature_hex`.

Signed bytes (exact UTF-8 concatenation, not JSON):

`prometheus-signed-tree-head|{merkle_root}|{leaf_count}|{signed_at}|{issuer_public_key_hex}`

`leaf_count` is the decimal integer with no leading zeros, except the number 0. `signed_at` is RFC3339 UTC with seconds precision and a `Z` suffix. The pipe character is literal ASCII 0x7C. Check reconstructs these bytes from the fields and never signs the JSON object. Field reorder in the JSON container cannot change the signed bytes.

`prometheus log check-root --tree-head FILE [--require-current-root]`:

- The signature must verify with the public key in the file.
- That key must be this issuer's current key, a previous key, or a key on the accept list.
- A tree head signed before a previous key's `kill_date` remains a historical pin. The key does not have to still be current. A previous key used to sign after its `kill_date` is refused, including when a test injects the clock.
- If `--require-current-root` is passed, `merkle_root` and `leaf_count` must match this store's current Merkle root. Default check is signature plus accept list so a second store can pin a foreign tree head.

Fail closed: empty `leaf_count`, missing Merkle root, missing signature, a tampered Merkle root with valid-looking other fields, an unknown issuer key, and a previous key used to sign after its `kill_date`.

The hash chain and the prove / check-proof commands are unchanged.

This is a locally signed Merkle root. This is not Certificate Transparency. This is not a gossip protocol. This is not a public log. This is not a multi-witness signed tree head. This is not a sixth identity record.

## STE100 — First binder

Honest bound:

- First binder means: the `holder_public_key` on an instance record is written once at birth or spawn and every later persist of that instance must keep the same `holder_public_key`.
- This is not a remote proof-of-possession protocol. Challenge remains a local nonce.
- This is not SPIFFE. X.509 must not become the instance name.
- It does not add a sixth record. The binder is the existing `holder_public_key` field on the instance record.

Identity is not the key. A later write that swaps the holder public key is a golden-ticket-class bind: the attacker becomes the instance.

Fail-closed design:

- The check lives on `save_instance`. Any persist of an existing instance whose `holder_public_key` differs from the stored value is refused. That is the smaller lock. Kill, revoke, expire, and parent-kill already persist through that path and cannot rewrite the binder.
- A new instance may set the key once. An empty holder public key is refused.
- `prometheus instance rebind --instance ID --public-key-hex HEX` always refuses with a first-binder error. There is no holder-key rotate and no holder-key reset.
- `prometheus instance show --instance ID` prints the instance, including `holder_public_key`, so a later persist can be compared.

This is the first-binder invariant. This is not a remote proof-of-possession protocol. This is not SPIFFE. This is not a sixth identity record.

## STE100 — Issuer seal

Honest bound:

- This is a pre-committed issuer `kill_date` on the existing issuer record. It is not a network partition detector, not a liveness probe, not a multi-witness clock.
- After `kill_date`, this store refuses new mint, birth, and spawn AND refuses act (verify / check / host). Historical receipt signature check may still succeed (audit). That split is documented and tested.
- Not threshold issuance. Not post-quantum. Not a sixth record.

A realm that cannot be refreshed must not mint or act forever. That is the Kerberos golden-ticket failure: one long-lived issuer key mints offline forever.

`prometheus issuer seal --after-seconds N` sets `issuer.kill_date` to now plus N seconds. N of zero or missing is refused. If the issuer is already sealed, a new `kill_date` that is later than or equal to the existing `kill_date` is refused. Death cannot be postponed. A later seal that only shortens the remaining life is allowed.

Fail-closed design:

- Realm `issuer.kill_date` is this issuer record's own death. Previous-key `kill_date` remains "this old key cannot mint." Seal does not write `previous_issuer_keys`. Rotate does not write realm `issuer.kill_date`.
- After `now >= kill_date`, mint, birth, spawn, issuer rotate, issuer accept, and `log sign-root` refuse. Attenuation is also refused because it issues a new capability.
- Verify, check, and host refuse even if the capability is unexpired. The store does not sign a new decision receipt after death. A refused act after death is a refused decision without a new receipt.
- `prometheus receipt verify` of an already-written receipt still succeeds. That is historical audit, not a live act.
- Once the seal time has passed, a later seal cannot move death into the future. The store stays dead.

This is a pre-committed issuer death. This is not a network partition detector. This is not a liveness probe. This is not a multi-witness clock. This is not threshold issuance. This is not a production FIPS module. This is not a post-quantum Biscuit. This is not a sixth identity record.

## STE100 — Local act bundle

Honest bound:

- This is a local export of three existing artifacts: a signed decision receipt, a Merkle inclusion proof, and a signed tree head. It is not a global name system, not SPIFFE federation, not Certificate Transparency gossip.
- The second store must already have the first issuer public key on its accept list.
- Not a sixth record.

A second store used to need the whole foreign `issuance.log` to check one decision receipt. That pushed the accept-list path toward copying the log or becoming a second identity kernel.

`prometheus act export --receipt FILE --output-directory DIR` requires a signed receipt. It reads `issuance_log_line` from that receipt, takes the existing `line_hash` on that line, writes `DIR/receipt.json` (copy), `DIR/proof.json` (`log prove` for that line), and `DIR/tree-head.json` (`log sign-root` as of now). Refuse if the receipt line is not in this store's log. Refuse if the issuer is sealed (`sign-root` already refuses).

`prometheus act accept --bundle-directory DIR` loads the three files. Any missing file refuses.

Fail-closed design:

- `check-root` on the tree head uses signature plus accept list. It does not pass `--require-current-root`. This is a foreign pin.
- `check-proof` uses the tree-head `merkle_root`, not this store's current root.
- Receipt signature verify uses this store's current accept list. The receipt bound `line_hash` must match `proof.line_hash`.
- Refuse if `proof.line_hash` does not match the receipt bound line.
- Refuse if `proof.root` does not match `tree-head.merkle_root`.
- Accept is verify-only. It does not mint, does not create instance records, and does not write a second `issuance.log` line.
- A previous key past `kill_date` is not on the current accept list. Those old receipts stay on the historical `receipt verify` path against a copied issuance.log. Act accept is not a second historical-audit kernel.

Receipt verify, prove, check-proof, sign-root, check-root, and the accept list are reused. They are not replaced.

This is a local export of three existing artifacts. This is not a global name system. This is not SPIFFE federation. This is not Certificate Transparency gossip. This is not a sixth identity record.

## STE100 — Signed presentation document

Honest bound:

- This is a signed presentation document from the existing instance, capability, and issuer records. It is not a SPIFFE SVID, not an X.509 certificate, not a WIMSE token, not a Transaction Token.
- Present is a document, not a name. X.509 remains a later on-ramp only. The instance identifier must not become a certificate subject. Do not put the instance name in an X.509 distinguished name.
- Not a sixth record.

The five kernel system calls are mint, verify, attenuate, present, and kill. Presentation is not identity.

A host that only sees a capability identifier still has no holder-bound, time-bounded statement it can hand to a second store. A bearer present would be the OAuth failure again.

`prometheus present --instance ID --capability ID --output FILE --challenge-nonce HEX --holder-secret-path PATH` requires a live instance and an unexpired capability that belongs to that instance. The issuer must not be sealed. Present reuses the existing one-time challenge path. That is the smaller fail-closed design: present is not bearer. A missing, spent, expired, or wrong-instance challenge is refused.

The JSON container holds `instance_id`, `agent_type_id`, `capability_id`, `on_behalf_of`, `intent`, `audience`, `holder_public_key`, `issuer_public_key_hex`, `presented_at`, `expires_at`, and `signature_hex`. `expires_at` is the earlier of the capability expiry and a 60-second presentation window.

Signed bytes (exact UTF-8 concatenation, not JSON):

`prometheus-presentation|{instance_id}|{agent_type_id}|{capability_id}|{on_behalf_of}|{intent}|{audience}|{holder_public_key}|{issuer_public_key_hex}|{presented_at}|{expires_at}`

`presented_at` and `expires_at` are RFC3339 UTC with seconds precision and a `Z` suffix. The pipe character is literal ASCII 0x7C. Check reconstructs these bytes from the fields and never signs the JSON object.

Present does not write a sixth identity record. Holder proof reuses the existing `challenge_spent` log line.

`prometheus present verify --presentation FILE` reconstructs the signed bytes and checks the issuer signature. The issuer public key in the file must be on this store accept list. Refuse if now is at or after `expires_at`. The unit test injects a clock. Refuse tamper, an unknown key, and a missing signature. Verify-only: do not mint and do not write instance records. A sealed local issuer does not block historical presentation verify.

This is a signed presentation document. This is not a name. This is not a SPIFFE SVID. This is not an X.509 certificate. This is not a sixth identity record.

## STE100 — Authorization-limit freeze

Honest bound:

- Freeze means: after the first write of an agent type, that type's `authorization_limit` must not increase (the string or prefix must not become wider). Decrease (a narrower prefix) may persist. The same value may persist. First write on create still sets the limit.
- A raise is a new limit that is not allowed by the stored limit. The comparison is `audience_within_authorization_limit`, the same function mint and spawn use. Do not invent a second comparison. If the destination is a prefix class, a shorter prefix or a new prefix that is not a child of the stored limit is a raise.
- The instance still cannot raise its own limit above the type.
- Raise is refused even when no instance of that type exists. That is the smaller fail-closed lock.
- Not a sixth record.

A later write that raises the type ceiling is a golden-ticket-class raise: the type becomes more powerful than at birth of its instances.

Fail-closed design:

- The check lives on `save_agent_type`. Any persist of an existing type whose `authorization_limit` is a raise versus the stored value is refused. That is the smaller lock.
- A new agent type may set the limit once.
- `prometheus agent-type raise --agent-type ID --authorization-limit VALUE` always refuses with an authorization-limit freeze error. There is no type-limit raise that succeeds.
- Narrowing to a child of the stored limit may persist through `save_agent_type`. There is no type-edit CLI that widens the ceiling.

This is the authorization-limit freeze. This is not a sixth identity record.

## STE100 — Capability-expiry freeze

Honest bound:

- Freeze means: after the first write of a capability identifier, that capability's `expires` must not move later. Decrease (a shorter remaining life) may persist. The same value may persist. First write on create still sets `expires`.
- This uses the existing capability `expires` field and the existing kernel clock. This is not a second clock. The presentation document still has its own `expires_at`.
- Attenuation creates a new capability identifier, so its own first persist may set a shorter expiry. The child expiry must not exceed the parent capability expiry.
- Not a sixth record.

A later write that moves `expires` later is a golden-ticket-class extension: the capability outlives the mint.

Fail-closed design:

- The check lives on `save_capability`. Any persist of an existing capability whose `expires` is later than the stored value is refused. That is the smaller lock.
- A new capability may set `expires` once.
- `prometheus capability extend --capability ID --expires-at TIME` always refuses with a capability-expiry freeze error. There is no expiry extend that succeeds.
- Attenuation copies or shortens the parent expiry. A child expiry after the parent is refused.

This is the capability-expiry freeze. This is not a sixth identity record.

## STE100 — Token-record fact consistency

Honest bound:

- The store record is the source for identity fields. The token must not exceed or contradict it.
- This is not a new record type.

A token that says a wider intent, a wider audience, a different `on_behalf_of`, or a different `instance_id` than the capability record is a golden-ticket-class lie: the token claims more than the store issued.

Fail-closed design:

- After the token signature check, `evaluate_capability` and `present_capability` read the authority-block facts (`intent`, `audience_prefix`, `on_behalf_of`, `instance`) through the same biscuit-auth authorizer path verify already uses.
- `instance_id` and `on_behalf_of` must match the record exactly.
- Intent and audience use `is_narrower_or_equal`, the same helper mint, spawn, and `authorization_limit` use. A token fact that is not within the record is a claimed exceed.
- Attenuation keeps the parent authority facts and adds narrower checks. A claimed exceed is refused only when the token still authorizes at that wider fact. An honest attenuated child still verifies.
- Host uses the same check path. No sixth record.

This is token-record fact consistency. This is not a sixth identity record.

## STE100 — Allowed-intents freeze

Honest bound:

- First persist of an agent type sets `allowed_intents`. A later persist that adds any intent string not in the stored set is refused. Removing an intent (narrow) may persist. The same set may persist.
- The comparison is `allowed_intents_within_stored`: every new intent string must already sit in the stored set. Exact string membership. Not a prefix class.
- In the same `save_agent_type` choke point, `max_delegation_depth` must not increase. A later persist whose new depth is greater than the stored depth is refused. A lower depth may persist. The same depth may persist.
- Reuse the existing `save_agent_type` choke point next to the authorization-limit freeze. Raise is refused even when no instance of that type exists.
- `prometheus agent-type add-intent` always refuses. There is no add-intent that succeeds.
- Not a sixth record.

Adding an intent after the first write is a golden-ticket-class raise: the type becomes more powerful than at birth.

This is the allowed-intents freeze. This is not a sixth identity record.

## STE100 — Persist-raise hunt

A later save of an existing record could grant more rights than the first write. The instance expiry could move later. The instance could swap to a more powerful agent type. A child could leave the parent kill tree. A revoked instance could return to live and mint. A type lifetime could grow. A chain hop index could drop. A killed chain flag could clear and un-kill children. A child chain could drop its parent pointer and leave the parent kill walk.

Fail-closed design:

- `save_instance` refuses a later `expires`, a changed `agent_type_id`, a changed `parent_instance_id`, and a revoked-to-live status.
- `save_agent_type` refuses a later `lifetime_seconds` next to the existing authorization-limit, allowed-intents, and maximum-delegation-depth freezes.
- `save_chain` refuses a decreased `hop_index`, a changed `parent_capability_id`, and a `revoke_from_here` clear after the flag is true.
- Capability `instance_id` swap is not a working raise. Token-record fact consistency already refuses a token that names a different instance.
- Capability `revoke_identifier` change is not a working raise. Kill uses the issuance-log capability identifier and the signed token revocation identifiers.
- Issuer `threshold_n` is stored as 1. It is not a bypass. Threshold issuance remains open.
- There is no force-allow leftover.
- No sixth record. No new always-refuse command-line interface. No twenty-fourth demonstration.

This is the persist-raise hunt. This is not a sixth identity record.

## STE100 — Issuer signatures on instance and capability records

Honest bound:

- This is a laboratory issuer signature on the instance and capability JSON records. It is not a Merkle tree of the whole store, not a database, not a transparency log of records.
- An attacker who can write the data directory still cannot mint a trusted record without `issuer.secret`.
- Not a production FIPS module. Not a post-quantum Biscuit.
- Not a sixth record. The signature fields live on the existing instance and capability records.

A file planted in the data directory used to act if the JSON parsed. The store JSON is not enough.

Fail-closed design:

- Instance and capability records store `issuer_signature_hex` and `issuer_public_key_hex`.
- The kernel re-signs with the current issuer secret on every successful `save_instance` and `save_capability`. Freeze checks still refuse a raise before a signature is written. Kill re-signs. A caller cannot persist an arbitrary signature.
- Signed bytes are a documented concatenation, not the raw JSON. The signature field itself is excluded. Field reorder in the JSON container cannot change the signed bytes.

Instance signed bytes (exact UTF-8 concatenation, not JSON):

`prometheus-instance|{id}|{agent_type_id}|{owner}|{born}|{expires}|{holder_public_key}|{status}|{parent_instance_id}|{issuer_public_key_hex}`

`born` and `expires` are RFC3339 UTC with seconds precision and a `Z` suffix. `status` is the exact word `live` or `revoked`. `parent_instance_id` is empty when there is no parent. Status is included so a revoked-to-live write breaks the signature and is already refused at persist.

Capability signed bytes (exact UTF-8 concatenation, not JSON):

`prometheus-capability|{id}|{instance_id}|{on_behalf_of}|{intent}|{audience}|{issued}|{expires}|{issuer_public_key_hex}`

`issued` and `expires` are RFC3339 UTC with seconds precision and a `Z` suffix. Token bytes are excluded so token-record fact consistency stays the token-versus-record layer.

- Evaluate, verify, check, host, and present recompute those bytes after load. A missing signature refuses. A flipped nibble refuses. A tampered identity field in memory fails the recomputed signature. The signature key must be the current key or a previous key still before `kill_date`. A foreign accept-list key cannot mint a local record.
- Rotate re-signs every stored instance and capability with the new current secret so an old capability still verifies after the previous-key `kill_date`.
- Mint, spawn, and attenuate also refuse a planted parent or instance whose signature is not trusted.

This is a laboratory issuer signature on the instance and capability JSON records. This is not a Merkle tree of the whole store. This is not a database. This is not a transparency log of records. This is not production post-quantum. This is not a sixth identity record.

## STE100 — Issuer signatures on agent type records

Honest bound:

- Laboratory issuer signature on the agent type JSON record. Same limits as instance/capability signatures. Not a store Merkle tree.

A file planted in the data directory used to mint if the agent type JSON parsed. A wider `authorization_limit` or an extra intent on that planted type was a golden-ticket-class raise. The store JSON is not enough.

Fail-closed design:

- Agent type records store `issuer_signature_hex` and `issuer_public_key_hex`.
- The kernel re-signs with the current issuer secret on every successful `save_agent_type`. Freeze checks still refuse a raise before a signature is written. A caller cannot persist an arbitrary signature.
- Signed bytes are a documented concatenation, not the raw JSON. The signature field itself is excluded. Field reorder in the JSON container cannot change the signed bytes.

Agent type signed bytes (exact UTF-8 concatenation, not JSON):

`prometheus-agent-type|{id}|{owner}|{allowed_intents sorted}|{authorization_limit}|{max_delegation_depth}|{crypto_profile}|{lifetime_seconds}|{issuer_public_key_hex}`

`allowed_intents sorted` is the intent strings sorted in lexicographic order and joined with a comma. An empty list is the empty string.

- Mint, birth, spawn, and evaluate recompute those bytes after load. A missing signature refuses. A flipped nibble refuses. A planted type with a wider limit or an extra intent and no or a forged signature refuses. The signature key must be the current key or a previous key still before `kill_date`.
- Rotate re-signs every stored agent type with the new current secret so an old type still verifies after the previous-key `kill_date`.

This is a laboratory issuer signature on the agent type JSON record. This is not a Merkle tree of the whole store. This is not a sixth identity record.

## STE100 — Issuer signatures on chain records

Honest bound:

- Laboratory issuer signature on the chain JSON record. Same limits as instance, capability, and agent type signatures. Not a store Merkle tree.
- Evaluate, attenuate, and spawn read `hop_index` and `revoke_from_here` from disk as an authorization input.

A file planted in the data directory used to grant more hops or revive a killed chain if the chain JSON parsed. A lower `hop_index` on a parent chain would let attenuate and spawn mint past `max_delegation_depth`. A cleared `revoke_from_here` on an ancestor would let evaluate allow a child after kill. The store JSON is not enough.

Fail-closed design:

- Chain records store `issuer_signature_hex` and `issuer_public_key_hex`.
- The kernel re-signs with the current issuer secret on every successful `save_chain`. Freeze checks still refuse a raise before a signature is written. Kill re-signs. A caller cannot persist an arbitrary signature.
- Signed bytes are a documented concatenation, not the raw JSON. The signature field itself is excluded. Field reorder in the JSON container cannot change the signed bytes.

Chain signed bytes (exact UTF-8 concatenation, not JSON):

`prometheus-chain|{capability_id}|{parent_capability_id}|{hop_index}|{attenuated_by}|{revoke_from_here}|{issuer_public_key_hex}`

`parent_capability_id` is empty when there is no parent. `hop_index` is a decimal integer with no leading zeros, except the number 0. `revoke_from_here` is the exact word `true` or `false`. Hop index and revoke-from-here are included so a planted lower hop or a cleared kill flag breaks the signature.

- Evaluate, verify, check, host, present, attenuate, and spawn recompute those bytes after load. A missing signature refuses. A flipped nibble refuses. A planted chain with a lower hop or a cleared kill flag and no or a forged signature refuses. The signature key must be the current key or a previous key still before `kill_date`.
- Rotate re-signs every stored chain with the new current secret so an old chain still verifies after the previous-key `kill_date`.

This is a laboratory issuer signature on the chain JSON record. This is not a Merkle tree of the whole store. This is not a sixth identity record.

## STE100 — Issuer signatures on issuance-log lines

Honest bound:

- Each log line carries `issuer_signature_hex` over a documented concatenation of the line fields excluding the signature itself. `line_hash` is SHA-256 of the compact JSON including `previous_line_hash` and `issuer_public_key_hex`, with `line_hash` and `issuer_signature_hex` omitted. The kernel then signs `prometheus-issuance-log-line|{line_hash}|{issuer_public_key_hex}`.
- This is still a local log. This is not Certificate Transparency.

A hash-chain-only append used to verify if the previous hash and the line hash matched. An attacker who could write `issuance.log` did not need `issuer.secret`.

Fail-closed design:

- The kernel signs with the current issuer secret on every successful append. The JSON line stores `issuer_public_key_hex` and `issuer_signature_hex`.
- `prometheus log verify` walks the hash chain and each line signature. A missing signature refuses. A flipped nibble refuses. A well-hashed line without a valid signature refuses.
- This store trusts the current key and previous keys. The log is append-only and is not re-signed on rotate, so a previous key remains valid for already-written lines after `kill_date`. A copied foreign log uses the accept list.
- Receipt verify still requires the bound line to match. That line's signature must verify. An unsigned bound line refuses.

This is a laboratory issuer signature on each issuance-log line. This is still a local log. This is not Certificate Transparency. This is not a sixth identity record.

## STE100 — Rotate must not launder a planted file

Honest bound:

- Laboratory issuer signatures already refuse a planted file on evaluate, mint, spawn, present, and host.
- Rotate used to load every JSON file and re-sign it with the current issuer secret. That gave a planted unsigned file a trusted signature.

A planted wider agent type could mint after rotate. A planted chain that cleared `revoke_from_here` could revive a killed child after rotate.

Fail-closed design:

- `save_agent_type`, `save_instance`, `save_capability`, and `save_chain` refuse persist of an existing file whose stored issuer signature is missing, wrong, or untrusted.
- First write still has no stored signature and may persist.
- Freeze raises still refuse before a signature is written.
- Rotate skips an untrusted stored file and does not write a current-key signature onto it.
- Honest records still re-sign so an old capability still verifies after the previous-key `kill_date`.

This is not a sixth identity record. No twenty-fourth demonstration.

## STE100 — Remaining launder / re-sign / copy hunt

Honest bound:

- `save_*` already refuses persist of an existing record whose stored issuer signature is missing, wrong, or untrusted.
- Rotate already skips those files.

Hunt of remaining copy paths: spawn, attenuate, kill, birth, mint, present, and first-write save. Spawn and attenuate verify the parent instance, capability, chain, and type before they write a signed child. Birth and mint verify the type before they copy lifetime or mint. Present verifies the instance and capability before it signs a document. Kill loads a planted file and then save refuses the untrusted stored signature. A trusted revoked record would not be a raise.

No working launder remained. No sixth identity record. No twenty-fourth demonstration.


## STE100 — Laboratory Module-Lattice Digital Signature Algorithm issuer profile

Honest bound:

- The identity root is Module-Lattice Digital Signature Algorithm 65. The crate is `fips204`. The Federal Information Processing Standard 204 parameter set is ML-DSA-65.
- The Biscuit envelope is still laboratory Ed25519. biscuit-auth cannot carry Module-Lattice Digital Signature Algorithm yet.
- This is not a production FIPS module. This is not a post-quantum Biscuit.

Issuer init refuses a classical-only root. Profile `lab-ed25519` as the only issuer signature algorithm is refused. The Biscuit public key lives on the existing issuer record as `biscuit_public_key_hex`. Rotate changes the Module-Lattice current key only. The Biscuit key stays. The Biscuit key must not sign records, log lines, receipts, or tree heads.

Five records stay closed. Present stays a document. The instance identifier must not become an X.509 name. This is not a SPIFFE SVID.

## STE100 — Multi-signature issuance

Honest cryptographic bound:

- Do not implement a Shamir split of `issuer.secret`. A Shamir split reconstitutes one key on one host. That is not threshold issuance.
- Do not implement FROST or threshold Edwards-curve Digital Signature Algorithm on Curve 25519 as the identity root. That root would be classical.
- Do not claim Federal Information Processing Standard 204 threshold Module-Lattice Digital Signature Algorithm. That scheme is not what this laboratory ships.
- Ship multi-signature issuance: a mint, birth, spawn, save-sign, log-append, receipt, or tree-head is valid only when at least `threshold_n` distinct Module-Lattice Digital Signature Algorithm 65 signatures from trusted issuer member keys verify over the same documented concatenation.
- When `threshold_n` is 1, one current Module-Lattice key signs, the same as before this work.

Members:

- Trusted signing members are the current Module-Lattice public key plus additional member public keys stored on the existing issuer `public_keys` list.
- `prometheus issuer member add` generates a second Module-Lattice key pair and writes `issuer-member-<first-16-hex-of-public-key>.secret` under the data directory. That file is gitignored (`**/*.secret`).
- The Biscuit envelope key is never a member and never counts toward `threshold_n`.
- Need two members before `--n 2`.

Threshold field:

- `threshold_n` stays on the existing issuer record. Init default remains 1. The value must be at least 1.
- `prometheus issuer threshold --n K` refuses K less than 1, refuses K greater than the trusted Module-Lattice member count, and refuses lowering. Raising is allowed. Lowering is a persist-raise class and fails closed.

Signatures:

- Records, issuance-log lines, decision receipts, signed tree heads, and presentations keep the existing single signature field for `threshold_n` 1.
- When `threshold_n` is greater than 1, artifacts also store `issuer_signatures`: a list of `{public_key_hex, signature_hex}`.
- Verify counts distinct trusted Module-Lattice keys whose signatures verify over the same documented concatenation. The count must be at least `threshold_n`. Missing, untrusted, and duplicate-key signatures do not count.

Mint path:

- `save_*` / mint / birth / spawn / sign-root load `threshold_n` member secrets. One secret (`issuer.secret`) when n=1. `issuer.secret` plus `issuer-member-*.secret` when n>1. If only one secret is present when n=2, refuse.
- Rotate still rotates the current Module-Lattice key. `threshold_n` is unchanged. The previous key remains a member until `kill_date`.
- Planted files and rotate-launder still refuse untrusted stored signatures. For n=2, a record with only one valid signature refuses evaluate.

This is multi-signature issuance. This is not a sixth identity record. This is not a production FIPS module. This is not a post-quantum Biscuit.

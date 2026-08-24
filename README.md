# Prometheus

This directory is PolicyLab-2 laboratory code. Jason Gale owns this work.

This package is a laboratory prototype. This package is not affiliated with Sanctum. This package is not a Cyera product.

## Defined terms

- **Biscuit**: the capability token format. The biscuit-auth package signs and attenuates the token. Prefer the words “capability token” in user text after this definition.
- **Authorization limit**: the highest combination of intent and destination this agent type may hold. The instance cannot raise this limit.

## Purpose

This program is an agent-identity kernel for artificial-intelligence agents. A host must be able to allow or refuse a tool action.

The kernel stores five closed records. There is no sixth record type.

A name is not a key. An instance identifier is not the holder public key.

## The five records

1. **agent type**: `id` (identifier string, not a key), `owner`, `allowed_intents`, `authorization_limit`, `max_delegation_depth`, `crypto_profile`, `lifetime_seconds` (frozen after the first write; a later persist must not raise this lifetime), `issuer_public_key_hex`, `issuer_signature_hex` (laboratory issuer signature over the documented agent type concatenation; missing, wrong, or untrusted signatures refuse mint), optional `issuer_signatures` (list of `{public_key_hex, signature_hex}` when `threshold_n` is greater than 1).
2. **instance**: `id` (not a key), `agent_type_id` (written once at birth; a later persist must not replace this value), `owner`, `born`, `expires` (frozen after the first write; a later persist must not move this time later), `holder_public_key` (hexadecimal bytes; laboratory holder challenge only; written once at birth or spawn and never replaced), `status` (`live` or `revoked`; a later persist must not set a revoked instance back to live), optional `parent_instance_id` (written once at birth; a later persist must not clear or replace this value), `attributes` map for site, region, and runtime, `issuer_public_key_hex`, `issuer_signature_hex` (laboratory issuer signature over the documented instance concatenation; missing, wrong, or untrusted signatures refuse act), optional `issuer_signatures` (list of `{public_key_hex, signature_hex}` when `threshold_n` is greater than 1).
3. **capability**: `id`, `instance_id`, `on_behalf_of` (a user identifier or `autonomous`), `intent`, `audience` (the destination), `caveats`, `issued`, `expires` (frozen after the first write; a later persist must not move this time later), `revoke_identifier`, capability token bytes, `issuer_public_key_hex`, `issuer_signature_hex` (laboratory issuer signature over the documented capability concatenation; missing, wrong, or untrusted signatures refuse act), optional `issuer_signatures` (list of `{public_key_hex, signature_hex}` when `threshold_n` is greater than 1).
4. **chain**: `capability_id`, optional `parent_capability_id` (written once at birth; a later persist must not clear or replace this value), `hop_index` (frozen after the first write; a later persist must not decrease this index), `attenuated_by`, `revoke_from_here` (after this flag is true, a later persist must not set it false), `issuer_public_key_hex`, `issuer_signature_hex` (laboratory issuer signature over the documented chain concatenation; missing, wrong, or untrusted signatures refuse act), optional `issuer_signatures` (list of `{public_key_hex, signature_hex}` when `threshold_n` is greater than 1).
5. **issuer**: `current_public_key` (Module-Lattice Digital Signature Algorithm hexadecimal), `public_keys`, `previous_issuer_keys` (each entry is `{public_key_hex, kill_date}`), `accepted_issuer_public_keys` (hexadecimal Module-Lattice public keys this store trusts for receipt verify; always includes this store's own current key; a previous key stays on the list until its kill_date), `biscuit_public_key_hex` (laboratory Ed25519 capability-envelope public key; this is not the identity root; rotate keeps this key), `crypto_profile` (default `lab-ml-dsa-65-hybrid-biscuit-ed25519`), optional `kill_date` (store-wide issuer death; after this time the store refuses new mint, birth, and spawn, and refuses act; historical receipt signature check may still succeed), `threshold_n` (init default `1`; a mint, birth, spawn, save-sign, log-append, receipt, or tree-head is valid only when at least this many distinct trusted Module-Lattice member signatures verify; lowering is refused), `issuance_log` path. `current_public_key`, `previous_issuer_keys`, `accepted_issuer_public_keys`, and `kill_date` are fields on the issuer record. They are not a sixth identity record. Trusted signing members are the current Module-Lattice public key plus additional member public keys stored on `public_keys`. The Biscuit envelope key is not a member. After rotate, new mint, birth, spawn, and receipts sign with the current key plus any remaining members required by `threshold_n`. `threshold_n` is unchanged. The previous key remains a member until `kill_date`. Old capabilities verify until capability expiry. Realm `issuer.kill_date` is this issuer record's own death. A previous-key `kill_date` remains "this old key cannot mint." This is laboratory multi-signature issuance over Module-Lattice Digital Signature Algorithm 65. This is not a Shamir split of `issuer.secret`. This is not FROST. This is not Federal Information Processing Standard 204 threshold Module-Lattice Digital Signature Algorithm. This is not a production FIPS module. This is not a post-quantum Biscuit.

The program writes JSON files under `./data`: `agent_types/`, `instances/`, `capabilities/`, `chains/`, `issuer.json`, and `issuance.log`. The laboratory also writes `issuer.secret` (current Module-Lattice identity root), `issuer-member-*.secret` (additional multi-signature member secrets when a second member is added), `biscuit.secret` (Biscuit envelope only), and a holder secret file under `holders/`. Those secret files are ignored by `.gitignore`. A secret holder is out of scope. Sanctum can hold secrets later.

## Authorization limit

The authorization limit is the highest combination of intent and destination that this agent type may hold.

This laboratory kernel uses a simple ordered comparison:

- Destination: the authorization limit is a prefix class. Example: if the authorization limit is `payments`, the audience values `payments` and `payments/prod` are inside the limit. The audience values `public` and any destination that does not sit under that prefix are above the limit. Mint fails when the audience is above the limit.
- Intent: the agent type stores `allowed_intents`. The mint intent must be in that list. The authorization limit is the destination prefix. The `allowed_intents` list is the intent allow list.

Mint fails when the requested intent is not in `allowed_intents` or the requested audience is above the authorization limit. The instance cannot raise the authorization limit.

The type authorization limit is frozen after the first write. See Authorization-limit freeze (STE100).

## One-time holder challenge

Each instance stores a holder public key. The instance identifier is not the holder public key.

The `challenge` command writes a one-time challenge for an instance. The challenge holds a nonce, an issued time, and an expiry. The challenge is stored as a line in the issuance log. This is log state, not a sixth identity record.

Verify, check, spawn, and the local host require a holder proof that answers that challenge:

- The caller must name the challenge nonce.
- A path to the holder secret file is accepted only when it signs that challenge.
- A hexadecimal Ed25519 signature is accepted only when it signs that challenge.

Re-use of a spent nonce fails. A challenge past its time window fails. A static laboratory challenge is not accepted. A stolen proof cannot be replayed forever.

A verify call without a valid holder proof fails. A capability token is not accepted as a bearer token.

This laboratory method shows that the caller has the holder secret and can answer a fresh nonce. This method is not a production proof of possession.

## First binder

The `holder_public_key` on an instance record is written once at birth or spawn. Every later persist of that instance must keep the same `holder_public_key`. A later write that swaps the holder key is refused. Identity is not the key. The instance identifier is not the binder.

`prometheus instance show --instance <identifier>` prints the instance record, including `holder_public_key`. `prometheus instance rebind --instance <identifier> --public-key-hex <hex>` always refuses. There is no holder-key rotate and no holder-key reset. Kill, revoke, expire, and parent-kill do not rewrite `holder_public_key`.

This is the first-binder invariant. This is not a remote proof-of-possession protocol. Challenge remains a local nonce. This is not SPIFFE. X.509 must not become the instance name.

## Authorization-limit freeze (STE100)

The authorization limit is the highest intent and destination an agent type may hold. A later write that raises that ceiling after the type exists is a golden-ticket-class raise: the type becomes more powerful than at birth of its instances.

Honest bound:

- Freeze means: after the first write of an agent type, that type's `authorization_limit` must not increase. A new limit that is not allowed by the stored limit is a raise.
- The comparison is `audience_within_authorization_limit`: the same function mint and spawn use. Do not invent a second comparison. If the destination is a prefix class, a shorter prefix or a new prefix that is not a child of the stored limit is a raise.
- Narrowing (a child of the stored limit) may persist. The same value may persist. First write on create still sets the limit.
- The instance still cannot raise its own limit above the type.
- Not a sixth record.

`save_agent_type` refuses any persist of an existing type whose `authorization_limit` is a raise versus the stored value, whether or not an instance of that type exists. That is the smaller lock.

`prometheus agent-type raise --agent-type ID --authorization-limit VALUE` always refuses. There is no type-limit raise that succeeds. There is no type-edit command that widens the ceiling.

This is the authorization-limit freeze. This is not a sixth identity record.

## Allowed-intents freeze (STE100)

The allowed intents are the intent strings an agent type may mint. A later write that adds an intent after the type exists is a golden-ticket-class raise: the type becomes more powerful than at birth.

Honest bound:

- Freeze means: after the first write of an agent type, that type's `allowed_intents` must not gain a new intent string. Removing an intent may persist. The same set may persist. First write on create still sets the set.
- The comparison is subset: every new intent string must already sit in the stored set. The helper is `allowed_intents_within_stored`. This is exact string membership. This is not a prefix class.
- After the first write, `max_delegation_depth` must not increase. A later persist whose new depth is greater than the stored depth is refused. A lower depth may persist. The same depth may persist.
- The check lives on `save_agent_type` next to the authorization-limit freeze. Raise is refused even when no instance of that type exists.
- Not a sixth record.

`prometheus agent-type add-intent --agent-type ID --intent VALUE` always refuses. There is no add-intent that succeeds.

This is the allowed-intents freeze. This is not a sixth identity record.

## Capability-expiry freeze (STE100)

The first persist of a new capability sets `expires`. A later write that moves that time later is a golden-ticket-class extension: the capability outlives the mint.

Honest bound:

- Freeze means: after the first write of a capability identifier, that capability's `expires` must not move later. Earlier (a shorter remaining life) may persist. The same value may persist. First write on create still sets `expires`.
- This uses the existing capability `expires` field and the existing kernel clock. This is not a second clock. The presentation document still has its own `expires_at`.
- Attenuation creates a new capability identifier, so its own first persist may set a shorter expiry. The child expiry must not exceed the parent capability expiry.
- Not a sixth record.

`save_capability` refuses any persist of an existing capability whose `expires` is later than the stored value. That is the smaller lock.

`prometheus capability extend --capability ID --expires-at TIME` always refuses. There is no expiry extend that succeeds.

This is the capability-expiry freeze. This is not a sixth identity record.

## Instance persist freeze (STE100)

The first persist of an instance sets `expires`, `agent_type_id`, and `parent_instance_id`. A later write that moves `expires` later, replaces `agent_type_id`, or clears or replaces `parent_instance_id` is a golden-ticket-class raise.

Honest bound:

- After the first write, `expires` must not move later. An earlier (shorter) expiry may persist. The same value may persist.
- After the first write, `agent_type_id` must not change. Swapping to another type, including a more powerful type, is refused.
- After the first write, `parent_instance_id` must not change. Clearing the parent leaves the parent kill tree.
- A revoked instance must not return to live. Un-revoking grants mint after kill.
- This uses the existing instance fields and the existing kernel clock. This is not a second clock.
- Not a sixth record.

`save_instance` is the choke point. There is no new command-line interface. There is no twenty-fourth demonstration.

This is the instance persist freeze. This is not a sixth identity record.

## Type lifetime freeze (STE100)

After the first write of an agent type, `lifetime_seconds` must not increase. A later persist that raises the lifetime is a golden-ticket-class raise: new instances and first capabilities of that type would live longer than at birth of the type.

A lower lifetime may persist. The same lifetime may persist. The check lives on `save_agent_type` next to the authorization-limit freeze.

This is the type lifetime freeze. This is not a sixth identity record.

## Chain persist freeze (STE100)

The first persist of a chain sets `hop_index`, `parent_capability_id`, and `revoke_from_here`. A later write that decreases `hop_index`, clears or replaces `parent_capability_id`, or sets `revoke_from_here` back to false is a golden-ticket-class raise.

Honest bound:

- After the first write, `hop_index` must not decrease. The same hop index may persist. A kill persist keeps the hop index.
- After the first write, `parent_capability_id` must not change. Clearing the parent leaves the parent kill walk.
- After `revoke_from_here` is true, a later persist must not set it false. Clearing the flag un-kills child capabilities that walk to that ancestor.
- Not a sixth record.

`save_chain` is the choke point. There is no new command-line interface.

This is the chain persist freeze. This is not a sixth identity record.

## Token-record fact consistency (STE100)

The store record is the source for identity fields. The capability token must not exceed or contradict that record. This is not a new record type.

A token that says a wider intent, a wider audience, a different `on_behalf_of`, or a different `instance_id` than the capability record is a golden-ticket-class lie.

After the token signature check, verify, check, host, and present read the authority-block facts and compare them to the capability record. `instance_id` and `on_behalf_of` must match exactly. Intent and audience use `is_narrower_or_equal`, the same helper mint, spawn, and `authorization_limit` use. Attenuation keeps the parent facts and adds narrower checks; a claimed exceed is refused only when the token still authorizes at that wider fact. An honest attenuated child still verifies.

This is token-record fact consistency. This is not a sixth identity record.

## Issuer signatures on instance and capability records (STE100)

Honest bound:

- This is a laboratory issuer signature on the instance and capability JSON records. It is not a Merkle tree of the whole store, not a database, not a transparency log of records.
- An attacker who can write the data directory still cannot mint a trusted record without `issuer.secret`.
- Not a production FIPS module. Not a post-quantum Biscuit.
- Not a sixth record.

A file planted in the data directory must not act. The store JSON is not enough.

The kernel re-signs with the current issuer secret on every successful `save_instance` and `save_capability`. Freeze checks still refuse a raise before a signature is written. Kill re-signs. A caller cannot persist an arbitrary signature. Rotate re-signs every stored instance, capability, agent type, and chain with the new current secret.

Signed bytes (exact UTF-8 concatenation, not JSON):

`prometheus-instance|{id}|{agent_type_id}|{owner}|{born}|{expires}|{holder_public_key}|{status}|{parent_instance_id}|{issuer_public_key_hex}`

`prometheus-capability|{id}|{instance_id}|{on_behalf_of}|{intent}|{audience}|{issued}|{expires}|{issuer_public_key_hex}`

`born`, `expires`, and `issued` are RFC3339 UTC with seconds precision and a `Z` suffix. `status` is the exact word `live` or `revoked`. `parent_instance_id` is empty when there is no parent. The pipe character is literal ASCII 0x7C. The signature field itself is excluded. Token bytes are excluded so token-record fact consistency stays the token-versus-record layer. Status is included so a revoked-to-live write breaks the signature and is already refused at persist.

Evaluate, verify, check, host, and present recompute those bytes after load. A missing signature refuses. A wrong signature refuses. The signature key must be the current key or a previous key still before `kill_date`. A planted file cannot act.

This is a laboratory issuer signature on the instance and capability JSON records. This is not a sixth identity record.

## Issuer signatures on agent type records (STE100)

Honest bound:

- This is a laboratory issuer signature on the agent type JSON record. It is not a Merkle tree of the whole store, not a database, not a transparency log of records.
- An attacker who can write the data directory still cannot mint from a planted type without `issuer.secret`.
- Not a production FIPS module. Not a post-quantum Biscuit.
- Not a sixth record.

The kernel re-signs with the current issuer secret on every successful `save_agent_type`. Freeze raises still refuse before a signature is written. A caller cannot persist an arbitrary signature. Rotate re-signs every stored agent type.

Signed bytes (exact UTF-8 concatenation, not JSON):

`prometheus-agent-type|{id}|{owner}|{allowed_intents sorted}|{authorization_limit}|{max_delegation_depth}|{crypto_profile}|{lifetime_seconds}|{issuer_public_key_hex}`

`allowed_intents sorted` is the intent strings sorted in lexicographic order and joined with a comma. An empty list is the empty string. The pipe character is literal ASCII 0x7C. The signature field itself is excluded.

Mint, birth, spawn, and evaluate recompute those bytes after load. A missing signature refuses. A wrong signature refuses. A planted type with a wider `authorization_limit` or an extra intent cannot mint.

This is a laboratory issuer signature on the agent type JSON record. This is not a sixth identity record.

## Issuer signatures on chain records (STE100)

Honest bound:

- This is a laboratory issuer signature on the chain JSON record. It is not a Merkle tree of the whole store, not a database, not a transparency log of records.
- Evaluate, attenuate, and spawn read `hop_index` and `revoke_from_here` from disk as an authorization input. A planted chain with a lower hop index would grant more hops. A planted chain that clears `revoke_from_here` would revive a killed chain.
- An attacker who can write the data directory still cannot grant hops or revive a killed chain without `issuer.secret`.
- Not a production FIPS module. Not a post-quantum Biscuit.
- Not a sixth record. The signature fields live on the existing chain record.

The kernel re-signs with the current issuer secret on every successful `save_chain`. Freeze checks still refuse a raise before a signature is written. Kill re-signs. A caller cannot persist an arbitrary signature. Rotate re-signs every stored chain with the instances, capabilities, and agent types.

Signed bytes (exact UTF-8 concatenation, not JSON):

`prometheus-chain|{capability_id}|{parent_capability_id}|{hop_index}|{attenuated_by}|{revoke_from_here}|{issuer_public_key_hex}`

`parent_capability_id` is empty when there is no parent. `hop_index` is a decimal integer with no leading zeros, except the number 0. `revoke_from_here` is the exact word `true` or `false`. The pipe character is literal ASCII 0x7C. The signature field itself is excluded. Hop index and revoke-from-here are included so a planted lower hop or a cleared kill flag breaks the signature.

Evaluate, verify, check, host, present, attenuate, and spawn recompute those bytes after load. A missing signature refuses. A wrong signature refuses. The signature key must be the current key or a previous key still before `kill_date`. A planted file cannot act.

This is a laboratory issuer signature on the chain JSON record. This is not a sixth identity record.

## One birth write

The `birth` command creates an instance and the first capability as one issuance event. Identity starts as an authorized act, not as a directory row that later receives a token. A name is not a key.

The issuance log records one `birth_write` line that includes both the instance identifier and the capability identifier.

## Agent-to-agent spawn

The `spawn` command creates a child instance and a narrower capability as one issuance. The child record stores `parent_instance_id`. The child cannot gain rights that the parent does not have. The child act authority must stay compatible with the parent. A parent on behalf of a named user cannot birth an autonomous child. The child must keep that same user. An autonomous parent may birth an autonomous child or a child on behalf of a named user. The child token stores the child act authority. The parent must present a holder proof. This is an agent-to-agent primitive. This is not a cloud-directory catalog template.

## Tool-boundary host

The `check` command and the `host` command allow a runtime to allow or refuse a tool action.

The host listens on a loopback address only. The default is `127.0.0.1:18765`. Binding to all interfaces is not permitted.

The host answers `POST /check` with JSON fields `instance_id`, `capability_id`, `intent`, `audience`, `challenge_nonce`, `on_behalf_of`, and a holder proof (`holder_secret_path` or `holder_proof`). A check that omits `capability_id` is refused. A check that omits `on_behalf_of` is refused. Empty is not autonomous. The exact word `autonomous` is required. The kernel does not guess which capability or which act authority.

The `on_behalf_of` value must match the capability token fact and the capability record. Autonomous and a named user are first-class act authorities. A mismatch fails closed.

The check fails closed when any of these is true: missing holder proof, missing challenge nonce, spent nonce, challenge past its time window, missing capability identifier, missing `on_behalf_of`, empty `on_behalf_of`, missing issuance-log line, broken issuance-log hash chain, expired capability or instance, revoked capability or instance, audience above the authorization limit, hop depth exceeded, act authority that does not match the capability token, a capability token whose facts exceed or contradict the capability record, or the store-wide issuer seal `kill_date` has been reached.

Every successful or refused check appends one identity event to `issuance.log`. The log records the instance, the capability, the audience, the intent, and the result. The log does not record secret material.

Each issuance-log JSON line includes `previous_line_hash` and `line_hash`. Both values are SHA-256 hexadecimal digests.

- `previous_line_hash` is the SHA-256 digest of the previous raw line without the trailing newline. The first line uses the documented empty-hash: the SHA-256 digest of empty input, `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
- `line_hash` is the SHA-256 digest of this line's compact JSON serialization with the `line_hash` field omitted. That omitted-field serialization is the documented canonical form.

`prometheus log verify` walks the file. A missing `previous_line_hash`, a missing `line_hash`, a wrong previous hash, or a wrong line hash fails closed. Deleting or inserting a middle line is detectable. This is a local hash chain. This is not a public append-only service.

The store can also compute a local Merkle root over the sequence of `line_hash` values. The Merkle leaf is the existing `line_hash`. This is not a third hash chain. Internal nodes are SHA-256 of the left digest concatenated with the right digest. A single leaf is its own root and is not padded. Two or more leaves are padded to the next power of two with the documented empty-hash. `prometheus log root` prints the root and the leaf count. `prometheus log prove --line-hash HEX` writes an inclusion proof. `prometheus log check-proof --proof FILE [--root HEX]` recomputes the root and fail-closes on a mismatch, an empty proof, a truncated sibling list, or a leaf that is not the claimed `line_hash`. A second store can check one logged mint against a known root without copying the log and without becoming a second identity kernel. The decision receipt does not carry `issuance_log_root`. This is a local Merkle tree over the hash-chained issuance log. This is not a public transparency log. This is not Certificate Transparency. This is not a gossiped signed tree head. Proofs are derived from the existing `issuance.log` lines. This is not a sixth record.

`prometheus log sign-root [--output FILE]` signs that current Merkle root with the current issuer secret only. Previous keys past `kill_date` cannot sign a new tree head. The JSON container holds `merkle_root`, `leaf_count`, `signed_at`, `issuer_public_key_hex`, and `signature_hex`. The signed bytes are the documented concatenation `prometheus-signed-tree-head|{merkle_root}|{leaf_count}|{signed_at}|{issuer_public_key_hex}`. That is not JSON. `prometheus log check-root --tree-head FILE [--require-current-root]` verifies the signature with the key in the file and requires that key to be this issuer's current key, a previous key, or a key on the accept list. A tree head signed before a previous key's `kill_date` remains a historical pin. A previous key used to sign after its `kill_date` is refused. `--require-current-root` also requires this store's current root and leaf count. Default check is signature plus accept list so a second store can pin a foreign tree head without becoming a second identity kernel. This is a locally signed Merkle root. This is not Certificate Transparency. This is not a gossip protocol. This is not a public log. This is not a multi-witness signed tree head. This is not a sixth record.

## Decision receipt

After every verify or check, allow or refuse, the kernel signs a decision receipt with the issuer private key. The receipt names the instance, the capability, the intent, the audience, the act authority, the result, the reason when refused, the challenge nonce, the issued time, and `issuance_log_line` (the exact JSON line of that check or verify event as written to `issuance.log`).

The receipt is a signed document. The receipt is not a sixth identity record. Holder secrets are not written into the receipt.

`prometheus receipt verify --receipt <file> [--issuance-log <path>]` checks the signature against this store's accept list at the current time, that the receipt fields parse, that the chosen issuance log hash chain is intact, and that `issuance_log_line` is still present in that log. The current issuer public key is always accepted if it is on the list. A previous issuer key is accepted only when now is before that key's `kill_date`. After `kill_date`, a new signature from the old key is refused even if the signature is valid, unless the bound line is already in the issuance log (an old receipt; rotate only kills new minting). If `--issuance-log` is omitted, this store's `issuance.log` is used. A tampered result fails. A missing signature fails. A receipt signed by a key that is not on the accept list fails. A valid signature is not enough if the bound log line was deleted or altered, or if the hash chain is broken.

A second Prometheus store can accept the first issuer public key with `prometheus issuer accept --public-key-hex <hex>` and then verify a receipt from the first store against the first `issuance.log`. The second store does not become a second identity kernel. This is an accept list. This is not a global name system. This is not SPIFFE federation. Empty public keys cannot be added.

This is a laboratory Module-Lattice Digital Signature Algorithm signature. When `threshold_n` is greater than 1, the receipt also stores `issuer_signatures`. This is a local JSON line log. This is not a public transparency log. A third party can check that Prometheus allowed or refused an act without trusting only the local JSON log. That third party still has to trust this laboratory issuer key. Later public transparency can use this same binding.

## Issuer key rotation

`prometheus issuer rotate [--kill-after-seconds N]` creates a new laboratory issuer key pair. The old public key is stored on `previous_issuer_keys` with `kill_date` equal to now plus a short laboratory window, or the given seconds. `issuer.secret` becomes the new key only. New mint, birth, spawn, and receipts sign with the current key only. The old public key stays on the accept list until `kill_date`.

Old capabilities verify until capability expiry. Rotate does not revoke already-issued capabilities. After `kill_date` the old key cannot mint. If an attacker stole the old secret after rotate, they cannot mint through this store because the store no longer has that secret. If they mint offline, verify fail-closes because the new capability is not in the issuance log, and because the signature key is a previous key past `kill_date`.

Rotate still rotates the current Module-Lattice key only. `threshold_n` is unchanged. The previous key remains a trusted member until `kill_date`. The Biscuit envelope key stays and is not a member. This is not a Shamir split. This is not FROST. This is not Federal Information Processing Standard 204 threshold Module-Lattice Digital Signature Algorithm. This is not a production FIPS module. This is not a post-quantum Biscuit.

## Issuer seal (STE100)

`prometheus issuer seal --after-seconds N` sets `issuer.kill_date` to now plus N seconds. N must be greater than zero. A missing `--after-seconds` is refused. If the issuer is already sealed, a later seal cannot postpone death: a new `kill_date` that is later than or equal to the existing `kill_date` is refused. A later seal that only shortens the remaining life is allowed.

After `now >= issuer.kill_date` this store refuses new mint, birth, spawn, issuer rotate, issuer accept, `log sign-root`, and present. Attenuation is also refused because it issues a new capability. Verify, check, and host refuse even if the capability is unexpired. The store does not sign a new decision receipt after death. `prometheus receipt verify` of an already-written receipt still succeeds. `prometheus present verify` of an already-written presentation still succeeds. That is historical audit. That split is intentional.

This is a pre-committed issuer `kill_date` on the existing issuer record. This is not a network partition detector. This is not a liveness probe. This is not a multi-witness clock. This is not threshold issuance. This is not a production FIPS module. This is not a post-quantum Biscuit. This is not a sixth identity record.

Realm `issuer.kill_date` is the issuer record's own death. Previous-key `kill_date` remains "this old key cannot mint."

## Act bundle (STE100)

A second store can check one decision without copying the foreign `issuance.log` and without becoming a second identity kernel.

`prometheus act export --receipt FILE --output-directory DIR` requires a signed decision receipt. It reads `issuance_log_line` from that receipt, takes the existing `line_hash` on that line, and writes three existing artifacts:

- `DIR/receipt.json` — copy of the signed receipt
- `DIR/proof.json` — `log prove` for that line
- `DIR/tree-head.json` — `log sign-root` as of now

Refuse if the receipt line is not in this store's log. Refuse if the issuer is sealed (`log sign-root` already refuses).

`prometheus act accept --bundle-directory DIR` loads those three files. Any missing file refuses. It runs `log check-root` on the tree head without `--require-current-root` (a foreign pin), `log check-proof` against the tree-head `merkle_root` (not this store's current root), and receipt signature verify against this store's accept list. Refuse if `proof.line_hash` does not match the receipt bound line. Refuse if `proof.root` does not match `tree-head.merkle_root`.

Accept is verify-only. It does not mint, does not create instance records, and does not write a second `issuance.log` line. The second store must already have the first issuer public key on its accept list.

This is a local export of three existing artifacts. This is not a global name system. This is not SPIFFE federation. This is not Certificate Transparency gossip. This is not a sixth identity record.

## Present (STE100)

Present is a signed presentation document from the existing instance, capability, and issuer records. Present is a document, not a name.

This is not a SPIFFE SVID. This is not an X.509 certificate. This is not a WIMSE token. This is not a Transaction Token. X.509 remains a later on-ramp only. The instance identifier must not become a certificate subject. Do not put the instance name in an X.509 distinguished name. This is not a sixth record.

`prometheus present --instance ID --capability ID --output FILE --challenge-nonce HEX --holder-secret-path PATH` requires a live instance and an unexpired capability that belongs to that instance. The issuer must not be sealed. Present requires a one-time challenge nonce from `prometheus challenge --instance` and a holder proof. Present is not a bearer document. A missing, spent, expired, or wrong-instance challenge is refused. A revoked instance, an expired capability, a capability that does not belong to the instance, and a sealed issuer are refused.

The JSON container holds `instance_id`, `agent_type_id`, `capability_id`, `on_behalf_of`, `intent`, `audience`, `holder_public_key` (the first binder), `issuer_public_key_hex`, `presented_at`, `expires_at`, and `signature_hex`. `expires_at` is the earlier of the capability expiry and a 60-second presentation window. The signed bytes are the documented concatenation `prometheus-presentation|{instance_id}|{agent_type_id}|{capability_id}|{on_behalf_of}|{intent}|{audience}|{holder_public_key}|{issuer_public_key_hex}|{presented_at}|{expires_at}`. That is not JSON. Field reorder in the JSON container cannot change the signed bytes. The current issuer secret signs those bytes. Present does not write a sixth identity record. Holder proof reuses the existing `challenge_spent` log line.

`prometheus present verify --presentation FILE` reconstructs the signed bytes and checks the issuer signature. The issuer public key in the file must be on this store accept list, so a second store can verify a presentation after `issuer accept`. Refuse if now is at or after `expires_at` (the unit test injects a clock). Refuse tamper, an unknown key, and a missing signature. Verify-only: do not mint and do not write instance records. Historical presentation verify of an already-written document still succeeds after this store is sealed.

This is a signed presentation document. This is not a name. This is not a SPIFFE SVID. This is not an X.509 certificate. This is not a sixth identity record.

## Multi-signature issuance (STE100)

Honest cryptographic bound:

- This is not a Shamir split of `issuer.secret`. A Shamir split reconstitutes one key on one host. That is not threshold issuance.
- This is not FROST or threshold Edwards-curve Digital Signature Algorithm on Curve 25519 as the identity root. That root would be classical.
- This is not Federal Information Processing Standard 204 threshold Module-Lattice Digital Signature Algorithm. That scheme is not what this laboratory ships.
- A mint, birth, spawn, save-sign, log-append, receipt, or tree-head is valid only when at least `threshold_n` distinct Module-Lattice Digital Signature Algorithm 65 signatures from trusted issuer member keys verify over the same documented concatenation.
- When `threshold_n` is 1, one current Module-Lattice key signs, the same as before this work.

`prometheus issuer member add` installs a second Module-Lattice key pair for this store and writes `issuer-member-<first-16-hex-of-public-key>.secret` under the data directory. Need two members before `--n 2`. The Biscuit envelope key is not a member.

`prometheus issuer threshold --n K` sets `threshold_n`. K less than 1 is refused. K greater than the number of trusted Module-Lattice member keys is refused. Raising is allowed. Lowering is refused.

When `threshold_n` is greater than 1, issuer-signed artifacts store `issuer_signatures` as a list of `{public_key_hex, signature_hex}`. Verify counts distinct trusted Module-Lattice keys with valid signatures. The count must be at least `threshold_n`. Canonical byte strings stay the same concatenations. Each member signs the same bytes.

Mint, birth, spawn, and save-sign load `threshold_n` member secrets from `issuer.secret` plus additional `issuer-member-*.secret` files when n is greater than 1. One secret when n is 1. If only one secret is present when n is 2, refuse.

This is multi-signature issuance. This is not a sixth identity record.

## Invariants

- Attenuation can only reduce audience, intent, lifetime, or depth. Attenuation cannot widen rights.
- A child cannot gain rights that the parent does not have.
- A child act authority cannot widen to autonomous from a named user. A named-user parent may birth only a child of that same user.
- The instance cannot raise its own authorization limit.
- The type authorization limit is frozen after the first write. A later persist that raises `authorization_limit` is refused. `prometheus agent-type raise` always refuses. Narrowing a child of the stored limit may persist.
- The allowed intents are frozen after the first write. A later persist that adds an intent string is refused. `prometheus agent-type add-intent` always refuses. Removing an intent may persist. The same set may persist.
- The maximum delegation depth is frozen after the first write. A later persist that raises `max_delegation_depth` is refused. A lower depth may persist.
- The capability expiry is frozen after the first write. A later persist that moves `expires` later is refused. `prometheus capability extend` always refuses. A shorter expiry may persist. An attenuated child must not expire after the parent.
- Every mint, birth write, spawn, attenuate, kill, check, verify, and issuer rotate operation appends one JSON object as a line to `issuance.log`.
- Verification and check must fail if the capability identifier is not in the issuance log.
- Receipt verify must fail if `issuance_log_line` is missing from the receipt, is not present in the chosen issuance log, the chosen issuance log hash chain is broken, or the signing key is not an accepted current key and is not a previous key before its kill_date. A previous key after kill_date cannot mint. A new signature from that old key that is not in the issuance log is refused even if the signature is valid. A signature alone is not enough. An unknown issuer key is refused.
- `prometheus log verify` must fail if a line is missing `previous_line_hash` or `line_hash`, if a previous hash does not match the previous raw line, or if a line hash does not match the documented canonical form.
- `prometheus log prove` must fail if the `line_hash` is not in this issuance log. `prometheus log check-proof` must fail if the proof is empty, the sibling list is truncated, the leaf is not the claimed `line_hash`, or the recomputed root does not match the expected root. An old proof is accepted only against the old root.
- `prometheus log sign-root` must use the current issuer secret only. `prometheus log check-root` must fail if the Merkle root is missing, `leaf_count` is empty, the signature is missing, the Merkle root was tampered, the issuer key is unknown, or a previous key signed after its `kill_date`. A tree head signed before `kill_date` remains a historical pin.
- A kill operation records `revoke_identifier`. Verification fails when the capability is revoked.
- A parent kill stops the parent, all child instances, and all capabilities in those chains.
- Verify, check, spawn, and present require a one-time challenge nonce. A static challenge is not accepted. Present is not a bearer document.
- Check and verify must name `on_behalf_of`. Empty is not autonomous. The exact word `autonomous` is required. The value must match the capability token fact. A mismatch fails closed.
- The capability token facts must agree with the capability record on verify, check, host, and present. A wider intent, a wider audience, a different `on_behalf_of`, or a different `instance_id` is refused.
- Evaluate, verify, check, host, and present must refuse an instance or capability whose issuer signature is missing, wrong, or not from the current key or a previous key still before `kill_date`. A planted file cannot act. The store JSON is not enough.
- A mint, birth, spawn, save-sign, log-append, receipt, or tree-head must refuse when fewer than `threshold_n` distinct trusted Module-Lattice member signatures verify. Missing, untrusted, duplicate-key, and Biscuit-envelope signatures do not count. `prometheus issuer threshold --n K` must refuse K less than 1, K greater than the member count, and any lowering. Mint with one secret when `threshold_n` is 2 must refuse.
- There is no force-allow command and no debug bypass.
- The first binder is written once at birth or spawn. A later persist that replaces `holder_public_key` is refused. `prometheus instance rebind` always refuses. Kill, revoke, expire, and parent-kill do not rewrite `holder_public_key`.
- After `issuer.kill_date` this store refuses new mint, birth, spawn, issuer rotate, issuer accept, `log sign-root`, present, and act (verify, check, host). Historical `prometheus receipt verify` of an already-written receipt still succeeds. Historical `prometheus present verify` of an already-written presentation still succeeds. A later seal cannot postpone death.
- `prometheus act export` must fail if the receipt line is not in this store's issuance log or if the issuer is sealed. `prometheus act accept` must fail if any of `receipt.json`, `proof.json`, or `tree-head.json` is missing, if `check-root` fails, if `check-proof` fails against the tree-head `merkle_root`, if the receipt signature is not valid for this store's accept list, if `proof.line_hash` does not match the receipt bound line, or if `proof.root` does not match `tree-head.merkle_root`. Accept must not mint and must not write a second `issuance.log` line.
- `prometheus present` must fail if the instance is revoked, the capability is expired, the capability does not belong to the instance, the issuer is sealed, the capability token facts exceed or contradict the capability record, or the challenge is missing, spent, expired, or for the wrong instance. `prometheus present verify` must fail if the signature is missing, the signature does not match the reconstructed concatenation, the issuer public key is not on this store accept list, or now is at or after `expires_at`. Present verify must not mint and must not write instance records.

## Cryptography

The laboratory issuer profile name is `lab-ml-dsa-65-hybrid-biscuit-ed25519`. The crate is `fips204` 0.4.6. The Federal Information Processing Standard (FIPS) 204 parameter set is Module-Lattice Digital Signature Algorithm 65 (ML-DSA-65).

The identity root is Module-Lattice Digital Signature Algorithm. Record signatures, issuance-log line signatures, decision receipts, and signed tree heads use that root. Issuer init refuses a classical-only root. Profile `lab-ed25519` as the only issuer signature algorithm is refused.

The Biscuit envelope is still laboratory Edwards-curve Digital Signature Algorithm on Curve 25519 (Ed25519). biscuit-auth cannot carry Module-Lattice Digital Signature Algorithm yet. The Biscuit public key is stored as `biscuit_public_key_hex` on the existing issuer record. The Biscuit secret is a laboratory file `biscuit.secret`. The Biscuit key is a capability-envelope key, not the identity root. It must not be used to sign records, log lines, receipts, or tree heads.

This is not a production FIPS module. This is not a post-quantum Biscuit. This laboratory ships multi-signature issuance: at least `threshold_n` distinct trusted Module-Lattice member signatures over the same documented concatenation. This is not a Shamir split of `issuer.secret`. This is not FROST. This is not Federal Information Processing Standard 204 threshold Module-Lattice Digital Signature Algorithm.

The issuance log hash chain uses SHA-256. `previous_line_hash` and `line_hash` are lowercase hexadecimal SHA-256 digests. The first line's `previous_line_hash` is the SHA-256 digest of empty input. This is a local hash chain. This is not a public append-only service.

The local Merkle tree reuses those `line_hash` values as leaves. A parent node is the SHA-256 hexadecimal digest of the UTF-8 bytes of the left digest concatenated with the right digest. This is a local Merkle tree. This is not a public transparency log.

The signed tree head is Module-Lattice Digital Signature Algorithm over the UTF-8 bytes of `prometheus-signed-tree-head|{merkle_root}|{leaf_count}|{signed_at}|{issuer_public_key_hex}`. `signed_at` is RFC3339 UTC with seconds precision and a `Z` suffix. `leaf_count` is a decimal integer with no leading zeros, except the number 0. This is a locally signed Merkle root. This is not Certificate Transparency.

The presentation document is Module-Lattice Digital Signature Algorithm over the UTF-8 bytes of `prometheus-presentation|{instance_id}|{agent_type_id}|{capability_id}|{on_behalf_of}|{intent}|{audience}|{holder_public_key}|{issuer_public_key_hex}|{presented_at}|{expires_at}`. `presented_at` and `expires_at` are RFC3339 UTC with seconds precision and a `Z` suffix. This is a signed presentation document. This is not a name. This is not a SPIFFE SVID. This is not an X.509 certificate.

The instance record issuer signature is Module-Lattice Digital Signature Algorithm over the UTF-8 bytes of `prometheus-instance|{id}|{agent_type_id}|{owner}|{born}|{expires}|{holder_public_key}|{status}|{parent_instance_id}|{issuer_public_key_hex}`. The capability record issuer signature is Module-Lattice Digital Signature Algorithm over the UTF-8 bytes of `prometheus-capability|{id}|{instance_id}|{on_behalf_of}|{intent}|{audience}|{issued}|{expires}|{issuer_public_key_hex}`. Times are RFC3339 UTC with seconds precision and a `Z` suffix. This is a laboratory issuer signature on the JSON records. This is not a Merkle tree of the whole store. This is not a production FIPS module. This is not a post-quantum Biscuit.

## How to run the demonstrations

`prometheus status` prints a laboratory operator view of one store: cryptographic profile, current issuer public key (first eight and last eight hexadecimal characters plus length), the honest identity-root line, `threshold_n`, member count, sealed or not, record counts, issuance-log leaf count, Merkle root, and the loopback host reminder. Status refuses if the issuer is missing. Status does not print secrets.

`bash scripts/demo_walkthrough.sh` is one short walkthrough: init, status, birth, check, present, act, status, and one fail-closed refuse. Run it from this directory.

From this directory:

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

Optional: `just demo` if the `just` command is installed.

## Commands

```
prometheus --data-directory ./data init
prometheus --data-directory ./data status
prometheus --data-directory ./data agent-type add --owner <name> --intent read --authorization-limit payments
prometheus --data-directory ./data agent-type raise --agent-type <identifier> --authorization-limit public
prometheus --data-directory ./data agent-type add-intent --agent-type <identifier> --intent public
prometheus --data-directory ./data birth --agent-type <identifier> --owner <name> --intent read --audience payments
prometheus --data-directory ./data challenge --instance <identifier>
prometheus --data-directory ./data capability verify --capability <identifier> --audience payments --intent read --holder-secret-path ./data/holders/<instance>.secret --challenge-nonce <nonce> --on-behalf-of autonomous
prometheus --data-directory ./data capability attenuate --capability <identifier> --audience payments/prod --intent read/limited
prometheus --data-directory ./data spawn --parent-instance <identifier> --parent-capability <identifier> --owner child --intent read --audience payments/prod --holder-secret-path <path> --challenge-nonce <nonce>
prometheus --data-directory ./data check --instance <identifier> --capability <identifier> --intent read --audience payments --holder-secret-path <path> --challenge-nonce <nonce> --on-behalf-of autonomous
prometheus --data-directory ./data host --listen-address 127.0.0.1:18765
prometheus --data-directory ./data capability kill --capability <identifier>
prometheus --data-directory ./data capability extend --capability <identifier> --expires-at <time>
prometheus --data-directory ./data instance show --instance <identifier>
prometheus --data-directory ./data instance rebind --instance <identifier> --public-key-hex <hexadecimal>
prometheus --data-directory ./data instance kill --instance <identifier>
prometheus --data-directory ./data log show
prometheus --data-directory ./data log verify
prometheus --data-directory ./data log root
prometheus --data-directory ./data log prove --line-hash <hexadecimal>
prometheus --data-directory ./data log check-proof --proof ./proof.json
prometheus --data-directory ./data log check-proof --proof ./proof.json --root <hexadecimal>
prometheus --data-directory ./data log sign-root
prometheus --data-directory ./data log sign-root --output ./tree_head.json
prometheus --data-directory ./data log check-root --tree-head ./tree_head.json
prometheus --data-directory ./data log check-root --tree-head ./tree_head.json --require-current-root
prometheus --data-directory ./data receipt verify --receipt ./receipt.json
prometheus --data-directory ./data issuer accept --public-key-hex <hex>
prometheus --data-directory ./data issuer rotate --kill-after-seconds 300
prometheus --data-directory ./data issuer seal --after-seconds 60
prometheus --data-directory ./data issuer member add
prometheus --data-directory ./data issuer threshold --n 2
prometheus --data-directory ./other receipt verify --receipt ./receipt.json --issuance-log ./data/issuance.log
prometheus --data-directory ./data present --instance <identifier> --capability <identifier> --output ./presentation.json --holder-secret-path <path> --challenge-nonce <nonce>
prometheus --data-directory ./data present verify --presentation ./presentation.json
prometheus --data-directory ./other present verify --presentation ./presentation.json
prometheus --data-directory ./data act export --receipt ./receipt.json --output-directory ./act-bundle
prometheus --data-directory ./data act accept --bundle-directory ./act-bundle
```

## What this prototype does not implement

- Shamir split of `issuer.secret`, FROST or threshold Edwards-curve Digital Signature Algorithm on Curve 25519 as the identity root, and Federal Information Processing Standard 204 threshold Module-Lattice Digital Signature Algorithm. This laboratory ships multi-signature issuance: at least `threshold_n` distinct trusted Module-Lattice member signatures over the same documented concatenation.
- A production FIPS module. The laboratory identity root is Module-Lattice Digital Signature Algorithm 65. The Biscuit envelope is still laboratory Ed25519. This is not a production FIPS module. This is not a post-quantum Biscuit. Issuer init refuses a classical-only root.
- A public transparency log. This package writes a local JSON line log with a local SHA-256 hash chain, a local Merkle inclusion proof over those line_hash values, a locally signed Merkle tree head, and a laboratory signed decision receipt bound to that local log. The hash chain is not a public append-only service. The Merkle tree is not Certificate Transparency and not a gossiped signed tree head. The signed tree head is not Certificate Transparency, not a gossip protocol, not a public log, and not a multi-witness signed tree head. The receipt is not a public transparency log. The act bundle is a local export of those three artifacts, not Certificate Transparency gossip. Multi-signature issuance is implemented on this local store. This is not a public log.
- A production proof of possession. The holder challenge uses a nonce and a time window. This is still a laboratory method.
- A global name system, a second identity kernel, or SPIFFE federation. This package stores an accept list of issuer public keys for receipt verify. A second store can check a foreign receipt against the foreign issuance log, or accept a local act bundle of receipt plus inclusion proof plus signed tree head, without becoming a second identity kernel. This is not a global name system. This is not SPIFFE federation. This is not Certificate Transparency gossip.
- A secret holder. A secret holder is out of scope. Sanctum can hold secrets later.
- SPIFFE as identity. This package does not issue a SPIFFE document. Present is a signed presentation document, not a name. This package does not issue a SPIFFE SVID, an X.509 certificate, a WIMSE token, or a Transaction Token. The instance identifier must not become a certificate subject.
- Network identity outside the local loopback check host.
- A network partition detector, a liveness probe, or a multi-witness clock. Issuer seal is a pre-committed `issuer.kill_date` on this store. After that time this store refuses new mint and act. Historical receipt signature check may still succeed.

This package is laboratory code. This package is not affiliated with Sanctum. This package is not a Cyera product.

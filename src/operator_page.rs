//! Laboratory operator HTML page served on GET /laboratory of the loopback host.
//! This page is a static string. Behavior is unchanged. GET / is the later user interface.
//! The browser does not read secret files from disk. The operator pastes text.

/// HTML for the loopback operator page. Secrets are not embedded.
pub const OPERATOR_PAGE_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Prometheus loopback operator page</title>
<style>
body { font-family: sans-serif; margin: 1.5rem auto; max-width: 52rem; color: #111; }
label { display: block; margin-top: 0.85rem; font-weight: 600; }
textarea, input[type="text"], select { width: 100%; box-sizing: border-box; margin-top: 0.25rem; }
textarea { min-height: 8rem; font-family: monospace; }
pre { background: #f4f4f4; padding: 0.75rem; overflow: auto; white-space: pre-wrap; }
.note { color: #333; }
.result-allowed { color: #0a5a2a; font-weight: 700; }
.result-refused { color: #a20; font-weight: 700; }
button { margin-top: 0.85rem; padding: 0.4rem 0.8rem; }
</style>
</head>
<body>
<h1>Prometheus loopback operator page</h1>
<p>This page is a laboratory operator surface. This host binds to a loopback address only.</p>
<p>This page is not a public listener. This page is not the later full user interface.</p>
<p class="note">This page does not show issuer secrets, Biscuit secrets, holder secrets, or member-two secrets.</p>

<h2>Laboratory well-known check</h2>
<p>A runtime GETs <code>/.well-known/prometheus-check</code> on this loopback host. Then the runtime POSTs /check-svid or /check-wimse. The document names POST /verifier-challenge. A Store B check needs a holder signature over that nonce. The document names POST /seal-export, POST /seal-accept, POST /previous-key-export, and POST /previous-key-accept as operator pin paths.</p>
<p>The laboratory runtime starts from GET <code>/.well-known/prometheus-check</code>. The runtime learns check paths from that document only.</p>
<p>This document is a laboratory discovery artifact. This document is not a sixth identity record. This document is not a public listener. A later market name stays open.</p>
<pre id="well-known-check">The well-known check document is loading.</pre>
<button type="button" id="refresh-well-known-check">Refresh the well-known check document</button>

<h2>Store status</h2>
<p>The status view shows live and revoked instance counts. The issuer public key is truncated.</p>
<pre id="store-status">The status is loading.</pre>
<button type="button" id="refresh-status">Refresh the store status</button>

<h2>This store issuer public key</h2>
<p>GET /issuer-public returns the full current issuer public key hexadecimal and the crypto profile. GET /status stays truncated.</p>
<p class="note">Copy this public key. Paste it into Accept an issuer public key on a verifier host. This page does not fetch a foreign host. This page does not pair stores.</p>
<label for="this-store-issuer-public-key">Current issuer public key hexadecimal</label>
<textarea id="this-store-issuer-public-key" readonly></textarea>
<p id="this-store-crypto-profile">The crypto profile is loading.</p>
<button type="button" id="copy-issuer-public-key">Copy the issuer public key</button>
<button type="button" id="refresh-issuer-public">Refresh the issuer public key</button>

<h2>Add an agent type</h2>
<p>Fill allowed intents and the authorization limit. POST /agent-type reuses the kernel agent-type add. Allowed intents freeze after the first write.</p>
<p class="note">The response returns the agent type identifier and allowed intents only. Authorization limit is the highest destination. Init stays off this page.</p>

<label for="new-allowed-intents">Allowed intents</label>
<input id="new-allowed-intents" name="allowed_intents" type="text" value="read">
<p class="note">Separate more than one intent with a space.</p>

<label for="new-authorization-limit">Authorization limit</label>
<input id="new-authorization-limit" name="authorization_limit" type="text" value="internal">

<label for="new-agent-type-owner">Owner</label>
<input id="new-agent-type-owner" name="owner" type="text" value="laboratory">

<label for="agent-type-member-secret-path">Member secret path on this host</label>
<input id="agent-type-member-secret-path" name="member_secret_path" type="text">
<p class="note">Paste a path on this host when issuance threshold is two. This page does not read that file in the browser. Secret bytes are not uploaded. After issuance threshold_n is 2 this path is required on the agent-type body.</p>

<button type="button" id="add-agent-type">Add the agent type</button>
<p id="agent-type-result">No agent type has been added on this page.</p>

<h2>Birth an instance</h2>
<p>Choose an agent type. Fill intent and audience. POST /birth reuses the kernel birth write. The holder key is created on this host.</p>
<p class="note">The response returns the holder secret path only. Secret file bytes are not returned. After issuance threshold_n is 2, type the local outside member secret path. Init stays off this page.</p>

<label for="agent-type-id">Agent type</label>
<select id="agent-type-id" name="agent_type_id">
<option value="">No agent type is selected</option>
</select>

<label for="birth-owner">Owner</label>
<input id="birth-owner" name="owner" type="text" value="laboratory">

<label for="birth-intent">Intent</label>
<input id="birth-intent" name="intent" type="text" value="read">

<label for="birth-audience">Audience</label>
<input id="birth-audience" name="audience" type="text" value="internal">

<label for="birth-on-behalf-of">Act authority on_behalf_of</label>
<input id="birth-on-behalf-of" name="on_behalf_of" type="text" value="autonomous">

<label for="birth-member-secret-path">Member secret path on this host</label>
<input id="birth-member-secret-path" name="member_secret_path" type="text">
<p class="note">Paste a path on this host when issuance threshold is two. This page does not read that file in the browser. Secret bytes are not uploaded. After issuance threshold_n is 2 this path is required on the birth body.</p>

<button type="button" id="birth-instance">Birth an instance</button>
<p id="birth-result">No instance has been born on this page.</p>

<h2>Instances</h2>
<p>GET /instances lists instance identifiers, live or revoked status, capability identifiers, and parent_instance_id when the instance is a spawn child. Holder public keys and capability tokens are not shown. A child is a narrower act, not a role.</p>
<pre id="instance-list">The instance list is loading.</pre>
<button type="button" id="refresh-instances">Refresh the instance list</button>

<h2>Spawn a narrower child</h2>
<p>Pick a live parent. Fill a narrower intent and audience. POST /spawn reuses the kernel spawn write. The child cannot exceed the parent.</p>
<p class="note">The response returns the child holder secret path only. Secret file bytes are not returned. This page is not a role catalog. Init stays off this page.</p>

<label for="spawn-parent-instance-id">Live parent instance</label>
<select id="spawn-parent-instance-id" name="parent_instance_id">
<option value="">No live parent is selected</option>
</select>

<label for="spawn-parent-capability-id">Parent capability identifier</label>
<input id="spawn-parent-capability-id" name="parent_capability_id" type="text">

<label for="spawn-owner">Owner</label>
<input id="spawn-owner" name="owner" type="text" value="laboratory">

<label for="spawn-intent">Narrower intent</label>
<input id="spawn-intent" name="intent" type="text" value="read">

<label for="spawn-audience">Narrower audience</label>
<input id="spawn-audience" name="audience" type="text" value="internal/prod">

<label for="spawn-on-behalf-of">Act authority on_behalf_of</label>
<input id="spawn-on-behalf-of" name="on_behalf_of" type="text" value="autonomous">

<label for="spawn-holder-secret-path">Parent holder secret path on this host</label>
<input id="spawn-holder-secret-path" name="holder_secret_path" type="text">

<label for="spawn-holder-proof">Parent holder proof hexadecimal</label>
<input id="spawn-holder-proof" name="holder_proof" type="text">

<label for="spawn-challenge-nonce">Parent challenge nonce</label>
<input id="spawn-challenge-nonce" name="challenge_nonce" type="text">

<label for="spawn-member-secret-path">Member secret path on this host</label>
<input id="spawn-member-secret-path" name="member_secret_path" type="text">
<p class="note">Paste a path on this host when issuance threshold is two. This page does not read that file in the browser. Secret bytes are not uploaded. After issuance threshold_n is 2 this path is required on the spawn body.</p>

<button type="button" id="request-spawn-challenge">Request a parent challenge</button>
<button type="button" id="spawn-child">Spawn a narrower child</button>
<p id="spawn-result">No child has been spawned on this page.</p>

<h2>Kill a live instance</h2>
<p>Pick a live instance. Type the same instance identifier to confirm. POST /kill reuses the kernel local kill.</p>
<p>After kill, refresh shows revoked. A following POST /check-svid or POST /check-wimse of a historical present is refused. Reuse the present and check forms on this page.</p>
<p class="note">Init stays off this page. Secret bytes are not returned.</p>

<label for="kill-instance-id">Live instance to kill</label>
<select id="kill-instance-id" name="kill_instance_id">
<option value="">No live instance is selected</option>
</select>

<label for="kill-confirm">Type the instance identifier to confirm</label>
<input id="kill-confirm" name="confirm" type="text">

<label for="kill-member-secret-path">Member secret path on this host</label>
<input id="kill-member-secret-path" name="member_secret_path" type="text">
<p class="note">Paste a path on this host when issuance threshold is two. This page does not read that file in the browser. Secret bytes are not uploaded. After issuance threshold_n is 2 this path is required on the kill body.</p>

<button type="button" id="kill-instance">Kill the instance</button>
<p id="kill-result">No instance has been killed on this page.</p>

<h2>Seal the issuer</h2>
<p>Type the word seal to confirm. POST /seal reuses the kernel issuer seal. No second seal path.</p>
<p>After remaining life, mint, birth, spawn, present, check, and agent-type add are refused. Kill after seal stays allowed.</p>
<p class="note">A later host start refuses after seal. Secret bytes are not returned. Init stays off this page.</p>

<label for="seal-after-seconds">Seconds until issuer death</label>
<input id="seal-after-seconds" name="after_seconds" type="text" value="60">

<label for="seal-confirm">Type the word seal to confirm</label>
<input id="seal-confirm" name="seal_confirm" type="text">

<label for="seal-member-secret-path">Member secret path on this host</label>
<input id="seal-member-secret-path" name="member_secret_path" type="text">
<p class="note">Paste a path on this host when issuance threshold is two. This page does not read that file in the browser. Secret bytes are not uploaded. After issuance threshold_n is 2 this path is required on the seal body.</p>

<button type="button" id="seal-issuer">Seal the issuer</button>
<p id="seal-result">The issuer is not sealed on this page.</p>

<h2>Export a seal bundle</h2>
<p>After local seal, POST /seal-export reuses the kernel seal export.</p>
<p>The response returns event, proof, and tree_head. These are public artifacts. A verifier accepts the signed seal. The verifier does not copy the inode.</p>
<p class="note">A live issuer is refused. Secret bytes are not returned. Paste the artifacts on a verifier host into Accept a seal bundle.</p>
<label for="seal-export-member-secret-path">Member secret path on this host</label>
<input id="seal-export-member-secret-path" name="member_secret_path" type="text">
<p class="note">Paste a path on this host when issuance threshold is two. This page does not read that file in the browser. Secret bytes are not uploaded. After issuance threshold_n is 2 this path is required on the seal-export body.</p>
<button type="button" id="export-seal-bundle">Export the seal bundle</button>
<p id="seal-export-result">No seal bundle has been exported on this page.</p>
<pre id="seal-export-event">event.json is empty until export.</pre>
<pre id="seal-export-proof">proof.json is empty until export.</pre>
<pre id="seal-export-tree-head">tree-head.json is empty until export.</pre>

<h2>Rotate the issuer</h2>
<p>Type the word rotate to confirm. POST /rotate reuses the kernel issuer rotate. The previous public key keeps a kill date.</p>
<p>After rotate, GET /issuer-public returns the new current key. Then POST /previous-key-export can export the old key plus kill date.</p>
<p>After issuer seal, rotate is refused. Rotate writes a new issuer key.</p>
<p class="note">Secret bytes are not returned. The issuer secret path is not shown. Init stays off this page.</p>

<label for="rotate-kill-after-seconds">Seconds until the previous key kill date</label>
<input id="rotate-kill-after-seconds" name="kill_after_seconds" type="text" value="300">

<label for="rotate-confirm">Type the word rotate to confirm</label>
<input id="rotate-confirm" name="rotate_confirm" type="text">

<label for="rotate-member-secret-path">Member secret path on this host</label>
<input id="rotate-member-secret-path" name="member_secret_path" type="text">
<p class="note">Paste a path on this host when issuance threshold is two. This page does not read that file in the browser. Secret bytes are not uploaded. After issuance threshold_n is 2 this path is required on the rotate body.</p>

<button type="button" id="rotate-issuer">Rotate the issuer</button>
<p id="rotate-result">The issuer is not rotated on this page.</p>
<pre id="rotate-body">rotate JSON is empty until rotate.</pre>

<h2>Laboratory restore</h2>
<p>Backup, restore, and diagnose reuse the kernel. This is issuing loopback only. Check-only hosts refuse these writes. Standing data-a is not the restore dest.</p>
<p>The backup path must live outside the data directory. Restore onto a dest that already has an issuer is refused. Secret bytes are not returned.</p>
<p>Type the word backup or restore to confirm. POST /diagnose takes a from path only.</p>

<label for="backup-path">Backup path on this host</label>
<input id="backup-path" name="path" type="text">
<label for="backup-confirm">Type the word backup to confirm</label>
<input id="backup-confirm" name="confirm" type="text">
<button type="button" id="export-issuer-backup">Write the issuer backup</button>
<p id="backup-result">No issuer backup has been written on this page.</p>
<pre id="backup-body">backup JSON is empty until backup.</pre>

<label for="restore-from">Restore from path</label>
<input id="restore-from" name="from" type="text">
<label for="restore-confirm">Type the word restore to confirm</label>
<input id="restore-confirm" name="confirm" type="text">
<button type="button" id="restore-issuer-backup">Restore onto this empty store</button>
<p id="restore-result">No restore has run on this page.</p>
<pre id="restore-body">restore JSON is empty until restore.</pre>

<label for="diagnose-from">Diagnose from path</label>
<input id="diagnose-from" name="from" type="text">
<button type="button" id="diagnose-restore">Diagnose restore</button>
<p id="diagnose-result">No restore diagnostics have run on this page.</p>
<pre id="diagnose-body">diagnose JSON is empty until diagnose.</pre>

<h2>Register member two</h2>
<p>Type a local outside path. POST /member-two reuses the kernel member add. The host writes the second Module-Lattice member secret only at that path.</p>
<p>Member two is a second key for this same issuer. This is not a second store. After issuer seal this write is refused.</p>
<p class="note">This page does not read that file in the browser. Secret bytes are not uploaded. Secret bytes are not returned. A third laboratory member may be added on POST /member-two with a new outside path. Who holds member two in a later market stays open.</p>

<label for="member-two-secret-path">Member two secret path on this host</label>
<input id="member-two-secret-path" name="member_secret_path" type="text">

<button type="button" id="register-member-two">Register member two</button>
<p id="member-two-result">Member two is not registered on this page.</p>
<pre id="member-two-body">member-two JSON is empty until register.</pre>

<h2>Set verify threshold</h2>
<p>Type the word verify-threshold to confirm. POST /set-verify-threshold reuses the kernel verify-threshold write. Persist member two first.</p>
<p class="note">This path sets verify_threshold_n to 2 after member two exists. Secret bytes are not returned. Init stays off this page.</p>

<label for="verify-threshold-n">verify_threshold_n</label>
<input id="verify-threshold-n" name="n" type="text" value="2">

<label for="verify-threshold-confirm">Type the word verify-threshold to confirm</label>
<input id="verify-threshold-confirm" name="verify_threshold_confirm" type="text">

<label for="verify-threshold-member-secret-path">Member secret path on this host</label>
<input id="verify-threshold-member-secret-path" name="member_secret_path" type="text">
<p class="note">Paste a path on this host when issuance threshold is two. This page does not read that file in the browser. Secret bytes are not uploaded. After issuance threshold_n is 2 this path is required on the set-verify-threshold body.</p>

<button type="button" id="set-verify-threshold">Set the verify threshold</button>
<p id="verify-threshold-result">The verify threshold is not changed on this page.</p>
<pre id="verify-threshold-body">verify-threshold JSON is empty until set.</pre>

<h2>Set issuer threshold</h2>
<p>Type the word issuer-threshold to confirm. POST /set-issuer-threshold reuses the kernel issuance-threshold write. Persist member two first.</p>
<p class="note">This path sets threshold_n to 2 after member two exists. n=3 is allowed when three members exist. Standing data-a stays 2. Secret bytes are not returned. Init stays off this page.</p>

<label for="issuer-threshold-n">threshold_n</label>
<input id="issuer-threshold-n" name="n" type="text" value="2">

<label for="issuer-threshold-confirm">Type the word issuer-threshold to confirm</label>
<input id="issuer-threshold-confirm" name="issuer_threshold_confirm" type="text">

<button type="button" id="set-issuer-threshold">Set the issuer threshold</button>
<p id="issuer-threshold-result">The issuer threshold is not changed on this page.</p>
<pre id="issuer-threshold-body">issuer-threshold JSON is empty until set.</pre>

<h2>Export a previous issuer key</h2>
<p>After POST /rotate writes a previous issuer key with a kill date, POST /previous-key-export returns the public key hexadecimal and that kill date.</p>
<p>These are public artifacts. A verifier accepts the previous key and its kill date. The verifier does not copy issuer secrets.</p>
<p class="note">A previous key without a kill date is refused. Secret bytes are not returned. Paste the artifacts on a verifier host into Accept a previous issuer key.</p>
<button type="button" id="export-previous-key">Export the previous issuer key</button>
<p id="previous-key-export-result">No previous issuer key has been exported on this page.</p>
<pre id="previous-key-export-body">previous-key JSON is empty until export.</pre>

<h2>Export a kill bundle</h2>
<p>After local kill, pick the revoked instance. Type the same identifier to confirm. POST /kill-export reuses the kernel kill export.</p>
<p>The response returns event, proof, and tree_head. These are public artifacts. A verifier accepts the signed bundle. The verifier does not copy the inode.</p>
<p class="note">Secret bytes are not returned. Init stays off this page. Paste the artifacts on a verifier host into Accept a kill bundle.</p>

<label for="kill-export-instance-id">Revoked instance</label>
<select id="kill-export-instance-id" name="kill_export_instance_id">
<option value="">No revoked instance is selected</option>
</select>

<label for="kill-export-confirm">Type the instance identifier to confirm</label>
<input id="kill-export-confirm" name="kill_export_confirm" type="text">

<label for="kill-export-member-secret-path">Member secret path on this host</label>
<input id="kill-export-member-secret-path" name="member_secret_path" type="text">
<p class="note">Paste a path on this host when issuance threshold is two. This page does not read that file in the browser. Secret bytes are not uploaded. After issuance threshold_n is 2 this path is required on the kill-export body.</p>

<button type="button" id="export-kill-bundle">Export the kill bundle</button>
<p id="kill-export-result">No kill bundle has been exported on this page.</p>
<pre id="kill-export-event">event.json is empty until export.</pre>
<pre id="kill-export-proof">proof.json is empty until export.</pre>
<pre id="kill-export-tree-head">tree-head.json is empty until export.</pre>
<button type="button" id="download-kill-event">Download event.json</button>
<button type="button" id="download-kill-proof">Download proof.json</button>
<button type="button" id="download-kill-tree-head">Download tree-head.json</button>

<label for="check-base">Check base</label>
<input id="check-base" name="check_base" type="text" autocomplete="off">
<p class="note">The accepted bases are http://127.0.0.1 on this host or https://check.prestigeworldwide.digital. Verifier pins follow GET /.well-known/prometheus-check on that base. This page posts POST /well-known-follow and POST /operator-pin on this store. This page does not fetch the public name. Other names are refused. HTTP to the public name is refused.</p>

<h2>Accept an issuer public key</h2>
<p>Paste a foreign issuer public key hexadecimal. POST /issuer-accept reuses the kernel issuer accept.</p>
<p class="note">This store pins the public key only. This store does not copy issuer secrets. This store does not mint.</p>

<label for="issuer-public-key-hex">Foreign issuer public key hexadecimal</label>
<input id="issuer-public-key-hex" name="public_key_hex" type="text">

<button type="button" id="accept-issuer-key">Accept the issuer public key</button>
<p id="issuer-accept-result">No issuer public key has been accepted on this page.</p>

<h2>Accept a kill bundle</h2>
<p>Paste or load the three public artifacts from POST /kill-export. POST /kill-accept reuses the kernel kill accept.</p>
<p>This verifier accepts signed death. This verifier does not copy the inode. After accept, POST /check-svid of that wrap on this host refuses.</p>
<p class="note">This store writes no instance record. This store does not mint. Secret bytes are not returned.</p>

<label for="kill-accept-export-json">Kill-export JSON</label>
<textarea id="kill-accept-export-json" name="kill_accept_export_json"></textarea>
<button type="button" id="load-kill-accept-bundle">Load the three artifacts</button>

<label for="kill-accept-event">event</label>
<textarea id="kill-accept-event" name="event"></textarea>

<label for="kill-accept-proof">proof</label>
<textarea id="kill-accept-proof" name="proof"></textarea>

<label for="kill-accept-tree-head">tree_head</label>
<textarea id="kill-accept-tree-head" name="tree_head"></textarea>

<button type="button" id="accept-kill-bundle">Accept the kill bundle</button>
<p id="kill-accept-result">No kill bundle has been accepted on this page.</p>
<pre id="kill-accept-accepted">Accepted identifiers are empty until accept.</pre>
<pre id="kill-accept-instances">This store wrote no instance record until refresh.</pre>

<h2>Accept a seal bundle</h2>
<p>Paste or load the three public artifacts from POST /seal-export. POST /seal-accept reuses the kernel seal accept.</p>
<p>This verifier pins accepted seal on the issuer record. This verifier writes no instance record. After accept, present and act for that issuer pin refuse.</p>
<p class="note">This store does not mint. This store does not copy issuer secrets. Secret bytes are not returned. Clearing an accepted seal is refused.</p>
<label for="seal-accept-export-json">Seal-export JSON</label>
<textarea id="seal-accept-export-json" name="seal_accept_export_json"></textarea>
<button type="button" id="load-seal-accept-bundle">Load the three artifacts</button>
<label for="seal-accept-event">event</label>
<textarea id="seal-accept-event" name="event"></textarea>
<label for="seal-accept-proof">proof</label>
<textarea id="seal-accept-proof" name="proof"></textarea>
<label for="seal-accept-tree-head">tree_head</label>
<textarea id="seal-accept-tree-head" name="tree_head"></textarea>
<button type="button" id="accept-seal-bundle">Accept the seal bundle</button>
<p id="seal-accept-result">No seal bundle has been accepted on this page.</p>
<pre id="seal-accept-accepted">Accepted seal is empty until accept.</pre>
<pre id="seal-accept-instances">This store wrote no instance record until refresh.</pre>

<h2>Accept a previous issuer key</h2>
<p>Paste the public key hexadecimal and kill date from POST /previous-key-export. POST /previous-key-accept reuses the kernel previous-key accept.</p>
<p>This verifier pins accepted previous-key kill on the issuer record. This verifier writes no instance record. After the kill date, a present signed only by that previous key is refused.</p>
<p class="note">This store does not mint. This store does not copy issuer secrets. Secret bytes are not returned. Truncated hex, the envelope key, postpone, remove, and clearing are refused.</p>
<label for="previous-key-accept-export-json">Previous-key-export JSON</label>
<textarea id="previous-key-accept-export-json" name="previous_key_accept_export_json"></textarea>
<button type="button" id="load-previous-key-accept">Load the public artifacts</button>
<label for="previous-key-accept-public-key">public_key_hex</label>
<input id="previous-key-accept-public-key" name="public_key_hex" type="text">
<label for="previous-key-accept-kill-date">kill_date</label>
<input id="previous-key-accept-kill-date" name="kill_date" type="text">
<button type="button" id="accept-previous-key">Accept the previous issuer key</button>
<p id="previous-key-accept-result">No previous issuer key has been accepted on this page.</p>
<pre id="previous-key-accept-instances">This store wrote no instance record until refresh.</pre>

<h2>Accept an act bundle</h2>
<p>Paste or load the three public artifacts from POST /act-export. POST /act-accept reuses the kernel act accept.</p>
<p>This verifier verifies the signed act. This verifier does not copy the inode. This verifier writes no instance record.</p>
<p class="note">This store does not mint. Secret bytes are not returned. Accept the issuer public key first.</p>

<label for="act-accept-export-json">Act-export JSON</label>
<textarea id="act-accept-export-json" name="act_accept_export_json"></textarea>
<button type="button" id="load-act-accept-bundle">Load the three artifacts</button>

<label for="act-accept-receipt">receipt</label>
<textarea id="act-accept-receipt" name="receipt"></textarea>

<label for="act-accept-proof">proof</label>
<textarea id="act-accept-proof" name="proof"></textarea>

<label for="act-accept-tree-head">tree_head</label>
<textarea id="act-accept-tree-head" name="tree_head"></textarea>

<button type="button" id="accept-act-bundle">Accept the act bundle</button>
<p id="act-accept-result">No act bundle has been accepted on this page.</p>
<pre id="act-accept-instances">This store wrote no instance record until refresh.</pre>

<h2>Challenge and emit a laboratory X.509-SVID wrap</h2>
<p>Pick a live instance. Request a challenge. Emit the wrap. Then submit POST /check-svid on this same page.</p>
<p>The host process reads the holder secret path on this computer. This page does not upload secret file bytes.</p>

<label for="instance-id">Live instance</label>
<select id="instance-id" name="instance_id">
<option value="">No live instance is selected</option>
</select>

<label for="capability-id">Capability identifier</label>
<input id="capability-id" name="capability_id" type="text">

<label for="wrap-intent">Intent</label>
<input id="wrap-intent" name="intent" type="text" value="read">

<label for="wrap-audience">Audience</label>
<input id="wrap-audience" name="audience" type="text" value="internal">

<label for="holder-proof">Holder proof hexadecimal</label>
<input id="holder-proof" name="holder_proof" type="text">

<label for="holder-secret-path">Holder secret path on this host</label>
<input id="holder-secret-path" name="holder_secret_path" type="text">
<p class="note">Paste a path on this host if you use a secret file. This page does not read that file in the browser.</p>

<label for="present-member-secret-path">Member secret path on this host</label>
<input id="present-member-secret-path" name="member_secret_path" type="text">
<p class="note">Paste a path on this host when issuance threshold is two. This page does not read that file in the browser. Secret bytes are not uploaded. After issuance threshold_n is 2 this path is required on the present-svid, present-wimse, challenge, and issuing-store check-svid and check-wimse body. Store B verify does not need this path.</p>

<label for="challenge-nonce">Challenge nonce</label>
<input id="challenge-nonce" name="challenge_nonce" type="text">

<label for="challenge-message">Verifier challenge message</label>
<input id="challenge-message" name="challenge_message" type="text">

<h2>Verifier challenge</h2>
<p>A verifier that is not a replica issues a short-lived nonce. This is an artifact. This is not a record. This store writes no instance.</p>
<p>On Store B, request a verifier challenge. Sign the nonce on the issuing host or this workstation. Paste the holder signature into Holder proof hexadecimal. Store B does not open a holder secret file.</p>
<p class="note">Sign reads the holder secret path you typed on this computer. Secret bytes are not returned. Paste the signature onto the Store B check.</p>
<button type="button" id="request-verifier-challenge">Request a verifier challenge</button>
<button type="button" id="sign-verifier-nonce">Sign the verifier nonce on this host</button>
<p id="verifier-challenge-result">No verifier challenge has been issued.</p>

<label for="on-behalf-of">Act authority on_behalf_of</label>
<input id="on-behalf-of" name="on_behalf_of" type="text" value="autonomous">

<button type="button" id="request-challenge">Request a challenge</button>
<button type="button" id="emit-wrap">Emit the wrap</button>
<p id="wrap-result">No wrap has been emitted.</p>

<h2>Check a laboratory X.509-SVID wrap</h2>
<p>Emit fills the presentation JSON and the certificate PEM. Type a check base. This origin follows GET /.well-known/prometheus-check and posts the documented check path. A different accepted base uses POST /runtime-check on this store. Other names are refused. HTTP to the public name is refused.</p>
<p>Holder proof remains required. After emit, this page requests a new challenge because present spends the first nonce.</p>

<form id="check-form">
<label for="presentation-json">Presentation JSON</label>
<textarea id="presentation-json" name="presentation_json" required></textarea>

<label for="certificate-pem">Certificate PEM</label>
<textarea id="certificate-pem" name="certificate_pem" required></textarea>

<button type="submit">Submit the check</button>
</form>

<h2>Challenge and emit a laboratory Workload Identity Token</h2>
<p>Pick a live instance. Request a challenge. Emit the token. Then submit POST /check-wimse on this same page.</p>
<p>The host process reads the holder secret path on this computer. This page does not upload secret file bytes.</p>
<p class="note">POST /check-wimse binds HTTP @method, @request-target, and content-digest. Emit returns that signature. This page sends Signature-Input, Signature, and Content-Digest. Secret bytes stay off this page. This is still not a full header-coverage stack.</p>

<button type="button" id="emit-wimse">Emit the Workload Identity Token</button>
<p id="wimse-result">No Workload Identity Token has been emitted.</p>

<h2>Check a laboratory Workload Identity Token</h2>
<p>Emit fills the presentation JSON, the Workload Identity Token, Content-Digest, and the HTTP Message Signature. That signature covers @method, @request-target, and content-digest. Type a check base. This origin follows GET /.well-known/prometheus-check and posts the documented check path. A different accepted base uses POST /runtime-check on this store. Other names are refused. HTTP to the public name is refused.</p>
<p>Holder proof remains required. After emit, this page requests a new challenge because present spends the first nonce.</p>
<p class="note">The instance identifier stays inside the present. The token subject names the present hash. Secret bytes are not shown.</p>

<form id="check-wimse-form">
<label for="wimse-presentation-json">Presentation JSON</label>
<textarea id="wimse-presentation-json" name="presentation_json" required></textarea>

<label for="workload-identity-token">Workload Identity Token</label>
<textarea id="workload-identity-token" name="workload_identity_token" required></textarea>

<label for="content-digest">Content-Digest</label>
<input id="content-digest" name="content_digest" type="text">

<input id="wimse-signature-input" name="signature_input" type="hidden">
<input id="wimse-signature" name="signature" type="hidden">

<button type="submit">Submit the WIMSE check</button>
</form>

<button type="button" id="check-again">Check again</button>
<p class="note">Check again posts the same present to the typed check base. This page does not store ALLOWED. Each click hits the host.</p>

<h2>Decision</h2>
<p id="decision-result">No check has been submitted.</p>
<p id="decision-reason"></p>
<pre id="decision-body"></pre>

<h2>Export an act bundle</h2>
<p>After a successful check, POST /act-export reuses the kernel act export. The body is the signed check receipt.</p>
<p>The response returns receipt, proof, and tree_head. These are public artifacts. A verifier accepts the signed bundle. The verifier does not copy the inode.</p>
<p class="note">Secret bytes are not returned. Paste the artifacts on a verifier host into Accept an act bundle.</p>

<label for="act-export-receipt">Check receipt JSON</label>
<textarea id="act-export-receipt" name="receipt"></textarea>

<label for="act-export-member-secret-path">Member secret path on this host</label>
<input id="act-export-member-secret-path" name="member_secret_path" type="text">
<p class="note">Paste a path on this host when issuance threshold is two. This page does not read that file in the browser. Secret bytes are not uploaded. After issuance threshold_n is 2 this path is required on the act-export body.</p>

<button type="button" id="export-act-bundle">Export the act bundle</button>
<p id="act-export-result">No act bundle has been exported on this page.</p>
<pre id="act-export-receipt-out">receipt.json is empty until export.</pre>
<pre id="act-export-proof">proof.json is empty until export.</pre>
<pre id="act-export-tree-head">tree-head.json is empty until export.</pre>

<script>
function el(id) { return document.getElementById(id); }
function setResult(id, text, allowed) {
  var node = el(id);
  node.textContent = text;
  node.className = allowed ? "result-allowed" : "result-refused";
}
function postJson(path, body, extraHeaders) {
  var headers = { "Content-Type": "application/json" };
  if (extraHeaders) {
    Object.keys(extraHeaders).forEach(function (name) {
      if (extraHeaders[name]) { headers[name] = extraHeaders[name]; }
    });
  }
  return fetch(path, { method: "POST", headers: headers, body: JSON.stringify(body) })
    .then(function (response) {
      return response.text().then(function (text) { return { ok: response.ok, text: text }; });
    });
}
function readJsonPayload(payload, failText) {
  try { return JSON.parse(payload.text); }
  catch (error) { throw new Error(failText); }
}
function typedCheckBase() {
  var raw = (el("check-base").value || "").trim();
  if (!raw) { raw = location.origin; }
  if (raw.charAt(raw.length - 1) === "/") { raw = raw.slice(0, -1); }
  return raw;
}
function refuseTypedCheckBase(base) {
  var lower = (base || "").toLowerCase();
  if (lower.indexOf("http://check.prestigeworldwide.digital") === 0) {
    return "HTTP to check.prestigeworldwide.digital is refused. The laboratory runtime uses HTTPS for that name. Loopback stays raw HTTP on 127.0.0.1.";
  }
  var loopback = /^http:\/\/127\.0\.0\.1(?::\d+)?$/i.test(base);
  var publicName = /^https:\/\/check\.prestigeworldwide\.digital(?::443)?$/i.test(base);
  if (!loopback && !publicName) {
    return "The laboratory runtime accepts http://127.0.0.1 or https://check.prestigeworldwide.digital. Other hosts are refused.";
  }
  return "";
}
function isThisOriginCheckBase(base) {
  return base === location.origin;
}
function documentedPinPath(document, pinName) {
  var want = String(pinName || "").replace(/^\/+/, "").toLowerCase();
  if (!want) { throw new Error("The well-known check document does not name that operator pin. The check fails closed."); }
  var writeVerbs = ["/birth", "/spawn", "/present-svid", "/present-wimse", "/agent-type", "/kill", "/seal", "/rotate", "/sign-holder-nonce", "/member-two", "/act-export", "/kill-export", "/seal-export", "/previous-key-export", "/backup", "/restore", "/diagnose"];
  var lists = (document.operator_pin_paths || []).concat(document.checks || []);
  if (document.verifier_challenge) { lists = lists.concat([document.verifier_challenge]); }
  var found = null;
  for (var i = 0; i < lists.length; i++) {
    var path = (lists[i].path || "").replace(/^\/+/, "").toLowerCase();
    if (path === want || path.slice(-(want.length + 1)) === "-" + want) { found = lists[i]; break; }
  }
  if (!found || !found.path) { throw new Error("The well-known check document does not name " + pinName + ". The check fails closed."); }
  if ((found.method || "POST") !== "POST") { throw new Error("The documented pin method must be POST. The check fails closed."); }
  var exact = found.path;
  for (var j = 0; j < writeVerbs.length; j++) {
    if (exact === writeVerbs[j] || exact.indexOf(writeVerbs[j] + "/") === 0 || exact.indexOf(writeVerbs[j] + "?") === 0) {
      throw new Error("The well-known check document names a write verb. The check fails closed.");
    }
  }
  return exact;
}
function followWellKnownThenPin(pinName, body, resultId, onOk) {
  var base = typedCheckBase();
  var refuse = refuseTypedCheckBase(base);
  if (refuse) { setResult(resultId, refuse, false); return; }
  if (isThisOriginCheckBase(base)) {
    fetch("/.well-known/prometheus-check").then(function (response) {
      if (!response.ok) { throw new Error("well-known"); }
      return response.json();
    }).then(function (document) {
      return postJson(documentedPinPath(document, pinName), body);
    }).then(onOk).catch(function (error) {
      setResult(resultId, error.message || "The well-known check document was not followed. The check fails closed.", false);
    });
    return;
  }
  postJson("/well-known-follow", { check_base: base }).then(function (payload) {
    var document = readJsonPayload(payload, "The well-known follow response is not valid JSON. The check fails closed.");
    if (!payload.ok) { throw new Error(document.reason || "The well-known check document was not followed. The check fails closed."); }
    documentedPinPath(document, pinName);
    return postJson("/operator-pin", { check_base: base, pin: pinName, body: body });
  }).then(onOk).catch(function (error) {
    setResult(resultId, error.message || "The well-known check document was not followed. The check fails closed.", false);
  });
}

function documentedCheckPath(document, onRamp) {
  var names = document.on_ramp_artifacts || [];
  var checks = document.checks || [];
  var index = names.indexOf(onRamp);
  if (index < 0 || !checks[index] || !checks[index].path) {
    throw new Error("The well-known check document does not name " + onRamp + ". The check fails closed.");
  }
  if ((checks[index].method || "POST") !== "POST") {
    throw new Error("The documented check method must be POST. The check fails closed.");
  }
  return checks[index].path;
}
function followWellKnownThenCheck(onRamp, usePath) {
  fetch("/.well-known/prometheus-check").then(function (response) {
    if (!response.ok) { throw new Error("well-known"); }
    return response.json();
  }).then(function (document) {
    usePath(documentedCheckPath(document, onRamp));
  }).catch(function () {
    setResult("decision-result", "The well-known check document was not followed. The check fails closed.", false);
  });
}
function checkBody(presentationId) {
  var body = {
    presentation_json: el(presentationId).value,
    intent: el("wrap-intent").value,
    audience: el("wrap-audience").value,
    holder_proof: el("holder-proof").value || null,
    holder_secret_path: el("holder-proof").value ? null : (el("holder-secret-path").value || null),
    challenge_nonce: el("challenge-nonce").value || null,
    on_behalf_of: el("on-behalf-of").value || null
  };
  addMemberSecretPath(body, "present-member-secret-path");
  return body;
}
function runtimeCheckBody(kind) {
  var presentationId = kind === "wimse" ? "wimse-presentation-json" : "presentation-json";
  var body = {
    check_base: typedCheckBase(),
    presentation_json: el(presentationId).value,
    holder_proof: el("holder-proof").value || null
  };
  if (!el("holder-proof").value) {
    var holderPath = (el("holder-secret-path").value || "").trim();
    if (holderPath) { body.holder_secret_path = holderPath; }
  }
  if (kind === "wimse") {
    body.workload_identity_token = el("workload-identity-token").value;
    body.content_digest = el("content-digest").value;
    body.signature_input = el("wimse-signature-input").value;
    body.signature = el("wimse-signature").value;
  } else {
    body.certificate_pem = el("certificate-pem").value;
  }
  return body;
}
function showDecision(payload) {
  el("decision-body").textContent = payload.text;
  try {
    var data = JSON.parse(payload.text);
    if (data.result === "allowed") {
      el("decision-result").textContent = "The host allowed the tool action.";
      el("decision-result").className = "result-allowed";
      if (data.receipt) {
        el("act-export-receipt").value = JSON.stringify(data.receipt, null, 2);
      }
    } else {
      el("decision-result").textContent = "The host refused the tool action.";
      el("decision-result").className = "result-refused";
    }
    if (data.reason) {
      el("decision-reason").textContent = data.reason;
    } else {
      el("decision-reason").textContent = "The host did not supply a reason sentence.";
    }
  } catch (error) {
    el("decision-result").textContent = "The host returned a body that is not valid JSON. The check fails closed.";
    el("decision-result").className = "result-refused";
    el("decision-reason").textContent = "";
  }
}
var lastCheckKind = "";
function submitCheckSvid() {
  lastCheckKind = "svid";
  var base = typedCheckBase();
  var refuse = refuseTypedCheckBase(base);
  if (refuse) { setResult("decision-result", refuse, false); return; }
  if (isThisOriginCheckBase(base)) {
    followWellKnownThenCheck("X.509-SVID", function (path) {
      var body = checkBody("presentation-json");
      body.certificate_pem = el("certificate-pem").value;
      postJson(path, body).then(showDecision).catch(function () {
        setResult("decision-result", "The host did not answer. The check fails closed.", false);
      });
    });
    return;
  }
  postJson("/runtime-check", runtimeCheckBody("svid")).then(showDecision).catch(function () {
    setResult("decision-result", "The host did not answer. The check fails closed.", false);
  });
}
function submitCheckWimse() {
  lastCheckKind = "wimse";
  var base = typedCheckBase();
  var refuse = refuseTypedCheckBase(base);
  if (refuse) { setResult("decision-result", refuse, false); return; }
  if (isThisOriginCheckBase(base)) {
    followWellKnownThenCheck("WIMSE", function (path) {
      var body = checkBody("wimse-presentation-json");
      body.workload_identity_token = el("workload-identity-token").value;
      body.content_digest = el("content-digest").value;
      postJson(path, body, { "Signature-Input": el("wimse-signature-input").value, "Signature": el("wimse-signature").value, "Content-Digest": body.content_digest }).then(showDecision).catch(function () {
        setResult("decision-result", "The host did not answer. The check fails closed.", false);
      });
    });
    return;
  }
  postJson("/runtime-check", runtimeCheckBody("wimse")).then(showDecision).catch(function () {
    setResult("decision-result", "The host did not answer. The check fails closed.", false);
  });
}
function checkAgain() {
  if (lastCheckKind === "wimse") { submitCheckWimse(); return; }
  if (lastCheckKind === "svid") { submitCheckSvid(); return; }
  setResult("decision-result", "Submit a check before you check again. The check fails closed.", false);
}

function showStatus(text) {
  document.getElementById("store-status").textContent = text;
}

function loadWellKnownCheck() {
  fetch("/.well-known/prometheus-check")
    .then(function (response) { return response.text(); })
    .then(function (text) {
      try {
        var data = JSON.parse(text);
        document.getElementById("well-known-check").textContent = JSON.stringify(data, null, 2);
      } catch (error) {
        document.getElementById("well-known-check").textContent = "The well-known check response is not valid JSON. The check fails closed.";
      }
    })
    .catch(function () {
      document.getElementById("well-known-check").textContent = "The host did not return the well-known check document. The check fails closed.";
    });
}

function loadStatus() {
  fetch("/status")
    .then(function (response) { return response.text(); })
    .then(function (text) {
      try {
        var data = JSON.parse(text);
        showStatus(JSON.stringify(data, null, 2));
      } catch (error) {
        showStatus("The status response is not valid JSON. The check fails closed.");
      }
    })
    .catch(function () {
      showStatus("The host did not return store status. The check fails closed.");
    });
}

function loadIssuerPublic() {
  fetch("/issuer-public")
    .then(function (response) { return response.text(); })
    .then(function (text) {
      try {
        var data = JSON.parse(text);
        document.getElementById("this-store-issuer-public-key").value = data.current_issuer_public_key_hex || "";
        if (data.crypto_profile) {
          document.getElementById("this-store-crypto-profile").textContent = "crypto_profile: " + data.crypto_profile;
        } else {
          document.getElementById("this-store-crypto-profile").textContent = "The crypto profile is missing. The check fails closed.";
        }
      } catch (error) {
        document.getElementById("this-store-issuer-public-key").value = "";
        document.getElementById("this-store-crypto-profile").textContent = "The issuer-public response is not valid JSON. The check fails closed.";
      }
    })
    .catch(function () {
      document.getElementById("this-store-issuer-public-key").value = "";
      document.getElementById("this-store-crypto-profile").textContent = "The host did not return the issuer public key. The check fails closed.";
    });
}

function copyIssuerPublicKey() {
  var box = document.getElementById("this-store-issuer-public-key");
  box.focus();
  box.select();
  try {
    document.execCommand("copy");
  } catch (error) {
  }
}

function selectedInstanceId() {
  return document.getElementById("instance-id").value;
}

function instanceListingLabel(listing) {
  var label = listing.instance_id + " " + listing.status;
  if (listing.parent_instance_id) {
    label += " parent " + listing.parent_instance_id;
  }
  return label;
}

function formatInstanceList(instances) {
  return JSON.stringify(instances, ["instance_id", "parent_instance_id", "status", "capability_ids", "agent_type_id"], 2);
}

function fillOneInstanceSelect(selectId, instances) {
  var select = document.getElementById(selectId);
  var previous = select.value;
  select.innerHTML = "";
  var placeholder = document.createElement("option");
  placeholder.value = "";
  placeholder.textContent = "No live instance is selected";
  select.appendChild(placeholder);
  var liveCount = 0;
  for (var index = 0; index < instances.length; index += 1) {
    var listing = instances[index];
    if (listing.status !== "live") {
      continue;
    }
    var option = document.createElement("option");
    option.value = listing.instance_id;
    option.textContent = instanceListingLabel(listing);
    option.setAttribute("data-capability-ids", (listing.capability_ids || []).join(" "));
    select.appendChild(option);
    liveCount += 1;
  }
  if (previous) {
    select.value = previous;
  }
  if (liveCount === 0) {
    placeholder.textContent = "No live instance is on this store";
  }
}

function fillRevokedInstanceSelect(selectId, instances) {
  var select = document.getElementById(selectId);
  var previous = select.value;
  select.innerHTML = "";
  var placeholder = document.createElement("option");
  placeholder.value = "";
  placeholder.textContent = "No revoked instance is selected";
  select.appendChild(placeholder);
  var revokedCount = 0;
  for (var index = 0; index < instances.length; index += 1) {
    var listing = instances[index];
    if (listing.status !== "revoked") {
      continue;
    }
    var option = document.createElement("option");
    option.value = listing.instance_id;
    option.textContent = instanceListingLabel(listing);
    select.appendChild(option);
    revokedCount += 1;
  }
  if (previous) {
    select.value = previous;
  }
  if (revokedCount === 0) {
    placeholder.textContent = "No revoked instance is on this store";
  }
}

function fillInstanceSelect(instances) {
  fillOneInstanceSelect("instance-id", instances);
  fillOneInstanceSelect("kill-instance-id", instances);
  fillOneInstanceSelect("spawn-parent-instance-id", instances);
  fillRevokedInstanceSelect("kill-export-instance-id", instances);
}

function capabilityIdsFromSelect(selectId) {
  var select = document.getElementById(selectId);
  if (!select || !select.value) {
    return [];
  }
  var option = select.options[select.selectedIndex];
  if (!option) {
    return [];
  }
  return (option.getAttribute("data-capability-ids") || "").split(" ").filter(function (value) {
    return value.length > 0;
  });
}

function fillCapabilityFieldFromSelect(selectId, fieldId) {
  var field = document.getElementById(fieldId);
  if (!field) {
    return;
  }
  var ids = capabilityIdsFromSelect(selectId);
  if (ids.length === 0) {
    return;
  }
  if (ids.indexOf(field.value) !== -1) {
    return;
  }
  field.value = ids[0];
}

function applySelectedInstanceCapabilities() {
  fillCapabilityFieldFromSelect("instance-id", "capability-id");
  fillCapabilityFieldFromSelect("spawn-parent-instance-id", "spawn-parent-capability-id");
}

function loadInstances(selectInstanceId, selectExportInstanceId) {
  fetch("/instances")
    .then(function (response) { return response.text(); })
    .then(function (text) {
      try {
        var data = JSON.parse(text);
        var instances = data.instances || [];
        document.getElementById("instance-list").textContent = formatInstanceList(instances);
        fillInstanceSelect(instances);
        if (selectInstanceId) {
          document.getElementById("instance-id").value = selectInstanceId;
          document.getElementById("kill-instance-id").value = selectInstanceId;
          document.getElementById("spawn-parent-instance-id").value = selectInstanceId;
        }
        if (selectExportInstanceId) {
          document.getElementById("kill-export-instance-id").value = selectExportInstanceId;
        }
        applySelectedInstanceCapabilities();
      } catch (error) {
        document.getElementById("instance-list").textContent = "The instances response is not valid JSON. The check fails closed.";
      }
    })
    .catch(function () {
      document.getElementById("instance-list").textContent = "The host did not return the instance list. The check fails closed.";
    });
}

function fillAgentTypeSelect(agentTypes) {
  var select = document.getElementById("agent-type-id");
  var previous = select.value;
  select.innerHTML = "";
  var placeholder = document.createElement("option");
  placeholder.value = "";
  placeholder.textContent = "No agent type is selected";
  select.appendChild(placeholder);
  for (var index = 0; index < agentTypes.length; index += 1) {
    var listing = agentTypes[index];
    var option = document.createElement("option");
    option.value = listing.agent_type_id;
    var intents = listing.allowed_intents || [];
    option.textContent = listing.agent_type_id;
    option.setAttribute("data-allowed-intents", intents.join(" "));
    select.appendChild(option);
  }
  if (previous) {
    select.value = previous;
  } else if (agentTypes.length === 1) {
    select.value = agentTypes[0].agent_type_id;
  }
  if (agentTypes.length === 0) {
    placeholder.textContent = "No agent type is on this store";
  }
  applySelectedAgentTypeIntents();
}

function applySelectedAgentTypeIntents() {
  var select = document.getElementById("agent-type-id");
  var option = select.options[select.selectedIndex];
  if (!option || !option.value) {
    return;
  }
  var intents = (option.getAttribute("data-allowed-intents") || "").split(" ").filter(function (value) {
    return value.length > 0;
  });
  var intentField = document.getElementById("birth-intent");
  if (intents.length > 0 && intents.indexOf(intentField.value) === -1) {
    intentField.value = intents[0];
  }
}

function loadAgentTypes(selectAgentTypeId) {
  fetch("/agent-types")
    .then(function (response) { return response.text(); })
    .then(function (text) {
      try {
        var data = JSON.parse(text);
        var agentTypes = data.agent_types || [];
        fillAgentTypeSelect(agentTypes);
        if (selectAgentTypeId) {
          document.getElementById("agent-type-id").value = selectAgentTypeId;
          applySelectedAgentTypeIntents();
        }
      } catch (error) {
        document.getElementById("birth-result").textContent = "The agent-types response is not valid JSON. The check fails closed.";
        document.getElementById("birth-result").className = "result-refused";
      }
    })
    .catch(function () {
      document.getElementById("birth-result").textContent = "The host did not return agent types. The check fails closed.";
      document.getElementById("birth-result").className = "result-refused";
    });
}

function addMemberSecretPath(body, fieldId) {
  var field = document.getElementById(fieldId);
  if (!field) {
    return;
  }
  var memberPath = (field.value || "").trim();
  if (memberPath) {
    body.member_secret_path = memberPath;
  }
}

function addAgentType() {
  var intentsText = document.getElementById("new-allowed-intents").value || "";
  var allowedIntents = intentsText.split(/[\s,]+/).filter(function (value) {
    return value.length > 0;
  });
  var body = {
    allowed_intents: allowedIntents,
    authorization_limit: document.getElementById("new-authorization-limit").value || null,
    owner: document.getElementById("new-agent-type-owner").value || null
  };
  addMemberSecretPath(body, "agent-type-member-secret-path");
  fetch("/agent-type", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  })
    .then(function (response) {
      return response.text().then(function (text) {
        return { ok: response.ok, text: text };
      });
    })
    .then(function (payload) {
      try {
        var data = JSON.parse(payload.text);
        if (data.agent_type_id && data.allowed_intents) {
          document.getElementById("agent-type-result").textContent = "The host wrote the agent type. The agent type list is refreshed. Birth can use this class.";
          document.getElementById("agent-type-result").className = "result-allowed";
          loadAgentTypes(data.agent_type_id);
          return;
        }
        document.getElementById("agent-type-result").textContent = data.reason || "The host refused the agent type write. The check fails closed.";
        document.getElementById("agent-type-result").className = "result-refused";
      } catch (error) {
        document.getElementById("agent-type-result").textContent = "The agent-type response is not valid JSON. The check fails closed.";
        document.getElementById("agent-type-result").className = "result-refused";
      }
    })
    .catch(function () {
      document.getElementById("agent-type-result").textContent = "The host did not write an agent type. The check fails closed.";
      document.getElementById("agent-type-result").className = "result-refused";
    });
}

function birthInstance() {
  var agentTypeId = document.getElementById("agent-type-id").value;
  if (!agentTypeId) {
    document.getElementById("birth-result").textContent = "Pick an agent type before you birth an instance.";
    document.getElementById("birth-result").className = "result-refused";
    return;
  }
  var body = {
    agent_type_id: agentTypeId,
    owner: document.getElementById("birth-owner").value || null,
    intent: document.getElementById("birth-intent").value || null,
    audience: document.getElementById("birth-audience").value || null,
    on_behalf_of: document.getElementById("birth-on-behalf-of").value || null
  };
  var memberPath = document.getElementById("birth-member-secret-path").value.trim();
  if (memberPath) {
    body.member_secret_path = memberPath;
  }
  fetch("/birth", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  })
    .then(function (response) {
      return response.text().then(function (text) {
        return { ok: response.ok, text: text };
      });
    })
    .then(function (payload) {
      try {
        var data = JSON.parse(payload.text);
        if (data.instance_id && data.capability_id && data.holder_secret_path) {
          document.getElementById("capability-id").value = data.capability_id;
          document.getElementById("holder-secret-path").value = data.holder_secret_path;
          document.getElementById("spawn-parent-capability-id").value = data.capability_id;
          document.getElementById("spawn-holder-secret-path").value = data.holder_secret_path;
          document.getElementById("birth-result").textContent = "The host wrote a live instance. The instance list is refreshed. Challenge and present can run on this page.";
          document.getElementById("birth-result").className = "result-allowed";
          loadInstances(data.instance_id);
          return;
        }
        document.getElementById("birth-result").textContent = data.reason || "The host refused birth. The check fails closed.";
        document.getElementById("birth-result").className = "result-refused";
      } catch (error) {
        document.getElementById("birth-result").textContent = "The birth response is not valid JSON. The check fails closed.";
        document.getElementById("birth-result").className = "result-refused";
      }
    })
    .catch(function () {
      document.getElementById("birth-result").textContent = "The host did not birth an instance. The check fails closed.";
      document.getElementById("birth-result").className = "result-refused";
    });
}

function selectedKillInstanceId() {
  return document.getElementById("kill-instance-id").value;
}

function killInstance() {
  var instanceId = selectedKillInstanceId();
  if (!instanceId) {
    document.getElementById("kill-result").textContent = "Pick a live instance before you kill.";
    document.getElementById("kill-result").className = "result-refused";
    return;
  }
  var confirmValue = document.getElementById("kill-confirm").value;
  if (confirmValue !== instanceId) {
    document.getElementById("kill-result").textContent = "Type the same instance identifier to confirm. A wrong click does not kill. The check fails closed.";
    document.getElementById("kill-result").className = "result-refused";
    return;
  }
  var killBody = { instance_id: instanceId, confirm: confirmValue };
  addMemberSecretPath(killBody, "kill-member-secret-path");
  fetch("/kill", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(killBody)
  })
    .then(function (response) {
      return response.text().then(function (text) {
        return { ok: response.ok, text: text };
      });
    })
    .then(function (payload) {
      try {
        var data = JSON.parse(payload.text);
        if (data.instance_id && data.status === "revoked") {
          document.getElementById("kill-result").textContent = "The host revoked the instance. The instance list is refreshed. A following check of a historical wrap is refused. Export the kill bundle below.";
          document.getElementById("kill-result").className = "result-allowed";
          document.getElementById("kill-confirm").value = "";
          document.getElementById("kill-export-confirm").value = data.instance_id;
          loadInstances(null, data.instance_id);
          loadStatus();
          return;
        }
        document.getElementById("kill-result").textContent = data.reason || "The host refused local kill. The check fails closed.";
        document.getElementById("kill-result").className = "result-refused";
      } catch (error) {
        document.getElementById("kill-result").textContent = "The kill response is not valid JSON. The check fails closed.";
        document.getElementById("kill-result").className = "result-refused";
      }
    })
    .catch(function () {
      document.getElementById("kill-result").textContent = "The host did not kill an instance. The check fails closed.";
      document.getElementById("kill-result").className = "result-refused";
    });
}

function selectedKillExportInstanceId() {
  return document.getElementById("kill-export-instance-id").value;
}

function showKillExportArtifacts(data) {
  document.getElementById("kill-export-event").textContent = JSON.stringify(data.event, null, 2);
  document.getElementById("kill-export-proof").textContent = JSON.stringify(data.proof, null, 2);
  document.getElementById("kill-export-tree-head").textContent = JSON.stringify(data.tree_head, null, 2);
  window.__killExportBundle = data;
}

function exportKillBundle() {
  var instanceId = selectedKillExportInstanceId();
  if (!instanceId) {
    document.getElementById("kill-export-result").textContent = "Pick a revoked instance before you export the kill bundle.";
    document.getElementById("kill-export-result").className = "result-refused";
    return;
  }
  var confirmValue = document.getElementById("kill-export-confirm").value;
  if (confirmValue !== instanceId) {
    document.getElementById("kill-export-result").textContent = "Type the same instance identifier to confirm. The check fails closed.";
    document.getElementById("kill-export-result").className = "result-refused";
    return;
  }
  var killExportBody = { instance_id: instanceId, confirm: confirmValue };
  addMemberSecretPath(killExportBody, "kill-export-member-secret-path");
  fetch("/kill-export", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(killExportBody)
  })
    .then(function (response) {
      return response.text().then(function (text) {
        return { ok: response.ok, text: text };
      });
    })
    .then(function (payload) {
      try {
        var data = JSON.parse(payload.text);
        if (data.event && data.proof && data.tree_head) {
          document.getElementById("kill-export-result").textContent = "The host returned the public kill artifacts. Event, proof, and tree head are shown. Secret bytes are not returned.";
          document.getElementById("kill-export-result").className = "result-allowed";
          showKillExportArtifacts(data);
          return;
        }
        document.getElementById("kill-export-result").textContent = data.reason || "The host refused kill export. The check fails closed.";
        document.getElementById("kill-export-result").className = "result-refused";
      } catch (error) {
        document.getElementById("kill-export-result").textContent = "The kill-export response is not valid JSON. The check fails closed.";
        document.getElementById("kill-export-result").className = "result-refused";
      }
    })
    .catch(function () {
      document.getElementById("kill-export-result").textContent = "The host did not export a kill bundle. The check fails closed.";
      document.getElementById("kill-export-result").className = "result-refused";
    });
}

function showSealExportArtifacts(data) {
  document.getElementById("seal-export-event").textContent = JSON.stringify(data.event, null, 2);
  document.getElementById("seal-export-proof").textContent = JSON.stringify(data.proof, null, 2);
  document.getElementById("seal-export-tree-head").textContent = JSON.stringify(data.tree_head, null, 2);
  window.__sealExportBundle = data;
}

function exportSealBundle() {
  var body = {};
  addMemberSecretPath(body, "seal-export-member-secret-path");
  fetch("/seal-export", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  })
    .then(function (response) {
      return response.text().then(function (text) {
        return { ok: response.ok, text: text };
      });
    })
    .then(function (payload) {
      try {
        var data = JSON.parse(payload.text);
        if (data.event && data.proof && data.tree_head) {
          document.getElementById("seal-export-result").textContent = "The host returned the public seal artifacts. Event, proof, and tree head are shown. Secret bytes are not returned.";
          document.getElementById("seal-export-result").className = "result-allowed";
          showSealExportArtifacts(data);
          return;
        }
        document.getElementById("seal-export-result").textContent = data.reason || "The host refused seal export. The check fails closed.";
        document.getElementById("seal-export-result").className = "result-refused";
      } catch (error) {
        document.getElementById("seal-export-result").textContent = "The seal-export response is not valid JSON. The check fails closed.";
        document.getElementById("seal-export-result").className = "result-refused";
      }
    })
    .catch(function () {
      document.getElementById("seal-export-result").textContent = "The host did not export a seal bundle. The check fails closed.";
      document.getElementById("seal-export-result").className = "result-refused";
    });
}

function loadSealAcceptBundle() {
  var raw = document.getElementById("seal-accept-export-json").value;
  try {
    var data = parseJsonObject(raw, "seal-export JSON");
    if (!data.event || !data.proof || !data.tree_head) {
      document.getElementById("seal-accept-result").textContent = "The seal-export JSON must include event, proof, and tree_head. The check fails closed.";
      document.getElementById("seal-accept-result").className = "result-refused";
      return;
    }
    document.getElementById("seal-accept-event").value = JSON.stringify(data.event, null, 2);
    document.getElementById("seal-accept-proof").value = JSON.stringify(data.proof, null, 2);
    document.getElementById("seal-accept-tree-head").value = JSON.stringify(data.tree_head, null, 2);
    document.getElementById("seal-accept-result").textContent = "The three public artifacts are loaded. Secret bytes are not present.";
    document.getElementById("seal-accept-result").className = "result-allowed";
  } catch (error) {
    document.getElementById("seal-accept-result").textContent = error.message || "The seal-export JSON did not load. The check fails closed.";
    document.getElementById("seal-accept-result").className = "result-refused";
  }
}

function showSealAcceptNoInstanceRecord(acceptedText) {
  fetch("/instances")
    .then(function (response) { return response.text(); })
    .then(function (text) {
      try {
        var data = JSON.parse(text);
        var listings = data.instances || [];
        document.getElementById("seal-accept-instances").textContent = "This store wrote no instance record.\\n" + JSON.stringify(listings, null, 2);
      } catch (error) {
        document.getElementById("seal-accept-instances").textContent = "This store wrote no instance record. The instance list did not parse.";
      }
      document.getElementById("seal-accept-accepted").textContent = acceptedText;
      loadStatus();
    })
    .catch(function () {
      document.getElementById("seal-accept-instances").textContent = "This store wrote no instance record. The host did not return the instance list.";
      document.getElementById("seal-accept-accepted").textContent = acceptedText;
    });
}

function rotateIssuer() {
  var confirmValue = document.getElementById("rotate-confirm").value;
  if (confirmValue !== "rotate") {
    document.getElementById("rotate-result").textContent = "Type the exact word rotate to confirm. A wrong click does not rotate. The check fails closed.";
    document.getElementById("rotate-result").className = "result-refused";
    return;
  }
  var body = { confirm: confirmValue };
  var afterSeconds = parseInt(document.getElementById("rotate-kill-after-seconds").value, 10);
  if (afterSeconds) {
    body.kill_after_seconds = afterSeconds;
  }
  var memberPath = document.getElementById("rotate-member-secret-path").value;
  if (memberPath) {
    body.member_secret_path = memberPath;
  }
  fetch("/rotate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  })
    .then(function (response) {
      return response.text().then(function (text) {
        return { ok: response.ok, text: text };
      });
    })
    .then(function (payload) {
      try {
        var data = JSON.parse(payload.text);
        if (payload.ok && data.current_issuer_public_key_hex && data.previous_public_key_hex && data.previous_kill_date) {
          document.getElementById("rotate-result").textContent = "The host rotated the issuer. The previous public key keeps a kill date. GET /issuer-public now returns the new current key. Previous-key-export is usable. Secret bytes are not returned.";
          document.getElementById("rotate-result").className = "result-allowed";
          document.getElementById("rotate-confirm").value = "";
          document.getElementById("rotate-body").textContent = JSON.stringify(data, null, 2);
          loadIssuerPublic();
          loadStatus();
          return;
        }
        document.getElementById("rotate-result").textContent = data.reason || "The host refused issuer rotate. The check fails closed.";
        document.getElementById("rotate-result").className = "result-refused";
      } catch (error) {
        document.getElementById("rotate-result").textContent = "The rotate response is not valid JSON. The check fails closed.";
        document.getElementById("rotate-result").className = "result-refused";
      }
    })
    .catch(function () {
      document.getElementById("rotate-result").textContent = "The host did not rotate the issuer. The check fails closed.";
      document.getElementById("rotate-result").className = "result-refused";
    });
}

function exportPreviousKey() {
  fetch("/previous-key-export", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({})
  })
    .then(function (response) {
      return response.text().then(function (text) {
        return { ok: response.ok, text: text };
      });
    })
    .then(function (payload) {
      try {
        var data = JSON.parse(payload.text);
        if (data.public_key_hex && data.kill_date) {
          document.getElementById("previous-key-export-result").textContent = "The host returned the public previous-key artifacts. Secret bytes are not returned.";
          document.getElementById("previous-key-export-result").className = "result-allowed";
          document.getElementById("previous-key-export-body").textContent = JSON.stringify(data, null, 2);
          return;
        }
        document.getElementById("previous-key-export-result").textContent = data.reason || "The host refused previous-key export. The check fails closed.";
        document.getElementById("previous-key-export-result").className = "result-refused";
      } catch (error) {
        document.getElementById("previous-key-export-result").textContent = "The previous-key-export response is not valid JSON. The check fails closed.";
        document.getElementById("previous-key-export-result").className = "result-refused";
      }
    })
    .catch(function () {
      document.getElementById("previous-key-export-result").textContent = "The host did not export a previous issuer key. The check fails closed.";
      document.getElementById("previous-key-export-result").className = "result-refused";
    });
}

function loadPreviousKeyAccept() {
  var raw = document.getElementById("previous-key-accept-export-json").value;
  try {
    var data = parseJsonObject(raw, "previous-key-export JSON");
    if (!data.public_key_hex || !data.kill_date) {
      document.getElementById("previous-key-accept-result").textContent = "The previous-key-export JSON must include public_key_hex and kill_date. The check fails closed.";
      document.getElementById("previous-key-accept-result").className = "result-refused";
      return;
    }
    document.getElementById("previous-key-accept-public-key").value = data.public_key_hex;
    document.getElementById("previous-key-accept-kill-date").value = data.kill_date;
    document.getElementById("previous-key-accept-result").textContent = "The public artifacts are loaded. Secret bytes are not present.";
    document.getElementById("previous-key-accept-result").className = "result-allowed";
  } catch (error) {
    document.getElementById("previous-key-accept-result").textContent = error.message || "The previous-key-export JSON did not load. The check fails closed.";
    document.getElementById("previous-key-accept-result").className = "result-refused";
  }
}

function showPreviousKeyAcceptNoInstanceRecord() {
  fetch("/instances")
    .then(function (response) { return response.text(); })
    .then(function (text) {
      try {
        var data = JSON.parse(text);
        var listings = data.instances || [];
        document.getElementById("previous-key-accept-instances").textContent = "This store wrote no instance record.\n" + JSON.stringify(listings, null, 2);
      } catch (error) {
        document.getElementById("previous-key-accept-instances").textContent = "This store wrote no instance record. The instance list did not parse.";
      }
      loadStatus();
    })
    .catch(function () {
      document.getElementById("previous-key-accept-instances").textContent = "This store wrote no instance record. The host did not return the instance list.";
    });
}

function acceptPreviousKey() {
  followWellKnownThenPin("previous-key-accept", {
    public_key_hex: document.getElementById("previous-key-accept-public-key").value,
    kill_date: document.getElementById("previous-key-accept-kill-date").value
  }, "previous-key-accept-result", function (payload) {
    var data = readJsonPayload(payload, "The previous-key-accept response is not valid JSON. The check fails closed.");
    if (payload.ok && data.public_key_hex && data.kill_date) {
      document.getElementById("previous-key-accept-result").textContent = "This store accepted the previous issuer key and its kill date. After the kill date a present signed only by that key is refused. This store wrote no instance record.";
      document.getElementById("previous-key-accept-result").className = "result-allowed";
      showPreviousKeyAcceptNoInstanceRecord();
      return;
    }
    document.getElementById("previous-key-accept-result").textContent = data.reason || "The host refused previous-key accept. The check fails closed.";
    document.getElementById("previous-key-accept-result").className = "result-refused";
  });
}

function acceptSealBundle() {
  var eventText = document.getElementById("seal-accept-event").value;
  var proofText = document.getElementById("seal-accept-proof").value;
  var treeHeadText = document.getElementById("seal-accept-tree-head").value;
  var body;
  try {
    body = {
      event: parseJsonObject(eventText, "event"),
      proof: parseJsonObject(proofText, "proof"),
      tree_head: parseJsonObject(treeHeadText, "tree_head")
    };
  } catch (error) {
    document.getElementById("seal-accept-result").textContent = error.message || "The seal artifacts did not parse. The check fails closed.";
    document.getElementById("seal-accept-result").className = "result-refused";
    return;
  }
  followWellKnownThenPin("seal-accept", body, "seal-accept-result", function (payload) {
    var data = readJsonPayload(payload, "The seal-accept response is not valid JSON. The check fails closed.");
    if (payload.ok && data.public_key_hex) {
      document.getElementById("seal-accept-result").textContent = "This store accepted the seal. Present and act for that issuer pin refuse. This store wrote no instance record.";
      document.getElementById("seal-accept-result").className = "result-allowed";
      showSealAcceptNoInstanceRecord(JSON.stringify(data, null, 2));
      return;
    }
    document.getElementById("seal-accept-result").textContent = data.reason || "The host refused seal accept. The check fails closed.";
    document.getElementById("seal-accept-result").className = "result-refused";
  });
}

function parseJsonObject(text, label) {
  try {
    var value = JSON.parse(text);
    if (!value || typeof value !== "object") {
      throw new Error("not an object");
    }
    return value;
  } catch (error) {
    throw new Error("The " + label + " text is not valid JSON. The check fails closed.");
  }
}

function acceptIssuerKey() {
  var publicKeyHex = document.getElementById("issuer-public-key-hex").value;
  if (!publicKeyHex) {
    document.getElementById("issuer-accept-result").textContent = "Paste a foreign issuer public key hexadecimal before you accept.";
    document.getElementById("issuer-accept-result").className = "result-refused";
    return;
  }
  followWellKnownThenPin("issuer-accept", { public_key_hex: publicKeyHex }, "issuer-accept-result", function (payload) {
    var data = readJsonPayload(payload, "The issuer-accept response is not valid JSON. The check fails closed.");
    if (data.public_key_hex) {
      document.getElementById("issuer-accept-result").textContent = "This store pinned the foreign issuer public key. Secret bytes were not copied.";
      document.getElementById("issuer-accept-result").className = "result-allowed";
      return;
    }
    document.getElementById("issuer-accept-result").textContent = data.reason || "The host refused issuer accept. The check fails closed.";
    document.getElementById("issuer-accept-result").className = "result-refused";
  });
}

function loadKillAcceptBundle() {
  var raw = document.getElementById("kill-accept-export-json").value;
  try {
    var data = parseJsonObject(raw, "kill-export JSON");
    if (!data.event || !data.proof || !data.tree_head) {
      document.getElementById("kill-accept-result").textContent = "The kill-export JSON must include event, proof, and tree_head. The check fails closed.";
      document.getElementById("kill-accept-result").className = "result-refused";
      return;
    }
    document.getElementById("kill-accept-event").value = JSON.stringify(data.event, null, 2);
    document.getElementById("kill-accept-proof").value = JSON.stringify(data.proof, null, 2);
    document.getElementById("kill-accept-tree-head").value = JSON.stringify(data.tree_head, null, 2);
    document.getElementById("kill-accept-result").textContent = "The three public artifacts are loaded. Secret bytes are not present.";
    document.getElementById("kill-accept-result").className = "result-allowed";
  } catch (error) {
    document.getElementById("kill-accept-result").textContent = error.message || "The kill-export JSON did not load. The check fails closed.";
    document.getElementById("kill-accept-result").className = "result-refused";
  }
}

function showKillAcceptNoInstanceRecord(acceptedText) {
  fetch("/instances")
    .then(function (response) { return response.text(); })
    .then(function (text) {
      try {
        var data = JSON.parse(text);
        var listings = data.instances || [];
        document.getElementById("kill-accept-instances").textContent = "This store wrote no instance record.\n" + JSON.stringify(listings, null, 2);
      } catch (error) {
        document.getElementById("kill-accept-instances").textContent = "This store wrote no instance record. The instance list did not parse.";
      }
      document.getElementById("kill-accept-accepted").textContent = acceptedText;
      loadStatus();
    })
    .catch(function () {
      document.getElementById("kill-accept-instances").textContent = "This store wrote no instance record. The host did not return the instance list.";
      document.getElementById("kill-accept-accepted").textContent = acceptedText;
    });
}

function acceptKillBundle() {
  var eventText = document.getElementById("kill-accept-event").value;
  var proofText = document.getElementById("kill-accept-proof").value;
  var treeHeadText = document.getElementById("kill-accept-tree-head").value;
  var body;
  try {
    body = {
      event: parseJsonObject(eventText, "event"),
      proof: parseJsonObject(proofText, "proof"),
      tree_head: parseJsonObject(treeHeadText, "tree_head")
    };
  } catch (error) {
    document.getElementById("kill-accept-result").textContent = error.message || "The three artifacts did not parse. The check fails closed.";
    document.getElementById("kill-accept-result").className = "result-refused";
    return;
  }
  followWellKnownThenPin("kill-accept", body, "kill-accept-result", function (payload) {
    var data = readJsonPayload(payload, "The kill-accept response is not valid JSON. The check fails closed.");
    if (payload.ok && (data.accepted_killed_instance_ids || data.accepted_killed_capability_ids || data.accepted_revoke_identifiers)) {
      document.getElementById("kill-accept-result").textContent = "This store accepted the signed death bundle. This store wrote no instance record.";
      document.getElementById("kill-accept-result").className = "result-allowed";
      showKillAcceptNoInstanceRecord(JSON.stringify({
        accepted_killed_instance_ids: data.accepted_killed_instance_ids || [],
        accepted_killed_capability_ids: data.accepted_killed_capability_ids || [],
        accepted_revoke_identifiers: data.accepted_revoke_identifiers || []
      }, null, 2));
      return;
    }
    document.getElementById("kill-accept-result").textContent = data.reason || "The host refused kill accept. The check fails closed.";
    document.getElementById("kill-accept-result").className = "result-refused";
  });
}

function showActExportArtifacts(data) {
  document.getElementById("act-export-receipt-out").textContent = JSON.stringify(data.receipt, null, 2);
  document.getElementById("act-export-proof").textContent = JSON.stringify(data.proof, null, 2);
  document.getElementById("act-export-tree-head").textContent = JSON.stringify(data.tree_head, null, 2);
  window.__actExportBundle = data;
}

function exportActBundle() {
  var raw = document.getElementById("act-export-receipt").value;
  var receipt;
  try {
    receipt = parseJsonObject(raw, "check receipt");
  } catch (error) {
    document.getElementById("act-export-result").textContent = error.message || "The check receipt did not parse. The check fails closed.";
    document.getElementById("act-export-result").className = "result-refused";
    return;
  }
  var actExportBody = { receipt: receipt };
  addMemberSecretPath(actExportBody, "act-export-member-secret-path");
  fetch("/act-export", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(actExportBody)
  })
    .then(function (response) {
      return response.text().then(function (text) {
        return { ok: response.ok, text: text };
      });
    })
    .then(function (payload) {
      try {
        var data = JSON.parse(payload.text);
        if (data.receipt && data.proof && data.tree_head) {
          document.getElementById("act-export-result").textContent = "The host returned the public act artifacts. Receipt, proof, and tree head are shown. Secret bytes are not returned.";
          document.getElementById("act-export-result").className = "result-allowed";
          showActExportArtifacts(data);
          return;
        }
        document.getElementById("act-export-result").textContent = data.reason || "The host refused act export. The check fails closed.";
        document.getElementById("act-export-result").className = "result-refused";
      } catch (error) {
        document.getElementById("act-export-result").textContent = "The act-export response is not valid JSON. The check fails closed.";
        document.getElementById("act-export-result").className = "result-refused";
      }
    })
    .catch(function () {
      document.getElementById("act-export-result").textContent = "The host did not export an act bundle. The check fails closed.";
      document.getElementById("act-export-result").className = "result-refused";
    });
}

function loadActAcceptBundle() {
  var raw = document.getElementById("act-accept-export-json").value;
  try {
    var data = parseJsonObject(raw, "act-export JSON");
    if (!data.receipt || !data.proof || !data.tree_head) {
      document.getElementById("act-accept-result").textContent = "The act-export JSON must include receipt, proof, and tree_head. The check fails closed.";
      document.getElementById("act-accept-result").className = "result-refused";
      return;
    }
    document.getElementById("act-accept-receipt").value = JSON.stringify(data.receipt, null, 2);
    document.getElementById("act-accept-proof").value = JSON.stringify(data.proof, null, 2);
    document.getElementById("act-accept-tree-head").value = JSON.stringify(data.tree_head, null, 2);
    document.getElementById("act-accept-result").textContent = "The three public artifacts are loaded. Secret bytes are not present.";
    document.getElementById("act-accept-result").className = "result-allowed";
  } catch (error) {
    document.getElementById("act-accept-result").textContent = error.message || "The act-export JSON did not load. The check fails closed.";
    document.getElementById("act-accept-result").className = "result-refused";
  }
}

function showActAcceptNoInstanceRecord() {
  fetch("/instances")
    .then(function (response) { return response.text(); })
    .then(function (text) {
      try {
        var data = JSON.parse(text);
        var listings = data.instances || [];
        document.getElementById("act-accept-instances").textContent = "This store wrote no instance record.\n" + JSON.stringify(listings, null, 2);
      } catch (error) {
        document.getElementById("act-accept-instances").textContent = "This store wrote no instance record. The instance list did not parse.";
      }
      loadStatus();
    })
    .catch(function () {
      document.getElementById("act-accept-instances").textContent = "This store wrote no instance record. The host did not return the instance list.";
    });
}

function acceptActBundle() {
  var receiptText = document.getElementById("act-accept-receipt").value;
  var proofText = document.getElementById("act-accept-proof").value;
  var treeHeadText = document.getElementById("act-accept-tree-head").value;
  var body;
  try {
    body = {
      receipt: parseJsonObject(receiptText, "receipt"),
      proof: parseJsonObject(proofText, "proof"),
      tree_head: parseJsonObject(treeHeadText, "tree_head")
    };
  } catch (error) {
    document.getElementById("act-accept-result").textContent = error.message || "The three artifacts did not parse. The check fails closed.";
    document.getElementById("act-accept-result").className = "result-refused";
    return;
  }
  followWellKnownThenPin("act-accept", body, "act-accept-result", function (payload) {
    var data = readJsonPayload(payload, "The act-accept response is not valid JSON. The check fails closed.");
    if (payload.ok && data.result === "accepted") {
      document.getElementById("act-accept-result").textContent = "This store accepted the signed act bundle. This store wrote no instance record.";
      document.getElementById("act-accept-result").className = "result-allowed";
      showActAcceptNoInstanceRecord();
      return;
    }
    document.getElementById("act-accept-result").textContent = data.reason || "The host refused act accept. The check fails closed.";
    document.getElementById("act-accept-result").className = "result-refused";
  });
}

function downloadKillArtifact(field, fileName) {
  var bundle = window.__killExportBundle;
  if (!bundle || !bundle[field]) {
    document.getElementById("kill-export-result").textContent = "Export the kill bundle before you download an artifact.";
    document.getElementById("kill-export-result").className = "result-refused";
    return;
  }
  var text = JSON.stringify(bundle[field], null, 2) + "\n";
  var blob = new Blob([text], { type: "application/json" });
  var url = URL.createObjectURL(blob);
  var link = document.createElement("a");
  link.href = url;
  link.download = fileName;
  link.click();
  URL.revokeObjectURL(url);
}

function requestChallenge() {
  var instanceId = selectedInstanceId();
  if (!instanceId) {
    document.getElementById("wrap-result").textContent = "Pick a live instance before you request a challenge.";
    document.getElementById("wrap-result").className = "result-refused";
    return Promise.reject(new Error("no live instance"));
  }
  var challengeBody = { instance_id: instanceId };
  addMemberSecretPath(challengeBody, "present-member-secret-path");
  return fetch("/challenge", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(challengeBody)
  })
    .then(function (response) {
      return response.text().then(function (text) {
        return { ok: response.ok, text: text };
      });
    })
    .then(function (payload) {
      try {
        var data = JSON.parse(payload.text);
        if (data.challenge_nonce) {
          document.getElementById("challenge-nonce").value = data.challenge_nonce;
          document.getElementById("wrap-result").textContent = "The host returned a challenge nonce.";
          document.getElementById("wrap-result").className = "result-allowed";
          return data.challenge_nonce;
        }
        document.getElementById("wrap-result").textContent = data.reason || "The host refused the challenge. The check fails closed.";
        document.getElementById("wrap-result").className = "result-refused";
        return Promise.reject(new Error("challenge refused"));
      } catch (error) {
        document.getElementById("wrap-result").textContent = "The challenge response is not valid JSON. The check fails closed.";
        document.getElementById("wrap-result").className = "result-refused";
        return Promise.reject(error);
      }
    });
}

function requestVerifierChallenge() {
  followWellKnownThenPin("verifier-challenge", {}, "verifier-challenge-result", function (payload) {
    var data = readJsonPayload(payload, "The verifier challenge response is not valid JSON. The check fails closed.");
    if (data.challenge_nonce) {
      document.getElementById("challenge-nonce").value = data.challenge_nonce;
      document.getElementById("challenge-message").value = data.challenge_message || "";
      document.getElementById("verifier-challenge-result").textContent = "The host returned a verifier challenge nonce. This store wrote no instance.";
      document.getElementById("verifier-challenge-result").className = "result-allowed";
      return;
    }
    document.getElementById("verifier-challenge-result").textContent = data.reason || "The host refused the verifier challenge. The check fails closed.";
    document.getElementById("verifier-challenge-result").className = "result-refused";
  });
}

function signVerifierNonce() {
  var body = {
    challenge_nonce: document.getElementById("challenge-nonce").value || null,
    challenge_message: document.getElementById("challenge-message").value || null,
    holder_secret_path: document.getElementById("holder-secret-path").value
  };
  fetch("/sign-holder-nonce", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  })
    .then(function (response) {
      return response.text().then(function (text) {
        return { ok: response.ok, text: text };
      });
    })
    .then(function (payload) {
      try {
        var data = JSON.parse(payload.text);
        if (data.holder_proof) {
          document.getElementById("holder-proof").value = data.holder_proof;
          document.getElementById("verifier-challenge-result").textContent = "The host signed the verifier nonce. Secret bytes were not returned. Paste this signature onto the Store B check.";
          document.getElementById("verifier-challenge-result").className = "result-allowed";
          return;
        }
        document.getElementById("verifier-challenge-result").textContent = data.reason || "The host refused to sign the verifier nonce. The check fails closed.";
        document.getElementById("verifier-challenge-result").className = "result-refused";
      } catch (error) {
        document.getElementById("verifier-challenge-result").textContent = "The sign response is not valid JSON. The check fails closed.";
        document.getElementById("verifier-challenge-result").className = "result-refused";
      }
    })
    .catch(function () {
      document.getElementById("verifier-challenge-result").textContent = "The host did not answer. The check fails closed.";
      document.getElementById("verifier-challenge-result").className = "result-refused";
    });
}

function emitWimse() {
  var instanceId = selectedInstanceId();
  if (!instanceId) {
    document.getElementById("wimse-result").textContent = "Pick a live instance before you emit the Workload Identity Token.";
    document.getElementById("wimse-result").className = "result-refused";
    return;
  }
  var body = {
    instance_id: instanceId,
    capability_id: document.getElementById("capability-id").value || null,
    intent: document.getElementById("wrap-intent").value || null,
    audience: document.getElementById("wrap-audience").value || null,
    holder_proof: document.getElementById("holder-proof").value || null,
    holder_secret_path: document.getElementById("holder-secret-path").value || null,
    challenge_nonce: document.getElementById("challenge-nonce").value || null,
    on_behalf_of: document.getElementById("on-behalf-of").value || null
  };
  addMemberSecretPath(body, "present-member-secret-path");
  fetch("/present-wimse", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  })
    .then(function (response) {
      return response.text().then(function (text) {
        return { ok: response.ok, text: text };
      });
    })
    .then(function (payload) {
      try {
        var data = JSON.parse(payload.text);
        if (data.presentation_json && data.workload_identity_token && data.content_digest) {
          document.getElementById("wimse-presentation-json").value = data.presentation_json;
          document.getElementById("workload-identity-token").value = data.workload_identity_token;
          document.getElementById("content-digest").value = data.content_digest;
          document.getElementById("wimse-signature-input").value = data.signature_input || "";
          document.getElementById("wimse-signature").value = data.signature || "";
          try {
            var presentation = JSON.parse(data.presentation_json);
            if (presentation.intent) {
              document.getElementById("wrap-intent").value = presentation.intent;
            }
            if (presentation.audience) {
              document.getElementById("wrap-audience").value = presentation.audience;
            }
          } catch (parseError) {
            // The check form still holds the presentation JSON bytes.
          }
          document.getElementById("wimse-result").textContent = "The host emitted the Workload Identity Token. A new challenge is requested because present spent the first nonce.";
          document.getElementById("wimse-result").className = "result-allowed";
          requestChallenge();
          return;
        }
        document.getElementById("wimse-result").textContent = data.reason || "The host refused the Workload Identity Token. The check fails closed.";
        document.getElementById("wimse-result").className = "result-refused";
      } catch (error) {
        document.getElementById("wimse-result").textContent = "The present-wimse response is not valid JSON. The check fails closed.";
        document.getElementById("wimse-result").className = "result-refused";
      }
    })
    .catch(function () {
      document.getElementById("wimse-result").textContent = "The host did not emit a Workload Identity Token. The check fails closed.";
      document.getElementById("wimse-result").className = "result-refused";
    });
}

function emitWrap() {
  var instanceId = selectedInstanceId();
  if (!instanceId) {
    document.getElementById("wrap-result").textContent = "Pick a live instance before you emit the wrap.";
    document.getElementById("wrap-result").className = "result-refused";
    return;
  }
  var body = {
    instance_id: instanceId,
    capability_id: document.getElementById("capability-id").value || null,
    intent: document.getElementById("wrap-intent").value || null,
    audience: document.getElementById("wrap-audience").value || null,
    holder_proof: document.getElementById("holder-proof").value || null,
    holder_secret_path: document.getElementById("holder-secret-path").value || null,
    challenge_nonce: document.getElementById("challenge-nonce").value || null,
    on_behalf_of: document.getElementById("on-behalf-of").value || null
  };
  addMemberSecretPath(body, "present-member-secret-path");
  fetch("/present-svid", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  })
    .then(function (response) {
      return response.text().then(function (text) {
        return { ok: response.ok, text: text };
      });
    })
    .then(function (payload) {
      try {
        var data = JSON.parse(payload.text);
        if (data.presentation_json && data.certificate_pem) {
          document.getElementById("presentation-json").value = data.presentation_json;
          document.getElementById("certificate-pem").value = data.certificate_pem;
          try {
            var presentation = JSON.parse(data.presentation_json);
            if (presentation.intent) {
              document.getElementById("wrap-intent").value = presentation.intent;
            }
            if (presentation.audience) {
              document.getElementById("wrap-audience").value = presentation.audience;
            }
          } catch (parseError) {
            // The check form still holds the presentation JSON bytes.
          }
          document.getElementById("wrap-result").textContent = "The host emitted the wrap. A new challenge is requested because present spent the first nonce.";
          document.getElementById("wrap-result").className = "result-allowed";
          requestChallenge();
          return;
        }
        document.getElementById("wrap-result").textContent = data.reason || "The host refused the wrap. The check fails closed.";
        document.getElementById("wrap-result").className = "result-refused";
      } catch (error) {
        document.getElementById("wrap-result").textContent = "The present-svid response is not valid JSON. The check fails closed.";
        document.getElementById("wrap-result").className = "result-refused";
      }
    })
    .catch(function () {
      document.getElementById("wrap-result").textContent = "The host did not emit a wrap. The check fails closed.";
      document.getElementById("wrap-result").className = "result-refused";
    });
}

function selectedSpawnParentInstanceId() {
  return document.getElementById("spawn-parent-instance-id").value;
}

function requestSpawnChallenge() {
  var instanceId = selectedSpawnParentInstanceId();
  if (!instanceId) {
    document.getElementById("spawn-result").textContent = "Pick a live parent before you request a challenge.";
    document.getElementById("spawn-result").className = "result-refused";
    return Promise.reject(new Error("no live parent"));
  }
  var challengeBody = { instance_id: instanceId };
  addMemberSecretPath(challengeBody, "spawn-member-secret-path");
  return fetch("/challenge", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(challengeBody)
  })
    .then(function (response) {
      return response.text().then(function (text) {
        return { ok: response.ok, text: text };
      });
    })
    .then(function (payload) {
      try {
        var data = JSON.parse(payload.text);
        if (data.challenge_nonce) {
          document.getElementById("spawn-challenge-nonce").value = data.challenge_nonce;
          document.getElementById("spawn-result").textContent = "The host returned a parent challenge nonce.";
          document.getElementById("spawn-result").className = "result-allowed";
          return data.challenge_nonce;
        }
        document.getElementById("spawn-result").textContent = data.reason || "The host refused the parent challenge. The check fails closed.";
        document.getElementById("spawn-result").className = "result-refused";
        return Promise.reject(new Error("challenge refused"));
      } catch (error) {
        document.getElementById("spawn-result").textContent = "The spawn challenge response is not valid JSON. The check fails closed.";
        document.getElementById("spawn-result").className = "result-refused";
        return Promise.reject(error);
      }
    });
}

function spawnChild() {
  var parentInstanceId = selectedSpawnParentInstanceId();
  if (!parentInstanceId) {
    document.getElementById("spawn-result").textContent = "Pick a live parent before you spawn.";
    document.getElementById("spawn-result").className = "result-refused";
    return;
  }
  var body = {
    parent_instance_id: parentInstanceId,
    parent_capability_id: document.getElementById("spawn-parent-capability-id").value || null,
    owner: document.getElementById("spawn-owner").value || null,
    intent: document.getElementById("spawn-intent").value || null,
    audience: document.getElementById("spawn-audience").value || null,
    on_behalf_of: document.getElementById("spawn-on-behalf-of").value || null,
    holder_secret_path: document.getElementById("spawn-holder-secret-path").value || null,
    holder_proof: document.getElementById("spawn-holder-proof").value || null,
    challenge_nonce: document.getElementById("spawn-challenge-nonce").value || null
  };
  addMemberSecretPath(body, "spawn-member-secret-path");
  fetch("/spawn", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  })
    .then(function (response) {
      return response.text().then(function (text) {
        return { ok: response.ok, text: text };
      });
    })
    .then(function (payload) {
      try {
        var data = JSON.parse(payload.text);
        if (data.instance_id && data.capability_id && data.holder_secret_path) {
          document.getElementById("capability-id").value = data.capability_id;
          document.getElementById("holder-secret-path").value = data.holder_secret_path;
          document.getElementById("spawn-parent-capability-id").value = data.capability_id;
          document.getElementById("spawn-holder-secret-path").value = data.holder_secret_path;
          document.getElementById("spawn-challenge-nonce").value = "";
          document.getElementById("spawn-result").textContent = "The host wrote a narrower child. The instance list is refreshed. The child appears as a live instance.";
          document.getElementById("spawn-result").className = "result-allowed";
          loadInstances(data.instance_id);
          loadStatus();
          return;
        }
        document.getElementById("spawn-result").textContent = data.reason || "The host refused spawn. The check fails closed.";
        document.getElementById("spawn-result").className = "result-refused";
      } catch (error) {
        document.getElementById("spawn-result").textContent = "The spawn response is not valid JSON. The check fails closed.";
        document.getElementById("spawn-result").className = "result-refused";
      }
    })
    .catch(function () {
      document.getElementById("spawn-result").textContent = "The host did not spawn a child. The check fails closed.";
      document.getElementById("spawn-result").className = "result-refused";
    });
}

function sealIssuer() {
  var confirmValue = document.getElementById("seal-confirm").value;
  if (confirmValue !== "seal") {
    document.getElementById("seal-result").textContent = "Type the exact word seal to confirm. A wrong click does not seal. The check fails closed.";
    document.getElementById("seal-result").className = "result-refused";
    return;
  }
  var afterSeconds = parseInt(document.getElementById("seal-after-seconds").value, 10);
  if (!afterSeconds || afterSeconds < 1) {
    document.getElementById("seal-result").textContent = "after_seconds must be greater than zero. The check fails closed.";
    document.getElementById("seal-result").className = "result-refused";
    return;
  }
  var body = { confirm: confirmValue, after_seconds: afterSeconds };
  var memberPath = document.getElementById("seal-member-secret-path").value;
  if (memberPath) {
    body.member_secret_path = memberPath;
  }
  fetch("/seal", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  })
    .then(function (response) {
      return response.text().then(function (text) {
        return { ok: response.ok, text: text };
      });
    })
    .then(function (payload) {
      try {
        var data = JSON.parse(payload.text);
        if (payload.ok && data.status === "sealed") {
          document.getElementById("seal-result").textContent = "The issuer is sealed. Status is refreshed. Birth, present, and check refuse after remaining life. Kill after seal stays allowed.";
          document.getElementById("seal-result").className = "result-allowed";
          document.getElementById("seal-confirm").value = "";
          loadStatus();
          return;
        }
        document.getElementById("seal-result").textContent = data.reason || "The host refused issuer seal. The check fails closed.";
        document.getElementById("seal-result").className = "result-refused";
      } catch (error) {
        document.getElementById("seal-result").textContent = "The seal response is not valid JSON. The check fails closed.";
        document.getElementById("seal-result").className = "result-refused";
      }
    })
    .catch(function () {
      document.getElementById("seal-result").textContent = "The host did not seal the issuer. The check fails closed.";
      document.getElementById("seal-result").className = "result-refused";
    });
}


function exportIssuerBackup() {
  var path = document.getElementById("backup-path").value.trim();
  var confirmValue = document.getElementById("backup-confirm").value;
  if (confirmValue !== "backup") {
    document.getElementById("backup-result").textContent = "Type the exact word backup to confirm. A wrong click does not write a backup. The check fails closed.";
    document.getElementById("backup-result").className = "result-refused";
    return;
  }
  if (!path) {
    document.getElementById("backup-result").textContent = "Type a backup path outside the data directory. The check fails closed.";
    document.getElementById("backup-result").className = "result-refused";
    return;
  }
  fetch("/backup", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ path: path, confirm: confirmValue })
  })
    .then(function (response) {
      return response.text().then(function (text) {
        return { ok: response.ok, text: text };
      });
    })
    .then(function (payload) {
      try {
        var data = JSON.parse(payload.text);
        if (payload.ok && data.path) {
          document.getElementById("backup-result").textContent = "The host wrote the issuer backup. The response returns the path only. Secret bytes are not returned. Member two is not in the backup.";
          document.getElementById("backup-result").className = "result-allowed";
          document.getElementById("backup-body").textContent = JSON.stringify(data, null, 2);
          document.getElementById("backup-confirm").value = "";
          document.getElementById("restore-from").value = data.path;
          document.getElementById("diagnose-from").value = data.path;
          return;
        }
        document.getElementById("backup-result").textContent = data.reason || "The host refused backup. The check fails closed.";
        document.getElementById("backup-result").className = "result-refused";
        document.getElementById("backup-body").textContent = payload.text;
      } catch (error) {
        document.getElementById("backup-result").textContent = "The backup response is not valid JSON. The check fails closed.";
        document.getElementById("backup-result").className = "result-refused";
      }
    })
    .catch(function () {
      document.getElementById("backup-result").textContent = "The host did not write a backup. The check fails closed.";
      document.getElementById("backup-result").className = "result-refused";
    });
}

function restoreIssuerBackup() {
  var from = document.getElementById("restore-from").value.trim();
  var confirmValue = document.getElementById("restore-confirm").value;
  if (confirmValue !== "restore") {
    document.getElementById("restore-result").textContent = "Type the exact word restore to confirm. A wrong click does not restore. The check fails closed.";
    document.getElementById("restore-result").className = "result-refused";
    return;
  }
  if (!from) {
    document.getElementById("restore-result").textContent = "Type a restore from path. Restore onto a dest that already has an issuer is refused. The check fails closed.";
    document.getElementById("restore-result").className = "result-refused";
    return;
  }
  fetch("/restore", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ from: from, confirm: confirmValue })
  })
    .then(function (response) {
      return response.text().then(function (text) {
        return { ok: response.ok, text: text };
      });
    })
    .then(function (payload) {
      try {
        var data = JSON.parse(payload.text);
        document.getElementById("restore-body").textContent = JSON.stringify(data, null, 2);
        if (payload.ok && data.operation_normal) {
          document.getElementById("restore-result").textContent = "Restore succeeded. operation_normal is yes. Secret bytes are not returned. Standing data-a is not the restore dest.";
          document.getElementById("restore-result").className = "result-allowed";
          document.getElementById("restore-confirm").value = "";
          loadStatus();
          return;
        }
        document.getElementById("restore-result").textContent = data.reason || "The host refused restore. Restore onto a dest that already has an issuer is refused. The check fails closed.";
        document.getElementById("restore-result").className = "result-refused";
      } catch (error) {
        document.getElementById("restore-result").textContent = "The restore response is not valid JSON. The check fails closed.";
        document.getElementById("restore-result").className = "result-refused";
      }
    })
    .catch(function () {
      document.getElementById("restore-result").textContent = "The host did not restore. The check fails closed.";
      document.getElementById("restore-result").className = "result-refused";
    });
}

function diagnoseRestore() {
  var from = document.getElementById("diagnose-from").value.trim();
  if (!from) {
    document.getElementById("diagnose-result").textContent = "Type a diagnose from path. The check fails closed.";
    document.getElementById("diagnose-result").className = "result-refused";
    return;
  }
  fetch("/diagnose", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ from: from })
  })
    .then(function (response) {
      return response.text().then(function (text) {
        return { ok: response.ok, text: text };
      });
    })
    .then(function (payload) {
      try {
        var data = JSON.parse(payload.text);
        document.getElementById("diagnose-body").textContent = JSON.stringify(data, null, 2);
        if (payload.ok) {
          document.getElementById("diagnose-result").textContent = data.operation_normal ? "operation_normal is yes. Secret bytes are not returned." : "operation_normal is no. Secret bytes are not returned.";
          document.getElementById("diagnose-result").className = data.operation_normal ? "result-allowed" : "result-refused";
          return;
        }
        document.getElementById("diagnose-result").textContent = data.reason || "The host refused diagnose. The check fails closed.";
        document.getElementById("diagnose-result").className = "result-refused";
      } catch (error) {
        document.getElementById("diagnose-result").textContent = "The diagnose response is not valid JSON. The check fails closed.";
        document.getElementById("diagnose-result").className = "result-refused";
      }
    })
    .catch(function () {
      document.getElementById("diagnose-result").textContent = "The host did not diagnose. The check fails closed.";
      document.getElementById("diagnose-result").className = "result-refused";
    });
}

function registerMemberTwo() {
  var path = document.getElementById("member-two-secret-path").value;
  if (!path) {
    document.getElementById("member-two-result").textContent = "Type a local outside path. Secret bytes are not uploaded. The check fails closed.";
    document.getElementById("member-two-result").className = "result-refused";
    return;
  }
  var body = { member_secret_path: path };
  fetch("/member-two", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  })
    .then(function (response) {
      return response.text().then(function (text) {
        return { ok: response.ok, text: text };
      });
    })
    .then(function (payload) {
      try {
        var data = JSON.parse(payload.text);
        if (payload.ok && data.public_key_hex) {
          document.getElementById("member-two-result").textContent = "The host registered member two. The response returns the member public key hexadecimal only. Secret bytes are not returned.";
          document.getElementById("member-two-result").className = "result-allowed";
          document.getElementById("member-two-body").textContent = JSON.stringify(data, null, 2);
          loadStatus();
          return;
        }
        document.getElementById("member-two-result").textContent = data.reason || "The host refused member two. The check fails closed.";
        document.getElementById("member-two-result").className = "result-refused";
      } catch (error) {
        document.getElementById("member-two-result").textContent = "The member-two response is not valid JSON. The check fails closed.";
        document.getElementById("member-two-result").className = "result-refused";
      }
    })
    .catch(function () {
      document.getElementById("member-two-result").textContent = "The host did not register member two. The check fails closed.";
      document.getElementById("member-two-result").className = "result-refused";
    });
}

function setVerifyThreshold() {
  var confirmValue = document.getElementById("verify-threshold-confirm").value;
  if (confirmValue !== "verify-threshold") {
    document.getElementById("verify-threshold-result").textContent = "Type the exact word verify-threshold to confirm. A wrong click does not raise verify_threshold_n. The check fails closed.";
    document.getElementById("verify-threshold-result").className = "result-refused";
    return;
  }
  var n = parseInt(document.getElementById("verify-threshold-n").value, 10);
  var body = { confirm: confirmValue, n: n };
  addMemberSecretPath(body, "verify-threshold-member-secret-path");
  fetch("/set-verify-threshold", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  })
    .then(function (response) {
      return response.text().then(function (text) {
        return { ok: response.ok, text: text };
      });
    })
    .then(function (payload) {
      try {
        var data = JSON.parse(payload.text);
        if (payload.ok && data.verify_threshold_n) {
          document.getElementById("verify-threshold-result").textContent = "The host raised verify_threshold_n. Secret bytes are not returned.";
          document.getElementById("verify-threshold-result").className = "result-allowed";
          document.getElementById("verify-threshold-confirm").value = "";
          document.getElementById("verify-threshold-body").textContent = JSON.stringify(data, null, 2);
          loadStatus();
          return;
        }
        document.getElementById("verify-threshold-result").textContent = data.reason || "The host refused verify-threshold. The check fails closed.";
        document.getElementById("verify-threshold-result").className = "result-refused";
      } catch (error) {
        document.getElementById("verify-threshold-result").textContent = "The verify-threshold response is not valid JSON. The check fails closed.";
        document.getElementById("verify-threshold-result").className = "result-refused";
      }
    })
    .catch(function () {
      document.getElementById("verify-threshold-result").textContent = "The host did not set verify_threshold_n. The check fails closed.";
      document.getElementById("verify-threshold-result").className = "result-refused";
    });
}

function setIssuerThreshold() {
  var confirmValue = document.getElementById("issuer-threshold-confirm").value;
  if (confirmValue !== "issuer-threshold") {
    document.getElementById("issuer-threshold-result").textContent = "Type the exact word issuer-threshold to confirm. A wrong click does not raise threshold_n. The check fails closed.";
    document.getElementById("issuer-threshold-result").className = "result-refused";
    return;
  }
  var n = parseInt(document.getElementById("issuer-threshold-n").value, 10);
  var body = { confirm: confirmValue, n: n };
  fetch("/set-issuer-threshold", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  })
    .then(function (response) {
      return response.text().then(function (text) {
        return { ok: response.ok, text: text };
      });
    })
    .then(function (payload) {
      try {
        var data = JSON.parse(payload.text);
        if (payload.ok && data.threshold_n) {
          document.getElementById("issuer-threshold-result").textContent = "The host raised threshold_n. Secret bytes are not returned.";
          document.getElementById("issuer-threshold-result").className = "result-allowed";
          document.getElementById("issuer-threshold-confirm").value = "";
          document.getElementById("issuer-threshold-body").textContent = JSON.stringify(data, null, 2);
          loadStatus();
          return;
        }
        document.getElementById("issuer-threshold-result").textContent = data.reason || "The host refused issuer-threshold. The check fails closed.";
        document.getElementById("issuer-threshold-result").className = "result-refused";
      } catch (error) {
        document.getElementById("issuer-threshold-result").textContent = "The issuer-threshold response is not valid JSON. The check fails closed.";
        document.getElementById("issuer-threshold-result").className = "result-refused";
      }
    })
    .catch(function () {
      document.getElementById("issuer-threshold-result").textContent = "The host did not set threshold_n. The check fails closed.";
      document.getElementById("issuer-threshold-result").className = "result-refused";
    });
}

document.getElementById("refresh-well-known-check").addEventListener("click", loadWellKnownCheck);
document.getElementById("refresh-status").addEventListener("click", loadStatus);
document.getElementById("refresh-issuer-public").addEventListener("click", loadIssuerPublic);
document.getElementById("copy-issuer-public-key").addEventListener("click", copyIssuerPublicKey);
document.getElementById("refresh-instances").addEventListener("click", function () {
  loadInstances();
});
document.getElementById("instance-id").addEventListener("change", applySelectedInstanceCapabilities);
document.getElementById("spawn-parent-instance-id").addEventListener("change", applySelectedInstanceCapabilities);
document.getElementById("request-challenge").addEventListener("click", function () {
  requestChallenge().catch(function () {});
});
document.getElementById("emit-wrap").addEventListener("click", emitWrap);
document.getElementById("emit-wimse").addEventListener("click", emitWimse);
document.getElementById("add-agent-type").addEventListener("click", addAgentType);
document.getElementById("birth-instance").addEventListener("click", birthInstance);
document.getElementById("kill-instance").addEventListener("click", killInstance);
document.getElementById("seal-issuer").addEventListener("click", sealIssuer);
document.getElementById("rotate-issuer").addEventListener("click", rotateIssuer);
document.getElementById("export-issuer-backup").addEventListener("click", exportIssuerBackup);
document.getElementById("restore-issuer-backup").addEventListener("click", restoreIssuerBackup);
document.getElementById("diagnose-restore").addEventListener("click", diagnoseRestore);
document.getElementById("register-member-two").addEventListener("click", registerMemberTwo);
document.getElementById("set-verify-threshold").addEventListener("click", setVerifyThreshold);
document.getElementById("set-issuer-threshold").addEventListener("click", setIssuerThreshold);
document.getElementById("export-seal-bundle").addEventListener("click", exportSealBundle);
document.getElementById("export-kill-bundle").addEventListener("click", exportKillBundle);
document.getElementById("download-kill-event").addEventListener("click", function () {
  downloadKillArtifact("event", "event.json");
});
document.getElementById("download-kill-proof").addEventListener("click", function () {
  downloadKillArtifact("proof", "proof.json");
});
document.getElementById("download-kill-tree-head").addEventListener("click", function () {
  downloadKillArtifact("tree_head", "tree-head.json");
});
document.getElementById("accept-issuer-key").addEventListener("click", acceptIssuerKey);
document.getElementById("load-kill-accept-bundle").addEventListener("click", loadKillAcceptBundle);
document.getElementById("accept-kill-bundle").addEventListener("click", acceptKillBundle);
document.getElementById("load-seal-accept-bundle").addEventListener("click", loadSealAcceptBundle);
document.getElementById("accept-seal-bundle").addEventListener("click", acceptSealBundle);
document.getElementById("export-previous-key").addEventListener("click", exportPreviousKey);
document.getElementById("load-previous-key-accept").addEventListener("click", loadPreviousKeyAccept);
document.getElementById("accept-previous-key").addEventListener("click", acceptPreviousKey);
document.getElementById("export-act-bundle").addEventListener("click", exportActBundle);
document.getElementById("load-act-accept-bundle").addEventListener("click", loadActAcceptBundle);
document.getElementById("accept-act-bundle").addEventListener("click", acceptActBundle);
document.getElementById("request-verifier-challenge").addEventListener("click", requestVerifierChallenge);
document.getElementById("sign-verifier-nonce").addEventListener("click", signVerifierNonce);
document.getElementById("request-spawn-challenge").addEventListener("click", function () {
  requestSpawnChallenge().catch(function () {});
});
document.getElementById("spawn-child").addEventListener("click", spawnChild);
document.getElementById("agent-type-id").addEventListener("change", applySelectedAgentTypeIntents);
loadWellKnownCheck();
loadStatus();
loadIssuerPublic();
loadAgentTypes();
loadInstances();

document.getElementById("check-wimse-form").addEventListener("submit", function (event) {
  event.preventDefault();
  submitCheckWimse();
});

document.getElementById("check-form").addEventListener("submit", function (event) {
  event.preventDefault();
  submitCheckSvid();
});
document.getElementById("check-again").addEventListener("click", checkAgain);
if (el("check-base") && !el("check-base").value) { el("check-base").value = location.origin; }
</script>
</body>
</html>
"#;

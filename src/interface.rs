//! Later loopback user interface served on GET / of the same host.
//! This page tells the kernel story. This page is not a public listener.
//! This page consumes existing JSON paths only. Kernel policy is not forked.
//! Secret bytes are not embedded. The issuer secret path string is not embedded.

/// HTML for the later loopback user interface. Secrets are not embedded.
pub const INTERFACE_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Prometheus later user interface</title>
<style>
:root {
  --paper: #e7f1ea;
  --ink: #162019;
  --rail: #2c2118;
  --copper: #7a2910;
  --moss: #0d4f32;
  --blood: #7a1410;
  --ash: #3d4a42;
  --field: #f6fbf7;
  --focus: #0a4d6e;
  --gap: 2.75rem;
  --font-mark: "Bahnschrift", "DIN Alternate", "Arial Narrow", "Franklin Gothic Medium", "Helvetica Neue", sans-serif;
  --font-body: "Trebuchet MS", Verdana, Geneva, sans-serif;
  --font-data: ui-monospace, "Cascadia Code", "Segoe UI Mono", "SFMono-Regular", Menlo, Consolas, monospace;
}
* { box-sizing: border-box; }
html { scroll-behavior: smooth; }
body {
  margin: 0 auto;
  max-width: 40rem;
  padding: 1.25rem 1.25rem 4rem 1.7rem;
  color: var(--ink);
  background: var(--paper);
  font-family: var(--font-body);
  font-size: 1.02rem;
  line-height: 1.55;
}
.skip {
  position: absolute;
  left: -999px;
  top: 0;
}
.skip:focus, .skip:focus-visible {
  left: 1rem;
  top: 1rem;
  z-index: 8;
  padding: 0.4rem 0.7rem;
  background: var(--paper);
  color: var(--ink);
  outline: 3px solid var(--focus);
  outline-offset: 2px;
}
header {
  padding-bottom: 1.1rem;
  border-bottom: 2px solid var(--rail);
}
.kicker {
  margin: 0 0 0.35rem;
  font-family: var(--font-mark);
  font-stretch: condensed;
  letter-spacing: 0.18em;
  text-transform: uppercase;
  font-size: 0.72rem;
  color: var(--copper);
}
h1, h2, h3, button, nav a, summary, .beat-name {
  font-family: var(--font-mark);
  font-stretch: condensed;
  letter-spacing: 0.04em;
}
h1 {
  font-size: 1.85rem;
  line-height: 1.15;
  margin: 0 0 0.7rem;
  font-weight: 700;
}
h2 {
  font-size: 1.35rem;
  margin: 0 0 0.55rem;
  font-weight: 700;
}
h3 {
  font-size: 1.05rem;
  margin: 1.35rem 0 0.4rem;
  font-weight: 700;
}
p { margin: 0.5rem 0; }
.story {
  margin: 0.85rem 0 0.7rem;
  font-size: 1.12rem;
  line-height: 1.4;
}
.note { color: var(--ash); }
a { color: var(--copper); text-underline-offset: 0.18em; }
a:hover { color: var(--ink); }
nav[aria-label="Kernel story"] {
  display: flex;
  flex-wrap: wrap;
  gap: 0.45rem 1rem;
  margin-top: 0.95rem;
}
nav[aria-label="Kernel story"] a {
  color: var(--ink);
  text-decoration: none;
  border-bottom: 2px solid var(--copper);
  padding-bottom: 0.05rem;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  font-size: 0.78rem;
}
nav[aria-label="Kernel story"] a:hover { color: var(--copper); }
#carried {
  position: sticky;
  top: 0;
  z-index: 3;
  background: var(--paper);
  padding: 0.75rem 0 0.7rem;
  border-bottom: 1px solid var(--rail);
}
#carried[data-status="live"] { box-shadow: inset 6px 0 0 var(--moss); padding-left: 0.7rem; }
#carried[data-status="revoked"] { box-shadow: inset 6px 0 0 var(--blood); padding-left: 0.7rem; }
#carried[data-status="empty"] { box-shadow: inset 6px 0 0 var(--ash); padding-left: 0.7rem; }
#carried-line, .carried-echo {
  font-family: var(--font-data);
  font-size: 0.86rem;
  line-height: 1.45;
  margin: 0.15rem 0 0;
}
main#story {
  border-left: 4px solid var(--rail);
  margin: 0.2rem 0 0;
  padding-left: 1.1rem;
}
.beat {
  margin: var(--gap) 0 0;
  padding: 0;
  position: relative;
}
.beat::before {
  content: "";
  position: absolute;
  left: calc(-1.1rem - 4px);
  top: 0.35rem;
  width: 0.72rem;
  height: 0.72rem;
  background: var(--paper);
  border: 3px solid var(--rail);
}
.beat-name {
  margin: 0 0 0.15rem;
  font-size: 0.72rem;
  letter-spacing: 0.22em;
  text-transform: uppercase;
  color: var(--copper);
}
label {
  display: block;
  margin-top: 0.95rem;
  font-weight: 700;
  font-size: 0.92rem;
}
input[type="text"], textarea, select {
  width: 100%;
  margin-top: 0.28rem;
  padding: 0.4rem 0.45rem;
  color: var(--ink);
  background: var(--field);
  border: 0;
  border-bottom: 2px solid var(--rail);
  border-radius: 0;
  font-family: var(--font-data);
  font-size: 0.92rem;
}
textarea { min-height: 7rem; }
pre {
  margin: 0.55rem 0;
  padding: 0.35rem 0 0.35rem 0.8rem;
  background: transparent;
  border-left: 3px solid var(--rail);
  overflow: auto;
  white-space: pre-wrap;
  font-family: var(--font-data);
  font-size: 0.82rem;
  color: var(--ink);
}
.counts { font-size: 1.08rem; font-weight: 700; }
button {
  margin: 0.85rem 0.55rem 0 0;
  padding: 0.42rem 0.9rem;
  color: var(--ink);
  background: var(--paper);
  border: 2px solid var(--rail);
  border-radius: 0;
  font-size: 0.92rem;
  font-weight: 700;
  cursor: pointer;
}
button:hover { background: var(--rail); color: var(--paper); }
button.danger { border-color: var(--blood); color: var(--blood); }
button.danger:hover { background: var(--blood); color: var(--paper); }
:focus-visible {
  outline: 3px solid var(--focus);
  outline-offset: 2px;
}
.result {
  margin-top: 0.7rem;
  padding: 0.35rem 0 0.35rem 0.7rem;
  font-weight: 700;
}
.result-allowed {
  color: var(--moss);
  border-left: 4px solid var(--moss);
}
.result-refused {
  color: var(--blood);
  border-left: 4px double var(--blood);
}
.result-death {
  color: var(--ink);
  border-left: 4px dashed var(--blood);
  text-decoration: underline;
  text-underline-offset: 0.18em;
}
#verifier { margin-top: calc(var(--gap) + 0.5rem); }
details.advanced {
  margin-top: 3rem;
  padding-top: 0.8rem;
  border-top: 2px solid var(--rail);
}
details.advanced > summary {
  font-weight: 700;
  font-size: 1.15rem;
  cursor: pointer;
}
@media (prefers-reduced-motion: reduce) {
  html { scroll-behavior: auto; }
  *, *::before, *::after {
    animation: none !important;
    transition: none !important;
  }
}
</style>
</head>
<body>
<a class="skip" href="#story">Skip to the kernel story</a>
<header>
<p class="kicker">Loopback 127.0.0.1</p>
<h1>Prometheus later user interface</h1>
<p>This host binds to 127.0.0.1 only. This is not a public listener.</p>
<p class="story">Create Agent Principal writes a live agent. Spawn writes a narrower child of that act. The agent can present an Assertion Act. A consumer can check that Assertion Act. Decommission ends the identity. Death wins.</p>
<p class="note">This page does not show issuer secrets, Biscuit secrets, holder secrets, or member-two secrets. Secret file bytes are not uploaded. The browser does not read secret files from disk.</p>
<p>The laboratory operator page remains at <a href="/laboratory">GET /laboratory</a>.</p>
<nav aria-label="Kernel story">
<a href="#status">Status</a>
<a href="#birth">Create Agent Principal</a>
<a href="#spawn">Spawn</a>
<a href="#present">Assertion Act</a>
<a href="#check">Check</a>
<a href="#death">Decommission</a>
<a href="#verifier">Verifier</a>
</nav>
</header>
<section id="carried" data-status="empty" aria-live="polite">
<p class="beat-name">This instance</p>
<p id="carried-line">No instance is carried yet. Create Agent Principal writes one. Spawn writes a narrower child. Assertion Act, Check, and Decommission use that instance.</p>
</section>
<main id="story">
<section id="status" class="beat">
<p class="beat-name">Status</p>
<h2>Status</h2>
<p>GET /status shows live and revoked instance counts. GET /issuer-public returns the full current issuer public key hexadecimal. Secret bytes are not shown.</p>
<p id="status-counts" class="counts">The store status is loading.</p>
<details>
<summary>Store status JSON</summary>
<pre id="store-status">The status is loading.</pre>
</details>
<label for="this-store-issuer-public-key">Current issuer public key hexadecimal</label>
<textarea id="this-store-issuer-public-key" readonly></textarea>
<p id="this-store-crypto-profile">The crypto profile is loading.</p>
<button type="button" id="refresh-status">Refresh the store status</button>
<button type="button" id="copy-issuer-public-key">Copy the issuer public key</button>
<button type="button" id="refresh-issuer-public">Refresh the issuer public key</button>
<p class="note">On an issuing store, after issuance threshold_n is 2, type a local member secret path. Verifier forms do not send that path.</p>
<label for="issuing-member-secret-path">Issuing-store member secret path</label>
<input id="issuing-member-secret-path" name="member_secret_path" type="text" autocomplete="off">
</section>

<section id="birth" class="beat">
<p class="beat-name">Create Agent Principal</p>
<h2>Create Agent Principal</h2>
<p>Add an agent type. Then use Create Agent Principal. POST /agent-type and POST /birth reuse the kernel. The response returns the holder secret path only. Secret bytes are not shown.</p>
<p class="carried-echo" data-echo></p>
<h3>Add an agent type</h3>
<label for="new-allowed-intents">Allowed intents</label>
<input id="new-allowed-intents" name="allowed_intents" type="text" value="read">
<label for="new-authorization-limit">Authorization limit</label>
<input id="new-authorization-limit" name="authorization_limit" type="text" value="internal">
<label for="new-agent-type-owner">Owner</label>
<input id="new-agent-type-owner" name="owner" type="text" value="laboratory">
<button type="button" id="add-agent-type">Add the agent type</button>
<p id="agent-type-result">No agent type has been added on this page.</p>
<h3>Birth an instance</h3>
<label for="agent-type-id">Agent type</label>
<select id="agent-type-id" name="agent_type_id"><option value="">No agent type is selected</option></select>
<label for="birth-owner">Owner</label>
<input id="birth-owner" name="owner" type="text" value="laboratory">
<label for="birth-intent">Intent</label>
<input id="birth-intent" name="intent" type="text" value="read">
<label for="birth-audience">Audience</label>
<input id="birth-audience" name="audience" type="text" value="internal">
<label for="birth-on-behalf-of">Act authority on_behalf_of</label>
<input id="birth-on-behalf-of" name="on_behalf_of" type="text" value="autonomous">
<button type="button" id="birth-instance">Birth an instance</button>
<p id="birth-result">No instance has been born on this page.</p>
<p id="birth-holder-path" class="note">The holder secret path is empty until birth.</p>
<h3>Instances</h3>
<p>GET /instances lists instance identifiers and live or revoked status. Holder public keys and capability tokens are not shown.</p>
<pre id="instance-list">The instance list is loading.</pre>
<button type="button" id="refresh-instances">Refresh the instance list</button>
</section>

<section id="spawn" class="beat">
<p class="beat-name">Spawn</p>
<h2>Spawn</h2>
<p>POST /spawn reuses the kernel spawn write. Pick a live parent from birth or from GET /instances. Fill an intent and an audience that are narrower than or equal to the parent. A child that exceeds the parent is refused. This is not a role catalog. The response returns the child instance identifier, the child capability identifier, and the holder secret path only. Secret bytes are not shown.</p>
<p class="carried-echo" data-echo></p>
<label for="spawn-parent-instance-id">Live parent instance</label>
<select id="spawn-parent-instance-id" name="parent_instance_id"><option value="">No live parent is selected</option></select>
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
<button type="button" id="request-spawn-challenge">Request a parent challenge</button>
<button type="button" id="spawn-child">Spawn a narrower child</button>
<p id="spawn-result">No child has been spawned on this page.</p>
</section>

<section id="present" class="beat">
<p class="beat-name">Assertion Act</p>
<h2>Assertion Act</h2>
<p>Request a challenge or a verifier challenge. Emit a laboratory X.509-SVID wrap or a Workload Identity Token as an Assertion Act. Sign a verifier nonce on this host. POST /challenge, POST /verifier-challenge, POST /present-svid, POST /present-wimse, and POST /sign-holder-nonce reuse the kernel. Secret bytes are not shown.</p>
<p class="carried-echo" data-echo></p>
<label for="instance-id">Live instance</label>
<select id="instance-id" name="instance_id"><option value="">No live instance is selected</option></select>
<label for="capability-id">Capability identifier</label>
<input id="capability-id" name="capability_id" type="text">
<label for="wrap-intent">Intent</label>
<input id="wrap-intent" name="intent" type="text" value="read">
<label for="wrap-audience">Audience</label>
<input id="wrap-audience" name="audience" type="text" value="internal">
<label for="on-behalf-of">Act authority on_behalf_of</label>
<input id="on-behalf-of" name="on_behalf_of" type="text" value="autonomous">
<label for="holder-secret-path">Holder secret path on this host</label>
<input id="holder-secret-path" name="holder_secret_path" type="text" autocomplete="off">
<label for="holder-proof">Holder proof hexadecimal</label>
<input id="holder-proof" name="holder_proof" type="text">
<label for="challenge-nonce">Challenge nonce</label>
<input id="challenge-nonce" name="challenge_nonce" type="text">
<label for="challenge-message">Verifier challenge message</label>
<input id="challenge-message" name="challenge_message" type="text">
<button type="button" id="request-challenge">Request a challenge</button>
<button type="button" id="request-verifier-challenge">Request a verifier challenge</button>
<button type="button" id="sign-verifier-nonce">Sign the holder nonce</button>
<button type="button" id="emit-wrap">Present X.509-SVID</button>
<button type="button" id="emit-wimse">Present WIMSE</button>
<p id="wrap-result">No present has been emitted on this page.</p>
<p id="wimse-result">No Workload Identity Token has been emitted on this page.</p>
<p id="verifier-challenge-result">No verifier challenge has been issued.</p>
</section>

<section id="check" class="beat">
<p class="beat-name">Check</p>
<h2>Check</h2>
<p>POST /check-svid and POST /check-wimse allow or refuse. Death wins. Short certificate or token life is not kill. Holder proof remains required.</p>
<p>Type a check base. The accepted bases are http://127.0.0.1 on this host or https://check.prestigeworldwide.digital. This page follows GET /.well-known/prometheus-check. Other names are refused. HTTP to the public name is refused. Secret bytes are not uploaded.</p>
<p class="note">A verifier check uses the present. An empty live-instance field is correct. Do not birth on a verifier. This store does not invent an instance identifier. When this store has no live instance, the check body does not include holder_secret_path or member_secret_path.</p>
<p class="note">POST /check-wimse binds HTTP @method, @request-target, and content-digest. This is still not a full header-coverage stack.</p>
<p class="carried-echo" data-echo></p>
<label for="check-base">Check base</label>
<input id="check-base" name="check_base" type="text" autocomplete="off">
<p class="note">The holder secret path stays on this host. POST /runtime-check signs the verifier nonce here. The path is not sent to the check base.</p>
<label for="check-instance-id">Live instance on this store</label>
<input id="check-instance-id" name="instance_id" type="text" readonly>
<label for="presentation-json">Presentation JSON</label>
<textarea id="presentation-json" name="presentation_json"></textarea>
<label for="certificate-pem">Certificate PEM</label>
<textarea id="certificate-pem" name="certificate_pem"></textarea>
<button type="button" id="submit-check-svid">Check X.509-SVID</button>
<label for="wimse-presentation-json">WIMSE presentation JSON</label>
<textarea id="wimse-presentation-json" name="wimse_presentation_json"></textarea>
<label for="workload-identity-token">Workload Identity Token</label>
<textarea id="workload-identity-token" name="workload_identity_token"></textarea>
<label for="content-digest">Content-Digest</label>
<input id="content-digest" name="content_digest" type="text">
<input id="wimse-signature-input" name="signature_input" type="hidden">
<input id="wimse-signature" name="signature" type="hidden">
<button type="button" id="submit-check-wimse">Check WIMSE</button>
<button type="button" id="check-again">Check again</button>
<p class="note">Check again posts the same present to the typed check base. This page does not store ALLOWED. Each click hits the host.</p>
<p class="note">This page can hold two Assertion Acts. Present the parent. Spawn a narrower child. Present the child. Check both posts POST /runtime-check once per present. ALLOWED only if both allow. Each present is a separate host hit. This page does not store ALLOWED. After parent Decommission, Check both and a named check of the child refuse because this store accepted a kill cascade. A parent laboratory X.509-SVID wrap and a child WIMSE Assertion Act refuse after parent Decommission because this store accepted a kill cascade. Two independent Create Agent Principal presents can also be held. One present may be a laboratory X.509-SVID wrap and the other a WIMSE Assertion Act. After the first dies, Check both refuses and a named check of the live act may still allow. After the WIMSE act dies, Check both refuses because SVID allow plus WIMSE refuse is not ALLOWED.</p>
<p id="held-acts">No Assertion Act is held on this page.</p>
<button type="button" id="check-both">Check both</button>
<label for="check-act-number">Check this act only</label>
<input id="check-act-number" name="check_act_number" type="text" inputmode="numeric" autocomplete="off">
<button type="button" id="check-this-act">Check this act only</button>
<p id="decision-result">No check has been submitted.</p>
<p id="decision-reason"></p>
<pre id="decision-body">The check body is empty until a check.</pre>
</section>

<section id="death" class="beat">
<p class="beat-name">Decommission</p>
<h2>Decommission</h2>
<p>Use Decommission on a live instance. Type the same instance identifier to confirm. Then export the signed death bundle. POST /kill and POST /kill-export reuse the kernel. A following check of a historical Assertion Act is refused.</p>
<p class="carried-echo" data-echo></p>
<label for="kill-instance-id">Live instance to kill</label>
<select id="kill-instance-id" name="kill_instance_id"><option value="">No live instance is selected</option></select>
<label for="kill-confirm">Type the instance identifier to confirm</label>
<input id="kill-confirm" name="confirm" type="text">
<button type="button" id="kill-instance" class="danger">Kill the instance</button>
<p id="kill-result">No instance has been killed on this page.</p>
<label for="kill-export-instance-id">Revoked instance</label>
<select id="kill-export-instance-id" name="kill_export_instance_id"><option value="">No revoked instance is selected</option></select>
<label for="kill-export-confirm">Type the instance identifier to confirm export</label>
<input id="kill-export-confirm" name="kill_export_confirm" type="text">
<button type="button" id="export-kill-bundle">Export the kill bundle</button>
<p id="kill-export-result">No kill bundle has been exported on this page.</p>
<pre id="kill-export-event">event.json is empty until export.</pre>
<pre id="kill-export-proof">proof.json is empty until export.</pre>
<pre id="kill-export-tree-head">tree-head.json is empty until export.</pre>
</section>

<section id="verifier">
<h2>Verifier</h2>
<p>A verifier pins public artifacts. This store writes no instance record. Verifier forms do not send a member secret path. Store B does not need issuer member secrets.</p>
<label for="issuer-public-key-hex">Foreign issuer public key hexadecimal</label>
<input id="issuer-public-key-hex" name="public_key_hex" type="text">
<button type="button" id="accept-issuer-key">Accept the issuer public key</button>
<p id="issuer-accept-result">No issuer public key has been accepted on this page.</p>
<label for="kill-accept-export-json">Kill-export JSON</label>
<textarea id="kill-accept-export-json" name="kill_accept_export_json"></textarea>
<button type="button" id="load-kill-accept-bundle">Load the kill artifacts</button>
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
<label for="seal-accept-export-json">Seal-export JSON</label>
<textarea id="seal-accept-export-json" name="seal_accept_export_json"></textarea>
<button type="button" id="load-seal-accept-bundle">Load the seal artifacts</button>
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
<label for="previous-key-accept-export-json">Previous-key-export JSON</label>
<textarea id="previous-key-accept-export-json" name="previous_key_accept_export_json"></textarea>
<button type="button" id="load-previous-key-accept">Load the previous-key artifacts</button>
<label for="previous-key-accept-public-key">public_key_hex</label>
<input id="previous-key-accept-public-key" name="public_key_hex" type="text">
<label for="previous-key-accept-kill-date">kill_date</label>
<input id="previous-key-accept-kill-date" name="kill_date" type="text">
<button type="button" id="accept-previous-key">Accept the previous issuer key</button>
<p id="previous-key-accept-result">No previous issuer key has been accepted on this page.</p>
<pre id="previous-key-accept-instances">This store wrote no instance record until refresh.</pre>
<p class="note">Request a verifier challenge in Assertion Act. Sign the nonce on the issuing host. Paste the holder signature into Holder proof hexadecimal. A verifier challenge does not send a member secret.</p>
</section>
<details class="advanced">
<summary>Advanced issuer writes</summary>
<p>These writes stay on the same loopback host. After issuance threshold_n is 2 they send the issuing-store member secret path. A threshold of 3 stays parked. Init stays off this page.</p>
<h3>Rotate the issuer</h3>
<p>Type the word rotate to confirm. POST /rotate reuses the kernel. Secret bytes are not returned.</p>
<label for="rotate-kill-after-seconds">Seconds until the previous key kill date</label>
<input id="rotate-kill-after-seconds" name="kill_after_seconds" type="text" value="300">
<label for="rotate-confirm">Type the word rotate to confirm</label>
<input id="rotate-confirm" name="rotate_confirm" type="text">
<button type="button" id="rotate-issuer">Rotate the issuer</button>
<p id="rotate-result">The issuer is not rotated on this page.</p>
<pre id="rotate-body">rotate JSON is empty until rotate.</pre>
<button type="button" id="export-previous-key">Export the previous issuer key</button>
<p id="previous-key-export-result">No previous issuer key has been exported on this page.</p>
<pre id="previous-key-export-body">previous-key JSON is empty until export.</pre>
<h3>Register member two</h3>
<p>Type a local outside path. POST /member-two reuses the kernel member add. Secret bytes are not uploaded and not returned.</p>
<label for="member-two-secret-path">Member two secret path on this host</label>
<input id="member-two-secret-path" name="member_secret_path" type="text">
<button type="button" id="register-member-two">Register member two</button>
<p id="member-two-result">Member two is not registered on this page.</p>
<pre id="member-two-body">member-two JSON is empty until register.</pre>
<h3>Set verify threshold</h3>
<p>Type the word verify-threshold to confirm. Persist member two first.</p>
<label for="verify-threshold-n">verify_threshold_n</label>
<input id="verify-threshold-n" name="n" type="text" value="2">
<label for="verify-threshold-confirm">Type the word verify-threshold to confirm</label>
<input id="verify-threshold-confirm" name="verify_threshold_confirm" type="text">
<button type="button" id="set-verify-threshold">Set the verify threshold</button>
<p id="verify-threshold-result">The verify threshold is not changed on this page.</p>
<pre id="verify-threshold-body">verify-threshold JSON is empty until set.</pre>
<h3>Set issuer threshold</h3>
<p>Type the word issuer-threshold to confirm. A threshold of 3 stays parked.</p>
<label for="issuer-threshold-n">threshold_n</label>
<input id="issuer-threshold-n" name="n" type="text" value="2">
<label for="issuer-threshold-confirm">Type the word issuer-threshold to confirm</label>
<input id="issuer-threshold-confirm" name="issuer_threshold_confirm" type="text">
<button type="button" id="set-issuer-threshold">Set the issuer threshold</button>
<p id="issuer-threshold-result">The issuer threshold is not changed on this page.</p>
<pre id="issuer-threshold-body">issuer-threshold JSON is empty until set.</pre>
<h3>Seal the issuer</h3>
<p>Type the word seal to confirm. After remaining life, mint, birth, spawn, present, and check are refused. Kill after seal stays allowed.</p>
<label for="seal-after-seconds">Seconds until issuer death</label>
<input id="seal-after-seconds" name="after_seconds" type="text" value="60">
<label for="seal-confirm">Type the word seal to confirm</label>
<input id="seal-confirm" name="seal_confirm" type="text">
<button type="button" id="seal-issuer">Seal the issuer</button>
<p id="seal-result">The issuer is not sealed on this page.</p>
<button type="button" id="export-seal-bundle">Export the seal bundle</button>
<p id="seal-export-result">No seal bundle has been exported on this page.</p>
<pre id="seal-export-event">event.json is empty until export.</pre>
<pre id="seal-export-proof">proof.json is empty until export.</pre>
<pre id="seal-export-tree-head">tree-head.json is empty until export.</pre>
<h3>Export an act bundle</h3>
<p>After a successful check, POST /act-export returns receipt, proof, and tree_head. POST /act-accept on a verifier host reuses Kernel act accept.</p>
<label for="act-export-receipt">Check receipt JSON</label>
<textarea id="act-export-receipt" name="receipt"></textarea>
<button type="button" id="export-act-bundle">Export the act bundle</button>
<p id="act-export-result">No act bundle has been exported on this page.</p>
<pre id="act-export-receipt-out">receipt.json is empty until export.</pre>
<pre id="act-export-proof">proof.json is empty until export.</pre>
<pre id="act-export-tree-head">tree-head.json is empty until export.</pre>
<label for="act-accept-export-json">Act-export JSON</label>
<textarea id="act-accept-export-json" name="act_accept_export_json"></textarea>
<button type="button" id="load-act-accept-bundle">Load the act artifacts</button>
<label for="act-accept-receipt">receipt</label>
<textarea id="act-accept-receipt" name="receipt"></textarea>
<label for="act-accept-proof">proof</label>
<textarea id="act-accept-proof" name="proof"></textarea>
<label for="act-accept-tree-head">tree_head</label>
<textarea id="act-accept-tree-head" name="tree_head"></textarea>
<button type="button" id="accept-act-bundle">Accept the act bundle</button>
<p id="act-accept-result">No act bundle has been accepted on this page.</p>
<pre id="act-accept-instances">This store wrote no instance record until refresh.</pre>
</details>
<script>
function el(id) { return document.getElementById(id); }
function setResult(id, text, allowed) {
  var node = el(id);
  var kind = "refused";
  if (allowed) { kind = (id === "kill-result") ? "death" : "allowed"; }
  var mark = kind === "allowed" ? "ALLOWED. " : (kind === "death" ? "REVOKED. " : "REFUSED. ");
  var already = text.indexOf("ALLOWED. ") === 0 || text.indexOf("REFUSED. ") === 0 || text.indexOf("REVOKED. ") === 0;
  node.textContent = already ? text : (mark + text);
  node.className = "result result-" + kind;
  node.setAttribute("data-outcome", kind);
}

var carried = { instanceId: "", status: "", capabilityId: "", holderPath: "" };
var holderPaths = {};
function selectHasValue(selectId, value) {
  var select = el(selectId);
  if (!select || !value) { return false; }
  for (var i = 0; i < select.options.length; i += 1) {
    if (select.options[i].value === value) { return true; }
  }
  return false;
}
function renderCarried() {
  var line = el("carried-line");
  var box = el("carried");
  if (!line || !box) { return; }
  var text;
  if (!carried.instanceId) {
    text = "No instance is carried yet. Create Agent Principal writes one on an issuing store. Spawn writes a narrower child. A verifier check uses the Assertion Act. An empty live-instance field is correct.";
    box.setAttribute("data-status", "empty");
  } else {
    var bits = ["Instance " + carried.instanceId, (carried.status || "live").toUpperCase()];
    if (carried.capabilityId) { bits.push("capability " + carried.capabilityId); }
    if (carried.holderPath) { bits.push("holder path " + carried.holderPath); }
    text = bits.join(" · ") + ". Secret bytes are not shown.";
    box.setAttribute("data-status", carried.status || "live");
  }
  line.textContent = text;
  var echoes = document.querySelectorAll("[data-echo]");
  for (var i = 0; i < echoes.length; i += 1) { echoes[i].textContent = text; }
  if (el("check-instance-id")) { el("check-instance-id").value = carried.instanceId || ""; }
}
function rememberHolderPath(instanceId, holderPath) {
  if (instanceId && holderPath) { holderPaths[instanceId] = holderPath; }
}
function setCarriedFromBirth(instanceId, capabilityId, holderPath) {
  carried.instanceId = instanceId || "";
  carried.status = "live";
  carried.capabilityId = capabilityId || "";
  carried.holderPath = holderPath || "";
  rememberHolderPath(instanceId, holderPath);
  renderCarried();
}
function addIssuingMemberSecretPath(body) {
  var memberPath = (el("issuing-member-secret-path").value || "").trim();
  if (memberPath) { body.member_secret_path = memberPath; }
}
function parseJsonObject(text, label) {
  try {
    var value = JSON.parse(text);
    if (!value || typeof value !== "object") { throw new Error("not an object"); }
    return value;
  } catch (error) {
    throw new Error("The " + label + " text is not valid JSON. The check fails closed.");
  }
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
function instanceListingLabel(listing) {
  var label = listing.instance_id + " " + listing.status;
  if (listing.parent_instance_id) { label += " parent " + listing.parent_instance_id; }
  return label;
}
function fillOneInstanceSelect(selectId, instances) {
  var select = el(selectId);
  var previous = select.value;
  select.innerHTML = "";
  var placeholder = document.createElement("option");
  placeholder.value = "";
  placeholder.textContent = "No live instance is selected";
  select.appendChild(placeholder);
  var liveCount = 0;
  for (var index = 0; index < instances.length; index += 1) {
    var listing = instances[index];
    if (listing.status !== "live") { continue; }
    var option = document.createElement("option");
    option.value = listing.instance_id;
    option.textContent = instanceListingLabel(listing);
    option.setAttribute("data-capability-ids", (listing.capability_ids || []).join(" "));
    select.appendChild(option);
    liveCount += 1;
  }
  if (previous) { select.value = previous; }
  if (liveCount === 0) { placeholder.textContent = "No live instance is on this store"; }
}
function fillRevokedInstanceSelect(selectId, instances) {
  var select = el(selectId);
  var previous = select.value;
  select.innerHTML = "";
  var placeholder = document.createElement("option");
  placeholder.value = "";
  placeholder.textContent = "No revoked instance is selected";
  select.appendChild(placeholder);
  var revokedCount = 0;
  for (var index = 0; index < instances.length; index += 1) {
    var listing = instances[index];
    if (listing.status !== "revoked") { continue; }
    var option = document.createElement("option");
    option.value = listing.instance_id;
    option.textContent = instanceListingLabel(listing);
    select.appendChild(option);
    revokedCount += 1;
  }
  if (previous) { select.value = previous; }
  if (revokedCount === 0) { placeholder.textContent = "No revoked instance is on this store"; }
}
function capabilityIdsFromSelect(selectId) {
  var select = el(selectId);
  if (!select || !select.value) { return []; }
  var option = select.options[select.selectedIndex];
  if (!option) { return []; }
  return (option.getAttribute("data-capability-ids") || "").split(" ").filter(function (value) { return value.length > 0; });
}
function fillCapabilityFieldFromSelect(selectId, fieldId) {
  var field = el(fieldId);
  if (!field) { return; }
  var ids = capabilityIdsFromSelect(selectId);
  if (ids.length === 0) { return; }
  if (ids.indexOf(field.value) !== -1) { return; }
  field.value = ids[0];
}
function applySelectedInstanceCapabilities() {
  fillCapabilityFieldFromSelect("instance-id", "capability-id");
  fillCapabilityFieldFromSelect("spawn-parent-instance-id", "spawn-parent-capability-id");
}
function loadStatus() {
  fetch("/status").then(function (response) { return response.text(); }).then(function (text) {
    try {
      var data = JSON.parse(text);
      el("store-status").textContent = JSON.stringify(data, null, 2);
      var live = data.instance_live_count;
      var revoked = data.instance_revoked_count;
      el("status-counts").textContent = "Live instances: " + String(live) + ". Revoked instances: " + String(revoked) + ".";
    } catch (error) {
      el("store-status").textContent = "The status response is not valid JSON. The check fails closed.";
      el("status-counts").textContent = "The store status did not parse.";
    }
  }).catch(function () {
    el("store-status").textContent = "The host did not return store status. The check fails closed.";
    el("status-counts").textContent = "The host did not return store status.";
  });
}
function loadIssuerPublic() {
  fetch("/issuer-public").then(function (response) { return response.text(); }).then(function (text) {
    try {
      var data = JSON.parse(text);
      el("this-store-issuer-public-key").value = data.current_issuer_public_key_hex || "";
      el("this-store-crypto-profile").textContent = data.crypto_profile ? ("crypto_profile: " + data.crypto_profile) : "The crypto profile is missing. The check fails closed.";
    } catch (error) {
      el("this-store-issuer-public-key").value = "";
      el("this-store-crypto-profile").textContent = "The issuer-public response is not valid JSON. The check fails closed.";
    }
  }).catch(function () {
    el("this-store-issuer-public-key").value = "";
    el("this-store-crypto-profile").textContent = "The host did not return the issuer public key. The check fails closed.";
  });
}
function copyIssuerPublicKey() {
  var box = el("this-store-issuer-public-key");
  box.focus();
  box.select();
  try { document.execCommand("copy"); } catch (error) {}
}
function loadInstances(selectInstanceId, selectExportInstanceId) {
  fetch("/instances").then(function (response) { return response.text(); }).then(function (text) {
    try {
      var data = JSON.parse(text);
      var instances = data.instances || [];
      el("instance-list").textContent = JSON.stringify(instances, ["instance_id", "parent_instance_id", "status", "capability_ids", "agent_type_id"], 2);
      fillOneInstanceSelect("instance-id", instances);
      fillOneInstanceSelect("kill-instance-id", instances);
      fillOneInstanceSelect("spawn-parent-instance-id", instances);
      fillRevokedInstanceSelect("kill-export-instance-id", instances);
      var preferredLive = selectInstanceId || (carried.status !== "revoked" ? carried.instanceId : "");
      if (preferredLive) {
        if (selectHasValue("instance-id", preferredLive)) { el("instance-id").value = preferredLive; }
        if (selectHasValue("kill-instance-id", preferredLive)) { el("kill-instance-id").value = preferredLive; }
        if (selectHasValue("spawn-parent-instance-id", preferredLive)) { el("spawn-parent-instance-id").value = preferredLive; }
      }
      if (selectExportInstanceId) { el("kill-export-instance-id").value = selectExportInstanceId; }
      else if (carried.status === "revoked" && selectHasValue("kill-export-instance-id", carried.instanceId)) {
        el("kill-export-instance-id").value = carried.instanceId;
      }
      applySelectedInstanceCapabilities();
      if (preferredLive && el("instance-id").value === preferredLive) {
        var ids = capabilityIdsFromSelect("instance-id");
        if (ids.length > 0) { carried.capabilityId = ids[0]; }
        if (holderPaths[preferredLive]) { carried.holderPath = holderPaths[preferredLive]; }
        if (!carried.instanceId) { carried.instanceId = preferredLive; carried.status = "live"; }
        renderCarried();
      } else {
        renderCarried();
      }
    } catch (error) {
      el("instance-list").textContent = "The instances response is not valid JSON. The check fails closed.";
    }
  }).catch(function () {
    el("instance-list").textContent = "The host did not return the instance list. The check fails closed.";
  });
}
function applySelectedAgentTypeIntents() {
  var select = el("agent-type-id");
  var option = select.options[select.selectedIndex];
  if (!option || !option.value) { return; }
  var intents = (option.getAttribute("data-allowed-intents") || "").split(" ").filter(function (value) { return value.length > 0; });
  var intentField = el("birth-intent");
  if (intents.length > 0 && intents.indexOf(intentField.value) === -1) { intentField.value = intents[0]; }
}
function loadAgentTypes(selectAgentTypeId) {
  fetch("/agent-types").then(function (response) { return response.text(); }).then(function (text) {
    try {
      var data = JSON.parse(text);
      var agentTypes = data.agent_types || [];
      var select = el("agent-type-id");
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
        option.textContent = listing.agent_type_id;
        option.setAttribute("data-allowed-intents", (listing.allowed_intents || []).join(" "));
        select.appendChild(option);
      }
      if (selectAgentTypeId) { select.value = selectAgentTypeId; }
      else if (previous) { select.value = previous; }
      else if (agentTypes.length === 1) { select.value = agentTypes[0].agent_type_id; }
      if (agentTypes.length === 0) { placeholder.textContent = "No agent type is on this store"; }
      applySelectedAgentTypeIntents();
    } catch (error) {
      setResult("birth-result", "The agent-types response is not valid JSON. The check fails closed.", false);
    }
  }).catch(function () {
    setResult("birth-result", "The host did not return agent types. The check fails closed.", false);
  });
}
function addAgentType() {
  var allowedIntents = (el("new-allowed-intents").value || "").split(/[\s,]+/).filter(function (value) { return value.length > 0; });
  var body = { allowed_intents: allowedIntents, authorization_limit: el("new-authorization-limit").value || null, owner: el("new-agent-type-owner").value || null };
  addIssuingMemberSecretPath(body);
  postJson("/agent-type", body).then(function (payload) {
    var data = readJsonPayload(payload, "The agent-type response is not valid JSON. The check fails closed.");
    if (data.agent_type_id && data.allowed_intents) {
      setResult("agent-type-result", "The host wrote the agent type. Create Agent Principal can use this class.", true);
      loadAgentTypes(data.agent_type_id);
      return;
    }
    setResult("agent-type-result", data.reason || "The host refused the agent type write. The check fails closed.", false);
  }).catch(function (error) {
    setResult("agent-type-result", error.message || "The host did not write an agent type. The check fails closed.", false);
  });
}
function birthInstance() {
  var agentTypeId = el("agent-type-id").value;
  if (!agentTypeId) { setResult("birth-result", "Select an agent type before you birth an instance.", false); return; }
  var body = { agent_type_id: agentTypeId, owner: el("birth-owner").value || null, intent: el("birth-intent").value || null, audience: el("birth-audience").value || null, on_behalf_of: el("birth-on-behalf-of").value || null };
  addIssuingMemberSecretPath(body);
  postJson("/birth", body).then(function (payload) {
    var data = readJsonPayload(payload, "The birth response is not valid JSON. The check fails closed.");
    if (data.instance_id && data.capability_id && data.holder_secret_path) {
      el("capability-id").value = data.capability_id;
      el("holder-secret-path").value = data.holder_secret_path;
      el("spawn-parent-capability-id").value = data.capability_id;
      el("spawn-holder-secret-path").value = data.holder_secret_path;
      el("birth-holder-path").textContent = "Holder secret path: " + data.holder_secret_path + ". Secret bytes are not shown.";
      el("wrap-intent").value = el("birth-intent").value;
      el("wrap-audience").value = el("birth-audience").value;
      el("on-behalf-of").value = el("birth-on-behalf-of").value;
      setCarriedFromBirth(data.instance_id, data.capability_id, data.holder_secret_path);
      setResult("birth-result", "The host wrote a live instance. Challenge and present can run on this page.", true);
      loadInstances(data.instance_id);
      loadStatus();
      return;
    }
    setResult("birth-result", data.reason || "The host refused birth. The check fails closed.", false);
  }).catch(function (error) {
    setResult("birth-result", error.message || "The host did not birth an instance. The check fails closed.", false);
  });
}
function selectedInstanceId() { return el("instance-id").value; }
function presentBody() {
  var body = {
    instance_id: selectedInstanceId(),
    capability_id: el("capability-id").value || null,
    intent: el("wrap-intent").value || null,
    audience: el("wrap-audience").value || null,
    holder_proof: el("holder-proof").value || null,
    holder_secret_path: el("holder-secret-path").value || null,
    challenge_nonce: el("challenge-nonce").value || null,
    on_behalf_of: el("on-behalf-of").value || null
  };
  addIssuingMemberSecretPath(body);
  return body;
}
function requestChallenge() {
  var instanceId = selectedInstanceId();
  if (!instanceId) { setResult("wrap-result", "Select a live instance before you request a challenge.", false); return Promise.reject(new Error("no live instance")); }
  var challengeBody = { instance_id: instanceId };
  addIssuingMemberSecretPath(challengeBody);
  return postJson("/challenge", challengeBody).then(function (payload) {
    var data = readJsonPayload(payload, "The challenge response is not valid JSON. The check fails closed.");
    if (data.challenge_nonce) {
      el("challenge-nonce").value = data.challenge_nonce;
      setResult("wrap-result", "The host returned a challenge nonce.", true);
      return data.challenge_nonce;
    }
    setResult("wrap-result", data.reason || "The host refused the challenge. The check fails closed.", false);
    return Promise.reject(new Error("challenge refused"));
  });
}
function requestVerifierChallenge() {
  followWellKnownThenPin("verifier-challenge", {}, "verifier-challenge-result", function (payload) {
    var data = readJsonPayload(payload, "The verifier challenge response is not valid JSON. The check fails closed.");
    if (data.challenge_nonce) {
      el("challenge-nonce").value = data.challenge_nonce;
      el("challenge-message").value = data.challenge_message || "";
      setResult("verifier-challenge-result", "The host returned a verifier challenge nonce. This store wrote no instance. No member secret was sent.", true);
      return;
    }
    setResult("verifier-challenge-result", data.reason || "The host refused the verifier challenge. The check fails closed.", false);
  });
}
function signVerifierNonce() {
  var body = { challenge_nonce: el("challenge-nonce").value || null, challenge_message: el("challenge-message").value || null, holder_secret_path: el("holder-secret-path").value };
  postJson("/sign-holder-nonce", body).then(function (payload) {
    var data = readJsonPayload(payload, "The sign response is not valid JSON. The check fails closed.");
    if (data.holder_proof) {
      el("holder-proof").value = data.holder_proof;
      setResult("verifier-challenge-result", "The host signed the verifier nonce. Secret bytes were not returned.", true);
      return;
    }
    setResult("verifier-challenge-result", data.reason || "The host refused to sign the verifier nonce. The check fails closed.", false);
  }).catch(function (error) {
    setResult("verifier-challenge-result", error.message || "The host did not answer. The check fails closed.", false);
  });
}
function emitWrap() {
  if (!selectedInstanceId()) { setResult("wrap-result", "Select a live instance before you present.", false); return; }
  postJson("/present-svid", presentBody()).then(function (payload) {
    var data = readJsonPayload(payload, "The present-svid response is not valid JSON. The check fails closed.");
    if (data.presentation_json && data.certificate_pem) {
      el("presentation-json").value = data.presentation_json;
      el("certificate-pem").value = data.certificate_pem;
      holdPresentAct("svid");
      setResult("wrap-result", "The host emitted the wrap. A new challenge is requested because present spent the first nonce.", true);
      requestChallenge().catch(function () {});
      return;
    }
    setResult("wrap-result", data.reason || "The host refused the wrap. The check fails closed.", false);
  }).catch(function (error) {
    setResult("wrap-result", error.message || "The host did not emit a wrap. The check fails closed.", false);
  });
}
function emitWimse() {
  if (!selectedInstanceId()) { setResult("wimse-result", "Select a live instance before you present.", false); return; }
  postJson("/present-wimse", presentBody()).then(function (payload) {
    var data = readJsonPayload(payload, "The present-wimse response is not valid JSON. The check fails closed.");
    if (data.presentation_json && data.workload_identity_token && data.content_digest) {
      el("wimse-presentation-json").value = data.presentation_json;
      el("workload-identity-token").value = data.workload_identity_token;
      el("content-digest").value = data.content_digest;
      el("wimse-signature-input").value = data.signature_input || "";
      el("wimse-signature").value = data.signature || "";
      holdPresentAct("wimse");
      setResult("wimse-result", "The host emitted the Workload Identity Token. A new challenge is requested because present spent the first nonce.", true);
      requestChallenge().catch(function () {});
      return;
    }
    setResult("wimse-result", data.reason || "The host refused the Workload Identity Token. The check fails closed.", false);
  }).catch(function (error) {
    setResult("wimse-result", error.message || "The host did not emit a Workload Identity Token. The check fails closed.", false);
  });
}
function showDecision(payload) {
  el("decision-body").textContent = payload.text;
  try {
    var data = JSON.parse(payload.text);
    if (data.result === "allowed") {
      setResult("decision-result", "The host allowed the tool action.", true);
      if (data.receipt) { el("act-export-receipt").value = JSON.stringify(data.receipt, null, 2); }
    } else {
      setResult("decision-result", "The host refused the tool action. Death wins when the present is dead.", false);
    }
    el("decision-reason").textContent = data.reason || "The host did not supply a reason sentence.";
  } catch (error) {
    setResult("decision-result", "The host returned a body that is not valid JSON. The check fails closed.", false);
    el("decision-reason").textContent = "";
  }
}
function thisStoreHasLocalLiveInstance() {
  return Boolean(selectedInstanceId());
}
function checkBody(presentationId) {
  var body = {
    presentation_json: el(presentationId).value,
    intent: el("wrap-intent").value,
    audience: el("wrap-audience").value,
    holder_proof: el("holder-proof").value || null,
    challenge_nonce: el("challenge-nonce").value || null,
    on_behalf_of: el("on-behalf-of").value || null
  };
  if (thisStoreHasLocalLiveInstance()) {
    if (!el("holder-proof").value) {
      var holderPath = (el("holder-secret-path").value || "").trim();
      if (holderPath) { body.holder_secret_path = holderPath; }
    }
    addIssuingMemberSecretPath(body);
  }
  return body;
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
function documentedPinPath(document, pinName) {
  var want = String(pinName || "").replace(/^\/+/, "").toLowerCase();
  if (!want) { throw new Error("The well-known check document does not name that operator pin. The check fails closed."); }
  var writeVerbs = ["/birth", "/spawn", "/present-svid", "/present-wimse", "/agent-type", "/kill", "/seal", "/rotate", "/sign-holder-nonce", "/member-two", "/act-export", "/kill-export", "/seal-export", "/previous-key-export"];
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
  if (lastCheckKind === "both") { checkBoth(); return; }
  if (lastCheckKind === "act") { checkThisActOnly(); return; }
  if (lastCheckKind === "wimse") { submitCheckWimse(); return; }
  if (lastCheckKind === "svid") { submitCheckSvid(); return; }
  setResult("decision-result", "Submit a check before you check again. The check fails closed.", false);
}
var heldActs = [];
function holdPresentAct(kind) {
  var instanceId = selectedInstanceId();
  var holderPath = (el("holder-secret-path").value || "").trim();
  var act = { kind: kind, instance_id: instanceId, holder_secret_path: holderPath };
  if (kind === "wimse") {
    act.presentation_json = el("wimse-presentation-json").value;
    act.workload_identity_token = el("workload-identity-token").value;
    act.content_digest = el("content-digest").value;
    act.signature_input = el("wimse-signature-input").value;
    act.signature = el("wimse-signature").value;
  } else {
    act.presentation_json = el("presentation-json").value;
    act.certificate_pem = el("certificate-pem").value;
  }
  var replaced = false;
  for (var i = 0; i < heldActs.length; i++) {
    if (heldActs[i].instance_id === instanceId && heldActs[i].kind === kind) {
      heldActs[i] = act;
      replaced = true;
      break;
    }
  }
  if (!replaced) {
    heldActs.push(act);
    if (heldActs.length > 2) { heldActs.shift(); }
  }
  renderHeldActs();
}
function renderHeldActs() {
  if (!el("held-acts")) { return; }
  if (heldActs.length === 0) {
    el("held-acts").textContent = "No Assertion Act is held on this page.";
    return;
  }
  var lines = [];
  for (var i = 0; i < heldActs.length; i++) {
    lines.push("Act " + (i + 1) + " " + heldActs[i].kind + " instance " + heldActs[i].instance_id + ". Holder path is typed. Secret bytes are not shown.");
  }
  el("held-acts").textContent = lines.join(" ");
}
function runtimeCheckBodyFromAct(act) {
  var hasSvid = Boolean((act.certificate_pem || "").trim());
  var hasWimse = Boolean((act.workload_identity_token || "").trim() || (act.content_digest || "").trim() || (act.signature_input || "").trim() || (act.signature || "").trim());
  if (hasSvid && hasWimse) {
    throw new Error("Do not mix an X.509-SVID wrap with a WIMSE present on the same present row. Completing both checks is Check both. The check fails closed.");
  }
  if (!(act.holder_secret_path || "").trim() && !(act.holder_proof || "").trim()) {
    throw new Error("A holder signature is required. Type a local holder secret path. Secret bytes are not uploaded. The check fails closed.");
  }
  var body = {
    check_base: typedCheckBase(),
    presentation_json: act.presentation_json
  };
  if ((act.holder_proof || "").trim()) { body.holder_proof = act.holder_proof; }
  else { body.holder_secret_path = (act.holder_secret_path || "").trim(); }
  if (act.kind === "wimse" || hasWimse) {
    body.workload_identity_token = act.workload_identity_token;
    body.content_digest = act.content_digest;
    body.signature_input = act.signature_input;
    body.signature = act.signature;
  } else {
    body.certificate_pem = act.certificate_pem;
  }
  return body;
}
function showBothDecisions(first, second) {
  el("decision-body").textContent = first.text + "\n" + second.text;
  try {
    var firstData = JSON.parse(first.text);
    var secondData = JSON.parse(second.text);
    if (first.ok && second.ok && firstData.result === "allowed" && secondData.result === "allowed") {
      setResult("decision-result", "The host allowed both Assertion Acts.", true);
    } else {
      setResult("decision-result", "The host refused the tool action. Check both is ALLOWED only if both allow. Death wins when a present is dead.", false);
    }
    el("decision-reason").textContent = [firstData.reason, secondData.reason].filter(Boolean).join(" ");
  } catch (error) {
    setResult("decision-result", "The host returned a body that is not valid JSON. The check fails closed.", false);
    el("decision-reason").textContent = "";
  }
}
function checkBoth() {
  lastCheckKind = "both";
  if (heldActs.length < 2) {
    setResult("decision-result", "Hold two Assertion Acts before you check both. Present the parent, spawn a child, then present the child. The check fails closed.", false);
    return;
  }
  var base = typedCheckBase();
  var refuse = refuseTypedCheckBase(base);
  if (refuse) { setResult("decision-result", refuse, false); return; }
  var firstBody;
  var secondBody;
  try {
    firstBody = runtimeCheckBodyFromAct(heldActs[0]);
    secondBody = runtimeCheckBodyFromAct(heldActs[1]);
  } catch (error) {
    setResult("decision-result", error.message || "A present row failed closed.", false);
    return;
  }
  postJson("/runtime-check", firstBody).then(function (first) {
    return postJson("/runtime-check", secondBody).then(function (second) {
      showBothDecisions(first, second);
    });
  }).catch(function () {
    setResult("decision-result", "The host did not answer. The check fails closed.", false);
  });
}
function checkThisActOnly() {
  lastCheckKind = "act";
  var raw = (el("check-act-number").value || "").trim();
  var n = parseInt(raw, 10);
  if (!raw || n < 1 || n > heldActs.length) {
    setResult("decision-result", "Name a held act number. Act 0 and a number this page does not hold are refused. The check fails closed.", false);
    return;
  }
  var base = typedCheckBase();
  var refuse = refuseTypedCheckBase(base);
  if (refuse) { setResult("decision-result", refuse, false); return; }
  var body;
  try { body = runtimeCheckBodyFromAct(heldActs[n - 1]); }
  catch (error) {
    setResult("decision-result", error.message || "That present row failed closed.", false);
    return;
  }
  postJson("/runtime-check", body).then(showDecision).catch(function () {
    setResult("decision-result", "The host did not answer. The check fails closed.", false);
  });
}
function killInstance() {
  var instanceId = el("kill-instance-id").value;
  if (!instanceId) { setResult("kill-result", "Select a live instance before you kill.", false); return; }
  var confirmValue = el("kill-confirm").value;
  if (confirmValue !== instanceId) { setResult("kill-result", "Type the same instance identifier to confirm. A wrong selection does not kill. The check fails closed.", false); return; }
  var killBody = { instance_id: instanceId, confirm: confirmValue };
  addIssuingMemberSecretPath(killBody);
  postJson("/kill", killBody).then(function (payload) {
    var data = readJsonPayload(payload, "The kill response is not valid JSON. The check fails closed.");
    if (data.instance_id && data.status === "revoked") {
      carried.instanceId = data.instance_id;
      carried.status = "revoked";
      renderCarried();
      setResult("kill-result", "The host revoked the instance. A following check of a historical wrap is refused. Export the kill bundle below.", true);
      el("kill-confirm").value = "";
      el("kill-export-confirm").value = data.instance_id;
      loadInstances(null, data.instance_id);
      loadStatus();
      return;
    }
    setResult("kill-result", data.reason || "The host refused local kill. The check fails closed.", false);
  }).catch(function (error) {
    setResult("kill-result", error.message || "The host did not kill an instance. The check fails closed.", false);
  });
}
function exportKillBundle() {
  var instanceId = el("kill-export-instance-id").value;
  if (!instanceId) { setResult("kill-export-result", "Select a revoked instance before you export the kill bundle.", false); return; }
  var confirmValue = el("kill-export-confirm").value;
  if (confirmValue !== instanceId) { setResult("kill-export-result", "Type the same instance identifier to confirm. The check fails closed.", false); return; }
  var killExportBody = { instance_id: instanceId, confirm: confirmValue };
  addIssuingMemberSecretPath(killExportBody);
  postJson("/kill-export", killExportBody).then(function (payload) {
    var data = readJsonPayload(payload, "The kill-export response is not valid JSON. The check fails closed.");
    if (data.event && data.proof && data.tree_head) {
      setResult("kill-export-result", "The host returned the public kill artifacts. Secret bytes are not returned.", true);
      el("kill-export-event").textContent = JSON.stringify(data.event, null, 2);
      el("kill-export-proof").textContent = JSON.stringify(data.proof, null, 2);
      el("kill-export-tree-head").textContent = JSON.stringify(data.tree_head, null, 2);
      return;
    }
    setResult("kill-export-result", data.reason || "The host refused kill export. The check fails closed.", false);
  }).catch(function (error) {
    setResult("kill-export-result", error.message || "The host did not export a kill bundle. The check fails closed.", false);
  });
}
function acceptIssuerKey() {
  var publicKeyHex = el("issuer-public-key-hex").value;
  if (!publicKeyHex) { setResult("issuer-accept-result", "Paste a foreign issuer public key hexadecimal before you accept.", false); return; }
  followWellKnownThenPin("issuer-accept", { public_key_hex: publicKeyHex }, "issuer-accept-result", function (payload) {
    var data = readJsonPayload(payload, "The issuer-accept response is not valid JSON. The check fails closed.");
    if (data.public_key_hex) {
      setResult("issuer-accept-result", "This store pinned the foreign issuer public key. Secret bytes were not copied. No member secret was sent.", true);
      return;
    }
    setResult("issuer-accept-result", data.reason || "The host refused issuer accept. The check fails closed.", false);
  });
}
function showNoInstanceRecord(targetId, extraId, extraText) {
  fetch("/instances").then(function (response) { return response.text(); }).then(function (text) {
    try {
      var data = JSON.parse(text);
      el(targetId).textContent = "This store wrote no instance record.\n" + JSON.stringify(data.instances || [], null, 2);
    } catch (error) {
      el(targetId).textContent = "This store wrote no instance record. The instance list did not parse.";
    }
    if (extraId) { el(extraId).textContent = extraText || ""; }
    loadStatus();
  }).catch(function () {
    el(targetId).textContent = "This store wrote no instance record. The host did not return the instance list.";
    if (extraId) { el(extraId).textContent = extraText || ""; }
  });
}
function loadThree(sourceId, eventId, proofId, headId, resultId, label) {
  try {
    var data = parseJsonObject(el(sourceId).value, label);
    if (!data.event || !data.proof || !data.tree_head) {
      setResult(resultId, "The " + label + " must include event, proof, and tree_head. The check fails closed.", false);
      return false;
    }
    el(eventId).value = JSON.stringify(data.event, null, 2);
    el(proofId).value = JSON.stringify(data.proof, null, 2);
    el(headId).value = JSON.stringify(data.tree_head, null, 2);
    setResult(resultId, "The three public artifacts are loaded. Secret bytes are not present.", true);
    return true;
  } catch (error) {
    setResult(resultId, error.message || "The artifacts did not load. The check fails closed.", false);
    return false;
  }
}
function acceptKillBundle() {
  var body;
  try {
    body = { event: parseJsonObject(el("kill-accept-event").value, "event"), proof: parseJsonObject(el("kill-accept-proof").value, "proof"), tree_head: parseJsonObject(el("kill-accept-tree-head").value, "tree_head") };
  } catch (error) {
    setResult("kill-accept-result", error.message || "The three artifacts did not parse. The check fails closed.", false);
    return;
  }
  followWellKnownThenPin("kill-accept", body, "kill-accept-result", function (payload) {
    var data = readJsonPayload(payload, "The kill-accept response is not valid JSON. The check fails closed.");
    if (payload.ok && (data.accepted_killed_instance_ids || data.accepted_killed_capability_ids || data.accepted_revoke_identifiers)) {
      setResult("kill-accept-result", "This store accepted the signed death bundle. This store wrote no instance record. No member secret was sent.", true);
      showNoInstanceRecord("kill-accept-instances", "kill-accept-accepted", JSON.stringify({ accepted_killed_instance_ids: data.accepted_killed_instance_ids || [], accepted_killed_capability_ids: data.accepted_killed_capability_ids || [], accepted_revoke_identifiers: data.accepted_revoke_identifiers || [] }, null, 2));
      return;
    }
    setResult("kill-accept-result", data.reason || "The host refused kill accept. The check fails closed.", false);
  });
}
function acceptSealBundle() {
  var body;
  try {
    body = { event: parseJsonObject(el("seal-accept-event").value, "event"), proof: parseJsonObject(el("seal-accept-proof").value, "proof"), tree_head: parseJsonObject(el("seal-accept-tree-head").value, "tree_head") };
  } catch (error) {
    setResult("seal-accept-result", error.message || "The seal artifacts did not parse. The check fails closed.", false);
    return;
  }
  followWellKnownThenPin("seal-accept", body, "seal-accept-result", function (payload) {
    var data = readJsonPayload(payload, "The seal-accept response is not valid JSON. The check fails closed.");
    if (payload.ok && data.public_key_hex) {
      setResult("seal-accept-result", "This store accepted the seal. Present and act for that issuer pin refuse. This store wrote no instance record. No member secret was sent.", true);
      showNoInstanceRecord("seal-accept-instances", "seal-accept-accepted", JSON.stringify(data, null, 2));
      return;
    }
    setResult("seal-accept-result", data.reason || "The host refused seal accept. The check fails closed.", false);
  });
}
function loadPreviousKeyAccept() {
  try {
    var data = parseJsonObject(el("previous-key-accept-export-json").value, "previous-key-export JSON");
    if (!data.public_key_hex || !data.kill_date) {
      setResult("previous-key-accept-result", "The previous-key-export JSON must include public_key_hex and kill_date. The check fails closed.", false);
      return;
    }
    el("previous-key-accept-public-key").value = data.public_key_hex;
    el("previous-key-accept-kill-date").value = data.kill_date;
    setResult("previous-key-accept-result", "The public artifacts are loaded. Secret bytes are not present.", true);
  } catch (error) {
    setResult("previous-key-accept-result", error.message || "The previous-key-export JSON did not load. The check fails closed.", false);
  }
}
function acceptPreviousKey() {
  followWellKnownThenPin("previous-key-accept", { public_key_hex: el("previous-key-accept-public-key").value, kill_date: el("previous-key-accept-kill-date").value }, "previous-key-accept-result", function (payload) {
    var data = readJsonPayload(payload, "The previous-key-accept response is not valid JSON. The check fails closed.");
    if (payload.ok && data.public_key_hex && data.kill_date) {
      setResult("previous-key-accept-result", "This store accepted the previous issuer key and its kill date. This store wrote no instance record. No member secret was sent.", true);
      showNoInstanceRecord("previous-key-accept-instances");
      return;
    }
    setResult("previous-key-accept-result", data.reason || "The host refused previous-key accept. The check fails closed.", false);
  });
}
function requestSpawnChallenge() {
  var instanceId = el("spawn-parent-instance-id").value;
  if (!instanceId) { setResult("spawn-result", "Select a live parent before you request a challenge.", false); return Promise.reject(new Error("no live parent")); }
  var challengeBody = { instance_id: instanceId };
  addIssuingMemberSecretPath(challengeBody);
  return postJson("/challenge", challengeBody).then(function (payload) {
    var data = readJsonPayload(payload, "The spawn challenge response is not valid JSON. The check fails closed.");
    if (data.challenge_nonce) {
      el("spawn-challenge-nonce").value = data.challenge_nonce;
      setResult("spawn-result", "The host returned a parent challenge nonce.", true);
      return data.challenge_nonce;
    }
    setResult("spawn-result", data.reason || "The host refused the parent challenge. The check fails closed.", false);
    return Promise.reject(new Error("challenge refused"));
  });
}
function spawnChild() {
  var parentInstanceId = el("spawn-parent-instance-id").value;
  if (!parentInstanceId) { setResult("spawn-result", "Select a live parent before you spawn.", false); return; }
  var body = {
    parent_instance_id: parentInstanceId,
    parent_capability_id: el("spawn-parent-capability-id").value || null,
    owner: el("spawn-owner").value || null,
    intent: el("spawn-intent").value || null,
    audience: el("spawn-audience").value || null,
    on_behalf_of: el("spawn-on-behalf-of").value || null,
    holder_secret_path: el("spawn-holder-secret-path").value || null,
    holder_proof: el("spawn-holder-proof").value || null,
    challenge_nonce: el("spawn-challenge-nonce").value || null
  };
  addIssuingMemberSecretPath(body);
  postJson("/spawn", body).then(function (payload) {
    var data = readJsonPayload(payload, "The spawn response is not valid JSON. The check fails closed.");
    if (data.instance_id && data.capability_id && data.holder_secret_path) {
      el("capability-id").value = data.capability_id;
      el("holder-secret-path").value = data.holder_secret_path;
      el("spawn-parent-capability-id").value = data.capability_id;
      el("spawn-holder-secret-path").value = data.holder_secret_path;
      el("spawn-challenge-nonce").value = "";
      el("wrap-intent").value = el("spawn-intent").value;
      el("wrap-audience").value = el("spawn-audience").value;
      el("on-behalf-of").value = el("spawn-on-behalf-of").value;
      setCarriedFromBirth(data.instance_id, data.capability_id, data.holder_secret_path);
      setResult("spawn-result", "The host wrote a narrower child. Assertion Act, Check, and Decommission can run on this child.", true);
      loadInstances(data.instance_id);
      loadStatus();
      return;
    }
    setResult("spawn-result", data.reason || "The host refused spawn. The check fails closed.", false);
  }).catch(function (error) {
    setResult("spawn-result", error.message || "The host did not spawn a child. The check fails closed.", false);
  });
}
function rotateIssuer() {
  var confirmValue = el("rotate-confirm").value;
  if (confirmValue !== "rotate") { setResult("rotate-result", "Type the exact word rotate to confirm. A wrong selection does not rotate. The check fails closed.", false); return; }
  var body = { confirm: confirmValue };
  var afterSeconds = parseInt(el("rotate-kill-after-seconds").value, 10);
  if (afterSeconds) { body.kill_after_seconds = afterSeconds; }
  addIssuingMemberSecretPath(body);
  postJson("/rotate", body).then(function (payload) {
    var data = readJsonPayload(payload, "The rotate response is not valid JSON. The check fails closed.");
    if (payload.ok && data.current_issuer_public_key_hex && data.previous_public_key_hex && data.previous_kill_date) {
      setResult("rotate-result", "The host rotated the issuer. The previous public key keeps a kill date. Secret bytes are not returned.", true);
      el("rotate-confirm").value = "";
      el("rotate-body").textContent = JSON.stringify(data, null, 2);
      loadIssuerPublic();
      loadStatus();
      return;
    }
    setResult("rotate-result", data.reason || "The host refused issuer rotate. The check fails closed.", false);
  }).catch(function (error) {
    setResult("rotate-result", error.message || "The host did not rotate the issuer. The check fails closed.", false);
  });
}
function exportPreviousKey() {
  postJson("/previous-key-export", {}).then(function (payload) {
    var data = readJsonPayload(payload, "The previous-key-export response is not valid JSON. The check fails closed.");
    if (data.public_key_hex && data.kill_date) {
      setResult("previous-key-export-result", "The host returned the public previous-key artifacts. Secret bytes are not returned.", true);
      el("previous-key-export-body").textContent = JSON.stringify(data, null, 2);
      return;
    }
    setResult("previous-key-export-result", data.reason || "The host refused previous-key export. The check fails closed.", false);
  }).catch(function (error) {
    setResult("previous-key-export-result", error.message || "The host did not export a previous issuer key. The check fails closed.", false);
  });
}
function registerMemberTwo() {
  var memberPath = (el("member-two-secret-path").value || "").trim();
  if (!memberPath) { setResult("member-two-result", "Type a local outside path before you register member two.", false); return; }
  postJson("/member-two", { member_secret_path: memberPath }).then(function (payload) {
    var data = readJsonPayload(payload, "The member-two response is not valid JSON. The check fails closed.");
    if (payload.ok && data.public_key_hex) {
      setResult("member-two-result", "The host registered member two. The member public key is shown. Secret bytes are not returned.", true);
      el("member-two-body").textContent = JSON.stringify(data, null, 2);
      return;
    }
    setResult("member-two-result", data.reason || "The host refused member two. The check fails closed.", false);
  }).catch(function (error) {
    setResult("member-two-result", error.message || "The host did not register member two. The check fails closed.", false);
  });
}
function setVerifyThreshold() {
  var confirmValue = el("verify-threshold-confirm").value;
  if (confirmValue !== "verify-threshold") { setResult("verify-threshold-result", "Type the exact word verify-threshold to confirm. The check fails closed.", false); return; }
  var body = { confirm: confirmValue, n: parseInt(el("verify-threshold-n").value, 10) };
  addIssuingMemberSecretPath(body);
  postJson("/set-verify-threshold", body).then(function (payload) {
    var data = readJsonPayload(payload, "The verify-threshold response is not valid JSON. The check fails closed.");
    if (payload.ok && data.verify_threshold_n) {
      setResult("verify-threshold-result", "The host set verify_threshold_n. Secret bytes are not returned.", true);
      el("verify-threshold-confirm").value = "";
      el("verify-threshold-body").textContent = JSON.stringify(data, null, 2);
      loadStatus();
      return;
    }
    setResult("verify-threshold-result", data.reason || "The host refused verify-threshold. The check fails closed.", false);
  }).catch(function (error) {
    setResult("verify-threshold-result", error.message || "The host did not set verify_threshold_n. The check fails closed.", false);
  });
}
function setIssuerThreshold() {
  var confirmValue = el("issuer-threshold-confirm").value;
  if (confirmValue !== "issuer-threshold") { setResult("issuer-threshold-result", "Type the exact word issuer-threshold to confirm. The check fails closed.", false); return; }
  postJson("/set-issuer-threshold", { confirm: confirmValue, n: parseInt(el("issuer-threshold-n").value, 10) }).then(function (payload) {
    var data = readJsonPayload(payload, "The issuer-threshold response is not valid JSON. The check fails closed.");
    if (payload.ok && data.threshold_n) {
      setResult("issuer-threshold-result", "The host set threshold_n. Secret bytes are not returned.", true);
      el("issuer-threshold-confirm").value = "";
      el("issuer-threshold-body").textContent = JSON.stringify(data, null, 2);
      loadStatus();
      return;
    }
    setResult("issuer-threshold-result", data.reason || "The host refused issuer-threshold. The check fails closed.", false);
  }).catch(function (error) {
    setResult("issuer-threshold-result", error.message || "The host did not set threshold_n. The check fails closed.", false);
  });
}
function sealIssuer() {
  var confirmValue = el("seal-confirm").value;
  if (confirmValue !== "seal") { setResult("seal-result", "Type the exact word seal to confirm. A wrong selection does not seal. The check fails closed.", false); return; }
  var afterSeconds = parseInt(el("seal-after-seconds").value, 10);
  if (!afterSeconds || afterSeconds < 1) { setResult("seal-result", "after_seconds must be greater than zero. The check fails closed.", false); return; }
  var body = { confirm: confirmValue, after_seconds: afterSeconds };
  addIssuingMemberSecretPath(body);
  postJson("/seal", body).then(function (payload) {
    var data = readJsonPayload(payload, "The seal response is not valid JSON. The check fails closed.");
    if (payload.ok && data.status === "sealed") {
      setResult("seal-result", "The host sealed the issuer. After remaining life, mint, birth, spawn, present, and check are refused.", true);
      el("seal-confirm").value = "";
      loadStatus();
      return;
    }
    setResult("seal-result", data.reason || "The host refused issuer seal. The check fails closed.", false);
  }).catch(function (error) {
    setResult("seal-result", error.message || "The host did not seal the issuer. The check fails closed.", false);
  });
}
function exportSealBundle() {
  var body = {};
  addIssuingMemberSecretPath(body);
  postJson("/seal-export", body).then(function (payload) {
    var data = readJsonPayload(payload, "The seal-export response is not valid JSON. The check fails closed.");
    if (data.event && data.proof && data.tree_head) {
      setResult("seal-export-result", "The host returned the public seal artifacts. Secret bytes are not returned.", true);
      el("seal-export-event").textContent = JSON.stringify(data.event, null, 2);
      el("seal-export-proof").textContent = JSON.stringify(data.proof, null, 2);
      el("seal-export-tree-head").textContent = JSON.stringify(data.tree_head, null, 2);
      return;
    }
    setResult("seal-export-result", data.reason || "The host refused seal export. The check fails closed.", false);
  }).catch(function (error) {
    setResult("seal-export-result", error.message || "The host did not export a seal bundle. The check fails closed.", false);
  });
}
function exportActBundle() {
  var receipt;
  try { receipt = parseJsonObject(el("act-export-receipt").value, "check receipt"); }
  catch (error) { setResult("act-export-result", error.message || "The check receipt did not parse. The check fails closed.", false); return; }
  var actExportBody = { receipt: receipt };
  addIssuingMemberSecretPath(actExportBody);
  postJson("/act-export", actExportBody).then(function (payload) {
    var data = readJsonPayload(payload, "The act-export response is not valid JSON. The check fails closed.");
    if (data.receipt && data.proof && data.tree_head) {
      setResult("act-export-result", "The host returned the public act artifacts. Secret bytes are not returned.", true);
      el("act-export-receipt-out").textContent = JSON.stringify(data.receipt, null, 2);
      el("act-export-proof").textContent = JSON.stringify(data.proof, null, 2);
      el("act-export-tree-head").textContent = JSON.stringify(data.tree_head, null, 2);
      return;
    }
    setResult("act-export-result", data.reason || "The host refused act export. The check fails closed.", false);
  }).catch(function (error) {
    setResult("act-export-result", error.message || "The host did not export an act bundle. The check fails closed.", false);
  });
}
function loadActAcceptBundle() {
  try {
    var data = parseJsonObject(el("act-accept-export-json").value, "act-export JSON");
    if (!data.receipt || !data.proof || !data.tree_head) {
      setResult("act-accept-result", "The act-export JSON must include receipt, proof, and tree_head. The check fails closed.", false);
      return;
    }
    el("act-accept-receipt").value = JSON.stringify(data.receipt, null, 2);
    el("act-accept-proof").value = JSON.stringify(data.proof, null, 2);
    el("act-accept-tree-head").value = JSON.stringify(data.tree_head, null, 2);
    setResult("act-accept-result", "The three public artifacts are loaded. Secret bytes are not present.", true);
  } catch (error) {
    setResult("act-accept-result", error.message || "The act-export JSON did not load. The check fails closed.", false);
  }
}
function acceptActBundle() {
  var body;
  try {
    body = { receipt: parseJsonObject(el("act-accept-receipt").value, "receipt"), proof: parseJsonObject(el("act-accept-proof").value, "proof"), tree_head: parseJsonObject(el("act-accept-tree-head").value, "tree_head") };
  } catch (error) {
    setResult("act-accept-result", error.message || "The three artifacts did not parse. The check fails closed.", false);
    return;
  }
  followWellKnownThenPin("act-accept", body, "act-accept-result", function (payload) {
    var data = readJsonPayload(payload, "The act-accept response is not valid JSON. The check fails closed.");
    if (payload.ok && data.result === "accepted") {
      setResult("act-accept-result", "This store accepted the signed act bundle. This store wrote no instance record. No member secret was sent.", true);
      showNoInstanceRecord("act-accept-instances");
      return;
    }
    setResult("act-accept-result", data.reason || "The host refused act accept. The check fails closed.", false);
  });
}
el("refresh-status").addEventListener("click", loadStatus);
el("refresh-issuer-public").addEventListener("click", loadIssuerPublic);
el("copy-issuer-public-key").addEventListener("click", copyIssuerPublicKey);
el("refresh-instances").addEventListener("click", function () { loadInstances(); });
el("instance-id").addEventListener("change", function () {
  applySelectedInstanceCapabilities();
  var id = el("instance-id").value;
  carried.instanceId = id;
  carried.status = id ? "live" : "";
  var ids = capabilityIdsFromSelect("instance-id");
  if (ids.length > 0) { carried.capabilityId = ids[0]; }
  if (id && holderPaths[id]) { carried.holderPath = holderPaths[id]; }
  else if (!id) { carried.holderPath = ""; }
  if (id && selectHasValue("kill-instance-id", id)) { el("kill-instance-id").value = id; }
  if (id && selectHasValue("spawn-parent-instance-id", id)) { el("spawn-parent-instance-id").value = id; }
  renderCarried();
});
el("spawn-parent-instance-id").addEventListener("change", function () {
  applySelectedInstanceCapabilities();
  var id = el("spawn-parent-instance-id").value;
  if (id && holderPaths[id]) { el("spawn-holder-secret-path").value = holderPaths[id]; }
});
el("agent-type-id").addEventListener("change", applySelectedAgentTypeIntents);
el("add-agent-type").addEventListener("click", addAgentType);
el("birth-instance").addEventListener("click", birthInstance);
el("request-challenge").addEventListener("click", function () { requestChallenge().catch(function () {}); });
el("request-verifier-challenge").addEventListener("click", requestVerifierChallenge);
el("sign-verifier-nonce").addEventListener("click", signVerifierNonce);
el("emit-wrap").addEventListener("click", emitWrap);
el("emit-wimse").addEventListener("click", emitWimse);
el("submit-check-svid").addEventListener("click", submitCheckSvid);
el("submit-check-wimse").addEventListener("click", submitCheckWimse);
el("check-again").addEventListener("click", checkAgain);
el("check-both").addEventListener("click", checkBoth);
el("check-this-act").addEventListener("click", checkThisActOnly);
el("kill-instance").addEventListener("click", killInstance);
el("export-kill-bundle").addEventListener("click", exportKillBundle);
el("accept-issuer-key").addEventListener("click", acceptIssuerKey);
el("load-kill-accept-bundle").addEventListener("click", function () { loadThree("kill-accept-export-json", "kill-accept-event", "kill-accept-proof", "kill-accept-tree-head", "kill-accept-result", "kill-export JSON"); });
el("accept-kill-bundle").addEventListener("click", acceptKillBundle);
el("load-seal-accept-bundle").addEventListener("click", function () { loadThree("seal-accept-export-json", "seal-accept-event", "seal-accept-proof", "seal-accept-tree-head", "seal-accept-result", "seal-export JSON"); });
el("accept-seal-bundle").addEventListener("click", acceptSealBundle);
el("load-previous-key-accept").addEventListener("click", loadPreviousKeyAccept);
el("accept-previous-key").addEventListener("click", acceptPreviousKey);
el("request-spawn-challenge").addEventListener("click", function () { requestSpawnChallenge().catch(function () {}); });
el("spawn-child").addEventListener("click", spawnChild);
el("rotate-issuer").addEventListener("click", rotateIssuer);
el("export-previous-key").addEventListener("click", exportPreviousKey);
el("register-member-two").addEventListener("click", registerMemberTwo);
el("set-verify-threshold").addEventListener("click", setVerifyThreshold);
el("set-issuer-threshold").addEventListener("click", setIssuerThreshold);
el("seal-issuer").addEventListener("click", sealIssuer);
el("export-seal-bundle").addEventListener("click", exportSealBundle);
el("export-act-bundle").addEventListener("click", exportActBundle);
el("load-act-accept-bundle").addEventListener("click", loadActAcceptBundle);
el("accept-act-bundle").addEventListener("click", acceptActBundle);
if (el("check-base") && !el("check-base").value) { el("check-base").value = location.origin; }
renderCarried();
loadStatus();
loadIssuerPublic();
loadAgentTypes();
loadInstances();
</script>
</main>
</body>
</html>
"##;

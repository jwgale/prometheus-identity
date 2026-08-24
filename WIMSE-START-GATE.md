# WIMSE start gate, 20 August 2026

Prometheus laboratory only. Research only. This page is not Prometheus code. This page does not clone Sanctum. This page does not start SPIRE. Consensus unused (monthly cap, reset 2026-09-01). Specs via Exa (user-exa-keyed) and IETF text.

Question: may Prometheus start a WIMSE presenter?

VISION.md section 7 start condition. All three must be true.

1. Present construction is closed.
2. WIMSE drafts have a stable workload identifier.
3. WIMSE drafts have an HTTP binding that can carry a Prometheus present without putting the instance identifier into a distinguished name or a DID.

WIMSE is a second on-ramp artifact. WIMSE is not a sixth identity record. The instance identifier must not become a distinguished name or a DID.

## Verdict

**START.**

Condition 1 is true. Present construction is closed. VISION.md records this close: X.509-SVID wrap, host consume, kill refuse, envelope-key bind, judge walk yes.

Condition 2 is true. The working group has a dedicated identifier draft. The identifier is a Uniform Resource Identifier. The draft says that identifier is designed to be stable. See below.

Condition 3 is true. Two HTTP bindings exist. The HTTP Message Signatures binding can carry the present bytes as the request body. Identity sits in a JSON Web Token subject or in one Uniform Resource Identifier subject alternative name. The drafts do not force a distinguished name. The drafts do not mention a DID.

## Smallest on-ramp

Wrap the existing present document. Do not invent a sixth record. Do not invent a new inode name.

1. Keep `present --format x509-svid` as the first on-ramp. Do not replace it.
2. Add one HTTP presenter that posts the same present bytes as the request body.
3. Put a Workload Identity Token in the `Workload-Identity-Token` header. See draft-ietf-wimse-workload-creds-02 section 5.1.1.
4. Sign that request with HTTP Message Signatures. See draft-ietf-wimse-http-signature-06. The sender MUST include `Content-Digest`. The receiver MUST verify `Content-Digest`. That digest binds the present bytes.
5. Set the token `sub` claim to a type-level or present-hash Uniform Resource Identifier. Match the laboratory X.509-SVID rule: `wimse://<lab-trust-domain>/present/<sha256hex-of-present-bytes>` or a type path. The instance identifier stays inside the present bytes only.
6. Bind proof of possession to the same envelope public key that the present already names. Do not mint a second identity key.
7. Keep kill on the present path. Short token life is not kill.

Do not start these in the first on-ramp:

- Mutual Transport Layer Security and the Workload Identity Certificate. That path is a second X.509 wrap. The laboratory already has one.
- The Workload Proof Token. That token does not bind the request body. That draft expires 3 September 2026.
- A DID. The drafts do not define one.
- The instance identifier in `sub`, in a Uniform Resource Identifier path, or in a distinguished name.
- SPIRE as issuer. SPIRE start conditions stay in VISION.md section 7.

## Current working-group documents

Checked on 20 August 2026 from https://datatracker.ietf.org/group/wimse/documents/ and each document page. No WIMSE RFC exists. No protocol draft is in Working Group Last Call.

| Draft | Date | Status | Role |
|---|---|---|---|
| draft-ietf-wimse-arch-08 | 6 July 2026 | Internet-Draft exists. Working Group Document. Intended status none. Expires 7 January 2027. | Architecture. Informational. |
| draft-ietf-wimse-identifier-03 | 6 July 2026 | Internet-Draft exists. Working Group Document. Standards Track. Intended RFC status none. Expires 7 January 2027. | Workload identifier. |
| draft-ietf-wimse-workload-creds-02 | 2 July 2026 | Internet-Draft exists. Working Group Document. Standards Track. Intended RFC status none. Expires 3 January 2027. | Token and certificate formats. |
| draft-ietf-wimse-http-signature-06 | 4 August 2026 | Internet-Draft exists. Working Group Document. Standards Track. Intended RFC status none. Expires 5 February 2027. | HTTP binding with message signatures. Replaces draft-ietf-wimse-s2s-protocol. |
| draft-ietf-wimse-wpt-01 | 2 March 2026 | Internet-Draft exists. Working Group Document. Standards Track. Intended RFC status none. Expires 3 September 2026. | Second HTTP binding. Proof token. |
| draft-ietf-wimse-mutual-tls-02 | 6 July 2026 | Internet-Draft exists. Working Group Document. Standards Track. Intended RFC status none. Expires 7 January 2027. | Transport-layer X.509 mutual TLS. |
| draft-ietf-wimse-workload-identity-practices-05 | 30 June 2026 (page updated 4 August 2026) | Submitted to IESG for Publication. Area Director Evaluation: revised Internet-Draft needed. Informational. Expires 1 January 2027. | Existing platform practices. Not the presenter. |

Related individual Internet-Drafts exist (attestation, agent identity, execution-context tokens, condition-bounded credentials). They are not working-group documents. They do not change this gate.

The working group is active. Chairs: Justin Richer, Pieter Kasselman. Area Director: Charles Eckel.

## What the workload identifier looks like

Source: draft-ietf-wimse-identifier-03.

The Workload Identifier is an absolute Uniform Resource Identifier. The authority component is the trust domain. The identifier MUST NOT contain a query, a fragment, user information, or a port.

The scheme is not locked. The draft allows `spiffe` and defines `wimse`:

```
wimse://<trust-domain>/<path>
```

Examples from the draft:

```
wimse://trust.example.com/service/payment
wimse://trust.example.com/service/payment/instance/1234
wimse://prod.corp.example/workload/89a6ec51-f877-44c0-9501-b213597f2d1d
spiffe://prod.trust.domain/foo-service/sha256/<hex>
```

Section 4.5 says identifiers are intended to be stable over time. An issuer SHOULD NOT reassign an identifier to a different workload. Many instances MAY share one identifier when they are the same logical workload.

The identifier MAY name a logical workload. The identifier MAY name one instance. That choice is trust-domain policy. The draft does not force the instance identifier into the name. Prometheus MUST refuse that choice. Use a type path or the present-hash path. Do not put the instance Unique Lexicographically Sortable Identifier in the path.

The identifier is not a DID. The word DID does not appear in the working-group drafts that this page checked.

The identifier is not a distinguished name. draft-ietf-wimse-workload-creds-02 section 4 and section 6.1 put the one identifier in:

- Workload Identity Token: the `sub` claim.
- Workload Identity Certificate: exactly one Uniform Resource Identifier subject alternative name.

Only that Uniform Resource Identifier is the WIMSE identity. Other name types MAY exist. They are not the identity.

Condition 2 passes because the drafts now name this identifier, give it a Uniform Resource Identifier form, and say it is stable. Condition 2 does not wait for Working Group Last Call or for an RFC. VISION.md section 7 asks for a stable identifier in the drafts, not for IESG publication. The remaining flux is scheme choice and path policy. The smallest on-ramp locks both: `wimse` scheme, present-hash or type path, no instance.

## HTTP binding and the present document

Two application-layer HTTP bindings exist. One transport-layer binding exists.

### Binding A. HTTP Message Signatures (use this)

draft-ietf-wimse-http-signature-06. Date 4 August 2026.

The sender puts a Workload Identity Token in `Workload-Identity-Token`. The sender signs `@method`, `@request-target`, and the token header. If a body exists, the sender MUST send `Content-Digest` and MUST sign it. The receiver MUST verify that digest.

That is the carry for a Prometheus present. The present bytes are the body. The digest is the bind. The instance identifier is not copied into a name.

Signature life is short (minutes). Token life is longer (hours). Neither is kill.

### Binding B. Workload Proof Token (do not start)

draft-ietf-wimse-wpt-01. Date 2 March 2026. Expires 3 September 2026.

The sender puts the token in `Workload-Proof-Token`. The token is a signed JSON Web Token. Required claims include `aud`, `exp`, `jti`, and `wth` (hash of the Workload Identity Token). Optional hashes bind an access token, a transaction token, or other header tokens.

The proof token does not bind the request body. A present in the body would not be covered. This binding fails condition 3 as a carry for the present. This draft is also near expiry. Do not start it.

### Binding C. Mutual TLS (do not start as the WIMSE on-ramp)

draft-ietf-wimse-mutual-tls-02. Date 6 July 2026.

Identity is the Uniform Resource Identifier subject alternative name. The draft does not make the distinguished name the identity. This path is still a second certificate wrap. The laboratory already closed that wrap as X.509-SVID. Starting it again would open a second presenter format in parallel. VISION.md section 5 forbids that during present construction. Present construction is closed, but the smallest new on-ramp is the HTTP token path, not a second certificate.

### Token formats

Workload Identity Token (draft-ietf-wimse-workload-creds-02):

- Typed JSON Web Token. Header `typ` is `wit+jwt`.
- Required claims: `sub` (one Workload Identifier), `exp`, `cnf.jwk` (public key).
- `iss` is recommended. `jti` is optional.
- The token is not a bearer token. The holder MUST prove possession of the key in `cnf`.
- HTTP field name: `Workload-Identity-Token`.

Workload Identity Certificate:

- X.509. One Uniform Resource Identifier subject alternative name. That name is the identity.
- Distinguished name is not the identity.

The drafts do not force a DID. The drafts do not force a distinguished name as identity.

Condition 3 passes on binding A.

## Gate table

| Condition | Result | Why |
|---|---|---|
| 1. Present construction closed | Pass | VISION.md rungs 4 through 6 and 8 through 19 are closed. User brief confirms wrap, consume, kill refuse, envelope-key bind, judge walk yes. |
| 2. Stable workload identifier | Pass | draft-ietf-wimse-identifier-03 defines a Uniform Resource Identifier. Section 4.5 says it is stable. Scheme `wimse` is defined. Granularity MAY be instance; laboratory MUST not use that option. Not a DID. Not a distinguished name. |
| 3. HTTP binding that can carry the present without distinguished name or DID | Pass | draft-ietf-wimse-http-signature-06 signs `Content-Digest` of the body. Identity is `sub` or one Uniform Resource Identifier subject alternative name. |

## What not to copy

1. Instance Unique Lexicographically Sortable Identifier as `sub`, as Uniform Resource Identifier path, or as distinguished name.
2. A DID.
3. A sixth identity record.
4. Mutual TLS as the first WIMSE presenter.
5. Workload Proof Token as the first WIMSE presenter.
6. Short token life as kill.
7. SPIRE as issuer of instance names.
8. Sanctum, Cyera product, Oasis, or Trawsome.
9. A public listener.
10. Private claims on the Workload Identity Token as a second identity.

## Sources

- https://datatracker.ietf.org/group/wimse/documents/
- https://datatracker.ietf.org/wg/wimse/about/
- https://datatracker.ietf.org/doc/draft-ietf-wimse-identifier/
- https://www.ietf.org/archive/id/draft-ietf-wimse-identifier-03.txt
- https://datatracker.ietf.org/doc/draft-ietf-wimse-http-signature/
- https://www.ietf.org/archive/id/draft-ietf-wimse-http-signature-06.txt
- https://datatracker.ietf.org/doc/draft-ietf-wimse-workload-creds/
- https://www.ietf.org/archive/id/draft-ietf-wimse-workload-creds-02.txt
- https://datatracker.ietf.org/doc/draft-ietf-wimse-wpt/
- https://www.ietf.org/archive/id/draft-ietf-wimse-wpt-01.txt
- https://datatracker.ietf.org/doc/draft-ietf-wimse-mutual-tls/
- https://www.ietf.org/archive/id/draft-ietf-wimse-mutual-tls-02.txt
- https://datatracker.ietf.org/doc/draft-ietf-wimse-arch/
- https://datatracker.ietf.org/doc/draft-ietf-wimse-workload-identity-practices/
- /home/jason/Projects/Prometheus/VISION.md section 7 (read only)

Consensus: unused. No Sanctum claims. Ubuntu Prometheus tree not edited.

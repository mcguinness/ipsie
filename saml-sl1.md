# SAML 2.0 Web SSO – Constrained Interoperability Profile

> **Status:** Draft (informative + normative sections called out below)
>
> **Scope:** A deliberately constrained SAML 2.0 Web SSO profile designed to mirror OpenID Connect (OIDC) behavior **where possible** while remaining **SAML‑first**. Requirements are expressed in SAML terms; OIDC is referenced only for orientation in Appendix A.

---

## 1. Abstract (Informative)

This profile narrows the SAML 2.0 Web SSO feature set to ease interop with OIDC‑centric RPs while **staying 100% XML/SAML**. It:

* Uses **HTTP‑Redirect** for requests and **HTTP‑POST** for responses (success and error).
* Requires **signed Responses** and **signed Assertions**; allows **unsigned AuthnRequests** if the ACS is pre‑registered.
* Standardizes on **XML metadata** for discovery and keys; **multiple signing keys SHOULD** be published concurrently to enable safe rotation.
* Treats `Subject/NameID` as the canonical subject; requires OASIS **Subject Identifier Attributes** (`subject-id` or `pairwise-id`).
* Minimizes profile attributes to **LDAP names**: `mail`, `givenName`, `sn`, `displayName`.
* Adds precise processing rules for correlation, freshness, passive behavior, and errors.

---

## 2. Notation & Conformance (Normative)

* **MUST/SHOULD/MAY** are per RFC 2119.
* Unless stated otherwise, requirements apply to both IdPs and RPs (SPs in SAML).
* “RP” and “SP” are synonymous here; we prefer **SP** in normative text.

---

## 3. Goals (Informative)

* Tighten SAML to predictable, widely‑implemented subsets.
* Encourage key discovery, rotation, and robust metadata usage.
* Make subject identifiers consistent and privacy‑preserving.
* Keep attributes simple and LDAP‑named.

---

<a id="sec-5-1"></a>

## 5. Metadata, Discovery, and Keys (Normative)

### 5.1. HTTP‑Fetchable XML Metadata

* IdPs and SPs **MUST** publish/consume SAML metadata over HTTPS.
* Implementations **MUST** support metadata rooted at either **`<EntityDescriptor>`** or **`<EntitiesDescriptor>`**.

<a id="sec-5-2"></a>

### 5.2. Key Discovery and Rotation (XML‑Only)

* Signing keys **MUST** be discoverable via `<KeyDescriptor use="signing">` in metadata.
* **Multiple signing keys SHOULD** be present simultaneously to enable **pre‑publication** and **grace periods** during rotation.
* Relying parties **MUST** honor `validUntil`/`cacheDuration` and **SHOULD** re‑fetch on unknown‑key signature failures.
* This profile is **XML only**; non‑XML keying mechanisms are out of scope.

### 5.3. Certificate Material and Key Sizes

* Non‑key X.509 fields are not constrained here. Suggested practices: use **long‑lived, self‑signed**, not expired, and **avoid MD5/SHA‑1** certificate signatures.
* **RSA** keys **MUST** be ≥ 2048 bits (**3072** RECOMMENDED). **EC** keys **MUST** be ≥ 256 bits.
* IdP metadata **MUST** include at least one signing certificate (`<KeyDescriptor use="signing">` or no `use`).

---

<a id="sec-6"></a>

## 6. Subject Identifiers (Normative)

### 6.1. Core Requirements

* Every successful Assertion’s `<saml:Subject>` **MUST** contain `<saml:NameID>`.
* For broad interop, `<saml:NameID>` **SHOULD** use `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent`.
* The value of `<saml:NameID>` **SHOULD** be **equivalent** to the value emitted in the Subject Identifier Attribute(s) of §6.2 to keep a single notion of the subject.

### 6.2. Subject Identifier Attributes (OASIS CS01 Conformance)

IdPs and SPs **MUST** conform to **SAML V2.0 Subject Identifier Attributes Profile (CS01)** and **MUST include one or both** of:

* **`urn:oasis:names:tc:SAML:attribute:subject-id`** — stable across SPs.
* **`urn:oasis:names:tc:SAML:attribute:pairwise-id`** — unique per SP.

**Encoding:** `NameFormat` **MUST** be `urn:oasis:names:tc:SAML:2.0:attrname-format:uri`; each Attribute has **exactly one** `xs:string` value.

<a id="sec-6-3"></a>

### 6.3. Pairwise and Public Models

* **Public** model: IdP assigns the same ID to all SPs → **MUST** include `subject-id`.
* **Pairwise** model: per‑SP unique ID → **MUST** include `pairwise-id`.
* If both are present, SPs **SHOULD** prefer `pairwise-id` unless policy requires cross‑SP correlation.

<a id="sec-6-4"></a>

### 6.4. Scope Filtering (Optional)

* IdPs **MAY** scope or filter identifier release by policy; any such indication **MUST** be honored by SPs.

<a id="sec-6-5"></a>

### 6.5. RP Expression of Identifier Requirements (Metadata)

* SPs **MUST** declare identifier expectations via `md:Extensions/mdattr:EntityAttributes` (e.g., require `pairwise-id`, accept `subject-id`).

---

<a id="sec-7"></a>

## 7. Attributes (User Profile) (Normative)

### 7.1. Emission Requirements (IdP)

* IdPs **MUST emit** user profile attributes using LDAP canonical names.
* Attributes are **flat strings** (`xs:string`) with simple text content (no nested XML, no `xsi:type`).

### 7.2. Standard Attribute Set (LDAP Canonical)

Only the following attributes are defined by this profile:

| LDAP Name     | Description                                                       |
| ------------- | ----------------------------------------------------------------- |
| `mail`        | Primary email address.                                            |
| `givenName`   | First/given name.                                                 |
| `sn`          | Surname/family name.                                              |
| `displayName` | Preferred display name; MAY equal `givenName + sn` or user label. |

**Non‑normative example**

```xml
<AttributeStatement>
  <Attribute Name="mail"><AttributeValue>ava@example.com</AttributeValue></Attribute>
  <Attribute Name="givenName"><AttributeValue>Ava</AttributeValue></Attribute>
  <Attribute Name="sn"><AttributeValue>Nguyen</AttributeValue></Attribute>
  <Attribute Name="displayName"><AttributeValue>Ava Nguyen</AttributeValue></Attribute>
</AttributeStatement>
```

### 7.3. Receive‑Side Interoperability (Parsing)

* SPs **MUST** accept arbitrary `Attribute@Name` (string) and `NameFormat` (anyURI).
* `FriendlyName` is descriptive only; **MUST NOT** be used for comparisons/logic.
* `AttributeValue` simple text **MUST** be accepted; complex content is OPTIONAL.
* Common aliases accepted on ingest (informative):

  * `mail` ⇢ `email`, `emailAddress`, `userPrincipalName`
  * `givenName` ⇢ `firstName`, `gn`
  * `sn` ⇢ `surname`, `lastName`, `familyName`
  * `displayName` ⇢ `name`, `cn`

---

<a id="sec-9-1"></a>

## 9. Bindings and Messages (Normative)

### 9.1. Request Binding (SP → IdP)

* **MUST** use **HTTP‑Redirect** for `AuthnRequest`.
* **Unsigned requests allowed**: if the ACS URL is **pre‑registered** in SP metadata (§9.1.1), the `AuthnRequest` **NEED NOT** be signed. If signed, IdP **MAY** validate.
* `Issuer` **MUST** equal the SP entityID.
* **Receiver tolerance**: When processing an `AuthnRequest`, IdPs **MAY ignore** `Consent`, `Conditions`, `Destination`, and `ProviderName`. Security checks elsewhere still apply.

<a id="sec-9-1-1"></a>

#### 9.1.1. ACS URL Registration (Redirect‑URI Analogue)

* SP metadata **MUST** register one or more ACS endpoints (binding + URL). IdPs **MUST** enforce that `AssertionConsumerServiceURL` (if present) equals a registered location; else reject.
* Pre‑registered ACS enables **unsigned** AuthnRequests similar to OIDC redirect URI registration.

<a id="sec-9-2"></a>

### 9.2. Response Binding (IdP → SP)

* **MUST** use **HTTP‑POST** for **success and error** responses.
* The `Response` **MUST** be **signed**; the enclosed `Assertion` **MUST** also be **signed**.
* `Recipient`/`Destination` **MUST** equal the registered ACS.

**SubjectConfirmation (Bearer‑only)**

* Only **Bearer** assertions are supported. Every `SubjectConfirmation` **MUST** have `Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"` and include `SubjectConfirmationData` with `Recipient`, `NotOnOrAfter`, and (for RP‑initiated login) `InResponseTo`.
* Assertions with other methods **MUST** be rejected.

**Correlation (RP‑initiated login)**

* `Response@InResponseTo` **MUST** equal the initiating `AuthnRequest@ID`.
* Each Bearer `SubjectConfirmationData@InResponseTo` **MUST** equal that same ID.
* SPs **MUST** verify correlation and reject unmatched responses.

**Non‑normative example**

```xml
<samlp:AuthnRequest ID="_req123" .../>
<samlp:Response InResponseTo="_req123" ...>
  <saml:Assertion ...>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">A1B2C3...</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData InResponseTo="_req123" Recipient="https://rp.example.com/saml/acs" NotOnOrAfter="..."/>
      </saml:SubjectConfirmation>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>
```

### 9.3. Encryption

* Assertion encryption is **OPTIONAL**; if used, publish an encryption key via `<KeyDescriptor use="encryption">`.

<a id="sec-9-4"></a>

### 9.4. Error Responses (SAML‑First; Informative OIDC Mapping)

All errors **MUST** be POSTed to the registered ACS with a signed `Response` lacking an `Assertion`.

**Canonical SAML errors and mapping to OpenID Connect (informative)**

| SAML StatusCode (Top) | SAML StatusCode (Secondary)                                                                                        | When to use                                        | OIDC mapping (if any)                        |
| --------------------- | ------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------- | -------------------------------------------- |
| `Requester`           | `RequestUnsupported` / `UnsupportedBinding` / `RequestVersionTooLow/TooHigh/Deprecated` / `InvalidAttrNameOrValue` | Malformed/unsupported request, binding, or version | `invalid_request`                            |
| `Requester`           | `RequestDenied`                                                                                                    | SP unauthorized or policy deny                     | `unauthorized_client` or `access_denied`     |
| `Requester`           | `NoAuthnContext`                                                                                                   | Required context cannot be met                     | No exact equivalent (often `access_denied`)  |
| `Requester`           | `UnknownPrincipal`                                                                                                 | Unknown/disabled SP or untrusted issuer            | `invalid_client`                             |
| `Responder`           | *(none)*                                                                                                           | IdP internal error                                 | `server_error`                               |
| `Responder`           | *(none)*                                                                                                           | IdP temporarily unavailable                        | `temporarily_unavailable`                    |
| `Responder`           | `NoPassive`                                                                                                        | `IsPassive=true` but interaction needed            | `login_required` / `interaction_required`    |
| `Responder`           | `AuthnFailed`                                                                                                      | User authentication failed                         | No single equivalent (often `access_denied`) |

---

## 10. Authentication Semantics (Normative)

<a id="sec-10-1"></a>

### 10.1. Requested Authentication Context

* SPs **MUST** request required auth strength using `RequestedAuthnContext` with `Comparison="exact"` and one or more `AuthnContextClassRef` URIs.
* IdPs **MUST** return the **achieved** class in `AuthnContextClassRef`.

<a id="sec-10-2"></a>

### 10.2. Forced Re‑authentication

* To force re‑auth, SPs **MUST** set `ForceAuthn="true"` on `AuthnRequest` (analogous to `prompt=login`).

<a id="sec-10-3"></a>

### 10.3. Freshness

* SPs **SHOULD** evaluate freshness as `now() − AuthnInstant ≤ policy_freshness policy + skew`, where **policy_freshness policy** is deployment‑defined and **skew** accounts for clock drift (RECOMMENDED default **±120s**).

### 10.5. Example AuthnRequest (Unsigned; ACS pre‑registered)

````xml
<samlp:AuthnRequest ID="_a1b2c3" Version="2.0" IssueInstant="2025-10-21T19:30:00Z"
  Destination="https://idp.example.com/SAML2/SSO/Redirect"
  AssertionConsumerServiceURL="https://sp.example.com/saml/acs"
  ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
  ForceAuthn="true">
  <saml:Issuer>https://sp.example.com/metadata</saml:Issuer>
  <!-- NameIDPolicy intentionally omitted per §10.7 -->
  <samlp:RequestedAuthnContext Comparison="exact">
    <saml:AuthnContextClassRef>urn:example:acr:aal2</saml:AuthnContextClassRef>
  </samlp:RequestedAuthnContext>
</samlp:AuthnRequest>
``` Example AuthnRequest (Unsigned; ACS pre‑registered)
```xml
<samlp:AuthnRequest ID="_a1b2c3" Version="2.0" IssueInstant="2025-10-21T19:30:00Z"
  Destination="https://idp.example.com/SAML2/SSO/Redirect"
  AssertionConsumerServiceURL="https://sp.example.com/saml/acs"
  ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
  ForceAuthn="true">
  <saml:Issuer>https://sp.example.com/metadata</saml:Issuer>
  <!-- NameIDPolicy intentionally omitted per §10.7 -->
  <samlp:RequestedAuthnContext Comparison="exact">
    <saml:AuthnContextClassRef>urn:example:acr:aal2</saml:AuthnContextClassRef>
  </samlp:RequestedAuthnContext>
</samlp:AuthnRequest>
````

### 10.6. Passive Requests (`IsPassive`)

* IdPs **MUST** support `IsPassive` in `AuthnRequest` per SAML2Core. With `IsPassive="true"`, no user interaction is permitted: success only if an existing session satisfies the request; else respond `Responder`→`NoPassive`.

### 10.7. NameIDPolicy Requirements

* `AuthnRequest` **MUST** either **omit** `<NameIDPolicy>` (**RECOMMENDED**) **or** include `<NameIDPolicy AllowCreate="true">` **without** a `Format` attribute.

<a id="sec-10-8"></a>

### 10.8. Authentication Statement (Mandatory)

* Successful Assertions **MUST** include `<saml:AuthnStatement>` with:

  * `AuthnInstant` (time of end‑user auth), and
  * `AuthnContext` containing at least one `AuthnContextClassRef` (the **achieved** class).
* `SessionIndex` **MAY** be included for logout correlation.
* `SessionNotOnOrAfter` **MAY** be included. If present, the SP **MUST** treat it as a hard expiry and **at or before** that timestamp **redirect the user to the IdP** to extend (fresh response) or close the session; the SP **MUST NOT** treat the session as valid beyond that time without a round‑trip to the IdP.
* Freshness processing: see §10.3 (age + skew guidance).

<a id="sec-10-9"></a>

### 10.9. Assertion Structure (Success Responses)

For `StatusCode=Success`, the `Response` **MUST** contain **exactly one** `Assertion` with:

* **exactly one** `Subject`;
* **exactly one** `AuthnStatement` (per §10.8);
* **exactly one** `AttributeStatement` (per §7).
  Other statement types (e.g., `AuthzDecisionStatement`) are **not permitted** in success responses.

### 10.10. Authentication Method Reference (AMR) Attribute (Mandatory)

* Identity Providers **MUST** emit a SAML Attribute named **`https://openid.net/ipsie/amr`** conveying the set of **Authentication Method References (AMR)** that were actually verified for the end‑user in producing the assertion.
* **Value syntax:** flat **`xs:string`** tokens taken from the **OAuth 2.0 AMR values** registry (e.g., `pwd`, `otp`, `sms`, `mfa`, `hwk`, etc.).
* **Cardinality:** to express multiple AMRs, the IdP **MUST repeat** the `<saml:Attribute Name="https://openid.net/ipsie/amr">` element, with **one** `<saml:AttributeValue>` per element. Do **not** use complex XML.
* **Placement:** AMR values **MUST** be included in the single `AttributeStatement` required by §10.9 and generated in the same Assertion that contains the `AuthnStatement`.
* **Processing (SP):** Relying Parties **MUST** be able to consume this attribute and may enforce local policy based on the presence of specific AMR tokens.
* **Relationship to OIDC:** Informatively corresponds to the OIDC `amr` claim; this profile expresses it as a SAML Attribute with the exact `Name` URI above.

**Non‑normative example (multiple AMRs)**

```xml
<saml:AttributeStatement>
  <!-- Profile attributes (mail/givenName/sn/displayName) -->
  <saml:Attribute Name="mail"><saml:AttributeValue>ava@example.com</saml:AttributeValue></saml:Attribute>
  <saml:Attribute Name="givenName"><saml:AttributeValue>Ava</saml:AttributeValue></saml:Attribute>
  <saml:Attribute Name="sn"><saml:AttributeValue>Nguyen</saml:AttributeValue></saml:Attribute>
  <saml:Attribute Name="displayName"><saml:AttributeValue>Ava Nguyen</saml:AttributeValue></saml:Attribute>
  <!-- AMR values (repeat the Attribute for each token) -->
  <saml:Attribute Name="https://openid.net/ipsie/amr"><saml:AttributeValue>pwd</saml:AttributeValue></saml:Attribute>
  <saml:Attribute Name="https://openid.net/ipsie/amr"><saml:AttributeValue>otp</saml:AttributeValue></saml:Attribute>
</saml:AttributeStatement>
```

---

## 11. Security Considerations (Informative)

* Limit clock skew (default ±2 minutes). Enforce one‑time use of assertion IDs.
* Prefer pairwise identifiers for privacy where feasible.

## 12. Privacy Considerations (Informative)

* Minimize attribute release; avoid sensitive attributes unless necessary and consented.

## 13. IANA / Well‑Known (Informative)

* Non‑standard suggestion: `/.well-known/saml-metadata` as a stable human‑guessable location (registration out of scope).

## 14. Interoperability Guidance (Informative)

* XML is authoritative; non‑XML keying is out of scope.
* Keep ACS URLs stable; use entityID as sole Audience.

## 15. Cryptographic Algorithms (Normative)

**Digest algorithms (XML Signature)** — Implementations **MUST** support:

* `http://www.w3.org/2001/04/xmlenc#sha256`

**Signature algorithms (XML Signature)** — Implementations **MUST** support:

* `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`

**Additional signature algorithms (XML Signature)** — Implementations **SHOULD** support:

* `http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256`

**Block encryption (XML Encryption)** — Implementations **SHOULD** support:

* `http://www.w3.org/2009/xmlenc11#aes128-gcm`
* `http://www.w3.org/2009/xmlenc11#aes256-gcm`

**Backwards‑compatibility block encryption (XML Encryption)** — Implementations **MAY** support (legacy only):

* `http://www.w3.org/2001/04/xmlenc#aes128-cbc`
* `http://www.w3.org/2001/04/xmlenc#aes256-cbc`

**Key transport (XML Encryption)** — Implementations **MUST** support:

* `http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p`
* `http://www.w3.org/2009/xmlenc11#rsa-oaep`
* DigestMethod support for RSA‑OAEP: `http://www.w3.org/2001/04/xmlenc#sha256` and `http://www.w3.org/2000/09/xmldsig#sha1`.
* Default MGF1 with SHA‑1 for `xmlenc11#rsa-oaep` **MUST** be supported.

**Deny/disable list (configurable)** — Implementations **MUST** be able to disable:

* Digest: `http://www.w3.org/2001/04/xmldsig-more#md5`
* Signature: `http://www.w3.org/2001/04/xmldsig-more#rsa-md5`
* Key Transport: `http://www.w3.org/2001/04/xmlenc#rsa-1_5`

---

## 16. References (Informative)

* **SAML2Core**, **SAML2Meta**, **SAML Bindings**, **SAML Profiles** (OASIS)
* **SAML V2.0 Subject Identifier Attributes Profile** (OASIS CS01)
* **XML Signature** (W3C), **XML Encryption** (W3C), **RFC 4051** (URIs for XML Security)
* **RFC 7457** (TLS attacks), **Applied Crypto Hardening**

---

## Appendix A. SAML ↔ OIDC Feature Summary (Informative)

SAML requirements are authoritative; OIDC parallels are for orientation only.

| SAML feature                                                        | Where defined                          | Closest OIDC concept            | Notes                                                       |
| ------------------------------------------------------------------- | -------------------------------------- | ------------------------------- | ----------------------------------------------------------- |
| **Metadata & keys** (XML; overlapping keys for rotation)            | [§5.1–§5.3](#sec-5-1)                  | Provider config & jwk endpoint  | HTTP‑fetchable config & rotation; this profile is XML‑only. |
| **Subject identifier** (`NameID` + `subject-id`/`pairwise-id`)      | [§6](#sec-6)                           | `sub` (public/pairwise)         | NameID is canonical subject; attributes per OASIS CS01.     |
| **Pairwise vs public**                                              | [§6.3–§6.4](#sec-6-3)                  | Pairwise/public modes           | Pairwise is per‑SP; no sector_identifier_uri.               |
| **RP identifier requirements via metadata**                         | [§6.5](#sec-6-5)                       | Client metadata                 | SP declares `pairwise-id` vs `subject-id` needs.            |
| **Request binding** (Redirect; unsigned permitted with ACS pre‑reg) | [§9.1](#sec-9-1)                       | Authorization Request           | ACS pre‑registration ≈ redirect_uri registration.           |
| **Response binding** (POST; dual‑signed)                            | [§9.2](#sec-9-2)                       | Authz response + ID Token       | Bearer only.                                                |
| **Error signaling** (SAML Status; mapping table)                    | [§9.4](#sec-9-4)                       | Authorization errors            | Mapping is informative.                                     |
| **Requested authn context**                                         | [§10.1](#sec-10-1)                     | `acr_values`                    | Achieved class returned.                                    |
| **Forced re‑auth**                                                  | [§10.2](#sec-10-2)                     | `prompt=login`                  | Via `ForceAuthn=true`.                                      |
| **Passive**                                                         | [§10.6](#sec-10-6)                     | `prompt=none`                   | Non‑success → `Responder/NoPassive`.                        |
| **Freshness**                                                       | [§10.3](#sec-10-3), [§10.8](#sec-10-8) | `freshness policy`, `auth_time` | Age check w/ skew.                                          |
| **Profile attributes** (LDAP: mail/givenName/sn/displayName)        | [§7](#sec-7)                           | Standard profile claims         | Flat strings; liberal ingest.                               |
| **Assertion cardinality** (success)                                 | [§10.9](#sec-10-9)                     | Single ID Token + claims        | Exactly 1 assertion, 1 subject, 1 authn, 1 attribute stmt.  |
| **Session expiry** (`SessionNotOnOrAfter`)                          | [§10.8](#sec-10-8)                     | Token expiry                    | RP must round‑trip to IdP at/before expiry.                 |

---

## Appendix B. Comparison with Kantara Profiles (Informative)

**Legend:** **Aligned** = matches intent/requirement; **Stricter** = stronger than profile; **Looser** = permits more; **Missing** = not specified here. Clause references are indicative.

| Topic                               | This profile                       | saml2int (clause)          | fedinterop (clause)                                      | Disposition             | Notes                                                                                                 |
| ----------------------------------- | ---------------------------------- | -------------------------- | -------------------------------------------------------- | ----------------------- | ----------------------------------------------------------------------------------------------------- |
| **Metadata form & fetch**           | [§5.1–§5.3](#sec-5-1)              | §2.2 Metadata & Trust Mgmt | §2.2.1–2.2.2; [IIP‑MD02], [IIP‑MD05]–[IIP‑MD06]          | **Aligned**             | XML metadata; accept `EntityDescriptor` or `EntitiesDescriptor` roots.                                |
| **Key discovery & rotation**        | [§5.2](#sec-5-2)                   | §2.2 rollover guidance     | [IIP‑MD07]–[IIP‑MD08] rollover                           | **Aligned / Stricter**  | Concurrent keys **SHOULD** be present; fedinterop requires consumers to handle multiple.              |
| **Algorithm MTI set**               | §15                                | §2.3 algorithms            | §2.5; [IIP‑ALG01]…[IIP‑ALG08]                            | **Stricter**            | MTI digest/sign/transport, AES‑GCM SHOULD, legacy CBC MAY with warnings; deny‑list MD5/RSA1_5.        |
| **Bindings**                        | [§9.1](#sec-9-1), [§9.2](#sec-9-2) | §3.1 Web Browser SSO       | §2.3/§3.1                                                | **Aligned**             | Redirect for requests; POST for responses.                                                            |
| **Request signing**                 | [§9.1](#sec-9-1)                   | §3.1.1 Requests            | [IIP‑SP02] (response reject if unsigned)                 | **Aligned / Looser**    | Unsigned requests permitted with ACS pre‑reg; some federations require signing.                       |
| **Response/Assertion signing**      | [§9.2](#sec-9-2)                   | §3.1.2 Responses           | [IIP‑SP02]                                               | **Stricter**            | Require **both** Response and Assertion signatures.                                                   |
| **Assertion cardinality (success)** | [§10.9](#sec-10-9)                 | (not fixed)                | (not fixed)                                              | **Stricter**            | Exactly one Assertion/Subject/Authn/AttributeStatement.                                               |
| **NameID presence**                 | [§6.1](#sec-6)                     | §3.1/4.1                   | §3.1/4.1                                                 | **Aligned / Stricter**  | NameID **MUST** be present; persistent **SHOULD**.                                                    |
| **Subject identifier attributes**   | [§6.2–§6.4](#sec-6-4)              | §2.1 (varies)              | [IIP‑SP01] liberal parsing; SubjectID profile referenced | **Stricter**            | Require `subject-id` or `pairwise-id` (OASIS CS01).                                                   |
| **Pairwise model**                  | [§6.3](#sec-6-3)                   | (no sector id)             | (no sector id)                                           | **Aligned**             | Per‑SP uniqueness; no OIDC sector_identifier_uri.                                                     |
| **RP identifier requirements**      | [§6.5](#sec-6-5)                   | §2.2 EntityAttributes      | [IIP‑MD05]–[IIP‑MD06]                                    | **Aligned**             | Declare via `mdattr:EntityAttributes`.                                                                |
| **RequestedAuthnContext**           | [§10.1](#sec-10-1)                 | §3.1                       | §3.1/4.1                                                 | **Aligned**             | Exact comparison; achieved class returned.                                                            |
| **Passive / ForceAuthn**            | §10.6 / §10.2                      | §3.1/4.1                   | §3.1/4.1                                                 | **Aligned**             | SAML‑native semantics; OIDC mapping informative only.                                                 |
| **Freshness**                       | §10.3, §10.8                       | §2.1 clock skew            | §2.1 clock skew                                          | **Stricter (guidance)** | Concrete formula + skew default.                                                                      |
| **Session expiry**                  | §10.8                              | (deployment)               | (deployment)                                             | **Stricter**            | RP must redirect to IdP at/before `SessionNotOnOrAfter`.                                              |
| **Correlation**                     | §9.2                               | §3.1.2                     | §3.1/4.1                                                 | **Aligned / Clearer**   | Require `InResponseTo` on Response and SubjectConfirmationData.                                       |
| **Bearer‑only**                     | §9.2                               | common                     | common                                                   | **Stricter**            | Non‑bearer rejected.                                                                                  |
| **Attributes**                      | §7                                 | federation vocabularies    | federation vocabularies                                  | **Missing (narrow)**    | Only `mail`, `givenName`, `sn`, `displayName` defined here; federations may require eduPerson/REFEDS. |
| **FriendlyName**                    | §7                                 | non‑normative              | non‑normative                                            | **Aligned**             | Ignore for logic.                                                                                     |
| **Errors**                          | §9.4                               | Status model               | Status model                                             | **Aligned / Extra**     | Informative OIDC mapping; SAML semantics authoritative.                                               |

**Gap/Deviation call‑outs**

* **Attributes:** Minimal by design; add federation schemas (e.g., eduPerson) as deployment policy.
* **Unsigned requests:** Allowed with ACS pre‑reg; treat federation “request must be signed” as a policy override.
* **Dual signing & cardinality:** Stricter than some deployments; verify operator policy.
* **Algorithm signaling:** If your federation requires algorithm metadata extensions, add them without altering this core profile.

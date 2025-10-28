# Constrained Enterprise Profile of the SAML 2.0 Web Browser SSO Profile {#title}

*OpenID Foundation Implementer’s Draft 1*
Short Name: **SAML.EnterpriseProfile**
Editors: **Karl McGuinness** (OpenID Foundation Contributor)
License: **CC BY-SA 4.0**

> **Status of This Document.** This document is an OpenID Foundation Implementer’s Draft. It is a work in progress and may change without notice. Implementers are encouraged to provide feedback and implementation experience.

---

## 1. Introduction {#introduction}

This profile defines a **constrained enterprise** subset of the **SAML 2.0 Web Browser SSO Profile** that aims to provide **behavioral parity with OpenID Connect (OIDC)** while remaining a **subset of SAML2Int** (Kantara “SAML 2.0 Deployment Profile for Federation Interoperability”).
It is designed for **single-enterprise control planes** where the same organization operates both the **Identity Provider (IdP)** and **Service Provider (SP)** (a.k.a. RP in OIDC terminology).

### 1.1 Goals {#goals}

* Preserve SAML2Int interoperability while aligning the end-to-end experience with OIDC semantics (e.g., **ACR**, **AMR**, **prompt-like** behaviors).
* Reduce operational friction for controlled enterprise topologies by **relaxing** some SAML2Int requirements (e.g., **no mandatory signed AuthnRequests**, **no mandatory assertion encryption**, **no SLO**).
* **Constrain** areas that improve reliability, rollover, and troubleshooting (e.g., **metadata freshness, key naming, exact ACS matching**).

### 1.2 Non-Goals {#non-goals}

* This profile does **not** introduce new SAML extensions.
* This profile does **not** mandate federation across unrelated organizations.
* Logout profiles are **not required**.

---

## 2. Notation and Conventions {#notation}

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** are to be interpreted as described in RFC 2119.

“SAML2Int” refers to the **Kantara SAML 2.0 Deployment Profile for Federation Interoperability**.
“Subject ID Profile” refers to **SAML V2.0 Subject Identifier Attributes Profile (CS01)**.

---

## 3. Conformance Targets {#conformance}

Implementations claiming conformance to this profile **MUST** conform to:

* **SAML2Int**, except where this profile explicitly **loosens** or **tightens** requirements.
* **SAML V2.0 Core** and **Bindings** relevant to the Web Browser SSO Profile.
* **SAML V2.0 Subject Identifier Attributes Profile (CS01)**.
* **XML Signature**; algorithms as constrained herein.
* **TLS 1.2 or higher** for all endpoints.

Conformance targets are **Identity Provider** and **Service Provider**.

---

## 4. High-Level Parity with OIDC (Non-Normative) {#parity-overview}

This profile aligns with common OIDC behaviors:

* **ACR parity**: `RequestedAuthnContext` with `Comparison="exact"` mirrors `acr_values` and the IdP returns the achieved `AuthnContextClassRef`.
* **AMR parity**: IdP issues an **AMR attribute** (multi-valued) aligned to the OAuth AMR registry.
* **Prompt parity**: `ForceAuthn="true"` ≅ `prompt=login`; `IsPassive="true"` ≅ `prompt=none`.
* **Subject parity**: A single stable **NameID** (persistent) equals the selected **Subject Identifier Attribute** (`subject-id` or `pairwise-id`), analogous to OIDC `sub`.
* **Audience parity**: Exactly one `AudienceRestriction/Audience` equals SP `entityID`, akin to OIDC `aud`.

SP-initiated SSO is the **primary** flow (IdP-initiated MAY be supported; see §7.6).

---

## 5. Metadata Requirements {#metadata}

### 5.1 Format and Transport {#metadata-format}

* Metadata **MUST** be served with media type `application/samlmetadata+xml`.
* Metadata **MUST** include `validUntil` **and** `cacheDuration`.
* Consumers **MUST** cache per `cacheDuration` and **MUST** re-fetch and retry on signature failures where the signing key is unknown.

### 5.2 Signing and Keys {#metadata-keys}

* IdP metadata **MAY** be XML-signed and **MUST** be available over HTTPS.
* SP metadata **MAY** omit `<KeyDescriptor>` entirely; publishing zero keys is permitted.
* Each `<KeyDescriptor>` that is present **MUST** include a `ds:KeyName` that is a **stable key identifier**.
* Implementations **SHOULD** publish multiple active signing keys to enable pre-publication and graceful rotation.

### 5.3 Freshness {#metadata-freshness}

* Values for `validUntil` and `cacheDuration` **MUST** be consistent with SAML2Int guidance.
* On any signature verification failure due to an **unknown key**, the consumer **MUST** re-fetch metadata immediately.

---

## 6. Bindings, Endpoints, and Transport {#bindings}

* **AuthnRequest from SP to IdP:** **HTTP-Redirect** binding **MUST** be used.

  * Redirect binding **MUST** support **DEFLATE** and **URL-safe signature validation** per specification.
* **Response from IdP to SP:** **HTTP-POST** binding **MUST** be used.
* **Artifact binding:** **Not required** by this profile.
* All endpoints **MUST** enforce **TLS 1.2+** with modern cipher suites; **HSTS** is **RECOMMENDED**.

---

## 7. AuthnRequest Requirements (SP → IdP) {#authnrequest}

1. **Signing:** An SP **MUST NOT be required** to sign `AuthnRequest`. If present, signatures **MAY** be validated by the IdP.
2. **Issuer:** `AuthnRequest/Issuer` **MUST** equal the SP’s `entityID`.
3. **Destination:** `AuthnRequest/@Destination` **MUST** equal the IdP’s **Redirect SSO** endpoint.
4. **ACS Matching:** The ACS endpoint is selected by the IdP using the rules in §9. Exact match is required.
5. **NameIDPolicy:**

   * **RECOMMENDED:** Omit `<NameIDPolicy>`.
   * **ALTERNATIVE:** `<NameIDPolicy AllowCreate="true">` without a `Format` attribute.
6. **RequestedAuthnContext (ACR):**

   * If present, **MUST** use `Comparison="exact"` and one or more `AuthnContextClassRef` URIs.
   * The IdP **MUST** return the achieved class(es) in the `AuthnStatement`.
7. **ForceAuthn / IsPassive:**

   * `ForceAuthn="true"` **MUST** be honored (≅ OIDC `prompt=login`).
   * `IsPassive="true"` **MUST** be honored (≅ OIDC `prompt=none`).
8. **RelayState:**

   * If present, **MUST** be echoed by the IdP.
   * **MUST** be no more than **80 bytes**.
9. **IdP-Initiated Considerations:**

   * This profile **allows** SP-initiated and **may** allow IdP-initiated (see §7.6, §12.3).
10. **Request Correlation:**

    * If the request contains an ID, and the IdP issues a success `Response`, the `Response/@InResponseTo` **MUST** equal the request ID.

---

## 8. Response Requirements (IdP → SP) {#response}

1. **Binding:** IdP **MUST** use HTTP-POST.
2. **Signing:** The `Response` **MUST** be XML-signed; the enclosed `Assertion` **MUST** also be XML-signed.
3. **Recipient/Destination:**

   * `Response/@Destination` (if present) and `SubjectConfirmationData/@Recipient` **MUST** equal the selected ACS URL from SP metadata.
4. **Success Structure:** For `StatusCode=Success`, the `Response` **MUST** contain **exactly one** `Assertion` with:

   * **exactly one** `Subject`
   * **exactly one** `AuthnStatement`
   * **exactly one** `AttributeStatement`
     Other statement types (e.g., `AuthzDecisionStatement`) are **not permitted**.
5. **Bearer Only:** All `SubjectConfirmation` elements **MUST** use `Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"` and include `SubjectConfirmationData` with `Recipient`, `NotOnOrAfter`, and (for SP-initiated requests) `InResponseTo`.
6. **AudienceRestriction:** **Exactly one** `AudienceRestriction` with **exactly one** `Audience`, equal to the SP’s `entityID`. No wildcards or multiple audiences.
7. **Clock Skew & Lifetime:**

   * Implementations **MUST** follow SAML2Int defaults for assertion validity and clock skew.
   * **RECOMMENDED** practice: `NotOnOrAfter` ≤ **5 minutes**; clock skew ≤ **±300s**.

---

## 9. Assertion Content {#assertions}

### 9.1 Subject & NameID {#subject-nameid}

* Every successful `Assertion/Subject` **MUST** contain `NameID`.
* IdP **MUST** use `NameID/@Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"`.
* Exactly **one** **Subject Identifier Attribute** **MUST** be present: either

  * `urn:oasis:names:tc:SAML:attribute:subject-id` **or**
  * `urn:oasis:names:tc:SAML:attribute:pairwise-id`.
* The **`NameID` value MUST equal** the value of the **emitted Subject Identifier Attribute** (global or pairwise). Only one subject notion exists in a given assertion.

### 9.2 Subject Identifier Attributes Profile {#subject-id-profile}

* IdPs and SPs **MUST** conform to **SAML V2.0 Subject Identifier Attributes Profile (CS01)**.
* Deployments **MUST** support both **global** (`subject-id`) and **pairwise** (`pairwise-id`) subject models. The assertion includes **exactly one** of them.

### 9.3 Authentication Statement (ACR & AMR) {#authnstatement}

* Successful assertions **MUST** include an `AuthnStatement` with:

  * `AuthnInstant` (time of end-user authentication), and
  * `AuthnContext` containing **at least one** `AuthnContextClassRef` (the achieved ACR).
* **AMR Attribute (multi-valued):**

  * IdP **MUST** issue an attribute named **`https://openid.net/ipsi/amr`**
    with `NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"`; values **MUST** be tokens from the **OAuth AMR Registry**.
  * **Compatibility:** SPs **MAY** accept the legacy alias `https://openid.net/ipsie/amr` if present.

### 9.4 Conditions & Session {#conditions-session}

* `Conditions` **MUST** set appropriate `NotBefore/NotOnOrAfter` consistent with SAML2Int defaults.
* The `AuthnStatement` **SHOULD** contain `SessionIndex`.
* If `SessionNotOnOrAfter` is present, the SP **MUST** treat it as the **maximum RP session lifetime**. Upon expiry, SP **MUST** re-authenticate the user.
* **Data Minimization:** Assertions **SHOULD NOT** contain attributes beyond those required by the SP’s minimal bundle (§10) to reduce PII exposure (encryption is not required by this profile).

### 9.5 Replay Protection {#replay}

* SPs **MUST** enforce one-time use of assertion IDs within their validity window (cache until `NotOnOrAfter` plus skew).
* For SP-initiated success responses, `Response/@InResponseTo` **MUST** equal the request ID.

---

## 10. Attribute Bundle (Directory/LDAP-Oriented) {#attributes}

To mirror common OIDC claims while aligning with SAML2Int’s directory naming guidance, this profile **RECOMMENDS** (but does not require) the following **LDAP-style** attribute names when such data is needed:

| Purpose            | Attribute Name (URI NameFormat)                 | Notes                                            |        |
| ------------------ | ----------------------------------------------- | ------------------------------------------------ | ------ |
| Subject (global)   | `urn:oasis:names:tc:SAML:attribute:subject-id`  | **MUST** equal NameID (persistent) when selected |        |
| Subject (pairwise) | `urn:oasis:names:tc:SAML:attribute:pairwise-id` | **MUST** equal NameID (persistent) when selected |        |
| AMR                | `https://openid.net/ipsi/amr`                   | Multi-valued; OAuth AMR registry tokens          |        |
| Email              | `urn:oid:0.9.2342.19200300.100.1.3`             | `mail`                                           |        |
| Email Verified     | `urn:oid:1.3.6.1.4.1.5923.1.1.1.13`             | boolean as string “true                          | false” |
| Given Name         | `urn:oid:2.5.4.42`                              | `givenName`                                      |        |
| Surname            | `urn:oid:2.5.4.4`                               | `sn`                                             |        |
| Display Name       | `urn:oid:2.16.840.1.113730.3.1.241`             | `displayName`                                    |        |

> Deployments **SHOULD** request only what they need and IdPs **SHOULD** minimize release.

---

## 11. Cryptographic Requirements {#crypto}

* **SHA-1 is NOT allowed** for signatures or digests.
* Algorithms and key sizes **MUST** follow SAML2Int requirements (e.g., SHA-256+; RSA-PSS and/or ECDSA P-256 where applicable).
* All signatures **MUST** be verifiable against currently valid metadata keys; on unknown keys, **re-fetch** metadata (§5.3).

---

## 12. Session and Logout {#session-logout}

* **Single Logout (SLO)** is **not required** for IdP or SP.
* The presence of `SessionNotOnOrAfter` **MUST** bound the RP session; SP **MUST** force re-authentication after expiry.
* Implementations **MAY** offer app-local sign-out mechanisms; back-channel/front-channel logout is out-of-scope.

---

## 13. ACS Selection & Exact Matching {#acs}

* The IdP **MUST** select the ACS endpoint by **exact string match** against one of the SP’s registered ACS locations.
* Multiple ACS endpoints **MAY** be published; the IdP **MAY** use the `AssertionConsumerServiceIndex` when provided.
* Wildcards, prefix matching, or dynamic ACS values are **not permitted**.

---

## 14. Error Semantics and OIDC Mappings {#errors}

SPs often implement OIDC-style UX. The following **normative mappings** apply:

| SAML Status / Condition            | Typical Cause                                    | OIDC-like Error for RP Handling                |
| ---------------------------------- | ------------------------------------------------ | ---------------------------------------------- |
| `Responder` + `NoPassive`          | User interaction required while `IsPassive=true` | `interaction_required`                         |
| `Responder` + `AuthnFailed`        | User failed authentication                       | `access_denied` (or `login_required` on retry) |
| `Requester` + `RequestDenied`      | Policy or request invalid                        | `invalid_request`                              |
| `Requester` + `UnsupportedBinding` | Bad binding                                      | `invalid_request`                              |
| `Responder` + `PartialLogout`      | (If logout attempted)                            | `server_error`                                 |

---

## 15. SAML2Int Delta Table (Normative) {#deltas}

**Legend:** Kept = unchanged; Loosened = relaxed vs SAML2Int; Tightened = stricter than SAML2Int; Omitted = not required.

| Area                                           | This Profile                         | Delta              |
| ---------------------------------------------- | ------------------------------------ | ------------------ |
| Signed AuthnRequest required                   | **Not required**; optional           | **Loosened**       |
| Assertion Encryption                           | **Not required**                     | **Loosened**       |
| Single Logout                                  | **Not required**                     | **Omitted**        |
| Metadata `validUntil`/`cacheDuration`          | **Required**                         | **Tightened**      |
| Metadata media type                            | `application/samlmetadata+xml`       | **Tightened**      |
| `<KeyDescriptor>/ds:KeyName`                   | **Required when present**            | **Tightened**      |
| Multiple signing keys in metadata              | **SHOULD**                           | **Tightened**      |
| Unknown-key re-fetch on signature fail         | **MUST**                             | **Tightened**      |
| NameID Format                                  | **Persistent** and equals Subject ID | **Tightened**      |
| Subject Identifier Attributes (CS01)           | **MUST** support (one in assertion)  | **Kept/Tightened** |
| AudienceRestriction                            | Exactly one, equals SP `entityID`    | **Tightened**      |
| SP Request Binding                             | **HTTP-Redirect** only               | **Tightened**      |
| IdP Response Binding                           | **HTTP-POST** only                   | **Tightened**      |
| Response + Assertion both signed               | **MUST**                             | **Kept/Tightened** |
| Recipient/Destination exact ACS                | **MUST**                             | **Tightened**      |
| RequestedAuthnContext comparison               | **exact** only                       | **Tightened**      |
| ForceAuthn / IsPassive                         | **MUST honor**                       | **Kept/Tightened** |
| Bearer SubjectConfirmation only                | **MUST**                             | **Tightened**      |
| Success shape (1 Assertion/Subject/Authn/Attr) | **MUST**                             | **Tightened**      |
| RelayState ≤ 80 bytes, echoed                  | **MUST**                             | **Kept/Tightened** |
| SHA-1 allowed                                  | **No**                               | **Tightened**      |

---

## 16. OIDC Feature Equivalence (Informative) {#oidc-map}

| OIDC Concept          | SAML Mechanism in this Profile                                   |
| --------------------- | ---------------------------------------------------------------- |
| `acr_values` request  | `RequestedAuthnContext` with `Comparison="exact"` and class refs |
| Returned `acr`        | `AuthnContextClassRef` in `AuthnStatement`                       |
| `amr` claim           | AMR Attribute `https://openid.net/ipsi/amr` (multi-valued)       |
| `prompt=login`        | `ForceAuthn="true"`                                              |
| `prompt=none`         | `IsPassive="true"`                                               |
| `sub`                 | `NameID` (persistent) == `subject-id` or `pairwise-id`           |
| `aud`                 | `AudienceRestriction/Audience` == SP `entityID`                  |
| `state`               | `RelayState` (≤80 bytes, echoed)                                 |
| `iat` / `exp`         | `IssueInstant`; `Conditions/NotOnOrAfter` (+ clock skew)         |
| JWS/JWE               | XML Signature; (encryption not required in this profile)         |
| IdP-init login parity | SP-init is primary; IdP-init **MAY** be supported per deployment |

---

## 17. Informative Examples {#examples}

> **Note:** Examples are illustrative only. Line breaks and indentation are for readability.

### 17.1 SP-Initiated AuthnRequest (HTTP-Redirect) {#ex-request}

```xml
<samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="_a12345"
    Version="2.0"
    IssueInstant="2025-10-25T20:00:00Z"
    Destination="https://idp.example.com/sso/redirect"
    ForceAuthn="true"
    IsPassive="false">
  <saml:Issuer>https://sp.example.com/saml/metadata</saml:Issuer>

  <!-- Omit NameIDPolicy (RECOMMENDED) or include AllowCreate="true" -->
  <!-- <samlp:NameIDPolicy AllowCreate="true"/> -->

  <samlp:RequestedAuthnContext Comparison="exact">
    <saml:AuthnContextClassRef>https://refeds.org/profile/mfa</saml:AuthnContextClassRef>
  </samlp:RequestedAuthnContext>
</samlp:AuthnRequest>
```

### 17.2 Success Response (HTTP-POST), Single Assertion {#ex-response}

```xml
<samlp:Response
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="_r56789"
    Version="2.0"
    IssueInstant="2025-10-25T20:00:02Z"
    Destination="https://sp.example.com/saml/acs"
    InResponseTo="_a12345">
  <saml:Issuer>https://idp.example.com/saml/metadata</saml:Issuer>

  <!-- XML Signature over Response here -->

  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>

  <saml:Assertion ID="_A1" IssueInstant="2025-10-25T20:00:02Z" Version="2.0">
    <saml:Issuer>https://idp.example.com/saml/metadata</saml:Issuer>

    <!-- XML Signature over Assertion here -->

    <saml:Subject>
      <!-- NameID persistent and equals subject-id attribute -->
      <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">
        3f0a9c0b-5a2e-4f2a-9e1a-2b2c7f1c7e10
      </saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData
            InResponseTo="_a12345"
            Recipient="https://sp.example.com/saml/acs"
            NotOnOrAfter="2025-10-25T20:05:02Z"/>
      </saml:SubjectConfirmation>
    </saml:Subject>

    <saml:Conditions NotBefore="2025-10-25T20:00:02Z" NotOnOrAfter="2025-10-25T20:05:02Z">
      <saml:AudienceRestriction>
        <saml:Audience>https://sp.example.com/saml/metadata</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>

    <saml:AuthnStatement AuthnInstant="2025-10-25T19:59:40Z" SessionIndex="_S123" SessionNotOnOrAfter="2025-10-26T03:59:40Z">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>https://refeds.org/profile/mfa</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>

    <saml:AttributeStatement>
      <!-- Subject Identifier Attribute (global). Exactly one of subject-id or pairwise-id -->
      <saml:Attribute
          Name="urn:oasis:names:tc:SAML:attribute:subject-id"
          NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue>3f0a9c0b-5a2e-4f2a-9e1a-2b2c7f1c7e10</saml:AttributeValue>
      </saml:Attribute>

      <!-- AMR Attribute (multi-valued) -->
      <saml:Attribute
          Name="https://openid.net/ipsi/amr"
          NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue>pwd</saml:AttributeValue>
        <saml:AttributeValue>otp</saml:AttributeValue>
      </saml:Attribute>

      <!-- Optional directory-style attributes -->
      <saml:Attribute Name="urn:oid:0.9.2342.19200300.100.1.3">
        <saml:AttributeValue>user@example.com</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="urn:oid:2.5.4.42">
        <saml:AttributeValue>Alice</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="urn:oid:2.5.4.4">
        <saml:AttributeValue>Example</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>
```

### 17.3 SP Metadata (excerpt) {#ex-sp-metadata}

```xml
<EntityDescriptor
    xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="https://sp.example.com/saml/metadata"
    validUntil="2025-11-08T00:00:00Z"
    cacheDuration="PT168H">
  <SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">

    <!-- Zero KeyDescriptor is permitted by this profile -->
    <!-- <KeyDescriptor use="signing"> ... <ds:KeyName>sp-key-2025-10</ds:KeyName> ... </KeyDescriptor> -->

    <AssertionConsumerService
        index="0"
        isDefault="true"
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="https://sp.example.com/saml/acs"/>
    <AssertionConsumerService
        index="1"
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="https://sp.example.com/saml/acs/alt"/>
  </SPSSODescriptor>
</EntityDescriptor>
```

### 17.4 IdP Metadata (excerpt) {#ex-idp-metadata}

```xml
<EntityDescriptor
    xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="https://idp.example.com/saml/metadata"
    validUntil="2025-11-08T00:00:00Z"
    cacheDuration="PT168H">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:KeyName>idp-key-2025-10</ds:KeyName>
        <!-- ds:X509Data omitted -->
      </ds:KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="https://idp.example.com/sso/redirect"/>
  </IDPSSODescriptor>
</EntityDescriptor>
```

---

## 18. Security Considerations {#security}

* Because assertion encryption is **not required**, deployments **MUST** apply **data minimization** and transport-layer protection.
* Keys **MUST** be rotated regularly; `ds:KeyName` **MUST** be stable across publication cycles.
* **SHA-1 is prohibited**; use modern algorithms compliant with SAML2Int.
* Implement robust anti-replay caches and strict audience and recipient checks.

---

## 19. Privacy Considerations {#privacy}

* Release only the minimal attribute bundle necessary for the SP.
* Prefer **pairwise** subject identifiers when cross-SP correlation is a concern; when **global** is used, ensure contractual controls.
* Respect local policies and legal obligations for user notice and consent.

---

## 20. IANA / Registry Considerations {#iana}

This profile defines no new registries. It **reuses** the **OAuth AMR Registry** tokens in the AMR attribute.

---

## 21. References {#references}

### 21.1 Normative {#normative-refs}

* SAML 2.0 Core
* SAML 2.0 Bindings
* **SAML2Int** (Kantara SAML 2.0 Deployment Profile for Federation Interoperability)
* **SAML V2.0 Subject Identifier Attributes Profile (CS01)**
* XML Signature Specifications
* TLS 1.2+

### 21.2 Informative {#informative-refs}

* OpenID Connect Core 1.0
* OAuth 2.0 Authentication Method Reference (AMR) Registry
* Kantara Federation Interoperability Profile

---

## 22. Rationale (Non-Normative) {#rationale}

* **Unsigned requests** reduce SP complexity and reflect OIDC public clients while maintaining Response/Assertion signing end-to-end.
* **No encryption requirement** lowers operational friction in single-enterprise contexts where transport security and data minimization suffice.
* **No SLO requirement** minimizes brittleness; session lifetime is bounded via `SessionNotOnOrAfter`.
* **Exact ACS matching** and **single audience** eliminate common mis-routing and overbroad audience risks.
* **Subject unification** (NameID == Subject Identifier Attribute) avoids multiple “subject notions.”

---

## 23. Change Log {#changelog}

* **Implementer’s Draft 1 — 2025-10-25**

  * Initial publication of **Constrained Enterprise Profile of the SAML 2.0 Web Browser SSO Profile**
  * Aligns with SAML2Int; relaxes signed requests, encryption, SLO; tightens metadata and assertion constraints; adds ACR/AMR parity with OIDC; defines LDAP-style attributes.

---

### Appendix A. Quick Checklist (Non-Normative) {#checklist}

* [ ] SP uses **HTTP-Redirect**; IdP uses **HTTP-POST**.
* [ ] Response **and** Assertion are **signed** (SHA-256+).
* [ ] **Exact** ACS match; **exact** single audience == SP entityID.
* [ ] **One** subject notion: `NameID(persistent)` == `subject-id` **or** `pairwise-id`.
* [ ] `RequestedAuthnContext` (if used): `Comparison="exact"`.
* [ ] AMR attribute `https://openid.net/ipsi/amr` issued (values from OAuth AMR registry).
* [ ] `RelayState` ≤ 80 bytes and echoed.
* [ ] `SessionNotOnOrAfter` enforced at RP.
* [ ] SHA-1 **not allowed**.
* [ ] Metadata has `validUntil` + `cacheDuration`; `KeyName` present on keys; unknown-key ⇒ **re-fetch**.

---
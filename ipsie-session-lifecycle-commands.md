---
title: "IPSIE Session Lifecycle Commands"
abbrev: "IPSIE-SL-Commands"
docname: ipsie-session-lifecycle-commands-latest
category: info
submissiontype: independent
ipr: none

author:
  -
    fullname: Karl McGuinness
    organization: OpenID Foundation
    role: editor

normative:
  RFC2119:
  RFC6749:
  RFC7009:

  OIDC.Core:
    title: "OpenID Connect Core 1.0"
    target: https://openid.net/specs/openid-connect-core-1_0.html
    author:
      - name: N. Sakimura
      - name: J. Bradley
      - name: M. Jones
      - name: B. de Medeiros
      - name: C. Mortimore
    date: 2023-12

  OIDC.BackChannelLogout:
    title: "OpenID Connect Back-Channel Logout 1.0"
    target: https://openid.net/specs/openid-connect-backchannel-1_0.html
    author:
      - name: M. Jones
    date: 2022-09

  OIDC.FrontChannelLogout:
    title: "OpenID Connect Front-Channel Logout 1.0"
    target: https://openid.net/specs/openid-connect-frontchannel-1_0.html
    author:
      - name: M. Jones
    date: 2022-09

  SAML2.Core:
    title: "Assertions and Protocols for the OASIS Security Assertion Markup Language (SAML) V2.0"
    target: http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
    author:
      - name: S. Cantor
      - name: J. Kemp
      - name: R. Philpott
      - name: E. Maler
    date: 2005-03

  SAML2.Profiles:
    title: "Profiles for the OASIS Security Assertion Markup Language (SAML) V2.0"
    target: http://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf
    author:
      - name: J. Hughes
    date: 2005-03

  NIST.SP.800-63-3:
    title: "Digital Identity Guidelines"
    target: https://pages.nist.gov/800-63-3/sp800-63-3.html
    author:
      - name: P.A. Grassi
    date: 2017-06

  NIST.SP.800-63B:
    title: "Digital Identity Guidelines: Authentication and Lifecycle Management"
    target: https://pages.nist.gov/800-63-3/sp800-63b.html
    author:
      - name: P.A. Grassi
      - name: E.M. Newton
      - name: R.A. Perlner
      - name: A.R. Regenscheid
    date: 2017-06

  NIST.SP.800-63C:
    title: "Digital Identity Guidelines: Federation and Assertions"
    target: https://pages.nist.gov/800-63-3/sp800-63c.html
    author:
      - name: P.A. Grassi
    date: 2017-06

informative:
  OP-Commands:
    title: "OpenID Provider Commands"
    target: https://openid.net/specs/openid-provider-commands-1_0.html
    author:
      - name: M. Jones

  CAEP:
    title: "Continuous Access Evaluation Protocol (CAEP)"
    target: https://openid.net/specs/openid-caep-1_0.html
    author:
      - name: A. Backman

  SharedSignals:
    title: "Shared Signals Framework"
    target: https://openid.net/specs/sharedsignals-framework-1_0.html
    author:
      - name: A. Backman

  GlobalTokenRevocation:
    title: "OAuth 2.0 Global Token Revocation"
    author:
      - name: T. Lodderstedt

--- abstract

This specification defines two lifecycle commands that an Identity Provider (IdP) can send to a Relying Party (RP) to trigger access revalidation — requiring the RP to stop relying on a prior sign-in and obtain reauthentication from the IdP.

--- middle

# Introduction {#introduction}

This specification defines **two lifecycle commands** that an Identity Provider (IdP) can send to a Relying Party (RP) to trigger **access revalidation** — requiring the RP to stop relying on a prior sign-in and obtain reauthentication from the IdP.

These commands affect **session validity and the continued acceptability of prior authentication artifacts**. They do **not** affect roles, permissions, entitlements, or authorization policy within the RP.

| Command | Scope | Typical Trigger |
|---------|-------|-----------------|
| **Expire Session State** | All RP client sessions for the subject | Logout, inactivity timeout, step-up |
| **Invalidate Authentication State** | All sessions, tokens, and API keys | Account compromise, security incident |

## IPSIE Session Lifecycle Level Mapping {#level-mapping}

The commands defined in this specification map to the **IPSIE Session Lifecycle (SL) levels** as follows:

| IPSIE Level | Command | Requirement |
|-------------|---------|-------------|
| **SL1** | *(Not applicable)* | Session lifetime set from assertion; RP expires session when validity period ends |
| **SL2** | **Expire Session State** | **REQUIRED** — RP MUST expire sessions on demand at IdP request (same RP behavior as SL1 expiry, but IdP-triggered rather than time-based) |
| **SL2** | **Invalidate Authentication State** | **REQUIRED** — RP MUST invalidate sessions and tokens, and revoke API keys at IdP request |
| **SL2** | **Self-contained token max TTL** | **1 hour** — when the RP cannot invalidate self-contained access tokens on demand (see Section 7) |
| **SL3** | Both commands + continuous access signals | RP and IdP MUST communicate session and device state changes |
| **SL3** | **Self-contained token max TTL** | **5 minutes** — when the RP cannot invalidate self-contained access tokens on demand (see Section 7) |

**SL2 conformance** requires that:

- The **Identity Service** MUST be able to send both Expire Session State and Invalidate Authentication State commands to Applications
- The **Application** MUST process and enforce both commands as defined in this specification
- The **Application** MUST NOT accept unsolicited federation assertions (e.g., SAML IdP-initiated SSO)
- The **Identity Service** MUST enforce authentication method requests from the Application

**SL3 conformance** builds on SL2 and additionally requires bidirectional state communication via Shared Signals (CAEP), enabling continuous access evaluation.

## Notation and Conventions {#notation}

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** are to be interpreted as described in {{RFC2119}}.

## Terminology {#terminology}

**Authentication**
The process of verifying the identity of a subject (user, device, or workload). {{NIST.SP.800-63-3}} §4

**Authentication State**
The collection of artifacts that together represent the outcome of a successful authentication event and allow a subject to continue accessing resources without reauthenticating. Authentication state includes the RP client session, access tokens, refresh tokens, and API keys that were established or issued as a result of the subject's authentication. Authentication state is scoped to a subject at a specific RP and is distinct from authorization state (roles, permissions, entitlements). In this specification, the Invalidate Authentication State command requires the RP to treat all of these artifacts as no longer valid. {{NIST.SP.800-63B}} §7 (session management), {{NIST.SP.800-63C}} §6 (assertion lifetime and protection), {{RFC6749}} §1.4, §1.5 (token lifecycle)

**Authorization**
The process of determining what actions or resources an authenticated subject is permitted to access. Authorization is distinct from authentication and is not affected by the commands defined in this specification. {{RFC6749}} §1.1

**Access Token**
A credential issued by an Authorization Server that represents the authorization granted to a client to access protected resources at a Resource Server. Access tokens have a limited lifetime and may be self-contained (e.g., JWT) or reference-based. {{RFC6749}} §1.4

**API Key**
A long-lived, static credential issued by the RP (not the Authorization Server) that grants API access to the RP's resources on behalf of a subject. API keys include service keys, personal access tokens (PATs), and static bearer tokens. Unlike OAuth tokens, API keys are typically not bound to an OAuth grant, are not rotated via refresh tokens, and may have no expiration. API keys are authentication artifacts and are within the scope of the Invalidate Authentication State command.

**Assertion**
A statement from an Identity Provider to a Relying Party that conveys information about an authentication event and the authenticated subject. In OIDC, the ID Token serves as the assertion; in SAML, the `<Assertion>` element. {{NIST.SP.800-63C}} §4, {{OIDC.Core}} §2, {{SAML2.Core}} §2.3

**Authorization Server (AS)**
The server that issues access tokens and refresh tokens to a client after successfully authenticating the resource owner and obtaining authorization. {{RFC6749}} §1.1

**Expire**
To end the validity of an artifact (session, token, assertion) so that it is no longer accepted. Expiration may occur naturally when a time-based validity period ends (e.g., an assertion's `exp` claim at SL1), or on demand when requested by the IdP (the Expire Session State command at SL2). In both cases, expiration is a normal lifecycle event, not an indication of a security incident. {{RFC6749}} §1.5, {{OIDC.Core}} §3.1.3.7 (`exp` claim)

**Identity Provider (IdP)**
The entity that authenticates subjects and issues assertions to Relying Parties. Also referred to as OpenID Provider (OP) in OIDC and Identity Provider (IdP) in SAML. {{OIDC.Core}} §1.2, {{SAML2.Core}} §2.2

**Reauthentication**
The process of confirming the subscriber's continued presence and intent by performing a new primary authentication event at the Identity Provider, rather than relying on an existing session. Reauthentication is triggered when a prior authentication is no longer sufficient due to session expiry, security policy, or risk events. {{NIST.SP.800-63B}} §7.2

**Refresh Token**
A credential issued by an Authorization Server that a client uses to obtain new access tokens without requiring the resource owner to reauthenticate. Refresh tokens are typically long-lived and revocable. {{RFC6749}} §1.5

**Relying Party (RP)**
The application or service that depends on the Identity Provider for authentication of subjects. Also referred to as Service Provider (SP) in SAML or Client in OAuth. {{OIDC.Core}} §1.2, {{SAML2.Core}} §2.2, {{NIST.SP.800-63C}} §4

**Resource Server (RS)**
The server hosting protected resources, capable of accepting and responding to requests using access tokens. {{RFC6749}} §1.1

**Invalidate**
To render an artifact (token, session, API key, or authentication state) no longer valid or trustworthy, regardless of its remaining lifetime. Invalidation is an active security operation, typically in response to a security event. In this specification, "Invalidate Authentication State" denotes the IdP-initiated command to invalidate all prior authentication artifacts for a subject. {{NIST.SP.800-63B}} §7.1

**Revoke / Revocation**
The act of explicitly canceling a specific credential or token before its natural expiration, rendering it permanently unusable. Revocation is a specific form of invalidation applied to individual artifacts. {{RFC7009}} §1

**Session**
A temporary, stateful security context that is established after a successful authentication event and allows a subject to continue accessing a system without reauthenticating for each request. Sessions are time-limited, context-bound, and revocable. {{NIST.SP.800-63B}} §7, {{OIDC.Core}} §15.5.1

**Single Sign-On (SSO)**
A mechanism that allows a subject to authenticate once at an Identity Provider and subsequently access multiple Relying Parties without reauthenticating at each one, for the duration of the IdP session. {{NIST.SP.800-63C}} §5.3

**Subject**
The entity (user, device, or workload) whose identity is asserted by the Identity Provider. {{OIDC.Core}} §2 (`sub` claim), {{SAML2.Core}} §2.4

## Reference Deployment Model {#deployment-model}

The following diagram illustrates a common SaaS deployment where the Application acts as an RP to the enterprise IdP but also operates its own first-party Authorization Server that issues access tokens and refresh tokens to its own first-party clients (web app, mobile app, CLI).

~~~ ascii-art
+---------------------------------------------------------------------+
|  Enterprise                                                         |
|                                                                     |
|  +-----------------------+                                          |
|  |  Identity Provider    |                                          |
|  |  (IdP)                |                                          |
|  |                       |                                          |
|  |  +-----------------+  |    Lifecycle Commands                    |
|  |  | IdP SSO Session |  |- - - - - - - - - - - - - - +            |
|  |  +-----------------+  |    (expire / invalidate)    |            |
|  +-----------------------+                             v            |
|                                                                     |
|  +--------------------------------------------------------------+   |
|  |  SaaS Application (RP)                                       |   |
|  |                                                              |   |
|  |  +----------------------------------------------------------+|   |
|  |  |  Application Server                                      ||   |
|  |  |                                                          ||   |
|  |  |  +-----------------+    +----------------------+         ||   |
|  |  |  | RP Client       |    | 1st-Party            |         ||   |
|  |  |  | Sessions        |    | Authorization Server |         ||   |
|  |  |  |                 |    |                      |         ||   |
|  |  |  | o Web sessions  |    | o Access tokens      |         ||   |
|  |  |  | o App sessions  |    | o Refresh tokens     |         ||   |
|  |  |  +-----------------+    +----------------------+         ||   |
|  |  |                                                          ||   |
|  |  |  +-----------------+    +----------------------+         ||   |
|  |  |  | API Keys        |    | Resource Server(s)   |         ||   |
|  |  |  |                 |    |                      |         ||   |
|  |  |  | o Service keys  |    | o APIs               |         ||   |
|  |  |  | o PATs          |    | o Protected          |         ||   |
|  |  |  | o Static tokens |    |   resources          |         ||   |
|  |  |  +-----------------+    +----------------------+         ||   |
|  |  +----------------------------------------------------------+|   |
|  +--------------------------------------------------------------+   |
|                         ^           ^           ^                   |
|                         |           |           |                   |
|                    +---------+ +---------+ +---------+              |
|                    | Web App | | Mobile  | |  CLI    |              |
|                    |         | |  App    | |         |              |
|                    +---------+ +---------+ +---------+              |
|                         1st-Party Clients                           |
+---------------------------------------------------------------------+
~~~

In this model, the SaaS Application is both:

- A **Relying Party (RP)** that depends on the enterprise IdP for user authentication via SSO
- A **first-party Authorization Server** that issues its own OAuth access tokens and refresh tokens to its own clients (web app, mobile app, CLI)

The authentication artifacts managed by the SaaS Application include:

| Artifact | Issuer | Description |
|----------|--------|-------------|
| RP client sessions | Application | Browser cookie sessions, native-app session tokens |
| Access tokens | Application (1st-party AS) | Short-lived tokens issued to 1st-party clients for API access |
| Refresh tokens | Application (1st-party AS) | Long-lived tokens used by 1st-party clients to obtain new access tokens |
| API keys | Application | Service keys, PATs, and static bearer tokens issued to users |

## Command Effects on This Deployment

**Expire Session State** — IdP sends `expire`:

~~~ ascii-art
IdP --expire--> SaaS Application (RP)
                    |
                    +-- RP client sessions ......... EXPIRE
                    +-- Access tokens .............. unchanged
                    +-- Refresh tokens ............. unchanged
                    +-- API keys ................... unchanged
~~~

All of the user's interactive sessions are expired. First-party clients holding valid access tokens or refresh tokens continue to operate. Background API integrations using API keys are unaffected. The user must reauthenticate at the IdP to establish a new session.

**Invalidate Authentication State** — IdP sends `invalidate`:

~~~ ascii-art
IdP --invalidate--> SaaS Application (RP)
                        |
                        +-- RP client sessions ......... INVALIDATE
                        +-- Access tokens .............. INVALIDATE
                        +-- Refresh tokens ............. INVALIDATE
                        +-- API keys ................... REVOKE
                        |
                        |   1st-Party AS
                        +-- Revoke refresh tokens at AS
                        +-- Revoke/invalidate access tokens at AS
~~~

All authentication artifacts for the subject are invalidated or revoked. Access tokens held by first-party clients will be invalid on next use. Refresh token rotation will fail. API key-based integrations will stop functioning. The user and all automated integrations must reauthenticate at the IdP and obtain new credentials.

**Note on composition:** In this deployment, the SaaS Application is both the RP and the AS. The RP can invalidate sessions, tokens, and API keys in a single internal operation — no separate AS-side revocation protocol is needed. The protocol composition requirement in Section 4.3.2 applies when the RP and AS are separate entities (e.g., the enterprise IdP also serves as the AS for third-party applications).


# Lifecycle Command Definitions {#commands}

## Expire Session State {#cmd-expire}

An IdP command requiring the RP to expire **all** of the subject's RP client sessions and require reauthentication before continuing. This is the on-demand equivalent of the session expiry behavior at SL1, where the RP expires sessions when the assertion's validity period ends — but triggered by the IdP rather than by a time-based claim.

**Scope:** All RP client sessions for the subject — browser cookie sessions, native-app session tokens, and any other interactive session state.

### RP Requirements {#expire-rp}

When an RP receives this command, it **MUST**:

1. Expire all RP client sessions for the subject
2. Expire all associated session identifiers (delete session cookies, expire native-app session tokens)
3. Require **reauthentication** at the IdP (see Section 3)
4. NOT silently re-establish the session using existing tokens or SSO cookies

The RP **MUST NOT**:

- Revoke OAuth access tokens or refresh tokens at the Authorization Server
- Revoke API keys (service keys, personal access tokens, static bearer tokens)
- Treat this as authorization revocation or change roles/permissions

### IdP Requirements {#expire-idp}

When an IdP sends this command, it **MAY**:

- Expire the IdP SSO session (deployment-dependent)

### Resulting State {#expire-state}

| Artifact | State |
|----------|-------|
| RP client session | **Expired** |
| OAuth access tokens | **Unchanged** |
| OAuth refresh tokens | **Unchanged** |
| API keys | **Unchanged** |
| IdP SSO session | **MAY** be expired |
| Authorization grants | **Unchanged** |

### CAEP Events (SL3) {#expire-caep}

At **SL3**, the RP **SHOULD** publish the following CAEP events after processing an Expire Session State command:

| CAEP Event | URI | Purpose |
|------------|-----|---------|
| **Session Revoked** | `https://schemas.openid.net/secevent/caep/event-type/session-revoked` | Notify the ecosystem that the subject's RP client session has been expired |

The RP **SHOULD** include the following claims in the `session-revoked` event:

- `sub` — the subject whose session was expired
- `reason_admin` — indicate that the session was expired at IdP request (e.g., `"Session expired by IdP command"`)
- `event_timestamp` — the time at which the RP expired the session

The RP **SHOULD NOT** publish `credential-change` events for Expire Session State, as tokens and API keys are unaffected.

## Invalidate Authentication State {#cmd-invalidate}

An IdP command requiring all existing authentication artifacts to be treated as untrusted, including sessions, access tokens, refresh tokens, and API keys.

**Scope:** All prior authentication state — sessions, tokens, and API keys.

### RP Requirements {#revoke-rp}

When an RP receives this command, it **MUST**:

1. Perform all "Expire Session State" steps (Section 2.1.1)
2. Invalidate all existing access tokens for the subject
3. Invalidate all existing refresh tokens for the subject
4. Revoke all API keys for the subject (service keys, personal access tokens, static bearer tokens)
5. Require **reauthentication** at the IdP (see Section 3)
6. Stop any background API operations using existing tokens or API keys

The RP **MUST NOT**:

- Accept tokens or API keys that were issued before the invalidation event
- Treat this as authorization revocation or change roles/permissions

### IdP Requirements {#revoke-idp}

When an IdP sends this command, it **MUST**:

1. Invalidate the IdP SSO session
2. Revoke refresh tokens for the subject at the Authorization Server
3. Revoke or invalidate access tokens for the subject
4. Ensure Resource Servers can detect token invalidation

### Resulting State {#revoke-state}

| Artifact | State |
|----------|-------|
| RP client session | **Invalidated** |
| OAuth access tokens | **Invalidated** |
| OAuth refresh tokens | **Revoked** |
| API keys | **Revoked** |
| IdP SSO session | **Invalidated** |
| Authorization grants | **Unchanged** |

### CAEP Events (SL3) {#invalidate-caep}

At **SL3**, the RP **SHOULD** publish the following CAEP events after processing an Invalidate Authentication State command:

| CAEP Event | URI | Purpose |
|------------|-----|---------|
| **Session Revoked** | `https://schemas.openid.net/secevent/caep/event-type/session-revoked` | Notify the ecosystem that the subject's RP client session has been invalidated |
| **Credential Change** | `https://schemas.openid.net/secevent/caep/event-type/credential-change` | Notify the ecosystem that tokens and API keys for the subject have been invalidated or revoked |

The RP **SHOULD** include the following claims in the `session-revoked` event:

- `sub` — the subject whose session was invalidated
- `reason_admin` — indicate the security context (e.g., `"Authentication state invalidated by IdP command"`)
- `event_timestamp` — the time at which the RP invalidated the session

The RP **SHOULD** publish separate `credential-change` events for each credential type affected:

| Credential type | Change type | Description |
|-----------------|-------------|-------------|
| `access_token` | `revoke` | Access tokens invalidated |
| `refresh_token` | `revoke` | Refresh tokens invalidated |
| `api_key` | `revoke` | API keys revoked |

Publishing these events enables downstream Resource Servers and other participants in the SSF stream to stop accepting artifacts for the subject without waiting for token expiry or polling for revocation status.

## Command Processing Semantics {#command-semantics}

### Atomicity {#command-atomicity}

Each command **MUST** either complete fully or fail. Partial completion is not acceptable — the RP **MUST NOT** report success if any required step has not been performed.

If the RP requires asynchronous processing to complete a command (e.g., AS-side token revocation involves an external call), the RP **MUST** use a protocol that supports asynchronous completion (e.g., returning a pending status and confirming completion later). The RP **MUST NOT** report success before all steps are complete.

If any step fails (e.g., AS is unreachable for token revocation), the RP **MUST** report failure. The IdP **SHOULD** retry failed commands.

### Idempotency {#command-idempotency}

Commands **MUST** be idempotent. If the RP receives the same command multiple times (e.g., due to IdP retry after a network failure), it **MUST** process the command and report success, even if the resulting state has already been achieved by a prior command.

The RP **MAY** use the `jti` claim (when present) to detect duplicate commands for logging purposes, but **MUST NOT** reject a command solely because a command with the same `jti` was previously processed.

### Command Ordering {#command-ordering}

Invalidate Authentication State is a strict superset of Expire Session State — it includes all session expiry steps plus token invalidation and API key revocation.

If both commands are received for the same subject:

- **Expire Session State after Invalidate Authentication State:** The RP **MUST** succeed. The resulting state has already been achieved by the prior invalidation — all sessions are already invalidated and tokens revoked. No further action is needed.
- **Invalidate Authentication State after Expire Session State:** The RP **MUST** process the full Invalidate Authentication State command. Sessions may already be expired, but the RP must additionally invalidate tokens and revoke API keys.

In general, the RP **SHOULD** apply each command to the current state of the subject's artifacts. A command succeeds if the resulting state defined in Sections 2.1.3 or 2.2.3 is achieved, regardless of what prior state existed.


# Reauthentication Requirement {#fresh-auth}

Both commands require the RP to obtain **reauthentication** — a new primary authentication event at the IdP, not reuse of an existing SSO session.

## RP Requirements {#fresh-auth-rp}

The RP **MUST**:

1. Redirect the user to the IdP for authentication
2. Prevent silent SSO reuse (force user interaction)
3. Obtain a new authentication assertion or token with a **new session identifier**
4. Validate that the authentication time is recent and not from a prior session
5. Establish a new RP client session bound to the new assertion

**Note:** Reauthentication is not an extension of assurance for an existing session — it is a reevaluation of access through a new primary authentication event. The RP MUST obtain a new session identifier from the IdP (e.g., a new `sid` in OIDC or a new `SessionIndex` in SAML) and MUST NOT reuse or extend the prior session. {{NIST.SP.800-63B}} §7.2

## Protocol Controls for Reauthentication {#fresh-auth-controls}

| Protocol | Mechanism | Effect |
|----------|-----------|--------|
| **OIDC** | `prompt=login` and/or `max_age=0` | Forces re-authentication, disallows SSO session reuse |
| **SAML** | `ForceAuthn="true"` | Requires new authentication event |

The RP **MUST** validate `auth_time` (OIDC) or `AuthnInstant` (SAML) to confirm reauthentication. The RP **SHOULD** reject authentications that appear to reuse prior sessions.


# Protocol Mappings {#protocol-mappings}

A protocol maps to a command only if it can **fully complete** that command. Protocols that cover only part of a command's scope (e.g., token revocation without session invalidation) cannot fulfill a command on their own and are listed as **composition components** where applicable.

## Completeness Requirement {#completeness}

Each command defines a complete resulting state (Sections 2.1.3 and 2.2.3). A protocol implementation **MUST** achieve the full resulting state of a command to claim support for that command. Partial fulfillment is not sufficient.

**Implication:** It is acceptable for a protocol to support only one of the two commands. For example, OIDC Back-Channel Logout can fully complete "Expire Session State" but cannot on its own complete "Invalidate Authentication State" (it does not revoke tokens). Similarly, OAuth Token Revocation {{RFC7009}} revokes tokens but does not expire RP client sessions, so it cannot complete either command alone.

## Expire Session State — Protocol Mappings {#expire-mappings}

The following protocols can **fully complete** the Expire Session State command because they expire the RP client session and trigger reauthentication.

### OIDC Back-Channel Logout (RECOMMENDED) {#expire-bcl}

**Specification:** {{OIDC.BackChannelLogout}}

| Element | Value / Behavior |
|---------|-----------------|
| Trigger | IdP sends a Logout Token to the RP's registered `backchannel_logout_uri` |
| Token type | JWT with `"events": {"http://schemas.openid.net/event/backchannel-logout": {}}` |
| Subject identification | `sub` claim and/or `sid` (session ID) claim |
| RP behavior | Expire the RP client session(s) matching `sub`/`sid`; do NOT revoke OAuth tokens |
| IdP SSO session | MAY be expired independently |
| **Completes command?** | **Yes** — fully satisfies Expire Session State |

**RP Implementation:**

1. Validate the Logout Token signature against IdP JWKS
2. Verify `iss`, `aud`, `iat`, and `events` claims
3. Look up local session(s) by `sub` and/or `sid`
4. Expire matching RP client sessions
5. On next user interaction, redirect to IdP with `prompt=login`

### OIDC Front-Channel Logout (ACCEPTABLE) {#expire-fcl}

**Specification:** {{OIDC.FrontChannelLogout}}

| Element | Value / Behavior |
|---------|-----------------|
| Trigger | IdP renders an iframe pointing to the RP's `frontchannel_logout_uri` |
| Parameters | `iss` and `sid` (if session management supported) |
| RP behavior | Clear session cookies and expire server-side session state |
| **Completes command?** | **Conditionally** — only when browser is active and iframes/cookies are not blocked |

**Limitations:** Fails if browser is closed, third-party cookies are blocked, or iframes are suppressed. **NOT RECOMMENDED** as sole mechanism.

### SAML 2.0 Single Logout (ACCEPTABLE) {#expire-saml-slo}

**Specification:** {{SAML2.Profiles}} Section 4.4

| Element | Value / Behavior |
|---------|-----------------|
| Trigger | IdP sends `<LogoutRequest>` to SP |
| Binding | HTTP-Redirect (front-channel) or SOAP (back-channel) |
| Subject identification | `<NameID>` matching the original assertion |
| Session identification | `<SessionIndex>` from the original `<AuthnStatement>` |
| SP behavior | Expire the RP client session matching the NameID/SessionIndex; respond with `<LogoutResponse>` |
| **Completes command?** | **Yes** (back-channel SOAP) / **Conditionally** (front-channel) |

**SP Implementation (back-channel SOAP binding):**

1. Validate `<LogoutRequest>` signature
2. Verify `Issuer`, `Destination`, `NameID`
3. Look up local session by `NameID` and `SessionIndex`
4. Expire matching session
5. Return `<LogoutResponse>` with `Success` status
6. On next user interaction, redirect to IdP with `ForceAuthn="true"`

**Limitations:** Front-channel binding is browser-dependent and fragile in multi-SP deployments. SOAP back-channel is more reliable but less widely implemented.

### OpenID Provider Commands: `expire` (RECOMMENDED) {#expire-op-commands}

**Specification:** {{OP-Commands}}

This specification defines a new OP Command type **`expire`** that maps to the Expire Session State lifecycle command.

| Element | Value / Behavior |
|---------|-----------------|
| Trigger | IdP sends a Command Token to the RP's registered command endpoint |
| Command type | `expire` |
| Token type | JWT with `typ: command+jwt`, signed with IdP signing keys |
| Required claims | `iss`, `aud`, `client_id`, `iat`, `exp`, `jti`, `command`, `tenant`, `sub` |
| RP behavior | Expire all RP client sessions for the subject; do NOT revoke OAuth tokens; require reauthentication |
| **Completes command?** | **Yes** — fully satisfies Expire Session State |

**RP Implementation:**

1. Validate Command Token signature against IdP JWKS
2. Verify `typ` is `command+jwt`
3. Verify `iss`, `aud`, `iat`, `exp`, `jti`, and `command` claims
4. Confirm `command` value is `expire`
5. Look up all sessions by `sub` (and `tenant` if applicable)
6. Expire all matching RP client sessions
7. Return success response
8. On next user interaction, redirect to IdP with `prompt=login`

## Invalidate Authentication State — Protocol Mappings {#revoke-mappings}

### OpenID Provider Commands: `invalidate` (RECOMMENDED) {#revoke-op-invalidate}

**Specification:** {{OP-Commands}}

The existing OP Command type **`invalidate`** maps to the Invalidate Authentication State lifecycle command. When the IdP sends `invalidate`, it signals that all prior authentication artifacts for the subject must be treated as untrusted.

| Element | Value / Behavior |
|---------|-----------------|
| Trigger | IdP sends a Command Token to the RP's registered command endpoint |
| Command type | `invalidate` |
| Token type | JWT with `typ: command+jwt`, signed with IdP signing keys |
| Required claims | `iss`, `aud`, `client_id`, `iat`, `exp`, `jti`, `command`, `tenant`, `sub` |
| RP behavior | Invalidate RP client session, invalidate all existing access and refresh tokens, revoke all API keys for the subject, require reauthentication |
| **Completes command?** | **Session layer: Yes. Token layer: requires composition** (see below) |

**RP Implementation:**

1. Validate Command Token signature against IdP JWKS
2. Verify `typ` is `command+jwt`
3. Verify `iss`, `aud`, `iat`, `exp`, `jti`, and `command` claims
4. Confirm `command` value is `invalidate`
5. Look up all sessions and tokens by `sub` (and `tenant` if applicable)
6. Invalidate matching RP client sessions
7. Invalidate all existing access tokens for the subject
8. Invalidate all existing refresh tokens for the subject
9. Revoke all API keys for the subject (service keys, personal access tokens, static bearer tokens)
10. Return success response
11. On next user interaction, redirect to IdP with `prompt=login`

**Note:** The `invalidate` command instructs the RP to invalidate sessions and tokens, **and** revoke API keys at the RP. However, token revocation at the Authorization Server (and RS-side enforcement for self-contained JWTs) still requires composition with OAuth protocols. API key revocation is handled entirely by the RP since API keys are RP-issued credentials. See Section 4.3.3.

### Composition Requirement for Token Revocation {#revoke-why-composition}

While `invalidate` handles the RP-side enforcement (session invalidation + token invalidation), **AS-side token revocation** requires additional protocols. Without AS-side revocation, tokens may still be accepted by other Resource Servers that do not receive the `invalidate` command.

| Protocol | Invalidates RP session? | RP invalidates tokens? | Revokes API keys? | AS revokes tokens? | Completes full command alone? |
|----------|----------------------|-------------------|------------------|-------------------|------------------------------|
| OP Commands (`invalidate`) | Yes | Yes | Yes | No | **No** — needs AS-side revocation |
| OIDC Back-Channel Logout | Yes | No | No | No | **No** |
| SAML 2.0 Single Logout | Yes | No | No | No | **No** |
| OAuth Token Revocation (RFC 7009) | No | No | No | Yes (per-token) | **No** |
| OAuth Global Token Revocation | No | No | No | Yes (all tokens) | **No** |

To fully complete Invalidate Authentication State across the ecosystem, implementations MUST compose protocols:

| Layer | Protocol | Requirement |
|-------|----------|-------------|
| **RP session + RP token invalidation + API key revocation** | OP Commands (`invalidate`) — or — OIDC Back-Channel Logout / SAML SLO (session only; RP must additionally invalidate tokens and revoke API keys) | **REQUIRED** |
| **IdP SSO session** | IdP-side logout | **REQUIRED** |
| **AS-side token revocation** | OAuth 2.0 Token Revocation {{RFC7009}} or Global Token Revocation | **REQUIRED** |

**Note:** When the RP operates its own first-party Authorization Server (see Section 1.4), the RP handles both RP-side and AS-side token revocation internally. In this case, no separate AS-side revocation protocol is needed — the RP fulfills the AS-side requirement as part of its own command processing.

### Composition Components {#revoke-components}

The following protocols participate as **components** in the Invalidate Authentication State composition for AS-side and RS-side enforcement.

**OAuth 2.0 Token Revocation — RFC 7009 (token layer)**

| Element | Value / Behavior |
|---------|-----------------|
| Trigger | IdP (acting as or coordinating with the AS) revokes tokens |
| Endpoint | `POST /revoke` with `token` and `token_type_hint` |
| Scope | Revokes specified token; AS **SHOULD** also invalidate related tokens (e.g., revoking a refresh token invalidates its access tokens) |
| IdP behavior | Revoke all refresh tokens for the subject |
| **Alone?** | **No** — does not invalidate RP client sessions |

**OAuth 2.0 Global Token Revocation (token layer)**

| Element | Value / Behavior |
|---------|-----------------|
| Trigger | IdP requests revocation of all tokens for a subject |
| Scope | All access tokens and refresh tokens for the subject at the AS |
| Advantage | Single request revokes all tokens vs. per-token revocation |
| **Alone?** | **No** — does not invalidate RP client sessions |

**Shared Signals / CAEP (supplementary notification)**

| Element | Value / Behavior |
|---------|-----------------|
| Event type | `session-revoked` or `credential-change` |
| Purpose | Ecosystem-wide notification of invalidation event |
| Limitation | Informational by default; requires enforcement profile for mandatory RP enforcement |
| **Alone?** | **No** — does not invalidate sessions or revoke tokens |

**MUST NOT** be the sole mechanism for this command. Useful as supplementary broadcast.

## Protocol Mapping Summary {#mapping-summary}

Both commands are **REQUIRED at SL2**. The following table summarizes which command each protocol can fully complete.

| Protocol | Expire Session State (SL2) | Invalidate Authentication State (SL2) |
|----------|---------------------|----------------------------|
| **OP Commands (`expire`)** | **RECOMMENDED** — completes command | Not applicable |
| **OP Commands (`invalidate`)** | Not applicable | **RECOMMENDED** — completes RP-side (sessions + tokens + API keys); compose with AS-side revocation |
| **OIDC Back-Channel Logout** | **RECOMMENDED** — completes command | Component only — session layer |
| **OIDC Front-Channel Logout** | ACCEPTABLE — completes conditionally | Component only — session layer |
| **SAML 2.0 Single Logout** | ACCEPTABLE — completes command | Component only — session layer |
| **OAuth Token Revocation (RFC 7009)** | Not applicable | Component only — AS-side token revocation |
| **OAuth Global Token Revocation** | Not applicable | Component only — AS-side token revocation |
| **Shared Signals (CAEP)** | Not applicable | Supplementary notification only |


# Recommended Protocol Combinations {#recommendations}

Implementations conforming to **SL2** MUST support at least one protocol or protocol combination that **fully completes** each command.

## Expire Session State (SL2 REQUIRED) {#rec-expire}

A single protocol can fully complete this command.

**Primary (RECOMMENDED):**
- OP Commands (`expire`)
- OIDC Back-Channel Logout

**Fallback (ACCEPTABLE):**
- SAML 2.0 SLO (back-channel SOAP binding)

## Invalidate Authentication State (SL2 REQUIRED) {#rec-revoke}

Composition is **REQUIRED** to achieve full ecosystem coverage (RP-side + AS-side).

**Strong Coverage (RECOMMENDED):**

| Layer | Protocol |
|-------|----------|
| RP session + tokens + API keys | OP Commands (`invalidate`) |
| IdP session | IdP-side logout (automatic) |
| AS-side token revocation | OAuth Global Token Revocation |

**Standard Coverage (ACCEPTABLE):**

| Layer | Protocol |
|-------|----------|
| RP session + tokens + API keys | OP Commands (`invalidate`) |
| IdP session | IdP-side logout (automatic) |
| AS-side token revocation | OAuth Token Revocation (RFC 7009) |

**Legacy Coverage (ACCEPTABLE):**

| Layer | Protocol |
|-------|----------|
| RP session | OIDC Back-Channel Logout (RP must additionally invalidate tokens and revoke API keys) |
| IdP session | IdP-side logout (automatic) |
| AS-side token revocation | OAuth Token Revocation (RFC 7009) |


# Suggested Protocol Extensions {#extensions}

The following extensions would improve the ability to implement these commands with clear semantics and guaranteed enforcement. These are suggestions for future standardization work.

## OpenID Provider Commands: `expire` Command Registration {#ext-op-expire}

**Problem:** The OP Commands specification defines `invalidate` but does not define a session-only expiry command. The `invalidate` command implies full authentication revocation, which is too broad for the Expire Session State use case.

**Proposed Registration:** Register `expire` as a new OP Command type.

| Field | Value |
|-------|-------|
| Command name | `expire` |
| Command type | Account Command |
| Description | Expire the subject's RP client session. The RP MUST expire the session and require reauthentication. The RP MUST NOT revoke OAuth tokens. |
| Required claims | `iss`, `aud`, `client_id`, `iat`, `exp`, `jti`, `command`, `tenant`, `sub` |
| Lifecycle command | Expire Session State (Section 2.1) |

**Relationship to `invalidate`:**

| OP Command | Lifecycle Command | Session | Tokens | API Keys |
|------------|-------------------|---------|--------|----------|
| `expire` | Expire Session State | Expire | Unchanged | Unchanged |
| `invalidate` | Invalidate Authentication State | Invalidate | Invalidate all | Revoke all |

The RP **MUST** treat `expire` and `invalidate` as distinct commands with different scopes. Receiving `expire` **MUST NOT** trigger token invalidation; receiving `invalidate` **MUST** trigger both session invalidation and token invalidation.

## CAEP: Enforcement Profile for Session Lifecycle {#ext-caep-enforcement}

**Problem:** CAEP events are informational by default. An IdP cannot mandate that an RP act on a `session-revoked` event.

**Suggested Extension:** Define an enforcement profile that:

1. Maps CAEP event types to the commands defined in this specification
2. Requires the receiver to enforce the mapped command
3. Requires the receiver to report enforcement status

| CAEP Event | Mapped Command | Enforcement |
|------------|----------------|-------------|
| `session-revoked` (reason: `logout`, `timeout`, `step-up`) | Expire Session State | **MUST** expire RP session |
| `session-revoked` (reason: `policy-violation`, `compromise`) | Invalidate Authentication State | **MUST** invalidate session and tokens, and revoke API keys |
| `credential-change` | Invalidate Authentication State | **MUST** invalidate session and tokens, and revoke API keys |


# Self-Contained JWT Access Token Considerations {#jwt-tokens}

Self-contained JWT access tokens present a unique challenge for "Invalidate Authentication State" because they are validated locally by the Resource Server without contacting the Authorization Server. If the RP cannot invalidate these tokens on demand, the token lifetime becomes the maximum exposure window during which an invalidated token may still be accepted.

## On-Demand Invalidation {#jwt-on-demand}

RPs that can invalidate self-contained access tokens immediately upon receiving an Invalidate Authentication State command — for example, via revocation lists, status lists, or event-driven invalidation (CAEP/SSF) — are not subject to the maximum TTL constraints in Section 7.2.

| Strategy | Effectiveness | Tradeoff |
|----------|--------------|----------|
| **Revocation lists / status lists** | Strong — near-immediate | RS must fetch and check list (operational complexity) |
| **Event-driven invalidation** | Strong — near-immediate | RS must subscribe to events (CAEP/SSF) |

RPs that implement on-demand invalidation **MUST** invalidate self-contained access tokens within a reasonable time frame upon receiving the command.

## Maximum Token Lifetime {#jwt-max-ttl}

When the RP **cannot** invalidate self-contained access tokens on demand, the token lifetime is the sole control bounding the exposure window. In this case, self-contained access tokens **MUST** comply with the following maximum lifetime constraints:

| IPSIE Level | Maximum TTL | Rationale |
|-------------|-------------|-----------|
| **SL2** | **1 hour** | Bounds the exposure window to an acceptable duration for general enterprise use |
| **SL3** | **5 minutes** | Minimizes the exposure window for environments requiring continuous access evaluation |

The `exp` claim in a self-contained access token **MUST NOT** exceed the maximum TTL for the applicable IPSIE level, measured from the `iat` claim. Authorization Servers **MUST** enforce these limits at token issuance.

For "Invalidate Authentication State," implementers **SHOULD** implement on-demand invalidation (Section 7.1) rather than relying solely on token expiry.


# Security Considerations {#security}

- **Transport security:** All protocol messages **MUST** use TLS 1.2 or higher.
- **Message integrity:** Lifecycle commands **MUST** be authenticated (signed, MAC'd, or over authenticated channel).
- **Replay protection:** Lifecycle commands **SHOULD** include nonces or timestamps.
- **Authorization:** RPs **MUST** verify that lifecycle commands originate from the trusted IdP.
- **Fail-secure:** When command type is ambiguous or unknown, RPs **SHOULD** default to the more restrictive command (Invalidate Authentication State).
- **Enforcement gaps:** Browser-dependent mechanisms (Front-Channel Logout, front-channel SAML SLO) may fail silently. Implementers **SHOULD** prefer back-channel mechanisms.

--- back

# Change Log {#changelog}

* **Implementer's Draft 1 — 2025-XX-XX**
  * Initial publication
  * Defines two lifecycle commands: Expire Session State and Invalidate Authentication State
  * Comprehensive protocol mappings for OIDC, SAML, OAuth, Shared Signals
  * Suggested protocol extensions for command type signaling
  * Reauthentication requirements and JWT token considerations

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

This specification defines two lifecycle commands that an Identity Provider (IdP) can send to a Relying Party (RP) to manage federated session lifecycle — requiring the RP to reestablish a session through the IdP or to invalidate all authentication artifacts.

--- middle

# Introduction {#introduction}

This specification defines **two lifecycle commands** that an Identity Provider (IdP) can send to a Relying Party (RP) to manage the **federated session lifecycle**.

These commands affect **session validity and the continued acceptability of prior authentication artifacts**. They do **not** affect roles, permissions, entitlements, or authorization policy within the RP.

| Command | Scope | Typical Trigger |
|---------|-------|-----------------|
| **Reestablish Session** | All RP client sessions for the subject | Policy change, risk signal, logout, session management |
| **Invalidate Authentication State** | All sessions, tokens, and API keys | Account compromise, security incident |

## IdP Control by IPSIE Level {#lifecycle-levels}

The commands enable progressively greater IdP control over RP sessions. At SL1, the IdP influences session lifetime only through assertion claims — the RP expires sessions when the validity period ends. At SL2, the IdP can send commands at any time to require session reestablishment or full invalidation of authentication artifacts. At SL3, the IdP and RP additionally exchange continuous state signals. The following table summarizes what each level accomplishes:

| IPSIE Level | Session Termination Model | IdP Control | Artifact Scope |
|-------------|--------------------------|-------------|----------------|
| **SL1** | Time-based only — RP expires session when assertion validity period ends or timeout occurs | None — IdP sets lifetime via assertion claims (`exp`, `NotOnOrAfter`) | Sessions only |
| **SL2** | Time-based + on-demand — IdP can require session reestablishment or full authentication state invalidation at any time | Direct — IdP sends Reestablish Session or Invalidate Authentication State commands to RP | Sessions, tokens, API keys |
| **SL3** | Time-based + on-demand + continuous — RP and IdP exchange state changes in real time via Shared Signals | Continuous — bidirectional communication of session, device, and risk state changes via CAEP/SSF | Sessions, tokens, API keys + continuous signals |

## IPSIE Session Lifecycle Level Mapping {#level-mapping}

The commands defined in this specification map to the **IPSIE Session Lifecycle (SL) levels** as follows:

| IPSIE Level | Command | Requirement |
|-------------|---------|-------------|
| **SL1** | *(Not applicable)* | Session lifetime set from assertion; RP expires session when validity period ends |
| **SL2** | **Reestablish Session** | **REQUIRED** — RP MUST expire sessions on demand at IdP request and reestablish through the IdP, enabling access revalidation |
| **SL2** | **Invalidate Authentication State** | **REQUIRED** — RP MUST invalidate sessions and tokens, and revoke API keys at IdP request |
| **SL2** | **Self-contained token max TTL** | **1 hour** — when the RP cannot invalidate self-contained access tokens on demand (see Section 7) |
| **SL3** | Both commands + continuous access signals | RP and IdP MUST communicate session and device state changes |
| **SL3** | **Self-contained token max TTL** | **5 minutes** — when the RP cannot invalidate self-contained access tokens on demand (see Section 7) |

**SL2 conformance** requires that:

- The **Identity Service** MUST be able to send both Reestablish Session and Invalidate Authentication State commands to Applications
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
To end the validity of an artifact (session, token, assertion) so that it is no longer accepted. Expiration may occur naturally when a time-based validity period ends (e.g., an assertion's `exp` claim at SL1). Expiration is a normal lifecycle event, not an indication of a security incident. {{RFC6749}} §1.5, {{OIDC.Core}} §3.1.3.7 (`exp` claim)

**Identity Provider (IdP)**
The entity that authenticates subjects and issues assertions to Relying Parties. Also referred to as OpenID Provider (OP) in OIDC and Identity Provider (IdP) in SAML. {{OIDC.Core}} §1.2, {{SAML2.Core}} §2.2

**Forced Reauthentication**
An authentication intent in which the RP explicitly requires a fresh authentication event at the IdP, regardless of any existing IdP authentication session. The existing session MUST NOT be reused. The IdP MUST require a new primary authentication ceremony, the resulting authentication context MUST have a new `auth_time`, and previous authentication context values MUST NOT be relied upon. Both the Reestablish Session and Invalidate Authentication State commands require the RP to trigger Forced Reauthentication. See Section 3 for the full definition of authentication intents. {{NIST.SP.800-63B}} §7.2

**Session Continuation**
An authentication intent in which the RP requests authentication and the IdP determines that an existing authentication session satisfies the RP's stated authentication freshness and assurance requirements. No new authentication event occurs — the IdP reuses the existing session and its authentication context (`auth_time`, `acr`, `amr`). Session Continuation is the normal flow when the RP needs to reestablish local application state (e.g., after local session expiry, cookie loss, or RP-local logout) without requiring fresh authentication. See Section 3 for the full definition of authentication intents. {{NIST.SP.800-63C}} §5.3

**Step-Up Authentication**
An authentication intent in which the RP requires a higher level of assurance than is provided by the existing authentication session. The IdP evaluates whether the current authentication context satisfies the requested assurance and, if insufficient, requires additional authentication. The resulting authentication context reflects the updated assurance, including updated `acr`, `amr`, and `auth_time` as appropriate. See Section 3 for the full definition of authentication intents. {{NIST.SP.800-63B}} §7.2

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


# Federated Session Lifecycle {#session-lifecycle}

The Reestablish Session and Invalidate Authentication State commands affect RP session and authentication state in distinct ways — one expires sessions while preserving tokens, the other invalidates all artifacts. This section defines a **logical model** for the lifecycle of a federated authentication session at the Relying Party, providing a framework for understanding how each command transitions the subject's state. The model describes the states and transitions of **RP session and authentication-artifact state** — it does not model RP subscriber account lifecycle (e.g., provisioning, disabling, or deleting accounts), which is addressed separately by the IPSIE Account Lifecycle (AL) levels.

This model is **informational** — RPs are not required to implement these states or transitions internally. The normative requirements for RPs are defined by the lifecycle commands in Section 4. The model provides a shared vocabulary for reasoning about session state and the expected behavior of each command.

The IdP and RP manage sessions independently of each other — the federation protocol does not bind IdP session state to RP session state. {{NIST.SP.800-63C}} §5.3. This model describes the RP-side view of the federated session.

## Session State Diagram {#session-state-diagram}

~~~ ascii-art
                    +-------------------+
                    |  Unauthenticated  |<-----------------------+
                    +-------------------+                        |
                             |                                   |
                    (access protected resource)                  |
                             |                                   |
                             v                                   |
                    +-------------------+                        |
         +--------->|    Establish      |                        |
         |          +-------------------+                        |
         |                   |                                   |
         |          (session established)                        |
         |                   |                                   |
         |                   v                                   |
         |          +-------------------+                        |
         |          |      Active       |                        |
         |          +-------------------+                        |
         |           |    |       |    \                         |
         |           |    |       |     (user logout)            |
         |           |    |       |         \                    |
         |           v    v       v          v                   |
         |  +---------+ +-----------+ +------------+          |
         |  | Expired | | Suspended | | Terminated |          |
         |  +---------+ +-----------+ +------------+          |
         |       |             |               |                 |
         +-------+-------------+               +-----------------+
       (subject returns                   (subject returns
        to Establish)                      to Unauthenticated)
~~~

The lifecycle defines three progressive levels of IdP control over RP sessions, plus user-initiated logout:

| Level | State | Trigger | IdP Intent | Tokens & API Keys |
|-------|-------|---------|-----------|-------------------|
| **1. Check-back** | **Expired** | Time-based expiry (inactivity or absolute timeout) | "Come back so I can re-evaluate" | Unchanged |
| **2. Suspend** | **Suspended** | Reestablish Session command | "Get a fresh session — full re-evaluation required" | Unchanged |
| **3. Terminate** | **Terminated** | Invalidate Authentication State command | "Kill everything — security event" | Invalidated / revoked |
| — | **Unauthenticated** | User-initiated logout | Subject clears RP state | RP session cleared |

## State Descriptions {#session-states}

**Unauthenticated:**
No session exists for the subject at the RP. The subject has not yet authenticated, all prior authentication state has been terminated, or the subject has logged out. This is the initial state, the return state after termination, and the return state after user-initiated logout. {{NIST.SP.800-63B}} §7.1

**Establish:**
The RP has initiated a federation transaction. The subject is redirected to the IdP for authentication. The authentication intent — Session Continuation, Step-Up Authentication, or Forced Reauthentication — depends on how the subject arrived at this state (see Section 3.6). The IdP authenticates the subject (or satisfies the request from an existing session when the authentication intent permits), issues an assertion — an OIDC ID Token or SAML `<Assertion>` — and delivers it to the RP. The RP validates the assertion (signature, issuer, audience, freshness), establishes a local RP client session bound to the assertion, and MAY issue OAuth access tokens and refresh tokens to first-party clients. The subject MAY create API keys. These artifacts collectively form the subject's **authentication state** at the RP. If any validation step fails, the subject remains Unauthenticated. {{NIST.SP.800-63C}} §5–6, {{OIDC.Core}} §3.1.2, {{SAML2.Core}} §3.4, {{NIST.SP.800-63B}} §7.1

**Active:**
The subject has an established session and is accessing RP resources using the session, tokens, and API keys. The RP enforces session validity, token lifetime, and authorization policy. Token refresh operations extend API access without requiring reauthentication. {{NIST.SP.800-63B}} §7.2

**Expired:**
The subject's RP client sessions are no longer valid due to time-based expiry. Expiry may be triggered by:

- **Inactivity timeout** — no subscriber activity within the configured timeout period {{NIST.SP.800-63B}} §7.2
- **Absolute timeout** — maximum session duration reached regardless of activity {{NIST.SP.800-63B}} §7.2

Tokens and API keys remain valid. The subject returns to the Establish state, where the IdP may satisfy the request via **Session Continuation** (reusing the existing IdP session) or **Step-Up Authentication** if the IdP's policy requires it. **Forced Reauthentication** may also be used but is not required. This is the IdP's opportunity to periodically re-evaluate whether the subject should continue to have access. {{OIDC.Core}} §3.1.3.7

**Suspended:**
The subject's RP client sessions are suspended — expired but with tokens and API keys remaining valid. Unlike the Expired state, the subject MUST return to the Establish state via **Forced Reauthentication** — Session Continuation and Step-Up Authentication are NOT sufficient. The IdP re-evaluates policy, risk, device posture, account state, and conditional access rules before deciding whether to issue a new assertion. See Section 4.3 for Forced Reauthentication requirements.

A session may be suspended by the **Reestablish Session** command from the IdP, or by RP-specific mechanisms such as account lockout, account recovery, administrative action, or risk-based policy enforcement. This specification defines the IdP-initiated trigger; RP-specific triggers are outside the scope of this specification but produce the same logical state.

**Terminated:**
All authentication artifacts — sessions, tokens, and API keys — have been invalidated or revoked via the **Invalidate Authentication State** command (SL2). This is the most severe level of IdP control, indicating a security event where prior authentication artifacts should no longer be trusted. The subject returns to the Unauthenticated state and must proceed through Establish via **Forced Reauthentication**. {{NIST.SP.800-63B}} §7.1

## Session State Transitions {#session-transitions}

| From | To | Trigger | Notes |
|------|----|---------|-------|
| Unauthenticated | Establish | Subject accesses protected resource | RP initiates federation transaction |
| Establish | Active | Assertion validated, session created | RP creates session, issues tokens |
| Establish | Unauthenticated | Assertion validation fails | No session created |
| Active | Expired | Inactivity timeout or absolute timeout | Time-based triggers (SL1) |
| Active | Suspended | **Reestablish Session** command | IdP-initiated access revalidation (SL2) |
| Active | Terminated | **Invalidate Authentication State** command | IdP-initiated security operation (SL2) |
| Active | Unauthenticated | User-initiated logout | Subject clears RP session state |
| Expired | Establish | Subject requests access | Session Continuation, Step-Up, or Forced Reauthentication |
| Suspended | Establish | Subject requests access | Forced Reauthentication ONLY |
| Terminated | Unauthenticated | *(immediate)* | All artifacts invalidated; must start fresh |
| Unauthenticated | Establish | Subject requests access | New federation transaction |

## Progressive IdP Control {#session-progressive-control}

The three terminal states — Expired, Suspended, and Terminated — represent a **progressive escalation** of IdP control over the RP session:

| | **Expired** | **Suspended** | **Terminated** |
|---|---|---|---|
| **IdP intent** | Periodic check-back | Full access revalidation | Security response |
| **Sessions** | Expired | Expired | Invalidated |
| **Tokens** | Unchanged | Unchanged | Invalidated |
| **API keys** | Unchanged | Unchanged | Revoked |
| **Authentication intent** | Session Continuation, Step-Up, or Forced Reauthentication | Forced Reauthentication only | Forced Reauthentication only |
| **IdP session** | May still be valid | MUST NOT be reused | Invalidated |
| **Returns to** | Establish | Establish | Unauthenticated |
| **IPSIE level** | SL1+ | SL2+ | SL2+ |

# Authentication Intents {#auth-intents}

When a Relying Party redirects a subject to the Identity Provider, the resulting authentication interaction falls into one of three intents. These intents are orthogonal to protocol mechanics and are derived from the RP's expressed requirements (e.g., `prompt`, `max_age`, `acr_values`) and the IdP's local policy and risk evaluation.

## Session Continuation {#intent-continuation}

**Session Continuation** occurs when a Relying Party requests authentication and the Identity Provider determines that an existing authentication session satisfies the RP's stated authentication freshness and assurance requirements.

In this intent, no new authentication event occurs.

### Properties {#continuation-properties}

When performing Session Continuation:

* An existing IdP authentication session **MUST** exist and remain valid.
* The IdP **MUST NOT** require the user to perform a new primary authentication ceremony.
* The existing authentication context, including `auth_time`, `acr`, and `amr`, **MUST** be preserved.
* New tokens **MAY** be issued to the RP.
* The IdP **MUST** treat the request as a continuation of the existing authentication session, not as a reauthentication.

### Typical Triggers {#continuation-triggers}

Session Continuation is commonly applicable when:

* An RP session has expired or been terminated locally.
* The user agent has restarted or lost RP cookies.
* The RP has performed an RP-local logout.
* The RP is re-establishing application state.

### Protocol Expression {#continuation-protocol}

An RP requesting Session Continuation **MUST NOT** include `prompt=login` (OIDC) or `ForceAuthn="true"` (SAML). The RP **MAY** use `prompt=none` (OIDC) or `IsPassive="true"` (SAML) to require silent continuation — if no valid IdP session exists, the IdP returns an error rather than prompting the user. The RP also:

* Omits `max_age` or supplies a value satisfied by the existing session.
* Does not request higher assurance via `acr_values`.

### IdP Behavior {#continuation-idp}

If the IdP determines that the existing authentication session satisfies the RP's requirements, the IdP **MUST** perform Session Continuation.

The IdP **MAY** override Session Continuation and require additional authentication based on risk signals or local policy.

## Step-Up Authentication {#intent-stepup}

**Step-Up Authentication** occurs when the Relying Party requires a higher level of assurance than is provided by the existing authentication session.

In this intent, the IdP performs additional authentication steps sufficient to satisfy the requested assurance level.

### Properties {#stepup-properties}

When performing Step-Up Authentication:

* An existing IdP authentication session **MUST** exist.
* The IdP **MUST** evaluate whether the current authentication context satisfies the requested assurance.
* If the assurance is insufficient, the IdP **MUST** require additional authentication.
* The IdP **MAY** reuse previously satisfied authentication factors.
* The resulting authentication context **MUST** reflect the updated assurance, including updated `acr`, `amr`, and `auth_time` as appropriate.

### Typical Triggers {#stepup-triggers}

Step-Up Authentication is commonly applicable when:

* Accessing sensitive or privileged resources.
* Performing high-risk transactions.
* Responding to increased risk signals (e.g., device change, location change).

### Protocol Expression {#stepup-protocol}

An RP requesting Step-Up Authentication typically:

* Requests a higher assurance level using `acr_values`.
* Optionally requests specific authentication methods via `claims`.

## Forced Reauthentication {#intent-forced}

**Forced Reauthentication** occurs when the Relying Party explicitly requires a fresh authentication event, regardless of any existing authentication session at the IdP.

In this intent, the existing authentication session **MUST NOT** be reused.

### Properties {#forced-properties}

When performing Forced Reauthentication:

* Any existing authentication session **MUST NOT** satisfy the request.
* The IdP **MUST** require a new primary authentication ceremony.
* The resulting authentication context **MUST** have a new `auth_time`.
* Previous authentication context values **MUST NOT** be relied upon.
* The RP **MUST** obtain a new session identifier (`sid` in OIDC, `SessionIndex` in SAML).

### Typical Triggers {#forced-triggers}

Forced Reauthentication is commonly applicable when:

* The RP has received a **Reestablish Session** command from the IdP.
* The RP has received an **Invalidate Authentication State** command from the IdP.
* An IdP-initiated logout or account recovery has occurred.
* Regulatory or security policy mandates reauthentication.

### Protocol Expression {#forced-protocol}

An RP requesting Forced Reauthentication **MUST**:

| Protocol | Mechanism | Effect |
|----------|-----------|--------|
| **OIDC** | `prompt=login` and/or `max_age=0` | Forces full authentication, disallows SSO session reuse |
| **SAML** | `ForceAuthn="true"` | Requires new authentication event |

The RP **MUST** validate `auth_time` (OIDC) or `AuthnInstant` (SAML) to confirm that a new authentication occurred. The RP **MUST** verify that the session identifier (`sid` / `SessionIndex`) is different from the prior session. The RP **SHOULD** reject authentications that appear to reuse prior sessions.

## Intent Comparison {#intent-comparison}

| | **Session Continuation** | **Step-Up Authentication** | **Forced Reauthentication** |
|---|---|---|---|
| **Purpose** | Reestablish local RP state | Elevate assurance for a specific operation | Access revalidation — IdP re-evaluates policy, risk, and state |
| **Existing IdP session** | Reused | Reused (with additional factors) | Not reused — new authentication required |
| **Authentication ceremony** | None | Additional factors only | Full primary authentication |
| **`auth_time`** | Preserved from existing session | Updated | New |
| **`acr` / `amr`** | Preserved | Updated to reflect elevated assurance | New — reflects fresh authentication |
| **Session identifier** | May be same or new | Unchanged | New — MUST differ from prior session |
| **RP session binding** | New RP session, existing IdP session | Existing RP session preserved | New RP session, new IdP authentication |
| **Tokens and API keys** | Unchanged | Unchanged | Unchanged (Reestablish Session) or invalidated (Invalidate Authentication State) |
| **IdP evaluation** | Validates existing session is sufficient | Evaluates assurance requirements | Full policy evaluation — risk, device posture, conditional access, account state |
| **Initiated by** | RP (no command received) | RP (for a specific operation) | RP (in response to IdP command) |

## Command Requirements {#intent-command-requirements}

Both lifecycle commands defined in this specification require the RP to trigger **Forced Reauthentication** when the subject next interacts with the RP. Session Continuation and Step-Up Authentication are **NOT** sufficient to satisfy either command.

| Command | Required Authentication Intent | Rationale |
|---------|------------------------------|-----------|
| **Reestablish Session** | Forced Reauthentication | The IdP must perform a full policy evaluation to determine whether to grant continued access. Reusing an existing session would bypass this evaluation. |
| **Invalidate Authentication State** | Forced Reauthentication | All prior authentication artifacts are invalidated. A completely new authentication is required. |

When no command has been received — for example, when the RP's local session has expired, cookies have been lost, or the RP has performed an RP-local logout — the RP **MAY** allow Session Continuation. In this case, the RP does not include `prompt=login` or `ForceAuthn="true"`, and the IdP may satisfy the request from an existing authentication session.

## Authentication Intent Requirements by Session State {#session-auth-intents}

The authentication intent used when the subject returns to the Establish state depends on the terminal state and how it was reached.

| Terminal State | Trigger | Allowed Authentication Intents | Rationale |
|---------------|---------|------------------------------|-----------|
| **Expired** | Inactivity timeout | Session Continuation, Step-Up, or Forced Reauthentication | IdP session may still be valid; IdP re-evaluates on check-back |
| **Expired** | Absolute timeout | Session Continuation, Step-Up, or Forced Reauthentication | IdP session may still be valid; IdP re-evaluates on check-back |
| **Suspended** | Reestablish Session command | **Forced Reauthentication ONLY** | IdP explicitly requires full policy re-evaluation; existing IdP session MUST NOT be reused |
| **Terminated** | Invalidate Authentication State command | **Forced Reauthentication ONLY** | Security event; all prior artifacts are untrusted; full authentication required |
| **Unauthenticated** | User-initiated logout | Session Continuation, Step-Up, or Forced Reauthentication | No command received; IdP session may still be valid |


# Lifecycle Command Definitions {#commands}

## Reestablish Session {#cmd-reestablish}

An IdP command requiring the RP to expire **all** of the subject's RP client sessions and reestablish them through a full authentication at the IdP. The purpose of this command is **access revalidation** — giving the IdP the opportunity to re-evaluate policy, risk, device posture, account state, and conditional access rules before allowing the subject to continue accessing the RP.

This command transitions the session to the **Suspended** state (see Section 2), which requires **Forced Reauthentication** — Session Continuation and Step-Up Authentication are not sufficient. This is distinct from time-based session expiry (the **Expired** state), where the IdP may satisfy the request via Session Continuation.

**Scope:** All RP client sessions for the subject — browser cookie sessions, native-app session tokens, and any other interactive session state.

### RP Requirements {#reestablish-rp}

When an RP receives this command, it **MUST**:

1. Expire all RP client sessions for the subject
2. Expire all associated session identifiers (delete session cookies, expire native-app session tokens)
3. Require **Forced Reauthentication** at the IdP (see Section 3.3)
4. NOT silently re-establish the session using existing tokens, SSO cookies, or Session Continuation

The RP **MUST NOT**:

- Revoke OAuth access tokens or refresh tokens at the Authorization Server
- Revoke API keys (service keys, personal access tokens, static bearer tokens)
- Treat this as authorization revocation or change roles/permissions

### IdP Requirements {#reestablish-idp}

When an IdP sends this command, it **MAY**:

- Expire the IdP SSO session (deployment-dependent)

### Resulting State {#reestablish-state}

| Artifact | State |
|----------|-------|
| RP client session | **Expired** |
| OAuth access tokens | **Unchanged** |
| OAuth refresh tokens | **Unchanged** |
| API keys | **Unchanged** |
| IdP SSO session | **MAY** be expired |
| Authorization grants | **Unchanged** |

## Invalidate Authentication State {#cmd-invalidate}

An IdP command requiring all existing authentication artifacts to be treated as untrusted, including sessions, access tokens, refresh tokens, and API keys. This command transitions the session to the **Terminated** state (see Section 2), which invalidates all artifacts and requires **Forced Reauthentication**. This is the most severe level of IdP control, indicating a security event.

**Scope:** All prior authentication state — sessions, tokens, and API keys.

### RP Requirements {#revoke-rp}

When an RP receives this command, it **MUST**:

1. Expire all RP client sessions for the subject
2. Expire all associated session identifiers (delete session cookies, expire native-app session tokens)
3. Invalidate all existing access tokens for the subject
4. Invalidate all existing refresh tokens for the subject
5. Revoke all API keys for the subject (service keys, personal access tokens, static bearer tokens)
6. Require **Forced Reauthentication** at the IdP (see Section 3.3)
7. Stop any background API operations using existing tokens or API keys

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

## CAEP Events (SL3) {#caep-events}

At **SL3**, the RP **SHOULD** publish CAEP events after processing lifecycle commands. This enables downstream Resource Servers and other participants in the SSF stream to stop accepting artifacts for the subject without waiting for token expiry or polling for revocation status.

### Reestablish Session Events {#caep-reestablish}

After processing a Reestablish Session command, the RP **SHOULD** publish:

| CAEP Event | URI | Purpose |
|------------|-----|---------|
| **Session Revoked** | `https://schemas.openid.net/secevent/caep/event-type/session-revoked` | Notify the ecosystem that the subject's RP client session has been expired |

The RP **SHOULD** include the following claims in the `session-revoked` event:

- `sub` — the subject whose session was expired
- `reason_admin` — indicate that session reestablishment was requested (e.g., `"Session reestablishment required by IdP"`)
- `event_timestamp` — the time at which the RP expired the session

The RP **SHOULD NOT** publish `credential-change` events for Reestablish Session, as tokens and API keys are unaffected.

### Invalidate Authentication State Events {#caep-invalidate}

After processing an Invalidate Authentication State command, the RP **SHOULD** publish:

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

## Command Processing Semantics {#command-semantics}

### Atomicity {#command-atomicity}

Each command **MUST** either complete fully or fail. Partial completion is not acceptable — the RP **MUST NOT** report success if any required step has not been performed.

If the RP requires asynchronous processing to complete a command (e.g., AS-side token revocation involves an external call), the RP **MUST** use a protocol that supports asynchronous completion (e.g., returning a pending status and confirming completion later). The RP **MUST NOT** report success before all steps are complete.

If any step fails (e.g., AS is unreachable for token revocation), the RP **MUST** report failure. The IdP **SHOULD** retry failed commands.

### Idempotency {#command-idempotency}

Commands **MUST** be idempotent. If the RP receives the same command multiple times (e.g., due to IdP retry after a network failure), it **MUST** process the command and report success, even if the resulting state has already been achieved by a prior command.

The RP **MAY** use the `jti` claim (when present) to detect duplicate commands for logging purposes, but **MUST NOT** reject a command solely because a command with the same `jti` was previously processed.

### Command Ordering {#command-ordering}

Invalidate Authentication State is a strict superset of Reestablish Session — it includes all session expiry steps plus token invalidation and API key revocation. In the session lifecycle model, Reestablish Session transitions to the **Suspended** state while Invalidate Authentication State transitions to the **Terminated** state (see Section 2.4).

If both commands are received for the same subject:

- **Reestablish Session after Invalidate Authentication State:** The RP **MUST** succeed. The session is already in the Terminated state — all artifacts are invalidated. No further action is needed.
- **Invalidate Authentication State after Reestablish Session:** The RP **MUST** process the full Invalidate Authentication State command. The session transitions from the Suspended state to the Terminated state. Sessions may already be expired, but the RP must additionally invalidate tokens and revoke API keys.

In general, the RP **SHOULD** apply each command to the current state of the subject's artifacts. A command succeeds if the resulting state defined in Sections 4.1.3 or 4.2.3 is achieved, regardless of what prior state existed.


# Protocol Mappings {#protocol-mappings}

A protocol maps to a command only if it can **fully complete** that command. Protocols that cover only part of a command's scope (e.g., token revocation without session invalidation) cannot fulfill a command on their own and are listed as **composition components** where applicable.

## Completeness Requirement {#completeness}

Each command defines a complete resulting state (Sections 4.1.3 and 4.2.3). A protocol implementation **MUST** achieve the full resulting state of a command to claim support for that command. Partial fulfillment is not sufficient.

**Implication:** It is acceptable for a protocol to support only one of the two commands. For example, OIDC Back-Channel Logout can fully complete "Reestablish Session" but cannot on its own complete "Invalidate Authentication State" (it does not revoke tokens). Similarly, OAuth Token Revocation {{RFC7009}} revokes tokens but does not expire RP client sessions, so it cannot complete either command alone.

## Reestablish Session — Protocol Mappings {#reestablish-mappings}

The following protocols can **fully complete** the Reestablish Session command because they expire the RP client session and require the RP to reestablish it through a full authentication at the IdP.

### OIDC Back-Channel Logout (RECOMMENDED) {#reestablish-bcl}

**Specification:** {{OIDC.BackChannelLogout}}

| Element | Value / Behavior |
|---------|-----------------|
| Trigger | IdP sends a Logout Token to the RP's registered `backchannel_logout_uri` |
| Token type | JWT with `"events": {"http://schemas.openid.net/event/backchannel-logout": {}}` |
| Subject identification | `sub` claim and/or `sid` (session ID) claim |
| RP behavior | Expire the RP client session(s) matching `sub`/`sid`; do NOT revoke OAuth tokens |
| IdP SSO session | MAY be expired independently |
| **Completes command?** | **Yes** — fully satisfies Reestablish Session |

See Appendix B for RP implementation steps.

### OIDC Front-Channel Logout (ACCEPTABLE) {#reestablish-fcl}

**Specification:** {{OIDC.FrontChannelLogout}}

| Element | Value / Behavior |
|---------|-----------------|
| Trigger | IdP renders an iframe pointing to the RP's `frontchannel_logout_uri` |
| Parameters | `iss` and `sid` (if session management supported) |
| RP behavior | Clear session cookies and expire server-side session state |
| **Completes command?** | **Conditionally** — only when browser is active and iframes/cookies are not blocked |

**Limitations:** Fails if browser is closed, third-party cookies are blocked, or iframes are suppressed. **NOT RECOMMENDED** as sole mechanism.

### SAML 2.0 Single Logout (ACCEPTABLE) {#reestablish-saml-slo}

**Specification:** {{SAML2.Profiles}} Section 4.4

| Element | Value / Behavior |
|---------|-----------------|
| Trigger | IdP sends `<LogoutRequest>` to SP |
| Binding | HTTP-Redirect (front-channel) or SOAP (back-channel) |
| Subject identification | `<NameID>` matching the original assertion |
| Session identification | `<SessionIndex>` from the original `<AuthnStatement>` |
| SP behavior | Expire the RP client session matching the NameID/SessionIndex; respond with `<LogoutResponse>` |
| **Completes command?** | **Yes** (back-channel SOAP) / **Conditionally** (front-channel) |

**Limitations:** Front-channel binding is browser-dependent and fragile in multi-SP deployments. SOAP back-channel is more reliable but less widely implemented.

See Appendix B for SP implementation steps (back-channel SOAP binding).

### OpenID Provider Commands: `reestablish` (RECOMMENDED) {#reestablish-op-commands}

**Specification:** {{OP-Commands}}

This specification defines a new OP Command type **`reestablish`** that maps to the Reestablish Session lifecycle command. See Appendix C for the proposed formal registration.

| Element | Value / Behavior |
|---------|-----------------|
| Trigger | IdP sends a Command Token to the RP's registered command endpoint |
| Command type | `reestablish` |
| Token type | JWT with `typ: command+jwt`, signed with IdP signing keys |
| Required claims | `iss`, `aud`, `client_id`, `iat`, `exp`, `jti`, `command`, `tenant`, `sub` |
| RP behavior | Expire all RP client sessions for the subject; do NOT revoke OAuth tokens; require full authentication at IdP for session reestablishment |
| **Completes command?** | **Yes** — fully satisfies Reestablish Session |

See Appendix B for RP implementation steps.

## Invalidate Authentication State — Protocol Mappings {#revoke-mappings}

### OpenID Provider Commands: `invalidate` (RECOMMENDED) {#revoke-op-invalidate}

**Specification:** {{OP-Commands}}

The OP Command type **`invalidate`** maps to the Invalidate Authentication State lifecycle command, transitioning the session to the **Terminated** state. The `invalidate` command is a **strict superset** of the `reestablish` command — it includes all session expiry steps plus token invalidation and API key revocation. When the IdP sends `invalidate`, it signals that all prior authentication artifacts for the subject must be treated as untrusted.

| Element | Value / Behavior |
|---------|-----------------|
| Trigger | IdP sends a Command Token to the RP's registered command endpoint |
| Command type | `invalidate` |
| Token type | JWT with `typ: command+jwt`, signed with IdP signing keys |
| Required claims | `iss`, `aud`, `client_id`, `iat`, `exp`, `jti`, `command`, `tenant`, `sub` |
| RP behavior | Invalidate RP client session, invalidate all existing access and refresh tokens, revoke all API keys for the subject, require reauthentication |
| **Completes command?** | **Yes** — fully satisfies Invalidate Authentication State |

See Appendix B for RP implementation steps. See Section 7 for self-contained JWT access token considerations.

### Protocol Comparison {#revoke-protocol-comparison}

The following table compares the scope of each protocol when used for the Invalidate Authentication State command.

| Protocol | Invalidates RP session? | Invalidates tokens? | Revokes API keys? | Completes command alone? |
|----------|----------------------|-------------------|------------------|------------------------------|
| OP Commands (`invalidate`) | Yes | Yes | Yes | **Yes** |
| OIDC Back-Channel Logout | Yes | No | No | **No** — session layer only |
| SAML 2.0 Single Logout | Yes | No | No | **No** — session layer only |
| OAuth Token Revocation (RFC 7009) | No | Yes (per-token) | No | **No** — token layer only |
| OAuth Global Token Revocation | No | Yes (all tokens) | No | **No** — token layer only |

When not using OP Commands (`invalidate`), implementations MUST compose protocols to achieve full coverage:

| Layer | Protocol | Requirement |
|-------|----------|-------------|
| **RP session + token invalidation + API key revocation** | OIDC Back-Channel Logout / SAML SLO (session only; RP must additionally invalidate tokens and revoke API keys) | **REQUIRED** |
| **IdP SSO session** | IdP-side logout | **REQUIRED** |
| **AS-side token revocation** | OAuth 2.0 Token Revocation {{RFC7009}} or Global Token Revocation | **REQUIRED** |

### Supplementary Protocols {#revoke-components}

The following protocols may be used as **supplementary components** when OP Commands (`invalidate`) is not available, or for additional ecosystem-wide enforcement.

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

| Protocol | Reestablish Session (SL2) | Invalidate Authentication State (SL2) |
|----------|---------------------|----------------------------|
| **OP Commands (`reestablish`)** | **RECOMMENDED** — completes command | Not applicable |
| **OP Commands (`invalidate`)** | Not applicable | **RECOMMENDED** — completes command (sessions + tokens + API keys) |
| **OIDC Back-Channel Logout** | **RECOMMENDED** — completes command | Session layer only — must compose with token revocation and API key revocation |
| **OIDC Front-Channel Logout** | ACCEPTABLE — completes conditionally | Session layer only — must compose with token revocation and API key revocation |
| **SAML 2.0 Single Logout** | ACCEPTABLE — completes command | Session layer only — must compose with token revocation and API key revocation |
| **OAuth Token Revocation (RFC 7009)** | Not applicable | Token layer only — must compose with session invalidation |
| **OAuth Global Token Revocation** | Not applicable | Token layer only — must compose with session invalidation |
| **Shared Signals (CAEP)** | Not applicable | Supplementary notification only |


# Recommended Protocol Combinations {#recommendations}

Implementations conforming to **SL2** MUST support at least one protocol or protocol combination that **fully completes** each command.

## Reestablish Session (SL2 REQUIRED) {#rec-reestablish}

A single protocol can fully complete this command.

**Primary (RECOMMENDED):**
- OP Commands (`reestablish`)
- OIDC Back-Channel Logout

**Fallback (ACCEPTABLE):**
- SAML 2.0 SLO (back-channel SOAP binding)

## Invalidate Authentication State (SL2 REQUIRED) {#rec-revoke}

**Primary (RECOMMENDED):**
- OP Commands (`invalidate`) — completes the command in a single protocol exchange

**Legacy Coverage (ACCEPTABLE):**

When OP Commands is not available, implementations MUST compose protocols to achieve full coverage:

| Layer | Protocol |
|-------|----------|
| RP session | OIDC Back-Channel Logout (RP must additionally invalidate tokens and revoke API keys) |
| IdP session | IdP-side logout (automatic) |
| AS-side token revocation | OAuth Token Revocation (RFC 7009) or OAuth Global Token Revocation |


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

# Reference Deployment Model {#deployment-model}

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
|  |  +-----------------+  |    (reestablish / invalidate)    |            |
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

## Command Effects on This Deployment {#command-effects}

**Reestablish Session** — IdP sends `reestablish`:

~~~ ascii-art
IdP --reestablish--> SaaS Application (RP)
                         |
                         +-- RP client sessions ......... EXPIRE
                         +-- Access tokens .............. unchanged
                         +-- Refresh tokens ............. unchanged
                         +-- API keys ................... unchanged
~~~

All of the user's interactive sessions are expired. First-party clients holding valid access tokens or refresh tokens continue to operate. Background API integrations using API keys are unaffected. The user must complete a full authentication at the IdP — where the IdP re-evaluates policy, risk, and state — to establish a new session.

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

**Note on deployment:** In this deployment, the SaaS Application is both the RP and the AS. When the RP receives an OP Commands `invalidate` command, it invalidates sessions, tokens, and API keys in a single internal operation. When the RP and AS are separate entities, the RP is still responsible for invalidating all authentication artifacts within its domain upon receiving the command.

# Protocol Implementation Details {#appendix-protocol-details}

This appendix provides detailed RP implementation steps for each protocol mapping defined in Section 5. These steps are informational and intended to guide implementers.

## OIDC Back-Channel Logout — RP Implementation {#impl-bcl}

1. Validate the Logout Token signature against IdP JWKS
2. Verify `iss`, `aud`, `iat`, and `events` claims
3. Look up local session(s) by `sub` and/or `sid`
4. Expire matching RP client sessions
5. On next user interaction, trigger Forced Reauthentication (see Section 3.3)

## SAML 2.0 Single Logout — SP Implementation (Back-Channel SOAP) {#impl-saml-slo}

1. Validate `<LogoutRequest>` signature
2. Verify `Issuer`, `Destination`, `NameID`
3. Look up local session by `NameID` and `SessionIndex`
4. Expire matching session
5. Return `<LogoutResponse>` with `Success` status
6. On next user interaction, trigger Forced Reauthentication (see Section 3.3)

## OpenID Provider Commands: `reestablish` — RP Implementation {#impl-op-reestablish}

1. Validate Command Token signature against IdP JWKS
2. Verify `typ` is `command+jwt`
3. Verify `iss`, `aud`, `iat`, `exp`, `jti`, and `command` claims
4. Confirm `command` value is `reestablish`
5. Look up all sessions by `sub` (and `tenant` if applicable)
6. Expire all matching RP client sessions
7. Return success response
8. On next user interaction, trigger Forced Reauthentication (see Section 3.3)

## OpenID Provider Commands: `invalidate` — RP Implementation {#impl-op-invalidate}

1. Validate Command Token signature against IdP JWKS
2. Verify `typ` is `command+jwt`
3. Verify `iss`, `aud`, `iat`, `exp`, `jti`, and `command` claims
4. Confirm `command` value is `invalidate`
5. Look up all sessions by `sub` (and `tenant` if applicable)
6. Expire all matching RP client sessions
7. Invalidate all existing access tokens for the subject
8. Invalidate all existing refresh tokens for the subject
9. Revoke all API keys for the subject (service keys, personal access tokens, static bearer tokens)
10. Return success response
11. On next user interaction, trigger Forced Reauthentication (see Section 3.3)

**Note:** Because `invalidate` is a superset of `reestablish`, any RP that implements `invalidate` inherently satisfies the Reestablish Session command as well. The RP is responsible for invalidating all authentication artifacts within its domain, including any tokens issued by its own Authorization Server. See Section 7 for self-contained JWT access token considerations.


# Suggested Protocol Extensions {#extensions}

The following extensions would improve the ability to implement these commands with clear semantics and guaranteed enforcement. These are suggestions for future standardization work.

**Note:** The `reestablish` OP Command type is used normatively throughout this specification as the recommended protocol mapping for the Reestablish Session command. This appendix proposes its formal registration with the OP Commands specification.

## OpenID Provider Commands: `reestablish` Command Registration {#ext-op-reestablish}

**Problem:** The OP Commands specification defines `invalidate` but does not define a session reestablishment command. The `invalidate` command implies full authentication revocation, which is too broad for the Reestablish Session use case where the IdP wants to revalidate access without invalidating tokens and API keys.

**Proposed Registration:** Register `reestablish` as a new OP Command type.

| Field | Value |
|-------|-------|
| Command name | `reestablish` |
| Command type | Account Command |
| Description | Require the RP to expire the subject's session and reestablish it through a full authentication at the IdP. The IdP re-evaluates policy, risk, and state to determine whether to grant continued access. The RP MUST NOT revoke OAuth tokens or API keys. |
| Required claims | `iss`, `aud`, `client_id`, `iat`, `exp`, `jti`, `command`, `tenant`, `sub` |
| Lifecycle command | Reestablish Session (Section 4.1) |

**Relationship to `invalidate`:**

The `invalidate` command is a **strict superset** of `reestablish` — it performs all `reestablish` steps plus token invalidation and API key revocation.

| OP Command | Lifecycle Command | Session | Tokens | API Keys |
|------------|-------------------|---------|--------|----------|
| `reestablish` | Reestablish Session | Expire + reestablish | Unchanged | Unchanged |
| `invalidate` | Invalidate Authentication State | Terminated (superset of reestablish) | Invalidate all | Revoke all |

The RP **MUST** treat `reestablish` and `invalidate` as distinct commands with different scopes. Receiving `reestablish` **MUST NOT** trigger token invalidation; receiving `invalidate` **MUST** perform all `reestablish` steps and additionally invalidate tokens and revoke API keys.

## CAEP: Enforcement Profile for Session Lifecycle {#ext-caep-enforcement}

**Problem:** CAEP events are informational by default. An IdP cannot mandate that an RP act on a `session-revoked` event.

**Suggested Extension:** Define an enforcement profile that:

1. Maps CAEP event types to the commands defined in this specification
2. Requires the receiver to enforce the mapped command
3. Requires the receiver to report enforcement status

| CAEP Event | Mapped Command | Enforcement |
|------------|----------------|-------------|
| `session-revoked` (reason: `logout`, `timeout`, `policy-change`) | Reestablish Session | **MUST** expire RP session and require reestablishment |
| `session-revoked` (reason: `policy-violation`, `compromise`) | Invalidate Authentication State | **MUST** invalidate session and tokens, and revoke API keys |
| `credential-change` | Invalidate Authentication State | **MUST** invalidate session and tokens, and revoke API keys |


# Change Log {#changelog}

* **Implementer's Draft 1 — 2025-XX-XX**
  * Initial publication
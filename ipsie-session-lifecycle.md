# IdP → RP Security Actions for Access Revalidation {#title}

*OpenID Foundation Implementer's Draft 1*  
Short Name: **IPSIE.SessionLifecycle**  
Editors: **Karl McGuinness** (OpenID Foundation Contributor)  
License: **CC BY-SA 4.0**

> **Status of This Document.** This document is an OpenID Foundation Implementer's Draft. It is a work in progress and may change without notice. Implementers are encouraged to provide feedback and implementation experience.

---

## 1. Introduction {#introduction}

In federated single sign-on (SSO) systems, **authentication** (verifying the subject’s identity and producing an authentication event/assertion) is separate from **authorization** (the RP’s decision to grant access and what the subject is allowed to do). When an Identity Provider (IdP) needs the RP to stop relying on a prior sign-in and re-check with the IdP, it must communicate this to Relying Parties (RPs) in a way that is both precise and actionable.

Motivating examples where an IdP may want an RP to “check back” include:

- **Operational / low-disruption cases (typically “Expire Interactive Session”)**:
  - **User-initiated sign-out** at the IdP or security portal, where the expected outcome is “end the current browser login at the RP.”
  - **Idle / absolute session timeout** or “maximum session age” policy, where the user must re-authenticate before continuing.
  - **Step-up requirement** (e.g., the RP requests stronger authentication for a sensitive operation), where the IdP must force a new interactive authentication event.

- **Security incident / high-disruption cases (typically “Revoke All Authentication State”)**:
  - **Account compromise suspected or confirmed** (phishing, impossible travel, credential leak), where all sessions and tokens must be treated as no longer valid.
  - **Credential reset / factor reset** (password reset, MFA device reset), where prior sessions/tokens should not remain sufficient evidence of sign-in.
  - **Account disabled / high-risk posture** (suspension, strong risk signal, device integrity failure), where continued access must stop until the IdP re-evaluates policy via fresh authentication.

### 1.1 Problem Statement {#problem}

Federated identity systems maintain authentication state across **multiple independent layers**:

- **RP client sessions** (login state at the application, e.g., browser cookies or first-party native-app credentials to the RP backend such as a session token or RP-issued access/refresh tokens)
- **IdP SSO sessions** (central authentication state enabling single sign-on)
- **OAuth access tokens** (authorization for API access)
- **OAuth refresh tokens** (capability to obtain new access tokens)
- **Authorization grants / consent** (record of permissions granted)

These layers operate independently: a user may have an active RP session while their IdP session expires, or tokens may remain valid after an RP session terminates. This independence creates a fundamental ambiguity: **when an IdP triggers access revalidation, what exactly should happen at the RP?**

#### 1.1.1 The Ambiguity Problem {#ambiguity-problem}

Existing protocols and implementations suffer from ambiguity:

1. **Protocol-level ambiguity:** Different protocols use different semantics. An "logout" event might mean "end the session" or "revoke everything" depending on context.

2. **Implementation-level ambiguity:** Without clear, standardized action definitions, RPs interpret signals differently:
   - Does "session revoked" mean only the browser session, or also tokens?
   - Should logout invalidate refresh tokens, or only access tokens?
   - Is a security incident response the same as a normal logout?

3. **State ambiguity:** After receiving a signal, the resulting system state is often unclear:
   - Can the user still use existing tokens?
   - Will silent SSO still work?
   - Are background API operations affected?

4. **Cross-protocol ambiguity:** When multiple protocols are involved, signals from one protocol don't clearly map to actions in another.

This ambiguity leads to:
- **Under-reaction:** Treating a security incident as a simple logout, leaving tokens usable
- **Over-reaction:** Treating normal logout as full revocation, unnecessarily disrupting background operations
- **Inconsistent behavior:** Different RPs implementing different interpretations of the same signal
- **Security gaps:** Unclear boundaries allowing continued access when it should be terminated

#### 1.1.2 The Solution: Two Clear Security Actions {#solution}

This document defines **two distinct security actions** that eliminate ambiguity by:

1. **Defining precise artifact scope:** Each action explicitly specifies which authentication artifacts are affected
2. **Mandating required behavior:** Each action defines what the RP **MUST** do, not optional behavior
3. **Specifying resulting state:** The end state after processing each action is completely defined
4. **Translating across protocols:** Clear semantics that work with OIDC, SAML, OAuth, and Shared Signals
5. **Separating authentication from authorization:** These actions trigger access revalidation without changing authorization policy; authorization remains unchanged

**Result:** Any RP, regardless of implementation details, will arrive at the same security state after processing a given action.

### 1.2 Scope {#scope}

This document defines **two distinct security actions** that an IdP can send to an RP to trigger **access revalidation only**. These actions:

- **DO affect:** session validity and the continued acceptability of prior authentication artifacts (sessions, tokens)
- **DO NOT affect:** roles, permissions, entitlements, or authorization policy within the RP

Their goal is to require the RP to obtain **fresh authentication** (and therefore a current IdP policy evaluation) before access to the application can continue.

#### Access Revalidation (Informative) {#access-revalidation}

This document uses the term **access revalidation** to mean an IdP-initiated request that the RP **stop relying on a prior login / sign-in decision** and instead **check back with the IdP** by obtaining **fresh authentication** as required by this specification.

In practice, continued access is embodied in one or more artifacts (RP session state, IdP SSO session state, access tokens, refresh tokens). When access revalidation is triggered, the RP **MUST** stop treating the affected artifacts as sufficient evidence of a currently-acceptable sign-in and **MUST** obtain **fresh authentication** as required by this specification.

Access revalidation does **not** refer to in-application authorization state (roles/permissions) and does not require the RP to change authorization policy.

### 1.3 Goals {#goals}

- Define precise, actionable security actions with clear scope and required RP behavior
- Map these actions to existing protocols (OIDC, SAML, OAuth, Shared Signals)
- Prevent under-reaction (treating compromise as simple logout) and over-reaction (treating logout as full revocation)
- Establish a clear boundary between access revalidation and authorization policy changes
- Provide clear guidance on protocol selection and tradeoffs

### 1.4 Non-Goals {#non-goals}

- This document does **not** define new protocols or protocol extensions
- This document does **not** address authorization revocation or permission changes
- This document does **not** mandate specific protocol implementations
- This document does **not** define enforcement verification mechanisms

---

## 2. Understanding the Layers {#layers}

To understand why two distinct actions are necessary, we must first understand the independent layers of authentication state in federated systems.

### 2.1 What Is a Session? {#what-is-session}

A **session** is a temporary, revocable security state that proves a subject has already authenticated and defines what they can continue to do without re-authenticating. Sessions are maintained separately by identity providers, applications, and token systems.

A session answers the question: *"This subject has already authenticated — under what conditions can they keep accessing the system?"*

**Core Properties:**
- **Authenticated subject:** A user, device, or workload that has proven identity
- **Established at a moment in time:** Created after a successful authentication event
- **Context-bound:** Associated with a browser, device, client instance, or connection
- **Stateful:** Maintains security attributes about the login
- **Time-limited:** Ends due to timeout, logout, or risk event
- **Revocable:** Can be invalidated before natural expiration
- **Independent from authorization:** Governs access to the app, not permissions within it

### 2.2 The Three Session Types {#session-types}

Federated systems typically contain **three concurrent session types**:

| Session Type | Between | Purpose | Controlled By |
|--------------|---------|---------|--------------|
| **RP Client Session (Web or Native)** | User ↔ Application | Maintains login state at the app (browser cookie session, first-party app→backend session token, or first-party access/refresh tokens issued by the RP backend) | Relying Party |
| **IdP SSO Session** | User ↔ Identity Provider | Enables single sign-on across multiple apps | Identity Provider |
| **Token-Based Session** | Client ↔ Resource Server | Represents ongoing API access via tokens | Authorization Server / Resource Server |

#### 2.2.1 Layering Diagram (Informative) {#layering-diagram}

The following diagram shows the **independent authentication state layers** and where each piece of state is typically maintained.

```
                    (front ends)                                      (back-end / infra)

  +---------------------------+                 +--------------------------------------+
  |     Browser User Agent    |<-- cookies ---->|          Relying Party (RP)          |
  |  (web)                    |                 |  - RP client sessions:               |
  +---------------------------+                 |    [A] web cookie sessions            |
            ^                                   |    [A] native-app session tokens      |
            | (OIDC/SAML via browser)           |  - local session policy               |
            |                                   +--------------------------------------+
            |                                                     ^             |
            |                                                     |             | (access token)
            v                                                     |             v
  +---------------------------+                                   |   +---------------------------+
  |   Native App (Mobile)     |<-- first-party credentials -------|   |      Resource Server      |
  |                           |   (session token OR RP-issued      |   |                           |
  |                           |    access+refresh tokens)          |   |                           |
  |  (does NOT federate)      |---------- API --------------------+-->|          (RS)             |
  +---------------------------+                                       +---------------------------+

            ^ (federated authn response: SAML assertion / OIDC auth result)
            |
            v
  +---------------------------+                 +---------------------------+
  | Identity Provider (IdP)   |<--------------->| Authorization Server (AS) |
  | - [B] IdP SSO session     |   (tokens/grant)| - refresh token state     |
  | - authentication policy   |                 | - [D] grant/consent record|
  +---------------------------+                 +---------------------------+

State layers (independent lifetimes):
  [A] RP client session state (browser cookie sessions AND/OR native-app→backend first-party credentials such as session tokens or RP-issued access/refresh tokens)
  [B] IdP SSO session (cookie/session store at IdP)
  [C] Token-based session (OAuth access/refresh tokens; RS/AS validation)
  [D] Grant/consent record (AS)
```

**Note (Native App pattern):** In many SaaS deployments, the native app does not authenticate to the IdP directly. The RP backend performs federation and then issues the native app **first-party credentials** for calling the RP backend (for example, a session token, or an RP-issued access token plus refresh token). These first-party credentials are independent of the IdP SSO session and are part of the **RP client session** layer \([A]\).

### 2.3 Layer Independence {#layer-independence}

**Critical insight:** These layers operate **independently**. Their lifetimes are not synchronized:

- An RP session may expire while the IdP SSO session remains active
- Tokens may remain valid after an RP session terminates
- An IdP session may end without automatically terminating RP sessions
- Background API operations using tokens continue even if the browser session ends

**Example:** A user logs out of their browser (RP session ends), but their mobile app continues to work using existing access tokens (token-based session continues).

### 2.4 Why This Matters {#why-layers-matter}

Because layers are independent, **a single signal cannot safely imply full security containment**. An IdP must be able to:

1. **Terminate just the RP client session** (web cookie session and/or native-app first-party credentials) without implying OAuth token revocation
2. **Revoke all authentication artifacts** (security incident, account compromise) including tokens

These require different actions with different scopes.

### 2.5 Session vs Token vs Grant {#session-token-grant}

| Concept | Purpose | Stored Where | Ends How | Affected By Actions |
|---------|---------|--------------|----------|---------------------|
| **Session** | Maintain login state | RP or IdP | Logout or timeout | **YES** — both actions |
| **Access Token** | Authorize API calls | Client / Resource Server | Expiry or revocation | **Revoke All** only |
| **Refresh Token** | Obtain new access tokens | Client / Authorization Server | Revocation or rotation failure | **Revoke All** only |
| **Grant / Consent** | Record of permission | Authorization Server | Revoked or expires | **NO** — authorization unchanged |

---

## 3. The Two Security Actions {#actions}

This document defines two distinct security actions, each with a precise scope and unambiguous outcome.

### 3.1 Overview {#actions-overview}

| Action | Short Description | Scope of Revalidation | Typical Trigger |
|--------|-------------------|--------------------------|-----------------|
| **Expire Interactive Session** | End the current login session | Current RP client session only | Logout, inactivity timeout, step-up requirement |
| **Revoke All Authentication State** | Treat all prior authentication artifacts as no longer valid | All prior authentication state (sessions + tokens) | Account compromise, security incident, policy violation |

### 3.2 Why Two Separate Actions {#why-separate}

These actions must be separate because they address fundamentally different security scenarios:

- **Expire Interactive Session:** Normal operational events (logout, timeout, step-up) that should end the current login but preserve token-based access
- **Revoke All Authentication State:** Security incidents (compromise, violation) that require complete containment of all authentication artifacts

**If conflated:**
- **Treating logout as full revocation:** Unnecessary disruption occurs, breaking background API operations that should continue
- **Treating compromise reset as logout:** Tokens remain usable, allowing continued unauthorized access after a security incident

### 3.3 Unambiguous Outcomes {#unambiguous-outcomes}

Each action defines a **precise, unambiguous security outcome** that translates consistently across all RP implementations, regardless of protocol, architecture, token type, or session model.

#### 3.3.1 Expire Interactive Session — Resulting State {#outcome-expire}

**After processing this action:**

| Artifact | State | Rationale |
|----------|-------|-----------|
| RP client session | **Terminated** | User must re-authenticate to access the application |
| OAuth access tokens | **Unchanged** | Background API operations continue |
| OAuth refresh tokens | **Unchanged** | Token refresh continues to work |
| IdP SSO session | **MAY** be terminated | Deployment-dependent, but does not affect outcome |
| Authorization grants | **Unchanged** | Permissions remain valid |

**Result:** The user cannot access the application through the browser without re-authenticating, but existing tokens remain valid for API access. This outcome is **identical across all RP implementations**.

#### 3.3.2 Revoke All Authentication State — Resulting State {#outcome-revoke}

**After processing this action:**

| Artifact | State | Rationale |
|----------|-------|-----------|
| RP client session | **Terminated** | User must re-authenticate to access the application |
| OAuth access tokens | **Treated as invalid** | All API access using existing tokens is blocked |
| OAuth refresh tokens | **Revoked** | Cannot obtain new access tokens |
| IdP SSO session | **Terminated** | No silent SSO reuse possible |
| Authorization grants | **Unchanged** | Permissions remain valid (authorization unchanged) |

**Result:** The user cannot access the application through any means (browser or API) without re-authenticating with fresh credentials. All prior authentication artifacts are untrusted. This outcome is **identical across all RP implementations**.

#### 3.3.3 Why These Outcomes Are Unambiguous {#why-unambiguous}

1. **Binary state transitions:** Each artifact has a clear, binary state (valid/invalid, terminated/active)
2. **Complete specification:** Every artifact is explicitly addressed
3. **Protocol-agnostic semantics:** The actions define **what** must happen, not **how** it's communicated
4. **Testable outcomes:** The end state can be verified
5. **No interpretation required:** The action type directly maps to required behavior

---

## 4. Security Action 1: Expire Interactive Session {#action-expire}

### 4.1 Definition {#expire-definition}

An IdP command requiring the RP to terminate the subject's current **RP client session** (for example, a browser cookie session or a native-app→backend session token) and require the user to authenticate again before continuing.

### 4.2 Security Objective {#expire-objective}

Protect against unattended session misuse:
- **Walk-away risk:** User leaves workstation unattended
- **Policy timeout:** Session exceeds maximum duration
- **Step-up requirement:** Higher assurance needed for sensitive operations

### 4.3 Required Behavior {#expire-behavior}

**When an RP receives this action, it MUST:**

1. Invalidate local RP client session state
2. Invalidate the affected **RP client session** identifiers (for example, delete session cookies, revoke native-app→backend session tokens, revoke RP-issued first-party access/refresh tokens used by the native app, invalidate server-side session handles)
3. Require **fresh authentication at the IdP** (see Section 6)
4. NOT silently re-establish the session using existing tokens or SSO cookies

**The RP MUST NOT:**

- Change roles or permissions
- Treat this as authorization revocation
- Revoke OAuth access tokens or refresh tokens at the Authorization Server solely as a result of this action
- Treat this action as a requirement to perform global token revocation or ecosystem-wide containment

**When an IdP sends this action, it MAY:**

- Terminate the IdP SSO session (optional, deployment-dependent)
- Leave access tokens and refresh tokens unchanged

### 4.4 Scope Impact {#expire-scope}

| Layer | Effect |
|-------|--------|
| RP client session (web cookie and/or native-app first-party credentials) | **Terminated** |
| OAuth access tokens | **Unchanged** |
| OAuth refresh tokens | **Unchanged** |
| Authorization grants / consent | **Unchanged** |
| IdP SSO session | **MAY** be terminated |

#### 4.5 Native App Considerations (Informative) {#expire-native-apps}

Many SaaS deployments use a **backend-mediated** model for native apps: the native app does not authenticate to the IdP directly. Instead, the RP backend performs federation and issues the native app **first-party credentials** for calling the RP backend (for example, a session token, or an RP-issued access token plus refresh token). In this model, \"Expire Interactive Session\" applies to those first-party credentials the same way it applies to a browser cookie session.

When the RP invalidates native app first-party credentials in response to this action, a common pattern is:

1. The native app makes an API request using its app→backend session token.
2. The RP rejects the request (for example, `401 Unauthorized` or `403 Forbidden`) and indicates re-authentication is required.
3. The native app initiates sign-in again (typically by launching a system browser) and the RP performs federation with the IdP using fresh-auth controls (see Section 6).

This preserves the intended outcome: the user must perform a new interactive authentication event before continuing, without implying global token revocation.

---

## 5. Security Action 2: Revoke All Authentication State {#action-revoke}

### 5.1 Definition {#revoke-definition}

An IdP command requiring all existing authentication artifacts to be treated as untrusted, including sessions, access tokens, and refresh tokens.

### 5.2 Security Objective {#revoke-objective}

Contain compromise or high-risk events by revoking all prior authentication state (sessions and tokens). This action is appropriate when:

- Account compromise is suspected or confirmed
- Security incident requires immediate containment
- Policy violation requires access termination
- Account is disabled or suspended

### 5.3 Required Behavior {#revoke-behavior}

**When an RP receives this action, it MUST:**

1. Perform all "Expire Interactive Session" steps (Section 4.3)
2. Reject use of existing access tokens (treat as invalid)
3. Reject use of existing refresh tokens (treat as revoked)
4. Require **fresh authentication at the IdP** (see Section 6)
5. Terminate any background API operations using existing tokens

**The RP MUST NOT:**

- Change roles or permissions
- Treat this as authorization revocation
- Accept tokens issued before the invalidation event

**When an IdP sends this action, it MUST:**

1. Terminate IdP SSO session
2. Revoke refresh tokens for the subject
3. Revoke or invalidate access tokens for the subject
4. Ensure Resource Servers (RSs) can detect token invalidation

### 5.4 Scope Impact {#revoke-scope}

| Layer | Effect |
|-------|--------|
| RP client sessions (web cookie and/or native-app first-party credentials) | **Terminated** |
| OAuth access tokens | **Treated as invalid** |
| OAuth refresh tokens | **Revoked** |
| Authorization grants / consent | **Unchanged** |
| IdP SSO session | **Terminated** |

---

## 6. Protocol Options and Tradeoffs {#protocols}

This section presents the **menu of protocol options** for implementing each security action, explains the tradeoffs, and provides recommendations.

### 6.1 Protocol Selection Overview {#protocol-overview}

No single protocol provides complete coverage for both actions. Implementers must understand:

1. **Which protocols support which actions**
2. **What tradeoffs each protocol involves**
3. **How to compose multiple protocols for complete coverage**
4. **Which combinations are recommended**

### 6.2 Expire Interactive Session — Protocol Options {#expire-protocols}

| Protocol | Coverage | Enforcement | Reliability | Recommendation |
|----------|----------|-------------|-------------|-----------------|
| **OIDC Back-Channel Logout** | Strong | Notification only | High | **RECOMMENDED** — Best balance of coverage and reliability |
| **OpenID Provider Commands** | Strong (when profiled) | Command-based | High | **RECOMMENDED** — When profile defines mandatory behavior |
| **OIDC Front-Channel Logout** | Medium | Browser-dependent | Medium | **ACCEPTABLE** — Works but browser-dependent |
| **SAML 2.0 Single Logout** | Medium | Multi-SP issues | Medium | **ACCEPTABLE** — Works but fragile in complex deployments |
| **Shared Signals (CAEP)** | Weak by default | Event notification | Medium | **NOT RECOMMENDED** — Requires enforcement profile |

#### 6.2.1 Detailed Protocol Analysis — Expire Interactive Session {#expire-protocol-detail}

**OIDC Back-Channel Logout** (RECOMMENDED)
- **How it works:** Direct server-to-server logout token instructs RP to terminate session
- **Strengths:** Reliable, not browser-dependent, direct communication
- **Weaknesses:** No guarantee RP enforces; does not affect browser cookies directly
- **Tradeoff:** Strong coverage but requires RP to implement enforcement logic
- **Why recommended:** Best balance of reliability and coverage without browser dependencies

**OpenID Provider Commands** (RECOMMENDED when profiled)
- **How it works:** Explicit OP→RP command channel with clear semantics
- **Strengths:** Designed for this use case, clear semantics
- **Weaknesses:** Requires defined command type and mandatory RP behavior profile
- **Tradeoff:** Strong when profiled, but profile must exist
- **Why recommended:** Purpose-built for IdP→RP commands; needs profile to mandate enforcement

**OIDC Front-Channel Logout** (ACCEPTABLE)
- **How it works:** Browser-mediated logout clears RP session
- **Strengths:** Works when browser is available
- **Weaknesses:** Fails if browser closed, third-party cookies blocked, or iframe suppressed
- **Tradeoff:** Simple but unreliable
- **Why acceptable:** Works in many cases but not reliable enough for critical use cases

**SAML 2.0 Single Logout** (ACCEPTABLE)
- **How it works:** Designed for cross-SP session termination
- **Strengths:** Widely deployed, standardized
- **Weaknesses:** Fragile in multi-SP environments; partial logout common
- **Tradeoff:** Standardized but complex and error-prone
- **Why acceptable:** Works but requires careful deployment

**Shared Signals (CAEP)** (NOT RECOMMENDED for this action)
- **How it works:** Real-time event notifying RP
- **Strengths:** Fast notification
- **Weaknesses:** Only informational unless a profile mandates enforcement
- **Tradeoff:** Fast but no enforcement guarantee
- **Why not recommended:** Requires enforcement profile; other options are better

### 6.3 Revoke All Authentication State — Protocol Options {#revoke-protocols}

**Critical insight:** Revoke All Authentication State **cannot be implemented by one protocol alone**. It requires **protocol composition**.

#### 6.3.1 Required Protocol Composition {#revoke-composition}

To fully implement "Revoke All Authentication State," you need:

1. **Session termination** (OIDC Back-Channel Logout, SAML SLO, or OP Commands)
2. **Token revocation** (OAuth Token Revocation, Global Token Revocation)
3. **Token validation controls** (Token Introspection, short lifetimes)
4. **Event propagation** (Shared Signals Framework) — optional but recommended
5. **RP enforcement logic** (application-level implementation)

#### 6.3.2 Protocol Options by Layer {#revoke-by-layer}

| Layer | Protocol | Coverage | Enforcement | Recommendation |
|------|----------|----------|-------------|----------------|
| **RP Session** | OIDC Back-Channel Logout | Strong | Notification | **RECOMMENDED** |
| **RP Session** | OpenID Provider Commands | Strong (when profiled) | Command-based | **RECOMMENDED** when profiled |
| **IdP Session** | IdP logout | Strong | Direct | **REQUIRED** |
| **Refresh Tokens** | OAuth 2.0 Token Revocation (RFC 7009) | Strong | AS-side | **REQUIRED** |
| **Refresh + Access Tokens** | OAuth 2.0 Global Token Revocation (draft) | Strong (AS-side) | AS-side | **RECOMMENDED** if available |
| **Access Tokens** | OAuth 2.0 Token Introspection (RFC 7662) | Medium | RS-side | **RECOMMENDED** for reference tokens |
| **Access Tokens** | Short token lifetime | Medium | Time-based | **ACCEPTABLE** mitigation |
| **Event Broadcast** | Shared Signals (CAEP) | Weak by default | Event notification | **OPTIONAL** — for ecosystem notification |

#### 6.3.3 Recommended Protocol Combinations {#revoke-recommendations}

**Combination 1: Strong Coverage (RECOMMENDED)**
- **RP Session:** OIDC Back-Channel Logout or OP Commands
- **IdP Session:** IdP logout (automatic)
- **Tokens:** OAuth Global Token Revocation (if available) + Token Introspection for validation
- **Why recommended:** Provides strong coverage across all layers with clear enforcement points

**Combination 2: Standard Coverage (ACCEPTABLE)**
- **RP Session:** OIDC Back-Channel Logout
- **IdP Session:** IdP logout (automatic)
- **Tokens:** OAuth Token Revocation (RFC 7009) + Token Introspection
- **Why acceptable:** Uses standard protocols but requires more coordination

**Combination 3: Minimal Coverage (NOT RECOMMENDED)**
- **RP Session:** OIDC Front-Channel Logout
- **Tokens:** Short token lifetimes only
- **Why not recommended:** Incomplete coverage, relies on time-based mitigation

#### 6.3.4 Key Tradeoffs — Revoke All Authentication State {#revoke-tradeoffs}

**Self-contained JWT Access Tokens:**
- **Problem:** Cannot be immediately invalidated without RS participation
- **Solutions:**
  - Use Token Introspection (requires RS to check)
  - Use short token lifetimes (time-based, not immediate)
  - Use revocation lists (requires RS to check)
- **Tradeoff:** Immediate invalidation requires RS cooperation

**Reference Tokens:**
- **Advantage:** Can be immediately invalidated via introspection
- **Tradeoff:** Requires RS to introspect on every request (performance cost)

**Global Token Revocation:**
- **Advantage:** Revokes all tokens for a subject in one action
- **Limitation:** Still requires RS enforcement; not universally implemented
- **Tradeoff:** Strong AS-side coverage but depends on ecosystem

**Shared Signals:**
- **Advantage:** Fast ecosystem-wide notification
- **Limitation:** No mandatory enforcement without profile
- **Tradeoff:** Fast notification but requires enforcement profile

### 6.4 Protocol Selection Decision Tree {#protocol-decision-tree}

```
Which action are you implementing?

├─ Expire Interactive Session
│  ├─ Do you need highest reliability?
│  │  └─ YES → Use OIDC Back-Channel Logout (RECOMMENDED)
│  ├─ Do you have OP Commands with enforcement profile?
│  │  └─ YES → Use OP Commands (RECOMMENDED)
│  └─ Otherwise → Use OIDC Back-Channel Logout (ACCEPTABLE)
│
└─ Revoke All Authentication State
   ├─ Do you have Global Token Revocation?
   │  └─ YES → Use: OP Commands/OIDC Logout + Global Revocation + Introspection (RECOMMENDED)
   ├─ Do you use reference tokens?
   │  └─ YES → Use: OP Commands/OIDC Logout + Token Revocation + Introspection (RECOMMENDED)
   └─ Do you use self-contained JWT tokens?
      └─ YES → Use: OP Commands/OIDC Logout + Token Revocation + Short lifetimes + Introspection (ACCEPTABLE)
```

### 6.5 Summary of Recommendations {#protocol-summary}

**For Expire Interactive Session:**
- **Primary recommendation:** OIDC Back-Channel Logout
- **Alternative:** OpenID Provider Commands (when profiled with enforcement)
- **Avoid:** Relying solely on browser-dependent mechanisms

**For Revoke All Authentication State:**
- **Primary recommendation:** Protocol composition using:
  - OIDC Back-Channel Logout or OP Commands (sessions)
  - OAuth Global Token Revocation or Token Revocation (tokens)
  - Token Introspection (validation)
- **Critical:** No single protocol is sufficient; composition is required
- **Avoid:** Relying on short token lifetimes alone

---

## 7. Fresh Authentication Requirement {#fresh-auth}

Both security actions require the RP to obtain **fresh authentication** from the IdP. Fresh authentication means the IdP must perform a **new primary authentication event**, not reuse an existing SSO session.

### 7.1 RP Requirements {#fresh-auth-rp}

When an RP receives either security action, it **MUST**:

1. Redirect user to IdP for authentication
2. Prevent silent SSO reuse (force user interaction)
3. Obtain a new authentication assertion or token
4. Validate authentication time and assurance level

### 7.2 Protocol Controls {#fresh-auth-protocols}

| Protocol | Mechanism | Description |
|----------|-----------|-------------|
| OIDC | `prompt=login`, `max_age=0` | Forces re-authentication and disallows SSO session reuse |
| SAML | `ForceAuthn="true"` | Requires new authentication, not SSO session reuse |
| OP Commands | Carries instruction; RP enforces | Command includes requirement; RP must enforce via protocol parameters |

### 7.3 Authentication Time Validation {#fresh-auth-time}

The RP **MUST** validate that the authentication time (`auth_time` in OIDC, `AuthnInstant` in SAML) is recent and not from a prior session. The RP **SHOULD** reject authentications that appear to reuse prior sessions.

---

## 8. Key Differences Between Actions {#differences}

| Dimension | Expire Interactive Session | Revoke All Authentication State |
|-----------|---------------------------|----------------------|
| **Scope** | Session only | Sessions + tokens |
| **Trigger** | Logout, step-up, inactivity | Compromise, incident, policy violation |
| **Token impact** | None | Tokens invalid |
| **IdP SSO session** | MAY be terminated | MUST be terminated |
| **Refresh tokens** | Unchanged | Revoked |
| **Access tokens** | Unchanged | Treated as invalid |
| **Works without RS introspection** | Yes | No (for access tokens) |
| **Works if access tokens are JWTs** | Yes | Only with short lifetimes or RS checks |
| **Stops background API activity** | No | SHOULD |
| **Immediate containment** | No | Partial (depends on ecosystem enforcement) |
| **Operational disruption** | Low | High |
| **Requires protocol profiling** | Recommended | **Mandatory** |
| **Authorization impact** | None | None |
| **Revalidation scope** | Current RP client session only | All prior authentication state (sessions + tokens) |

---

## 9. Authentication vs Authorization Boundary {#auth-boundary}

These security actions trigger **access revalidation**, not authorization policy changes. The distinction is critical:

| Question | Controlled By | Affected by Actions |
|----------|---------------|---------------------|
| Who is the subject (identity) and how/when did they authenticate? | IdP | **YES** |
| Should the RP grant access right now? | RP | **INDIRECTLY** (requires fresh authentication) |
| What can the subject do inside the app? | RP | **NO** |

### 9.1 Conceptual Model {#conceptual-model}

These actions allow the IdP to say:

> "The previous sign-in is no longer sufficient. Ask me again."

They **do not** mean:

> "Change the user's permissions."

Authorization decisions remain entirely within the RP and occur only after successful fresh authentication.

### 9.2 Why This Matters {#why-boundary}

- **Authorization is RP-specific:** The RP determines what users can do based on roles, permissions, and business logic
- **Authentication is IdP-controlled:** The IdP determines whether a user's identity is verified and trustworthy
- **Separation enables flexibility:** RPs can implement different authorization models while relying on IdP authentication decisions

---

## 10. Implementation Guidance {#implementation}

### 10.1 Protocol Selection {#impl-protocol-selection}

**For Expire Interactive Session:**
- **RECOMMENDED:** OIDC Back-Channel Logout or OpenID Provider Commands (when profiled)
- **Rationale:** Strong coverage, reliable, not browser-dependent

**For Revoke All Authentication State:**
- **REQUIRED:** Protocol composition (see Section 6.3.3)
- **Rationale:** No single protocol provides complete coverage

### 10.2 Enforcement Implementation {#impl-enforcement}

Current protocols provide **notification** but not **enforcement guarantees**. Implementers **SHOULD**:

- Use protocol profiles that mandate RP behavior
- Implement application-level enforcement logic
- Monitor for compliance with security actions
- Log all security action receipts and enforcement

### 10.3 Token Handling {#impl-token-handling}

**For Revoke All Authentication State:**

- **Reference tokens:** Use Token Introspection to validate
- **Self-contained tokens (JWTs):** Implement short lifetimes and/or revocation lists
- **Refresh tokens:** Always revoke at the Authorization Server

### 10.4 Error Handling {#impl-error-handling}

RPs **MUST** handle cases where:

- Security action delivery fails (retry mechanisms)
- Protocol mapping is incomplete (fallback behaviors)
- Token revocation cannot be verified (fail-secure defaults)

**Fail-secure defaults:** When in doubt, RPs **SHOULD**:
- Treat "Revoke All Authentication State" as requiring immediate session termination
- Require fresh authentication even if protocol mapping is unclear
- Log security actions for audit and troubleshooting

---

## 11. Security Considerations {#security}

### 11.1 Threat Model {#threat-model}

These security actions address:

- **Session hijacking:** Expire Interactive Session terminates compromised sessions
- **Token theft:** Revoke All Authentication State revokes stolen tokens
- **Account compromise:** Revoke All Authentication State provides containment mechanism
- **Unattended sessions:** Expire Interactive Session mitigates walk-away risk

### 11.2 Protocol Security {#protocol-security}

- **Transport security:** All protocol messages **MUST** use TLS 1.2 or higher
- **Message integrity:** Security actions **MUST** be authenticated (signed, MAC'd, or over authenticated channel)
- **Replay protection:** Security actions **SHOULD** include nonces or timestamps
- **Authorization:** RPs **MUST** verify that security actions are authorized by the IdP

### 11.3 Enforcement Gaps {#enforcement-gaps}

Current protocol limitations create enforcement gaps:

- **Browser-dependent mechanisms:** May fail silently
- **Self-contained tokens:** Cannot be immediately invalidated without RS participation
- **Event frameworks:** Require profiling to mandate enforcement

Implementers **SHOULD** use protocol profiles that address these gaps.

### 11.4 Fail-Secure Defaults {#fail-secure}

When in doubt, RPs **SHOULD**:

- Treat "Revoke All Authentication State" as requiring immediate session termination
- Require fresh authentication even if protocol mapping is unclear
- Log security actions for audit and troubleshooting

---

## 12. Privacy Considerations {#privacy}

### 12.1 User Notification {#user-notification}

When security actions are executed, users **MAY** be:

- Redirected to IdP for re-authentication (transparent)
- Notified of session termination (if policy requires)
- Informed of account status changes (if applicable)

### 12.2 Data Minimization {#data-minimization}

Security actions **SHOULD** include only:

- Subject identifier (to identify the user)
- Action type (Expire Interactive Session or Revoke All Authentication State)
- Timestamp (for ordering and replay protection)
- Optional: Reason code (for audit and troubleshooting)

### 12.3 Audit Logging {#audit-logging}

RPs **SHOULD** log:

- Receipt of security actions
- Enforcement of security actions
- User re-authentication events
- Failures or errors in processing

---

## 13. IANA Considerations {#iana}

This document defines no new IANA registries. It references existing registries:

- OAuth 2.0 Authentication Method Reference (AMR) Values Registry
- OAuth 2.0 Token Type Hints Registry (for token revocation)

---

## 14. References {#references}

### 14.1 Normative References {#normative-refs}

**[RFC2119]**  
Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, DOI 10.17487/RFC2119, March 1997, <https://www.rfc-editor.org/info/rfc2119>.

**[RFC6749]**  
Hardt, D., Ed., "The OAuth 2.0 Authorization Framework", RFC 6749, DOI 10.17487/RFC6749, October 2012, <https://www.rfc-editor.org/info/rfc6749>.

**[RFC7009]**  
Lodderstedt, T., Ed., Dronia, S., and M. Scurtescu, "OAuth 2.0 Token Revocation", RFC 7009, DOI 10.17487/RFC7009, August 2013, <https://www.rfc-editor.org/info/rfc7009>.

**[RFC7662]**  
Richer, J., Ed., "OAuth 2.0 Token Introspection", RFC 7662, DOI 10.17487/RFC7662, October 2015, <https://www.rfc-editor.org/info/rfc7662>.

**[OIDC.Core]**  
Sakimura, N., Bradley, J., Jones, M., de Medeiros, B., and C. Mortimore, "OpenID Connect Core 1.0", December 2023, <https://openid.net/specs/openid-connect-core-1_0.html>.

**[SAML2.Core]**  
Cantor, S., Kemp, J., Philpott, R., and E. Maler, "Assertions and Protocols for the OASIS Security Assertion Markup Language (SAML) V2.0", OASIS Standard, March 2005, <http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf>.

**[SharedSignals]**  
Backman, A., et al., "Shared Signals Framework", OpenID Foundation, <https://openid.net/specs/sharedsignals-framework-1_0.html>.

### 14.2 Informative References {#informative-refs}

**[OP-Commands]**  
Jones, M., et al., "OpenID Provider Commands", OpenID Foundation, <https://openid.net/specs/openid-provider-commands-1_0.html>.

**[CAEP]**  
Backman, A., et al., "Continuous Access Evaluation Protocol (CAEP)", OpenID Foundation, <https://openid.net/specs/openid-caep-1_0.html>.

**[NIST.SP.800-63B]**  
Grassi, P.A., Newton, E.M., Perlner, R.A., and A.R. Regenscheid, "Digital Identity Guidelines: Authentication and Lifecycle Management", NIST Special Publication 800-63B, June 2017, <https://pages.nist.gov/800-63-3/sp800-63b.html>.

---

## 15. Change Log {#changelog}

* **Implementer's Draft 1 — 2025-01-XX**
  * Initial publication of **IdP → RP Security Actions for Access Revalidation**
  * Defines two distinct security actions: Expire Interactive Session and Revoke All Authentication State
  * Maps actions to existing protocols (OIDC, SAML, OAuth, Shared Signals)
  * Establishes authentication vs authorization boundary
  * Provides protocol selection guidance and recommendations

---

## Appendix A. Use Case Examples {#appendix-use-cases}

### A.1 Use Case 1: Expire Interactive Session {#uc-expire}

**Scenario:** A user logs out of the IdP, or their session expires due to inactivity.

**Goal:** Terminate the RP's current interactive session and force fresh authentication.  
**Non-Goal:** Revoke tokens or modify authorization.

**Protocol Flow:**
1. User initiates logout at IdP
2. IdP sends OIDC Back-Channel Logout token to RP
3. RP terminates local session
4. RP deletes session cookies
5. User must re-authenticate on next access

**Expected Outcome:** User's interactive session is terminated, but background API operations using existing tokens continue.

### A.2 Use Case 2: Revoke All Authentication State {#uc-revoke}

**Scenario:** Security team detects account compromise or policy violation.

**Goal:** Revoke all prior authentication state (sessions and tokens).  
**Non-Goal:** Change roles, permissions, or entitlements.

**Protocol Flow:**
1. Security team triggers account invalidation at IdP
2. IdP sends "Revoke All Authentication State" command via OP Commands (or equivalent)
3. IdP revokes refresh tokens at Authorization Server
4. RP receives command and terminates session
5. RP rejects existing access tokens
6. Resource Servers reject tokens via introspection
7. User must re-authenticate with fresh credentials

**Expected Outcome:** All authentication artifacts are invalidated, user must re-authenticate, but authorization (roles/permissions) remains unchanged.

---

## Appendix B. Quick Reference {#appendix-quick-ref}

### B.1 Decision Tree {#decision-tree}

```
Is this a security incident or account compromise?
├─ YES → Use "Revoke All Authentication State"
│   ├─ Terminate sessions
│   ├─ Revoke tokens
│   └─ Require fresh authentication
│
└─ NO → Use "Expire Interactive Session"
    ├─ Terminate session only
    ├─ Leave tokens unchanged
    └─ Require fresh authentication
```

### B.2 RP Checklist {#rp-checklist}

When receiving a security action:

- [ ] Verify action is authenticated (signed/authorized)
- [ ] Identify action type (Expire Interactive Session vs Revoke All Authentication State)
- [ ] Terminate interactive session
- [ ] Delete session cookies
- [ ] If "Revoke All Authentication State": reject existing tokens
- [ ] Require fresh authentication on next access
- [ ] Log action receipt and enforcement
- [ ] Do NOT change authorization (roles/permissions)

### B.3 IdP Checklist {#idp-checklist}

When sending a security action:

- [ ] Determine appropriate action type
- [ ] Authenticate the action (sign/MAC)
- [ ] Include subject identifier
- [ ] Include timestamp
- [ ] If "Revoke All Authentication State": revoke tokens at AS
- [ ] Send via appropriate protocol(s)
- [ ] Log action transmission

---

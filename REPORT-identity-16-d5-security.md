# identity-16 — D5, the standing security review

The audit is bounded, as the packet asked: **token minting and verification
(claims, scopes, expiry)**, the **OIDC client flows**, **session lifetime and
revocation**, and the **admin API's authorization checks**. What is below is what
I read, what I could demonstrate, and what I deliberately did not fix.

One finding is exploitable-now and is fixed with a red-green pair. Two more are
real and are reported unfixed, with the reason each one was left alone — in both
cases because the honest fix is a design decision that belongs to whoever owns
the contract, not to a review.

---

## Finding 1 — an authorization request was spendable by any browser holding the victim's session

**Exploitable-now. FIXED.**

### Where

- `internal/httpapi/oidc.go:405-417` (before the fix) — `handleOIDCLogin`'s silent
  path called `finishOIDCLogin` for any request presenting a live session cookie.
- `internal/oidc/authrequest.go:25-27` — the comment on the request id claimed
  *"it is not a credential: it names a request, and a request is only worth
  anything to a user who then authenticates against it."* On the silent path a
  request **is** worth something to a user who has not authenticated in it.

### The exploit

`GET /oidc/login/{requestID}` completed the authorization request for whoever
presented a session cookie. The request id is a uuid in a URL — in the address
bar, in history, in whatever link somebody was sent — so the only thing standing
between "the browser this flow was handed to" and "any browser signed in as the
same user" was that id being unguessable, which is not a property a user-agent
boundary respects.

1. The attacker is any registered tenant. `POST /v1/accounts/{id}/oidc-clients`
   is owner-gated, and every registration creates a personal account, so this is
   self-service and free (`oidc.go:872`).
2. They register a client with a `redirect_uri` on a host they control, take its
   one-time secret, and start `/oidc/authorize` with their own PKCE challenge.
   They get `/oidc/login/{id}` and keep the verifier.
3. They send the victim that login URL as a link. `SameSite=Lax` cookies ride a
   top-level navigation, so the victim's session is sent.
4. The victim's browser completes the request with **no interaction**: no form, no
   password, no second factor. The response is a 302 to the attacker's
   `redirect_uri` carrying a `code`.
5. The attacker redeems it with their own secret and their own verifier and
   receives an `id_token` whose `sub` is the victim.

`state` does not help, and the reason is worth being precise about: state is the
**client's** CSRF defence against the client's own callback, and here the
attacker *is* the client. `prompt=login` and `max_age` — the two levers a client
has for demanding interaction — were both refused by `checkAuthorizeParams`
(`oidc.go:256-258`), so there was nothing left to fall back on.

### Demonstration

Both tests in `internal/httpapi/oidc_browser_binding_test.go` are red on the
unfixed code, and the second one runs the whole chain with two different people
in it. With the fix reverted:

```
--- FAIL: TestAnAuthorizationRequestIsNotSpendableByABrowserThatDidNotStartIt
    a browser that never started this flow completed it: GET /oidc/login/44f2e23f…
    answered 302 carrying an authorization code to https://app.example.com/cb.
--- FAIL: TestAnAttackerExchangesACodeTheVictimsBrowserMintedForThem
    the attack completed: … the attacker exchanged it for an id_token whose
    subject is e8641ca4-f904-4c62-b19e-b3f6a91d87db — a user who never started
    this flow, never saw its login page and never typed a password for it.
```

### The fix

A `__Host-oidc-flow` cookie, set at `handleOIDCAuthorize` (`oidc.go:205-243`) and
required by `browserStartedThisFlow` (`oidc.go:444-449`) before any completion.

The authorize handler is the only place the *start* of a flow is observable. The
login page cannot set the cookie, because by the time it runs the two cases are
indistinguishable — a browser that legitimately followed the redirect and one that
followed a link are the same GET with the same ambient cookie. `__Host-` is what
makes it unforgeable from another origin; that is the entire property being spent.

It is deliberately **not** keyed by request id: the id does not exist until the
library has created the row, which is after the cookie must already have been
written, and binding it later would mean the cookie is set by the very page the
attack targets.

### The honest limit

The request id is still a bearer capability for *rendering a form*. An attacker
can still show a victim a login page for the attacker's own client — that is the
documented absence of a consent screen (`openid/openid.yaml:93-94`,
`README.md:1129-1135`). What they can no longer do is have the victim's existing
session sign it while the victim sees nothing. This closes the session-riding
half; the consent half is a product decision that was already on the record.

---

## Finding 2 — `POST /v1/introspections` answers "is this leaked token still live?"

**Exploitable-with-preconditions. NOT FIXED — see why.**

### Where

`internal/httpapi/apikeys.go:466-490` and `mayIntrospect` at `:500-534`.

The comment at `:481-484` says:

> The caller's standing, checked AFTER the token resolved … so an unknown token is
> `{"active": false}` for everybody … and the response cannot be used to find out
> whether a value is real.

It can, and it is the status code:

| named token | response |
|---|---|
| dead, revoked, expired, unknown | `200 {"active":false}` |
| live, caller may not read it | `403` / `404` |

The route is also ungated: `registerIntrospectionRoute` (`apikeys.go:415-420`)
mounts it with no `requireAccountRole`, so `scopeRequiredBy` is never consulted
and *any* live credential qualifies — a session cookie is enough.

### What it buys

Not discovery; the candidate is 256 bits of `crypto/rand`. **Triage.** The
realistic leak is a credential in a CI log, a shell history or a paste buffer —
which is exactly what the `cafaye_` prefix exists to make greppable
(`apikeys.go:62-75`). Given N such values this turns "rotate all N and hope" into
"rotate the ones still live", without ever using one.

I demonstrated it (200 vs 403 for identical caller standing), then **reverted the
fix I had written.** Two reasons, and they are the reason this is reported rather
than shipped:

1. **It needs a precondition.** The attacker must already hold the candidate
   value. That is `exploitable-with-preconditions` by the packet's own
   classification, so it does not carry the "test + fix" obligation — and the
   yield is a triage boolean, not access.
2. **Both available fixes are worse trades than the finding.** Refusing dead
   tokens to session callers (what I tried) breaks
   `TestAnUnusableTokenIsInactiveAndCarriesNothingElse`, which deliberately
   encodes "an unusable token is an answer, not a failure" — and it costs a
   documented owner capability. The other fix, attributing a dead token to its
   account so entitlement can be decided for it, means splitting `ByDigest`'s
   single statement, which is precisely the four-filters-in-one-query design that
   exists so the refusals are indistinguishable by timing. Either way this is a
   contract decision for whoever owns the surface.

Recorded for that decision, with the trade-off written down.

---

## Finding 3 — the published contract cannot mint a credential that reaches any admin route

**Correctness/availability. NOT FIXED — out of the audit's ownership surface.**

`openapi/v1.yaml`'s `APIKeyScope` enum (`:2131-2141`) and `x-scopes` (`:2019-2023`)
list **four** scopes. The code implements **six** (`apikeys.AllScopes()`,
`apikeys.go:238-243`). `audit_log:read` and `account_invitations:write` appear in
`openapi/v1.yaml` only inside prose.

Those two missing scopes are what `accountRouteScopes` gates the three admin
routes on (`accounts.go:188-190`), and `requireAdminToken` makes those routes
token-only. So an integration working from the published contract cannot mint a
credential that reaches any admin route — and the generated client, which mirrors
the enum, cannot even name them.

It fails closed, so it is not a security hole; it is a contract that under-describes
the service. It is also exactly the drift `AGENTS.md` claims is walked
("`accountRouteScopes` is the only scope table, and the OpenAPI document is its
mirror") and is not: no test compares the enum against `AllScopes()`. Flagged
because it makes the admin surface unreachable in practice, which is worth knowing
before someone concludes the gate is well-defended.

---

## Also found, below the bar for a fix

- **`F1` — the second-factor error page mints a `state` with no cookie**
  (`oidc.go:523-557`). `renderOIDCChallengeError` writes a fresh `state` into the
  form but never sets the matching cookie, so **one wrong MFA code makes the retry
  impossible**: the next submit finds no cookie and gets a 400. The success path
  (`renderOIDCChallenge`, `:471-472`) correctly sets both. It fails closed and is
  a correctness bug rather than a vulnerability — but it contradicts the
  repository's own contract at `openid/openid.yaml:669-679`. One line.
- **`F2` — `auth_time` and `amr` assert an authentication that did not happen**
  (`oidc.go:405-417` silent path, `authrequest.go:156-170`, `storage.go:377-392`).
  `auth_time` is stamped with *now*, not with the session's authentication time, and
  `amr` claims `pwd` for a request where no password was presented. A relying
  party gating on `auth_time` recency is misled. `GetAMR`'s own comment says "a
  token that claimed a method nobody used is a token a relying party might make a
  decision on" — here a method *is* claimed and nobody used it.
- **`F3` — `setUserinfo` never re-checks the client's `RevokedAt`**
  (`storage.go:553-580`), unlike `clientRowFor` (`:727-729`) and
  `AuthorizeClientIDSecret` (`:103-105`). A revocation racing an in-flight token
  exchange leaves a window where userinfo answers 200 for a revoked client.
  Hardening in practice — the window is one request wide.
- **`F4` — a `validateScopes` function that does not exist** is named as the thing
  enforcing scope clipping (`storage.go:198-201`). The enforcement is real (the
  library's clip plus the intersection at `:582-587`, both tested), but the comment
  points a reviewer at dead code for the one property it names.
- **`F5` — `Allows("")` is not unconditionally false** (`store.go:106`). The
  database permits `scopes = {''}` (`00011` checks `cardinality > 0`, not the
  elements), and `slices.Contains([""], "")` is true — which would open the
  deliberately-undeclared credential routes. **No shipped write path can produce
  it** (`ValidateScopes` skips `""`), so this is hardening, not a live hole. It
  matters because the repository states the invariant twice as *structural* while
  the layer that cannot be bypassed does not enforce it.
- **`F6` — `expires_in` floor disagrees three ways.** `MinTTL` is `24 * time.Hour`
  (`apikeys.go:121`), its comment says "an hour" (`:115`), and the contract says
  `minimum: 1` (`v1.yaml:2357`). Zero security impact; fails closed.
- **Out of the bounded scope, recorded because it is real:**
  `membershipResponses` (`accounts.go:923-929`) projects only `Role`, so
  `GET /v1/accounts/{id}` and `…/members` return members with empty
  `account_id`/`user_id` and a zero `created_at`. The document has no `Membership`
  schema, so nothing fails; the response is simply unusable.

---

## What I checked and found sound

Reported because an audit is more useful with its negatives stated.

- **Authorization code replay — no defect.** `ConsumeAuthCode`
  (`authrequest.go:208-232`) is one conditional `UPDATE` in a CTE, and the outer
  `SELECT` discriminates on `r.code_digest = $1` as well as the `IN`; the
  `code_digest` partial unique index (`00009:172-174`) makes "a different row with
  the same digest" impossible rather than unlikely. Covered by
  `TestOIDCReplayedCodeIsRefused` and a concurrent race test.
- **PKCE — no bypass.** Absent method, non-`S256` (case-sensitively), and
  `S256`-with-empty-challenge are all refused on **both** GET and POST, the table
  CHECK pins the method, and `requireS256` re-refuses at redemption. `plain` is
  unreachable.
- **Redirect URIs — exact match only.** `protocolClient` implements no
  `op.HasRedirectGlobs`, so the library's `slices.Contains` is the only path.
- **Revoked/unknown clients are refused at the token endpoint**, collapsed into one
  400 so a caller cannot enumerate registered products.
- **No scope escalation.** The library clips unregistered scopes, `IsScopeAllowed`
  is an exact match against a closed set, `setUserinfo` intersects again and
  refuses outright when the intersection lacks `openid`.
- **Expiry is consistent on every read path.** `Key.IsExpired` and the resolution
  query agree on the boundary; verification, introspection and the join all route
  through one `ByDigest`. **No path treats an expired token as live.**
- **The scope gate is fail-closed on every account route**, subject to F5.
- **No TOCTOU revives a token.** `Touch` writes only `last_used_at` and is
  conditional on `revoked_at IS NULL`; nothing in the codebase sets `revoked_at`
  back to NULL. `RemoveMember` revokes in the same transaction as the membership
  delete, so remove-and-re-invite does not resurrect a credential.
- **Session lifetime and revocation hold.** Revoke-all-on-MFA-enable and on-disable
  are inside the enrolment transaction (`mfa/service.go:408`, `:902`);
  `Logout` resolves then revokes by id; `Revoke` is idempotent. The gap is
  breadth, not correctness: there is no "list my sessions" or "revoke all my
  sessions" route, so a user who suspects a stolen session can only revoke the one
  they are holding.
- **The admin surface's authorization checks are the strongest thing in this
  repository and I could not dent them.** Token-only and enforced outside the
  handlers; role re-read from `account_users` on the request; account binding
  checked; scope from the single table; mutation and audit row in one transaction
  with the immutability trigger in the database. I looked specifically for a
  second way to reach those three routes and there is not one.

---

## The gate

One suite at a time, DB tier on, `TEST_DATABASE_URL` at :5433.

| gate | result |
|---|---|
| `bin/prime` | **ok** — 21 packages, all green |
| `go vet ./...` | **ok** |
| `gofmt -l .` | **ok** — prints nothing |
| `go test -race ./...` | **ok** — all 21 packages |
| coverage floor | **73.6%** against a 70% floor |

**Pass and skip counts, separately:**

```
PASS: 816
SKIP:   0
FAIL:   0
```

Zero skips, including subtests — worth stating on its own because `AGENTS.md`
records that a suite reporting `ok` without proving anything is the failure mode
this repository treats as worst, and CI fails on any `--- SKIP:` line.

**Secrets rule.** No token, key, secret or JWT appears in the tests, the report,
the CHANGELOG, or this commit message. Test fixtures use the package's existing
obviously-fake constants (`apiKeySecret`, `fakeKeyPrefix`) and per-run `uuid`s. The
one credential-shaped value printed anywhere is a request id from a failing
assertion, which the service itself puts in a URL.

**Ownership.** `gate.yml`, the `account_id` fallback and the compose files are
untouched. The CHANGELOG entry is appended at the top of `[Unreleased]`. Nothing
is pushed.

**Files changed**

- `internal/httpapi/oidc.go` — the fix
- `internal/httpapi/oidc_browser_binding_test.go` — new, the red-green pair
- `CHANGELOG.md` — the entry
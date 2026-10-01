# Open decisions

Every question this repository has not been told the answer to, numbered, with
the call that was made so the work could continue and the cost of making the
other one.

This file did not exist before packet `identity-09`. The two places an open
question in this repository used to live were `moon/DECISIONS.md` — which numbers
`MD…` and holds questions about the workspace rather than about one service — and
a `> DECISION NEEDED (…)` callout in `cafaye.yml`, which is where the
`openapi/v1.yaml` scope-claim question lives and which core's D6 shape moved
away from. Neither is identity's own record, and a packet that had to escalate
something had nowhere to put it. So the file is `DECISIONS.md` at the repository
root, numbered from D1, and the callouts in `cafaye.yml` keep pointing at the
question they raise.

**A settled decision moves into the [CHANGELOG](CHANGELOG.md)'s decision table
and its entry here is deleted; the number is never reused.**

| # | Question | Call made |
| --- | --- | --- |
| [D1](#d1-twelve-served-operations-are-in-no-document) | twelve served operations are in no document — document them, or rule them out of the contract? | not decided: the tripwire ships holding all twelve in a pinned list, and the question is escalated here |
| [D2](#d2-the-privilege-boundary-of-the-admin-surface) | what exactly may an account admin do that a member may not? | RULED: one sentence, and the code says exactly it. Three operations, two scopes, one table |
| [D3](#d3-where-the-audit-record-lives-and-why-nothing-can-edit-it) | where does the admin audit record live, and how is it made un-editable? | RULED: `account_audit_log`, append-only in the DATABASE, no foreign key to `accounts` |
| [D4](#d4-the-admin-surface-is-token-only) | may a browser session reach the admin surface? | RULED: no. Token-only, and the refusal is asserted per route |
| [D5](#d5-bulk-and-single-revocations-do-not-share-a-shape) | does a bulk revocation take the same request shape as a single one? | RULED: no. `confirm` in the body, a higher minimum, and both counts returned |
| [D6](#d6-the-generated-client-commits-a-dependency-that-md6-said-it-would-not) | the generated client commits a runtime dependency, which MD6 said it would not — and it takes the coverage floor | RULED, with MD6's stated REASON corrected: the client ships here, generated, and the dependency is paid for |
| [D8](#d8-one-link-template-for-four-messages-and-what-the-deployment-inherits) | one link template served all four messages — so a verification mail's button opened the password-reset screen. What does the template a deployment already set now MEAN? | RULED: it is the DEFAULT for every purpose with no template of its own, so nothing breaks at boot, and a purpose with neither is refused by name at startup |

## D1: twelve served operations are in no document

**Raised** 2026-09-30 by packet `identity-09`, which added the document-versus-
router tripwire (`internal/httpapi/openapi_drift_test.go`) and found this on its
first run. It is a finding, not a nuisance, and it is the seventh such check in
the fleet to fire.

**What was found**, read out of chi's own walk of the router and out of both
committed documents rather than off a list anybody wrote:

- **Ten tenancy operations.** `POST` and `GET /v1/accounts`,
  `GET`, `PATCH` and `DELETE /v1/accounts/{account_id}`,
  `GET /v1/accounts/{account_id}/members`,
  `POST /v1/accounts/{account_id}/invitations`, `PATCH` and
  `DELETE /v1/accounts/{account_id}/members/{user_id}`, and
  `POST /v1/invitations/accept`. Served since the accounts packet. In neither
  `openapi/v1.yaml` nor `openid/openid.yaml`, and not in the README's endpoint
  table either — so the document, the manifest's `exposes.api` and the README all
  describe a smaller service than the one that runs.

  They are not untested. All ten are rows in the authorization matrix, and seven
  of them declare a scope in `accountRouteScopes`, so they are gated, scope-
  checked and exercised. What is missing is that nobody ever wrote down that they
  are contract surface. That is the specific shape of the gap: **checked for
  authorization, unrecorded as contract.**

- **Two OIDC operations.** `POST /oidc/authorize` and `POST /oidc/userinfo`.
  `registerOIDCRoutes` mounts `GET` and `POST` on both, and says why in a
  comment: OpenID Connect Core permits both and "a product behind a strict
  corporate proxy may have no choice". `openid/openid.yaml` wrote down only the
  `GET`.

  This one is worth reading twice, because it is **billing's bug, already here**.
  billing's first drift check compared paths and never `route.verb`, so
  `resources :customers, only: %i[… update]` emitting both `PATCH` and `PUT`
  passed it: one path on each side, and the comparison reported agreement while
  `PUT /v1/customers/{id}` was served in a money-handling service and written
  down nowhere. The shape is identical here, on the OIDC surface of the service
  that issues every credential in the platform.

**What this packet did, and why not more.** `identity-09` was scoped to add a
check and explicitly not to add operations, so the two obvious fixes were both
closed: writing the twelve operations into `openapi/v1.yaml` is a content change
this packet may not make, and calling them "not client operations" in an
exclusion list would be false about all twelve — they are the most client-facing
routes in the service.

So the twelve sit in `knownDrift` in `openapi_drift_test.go`, which is named for
what it is rather than for what it excuses, and which:

- cannot grow — `TestKnownDriftIsExactlyTheRoutesItClaimsToBe` fails on a
  thirteenth entry, so a new undocumented route is red whether or not anybody
  remembers that file;
- cannot be emptied either, so the list cannot be deleted instead of the routes
  being fixed;
- is checked for staleness in both directions — an entry naming a route the
  router no longer serves, or one a document now describes, is a failure.

**The two calls available**, and this packet did not make either:

1. **They are contract surface; document them.** Twelve operations with full
   request and response schemas, an `info.version` bump, a CHANGELOG entry naming
   the operations added, and rows in the README's endpoint table. This is the
   answer that makes `knownDrift` empty and is almost certainly right for the ten
   tenancy routes — the platform generates clients from these documents, and a
   product that cannot call `POST /v1/invitations/accept` from a generated
   client has a real gap. The cost is a large document change in a packet that
   has to be its own, and it should be reviewed as contract rather than as
   bookkeeping.

2. **They are not contract surface; rule them out of it, in writing.** The
   `/v1/accounts` collection routes are the arguable ones: `GET /v1/accounts`
   answers "which accounts does this **user** belong to", which is a session's
   question and not a token's, and the README already argues a machine credential
   is not entitled to an inventory of every tenant its owner is in. If that logic
   extends to "these are never client operations", it has to be recorded — in the
   document's own header and in the README, which is what courier's
   `openapi_document_test.exs` requires of its own exclusions, and what makes the
   ruling a claim rather than a gap the check happened to miss.

The two OIDC `POST`s are not seriously arguable under either answer: the code
says both methods are deliberate, so the document either gains a `post` beside
its `get` or the router drops the `POST`. Dropping it would contradict the
comment that justifies it, and would break a product behind a strict corporate
proxy, which is the case the comment names.

**What is not an answer**: growing `knownDrift`, or adding a prefix filter to the
check. Both make a red go away without making the service true, and the first is
the failure mode the packet's own test exists to catch.

**Update from `identity-11` (the admin surface).** This packet added three
operations to the router and `knownDrift` **did not grow** — it is still twelve,
and `TestKnownDriftIsExactlyTheRoutesItClaimsToBe` still pins it at twelve. The
three were **documented** in `openapi/v1.yaml` under a new `admin` tag, with
operationIds, request and response schemas, and `info.version` bumped to 1.4.0.

That is the answer to D1's option 1, applied to three operations, and it is
evidence rather than argument: adding a route to this service is a routine
operation when the route is documented, and the twelve below are still
undocumented because nobody has done it for them.

**A finding worth recording, because it is about this file's own check.**
`identity-11` found that `TestEveryServedRouteIsDocumentedOrNamed` — the reverse
direction, the check holding these twelve — **passed green while three
undocumented operations were mounted**. `servedRoutes` builds an `options` struct
literal to make every conditional surface take its "configured" path, and the new
`admin` field was not in it, so `registerAdminRoutes` returned early and the walk
read a smaller service than the one that runs. `TestEveryRouteIsInTheMatrix` was
blinded the same way, at the same time.

The check went green **by not checking**, which is the one outcome this file
exists to prevent, and it happened to the check written to catch precisely that.
`internal/httpapi/router_walk_test.go` now holds the property:
`TestTheDriftWalkSeesTheAdminSurface` and `TestTheMatrixWalkSeesTheAdminSurface`
assert the walks FIND the routes, and `TestEveryConditionalSurfaceIsVisibleToTheWalk`
keeps a list of every surface field that can cause a registrar to skip its routes.

The general lesson, and the reason it is in DECISIONS.md rather than only in a
test comment: **a struct literal used to configure a check is a completeness
obligation, and nothing about it looks like one.** A conditional route makes the
omission silent and the suite green.

## D2: the privilege boundary of the admin surface

**Raised** 2026-09-30 by packet `identity-11`, which added the admin surface and
had to say what it was for before it could be reviewed.

**Ruled: an account admin may revoke pending invitations to their own account and
read that account's admin audit log — authority over other people's pending
access, and nothing else.**

One sentence, and the reason for insisting on one sentence rather than a
paragraph is the sentence's own failure mode: **a role checked in thirty places
is a role that will be checked in twenty-nine of them.** So the sentence is not
documentation of a boundary, it is the boundary, and the code says exactly it:

| operation | minimum | scope |
| --- | --- | --- |
| `GET /v1/accounts/{id}/admin/audit-log` | admin | `audit_log:read` |
| `DELETE /v1/accounts/{id}/admin/invitations/{id}` | admin | `account_invitations:write` |
| `POST /v1/accounts/{id}/admin/invitation-revocations` | **owner** | `account_invitations:write` |

Three rows in `accountRouteScopes`, and there is no fourth without a decision:
`TestTheScopeTableIsTheWholeBoundary` fails if the table gains an admin route, and
a new capability is a new scope in `internal/apikeys`, which is a file whose whole
argument is that a token is granted exactly what it names.

**The one-sentence test, and what it rules out.** Read the sentence and ask what
is not in it:

- **Not "manage the account".** `accounts:write` already covers rename, invite
  and remove-member, and an admin holds it. The admin surface is *not* that
  surface and deliberately overlaps none of it.
- **Not "read anything about members".** `accounts:read` covers that.
- **Not "see the account exists".** The trail is a record of *authority being
  used over time*, which is a different sensitivity from the account's current
  shape — which is why it has its own scope rather than riding on `accounts:read`.
  A CI token that can read the account should not thereby hold a standing record
  of every administrative action taken against it.
- **Not "act for any user".** There is no impersonation here, and adding it would
  be a fourth capability the sentence does not contain.

**Why invitation revocation, specifically.** 00007's own comment says a user
deletion is "refused by the database until they are revoked, which is a later
packet" — this is that packet's schema half. It is also the operation with the
right blast radius to justify a separate surface: an admin who sent an
invitation to the wrong distribution list needs to recall it, and the obvious
implementation (`DELETE` the row) would have destroyed the answer to "was this
revoked, or was it always broken?" — the same support question that keeps revoked
api keys and OIDC clients. So `revoked_at` is a column and the row is kept
(00013), and revoking **frees the address to be invited again**, which is the
whole point of the operation.

**Not a decision this packet could make:** a *platform* admin — one operator
across every tenant — does not exist and is not implied. The sentence is scoped
to "their own account" and the code enforces it: a token presented against a path
naming a different account is a 404 from `requireAccountRole`'s existing
membership lookup, and `TestAnAdminCannotReadAnotherAccountsTrail` proves it
over real SQL. A cross-tenant operator surface is a different design with
different answers, and building it needs a decision this packet may not make.

## D3: where the audit record lives and why nothing can edit it

**Raised** 2026-09-30 by packet `identity-11`.

**Ruled: `account_audit_log`, in identity's own database, appended in the same
transaction as the mutation, and refused `UPDATE` and `DELETE` by a database
trigger.**

**Why the same transaction, and how it is not merely intended.** Every operation
on `admin.Service` goes through `Audited`, which takes the mutation as a callback
and runs it inside the transaction that also writes the record. There is no
exported method that mutates without recording, so "somebody added an admin
action and forgot the audit row" is not a mistake this package's shape permits —
it needs a new exported method, which a review sees.

The proof is in both directions and both are asserted against a real database
with a `BEFORE INSERT` trigger that raises
(`TestAFailedAuditWriteRollsBackARealMutation`,
`TestAFailedMutationRollsBackARealAuditRecord`):

- the audit write fails → the transaction rolls back → **the mutation did not happen**
- the mutation fails → the transaction rolls back → **no record claims it did**

Asserting the happy path would have proved nothing, which is why the negative
proofs are the ones that carry the weight and the positive one
(`TestTheAuditRecordIsWrittenInTheSameTransactionAsTheAction`) exists only to
show the happy path writes *both* rows — a service that rolled back everything
would pass the negatives perfectly.

**Why the immutability is in the DATABASE and not in Go.** Three layers, in the
order a reviewer asks:

1. `GET` is the only method mounted on the audit path —
   `TestTheAuditTrailIsNotWritableThroughThisAPI` walks the router, because a
   check inside the handler would pass with a `DELETE` registered beside it.
2. `AuditStore` has `Append` and `List` and nothing else, so there is no
   function to call.
3. **The table refuses `UPDATE` and `DELETE`** (00012's trigger).

The third is the one that settles it, and the reason is that the first two only
describe *this codebase*: a repair script, an operator with `psql`, or a future
packet all bypass Go entirely, and the requirement is that the record survives
the admin whose action is in it. `TestTheAuditRecordCannotBeUpdated` and
`TestTheAuditRecordCannotBeDeleted` issue the statements **directly against the
pool**, which is what makes them proofs rather than restatements of the service's
own API.

**Why there is no foreign key to `accounts`, and this is the load-bearing line of
00012.** Every other table in this schema cascades from `accounts`. A cascade is a
`DELETE`, and this table does not delete — so a cascading account deletion would
be blocked, and `DELETE /v1/accounts/{account_id}` is a shipped route a tenant may
legitimately call. Exempting the cascade is not reliably possible: a trigger
cannot tell a cascading delete from a deliberate one.

Dropping the reference instead buys the strongest form of the property:

> **The admin surface cannot delete its own audit log by deleting the account.**

The shortest route from "an admin did something questionable" to "there is no
record of it" would otherwise be one request, and this packet's requirement would
be satisfied by the router rather than defeated by it. The rows become
unreachable through the API and are retained for an operator reading the table
directly. Same for the actor: `actor_key_id` is a bare uuid, so revoking or
deleting the credential does not erase what it did
(`TestTheAuditLogCannotBeReachedByRevokingTheToken`).

**Never a credential.** `actor_user_id` and `actor_key_id` are row ids, and there
is no field anywhere in `internal/admin` that a token could be written into. That
is structural, not a convention: `apikeys.Key` has a `TokenDigest` field, a
handler holds one, and an audit log is exactly where a careless
`fmt.Sprintf("%+v", caller)` would end up.
`TestNothingOnThisSurfaceCanRecordAToken` reflects over the types that reach the
table and fails if any grows a field that could hold a value, and
`TestAnAdminActionNeverWritesACredential` checks all four places a record could
leak — response body, audit row, application log, and problem document.

## D4: the admin surface is token-only

**Raised** 2026-09-30 by packet `identity-11`.

**Ruled: no admin route is reachable with a user session. A session is refused
with 403, and the refusal is asserted per route rather than in a helper.**

The security argument is the packet's: a session is a browser credential, and an
admin surface a session cookie opens is an admin surface one CSRF away from being
somebody else's. The second argument is this one, and it is the more interesting:
**an admin action must be attributable to a credential.** Every action on this
surface is recorded against the api key's row id, so a token is something an
audit record can *name* and a session is not. `adminActorFrom` refuses a caller
whose `KeyID` is zero rather than writing a record naming no credential.

This is the exact mirror of `sessionCredentialOnly`, and the two together mean no
route in this service is reachable by both kinds of credential unless somebody
wrote that down deliberately. `requireAdminToken` runs **outside**
`requireAccountRole`, which is what makes it a property of the surface: a check
inside a handler has whatever that handler remembered, and the route added next
is the one without it.

**Two consequences worth recording, because both are visible in the matrix and
both would otherwise read as bugs.**

- **The anonymous column is 403 on these three routes and 401 on every other row
  of the authorization matrix.** `requireAdminToken` runs first, so a request
  with no credential at all is refused as a *wrong kind of caller* — and on a
  route whose entire authentication story is "a scoped api key", that is the more
  informative answer than "who are you". `expectedStatus` in the matrix had to
  have its override checked *before* its authentication check for this to be
  recordable at all; it was the other way round, and the three rows were silently
  being answered 401 for a service that does not give that.
- **The matrix has a genuine hole on this surface, and it is stated rather than
  papered over.** The matrix's six columns are six *sessions*, so on a token-only
  surface every column is a 403 and the matrix carries no positive cell for these
  three routes at all. The token/session axis is the authorization this packet
  adds and the matrix cannot express it. What covers it instead:
  `TestNoAdminRouteIsReachableWithASessionAlone` (per route),
  `TestAnAdminTokenHoldingNeitherScopeIsRefused`,
  `TestTheBulkRouteIsOwnerOnly` (per role), and the rows are in the matrix so
  `TestEveryRouteIsInTheMatrix` still demands them.

**R2, the accountless token.** A service-to-service token with no `account_id` is
**refused, not defaulted**, and this packet did not need to build the refusal
because `api_keys.account_id` is `NOT NULL` and `claims.ClaimsFor` returns
`ErrNoAccountID`. What the packet owes is the *proof per route*, and that needs a
double: a token with no account would mismatch the path's account and be refused
**incidentally**, by the account comparison every account route already runs — so
a test using the real service would pass while proving nothing about the admin
surface. `TestATokenWithNoAccountIsRefused` manufactures the specific shape with
every scope in the vocabulary, so nothing about the scope gate can be what
refuses it, and asserts per route that the use case is never reached.
`TestAnAccountlessTokenCannotReachTheAdminSurface` records *why* the double is
needed, by asserting the row is unrepresentable in the schema.

## D5: bulk and single revocations do not share a shape

**Raised** 2026-09-30 by packet `identity-11`.

**Ruled: a bulk revocation requires `confirm: true` in the body, a named array of
at most 50, and an OWNER — where the single revocation needs none of those and an
admin.**

A bulk operation is the one where an off-by-one is an outage, so it does not look
like the single one, and the difference is in the **request shape** rather than in
a dialog — because a dialog is not something an API client has.

| | single | bulk |
| --- | --- | --- |
| request | `DELETE …/invitations/{id}` | `POST …/invitation-revocations` with a body |
| confirmation | none — the URL names the one row | **`confirm: true` required** |
| array | none | **required, 1–50** |
| minimum | admin | **owner** |
| response | 204 | `{requested, revoked}` |

**Why `confirm` is in the body and not a query parameter:** so that the request
that performs the operation and the request that describes it are the same bytes.
A `?confirm=true` is one link-builder's accident away from being sent without an
operator reading it, and the array is exactly the thing that must not be sent by
accident. Absent, `false` and the wrong JSON type are all the same 422 — a client
that got a different answer for `false` than for absent would have learned which
one it sent — and an unknown field is a 422, so a client misspelling `confirm` as
`confirm_all` is told rather than proceeding.

**Why the single route needs no `confirm`:** the URL names the one thing being
changed, so there is nothing in it that could be misread as "and everything else".
Adding a `confirm` field there would mean a client that forgot to send it gets a
422 on a safe, idempotent, single-row operation —
`TestTheSingleRouteNeedsNoConfirmation` exists because the tidying instinct is to
add it.

**Why owner and not admin:** revoking one invitation is a decision about a person.
Revoking every pending one is a decision about the account, it is the operation a
departing employee's automation might fire on a schedule, and there are only two
roles above `member` — the smaller one already has the single-revocation route.

**Why both counts are returned.** `revoked` is frequently smaller than
`requested`, because an id that was already revoked, or one belonging to another
account, changes no rows. A response carrying only one number would be a client
unable to tell "you asked for four and four went" from "you asked for four and
two went because two were never there" — and on an admin surface that is the
difference between a completed task and an incident.

**Why the bounds are refused and not clamped.** A request for 500 rows that
quietly received 100 has been told a lie about how much of the trail it has read,
and an operator building an export produces a short one without knowing
(`TestTheAuditLogBoundsAreEnforced`). Same reasoning for the 50-id array: a
request naming a thousand invitations that revoked the first fifty and reported
nothing is the outage this design exists to make harder.

**The cursor, and a bug this packet's own test found.** `before` is an **opaque
token encoding the row's `(occurred_at, id)` pair together**, returned as `next`.
The first implementation paged on `occurred_at < $before` alone and
`TestTheListIsBoundedAndNewestFirst` failed it: two records sharing an instant —
ordinary here, because the service's clock is a timestamp and not a sequence — put
one of them on each side of the boundary and it was **never returned at all**. A
cursor that is a timestamp is a cursor that drops rows.

It is opaque rather than two query parameters because a client handed
`?occurred_at=…&id=…` will eventually send one without the other, and each half
alone is that bug. It is a keyset rather than an offset because an offset is wrong
the moment a row is appended between two requests — which here is the normal
case: somebody is performing admin actions while somebody else pages through the
record of them. And a cursor this build did not issue is a **422 naming `before`**,
not a silent first page, because on a trail "your token was wrong" and "the records
are missing" are very different conclusions.


## D6: the generated client commits a dependency that MD6 said it would not

**Raised** 2026-09-30 by packet `identity-10`, which added `client/` — the Go client,
generated from `openapi/v1.yaml` by oapi-codegen v2.8.0, committed, with a
hand-written wrapper over it.

**What MD6 says, and why it is the reason this entry exists.** MD6 ruled "generate for
TypeScript and Go, hand-write the unified client, and do not generate Python yet",
and gave the reason for Go in one sentence: oapi-codegen "reaches `identity`'s
existing stack with no new dependency at runtime: it is a `go:generate` tool, not a
library a user imports. A generated client that compiles to ordinary structs and an
ordinary HTTP call has no supply-chain surface a user has to trust, because there is
nothing to trust after generation."

**That sentence is half right, and the half that is wrong is the load-bearing half.**
Measured, not assumed:

- **The generator really is not a dependency.** The `//go:generate` line is pinned to
  `v2.8.0`, and `go run <module>@<version>` resolves in module-aware mode, so
  oapi-codegen never appears in `go.mod`. That half of MD6's sentence is exactly
  right, and it is the same relationship goose is in for `migrations/README.md`.
- **The generated code IS a dependency.** `client/generated/api.gen.go` imports
  `github.com/oapi-codegen/runtime` for parameter binding and for its `UUID` and
  `Email` types. `go.mod` gains three modules: `oapi-codegen/runtime`,
  `apapsch/go-jsonmerge/v2` and `google/uuid`. A consumer who imports this client
  gets all three.

**What it costs, stated precisely, because "no new dependency" is the claim and the
claim is now false in a way somebody has to be able to check.**

| | before this packet | after |
| --- | --- | --- |
| `go.mod` modules added | 0 | 3 |
| `go list -deps ./cmd/identity \| grep oapi-codegen` | empty | **empty** |

**The shipped binary is unaffected**, and that is the part that matters for a service
which is the platform's security boundary. The dependency is in the module graph, in
the client package, and in anything that imports the client — not in the artefact
`identity` builds. `TestTheServiceBinaryDoesNotReachTheGeneratedClient` in
`client/transport_test.go` holds that as an executable claim, because a comment about
a supply-chain property is not a supply-chain property.

**The call, and the cost of the other one.**

1. **The client ships here, generated, and the three modules are paid for. CHOSEN.**
   The dependency is real, bounded, Apache-2.0, and stays out of the binary. The
   alternative costs more than it saves: the drift gate, the credential-leak test and
   `go vet` all run on the client *because* it is in this module and therefore in
   `bin/prime`'s `./...`. Moving it to its own module would leave the coverage floor
   untouched and leave the client ungated — the failure this repository is built
   against. AGENTS.md's own position is that "a green build with the database tier
   silently skipped is a false claim", and an ungated client is the same shape.

2. **Hand-write the Go client, like Python. REJECTED.** It would remove the three
   modules and cost the platform the drift gate's other half. MD6 already answers
   this: at 45 operations a hand-written client is "about a day per language" and
   "genuinely better", and re-decides "when it doubles". identity alone is at 20.

**WHY GO GENERATES AND PYTHON DOES NOT**, restated here because the asymmetry is a
ruling and not an accident, and the next person to see it should not "fix" the
inconsistency:

- **Go has a mature 3.1 generator whose output is reviewable.** oapi-codegen v2.8.0
  emits typed structs and a `Client` interface, produces byte-identical output across
  runs, and is Apache-2.0. Its output is ordinary Go — structs, an interface, an
  `*http.Response` — so the artefact a consumer reviews is the artefact they compile.
- **Python's generators impose a runtime.** hey-api's Python generator is v0.0.24
  and emits parameterless methods with unsubstituted path templates, so it would emit
  a request for the literal string `/v1/accounts/{account_id}/oidc-clients`.
  openapi-generator's Python output is correct but 3.1 is beta there and it inverts
  `const` discriminants to `any`, defeating compile-time narrowing on exactly the
  problem-details shape this platform uses.
- **So the asymmetry is about the generator, not about the language.** Go's toolchain
  makes generation a build-time concern; Python's tools make it a runtime one. A
  hand-written Python client has the smaller attack surface of the two, and that is
  not a close call.

**THE PART THAT IS STILL OPEN, and it is a manager's call, not this packet's.**

Adding 10,334 lines of committed, generated, **0%-covered** code to a module measured
at 74.7% takes it to **45.9%**. `ci.yml`'s coverage floor is 70, so the `coverage`
step goes red on this commit.

This packet did **not** move that floor, and did not add a filter to the coverage
measurement, because both are the shape of thing this repository forbids: making a
red go away by changing the check rather than the thing being checked. The numbers
are given here so the decision is available rather than buried.

The three answers, in the order this packet would rank them:

1. **Exclude `client/generated` from the coverage measurement.** It is generated
   output, and the repository already takes that position for lint in
   `.golangci.yml`, for exactly the stated reason. This is the closest analogue and
   the most defensible. It is a change to a CI check and belongs to whoever owns the
   floor.
2. **Lower the floor to the measured 45.9%.** Cheap, and honest about what the number
   now measures, but it makes the floor much weaker for the hand-written code it was
   there to protect.
3. **Move the client to its own module** (`client/go.mod`). Restores the service's
   coverage exactly and keeps the binary clean, and costs the client its place in
   `bin/prime` — so it needs a second gate, which AGENTS.md calls "a second thing to
   be wrong".

Whichever is chosen, it is a decision about the repository's coverage policy rather
than about this client, and it is recorded here rather than made silently.

### ANSWERED 2026-09-30 by packet `identity-12-coverage`: option 1, and why not 2

MD16 in the workspace `DECISIONS.md` ruled it. This records what was actually done
here rather than a summary of the ruling.

**Option 1, taken.** `coverage-exclusions` at the repository root declares
`client/generated` — one entry, one directory, with a reason, an owner, a `since`, an
`until`, the `files=` and `lines=` it covers, and the floor it was justified against.
`bin/coverage-floor` reads it, filters the profile, prints the measured number, the
excluded set and the floor in one block, and compares.
`TestTheCoverageExclusionIsOnlyGeneratedCode` in `internal/platform/ci` walks the tree
and fails if anything under the excluded directory is not itself generated, or if the
recorded file and line counts no longer match.

**Option 2 refused, and the numbers here are why.** This tree measures **44.6%** with
the generated client in it and **73.6%** without it. A floor of 45 is a threshold
chosen to be met: the gap it absorbs is a real regression in hand-written code, and
the generated code's weight in the denominator never changes, so the gap would be
permanent and invisible. Keeping 70 means the floor is still the number that was
measured against the code somebody wrote.

**The floor was not moved, and no test was added to generated code.** A test written
against `client/generated/api.gen.go` would be deleted by the next `go generate` and
the coverage would not survive a week — the same argument the lint exclusion in
`.golangci.yml` makes, for the same file, in the same shape.

### What is still open, and it is a different question from the one above

**Option 3 is not answered, and it is the correct long-term shape.** A generated SDK
is a different artefact with different properties, and a separate Go module makes the
boundary a compile-time fact rather than a config entry. It is not done here because
it changes the import path of a published client, which is a decision with a
deprecation window attached.

The signal to settle it is the one MD16 names: **a second repository asking for a
generated client.** Before then, `coverage-exclusions`'s `until=2027-03-31` fails the
build, so the question is asked on a date rather than whenever somebody is under
pressure.

### WHY THE MECHANISM LIVES HERE AND NOT IN kit, which is a judgement and not a fact

The shared workflow should carry the *mechanism* and each repository its own
*declaration* — that is the right shape and it is what the brief asks for.

It is not here for one concrete reason: **identity's enforcing coverage step is its
own `coverage` step in the `gate` job, and kit's cannot enforce anything in this
repository at all.** kit's `test` step runs with no database, so
`internal/mfa`'s `TestTheDatabaseTierActuallyRan` fails first and the run never
reaches a coverage step. A mechanism in kit would therefore not be the mechanism this
repository uses: identity would still need its own copy, and a copy in a repository
that cannot read kit's at run time is a drifting copy with extra steps — the argument
`templates/tier/skip-allowlist` already makes about the fleet-wide file.

So the mechanism is here, the declaration is here, and `kit` is untouched, which also
means this packet does not collide with `kit-04`, live in that repository.

**What kit should grow, and when.** A `coverage-exclusions` input on the reusable
workflow plus the filter, so a second repository gets the mechanism without writing
it. The test that should move with it is the "every `.go` file under the excluded
directory is generated" walk — that is the load-bearing part and the part a consumer
is most likely to skip. **Do it as a kit packet, not by copying a file across**: a
copy is a second dialect of the same rule, which is the thing this packet was told not
to create.

**And the disagreement that leaves behind.** `coverage-fail-under: '70'` is still
passed to kit. kit's step computes `total:` over the whole profile and cannot be told
about this declaration, so it would read 44.6% if it ever ran. Left alone on purpose:
lowering the input to 45 is option 2, and 0 would be weakening a gate to make a build
green. The threshold is stated in both files, and
`TestTheCoverageFloorInTheDeclarationIsTheFloorsFloor` fails if they stop being the
same number.

## D7: the mail seam has two methods, and this repository wires the one that fails

**Raised** 2026-10-01 by the recovery packet, which added password reset, address
verification and address change — three flows that can only be finished by proving
you can read an inbox, and therefore three flows that need to send mail.

**The problem.** courier is the platform's mail service and its delivery path is not
finished. So identity has to send mail it cannot yet send, and there are three
shapes this could take.

1. **Talk to courier's HTTP API anyway, and let it 503 in development.** Rejected: it
   invents a contract against a service whose real one is in flight, so the adapter
   would be written against a guess and thrown away.
2. **Implement sending inside identity** — an SMTP client, a provider SDK, a queue.
   Rejected, and this is the one worth being explicit about: it would be
   *reimplementing courier inside the security boundary*. Two delivery paths means
   two sets of retry semantics, two places a message can be lost, and two answers to
   "is this deployment actually configured to send". The brief for this packet said
   not to build courier's adapter, and the architecture says the same thing
   independently.
3. **One substitutable seam, wired to a mailer that fails loudly. CHOSEN.**

**The seam, and why `Ready` is not padding.** `recovery.Mailer` is two methods:

```go
type Mailer interface {
    Send(ctx context.Context, m Message) error
    Ready(ctx context.Context) error
}
```

`Ready` exists because every request flow must know whether a message *can* be
delivered **before** it decides whether to mint a token — and it must know before it
looks the address up. Without that ordering, a deployment with no mail answers `503`
for a registered address and `202` for an unregistered one, and "503 against 202" is
an account-existence oracle. The cheapest version of that bug is the kind that only
shows up in the one deployment where nobody is testing. So the flow asks the seam
first, and both answers come from the same place.

`Ready` must not send anything and must be cheap: it is on an anonymous request path,
so an implementation that performed a real delivery there would mail an empty message
on every password-reset request anybody ever asked for.

**Why the message is a rendered value, not a template name.** `Send` takes a
`Message` whose `Subject` and `Body` are already strings. There is no `Template`
field, and there is deliberately no code path where a delivery adapter chooses what
the mail says. The moment `Message` grows a `Template`, identity has taken courier's
rendering decisions and the two will disagree. Four templates live in
`internal/recovery/message.go` as `strings.Replacer`s, so there is no inline body
literal anywhere in a handler — which is a brief requirement and also the only way
"the mail says X" is reviewable in one file.

**Why `main` wires `Unavailable{}` and not a logger.** `Unavailable` is a struct (not
a nil `Mailer`, so no caller has to decide whether nil is a supported configuration)
whose `Send` and `Ready` both return `ErrNoMailer`. Every route that needs to send
answers `503 service_unavailable` with a sentence naming the deployment problem.

The tempting alternative is a mailer that logs the message so an operator can see it
"worked". That is exactly the wrong shape for this particular message: **the body
contains a live single-use credential**. A reset token in a log aggregator — which is
searchable, retained, and usually readable by everyone who can read a deployment's
metrics — is a reset token anybody who can read the logs can redeem. So the mailer
fails loudly instead, and `TestNoRecoveryTokenReachesTheLogs` is the executable form
of that decision.

**Wiring courier is three lines** in `buildRecovery`, and that is the test of whether
this was the right shape: the seam has exactly one production implementation and it
is the one that refuses. Nothing in `internal/recovery` mentions courier, SMTP, or
any provider, so the future adapter lands in one function in `cmd/identity` and the
use cases do not change.

**THE COST, STATED PLAINLY.** As wired, **a user who forgets their password cannot
recover.** The flows are complete and tested; there is nowhere for the link to go.
That is recorded in README.md's "Not built yet" with the reason, because the honest
state for "we depend on a service that is not ready" is a paragraph and not a
stub that returns 202 and drops the mail.

## D8: one link template for four messages, and what the deployment inherits

**Raised** 2026-10-02 by packet `identity-26`, after `identity-24` drove the flows
end to end against a real courier and found the verification mail's button pointing
at the password-reset screen.

**The problem.** `RecoveryMailer` held ONE `LinkTemplate` for all four of its
messages, and the design was defended at length in `internal/courier/mailer.go`: a
template with `{token}` beats a base URL plus a platform-chosen convention, and
`ValidateLinkTemplate` refuses a template that cannot render a working link. The
argument is sound **for a recovery link**. It was then applied to a verification
link, which is not a recovery link, and the result was a mail that renders
perfectly, passes every assertion in the repository, and sends the reader to a
screen where the token is a `404`.

The single template had to go — one template for two purposes is a template that
must be wrong for one of them. **What had to be decided is what the variable that
already exists now means**, and that is a question about deployments rather than
about code.

**The four shapes.**

1. **Require `EMAIL_VERIFICATION_LINK_TEMPLATE`.** Correct in the strictest sense and
   rejected: it refuses to start every installation that exists, on the security
   boundary, to fix a defect introduced after they were configured. The brief for
   this packet names that outcome as the one to avoid.
2. **Derive the verification path from the reset one** — replace the last path
   segment, or append a convention. Rejected: it is the platform choosing a
   product's URL, which is the exact thing `LinkTemplate` exists to avoid, and it is
   wrong for every product whose confirm screen is not spelled the way identity
   guessed. It would also make the defect **invisible in a way the chosen answer
   does not**: a derived path looks configured, and an operator reading the config
   would have nothing to notice.
3. **Make the legacy variable mean "recovery" specifically**, so a verification link
   becomes mandatory. Same failure as 1, wearing a hat.
4. **RULED: `RECOVERY_LINK_TEMPLATE` is the default for every purpose that has no
   variable of its own.** A purpose names a template and gets it; a purpose that
   names nothing takes the default; a purpose with neither its own nor the default
   is a **startup failure naming the variable**.

**Why 4, and what it costs.** The cost is real and is the whole of the argument:
**an unmigrated deployment's address-confirmation link still points at whatever its
one template says.** The compatibility promise is about booting and about the reset
link continuing to work, and it does not pretend to fix the verification link for a
deployment that has not configured one — because fixing it automatically means
guessing where the screen is.

So identity says it out loud instead. `buildMailer` warns on startup when any
purpose resolves to the shared default, naming the purpose and the variable that
would give it a link of its own. That warning is the load-bearing part of the
decision, and it is there because **nothing else in the process can see the
problem**: the send succeeds, the token redeems at its own endpoint, every existing
test is green, and the reader is the only person who discovers they are on the wrong
screen. A compatibility promise that is silent about its own remaining cost is a
worse trade than one that names it.

**Why a purpose with NEITHER is a boot failure rather than a fallback.** The
fallback is the defect. A deployment that sets `PASSWORD_RESET_LINK_TEMPLATE` and
forgets it also dropped its default for verification has, by omission, reproduced
exactly the state this decision exists to end — and it would do so with every mail
rendering correctly. Failing at boot costs one line in a startup log naming the
variable; failing later costs a user.

**The checks, and what each one is for.** The interesting question was never the
configuration shape — it is that **nothing about a URL says which screen it opens**,
so no assertion about bytes can catch this. Identity cannot catch it either, except
where it has its own endpoints:

- `internal/courier/link_purpose_test.go` builds the mailer from an
  **`internal/config` environment** rather than from a Go literal — a relationship
  between two links can only be tested by something that can express it — sends a
  reset and a verification through the real flows over a real database, and asserts
  the two rendered links have **different paths** and that **each token redeems at
  its own endpoint and is refused at the other**. The token is read back out of the
  URL rather than out of the message, because the claim is about what the *recipient*
  holds.
- The same file holds a **negative control**: one template for both purposes really
  does render one link for both messages, so the inequality above is a comparison and
  not a tautology.
- The inequality was shown to fire by injecting the real defect — making the
  verification purpose read the reset variable — which reds at the path comparison
  with a message naming what a reader would have found.

**WHAT WAS DELIBERATELY NOT DONE.** courier was not touched. `verify_email` still
maps onto courier's `welcome`, which is the honest mapping and stays: what changed
is the **link**, not the message kind. There is still no `email_verification` type in
courier, and this decision does not argue for one.
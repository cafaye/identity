# REPORT — identity-11-admin

The admin surface for `identity`: three operations, an immutable audit trail, and
a finding about this repository's own tripwire that is worth more than the three
routes.

Branch `worker/identity-11`. Worktree
`cafaye/identity-worker-identity-11`. Base `e500262` (merge of `worker/identity-09`).

---

## The gate

`TEST_DATABASE_URL` against a real Postgres on **port 15001**, database
`identity_worker_identity_11`, migrated by goose to **version 13**.

```
mise x -- ./bin/prime        exit 0
go vet ./...                 clean
gofmt -l .                   prints nothing
go test -count=1 -race ./... exit 0
```

The gate was run in `bash` with `${PIPESTATUS[0]}`, because zsh has no
`PIPESTATUS` and a piped exit code is the exit of `tail`.

### Pass and skip counts, reported separately

| | count |
|---|---|
| **PASS** (whole suite, incl. subtests) | **1679** |
| **SKIP** | **0** |
| FAIL | 0 |
| database tier PASS (the 14 packages that open a pool) | 1608 |
| database tier SKIP | 0 |

`0 skips is the claim`, and it is measured rather than asserted: the run log was
counted with CI's own `--- PASS:` / `--- SKIP:` patterns, and
`TestTheDatabaseTierActuallyRan` is present and passing. A green build with the
database tier silently skipped would have shown a skip count above zero, so the
absence is evidence.

Per package, the database tier:

```
cmd/identity                     20 passed  0 skipped
internal/accounts               114 passed  0 skipped
internal/admin                   42 passed  0 skipped
internal/apikeys                135 passed  0 skipped
internal/auth                    61 passed  0 skipped
internal/httpapi                669 passed  0 skipped
internal/mfa                    117 passed  0 skipped
internal/oauth                  111 passed  0 skipped
internal/oidc                    96 passed  0 skipped
internal/outbox                  79 passed  0 skipped
internal/platform/ci             18 passed  0 skipped
internal/platform/db             27 passed  0 skipped
internal/sessions                44 passed  0 skipped
internal/users                   75 passed  0 skipped
```

**No sleeps. No raised retries. No loosened assertions.** No test timeout was
touched, and the two test edits that changed an *expectation* are both documented
in `CHANGELOG.md` under `Changed` and below — one was a genuine bug in an
existing comment, the other is the finding this packet is really about.

---

## The finding: the tripwire was blind, and it was green because of it

**This is the most important thing in the report, and it is not about my three
routes.**

I added the admin surface and ran the suite. It was green. `internal/httpapi`
passed, `internal/apikeys` passed, and — the part that mattered —
`TestEveryServedRouteIsDocumentedOrNamed` **passed**, which is the
reverse-direction check holding this repository's twelve known-drift findings.

Three operations were mounted and in no document. The check said the documents
and the router agreed.

**Why it said that:** `servedRoutes` in `openapi_drift_test.go` builds an
`options` struct literal to make every *conditional* surface take its configured
path, and the new `admin` field was not in that literal. So
`registerAdminRoutes` returned early, and the walk enumerated a **smaller service
than the one that runs** — 38 routes instead of 41. The check agreed with the
document because it had read a router with no admin routes in it.

`TestEveryRouteIsInTheMatrix` was blinded identically, in the same commit, through
`mountedAccountRoutes`. The matrix's completeness check — the one the packet
names by name — passed with no admin row required.

So the answer to "if your work adds a route, the tripwire will go red" was, for
this packet, **not true** — not because the tripwire was weakened, but because
the packet's own new field made it blind, and nothing in the harness noticed.

### What I did about it

I did **not** grow `knownDrift`, and I did not add a prefix filter. The three
routes are documented (below), and the blind spot is closed structurally:

`internal/httpapi/router_walk_test.go` (new):

- `TestTheDriftWalkSeesTheAdminSurface` — asserts the walk **finds** the three
  routes. Not that a field was set: that it *reports them as served*.
- `TestTheMatrixWalkSeesTheAdminSurface` — the same for the matrix walk.
- `TestEveryConditionalSurfaceIsVisibleToTheWalk` — keeps a list of every
  `options` field whose `nil` value makes a registrar skip its routes, and fails
  if one is renamed. The next conditional surface added to `internal/httpapi`
  fails there until somebody adds its double to the walks.

### Proof the new check is not itself decorative

I re-injected the original fault — removed `admin: newFakeAdmin()` from
`servedRoutes`, restoring the exact bug — and the new check went red naming all
three routes, while `TestEveryServedRouteIsDocumentedOrNamed` **still passed**.
That is the demonstration that the old check could not see this class of fault
and the new one can. The fault was then reverted and the suite re-verified.

**The general lesson is recorded in D1**, not just in a test comment: *a struct
literal used to configure a check is a completeness obligation, and nothing about
it looks like one.* A conditional route makes the omission silent and the suite
green.

---

## The three routes

All under `/v1/accounts/{account_id}/admin/`, all **token-only**, all
account-scoped (so they ride `requireAccountRole`'s existing tenancy check
rather than a second one).

| route | minimum | scope | response |
|---|---|---|---|
| `GET …/admin/audit-log` | admin | `audit_log:read` | `200 {entries, next?}` |
| `DELETE …/admin/invitations/{invitation_id}` | admin | `account_invitations:write` | `204` |
| `POST …/admin/invitation-revocations` | **owner** | `account_invitations:write` | `200 {requested, revoked}` |

`operationId`s: `listAccountAuditLog`, `revokeAccountInvitation`,
`revokeAccountInvitations`. All unique; `TestEveryOperationHasAnOperationIdAndNoOperationIdIsUsedTwice`
passes. `info.version` 1.3.0 → **1.4.0**, non-breaking addition.

### The privilege boundary, in one sentence

> An account admin may revoke pending invitations to their own account and read
> that account's admin audit log — authority over other people's pending access,
> and nothing else.

It is a sentence because **a role checked in thirty places is a role that will be
checked in twenty-nine of them**. So the sentence is not documentation of the
boundary, it *is* the boundary: three rows in `accountRouteScopes`, two scopes,
and `TestTheScopeTableIsTheWholeBoundary` fails if a fourth admin route appears
without a new scope in `internal/apikeys`.

### Bulk vs single: different shapes on purpose

| | single | bulk |
|---|---|---|
| request | `DELETE …/invitations/{id}` | `POST …/invitation-revocations` + body |
| confirmation | **none** — the URL names the one row | **`confirm: true` required** |
| array | none | **required, 1–50** |
| minimum | admin | **owner** |
| response | `204` | `{requested, revoked}` — they differ |

`confirm` is in the **body**, not the query string, so the request that performs
the operation and the request that describes it are the same bytes. Absent,
`false` and wrong type are the same 422; an unknown field is a 422 too, so a
client misspelling `confirm_all` is told rather than proceeding.

---

## The red proofs

Four, each asserted against the failure direction.

**R3 — a failed audit write rolls the mutation back.**
`TestAFailedAuditWriteRollsBackARealMutation` installs a `BEFORE INSERT` trigger
in the test's own private schema that raises, drives the **real router**, and
then asserts against committed database state: the invitation is still
unrevoked, zero audit rows exist, and the transaction did not commit. The
companion `TestAFailedMutationRollsBackARealAuditRecord` asserts the other
direction — no record describing an action that did not happen. A happy-path
test proves neither, and a service that rolled back everything would pass the
negatives perfectly, so the positive proof
(`TestTheAuditRecordIsWrittenInTheSameTransactionAsTheAction`) exists to show the
happy path writes *both* rows.

**R2 — a token with no `account_id` is refused, per route.**
`TestATokenWithNoAccountIsRefused`, three subtests, one per route. It needs a
**double**, and the reason is the substantive part: a real accountless token
would mismatch the path's account and be refused *incidentally*, by the account
comparison every account route already runs — so a test using the real service
would pass while proving nothing about the admin surface. The double manufactures
the shape with **every scope in the vocabulary**, so nothing about the scope gate
can be what refuses it, and asserts per route that the use case is never
reached. `TestAnAccountlessTokenCannotReachTheAdminSurface` records *why* the
double is needed by asserting the row is unrepresentable (`23502` on
`account_id`) and that `claims.ClaimsFor` returns `ErrNoAccountID`.

**R4 — no admin route is reachable with a session alone.**
`TestNoAdminRouteIsReachableWithASessionAlone`, three subtests, per route. 403,
**and** the use case was never reached — a 403 written by a handler that had
already performed the action is not a refusal.

**Audit immutability — from the table's side, not the service's.**
`TestTheAuditRecordCannotBeUpdated` and `…CannotBeDeleted` issue the statements
**directly against the pool**, bypassing Go entirely, and assert the row is
genuinely unchanged afterwards. A test calling the service would only show the
service has no such method — true, and irrelevant to somebody with `psql`.

---

## The tripwire: extended, not weakened

| check | result |
|---|---|
| `TestEveryServedRouteIsDocumentedOrNamed` | passes — three routes **documented** |
| `TestEveryDocumentedOperationIsServed` | passes |
| `TestKnownDriftIsExactlyTheRoutesItClaimsToBe` | passes — **still 12** |
| `TestKnownDriftNamesOnlyServedRoutes` | passes |
| `TestEveryOperationHasAnOperationIdAndNoOperationIdIsUsedTwice` | passes |
| `TestTheDocumentIsOpenAPI31AndCarriesAVersion` | passes at 1.4.0 |

**`knownDrift` did not grow.** The list is still twelve and the pin is still
twelve. I added a comment at the pin saying that a future packet tempted to bump
it is being told the truth by the tripwire, and that the answer is to document the
route.

The three operations went into `openapi/v1.yaml` under a new `admin` tag with
full request/response schemas (`AuditLogPage`, `AuditLogEntry`,
`BulkInvitationRevocation`, `BulkRevocationResult`), `security: [bearerToken: []]`
and **not** `sessionCookie` — the token-only ruling is visible in the document a
client generates from.

---

## Schema (identity's own `migrations/`, not `core`)

Two migrations, each reversible — verified with a `down`/`up` round trip.

**00012 `account_audit_log`** — the audit table, and it has **no foreign key to
`accounts`, on purpose.** Every other table here cascades; a cascade is a
`DELETE`, and this table does not delete. Allowing it would make the shortest
route from "an admin did something questionable" to "there is no record of it" be
one request to `DELETE /v1/accounts/{account_id}` — the packet's requirement
satisfied by the router instead of defeated by it. Same reasoning for the actor:
`actor_key_id` is a bare uuid, so revoking a credential does not erase what it
did.

Immutability is a `BEFORE UPDATE OR DELETE` trigger, **in the database** — a
guarantee written in Go does not bind a `psql` session, a repair script, or a
future packet. `dbtest` re-creates the trigger per private schema, because
`LIKE` does not copy triggers and a test would otherwise run against a table the
production one can never `UPDATE`.

**00013 `account_invitation_revocation`** — the `revoked_at` column, and the
widened partial index that **frees the address to be invited again**, which is
the entire reason the operation exists. This is the schema half of what 00007's
comment anticipated: *"Deleting a user with pending invitations is therefore
refused by the database until they are revoked, which is a later packet."*

**No `core` schema change was needed or made.** The packet said to stop and report
if one were; it was not.

---

## Two things I changed in existing tests, and why

**`expectedStatus` in the authorization matrix: the `expect` override is now
consulted BEFORE the authentication check.** It had them the other way round, on
the stated grounds that "authentication is the one decision no endpoint
overrides" — true where the credential is resolved first, **false** on the admin
surface, where the credential *kind* is resolved first by `requireAdminToken`
outside `requireAccountRole`. A request with no credential there is answered
**403**, and the three new rows were silently being asserted 401 for a service
that does not give that. The one pre-existing row relying on the old order
(`POST /v1/invitations/accept`) now states its anonymous answer itself.

This is the one change a reviewer should look at hardest, because it makes an
unreachable override reachable. It is a fix, not a loosening: the matrix now
records what the service does.

**A comment in the matrix promised a test that does not exist.**
`TestRouteMinimumsMatchTheRouter` was named as the thing keeping the `min` column
honest. It is not in the tree and **cannot be** — chi's tree records the handler
and the minimum is a closure argument to `requireAccountRole`, so there is nothing
in the walk to compare against. I replaced the promise with the truth: the
minimums are enforced by the real router in these tests (`fakeTenancy` is the only
double), and the admin minimums are pinned by `TestTheBulkRouteIsOwnerOnly`.

---

## A bug my own test found

The first page-cursor implementation paged on `occurred_at < $before` alone.
`TestTheListIsBoundedAndNewestFirst` failed it: five records written with
deliberately repeated timestamps, and the row sharing a page boundary was
**never returned at all**. This service's clock is a timestamp and not a sequence,
so two admin actions in the same second is the normal case.

Fixed: the cursor is opaque and carries `(occurred_at, id)` together, and the
query uses a row-value comparison against the index's own column order. It is
opaque rather than two parameters because a client handed
`?occurred_at=…&id=…` will eventually send one without the other, and each half
alone is that bug. A cursor this build did not issue is a **422 naming `before`**,
not a silent first page — on a trail, "your token was wrong" and "the records are
missing" are very different conclusions.

---

## Never a credential

`TestNothingOnThisSurfaceCanRecordAToken` reflects over `Entry`, `Record`,
`Actor` and both input types and fails if any grows a field named for a
credential's *value* (`token`, `secret`, `bearer`, `jwt`, `password`, `digest`).
A test asserting "we did not log a token" is unfalsifiable; that one is not.

`TestAnAdminActionNeverWritesACredential` checks all four places a record could
leak, on the same action: the response body, every audit column, every log entry,
and a rendered problem document. A test asserting only the response would pass
against a service that leaked into the log, which is the leak nobody notices.

No token, cookie or JWT is logged anywhere in this packet. The audit entry
carries `actor_user_id` and `actor_key_id` — row ids.

---

## What I could not verify

**1. The authorization matrix has a genuine hole on this surface, and I did not
close it — I only named it.** Its six columns are six *sessions*, so on a
token-only surface every column is a 403 and **the matrix carries no positive cell
for any of the three routes**. The authorization this packet adds is "which
*credential* may do this", and a table of six sessions cannot express that axis.
The rows are in the matrix anyway so `TestEveryRouteIsInTheMatrix` still demands
them, and the axis is covered by
`TestNoAdminRouteIsReachableWithASessionAlone`,
`TestAnAdminTokenHoldingNeitherScopeIsRefused` and `TestTheBulkRouteIsOwnerOnly`
— but a **matrix** with a hole is worse than no matrix, and this one now has one.
Closing it properly means adding token columns to the matrix fixture, which is a
change to a shared harness every route's rows depend on, and I judged that
larger than this packet should absorb unasked. It is the first thing I would do
next.

**2. The `knownDrift` blindness is closed for *known* surfaces, not for future
ones.** `conditionalSurfaces` is a hand-maintained list. It fails on a **renamed**
field, and `TestTheDriftWalkSeesTheAdminSurface` catches the admin surface
specifically — but a genuinely new surface added to `internal/httpapi`, wired into
`newMux`, and absent from both literals would still be invisible to the drift
check, and `TestEveryConditionalSurfaceIsVisibleToTheWalk` would not catch it
either, because the new field is not *in* the list yet. Catching that needs the
walk to be derived from the registrar rather than configured beside it, which is
a structural change to `internal/httpapi`'s assembly that I did not attempt.

**3. Concurrency on the audit trail is untested.** Two admin actions in the same
transaction-shaped race, or two operators revoking the same invitation at once,
are not exercised. The conditional `UPDATE`s are written to be correct for the
invitation (`accepted_at IS NULL AND revoked_at IS NULL`, so the loser gets zero
rows and a 409), and `go test -race` is clean, but race is a data-race detector,
not a lost-update detector. A test that fires two concurrent revocations and
asserts exactly one 204 and one 409 would be the real proof and I did not write
it.

**4. `MaxAuditLogLimit = 100` and `MaxBulkInvitationIDs = 50` are judgement
calls, not measurements.** I argued the ceilings from blast radius and did not
measure a real fleet's page sizes or batch sizes. If a genuine operator needs to
revoke 400 invitations, the answer today is eight requests, and that is a
deliberate cost rather than an oversight — but it is a guess about usage.

**5. The `affected` count is the store's, and the store counts rows it changed
including rows that changed for another reason.** A concurrent `revoked_at` write
between the read and the update would be counted as this batch's work. It is
narrow, and the alternative — a count the caller asserts — is worse, but it is
untested under concurrency for the reason in (3).

**6. I did not verify the OpenAPI document against a real validator.** Both
documents "validate against OpenAPI 3.1" per AGENTS.md, and
`internal/platform/ci` checks the workflow, but I read that requirement as the
repository's CI's job and my own checks are the reader in
`openapi_reader_test.go` plus the tripwires. If `caf contract lint` is the real
validator, my YAML has not been through it. The `parameters` block under the audit
`get` operation is placed *after* `tags`/`operationId`, which is legal OpenAPI
(key order is not significant) but is not the order the other operations in the
file use — worth a validator run before merge.

**7. I did not measure coverage.** CI enforces `COVERAGE_FAIL_UNDER: '70'` and
records 73.2% at the base commit. Three new files landed, mostly tests; my
expectation is coverage went up, but I did not run the tool and am not claiming a
number.

**8. `psql`-level immutability is asserted through the test's own pool, not
through a role that lacks `UPDATE` grants.** The trigger fires for every writer
including the table owner, which is the property I wanted. A deployment where the
application connects as a superuser could still drop the trigger; nothing here
prevents that, and nothing here is meant to.

---

## Commits

Six, each with its tests, on `worker/identity-11`:

1. `migrations` — 00012 and 00013, each verified down/up
2. `admin` — the package, the two scopes, `dbtest` wiring
3. `httpapi` — the routes, the gate, the handlers
4. `tests` — the router walk, the matrix rows, the matrix ordering fix
5. `documents` — `openapi/v1.yaml` 1.4.0, README, CHANGELOG, AGENTS, DECISIONS
6. `report` — this file

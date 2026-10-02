# REPORT — identity-28: the tenancy surface is in a document, and D1 is decided

Branch `worker/identity-28`. Nothing pushed, nothing merged, nothing tagged.

## What landed

| | before | after |
|---|---|---|
| operations in `openapi/v1.yaml` | 31 | **41** |
| operations in `openid/openid.yaml` | 9 | **11** |
| `knownDrift` | 12 entries | **0, pinned at 0** |
| `info.version` | 1.6.0 | **1.7.0** |
| typed methods on the Go `Client` | 31 | **41** |

All twelve are in a contract, traced to a handler I read rather than to a shape I
invented. `TestEveryServedRouteIsDocumentedOrNamed` and
`TestEveryDocumentedOperationIsServed` are both green, which is the first time in
this repository's history that the two directions have both been empty.

## The ten tenancy operations, and where each shape came from

| operationId | method and path | operationId | method and path |
|---|---|---|---|
| `createAccount` | `POST /v1/accounts` | `deleteAccount` | `DELETE /v1/accounts/{account_id}` |
| `listAccounts` | `GET /v1/accounts` | `listMembers` | `GET /v1/accounts/{account_id}/members` |
| `getAccount` | `GET /v1/accounts/{account_id}` | `inviteMember` | `POST /v1/accounts/{account_id}/invitations` |
| `renameAccount` | `PATCH /v1/accounts/{account_id}` | `changeMemberRole` | `PATCH …/members/{user_id}` |
| | | `removeMember` | `DELETE …/members/{user_id}` |
| | | `acceptInvitation` | `POST /v1/invitations/accept` |

**The operationIds were not invented.** The `bearerToken` security scheme's
required-scopes table has named all ten by name since 1.4.0 — seven of those routes
enforce a scope, and a scope that gates a route no document declares is a promise
with nothing behind it. So the repository had already committed to these being
client operations and had not noticed. The table and the `paths:` block agree for
the first time.

**Every response body was read off a live server**, not off the handler's Go
struct, with a throwaway probe that printed the wire. That caught one thing a
struct reading would have missed (below) and confirmed the status tables. Two
answers were also checked against the real service rather than against the code:
`ErrInvitationEmailTaken`'s 409 fires only for a *pending* invitation (a redeemed
one does not block a re-invite, which is the behaviour `inviteMember`'s
description now states), and an invitation's `role=owner` is `422 not_invitable`
rather than `403`.

The minimum roles and the token scopes come from `accountRouteScopes` and
`registerTenancyRoutes` and are stated per operation. The three session-only
operations carry `security: [sessionCookie]` and a `403` that says why — that is
the accurate statement, and it is better than a header sentence ruling them "never
client operations".

## The two OIDC POSTs

Added to `openid/openid.yaml` as `authorizeViaPost` and `userinfoViaPost`, beside
the `GET` each duplicates. Same handlers, so the operationIds say `ViaPost` and the
descriptions say what actually differs:

- `POST /oidc/authorize` — the same parameters, in an
  `application/x-www-form-urlencoded` body rather than the query string. The
  handler reads `r.Form`, so the pre-checks and the library see the same values
  whichever method delivered them, and the four pre-checks and both error shapes
  are unchanged.
- `POST /oidc/userinfo` — **the `Authorization` header is still read first and
  still wins**; the form body is consulted only when there is no header. Verified
  against the library rather than assumed: `op.ParseUserinfoRequest` calls
  `getAccessToken(r)` first and falls back to `r.Form` + `oidc.UserInfoRequest`.
  So the POST accepts the body rather than requiring it, and grants nothing the GET
  did not.

The document says plainly that a token in a body is a token in a place
intermediaries log more eagerly, which is why the GET stays the right default.

## `knownDrift` is empty, and the map is kept

`var knownDrift = map[operationKey]string{}` — the map stays, pinned at zero.

The old pin said the list could not grow **and could not be emptied**. The second
half had to go, and the reason is worth stating because it is the only part of this
packet that is a judgement rather than a mechanical change: that clause was written
against a list of *known bugs*, where deleting an entry could have meant deleting
the memory of a gap. That is no longer the shape — the map's comment now names all
twelve and the commit that closed them, the CHANGELOG names them, and DECISIONS.md
D1 holds the finding — so the memory survives the removal and an empty map means
the service is fully documented rather than that somebody forgot.

`TestKnownDriftIsExactlyTheRoutesItClaimsToBe` became
`TestKnownDriftIsEmptyBecauseEveryServedOperationIsDocumented`. It still fails on
any entry, and its failure message is now the whole argument: not an exclusion
list, an admission, two legitimate ways to close one, three review-visible edits.

`TestKnownDriftNamesOnlyServedRoutes` — the staleness guard in both directions —
is kept and now runs over an empty map, which is where it earns its keep: it is
what would catch a stale entry in a future packet.

## The tripwire was watched going red

**Twice, and on the real thing.**

1. A route was reintroduced in `registerTenancyRoutes`
   (`GET /v1/accounts/{accountID}/drift-probe`) and the suite run.
   `TestEveryServedRouteIsDocumentedOrNamed` named it and went red:

   ```
   the router serves 1 operation(s) that openapi/v1.yaml, openid/openid.yaml
   and knownDrift all fail to account for:

     GET /v1/accounts/{}/drift-probe
   ```

   with the two legitimate ways out and the "do not add a prefix filter" warning.
   `TestTheTwelveThisPacketClosedAreCaughtAgainIfAnyOfThemReturns` also went red,
   reporting thirteen instead of twelve.

2. An entry was added to `knownDrift` and
   `TestKnownDriftIsEmptyBecauseEveryServedOperationIsDocumented` went red with
   the full argument quoted.

Both injections were reverted and the tree is clean of them.

**Permanent proof, not a development memory.**
`internal/httpapi/known_drift_test.go` (new, 190 lines) reads the **real** router
walk and the **real** documents, removes this packet's entries, and asserts all
twelve come back unexplained — the same expression
`TestEveryServedRouteIsDocumentedOrNamed` evaluates, pointed at the state the
repository was in on 2026-09-30. It uses no fixture, and it is not the hand-written
one-off maps the existing fault tests use: a pair of hand-written maps would prove
`diff` works and would keep proving it if the real reader quietly stopped reading,
which is the way every other check in this package has been fooled once. A second
test un-documents one real route chosen out of the router's own walk and asserts it
is reported, so the twelve cannot be a special case.

## D1 is decided

`DECISIONS.md` gets a ruling section, the summary row says RULED, and the original
finding is kept above it with a pointer. The argument, in short:

- **The strongest evidence for option 1 was already in the document** — the ten
  operationIds in the scopes table (above). The repository had already ruled; it
  had not noticed.
- **The cost was measured, not estimated.** `cafaye-ts` — the client `parlor` calls
  and the one a customer writes against — had `createClient`, `createSession`,
  `deleteSession`, `getCurrentUser`, `getEmailVerificationStatus`, `getMfaStatus`,
  `getOidcClient`, `introspectApiKey`, `listAccountAuditLog`, `listApiKeys`,
  `listOidcClients`. No `createAccount`, no `inviteMember`, no `acceptInvitation`.
- **The ruling-out could not have covered the OIDC pair at all**, and could not
  honestly have covered the account detail: those are member-and-role reads on a
  product's own tenant.

Cost, honestly: ~1160 lines of `openapi/v1.yaml`, the whole Go client
regenerated, and one response-shape change. `cafaye.yml`'s `DECISION NEEDED`
callout is rewritten as `DECIDED`.

## One behaviour change, found by having to document the response

`GET /v1/accounts/{account_id}` and `GET /v1/accounts/{account_id}/members`
returned:

```json
[{"account_id":"","user_id":"","role":"admin","created_at":"0001-01-01T00:00:00Z"},
 {"account_id":"","user_id":"","role":"member","created_at":"0001-01-01T00:00:00Z"},
 {"account_id":"","user_id":"","role":"owner","created_at":"0001-01-01T00:00:00Z"}]
```

**Three members, indistinguishable, and `PATCH`/`DELETE
/v1/accounts/{account_id}/members/{user_id}` both need the `user_id` the response
did not carry.** Nothing in the service could render or remove a member.

Cause: `membershipResponses` filled only `Role`, because `accounts.MemberSummary`
is shaped for `ListMine` ("which accounts does this user belong to") and carries
the account and the role and no user; `Members` reuses it for the other direction.

**This is a code change in a document packet, and I made it deliberately.** The
alternative — leaving those two operations in `knownDrift` with a reason naming
this blocker — is the escape the brief allows and would have been defensible. I
chose the fix because a documented operation whose response cannot identify its own
subject is a contract that lies green, which is the most expensive kind of wrong in
a document; and because **no client can be reading the old shape**, since these two
operations were in no document at all, so there is no migration and no consumer
with a switch on it. Four fields on `MemberSummary`, two columns on the select
list, four lines in the projection. `TestEveryMemberInAMemberListIdentifiesItself`
(written first, watched red, then implemented) holds it on both routes.

## The neighbouring event gap: verified, still blocked, left alone

`identity.account.created`, `identity.member.invited`, `identity.member.accepted`,
`identity.member.role_changed`, `identity.member.removed` remain emitted and
undeclared. **The blocker holds, and I verified rather than assumed.**

Measured against core at `5ec0cec` and again at `15a5df2` (core moved during this
session): `core/schemas/events/identity/` has `api_key`, `mfa`, `oidc_client`,
`session` and `user`, and **no `account/` and no `member/`**. `identity.member.accepted`
has no catalog row at all under that name; core calls the fact
`identity.member.joined`.

Then I **declared the five on a scratch copy and ran core's own checker** against
it. Six findings, verbatim:

```
FAIL event.unknown-published  cafaye.yml: exposes/events[11]: 'identity.member.accepted'
     is published here and core's catalog does not list it, so no consumer is known
     to be waiting for it
FAIL event.payload-schema-missing  exposes/events[9]:  'identity.account.created' …
     schemas/events/identity/account/created.schema.json
FAIL event.payload-schema-missing  exposes/events[10]: 'identity.member.invited' …
     schemas/events/identity/member/invited.schema.json
FAIL event.payload-schema-missing  exposes/events[11]: 'identity.member.accepted' …
     schemas/events/identity/member/accepted.schema.json
FAIL event.payload-schema-missing  exposes/events[12]: 'identity.member.role_changed' …
     schemas/events/identity/member/role_changed.schema.json
FAIL event.payload-schema-missing  exposes/events[13]: 'identity.member.removed' …
     schemas/events/identity/member/removed.schema.json
```

That is exactly what `knownUndeclaredEvents`' five reasons name, so the evidence is
a red build rather than a reading of a directory listing. The scratch copy was
reverted; `TestTheManifestDeclaresEveryEmittedEvent` still passes and still logs
the five gaps.

**What core needs, written down and left for its own packet:** five files at
`schemas/events/identity/account/created.schema.json` and
`schemas/events/identity/member/{invited,accepted,role_changed,removed}.schema.json`,
plus a catalog row for `identity.member.accepted` or a recorded ruling that
`accepted` and `joined` are one fact. All of it is in DECISIONS.md D1.

I also **corrected a stale claim this file was carrying**: its header said "core
ships one identity payload schema (user/created) for twelve published types", which
was true when written and is not now — core-23 shipped eight more, and there are
nine. The blocker is unchanged; the sentence about how many core ships was not, and
a file whose stated reason is false is a file whose exception stops being
reviewable.

## A second security defect found while verifying, NOT fixed here

**A revoked invitation still redeems.** This is the finding I did not fix and am
reporting plainly.

Three statements, none of which mentions `revoked_at`:

- `Store.InvitationByToken` — `SELECT … FROM account_invitations WHERE token_digest = $1`
- `Service.Accept` — checks `AcceptedAt` and `ExpiresAt`, nothing else
- `Store.MarkInvitationAccepted` — `… WHERE id = $1 AND accepted_at IS NULL`

Reproduced against a real database: mint an invitation, revoke it with the exact
statement the admin route runs (1 row affected), then redeem it as a *different*
signed-in user — **200, and a new membership**, leaving the row with **both**
`accepted_at` and `revoked_at` set. A state
`migrations/00013_account_invitation_revocation.sql`'s own header says cannot
happen.

`TestTheRevokedInvitationIsActuallyDead` **passes while this is true.** It posts
the redemption with the shared `post` helper, which sends no `Authorization`
header, so the route answers 401 and `accept.Code != http.StatusOK` is satisfied
by an authentication failure rather than by the revocation being honoured. I
verified this by running the test (green) beside the reproduction (red).

The consequence is that `DELETE /v1/accounts/{id}/admin/invitations/{invitation_id}`
and the bulk revocation recall nothing — which is the entire reason that surface
exists.

**Not this packet's.** It is a behaviour fix in the admin surface, it needs its own
packet, and nothing in this packet's document change depends on it — the document
I wrote does not claim a revoked invitation is dead. Recorded in the CHANGELOG under
**Security** and in DECISIONS.md D1 so it cannot be lost. My recommendation is that
it be the next identity packet, and that the test be re-pointed at a credentialed
request first.

## The gate, run honestly

Against a private Postgres (`wt-m39-identity-pg`, port 55439), goose-applied to
version 15:

| gate | result |
|---|---|
| `go build ./...` | green |
| `go vet ./...` | green |
| `gofmt -l .` | green, prints nothing |
| `go test -count=1 ./...` | **green, 23 packages** |
| `go test -race -count=1 ./...` | **green, 23 packages** |
| `bin/coverage-floor` | **74.2%** against a 70% floor |
| `golangci-lint run ./...` | 69 findings, **identical set before and after** — all pre-existing, none in the code this packet wrote |
| `caf contract lint .` (resolved core) | `OK cafaye.yml` |
| `oapi-codegen` regeneration gate | green — `TestTheCommittedGeneratedFileIsWhatThePinnedGeneratorProduces` runs the pinned v2.8.0 and compares |
| `openid/openid.yaml` validation | green — loaded by the same kin-openapi validator through oapi-codegen |

**`bin/prime` on its own is red**, and it is supposed to be:
`TestTheDatabaseTierActuallyRan` FAILS when `TEST_DATABASE_URL` is unset, by
design. With the variable set, the whole gate above is green.

**Coverage moved 74.7% → 74.2%.** Above the floor, and measured against the
baseline by stashing the branch and re-running, so the number is a comparison and
not an impression. The `coverage-exclusions` entry for `client/generated` was
restated in the same commit, which is what that mechanism is for: the generated
file went 16845 → 22435 lines and 3052 → 3976 statements because the document
gained ten operations, and `TestTheCoverageExclusionIsOnlyGeneratedCode` failed
until the declaration was rewritten. The floor did **not** move.

## Things I changed that are not the ten operations, and why

| | why |
|---|---|
| `internal/accounts/store.go`, `internal/httpapi/accounts.go` | the member-list fix above; without it two operations cannot be documented honestly |
| `client/transport.go`, `client/client.go` | ten interface methods and ten typed wrappers, because `TestTheTransportCoversEveryOperationInTheDocument` correctly refuses a document the client cannot call. Stale counts ("thirty-one", "twenty operations") corrected to 41 |
| `client/regeneration_test.go`, `credential_leak_test.go`, `safetolog.go`, `transport_test.go` | count corrections in comments only |
| `coverage-exclusions` | the excluded set is a function of the document, so a document change restates it |
| `internal/platform/ci/skip_exceptions_test.go` | it cited `knownDrift` as a model for "cannot grow **and cannot be emptied**". That is a rule this repository no longer follows, so the citation was the stale fact |
| `openapi/v1.yaml` Known gaps 1 and 3 | gap 1 said `Idempotency-Key` was missing on `POST /v1/users` and "the first thing to add to this surface"; it is missing on **nine** POSTs and my three join the list, so the gap text now says so rather than looking like the tenancy work forgot. Gap 3 said `info.version` was 1.3.0 — it was 1.6.0 and is now 1.7.0 |
| `openapi/v1.yaml` info block | the sentence "`identity` has no platform-admin role yet — the admin API is a later packet" was false in the same file that carried the `admin` tag. Corrected, and it now points at the `tenancy` tag's session-only rule |

## What I did NOT do

- **Did not push, merge or tag.**
- **Did not grow `knownDrift`, add a prefix filter, or add a tolerated-names
  list.** Any of those would have made a red go away without making the service
  true.
- **Did not declare the five events** — the evidence says it would trade a silent
  gap for six loud reds.
- **Did not fix the revoked-invitation defect.** It is a behaviour change on the
  admin surface and it needs its own packet.
- **Did not touch `Idempotency-Key`**, core's `/healthz`-in-the-document question
  (D25), the audit log's page envelope, or `/readyz`'s non-problem 503. All four
  are real core-convention findings that predate this packet and are recorded in
  the document's Known gaps; three of them are named in the gate output above and
  none is made worse by it.

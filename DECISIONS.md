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
| [D2](#d2-the-generated-client-commits-a-dependency-md6-said-it-would-not) | the generated client commits a runtime dependency, which MD6 said it would not — and it takes the coverage floor | RULED, with MD6's stated REASON corrected: the client ships here, generated, and the dependency is paid for |

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

## D2: the generated client commits a dependency, MD6 said it would not

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

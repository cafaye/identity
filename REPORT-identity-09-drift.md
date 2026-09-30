# REPORT — identity-09, the document-versus-router drift tripwire

**The tripwire fires on its first run, and that is the headline.** Twelve
operations are served by this service's router and described in **no committed
document** — not in `openapi/v1.yaml`, not in `openid/openid.yaml`, and for ten
of them not in this README's endpoint table either. A client generated from
either document has no method for any of them. They are gated, seven of them
carry a declared scope, and all ten are rows in the authorization matrix: they
are checked for authorization and unrecorded as contract surface at the same
time. The second pair is **billing's bug, already present here** —
`POST /oidc/authorize` and `POST /oidc/userinfo` are mounted deliberately and
`openid/openid.yaml` declares only the `GET`.

Nothing was already wrong in the *other* direction: every operation either
document declares is served. The drift is entirely one-directional.

This packet is scoped to add a check and not operations, so it does not fix
them. It holds all twelve in a pinned list and escalates the question as **D1**
in a `DECISIONS.md` this repository did not previously have.

---

## The four red proofs, verbatim

All four are reproducible from a clean tree; each edit is a one-line injection
and each is reverted with `git checkout` immediately after.

### Proof 1 — a handler with no document entry

`internal/httpapi/apikeys.go`, after the introspection route:

```go
	r.Get("/v1/proof-one", o.handleIntrospect)
```

```
    openapi_drift_test.go:284: the router serves 1 operation(s) that openapi/v1.yaml, openid/openid.yaml and knownDrift all fail to account for:

          GET /v1/proof-one

        A route that is neither documented nor named is the failure this file exists to catch, and the list must not become the place it hides. Do one of the two things:
          1. the route is part of the public surface — document it in openapi/v1.yaml or openid/openid.yaml depending on which surface it is on, and give it an operationId.
          2. the route is not meant to be public — add it to knownDrift with the reason it is not written down, and expect the pin on that list to fail so the addition gets read rather than merged.

        Do not add a prefix filter. A filter is a guess about intent, and it cannot see a method — which is how PUT /v1/customers/{id} went on being served in billing under a check that read paths only.
--- FAIL: TestEveryServedRouteIsDocumentedOrNamed (0.00s)
FAIL
FAIL	github.com/cafaye/identity/internal/httpapi	0.841s
```

### Proof 2 — a documented operation removed from the router

`r.Post("/v1/users", o.handleRegister)` deleted from `registerRoutes`:

```
    openapi_drift_test.go:315: the documents declare 1 operation(s) the router does not serve:

          POST /v1/users

        A generated client calls these and gets a 404. Do one of the two things:
          1. the operation is shipping — mount it.
          2. it is not — delete it from the document, and note the removal in the CHANGELOG.
--- FAIL: TestEveryDocumentedOperationIsServed (0.00s)
FAIL
FAIL	github.com/cafaye/identity/internal/httpapi	0.701s
```

### Proof 3 — an existing path under a second method (billing's bug)

`r.Put("/v1/session", o.handleLogin)` added beside the documented
`r.Post("/v1/session", …)`. The path set is now **identical on both sides** and
both counts are unchanged:

```
    openapi_drift_test.go:284: the router serves 1 operation(s) that openapi/v1.yaml, openid/openid.yaml and knownDrift all fail to account for:

          PUT /v1/session

        A route that is neither documented nor named is the failure this file exists to catch, and the list must not become the place it hides. Do one of the two things:
          1. the route is part of the public surface — document it in openapi/v1.yaml or openid/openid.yaml depending on which surface it is on, and give it an operationId.
          2. the route is not meant to be public — add it to knownDrift with the reason it is not written down, and expect the pin on that list to fail so the addition gets read rather than merged.

        Do not add a prefix filter. A filter is a guess about intent, and it cannot see a method — which is how PUT /v1/customers/{id} went on being served in billing under a check that read paths only.
--- FAIL: TestEveryServedRouteIsDocumentedOrNamed (0.00s)
--- PASS: TestEveryDocumentedOperationIsServed (0.00s)
FAIL
FAIL	github.com/cafaye/identity/internal/httpapi	0.686s
```

**The `--- PASS` on the forward direction in that run is the point.** A
path-only comparison and a count comparison both report agreement on this fault.
Only the `(method, path)` key sees it.

Incidental finding: injecting this needed `Put` added to the `chiRouter`
interface, which does not have it. That narrow interface is an accidental guard
against exactly this bug on the `/v1` surface — a `PUT` cannot be registered
through it — but `newMux` takes a `*chi.Mux` directly, so nothing stops one being
added at the router level.

### Proof 4 — the route added to the list instead of documented

The `/v1/proof-one` route of proof 1, still served, still undocumented, now given
a `knownDrift` entry. **The direction check goes green and the suite stays red**,
which is the whole property:

```
--- PASS: TestEveryServedRouteIsDocumentedOrNamed (0.00s)
    openapi_drift_test.go:351: knownDrift has grown from 12 entries to 13. A list that grows is the escape hatch: an undocumented route would get an entry and the suite would go green, which is a check that can be made green by not checking. Close DECISIONS.md D1 — by documenting the route, or by ruling it out of the contract in writing — and shrink this list with it. Never grow it to make a red go away.

          now: [DELETE /v1/accounts/{} DELETE /v1/accounts/{}/members/{} GET /v1/accounts GET /v1/accounts/{} GET /v1/accounts/{}/members GET /v1/proof-one PATCH /v1/accounts/{} PATCH /v1/accounts/{}/members/{} POST /oidc/authorize POST /oidc/userinfo POST /v1/accounts POST /v1/accounts/{}/invitations POST /v1/invitations/accept]
--- FAIL: TestKnownDriftIsExactlyTheRoutesItClaimsToBe (0.00s)
FAIL
FAIL	github.com/cafaye/identity/internal/httpapi	0.693s
```

### Restored

```
--- PASS: TestEveryServedRouteIsDocumentedOrNamed (0.00s)
--- PASS: TestEveryDocumentedOperationIsServed (0.00s)
--- PASS: TestKnownDriftIsExactlyTheRoutesItClaimsToBe (0.00s)
--- PASS: TestKnownDriftNamesOnlyServedRoutes (0.00s)
```

`git status` is clean after the sequence.

---

## The four red proofs also live in the suite

Terminal history is not a gate. `internal/httpapi/openapi_reader_faults_test.go`
keeps the proof where it runs on every commit: 38 tests covering the reader's
rules, nine documents it must refuse rather than under-read, and the comparison
pointed at injected faults in both directions. The load-bearing one,
`TestAMethodAddedOnOneSideOnlyIsDriftEvenThoughThePathMatches`, is proof 3 driven
through `diff/3` rather than through a reimplementation of it.

---

## `bin/prime`, with `TEST_DATABASE_URL` set

```
$ export TEST_DATABASE_URL="postgres://postgres@127.0.0.1:15711/identity_test?sslmode=disable"
$ ./bin/prime            # go mod download && go build ./... && go test ./...
```

```
ok  	github.com/cafaye/identity/cmd/identity	8.970s
ok  	github.com/cafaye/identity/internal/accounts	16.704s
ok  	github.com/cafaye/identity/internal/apikeys	16.702s
ok  	github.com/cafaye/identity/internal/auth	14.556s
ok  	github.com/cafaye/identity/internal/config	3.880s
ok  	github.com/cafaye/identity/internal/httpapi	39.641s
ok  	github.com/cafaye/identity/internal/mfa	20.056s
ok  	github.com/cafaye/identity/internal/oauth	10.718s
ok  	github.com/cafaye/identity/internal/oidc	6.373s
ok  	github.com/cafaye/identity/internal/outbox	4.881s
ok  	github.com/cafaye/identity/internal/platform/ci	0.828s
ok  	github.com/cafaye/identity/internal/platform/clock	1.408s
ok  	github.com/cafaye/identity/internal/platform/db	1.743s
ok  	github.com/cafaye/identity/internal/platform/id	1.535s
ok  	github.com/cafaye/identity/internal/sessions	1.632s
ok  	github.com/cafaye/identity/internal/users	1.507s
```

**1544 PASS, 0 FAIL, 0 SKIP.** Measured as PASS lines including subtests, which
is how `.github/workflows/ci.yml` counts.

| | before this packet (`bff6333`) | after | delta |
|---|---|---|---|
| with the database tier | 1506 PASS, 0 SKIP, 0 FAIL | **1544 PASS, 0 SKIP, 0 FAIL** | +38 |
| without it | 923 PASS, 364 SKIP, 2 FAIL | 961 PASS, 364 SKIP, 2 FAIL | +38 |

**All four gates green:** `bin/prime`, `go vet ./...` clean, `gofmt -l .` prints
nothing, `go test -race ./...` clean. No sleeps, no raised retries, no loosened
assertions.

Two notes on the numbers, both of which were already true before this packet:

- The brief quoted a baseline of 1392. Measured at `bff6333` the figure is 1506.
  I have used the measured one throughout.
- **Two** tests are called `TestTheDatabaseTierActuallyRan` — one in
  `internal/mfa`, one in `internal/apikeys` — so a run without a database fails
  twice, not once. The README said one.

### The CI floor

`.github/workflows/ci.yml` holds `SUITE_FLOOR: '1254'`. It is **not lowered**,
and I did not raise it. The measurement is 1544, so the floor has a 290-test
blind spot — the same defect the workflow's own comment records being fixed for
`internal/platform/ci` ("the floor had a number the floor could not see"). I left
it alone deliberately: pinning it to today's exact count turns a decrease
detector into a target that can go red on an unrelated platform difference, and
changing a CI gate is not this packet's business. **It is worth a separate
decision.**

---

## The exclusion list, and why there isn't one

**There is no exclusion list in this packet.** The brief expected one; identity
needs none, and inventing one would have been the wrong way to make the suite
green. What the brief anticipated, and what is actually true here:

| expected exclusion | what identity does | why |
|---|---|---|
| `GET /healthz` | **documented** in `openapi/v1.yaml` as `liveness` | a probe that is in the contract needs no excuse, and `TestTheProbesAreDocumentedRatherThanExcluded` holds that so a later packet cannot quietly exclude it |
| `GET /readyz` | **documented** as `readiness` | as above |
| `GET /up` | **not served** | identity has no Rails `/up`; it has `/healthz` |
| `404`, `422`, `500`, `503` | **not served** | chi registers no error-handler route. `NotFound` and `MethodNotAllowed` are handlers on the mux, not routes, so 404 and 405 do not appear in a walk. Those four paths are Rails' `config.exceptions_app` shape, from billing. |
| `/oidc/*`, `/.well-known/*` | **documented**, 9 of 11 | in `openid/openid.yaml`, which exists for them. Reading both documents is what keeps them out of a list of omissions that would have been false about nine of them. |

Whether a service may document its probes is **core's D25 and it is open**.
identity answered it for itself by documenting them; this packet asserts the
answer and does not decide the question.

### The one list that exists: `knownDrift`

Keyed by method **and** path, and it is not an exclusion list. Every entry is a
**bug**, and the name says so — an exclusion list claims a route is not part of
the contract, while `knownDrift` admits a route is served and written down
nowhere. Merging the two meanings would let a future route be excused by being
called a bug.

| operation | why it is here |
|---|---|
| `POST /v1/accounts` | served since the accounts packet; in no document |
| `GET /v1/accounts` | as above |
| `GET /v1/accounts/{account_id}` | as above |
| `PATCH /v1/accounts/{account_id}` | as above |
| `DELETE /v1/accounts/{account_id}` | as above |
| `GET /v1/accounts/{account_id}/members` | as above |
| `POST /v1/accounts/{account_id}/invitations` | as above |
| `PATCH /v1/accounts/{account_id}/members/{user_id}` | as above |
| `DELETE /v1/accounts/{account_id}/members/{user_id}` | as above |
| `POST /v1/invitations/accept` | as above |
| `POST /oidc/authorize` | `openid.yaml` declares `GET` only; the `POST` is deliberate in `registerOIDCRoutes` and justified in a comment there |
| `POST /oidc/userinfo` | as above |

**Closed in both directions, and the closure is what the brief asked for:**

- A route that is **neither documented nor listed** fails
  `TestEveryServedRouteIsDocumentedOrNamed`.
- The list **cannot grow** — proof 4. That is the escape hatch the brief warned
  about, and the pin is what closes it.
- The list **cannot be emptied either**, because that is somebody deleting the
  list instead of fixing the routes.
- Every entry is checked for staleness in both directions: one naming a route the
  router no longer serves, and one naming a route a document now describes, are
  both failures.
- Shrinking it is the only legal change, and it happens by documenting an
  operation.

---

## Judgments I made, and their cost

The brief says to make them and record them. Each is in the code, in
[DECISIONS.md](DECISIONS.md), or in the CHANGELOG.

**1. The check reads both documents, not only `openapi/v1.yaml`.** The brief asked
for the one. Reading only it would have been *wrong* rather than merely narrow:
eleven routes under `/oidc/*` and `/.well-known/*` are served, nine of them are
documented in the sibling document, and a one-document check would have had to
declare all eleven "not client operations" — false about nine. A list of
omissions is where a false claim does the most damage. The v1 direction is a
strict subset of what is now checked.

**2. `knownDrift` is a separate concept from an exclusion list.** The brief
anticipated an exclusion list holding probes and error routes. Neither exists
here, so the one list that remains means something different, and I kept it
separate rather than renaming it to fit the brief's vocabulary.

**3. Adding the twelve operations was out of scope, so D1 is open, not decided.**
The two available calls — document them, or rule them out of the contract in
writing — are both a human's. The cost of not deciding is a pinned list of
twelve; the cost of guessing wrong is a contract change in a security-boundary
service, made by a packet told not to make one.

**4. `New` now builds the mux through `newMux`.** So the walk reads the
production assembly rather than a second one written out in a test, which would
have been exactly the hand-maintained list the check exists to refuse. No
behaviour change; `New` is the only caller.

**5. No dependency added, and no YAML parser.** `go.mod` has none and `go mod
tidy` still leaves `go.mod` and `go.sum` unchanged. A YAML library *is* in the
module graph — `go.yaml.in/yaml/v3`, transitively, via `zitadel/schema` — and
importing it would promote it to a direct requirement, putting its versions and
its CVEs on this service for the sake of forty lines of structure. courier hit
the same wall and wrote a reader; this is that reader. It reads the `paths:`
block by indentation, derives its two levels from the document rather than
assuming two and four spaces, and turns every way it could under-read into an
error. **Verified against an independent parser** (Ruby's `psych`): 20 operations
in `openapi/v1.yaml`, 9 in `openid/openid.yaml`, 29 in the union, matching the
reader exactly. Router: 41 routes. 29 documented + 12 drift = 41.

**6. `info.version` not bumped.** The brief ties a bump to "the operations added".
This packet adds none, so 1.3.0 stands and `TestTheDocumentIsOpenAPI31AndCarriesAVersion`
pins it. A packet that adds an operation moves that pin in the same commit.

**7. identity's `DECISIONS.md` created, numbered from D1.** The brief said
"D-numbered after its existing ones"; there were none. `moon/DECISIONS.md` numbers
workspace questions `MD…` and `cafaye.yml` carried the one callout this
repository had. A packet that had to escalate something had nowhere to put it.
A `DECISION NEEDED` callout for D1 also went into `cafaye.yml`, because
`exposes.api` promises a document describes this service's HTTP surface.

**8. The README's testing counts were corrected.** They read 776/309/1 and 1254;
measured at `bff6333` they were 923/364/2 and 1506, so they were already stale
before this packet. Corrected to this tree's figures, with the earlier ones
recorded rather than quietly overwritten.

---

## Assumptions

**The router-reading test asserts on the test environment's route set, and Go
draws the same routes in every environment.** As the brief anticipated, I did not
expand scope to boot a production environment to prove it. The concrete
dependency is worth naming: the walk builds a router with every `Option`
populated, because `registerRoutes` returns immediately with no `auth`,
`registerTenancyRoutes` needs a tenancy service, `registerMFARoutes` needs a key,
`registerAPIKeyRoutes` needs `apiKeys`, the introspection route needs an
`Introspector`, and the OIDC surface needs a provider and a client store. If a
future packet ever makes a route's registration depend on a *value* rather than
on the presence of a dependency — a feature flag, a config field, a tenant —
this check will read a different route set in production than in the suite. The
same assumption is in six other services, and this is the test that would catch
it breaking.

**chi parameter names differ from the document's, deliberately.** chi registers
`{accountID}` and the document writes `{account_id}`, so the reader erases the
parameter name and keeps which segment it was. Renaming a parameter is a rename
inside one route, not a second route, and a check that cried wolf would be turned
off. This was verified against the real files rather than assumed.

---

## What this packet did not do

- It did not document the twelve operations. Forbidden by the brief, and a
  contract change to a security-boundary service belongs in its own packet.
- It did not remove the two OIDC `POST`s. The comment justifying them names the
  case — a product behind a strict corporate proxy — and removing them would
  break it.
- It did not touch `openapi/v1.yaml`'s content at all: not `info.version`, not a
  path, not a schema.
- It did not touch core, kit, or any other service. It did not create
  `moon/refs/`, create a remote, push, or change a visibility.
- It did not add a dependency.
- It did not lower the CI floor, and did not raise it either.
- It did not boot a production environment.

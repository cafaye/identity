# REPORT — identity-account-scope-01

**Worktree:** `wt-m39-identity-acctscope-01` · **branch:** `worker/identity-account-scope-01`
**Commit:** `b323113` — *account_scope.yml: identity's account-scope declaration, 42 of 54 entry points*

## 0. The short version

`account_scope.yml` exists at identity's root and core's checker reads it and
exits `0`:

```
$ cd core && python3 harness/account_scope_check.py ../wt-m39-identity-acctscope-01
OK  wt-m39-identity-acctscope-01: 17 account-scoped, 25 not-account-scoped,
    0 undeclared — 0 failure(s), 3 warning(s); warnings do not move the exit code
$ echo $?
0
```

| | |
|---|---|
| routes identity mounts | **54** |
| rows in `entryPoints` | **42** |
| `accountScoped: true` | **17** |
| `accountScoped: false` | **25** (12 `none`, 7 `public`, 6 `unauthenticated-callback`) |
| routes the instrument cannot see | **12**, enumerated in the file |
| `surface.sources` | 9 files, `internal/httpapi/*.go` |
| `surface.minimum` | **41** — the count the checker finds, exactly |
| warnings | 3, all reported in §6.3 |
| control / breakages planted / observed RED | **2 / 5 / 5** |

identity's own gate is **red on `master` before this packet and red after it**, for
one unrelated reason, with a control in §7. Adding this file moved no floor and no
tier count: `PASS=2385 SKIP=3 package_fail=1` on this worktree and `PASS=2385
SKIP=3 package_fail=1` on a clean `master` checkout — the same numbers, measured.

Five findings for `core` are in §6. Three of them are defects in the instrument on
the repository the packet names as the first adopter, and each one has a
reproduction rather than an argument.

---

## 1. What the declaration says, and the one thing it claims

Every one of the seventeen `accountScoped: true` rows carries the **same**
`accountFrom`:

```yaml
accountFrom: { via: requireAccountRole, file: internal/httpapi/accounts.go, line: 286 }
```

`accounts.go:286` is `accountID, ok := accountIDFrom(r)`, inside
`requireAccountRole` — the gate on every account-scoped route in this service.
The repetition is the claim: **this service has exactly one account boundary on
its HTTP surface**, and the file says so seventeen times in the only vocabulary
the format offers.

The seventeen are the account path surface (7 in `accounts.go`), the admin
surface (3), the api-key surface (3) and the OIDC-client-registration surface
(4). The three admin routes are wrapped
`requireAdminToken(requireAccountRole(...))` — a user session is refused
outright — and core's `HANDLER_WINDOW = 3` exists because identity's own
`admin.go:122-123` writes the path on one line and the middleware on the next.
Those two lines are why the packet says this is the right first adopter, and they
held.

---

## 2. The judgement calls, and why

This section is the one a reviewer should read before the numbers. Three things
in this file were decisions rather than readings, and none of them is forced by
the format.

### 2.1 `reason` has no member for "the caller's own rows", and I did not add one

core's schema closes the vocabulary at five:

| reason | core's definition | used here |
|---|---|---|
| `public` | reachable without a credential at all | 7 |
| `unauthenticated-callback` | a third party calling back over a signature this service verifies | 6 |
| `none` | for an entry point that reaches no data at all | 12 |
| `platform-admin` | scoped to the operator's own account and reaches no customer row | **0** |
| `system` | reached only by this fleet's own machinery | **0** |

**The gap.** The most common shape on this service's surface is: *a caller
presents a credential; the subject is derived from it; no account is named in the
request and no other account's row is reachable.* `GET /v1/me`,
`DELETE /v1/session`, the five MFA routes, `GET /v1/email-verification`, the
three email-change routes, `GET /v1/accounts`, `POST /v1/accounts`,
`POST /v1/introspections`. That is **12 rows**. Not one of the five members
describes it: `none` says it reaches *no data at all*, which is false for all
twelve.

**The choice, and the reasoning.** I used `none` on all twelve and wrote the
real answer in a comment on every one. The reasoning is which way the
mis-statement fails:

* `none` under-claims. A reader who believes it goes and looks.
* `platform-admin` over-claims, and in the dangerous direction: it asserts an
  operator boundary on a customer session. `platform-admin` rows are the ones an
  auditor trusts most — "scoped to the operator's own account and reaches no
  customer row" is the sentence you skip past. Putting it on
  `GET /v1/accounts/{accountID}/api-keys` would put a false boundary claim on
  the exact route a reader is most likely to be checking.

**This is a finding for core** (§6.5): a closed list gets filled with the
least-wrong member, so the members had better be the right ones. `platform-admin`
and `system` are used by **zero rows across every fixture core ships** and by
zero rows here — two of five members have never been exercised by anything.

### 2.2 `POST /v1/introspections` is the one boundary inside a handler

`registerIntrospectionRoute` mounts it with **no middleware at all**:

```go
r.Post("/v1/introspections", o.handleIntrospect)          // apikeys.go:419
```

The account is resolved one stack frame down, in `mayIntrospect`
(`apikeys.go:500`): `apikeys.ResolveAccountID(claims)` at line 503, then
`o.tenancy.Get(r.Context(), accountID, caller.User.ID)` at 511, which is what
refuses a caller who is not an owner with a **404**.

Declared `accountScoped: false`, and it is the truth: *a caller who does not
belong to the account cannot get at it*, which is the whole of what the field
asks. It is also the clearest evidence that `accountFrom.via` is not the only way
a service has to say where its boundary is — **there is no symbol on line 419 for
the contract to name.** Had I declared it `true` with `via: mayIntrospect`, the
checker would have answered `account-scope.scoping-bypassed`, which on this route
would be a false alarm on correct code.

### 2.3 The eleven OIDC protocol routes resolve no account, and the reason is in `internal/oidc`

This is the answer a reviewer will want, because it is not obvious from the
handler names: `/oidc/token` and `/oidc/userinfo` plainly "reach customer data".

They do not, for a reason that is written down in this repository. The token this
provider mints carries an **`accounts` array**, not one `account_id`:

```go
// internal/oidc/profiles.go:166
type claimAccount struct {
    AccountID string `json:"account_id"`
    Name      string `json:"name"`
    ...
```

whose own comment says why — *"a user of a cafaye product is a member of a
personal account and usually of several team accounts, so there is no single
`account_id` to put in a token."* So the account a caller receives on any of the
eleven is derived from the **user** identity the service authenticated, and no
caller can point any of them at an account they are not in.

The one account-owned row these routes do touch is the **client registration**
named by `client_id` — `oidc_clients` has an `account_id` column and
`tenancy.yml` §6 already names its secret-addressed lookup. The client
authenticates itself with its own secret to use it, which is what a credential
*is*, and it is the same argument `POST /v1/invitations/accept` gets from an
invitation token.

---

## 3. `surface.minimum: 41`, and why it is not 54

`minimum` is a **decrease-detector**, and core's doc says to set it to "the
number the sources held when you wrote this file". So: 41, measured.

54 is the number of routes. The thirteen the difference is made of are registered
with a **Go path constant** where a string literal would go, and core's chi
recogniser requires `("`:

```go
r.Get("/healthz", handleHealthz)                    // seen
r.Get(oidc.PathAuthorize, o.handleOIDCAuthorize)    // not seen
```

**Setting `minimum: 54` would have made every future run red for a reason that
has nothing to do with a defect** — which is the one thing a ratchet must never
do, and the reason the packet's rule exists. 41 still bites: §6.4 shows a deleted
route caught by exactly this floor.

`internal/httpapi/oauth.go` is named in `surface.sources` and contributes **zero**
recognised registrations. It is named anyway: the day somebody writes a third
route there as a string literal, this checker goes red naming it, instead of the
file staying invisible the way a file nobody named always is.

---

## 4. The twelve the declaration cannot contain — and why they are not rows

`account_scope.yml` names all twelve in a closing block, with file, line, method,
path and the honest scope answer, so a reader of the file can audit them today and
so they can be promoted by one commit the day the instrument can read a constant.

The short version: core's `registeredAt` check accepts a line that either
**matches a recogniser** or **contains the declared path's last segment**. On
these lines neither holds — `/oidc/authorize`'s last segment is `authorize` and
the line says `PathAuthorize`; `/v1/auth/oauth/{provider}`'s last segment
collapses to `{}` and the line says `{provider}`.

So each of the twelve, declared honestly at its real registration line, answers:

```
FAIL account-scope.stale: oidc-token: registeredAt points at a line that does
     not register it: internal/httpapi/oidc.go:138
```

**That text is false.** Line 138 registers it. Declared anywhere else — at the
constant's definition, or as `kind: internal` with the constant's name — the
checker goes quiet and the declaration stops describing the tree. Twelve findings
a reader has to learn to ignore is the failure mode core's own documentation names
as the reason guards get switched off, and this would be the *first adopter's*
file. So: a named gap in the file, and §6.1 for the fix.

**One of the thirteen is declared, and the reason is a coincidence of spelling.**
`GET /v1/auth/oauth/{provider}/callback` is in `entryPoints` because its last path
segment is the literal word `callback` and `callback` **is** on line 162. Its
sibling `GET /v1/auth/oauth/{provider}` is not, because a parameter's name never
appears in the source. That is the boundary between "declareable" and "not" in
this file, and it is a coincidence.

---

## 5. The `undeclared` half is what makes this a boundary and not a list

`undeclared` is decidable because `surface.sources` names the files. It is **0**
on the committed declaration, and it stayed 0 on four of the five falsification
runs. On the fifth — the one where a row was deleted from the declaration — it is
**1**, and it is the right 1 (§8, breakage 4). Nothing is left over: the
declaration covers **41 of the 41** registrations the instrument finds across the
nine named files.

---

## 6. Findings for `core`

Each has a reproduction. None was worked around in identity's tree, and the
checker was not modified.

### 6.1 A Go path constant makes a registration invisible, and no `registeredAt` line can name it

**Measured.** The chi recogniser's pattern is
`\.(?:(?P<verb>Get|…)\(\s*"(?P<path>/[^"]*)"…)` — a `"` is mandatory after the
`(`. `r.Get(oidc.PathAuthorize, …)` does not match, and neither recogniser nor
`concatenates` covers a *bare identifier* argument (concatenation is handled for
`"/v1/accounts/{id}/"+adminPrefix+"/audit-log"`, which has a leading literal).

**Two consequences, both on the repository this packet names as first adopter:**

* `undeclared` can never fire for such a route, in any file, in any language the
  fleet writes in Go. This is the "route in a syntax the recognisers do not
  know" entry in `notEnforced`, but measured rather than anticipated: **12 of
  identity's 54 routes**, 22% of the surface.
* declared honestly, `registeredAt` fires `account-scope.stale` — a finding whose
  message blames the author for the checker's blindness (§6.6).

**The fix is one lookup in a facility that already exists.** `module_index(repo)`
already walks the repository and records where each definition lives; the
contradiction check already builds it. Resolving `oidc.PathAuthorize` through it
gives `internal/oidc/provider.go:39`, whose text is
`PathAuthorize = "/oidc/authorize"`. One constant, and identity's twelve become
declarable — which is presumably why `handler_for` resolves handlers through an
index and `RECOGNISERS` does not resolve paths through one.

### 6.2 `_check_entry` does not strip comments from `registeredAt`. The surface walk does.

This is the one that only showed up because breakage 5 was a *tree* change
rather than a declaration change.

Commenting out `accounts.go:597` — the ordinary way a Go route is deleted —
produces **no `stale` and no `undeclared`**. Only `account-scope.surface-thin`.

```
FAIL account-scope.surface-thin: the declared sources register 40 entry point(s)
     and surface.minimum is 41
```

Measured cause, same line, two code paths, opposite behaviour:

```python
>>> line = '// r.Delete("/v1/accounts/{accountID}/members/{userID}", o.requireAccountRole(…))'
>>> registrations(line, "internal/httpapi/accounts.go")            # what _check_entry uses
[('DELETE', '/v1/accounts/{accountID}/members/{userID}', 'chi')]
>>> registrations(strip_comment(line), "internal/httpapi/accounts.go")   # what the surface walk uses
[]
```

`_line_at` returns the raw line and `_check_entry` hands it straight to
`registrations()`; the surface walk calls `strip_comment` first.

**Consequence, and it is the sharp one: `surface.minimum` at its exact count is
the only thing standing between a deleted route and a green run.** Measured
directly. With `minimum: 41` the only finding is `surface-thin`. With
`minimum: 40` — one lower, which the packet's own rule ("at or below the count")
permits — **the run is `OK`, exit 0, and the checker still reports the deleted
route as existing**:

```
$ # accounts.go:597 commented out, surface.minimum: 40
OK  wt-m39-identity-acctscope-01: 17 account-scoped, 25 not-account-scoped,
    0 undeclared — 0 failure(s), 3 warning(s)
exit=0

  account-scoped     DELETE /v1/accounts/{accountID}/members/{userID}
                     (internal/httpapi/accounts.go:597)        <-- not a route
```

A declaration reporting a route at a line that no longer registers it, in a green
run. The floor is a tripwire on one integer, and the finding whose entire job is
"a registration that has moved" does not fire on the most common way a
registration disappears.

`strip_comment`'s docstring names this exact case as its reason for existing —
*"identity's own router documents the routes it removed (`// GET /v1/x was
removed in…`)"*. It is handled in the walk and not in the entry check, so it is
half-handled.

**No live impact today, measured:** `grep -rEn "^\s*//.*\.(Get|Post|Put|Patch|Delete|Handle|HandleFunc)\(\"" --include=*.go`
over identity returns **0 hits**. Latent, not live. One `strip_comment` call in
`_check_entry` fixes it, and the measurement above is the red proof core's
`harness/tests/` rule would want alongside the fix.

### 6.3 A chi route whose handler is a bare function cannot be resolved, and the warning's remedy is for another language

Two of the twenty-five `false` rows in the first adopter's file cannot be
contradiction-checked:

```
WARN account-scope.contradiction-unreadable: healthz: … the handler could not be
     resolved to a file in this repository
WARN account-scope.contradiction-unreadable: readyz: … the handler could not be
     resolved to a file in this repository
```

Two distinct shapes, both in Go, both silent on every fixture core ships because
every fixture's handler is either a bare Phoenix module name or a dotted TS
member:

* `/healthz` registers `handleHealthz` — a bare package-level `func`. `_last_symbol`
  returns `handleHealthz`, and `_file_defining` only runs its definition search
  when `tail != symbol`, i.e. **only when the symbol carries a receiver**. Every
  bare `func handleX` in Go returns `None`.
* `/readyz` registers `o.handleReadyz(checks)`. `_last_symbol` walks the line
  backwards and returns the **last** token, which is `checks`.

And the remediation text on both warnings is *"name the router's middleware and
controller modules the way this repository already spells them"* — advice for a
Phoenix router. There is nothing to name: `handleHealthz` is a real function at
`internal/httpapi/httpapi.go:292`, and the checker's own definition search finds
it when it runs:

```
'func handleHealthz(w http.ResponseWriter, _ *http.Request) {'   ->  matched
```

The remedy is in the checker, not in the declaration, and the warning says
otherwise. A warning that tells the author to change a correct file is the
habit core's docs warn about, arriving by a different road.

The third warning — `social-login-callback`: *"no registration on the declared
surface matched this row"* — is the honest report of §4 and is correct.

### 6.4 `undeclared` fired on the right thing; `surface-thin` fired on the right thing

Both are on the good list and were not planted to be flattering:

```
BREAKAGE 4 (a row deleted, minimum: 41 unchanged)
FAIL account-scope.undeclared: chi registers DELETE /v1/accounts/{accountID}/members/{userID}
     at internal/httpapi/accounts.go:597, which is in a file surface.sources names
     and which no entry point covers

BREAKAGE 5 (the route itself deleted from the tree)
FAIL account-scope.surface-thin: the declared sources register 40 entry point(s)
     and surface.minimum is 41
```

The first is D18's failure with a finding attached: a registration nobody
declared. The second is what a ratchet is for. §6.2 is the caveat on the second.

### 6.5 The `reason` vocabulary, again, as a finding rather than an excuse

§2.1 argued the choice. The finding is the list itself:

* **5 members, 3 exercised** — `public`, `unauthenticated-callback` and `none` are
  the only ones used by any fixture core ships or by this adopter. `platform-admin`
  and `system`: **zero uses, anywhere.**
* **No member for "authenticated, resolves no account, subject is the caller's own
  row"** — 12 of 25 rows here, and it is the default shape for any service whose
  subjects *are* accounts. A closed list gets filled with the least-wrong member;
  the members had better be right.
* **`platform-admin`'s name is operator-specific while its semantics
  ("scoped to the caller's own account and reaches no customer row") are
  general.** Three of identity's rows fit those semantics exactly —
  `GET /v1/accounts`, `POST /v1/accounts` and `POST /v1/introspections`, the three
  that resolve the caller's *own* account and refuse any other — and not one of
  the three is operator-only. A reader grepping `platform-admin` to find
  operator-only surfaces would be misled, which is the reason it was the wrong
  member to reach for in §2.1.

One member that describes *"reachable only with the caller's own credential,
which resolves no account"* closes this, and would let `none` mean what the schema
says it means.

### 6.6 `account-scope.stale`'s message blames the author for the checker's reach

> `registeredAt points at a line that does not register it: internal/httpapi/oidc.go:138`

Line 138 registers it. The finding is right that the declaration does not verify
and wrong about why, and it says the wrong thing to the only reader who will act
on it. When the recogniser cannot see a syntax the service legitimately uses,
"this declaration is wrong" and "this checker cannot see this declaration" are
different findings, and the second one is the true one. `surface-missing` already
models the distinction — *"a checker told to look at a file that does not exist has
not looked"* — and it is a failure for the same reason.

---

## 7. The gate

### 7.1 What passed

`bin/prime` — `go mod download && go build ./... && go test -count=1 ./...` —
with `TEST_DATABASE_URL` against the local cluster, migrations applied to v17.
**21 of 22 packages `ok`.** Core's two other checkers against this tree:

| checker | verdict |
|---|---|
| `harness/account_scope_check.py` | **OK**, 0 failures, 3 warnings |
| `harness/gate_check.py` (static) | **OK**, 0 failures, 2 pre-existing warnings |
| `harness/tenancy_check.py` | **OK**, 0 failures, 1 pre-existing warning |

### 7.2 What was already red, with its control

```
--- FAIL: TestTheOtherSixSubstrateFunctionsAreKitsBytes (0.00s)
    substrate_copy_test.go:344: cafaye.protect_table differs from kit's.
FAIL github.com/cafaye/identity/internal/platform/ci
```

**Control: this fails identically on a clean `master` checkout of identity, with
no `account_scope.yml` present.**

```
$ cd identity && git status --porcelain      # (clean)
$ go test -count=1 -run TestTheOtherSixSubstrateFunctionsAreKitsBytes ./internal/platform/ci/
--- FAIL: TestTheOtherSixSubstrateFunctionsAreKitsBytes
```

So the red is pre-existing and unrelated to this packet. I did not adjust
`gate.yml`, any floor, any tier count, or the test.

**What it is, since it will be read.** kit's
`templates/database/tenancy/substrate.sql` has advanced: `cafaye.protect_table`
now also walks `pg_depend` and grants `USAGE` on the sequences a protected table's
own columns own. identity's `migrations/00016_account_isolation.sql`, which
declares itself a verbatim copy, does not. Two findings, and neither is mine to
fix here:

1. **identity's applied substrate has drifted from kit's current one.** The fix is
   a **new** migration (00018) — `AGENTS.md` and core's rules both forbid editing
   an applied migration. Note kit's own comment in the diff says *"Do not read
   this loop as a claim that `identity` was broken"*, so this is a substrate that
   has moved, not a broken service.
2. **The check does not honour `kit.ref`.** identity pins
   `1770009699a95d14c6e2729a1377590a9f71f103`; the local kit checkout is at
   `2e75d349a169d75d464e71a9e49c992c3e1bb95c`, which **is a descendant** of the
   pin (`git merge-base --is-ancestor` → yes). `findKitSubstrate` walks up to a
   sibling `kit/` and reads whatever is there, so the comparison target moves when
   kit moves and identity's gate goes red with nothing in identity having changed.
   A check against a pinned template that reads an unpinned copy of it is a check
   whose answer depends on the developer's directory layout.

### 7.3 Floors and tier counts: measured, not argued

identity's `gate.yml` carries **no** `proof[].minimum` — `AGENTS.md` says so and
`gate_check.py` confirms it (Go prints no test count). The decrease-detectors are
in `.github/workflows/ci.yml`:

| floor | value | measured |
|---|---|---|
| `SUITE_FLOOR` | 2020 | **2385** |
| `DATABASE_TIER_FLOOR` | 1732 | **1975** |

The tier partition is CI's own derivation — `dbtest.Pool|Schema|EnvVar` or
`TEST_DATABASE_URL` in a `_test.go`, comments stripped, which yields **16
packages** here — reproduced rather than approximated:

```
cmd/identity 31 · accounts 116 · admin 42 · apikeys 135 · auth 61 · courier 114
httpapi 831 · mfa 117 · oauth 111 · oidc 114 · outbox 79 · platform/db 27
recovery 55 · sessions 44 · tenancy 23 · users 75          = 1975
```

**The control, which is the point:**

| tree | PASS | SKIP | package failures |
|---|---|---|---|
| `wt-m39-identity-acctscope-01` (**with** `account_scope.yml`) | **2385** | **3** | **1** |
| `identity` @ master (**without** it) | **2385** | **3** | **1** |

Identical. Adding one YAML file at the root moved no floor, no tier count and no
test. The three skips are `internal/courier`'s declared e2e exemptions, and all
three are named exactly on `E2E_SKIP_EXCEPTIONS`, which is what CI's per-package
`s -ne 0` rule requires:

```
--- SKIP: TestAPasswordResetGoesOutThroughARealCourier
--- SKIP: TestAVerificationLinkReachesCouriersWelcomeTemplate
--- SKIP: TestTheTwoEmailChangeMessagesCourierCannotSendAreRefused
```

The one failure is §7.2, on both trees.

---

## 8. The falsification, with tallies

The load-bearing property of this declaration is that it **can fail**. A
declaration fitted to the checker until it passed would be worse than none,
because it reads as coverage. Five breaks were planted in the working tree, each
run, each reverted; the committed file was never modified and the tree was clean
at the end.

### Tallies, reported separately

| | |
|---|---|
| **controls** (nothing planted, expected green) | **2** — before the first break, and after the last revert |
| **breakages planted** | **5** |
| **observed RED** | **5** — one per breakage, five distinct findings |
| variants run on top of a breakage | **1** — breakage 5 re-run at `minimum: 40`, which went **green** and is reported as §6.2 and §8 |

Two further controls sit outside this table because they are about identity's own
gate rather than about this declaration: `bin/prime`'s one failure reproduces
identically on clean `master` (§7.2), and the PASS/SKIP/fail counts are identical
on both trees (§7.3).

### CONTROL 0 — the committed declaration

```
OK  wt-m39-identity-acctscope-01: 17 account-scoped, 25 not-account-scoped,
    0 undeclared — 0 failure(s), 3 warning(s)
exit=0
```

### BREAKAGE 1 — one wrong `accountFrom.line` (a real function, a real file, a wrong line)

`get-account`: `line: 286` → `line: 287` (`if !ok {`).

```
FAIL account-scope.account-key-lost: get-account: accountFrom names
     internal/httpapi/accounts.go:287, which does not carry any of
     ['account_id', 'accountId', 'account-id', 'accountid']
```

One row changed, one finding, **naming that row**. The other sixteen rows share
the identical `accountFrom` block and stayed green, which is the per-row
discrimination a shared block could easily have lost. The four spellings in the
message are derived from `surface.accountKey: account_id`, so the declaration is
what told the checker which vocabulary to search — no list the checker chose.

### BREAKAGE 2 — `accountScoped: true` on a genuinely public route

`GET /healthz` → `true`, with an `accountFrom` (the schema requires one).

```
FAIL account-scope.scoping-bypassed: healthz: registered at
     internal/httpapi/httpapi.go:245, which does not go through requireAccountRole
```

And the `contradiction-unreadable` warning on `healthz` **disappeared** — the
checker moved from "I could not read this row" to "I read it and it is wrong",
which is what a check gaining reach looks like. The warning on `readyz` stayed,
as it should.

### BREAKAGE 3 — a `true` row flipped to `false` (the liar direction)

`list-api-keys` → `false`, `reason: public`.

```
FAIL account-scope.declaration-contradicts-code: list-api-keys
     (GET /v1/accounts/{accountID}/api-keys) is declared accountScoped: false with
     reason 'public', and the registration goes through requireAccountRole, which
     this declaration itself names as an account resolver:
     `r.Get("/v1/accounts/{accountID}/api-keys", o.requireAccountRole(accounts.RoleOwner, o.handleListAPIKeys))`
     — resolver account evidence at internal/httpapi/apikeys.go:77
```

This is the finding core's `liar/` fixture exists for, firing on a real Go router,
and it fired from the declaration's **own vocabulary** — `requireAccountRole` is
not a name the checker chose, it is a name sixteen other rows in this same file
supply. The direction is worth stating: breakage 2 is *over*-claiming and breakage
3 is *under*-claiming, and the instrument caught both.

### BREAKAGE 4 — an entry point removed from the declaration, `minimum: 41` unchanged

The `remove-member` row deleted.

```
FAIL account-scope.undeclared: chi registers DELETE
     /v1/accounts/{accountID}/members/{userID} at internal/httpapi/accounts.go:597,
     which is in a file surface.sources names and which no entry point covers
```

D18's failure, with a finding attached: a registration nobody declared, in a file
the declaration named. Note `minimum` did **not** move — it counts registrations
in the sources, not rows — so `undeclared` is what carries this, and it carried it.

### BREAKAGE 5 — the route itself deleted from the tree

`accounts.go:597` commented out (not deleted, so no line numbers move).

```
FAIL account-scope.surface-thin: the declared sources register 40 entry point(s)
     and surface.minimum is 41
```

The floor bit. **This is also the breakage that found §6.2**: no `stale` and no
`undeclared` fired, because the surface walk strips the comment and
`_check_entry` does not. Re-run with `surface.minimum: 40` as well, the whole run
is `OK`, exit 0, and the summary still lists
`DELETE /v1/accounts/{accountID}/members/{userID}` at `accounts.go:597` — a route
that no longer exists. That variant is a **control on the floor**, not a sixth
breakage: it is what proves `minimum: 41` is load-bearing rather than decorative.

### CONTROL 1 — every breakage reverted

```
OK  wt-m39-identity-acctscope-01: 17 account-scoped, 25 not-account-scoped,
    0 undeclared — 0 failure(s), 3 warning(s)
exit=0
git status: 0 changed file(s)
```

---

## 9. What is NOT proven by this packet

* **The twelve unnamed routes are not checked.** They are written down and
  hand-classified. §6.1 is the fix; until it lands, `account_scope.yml` covers
  **42 of 54**, and a reader of the file alone knows it.
* **`accountScoped` on the twelve was decided by reading handlers, not by the
  instrument.** All twelve are `false`; §2.3 gives the argument for the eleven
  OIDC routes and the row for the social one. If any is wrong, the instrument
  cannot say so.
* **Two of the twenty-five `false` rows were not contradiction-checked** (§6.3).
  `healthz` and `readyz` are trusted on my reading plus their own code comments.
* **This file says nothing about whether the statements behind a handler scope
  their rows.** That is `tenancy.yml` and `harness/tenancy_check.py`, unchanged by
  this packet and green against this tree.
* **Core's own suite was not run** — this packet changes nothing in core, and
  core's checker was not modified. §6.1–§6.6 are reports, not patches; fixing
  them is a `core` packet and `core`'s rule applies: a finding, an inventory
  entry, and a red proof in the same commit.

## 10. What I did not do

* Did not modify the checker, `core`'s schema, `docs/account-scope.md`,
  `account_scope_findings.json`, or anything else in `core`.
* Did not modify any Go file, `tenancy.yml`, `gate.yml`, `ci.yml`, or any floor.
* Did not lower `surface.minimum` to make `surface-thin` go away; did not raise it
  above the truth to look thorough.
* Did not add a Go or Rust test tier to prove the declaration. The checker is the
  instrument; §8 is the proof.
* Did not merge and did not push. Branch is `worker/identity-account-scope-01`.
* Did not touch `billing`, `darkroom`, `muse`, any `wt-m39-pantry-*` worktree, or
  any `worker/pantry-*` branch.

**The three honest empty surfaces — `guard`, `site`, `parlor` — were not started.**
Per the packet they are three one-file packets in three repos, on their own
branches, after this one lands. `kit/reports/tenant-adapter-ts-01/subject-audit.sh`
has already measured that those three hold no database, so the empty declaration
is a fact to check rather than a claim — but it is not this branch, and bundling
it here would have made three repositories' worth of change indistinguishable
from one file.
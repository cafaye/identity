# REPORT — identity-14-rename

**Branch:** `worker/identity-14-rename` · **Not pushed. No tag created.**

## The finding

**The packet's central claim does not reproduce, and the defect underneath it is
worse than the one it named.**

The packet said identity "declares `core: ^0.1.0` and publishes `account.created`
— two segments, the forbidden form". I measured both halves before changing
anything.

The second half is false. All twelve published event types in `internal/outbox`
are three segments and carry the `identity.` prefix:

```
$ grep -rn 'Event[A-Za-z0-9_]* *= *"' --include='*.go' internal/
internal/outbox/envelope.go:46:   EventUserCreated       = "identity.user.created"
internal/outbox/tenancy.go:46:     EventAccountCreated   = "identity.account.created"
internal/outbox/tenancy.go:50:     EventMemberInvited    = "identity.member.invited"
internal/outbox/tenancy.go:72:     EventMemberAccepted   = "identity.member.accepted"
internal/outbox/tenancy.go:76:     EventMemberRoleChanged= "identity.member.role_changed"
internal/outbox/tenancy.go:81:     EventMemberRemoved    = "identity.member.removed"
internal/outbox/mfa.go:41,46       identity.mfa.enabled / identity.mfa.disabled
internal/outbox/apikeys.go:42,46   identity.api_key.created / identity.api_key.revoked
internal/outbox/oidc.go:28,34      identity.oidc_client.created / identity.oidc_client.revoked
```

The bare two-segment string survived only in prose: two comments and the short
labels of one test's map. There is a test in this repository that has been
pinning the shape for some time — `TestTenancyEventTypesAreThreeSegment`, whose
comment says why the assertion is needed at all: *"A constant that lost its
prefix would still pass Validate's pattern — it allows two or three segments —
so the shape is pinned here rather than inferred."*

`core` reached the same numbers before this packet started. `REPORT-core-17.md`
§1 is titled *"Did not reproduce: `identity` does not publish `account.created`"*
and measures 12 types, 7 declared, 5 undeclared — the same twelve, seven and
five I measured. Two independent measurements agreeing is why I am reporting the
premise as false rather than as a subtlety I could be wrong about.

**So the severity is lower than the packet stated.** This is a mis-declaration,
not a published contract violation. The `core:` range was the real finding, and
it is the one finding I could fix.

**The defect underneath is the one worth the packet's time.** `exposes.events` is
not a complete declaration of what this service publishes. Five events are
emitted from `internal/accounts/service.go` and declared nowhere:

| Event | Emitted at | In `exposes.events`? | In core's catalog? | Payload schema in core? |
| --- | --- | --- | --- | --- |
| `identity.account.created` | `service.go:153,221` | **no** | yes | **no** |
| `identity.member.invited` | `service.go:406` | **no** | yes | **no** |
| `identity.member.accepted` | `service.go:515` | **no** | **no** (`member.joined`) | **no** |
| `identity.member.role_changed` | `service.go:584` | **no** | yes | **no** |
| `identity.member.removed` | `service.go:700` | **no** | yes | **no** |

No core rule catches this, and **no core rule ever will as core is currently
written**: every rule in `harness/rules.json` reads a *declaration*, and none
reads a service's source. `REPORT-core-17.md` named exactly this and called it
"not this packet's work — it needs a decision about reading another language's
code." This packet is that work, for one language, on the one service whose gap
was measured.

## What changed

1. **`core: ^0.1.0` → `^0.2.0`**, in the same commit as the rename, as 0.2.0's
   changelog requires. This was the whole of what the contract checker had to
   say about the version.
2. **The two-segment spellings are gone from the tree.** `grep '\baccount\.created\b'`
   over the repository now returns nothing outside a qualified
   `identity.account.created`.
3. **Two comments in `cafaye.yml` that had become false are corrected** — see
   "Two false claims" below.
4. **`TestTheManifestDeclaresEveryEmittedEvent`** compares emitted types against
   declared types as sets, with the difference pinned.

## The contract checker does not go green, and cannot from here

**24 → 23. I removed exactly one finding and introduced none**, verified by
diffing the failure lists against pristine `master` rather than by reading the
count:

```
$ comm -13 <(FAIL lines on pristine master) <(FAIL lines after this change)
                                                    (empty — nothing new)
$ comm -23 <(...) <(...)
FAIL core.constraint-unmet cafaye.yml: core: core publishes 0.2.0 and this
     service declares `core: ^0.1.0`, which 0.2.0 is not in [0.1.0, 0.2.0).
```

The remaining 23 are all outside this packet's authority:

| Rule | Count | Where the fix lives |
| --- | --- | --- |
| `openapi.idempotency-key` | 10 | identity's handlers + `openapi/v1.yaml` — **another packet's surface** |
| `event.payload-schema-missing` | 6 | **core** — `schemas/events/identity/…`, forbidden by the brief |
| `openapi.paths-are-versioned` | 2 | `/healthz`, `/readyz` — the two probes; either version them or have core exempt probes. Which one is a decision I did not make. |
| `openapi.page-envelope` | 2 | the admin audit log's `entries/next` — identity-11's surface |
| `event.unknown-published` | 2 | **core** — `docs/event-naming.md` catalog rows, forbidden by the brief |
| `openapi.errors-are-problems` | 1 | `/readyz` 503 — another packet's surface |

`event.payload-schema-missing` reads `core / "schemas" / "events" / …` and the
catalog is `core/docs/event-naming.md` (`EVENT_CATALOG_RELATIVE`,
`cafaye_contract.py:366`). Both are in the core checkout, and the brief says
*"Do not edit core or other services."* The 8 event findings are therefore not
fixable from this repository by anyone working in this repository.

**I did not silence the 13 `openapi.*` findings, and that was a decision rather
than an oversight.** They are all in `openapi/v1.yaml` and all are fixable in
the document alone — add ten `Idempotency-Key` parameters, version two paths,
rename one page envelope, add one content type. That would have taken the
checker to 8 and looked like progress. It would also have made the document
**lie about the router**: a declared `Idempotency-Key` header that no handler
reads is a promise this service does not keep, and a page envelope renamed in
the document from `entries`/`next` to `data`/`page` breaks every real client
while turning the checker green. The brief's own precedent is the instruction
here — `gate.yml` is off-limits as *"another identity packet's surface"*, and
these are the same kind of thing. A green badge obtained by editing a document
to contradict its implementation is worse than a red one, because it is
indistinguishable from a real fix.

## Two false claims, both in the manifest

A contract manifest that misstates core's rules is the drift this packet exists
to remove, so both are corrected.

**`identity.user.created`.** The comment said core's catalog *"currently
disagrees"*, spelled the event `user.created`, and recorded it as open decision
D1 *"and names the three-segment form as the alternative it is not currently
using."* core 0.2.0 decided D1, froze three segments *"always prefixed, no
exceptions"*, and the catalog row now reads `identity.user.created` — I
confirmed it with the harness's own reader:

```python
event_catalog(core)['identity.user.created']  ->  True
```

The two halves of that disagreement now say the same thing, and the reason they
do is this release's `core: ^0.2.0`. The note is kept because the failure it
describes is still live for the OIDC types below it, where core's catalog has no
row at all.

**The "not yet emitted" list.** It claimed `account.created`, `member.invited`,
`member.removed` and `member.role_changed` were *"not yet emitted … the accounts
and tenancy packet"*. All four are emitted, from `internal/accounts/service.go`.
The list now separates what is genuinely not emitted from what is emitted and
undeclared, and gives the reason for the second.

## The check, and why it is not a second copy of core's rules

core's contract checker owns the grammar, and this file does not restate it.
`event.own-prefix` has read `exposes.events` since core-17; a second
implementation of core's rule inside a service would be a second answer to *"is
this type well formed"*, which is the four-way drift the shared harness exists to
end. So the new tests add no rule core already has.

What they add is the one direction no core rule reaches:

- `TestEveryEmittedEventTypeIsThreeSegmentAndOwnPrefixed` — core's grammar
  applied to the **emitted** side, over all twelve types rather than the five
  `tenancy_test.go` covers.
- `TestTheManifestDeclaresEveryEmittedEvent` — the set comparison, with
  `knownUndeclaredEvents` pinning the current five.

The comparison is over **sets, not counts**, for the reason
`TestEveryServedRouteIsDocumentedOrNamed` gives: one event declared and one
dropped leaves the count alone. The pin **can neither grow nor empty quietly** —
a new undeclared event is red, and a declared event whose pin was left behind is
red, so the list shrinks only by a packet declaring the event. That is
`knownDrift`'s rule from `AGENTS.md`, and `knownDrift` is the precedent for a
list of things a check does not yet hold.

**The five are not declared, deliberately.** Declaring them is blocked on core,
not on this file: `event.payload-schema-missing` reads the schemas out of the
core checkout, and core ships one identity payload schema
(`identity/user/created`) for twelve published types. Declaring them today
trades a silent gap for five loud reds. I do not think that is clearly better,
so the gap is written down, pinned, and reported.

The manifest is read by a small refusing reader rather than a YAML dependency
(`go.mod` has none, and adding one puts a parser and its CVEs in this module for
one list of strings). It **refuses** rather than under-reads, because a reader
that finds nothing agrees with another reader that finds nothing — a reader
returning an empty list would report all twelve events as undeclared, or worse,
report none.

## Red proofs

Every rule is proved red. None of these is a claim that the test *would* fail.

| Proof | How | Result |
| --- | --- | --- |
| A new emitted, undeclared event | temporary 13th constant in `internal/outbox` | red — *"is emitted … and is not in cafaye.yml's exposes.events"* |
| A two-segment type | temporary `EventProofB = "proof.b"` | red on both grammar rules — *"has 2 segments"* and *"does not start with the publishing service's own name"* |
| Declared but not emitted | temporary manifest entry | red — *"is declared in exposes.events and emitted nowhere"* |
| Stale pin | declared `identity.member.removed`, left the pin | red — *"still lists … but it IS declared … now"* |
| Six reader shapes | six malformed documents | red, **with a control** that it accepts the real shape |

All temporary artefacts were reverted and the tree verified clean afterwards.

**Two bugs in the new check were caught this way rather than by reading it,** and
both are worth recording because both would have shipped as a green suite:

1. **A missing `(?m)`.** The constant regex is `(?m)^\s*(Event…)\s*=\s*"…"`.
   Without `(?m)`, `^` matches only the start of the file, the expression finds
   nothing in a file that is nothing but constant definitions, and the check
   reports *"no published event constant matched"*. I had written the failure
   message to be loud about it, which is the only reason I read the failure
   instead of accepting it as a passing observation.
2. **The set comparison tested the wrong side.** It compared the Go constant
   *name* (`EventUserCreated`) against the manifest's *type strings*
   (`identity.user.created`), so all twelve types looked undeclared. The
   duplicated-symbol check in the same function did not catch it either. This is
   the exact bug class the new check exists to prevent, committed inside the new
   check.

## Gates

| Gate | Result |
| --- | --- |
| `bin/prime` | **1812 PASS / 0 FAIL / 0 SKIP** |
| `go vet ./...` | clean |
| `gofmt -l .` | clean (prints nothing) |
| `go test -race ./...` | clean, 0 data races |
| `bin/coverage-floor` | 73.6% over a 70% floor, **unchanged** |
| `cafaye-contract` | 24 → **23**, exit 1 (see above) |

**Pass and skip counts separately, as the brief requires: 1812 pass, 0 fail, 0
skip.** No test was skipped and no skip was added; `TEST_DATABASE_URL` was set
and `goose up` ran above the suite, so the database tier is genuinely exercised
rather than reported as clean. CI's suite floor is 1254.

## Fleet consumers of the renamed type

**None. Nothing in the fleet subscribes to any `identity` event, so nothing
follows this rename.** Checked every manifest in the workspace:

```
$ for d in billing courier guard muse pantry darkroom docs identity; do … done
billing      TWO-SEGMENT: -   IDENTITY-EV: -
courier      TWO-SEGMENT: -   IDENTITY-EV: -
guard        TWO-SEGMENT: -   IDENTITY-EV: -
muse         TWO-SEGMENT: -   IDENTITY-EV: -
pantry       TWO-SEGMENT: -   IDENTITY-EV: -
darkroom     TWO-SEGMENT: -   IDENTITY-EV: -
docs         TWO-SEGMENT: -   IDENTITY-EV: -
```

Every service either declares `consumes: []` (billing, courier, docs, guard,
muse, cafaye-rb) or omits the key entirely (identity, and it says why: *"an
empty list says 'we checked and there are none', which is true today but is a
claim that has to be revisited"*). **No manifest in the workspace names an
`identity.*` event under `consumes`, and none names a two-segment event at all.**
A fleet-wide grep for `account.created` outside this repository finds it only in
**core's** catalog, **core's** examples, **core's** tests and `caf`'s contract
fixtures — all already in the three-segment form. There is no subscription,
route, SDK constant or dashboard filter keyed on the old spelling.
**No other repository needs a follow-up for this rename, and I have not edited
another repository.**

## Left for someone else, named

1. **core: add a catalog row for `identity.oidc_client.created` and
   `identity.oidc_client.revoked`.** Both are published and both are absent from
   `docs/event-naming.md` — 2 × `event.unknown-published`. Core's own rule is
   that a catalog row and a publisher entry are the same fact stated twice, so
   this is core's half of identity's half.
2. **core: add payload schemas for six published identity events.** `oidc_client`
   `created`/`revoked`, `mfa` `enabled`/`disabled`, `api_key` `created`/`revoked`
   — 6 × `event.payload-schema-missing`. Identity cannot declare those events
   until these exist, which is what pins the five-item list above.
3. **A manager ruling on `identity.member.accepted` vs core's
   `identity.member.joined`.** The code emits `accepted`; core's catalog has
   `joined`; `accepted` is not in core's action vocabulary. The divergence is
   *recorded*, not accidental — `internal/outbox/tenancy.go` documents that it
   follows the packet as the manager's decision. Flipping it is one constant and
   one manifest line, and it is a manager's call, not a worker's. **It is the
   only one of the five with no core row at all**, so it is also the one that
   cannot be fixed by adding a schema.
4. **identity: the 13 `openapi.*` findings**, as a packet that implements the
   handlers rather than editing the document. Ten `Idempotency-Key` behaviours
   are real work in `internal/httpapi`, not ten document lines.
5. **core: the `v0.2.0` tag message and `DEBT.md` D22 both carry the false
   `account.created` claim.** core-17 reported this and correctly left it to the
   owner, since amending a published tag is not a worker's to do. A service owner
   reading that release note will go looking for a two-segment event that does
   not exist, and will not find the five undeclared events that do. **This packet
   is the second measurement of the same false claim; the third reader should be
   given the correction.**

## What I could not verify

- Whether the five undeclared events are *intended* to be undeclared. The
  manifest comment said so, but the same comment was false about four of the
  five being emitted at all, so I do not trust it as evidence of intent. What I
  verified is the mechanism, not the decision: declaring them is blocked on core.
- Whether core will accept five payload schemas for identity, or consider the
  absence a reason for identity to stop publishing them. That is core's call and
  I did not edit core.
- `identity.member.accepted` vs `joined` — recorded above as a manager decision.
  I did not flip it, because the recorded reasoning says the packet was the
  manager's decision and silently reversing it would erase that record.
- I ran the contract checker against the core checkout at `58c10b82`, twelve
  commits past the `v0.2.0` tag. The 8 event findings depend on what is in that
  checkout's `schemas/` and `docs/`; I did not check out the tag itself to
  confirm the same 8 fire there.

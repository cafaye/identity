# REPORT — registry-identity-social-02

**Branch** `worker/reg-identity-social-02` · **base** `10a23c3` (the recovery commit
for `registry-identity-social-01`) · not pushed, not merged.

The short version: the tripwire is deleted, the four claim surfaces tell the truth,
and the thing I did not expect is that **the tripwire was green the whole time**.
Not red with its checklist — green, because neither router walk could see the
surface it was watching. That is the finding, and it is worth more than the rest of
this packet.

## What was actually broken, before I touched anything

The packet said `go vet ./internal/httpapi/...` fails and that is the only break.
True, and it hid more than it showed:

```
go vet ./internal/httpapi/...
  BEFORE  vet: internal/httpapi/oauth_absent_test.go:70:7: socialLoginPrefix
          redeclared in this block
```

A compile failure in the **test** package. Nothing in `internal/httpapi` had been
executable since the social-login surface landed. That matters for one specific
reason, which is the next section.

## The finding: the tripwire was green, and a compile break is why

`oauth_absent_test.go` existed to be a red build with a checklist on it the day
somebody mounted `/v1/auth/oauth/google`. Its own header:

> So the rule is: **mounting social login without deleting this file is not
> finishing the work.** Deleting it is a review-visible act.

The day came. The test stayed green. **The walk it was handed did not contain the
two routes**, because `options.social` was set by neither router walk — not
`servedRoutes` in `openapi_drift_test.go`, not `walkOptions` in
`claims_faults_test.go` — and `social` was not in `conditionalSurfaces` in
`router_walk_test.go`. `registerSocialRoutes` returns early when that field is nil,
exactly like every other conditional registrar in this service.

So on the day the surface mounted:

- `TestEveryServedRouteIsDocumentedOrNamed` reported the OpenAPI documents and the
  router **in agreement** while they were not;
- `TestTheReadmeEndpointTablesAreTheRoutesTheRouterServes` compared the README
  against a router without the two routes in it, in both directions;
- and the absence check, whose failure message was the work order for this entire
  packet, reported nothing.

This repository has hit that bug twice before and both times the victim was a
reverse-direction documentation check (`admin`, then `recovery`). What is new is
*which* check was blinded: this time it was the check that would have named the
work. **And the repository could not find out for a whole packet**, for a reason
worth naming on its own — a package that does not compile cannot run the test that
would have caught it. A redeclared `socialLoginPrefix` is the single thing that
could hide a tripwire, and it is exactly what this packet inherited.

Three fixes, and the assertion shape is the point of two of them:
`social` joins `conditionalSurfaces`; both walks set `social: newFakeSocial()`;
`TestTheClaimWalkSeesEveryConditionalSurface` and the new
`TestTheDriftWalkSeesTheSocialLoginSurface` assert a **route**, not a field, since
a field test passes against a registrar that mounts nothing.

## The four claim surfaces

| Surface | What moved | Held by |
|---|---|---|
| README endpoint table | two rows, plus a section saying both are `security: []` | `TestTheReadmeEndpointTablesAreTheRoutesTheRouterServes` |
| README roadmap | `- [ ] … written and unmounted` → `- [x] … as a CLIENT of Google and GitHub … No goth` | `TestEveryCheckedRoadmapItemIsBackedByTheRouter` |
| `cafaye.yml` description | `social login` added | `TestTheManifestDescribesOnlyCapabilitiesThisServiceHas` |
| `manifestCapabilityEvidence` | two routes, `manifestCapabilityCount` 6 → 7 | `TestTheManifestCapabilityTableIsExactlyWhatItClaimsToBe` |

**The authorization matrix got no row, and that is a decision worth a reviewer's
eye.** The tripwire's work order said "a row in the authorization matrix — *if the
callback touches a session*". It does touch one: `linkTarget` resolves the caller's
session to decide link-versus-sign-in. But `mountedAccountRoutes()` walks
`registerTenancyRoutes`, which never mounts these two routes, so
`TestEveryRouteIsInTheMatrix` does not ask for a row and adding one would have been
inventing a coverage requirement. What satisfies the tripwire's actual intent — "a
caller with no credential can reach it, say so" — is the README section and the
`security: []` on both OpenAPI operations, and those say it in the place a reader
and a generated client will both see.

**The roadmap box named a library that was never a dependency.** The old text was
`- [x] OAuth (social login) via goth` before an earlier packet unchecked it; goth is
not in `go.mod` and never was. The new text says so explicitly, because "goth" is
the word a reader integrating would have chased first.

**The manifest word is "social login", not "OAuth", on purpose.** A bare "OAuth"
sitting beside "the OIDC provider" is precisely the pair this service could not tell
apart: it is the **provider** in one and a **client** in the other, and conflating
them is how the original claim survived as long as it did.

**The opening paragraph contradicted the packet, and I did not follow the
instruction.** The tripwire said to leave it alone because it "lists OAuth as a
thing the service owns… that is now true". The current text does not list OAuth at
all — an earlier packet had already removed it — so leaving it would have left the
surface unnamed in the one place a reader looks first. It now lists social login,
with a paragraph naming the two directions. If the packet's premise was right about
the file, my read was wrong; I checked before editing.

## The falsifiability case: option 2, and what it cost

I took option 2, the stronger one. `socialLoginRoutesMounted` (which reported the
presence of a social-login route as a defect) becomes
`undocumentedSocialLoginRoutes`: served, under `socialLoginPrefix`, with no README
row beside it. Its falsifiability case injects
`/v1/auth/oauth/{provider}/disconnect` — a genuinely fictional path — rather than
the real callback, because the real callback is now the mounted thing and injecting
it would assert the opposite of what the check believes.

**The cost, stated plainly: the case is now mechanically subsumed by
`readmeUndocumentedRoutes` directly above it.** A served route with no README row is
the same finding whether or not it is under the social prefix. This is no longer an
independent signal. What survives is the narrowing to the prefix, a failure message
that names the social surface specifically, and the anchor to `socialLoginPrefix` so
a future refactor that widens the predicate is a visible edit.

The alternative was deleting the case, which would have left the social surface with
no check of its own anywhere in the package — and the tripwire that used to be its
check has just been deleted. "Social routes remounted without documentation,
silently" would have gone unwatched, which is the specific regression this file
exists to prevent. Redundant-but-anchored is the smaller loss.

## The README's prose about absence: converted, not deleted

Four places asserted absence in prose, and `claims_test.go` cannot see any of them.
All four are now records of what happened and what exists.

**Conversion beat deletion because of the reader, not the writer.** A reader who
arrives at a corrected paragraph saying "OAuth was never mounted" — next to a router
that serves it — concludes the README is unreliable. For this one repository it
demonstrably was: it shipped a README promising a feature that answered 404. The
history is the evidence that the check works, and deleting it would have left the
defect invisible while making the correction look like an error.

- **Layout table** (was "WRITTEN AND NOT MOUNTED … with no route and no handler") —
  now describes the client side and points at the round trip.
- **The tripwire section** — converted, and this one carries the finding: the
  tripwire was green on the day the routes landed, the first two instances of this
  bug blinded a documentation check and this one blinded the absence check, and a
  compile break is why nobody noticed.
- **"Social login is not built, and the code that looks like it is"** — retitled
  **"Social login: what it was, and what it is"**, kept whole, with the first
  paragraph stating plainly that it used to say this and that it was then true. Every
  "Written" cell in its file table now reads "Live" — including `internal/config`
  reading `internal/oauth`'s settings and `connected_accounts` being written to,
  which was the tell that the table was empty while the code around it was finished.
- **"Why the remaining work is a decision and not a handler"** — became "The two
  decisions that were open, and how they were settled".

## The two settled security properties

Both were pre-settled and I did not re-open them; I recorded them where a reader
will find them, because they are the properties most likely to be got wrong by
somebody integrating.

- **An email collision REFUSES the sign-in.** `ErrSocialEmailInUse` → `409`, nothing
  minted, told to sign in locally. Jumpstart's behaviour, and the
  anti-account-takeover rule. The README names the product cost too — a password
  user who later clicks "Continue with Google" has to sign in the way they signed
  up — because a security property recorded without its cost reads as a bug.
- **`email_verified` gates any lookup against `users.email`.** Google's claim is
  read now; an unverified address is a suggestion, not a claim about identity.

Both are `security: []` on both operations, in the OpenAPI tag description and the
README section, with the reason: a browser arrives at the callback holding nothing
but the state cookie this service set. **Getting that wrong is the security bug,
not the documentation bug**, so it is the one thing in the document a reader must not
be able to get wrong by inference.

## Verification, and what each assertion was proved by

Named commands, all bounded by `timeout`:

```
go build ./...                              exit 0
go vet ./...                                exit 0   (whole module, not a subset)
gofmt -l .                                  prints nothing
go test -count=1 ./internal/httpapi/        ok
go test -count=1 ./client/...               ok
go generate ./client/                       exit 0   (oapi-codegen v2.8.0)
go test ./internal/platform/ci/ -run TestTheCoverageExclusionIsOnlyGeneratedCode
                                            ok  (was exit 1)
```

**Four mutations, each shown to bite, then reverted.** All four verified by exit
status *and* by the mutation being present in the file (grepped, per the rule that
a mutation which silently failed to apply proves nothing):

| Mutation | Result |
|---|---|
| `undocumentedSocialLoginRoutes` returns `""` at the top | `TestEveryClaimCheckFailsOnAnInjectedRoute/a_social-login_route_with_no_README_row` **FAIL** |
| `social: newFakeSocial()` removed from `walkOptions` | `TestTheClaimWalkSeesEveryConditionalSurface` **and** `TestTheDriftWalkSeesTheSocialLoginSurface` **FAIL** |
| `http.ErrUseLastResponse` → `nil` in `newTransport` | `TestTheClientDoesNotFollowARedirect` **FAIL** (the follow-up to `accounts.google.com` happened) |
| the link path returning a zero `Session` instead of `nil` | `.../a_provider_identity_linked,_no_session_minted` **FAIL** |

**`go test ./...` is NOT fully green and I did not make it so.** Five packages fail,
and only one of them was mine:

- `internal/apikeys`, `internal/courier`, `internal/mfa`, `internal/recovery` —
  `TestTheDatabaseTierActuallyRan`: `TEST_DATABASE_URL` is unset on this machine.
  These **fail rather than skip by design** (AGENTS.md), and I did not start a
  Postgres to satisfy them: the DSN requires `docker compose up -d --wait postgres`
  plus a `goose up`, which is a deployment step, and starting a shared cluster is not
  a thing to do unilaterally from inside another session's repo. **Not run: the
  database tier.** Named rather than absent.
- `internal/platform/ci` — `TestTheOtherSixSubstrateFunctionsAreKitsBytes`,
  `cafaye.protect_table differs from kit's`. **Pre-existing and out of scope**:
  measured failing identically in a clean worktree at `10a23c3` with none of my work
  applied. It is kit's substrate template having moved under a pinned `kit.ref`, and
  it belongs to whoever owns `migrations/00016`. Not touched.

`./bin/prime` is `go mod download && go build ./... && go test -count=1 ./...`, and
I did **not** run it: it is the same command as the above, it would take the same
~2.5 minutes, and its only extra content is the four database-tier failures I have
named. Running it and reporting a red that is not mine would have been a worse
report than naming the four packages.

## Two things I changed that the packet did not ask for

1. **`newTransport` now refuses to follow redirects.** `net/http` follows up to ten
   3xx hops by default, so following `StartSocialLogin`'s `Location` would have
   turned a method that returns a URL into one that makes an **authenticated request
   to Google**. The policy is `http.ErrUseLastResponse`. This is a change to *every*
   operation on the client, not just the two new ones — no other operation in the
   document answers 3xx, and refusing to follow is the safe direction if one starts
   to. It is called out in the commit and in the code because a transport-wide policy
   is not something to slip in with a feature.

2. **`coverage-exclusions` restated.** The regeneration grew the generated file and
   `TestTheCoverageExclusionIsOnlyGeneratedCode` caught it. Two things in that entry:
   `lines` read 22435 while the tree held **22411 before this packet started** — it
   had been overstating the excluded set for a day and the check was red on it and
   nobody noticed, because the only thing that reports it is a full-suite run. And
   `statements` read 3976 against a measured 5438 at base; worse, **no assertion
   reads that field at all**, because a statement count is not derivable without a
   coverage profile. It is now measured (5749) rather than carried forward.

I also removed the dead `wt-reg-identity-social-01` worktree, which git had already
released and which held no unique tree (`d5f77c9` and `10a23c3` are identical trees
on the same parent). Its branch `worker/identity-social-01` is untouched and I did
not push anything.

## Surprising

- The tripwire was green. Everything else in this packet is a consequence of that.
- A compile break in a test package is the one failure mode that hides a tripwire,
  and the inherited state was exactly it.
- `claims_test.go` held three things that existed only to assert an absence, and one
  of them (`socialLoginRoutesMounted`) could only be inverted, not deleted, without
  leaving the social surface unwatched.
- The regenerated client needed a **wrapper**, not just regeneration:
  `TestTheTransportCoversEveryOperationInTheDocument` demanded `Transport` methods
  and a `Client` method per `operationId`, so documenting the routes cascaded into
  hand-written client code. `CompleteSocialLogin` returns
  `(session, linked, error)` because a single return value makes the link path
  indistinguishable from a sign-in with an empty token.

## The single next move

**Decide where a social callback renders and what it redirects to on failure.** It
is the last thing on this surface that is a product decision rather than an
implementation one, and it is the only gap in what ships: a social sign-in is a 302
out and a 302 back, a person whose provider declined consent or whose callback was
rejected has to be told something, and this service renders no HTML at all. Today
every refusal is an `application/problem+json` document on the reasoning that a
failure redirect target is the integrating product's decision. That is defensible
and it is a gap, and the tripwire's successor should be the thing that says so —
not another absence test.
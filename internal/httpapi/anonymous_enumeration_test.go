package httpapi

// THE ENUMERATION AUDIT: EVERY ROUTE A STRANGER CAN REACH.
//
// ## What this file is for
//
// identity-27 found one account-enumeration oracle — a 409 on
// `POST /v1/email-verifications` that told an anonymous caller which addresses
// belong to VERIFIED accounts — and removed it. A single finding is a symptom, not
// a census: the same mistake is one branch away on any route that takes an address
// or an identifier from a caller who has proved nothing, and it is invisible in
// review because the branch always reads like a feature.
//
// So this file walks the whole unauthenticated family and answers ONE question per
// route, in a test rather than in a comment:
//
//	can the response distinguish "this account exists" from "it does not"?
//
// ## WHY IT IS A TABLE PLUS A WALK, AND NOT A LIST
//
// `TestEveryRouteThatAnswersAnAnonymousCallerIsInThisAudit` reads the ROUTER and
// requires the table to BE the family, in both directions: every mounted route under
// these prefixes has a row, and every row is a mounted route. A restated list would
// be one more thing to forget and its failure would be silent — a new route lands,
// nobody audits it, the suite is green. That is the same shape as
// `TestEveryRecoveryRouteIsInTheMatrix` on the authorization axis, and the reason
// that one walks chi rather than trusting a slice of strings.
//
// **THE 401 ROUTES ARE ROWS TOO**, and the first version of this test exempted them
// by probing each one and skipping whatever answered 401. The exemption was taken out
// after its own red proof showed what it was doing: an unlisted route has no probe
// body either, because the body lives IN the table, so the probe went out as `{}`,
// `decodeBody` refused it with a 400, and a session-gated route was reported as
// answering a stranger. A check whose probe cannot reach the code under test is
// measuring the probe.
//
// ## THE TWO ROWS THAT ANSWER YES
//
// They say so rather than being quietly reclassified, because an audit that cannot
// say "yes, here, and here is why it stands" is not an audit:
//
//   - `POST /v1/users` publishes "that address is taken". It has to: one account per
//     address is the unique index on `users.email`, and a caller registering has to
//     be told rather than left watching a request time out.
//     `TestRegistrationPublishesOnlyThatAnAddressIsTaken` holds the disclosure to
//     exactly one bit.
//   - `POST /v1/session` publishes "that account is locked", through a 423 the
//     stranger can reach with a wrong password.
//     `TestALockedAccountIsToldApartOnlyFromThePassword` holds it, measures how far
//     it reaches, and says why it is the smaller of the two.
//
// The question of whether the first one should be answered differently is a product
// decision about registration, and it is recorded as DECISIONS.md D9 rather than
// settled here.
//
// ## THE ROW THAT MUST NOT BE "FIXED"
//
// `POST /v1/introspections` is an oracle BY DESIGN — resolving a presented token to
// its claims is the entire purpose of a token introspection endpoint, and RFC 7662
// is its specification. Its protection is the CREDENTIAL the caller must present,
// not the shape of the answer.
// `TestIntrospectionIsAnOracleByDesignAndGatedOnACredential` says so where the next
// reader will find it.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/go-chi/chi/v5"

	"github.com/cafaye/identity/internal/apikeys"
	"github.com/cafaye/identity/internal/outbox"
	"github.com/cafaye/identity/internal/platform/clock"
	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/dbtest"
	"github.com/cafaye/identity/internal/platform/id"
	"github.com/cafaye/identity/internal/recovery"
	"github.com/cafaye/identity/internal/sessions"
	"github.com/cafaye/identity/internal/users"
)

// auditRoute is one row: a route a stranger can reach, the identifier it accepts,
// and what its answer discloses.
type auditRoute struct {
	name    string
	method  string
	pattern string

	// identifier is what the body carries that could name an account or a
	// credential. "nothing" is a legitimate value and a row worth having: a route
	// with no identifier cannot enumerate, and recording that is the answer.
	identifier string

	// probe is the anonymous request the coverage walk sends. It has to be a body
	// the route will accept, because a 400 from a malformed probe would make a route
	// look session-gated and drop it out of the audit.
	probe string

	// anonymous is the status that probe gets. 401 means the route demands a
	// credential, so no identifier ever reaches it from a stranger — which is what
	// exempts a route from needing a row of its own.
	anonymous int

	// discloses is the audit's answer, in a sentence a reader can check.
	discloses string
}

// auditFamilyPrefixes are the paths this file claims. A mounted route under one of
// them that answers an anonymous caller has to be in the table below.
//
// `/v1/email-verification` IS A PREFIX here and not an exact match, because it
// covers both the singular status route and the plural request routes — which is
// what this file wants, since every one of them is in the audit.
var auditFamilyPrefixes = []string{
	"/v1/users",
	"/v1/me",
	"/v1/session",
	"/v1/password-resets",
	"/v1/email-verification",
	"/v1/email-changes",
	"/v1/introspections",
}

// anonymousFamilyAudit is the table, one row per route.
//
// THE ORDER IS THE PACKET'S: auth first, then recovery, then the one route that is
// an oracle on purpose. It reads as a walk through the surface rather than as
// alphabet.
func anonymousFamilyAudit() []auditRoute {
	return []auditRoute{
		{
			name: "register", method: http.MethodPost, pattern: "/v1/users",
			identifier: "email",
			probe:      `{"email":"nobody@example.com","password":"` + validPassword + `"}`,
			anonymous:  http.StatusCreated,
			discloses: "THAT the address is taken, and nothing else about the account holding it. " +
				"One bit, and it is the one disclosure on this service that cannot be removed: " +
				"one account per address is the unique index, and a caller registering has to be " +
				"told. Pinned by TestRegistrationPublishesOnlyThatAnAddressIsTaken",
		},
		{
			name: "sign in", method: http.MethodPost, pattern: "/v1/session",
			identifier: "email, password",
			probe:      `{"email":"nobody@example.com","password":"not the right password"}`,
			anonymous:  http.StatusUnauthorized,
			discloses: "that the account is LOCKED (423), to a stranger who has caused the lockout " +
				"themselves. Six unauthenticated requests per candidate address. Held, measured " +
				"and not fixed by TestALockedAccountIsToldApartOnlyFromThePassword",
		},
		{
			name: "read the session", method: http.MethodGet, pattern: "/v1/me",
			anonymous: http.StatusUnauthorized,
			discloses: "nothing: 401 without a credential, so no identifier arrives from a stranger",
		},
		{
			name: "sign out", method: http.MethodDelete, pattern: "/v1/session",
			anonymous: http.StatusUnauthorized,
			discloses: "nothing: 401 without a credential. The session token IS the identifier, and " +
				"it is a credential rather than a name",
		},
		{
			name: "answer the second factor", method: http.MethodPost, pattern: "/v1/session/mfa",
			identifier: "challenge, code",
			probe:      `{"challenge":"a-challenge-that-is-not-one","code":"000000"}`,
			anonymous:  http.StatusNotFound,
			discloses: "nothing about any ACCOUNT. The body carries no address, and the challenge it " +
				"carries is itself the credential: 43 characters of entropy, not an identifier " +
				"there is a space to guess",
		},
		{
			name: "ask for a reset link", method: http.MethodPost, pattern: "/v1/password-resets",
			identifier: "email", probe: `{"email":"nobody@example.com"}`,
			anonymous: http.StatusAccepted,
			discloses: "nothing: 202 with a constant body for a registered address, an unregistered " +
				"one, a proved one and one inside the cooldown",
		},
		{
			name: "spend a reset link", method: http.MethodPost, pattern: "/v1/password-resets/confirm",
			identifier: "token, password",
			probe:      `{"token":"a-token-that-is-not-one","password":"` + validPassword + `"}`,
			anonymous:  http.StatusNotFound,
			discloses: "nothing: one 404 for a token that never existed, expired, was spent or " +
				"belongs to another flow",
		},
		{
			name: "ask for a confirmation link", method: http.MethodPost, pattern: "/v1/email-verifications",
			identifier: "email", probe: `{"email":"nobody@example.com"}`,
			anonymous: http.StatusAccepted,
			// THIS IS THE ROW IDENTITY-27 CHANGED. Two commits ago it read "whether the
			// address belongs to a VERIFIED account", and the 409 that answered it is
			// what an anonymous caller posted a list of addresses to collect.
			discloses: "nothing: 202 with a constant body for every address, INCLUDING one whose " +
				"account has already proved it",
		},
		{
			name: "spend a confirmation link", method: http.MethodPost, pattern: "/v1/email-verifications/confirm",
			identifier: "token", probe: `{"token":"a-token-that-is-not-one"}`,
			anonymous: http.StatusNotFound,
			discloses: "nothing: one 404, including for a token of the wrong LENGTH — which is the " +
				"spec/live disagreement TestATruncatedTokenAnswers404Not422 settles",
		},
		{
			name: "read the confirmation state", method: http.MethodGet, pattern: "/v1/email-verification",
			anonymous: http.StatusUnauthorized,
			discloses: "the caller's OWN verification state, and only behind a session. This is the " +
				"route a client that needs to say \"already verified\" must ask instead of the 409",
		},
		{
			name: "start an email change", method: http.MethodPost, pattern: "/v1/email-changes",
			identifier: "email", probe: `{"email":"new-address@example.com"}`,
			anonymous: http.StatusUnauthorized,
			discloses: "whether the NEW address is taken — to a signed-in caller who typed it, which " +
				"is the same disclosure POST /v1/users makes and the one place in this service it is safe",
		},
		{
			name: "confirm the current address", method: http.MethodPost, pattern: "/v1/email-changes/current-address",
			identifier: "token", probe: `{"token":"a-token-that-is-not-one"}`,
			anonymous: http.StatusNotFound,
			discloses: "nothing: one 404, including for the SECOND token presented here and for a " +
				"first token presented to the other half",
		},
		{
			name: "confirm the new address", method: http.MethodPost, pattern: "/v1/email-changes/new-address",
			identifier: "token", probe: `{"token":"a-token-that-is-not-one"}`,
			anonymous: http.StatusNotFound,
			discloses: "nothing about any account. A 409 IS reachable here, and only by a caller " +
				"holding a token that cannot exist before two inbox proofs",
		},
		{
			name: "introspect a token", method: http.MethodPost, pattern: "/v1/introspections",
			identifier: "token",
			probe:      `{"token":"` + scopedTokenForTheMatrix + `"}`,
			anonymous:  http.StatusUnauthorized,
			discloses: "EVERYTHING about a token, and that is what the endpoint is for. Its protection " +
				"is the credential the caller must present, not the shape of the answer. See " +
				"TestIntrospectionIsAnOracleByDesignAndGatedOnACredential before changing this row",
		},
	}
}

// TestEveryRouteThatAnswersAnAnonymousCallerIsInThisAudit is the census.
//
// IT WALKS THE ROUTER and requires the table to BE the family, in both directions.
// **Every mounted route under these prefixes has a row, and every row is a mounted
// route** — no exemptions, and the earlier version of this test tried to exempt the
// 401 routes and had to be taken out again.
//
// WHY THE EXEMPTION WAS A BAD IDEA, and it is worth recording because the red proof
// found it. The first version asked "does this unlisted route answer 401 to an
// anonymous probe?" and skipped it if so, on the reasoning that a 401 proves no
// identifier arrives. But an unlisted route has no probe body either, because the
// body lives IN the table — so the probe went out as `{}`, `decodeBody` refused it
// with a 400, and the test reported a route as "answering a stranger" when it was in
// fact session-gated. A check whose probe cannot reach the code under test is
// measuring the probe. Dropping the exemption makes the rule structural instead: the
// table is the census, and a route cannot be in the walk without being in it.
//
// THE STATUS each row claims is still MEASURED, over the row's own body — so a row
// that has quietly stopped describing the route is red rather than inherited.
func TestEveryRouteThatAnswersAnAnonymousCallerIsInThisAudit(t *testing.T) {
	audited := map[string]bool{}
	for _, row := range anonymousFamilyAudit() {
		key := normalizeRoute(row.method, row.pattern)
		if audited[key] {
			t.Errorf("%s has two rows in the enumeration audit, so a reader cannot tell which "+
				"answer is the audited one", key)
		}
		audited[key] = true
	}

	mounted := mountedFamilyRoutes()
	if len(mounted) == 0 {
		t.Fatal("the walk found no route in this family, so every assertion below would pass " +
			"vacuously. A walk that sees nothing agrees with a walk that sees nothing")
	}
	t.Logf("the family holds %d mounted routes and the audit has %d rows", len(mounted), len(audited))

	// Direction one: a mounted route with no row. No probe, no exemption — the row is
	// what carries the body a probe would need, so asking here would be asking a
	// question the data to answer it is not present for.
	for _, key := range mounted {
		if !audited[key] {
			t.Errorf("%s is mounted under this family's prefixes and has no row in the "+
				"enumeration audit. Add one, and answer the question: can the response tell "+
				"\"this account exists\" from \"it does not\"?", key)
		}
	}

	// Direction two: a row about a route that is not mounted. A stale row is a claim
	// about a route that nothing checks any more.
	for key := range audited {
		if !contains(mounted, key) {
			t.Errorf("the enumeration audit has a row for %s, which is not mounted under this "+
				"family's prefixes. A row about a route that is gone is a claim nothing checks; "+
				"delete it or mount the route", key)
		}
	}
}

// TestEveryAuditedRouteStillAnswersWhatItsRowSays is the half of the census that
// needs a server: each row's claimed status, measured over the row's own body.
//
// IT IS A SEPARATE TEST from the walk above so that the walk stays a pure comparison
// of two sets and does not need a database — which is what lets the red proof for the
// walk run without one, and what would let somebody delete the walk's database
// requirement and not notice.
func TestEveryAuditedRouteStillAnswersWhatItsRowSays(t *testing.T) {
	f := newAuditFixture(t)

	for _, row := range anonymousFamilyAudit() {
		if strings.TrimSpace(row.discloses) == "" {
			t.Errorf("the %s row records no answer. A row that does not say what the route "+
				"discloses is a route that has been walked past", row.name)
		}
		rec := anonymousProbe(t, f, row.method, row.pattern)
		if rec.Code != row.anonymous {
			t.Errorf("%s %s answered %d to the audit's own anonymous probe, want %d.\n"+
				"The row describes what this route discloses to a stranger, and a route that "+
				"has changed its answer without its row changing is the drift this catches.\n"+
				"body: %s", row.method, row.pattern, rec.Code, row.anonymous, rec.Body)
		}
	}
}

// --- per-route tests --------------------------------------------------------

// TestRegistrationPublishesOnlyThatAnAddressIsTaken is the YES on this surface,
// held to one bit.
//
// IT IS NOT AN OVERSIGHT. `users.email` carries a unique index — one account per
// address is a database fact — so a registration cannot complete for a taken address,
// and a caller has to be told rather than left watching a request time out. Whether
// registration should be asynchronous instead is a product decision this service does
// not get to make on its own; it is recorded as DECISIONS.md D9.
//
// WHAT IS HELD HERE IS THE REST OF THE DISCLOSURE. The 409 must be one fixed
// sentence, identical for two different accounts, naming nothing about either of
// them: no id, no account, no created-at, and nothing at all about whether the
// account holding the address has proved it. A 409 that varies with the account
// behind it turns one bit into an inventory, and the two accounts in this test
// differ in exactly that — one has proved its address and one has not.
func TestRegistrationPublishesOnlyThatAnAddressIsTaken(t *testing.T) {
	f := newAuditFixture(t)

	proved, _ := f.signUp(t)
	f.verifyAddress(t, proved)
	unproved, _ := f.signUp(t)
	free := dbtest.UniqueEmail(t)

	created := post(t, f.handler, "/v1/users", `{"email":"`+free+`","password":"`+validPassword+`"}`)
	if created.Code != http.StatusCreated {
		t.Fatalf("registering an unused address = %d, want 201; body: %s", created.Code, created.Body)
	}

	takenProved := post(t, f.handler, "/v1/users", `{"email":"`+proved+`","password":"`+validPassword+`"}`)
	takenUnproved := post(t, f.handler, "/v1/users", `{"email":"`+unproved+`","password":"`+validPassword+`"}`)
	for label, rec := range map[string]*httptest.ResponseRecorder{
		"a proved account":    takenProved,
		"an unproved account": takenUnproved,
	} {
		if rec.Code != http.StatusConflict {
			t.Fatalf("registering an address held by %s = %d, want 409; body: %s",
				label, rec.Code, rec.Body)
		}
		if got := decodeProblem(t, rec).Code; got != CodeConflict {
			t.Errorf("registering an address held by %s: code = %q, want %q", label, got, CodeConflict)
		}
	}

	// ONE SENTENCE FOR EVERY ACCOUNT. The two rows differ in their verification
	// state, and the refusal must not know that.
	a := decodeProblem(t, takenProved)
	b := decodeProblem(t, takenUnproved)
	a.TraceID, b.TraceID = "", ""
	if renderedA, renderedB := renderProblem(t, a), renderProblem(t, b); renderedA != renderedB {
		t.Errorf("the 409 differs between an account that has proved its address and one that has not:\n"+
			"  proved:   %s\n  unproved: %s", renderedA, renderedB)
	}

	// AND NOTHING ELSE REACHES THE BODY, checked as a WHOLE DOCUMENT rather than by
	// searching the bytes for a suspicious word. A grep would be the wrong tool twice
	// over: it cannot see a field this service adds later, and on the envelope's own
	// fixed text it fires on `trace_id`, on `instance: /v1/users` and on the word
	// "account" in the sentence that has to be there. A literal is the only version of
	// this assertion that means "these seven fields and no others", which is core's
	// own rule for the error body.
	//
	// A problem document is seven fields. If a future change adds an eighth — an id, a
	// name, a `verified` boolean — this fails and names it.
	want := Problem{
		Type:     "https://errors.cafaye.com/conflict",
		Title:    "Conflict",
		Status:   http.StatusConflict,
		Detail:   "an account already exists for that email address",
		Instance: "/v1/users",
		Code:     CodeConflict,
	}
	// A struct comparison rather than `==`, because `Problem` carries a slice and is
	// therefore not comparable with `==` at all. Comparing the RENDERED documents is
	// the better check anyway: it is the bytes on the wire, and it catches a field the
	// struct does not have a slot for — which is precisely the failure being guarded
	// against.
	if got, expected := renderProblem(t, a), renderProblem(t, want); got != expected {
		t.Errorf("the 409 is not the envelope and one fixed sentence.\n  got:  %s\n  want: %s\n"+
			"Anything beyond these seven fields is a fact about the account that already holds "+
			"the address, and this route is allowed to publish exactly one bit", got, expected)
	}

	// The 422 for a MALFORMED address is the other half of this route's answer, and it
	// must not echo the address back: two requests differing only in which addresses
	// exist would then differ.
	malformed := post(t, f.handler, "/v1/users",
		`{"email":"not-an-address","password":"`+validPassword+`"}`)
	if malformed.Code != http.StatusUnprocessableEntity {
		t.Fatalf("a malformed address = %d, want 422; body: %s", malformed.Code, malformed.Body)
	}
	if strings.Contains(malformed.Body.String(), proved) || strings.Contains(malformed.Body.String(), unproved) {
		t.Errorf("the 422 echoes a submitted address:\n%s", malformed.Body)
	}
}

// TestALockedAccountIsToldApartOnlyFromThePassword is the second YES, and it is
// recorded rather than fixed.
//
// THE LEAK. `POST /v1/session` answers **423** when an account is locked, and the
// lock is checked BEFORE the password — `internal/auth`'s step 3, and
// `TestLoginChecksTheLockBeforeThePassword` holds the order. So a stranger who posts
// a wrong password five times at a guessed address and once more reads 423, where an
// address with no row would have answered 401. Six unauthenticated requests per
// candidate, and the only side effect is a lockout the attacker caused themselves.
//
// WHY IT STANDS. **The same fact is already published by one request on a different
// route**: `POST /v1/users` answers 409 for any taken address, with no side effect at
// all, so "is there an account for this address" is not a secret this service keeps.
// The 423 adds "…and it is locked right now", and the attacker had to lock it.
// Removing it would cost a user who mistyped five times a "wrong password" instead of
// "try again in fifteen minutes", and a rewrite of an order this repository argues
// for on brute-force grounds. **What would change it is a decision about
// registration, not about login**, and it is recorded as DECISIONS.md D9.
//
// THE TWO THINGS ASSERTED: that the leak is the ONLY status a stranger can reach on
// this route, and that the right password still gets the honest 423 — which is the
// reason it is worth keeping at all.
func TestALockedAccountIsToldApartOnlyFromThePassword(t *testing.T) {
	f := newAuditFixture(t)

	known, _ := f.signUp(t)
	unknown := dbtest.UniqueEmail(t)
	sessionsBefore := f.sessionsFor(t, known)

	// The first five failures are the 401 the unknown address gets, which is what
	// makes the sixth the interesting one.
	for attempt := 1; attempt <= sessions.MaxFailedAttempts; attempt++ {
		rec := post(t, f.handler, "/v1/session", `{"email":"`+known+`","password":"wrong"}`)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d against a registered address = %d, want 401; body: %s",
				attempt, rec.Code, rec.Body)
		}
	}

	locked := post(t, f.handler, "/v1/session", `{"email":"`+known+`","password":"wrong"}`)
	if locked.Code != http.StatusLocked {
		t.Fatalf("a wrong password against a locked account = %d, want 423; body: %s",
			locked.Code, locked.Body)
	}
	if got := locked.Header().Get(RetryAfterHeader); got == "" {
		t.Error("the 423 carries no Retry-After, so its \"retry after\" sentence names nothing")
	}

	// THE LEAK, STATED AS AN ASSERTION rather than left to whoever reads the comment:
	// this is the one status a stranger can reach on this route.
	againstUnknown := post(t, f.handler, "/v1/session", `{"email":"`+unknown+`","password":"wrong"}`)
	if againstUnknown.Code != http.StatusUnauthorized {
		t.Errorf("a wrong password against an address with no account = %d, want 401. The same "+
			"request against a LOCKED account answers %d, and that difference is the leak this "+
			"test exists to name", againstUnknown.Code, locked.Code)
	}

	// The only other status a stranger can reach, and it needs the password: a 202 for
	// an account with a second factor. Reaching it requires a correct password, so it
	// discloses nothing to somebody who has not got one — which is why the 202 is not
	// in the leak above and the 423 is.
	for _, rec := range []*httptest.ResponseRecorder{
		post(t, f.handler, "/v1/session", `{"email":"`+known+`","password":"`+validPassword+`"}`),
		post(t, f.handler, "/v1/session", `{"email":"`+unknown+`","password":"`+validPassword+`"}`),
	} {
		if rec.Code != http.StatusLocked && rec.Code != http.StatusUnauthorized {
			t.Errorf("a sign-in attempt answered %d; on this route a stranger can reach a 423 "+
				"(locked) and a 401 (everything else), and this is a third: %s", rec.Code, rec.Body)
		}
	}

	// And the honest answer survives: the account's owner, with the right password, is
	// told to wait rather than left guessing.
	withPassword := post(t, f.handler, "/v1/session",
		`{"email":"`+known+`","password":"`+validPassword+`"}`)
	if withPassword.Code != http.StatusLocked {
		t.Errorf("the correct password against a locked account = %d, want 423; body: %s",
			withPassword.Code, withPassword.Body)
	}
	if got := f.sessionsFor(t, known); got != sessionsBefore {
		t.Errorf("%d sessions exist during the lockout window, want the %d that existed before "+
			"it: a refused login mints nothing", got, sessionsBefore)
	}
}

// TestTheRequestRoutesCarryNoIdentifierToEnumerate is the negative half of the two
// recovery rows, stated once and against the body rather than the status.
//
// Both routes take an `email`, so the question "what does that email's row say?" is
// live on both. This asserts the property that makes them safe — the body is a
// constant with exactly one field — by decoding it, because a body that grows a
// field is how the oracle comes back and a test that compared only statuses would not
// see it.
func TestTheRequestRoutesCarryNoIdentifierToEnumerate(t *testing.T) {
	f := newAuditFixture(t)

	address := dbtest.UniqueEmail(t)
	for _, path := range []string{"/v1/password-resets", "/v1/email-verifications"} {
		rec := post(t, f.handler, path, `{"email":"`+address+`"}`)
		if rec.Code != http.StatusAccepted {
			t.Fatalf("POST %s = %d, want 202; body: %s", path, rec.Code, rec.Body)
		}
		var raw map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
			t.Fatalf("the body of %s is not JSON: %v", path, err)
		}
		if len(raw) != 1 || raw["status"] != "accepted" {
			t.Errorf("POST %s answered with %v. This body IS the account-enumeration defence on "+
				"the route: one field, one value, whatever the row says. A second field is an "+
				"oracle and no other test in the repository would fail", path, raw)
		}
	}
}

// TestATokenRouteCannotBeToldApartFromASpentOne is the token routes' form of the
// question, and it is the form the question takes when the identifier is itself the
// credential.
//
// `POST /v1/email-verifications/confirm` is anonymous, so "is there a row for this
// token?" is answerable in principle. It is not answerable by GUESSING — the token
// is 256 bits of entropy and there is no space to enumerate — and it is not
// answerable by ACCIDENT either: a token that EXISTS and is dead answers exactly
// what a token that never existed answers, and so does a LIVE token presented to the
// wrong route. "Expired", "spent" and "minted for another flow" are all facts about
// rows that exist, which is why the comparison is over real rows rather than over
// garbage strings.
func TestATokenRouteCannotBeToldApartFromASpentOne(t *testing.T) {
	f := newAuditFixture(t)
	email, session := f.signUp(t)

	// FOUR REAL TOKENS: one spent, and three live across two purposes. A live token
	// presented to the route that MINTED it redeems — that is the endpoint working —
	// so "a token that exists" has to be tested with a token for the WRONG flow, and a
	// garbage string proves nothing about rows that are really there.
	spent := f.mintVerificationAndSpend(t, email)
	changeFirstHalf := f.mintEmailChange(t, session)
	// A SECOND verification token, which is live for the rest of this test. Minting
	// one on an account whose address is already proved is also a small demonstration
	// of identity-27's change: the request is accepted and the link is sent.
	liveVerification := f.mintVerification(t, email)

	if spent == liveVerification {
		t.Fatal("the two verification tokens are the same value, so the live case is not live")
	}

	for _, route := range []struct {
		path string
		// wrong are live tokens minted for a different flow, and on the SAME account:
		// rows that exist, are unexpired, and are refused only because of what they
		// were minted for.
		wrong []struct{ label, token string }
	}{
		{
			path:  "/v1/email-verifications/confirm",
			wrong: []struct{ label, token string }{{"a live email-change token", changeFirstHalf}},
		},
		{
			path: "/v1/email-changes/current-address",
			wrong: []struct{ label, token string }{
				{"a live verification token", liveVerification},
			},
		},
		{
			// The second half refuses the FIRST half too: they are for different
			// inboxes, and a token that worked on the wrong side would mean the wrong
			// inbox proved something.
			path: "/v1/email-changes/new-address",
			wrong: []struct{ label, token string }{
				{"a live verification token", liveVerification},
				{"a live first-half email-change token", changeFirstHalf},
			},
		},
	} {
		cases := []struct{ label, token string }{
			{"a token that was spent", spent},
			{"a token that never existed", strings.Repeat("z", 43)},
		}
		cases = append(cases, route.wrong...)

		reference := ""
		for i, c := range cases {
			rec := post(t, f.handler, route.path, `{"token":"`+c.token+`"}`)
			if rec.Code != http.StatusNotFound {
				t.Errorf("POST %s with %s = %d, want 404; body: %s", route.path, c.label, rec.Code, rec.Body)
				continue
			}
			p := decodeProblem(t, rec)
			p.TraceID = ""
			rendered := renderProblem(t, p)
			switch {
			case i == 0:
				reference = rendered
			case rendered != reference:
				t.Errorf("POST %s answers differently for %s than for a spent token:\n  that:    %s\n"+
					"  a spent: %s", route.path, c.label, rendered, reference)
			}
		}
		if reference == "" {
			t.Errorf("POST %s produced no comparable answer, so the comparison above passed "+
				"vacuously", route.path)
		}
	}
}

// TestIntrospectionIsAnOracleByDesignAndGatedOnACredential is the row the next
// reader is most likely to try to fix, so it is written down.
//
// **DO NOT MAKE THIS ROUTE LOOK LIKE THE OTHERS.** An introspection endpoint that
// could not tell a caller whether a token is live would be useless: the answer is
// the product, RFC 7662 defines it, and every resource server in the platform calls
// it for exactly that reason. A live token answers with its claims and a dead one
// with `{"active": false}`, and those two bodies are SUPPOSED to differ — the test
// below asserts that they do.
//
// WHAT ACTUALLY PROTECTS IT is the credential the CALLER must present, which is a
// different question from the answer's shape:
//
//   - no credential at all is 401, and that check runs before the body is read;
//   - a token may ask about itself and nothing else;
//   - a session may ask about a token in an account it OWNS, and is refused otherwise.
//
// All of it over the real apikeys service and a real database, so "active" and
// "inactive" are two real rows rather than two things a double decided.
func TestIntrospectionIsAnOracleByDesignAndGatedOnACredential(t *testing.T) {
	f := newAuditFixture(t)

	email, session := f.signUp(t)
	issued := f.issueAPIKey(t, email, session)

	// THE ORACLE, asserted first, so nobody reads the rest as a proposal to remove it.
	// The session is the credential, and it is the OWNER's — this is the account's own
	// inventory being read by the account's owner, which is the case that has to work.
	active := sendWith(t, f.handler, http.MethodPost, "/v1/introspections", session, "",
		`{"token":"`+issued+`"}`)
	if active.Code != http.StatusOK {
		t.Fatalf("the owner introspecting its own account's live token = %d, want 200; body: %s",
			active.Code, active.Body)
	}
	var claims map[string]any
	if err := json.Unmarshal(active.Body.Bytes(), &claims); err != nil {
		t.Fatalf("the claim document is not JSON: %v", err)
	}
	if claims["active"] != true || claims["sub"] == nil {
		t.Errorf("the claim document does not describe a live token: %v", claims)
	}

	inactive := sendWith(t, f.handler, http.MethodPost, "/v1/introspections", session, "",
		`{"token":"`+strings.Repeat("z", 43)+`"}`)
	if inactive.Code != http.StatusOK {
		t.Fatalf("introspecting an unknown token = %d, want 200", inactive.Code)
	}
	if inactive.Body.String() == active.Body.String() {
		t.Error("a live token and an unknown one answered identically. That is the failure the " +
			"OTHER routes in this file guard against, and here it would be the endpoint failing " +
			"at its job rather than leaking")
	}

	// THE GATE. No credential: refused before the body is read, so a stranger learns
	// nothing at all — not even whether a value they hold is live.
	if rec := anonymousProbe(t, f, http.MethodPost, "/v1/introspections"); rec.Code != http.StatusUnauthorized {
		t.Errorf("an anonymous introspection = %d, want 401. This route's protection is the "+
			"caller's credential and nothing else, so a 200 here would make every token in the "+
			"deployment publicly checkable", rec.Code)
	}

	// A signed-in stranger: refused, and which way it is refused is itself asserted so
	// that a change from 404 to 403 (or back) is noticed rather than inherited.
	_, strangerSession := f.signUp(t)
	refused := sendWith(t, f.handler, http.MethodPost, "/v1/introspections", strangerSession, "",
		`{"token":"`+issued+`"}`)
	if refused.Code != http.StatusForbidden && refused.Code != http.StatusNotFound {
		t.Errorf("a session from outside the account introspecting another account's token = %d, "+
			"want 403 or 404", refused.Code)
	}

	// A scoped token may read itself and nothing else. The peer case is inside the
	// account, so it is the one the session rules cannot reach.
	peer := f.issueAPIKey(t, email, session)
	if rec := sendWith(t, f.handler, http.MethodPost, "/v1/introspections", issued, "",
		`{"token":"`+peer+`"}`); rec.Code != http.StatusForbidden && rec.Code != http.StatusNotFound {
		t.Errorf("a token introspecting another token in the same account = %d, want 403 or 404; "+
			"reading a peer's scopes is reconnaissance", rec.Code)
	}
	if rec := sendWith(t, f.handler, http.MethodPost, "/v1/introspections", issued, "",
		`{"token":"`+issued+`"}`); rec.Code != http.StatusOK {
		t.Errorf("a token introspecting itself = %d, want 200; body: %s", rec.Code, rec.Body)
	}

	// The owner with a SESSION may ask too — asserted because the usual "fix" for a 403
	// that looks too strict is to drop the check, and this is where that would land.
	if rec := sendWith(t, f.handler, http.MethodPost, "/v1/introspections", session, "",
		`{"token":"`+issued+`"}`); rec.Code != http.StatusOK {
		t.Errorf("the owner introspecting its own account's token with a session = %d, want 200; "+
			"body: %s", rec.Code, rec.Body)
	}
}

// --- fixture ----------------------------------------------------------------

// auditFixture is the whole anonymous surface over ONE private schema: auth,
// tenancy, recovery, api keys and introspection, all real.
//
// IT EMBEDS the recovery fixture rather than repeating its helpers, because the
// helpers are the interesting part — `signUp` drives the real registration and login,
// and `verifyAddress` walks the real two anonymous routes rather than writing the
// column. A second copy of either would be a second thing to keep working.
type auditFixture struct {
	*recoveryServerFixture
}

func newAuditFixture(t *testing.T) *auditFixture {
	t.Helper()

	pool := dbtest.Schema(t)
	clk := clock.NewFake(time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))
	mailer := &captureMailer{}
	access := &captureAccessRevoker{revoked: map[string]time.Time{}}
	tenancy := realTenancy(pool, clk)
	keys := matrixAPIKeys(pool, clk, tenancy)

	handler := New(nil,
		WithAuth(authServiceFor(pool, clk)),
		WithTenancy(tenancy),
		WithRecovery(recovery.NewService(
			db.TxRunner{Pool: pool},
			db.Direct{Pool: pool},
			recovery.NewStore(pool),
			users.NewStore(pool),
			sessions.NewStore(pool),
			access,
			outbox.NewStore(pool),
			mailer,
			users.NewHasherWithParams(&argon2id.Params{
				Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32,
			}),
			clk,
		)),
		WithAPIKeys(keys),
		WithAPIKeyCaller(keys),
		// The introspection route is NOT account-scoped and hangs off this alone.
		// Without it the route is not mounted at all, and the census above would read
		// a smaller service than the one that runs.
		WithIntrospection(keys),
		WithLogger(slogLogger(&recordingHandler{})),
	)

	return &auditFixture{recoveryServerFixture: &recoveryServerFixture{
		handler: handler,
		pool:    pool,
		clk:     clk,
		mailer:  mailer,
		access:  access,
	}}
}

// mintVerification asks for a confirmation link and returns the token that was
// mailed, without redeeming it.
func (f *auditFixture) mintVerification(t *testing.T, email string) string {
	t.Helper()

	rec := post(t, f.handler, "/v1/email-verifications", `{"email":"`+email+`"}`)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST /v1/email-verifications = %d, want 202; body: %s", rec.Code, rec.Body)
	}
	return tokenIn(t, f.mailer.last(t))
}

// mintVerificationAndSpend does the whole verification flow and returns the token it
// spent, which is the "a row that exists and is dead" case the token routes have to
// be unable to tell apart from a row that never existed.
func (f *auditFixture) mintVerificationAndSpend(t *testing.T, email string) string {
	t.Helper()

	token := f.mintVerification(t, email)
	rec := post(t, f.handler, "/v1/email-verifications/confirm", `{"token":"`+token+`"}`)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("spending the verification token = %d, want 204; body: %s", rec.Code, rec.Body)
	}
	return token
}

// mintEmailChange starts a change and returns the first-half token, unredeemed.
func (f *auditFixture) mintEmailChange(t *testing.T, session string) string {
	t.Helper()

	rec := sendWith(t, f.handler, http.MethodPost, "/v1/email-changes", session, "",
		`{"email":"`+dbtest.UniqueEmail(t)+`"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /v1/email-changes = %d, want 201; body: %s", rec.Code, rec.Body)
	}
	return tokenIn(t, f.mailer.last(t))
}

// issueAPIKey mints a live scoped token in the account the session owns, through the
// real route, and returns the secret exactly once.
//
// Through HTTP rather than through the service's own method because the 201 is the
// only place the plaintext exists, and a test that wanted one from anywhere else
// would be asking for a value the service cannot produce twice.
func (f *auditFixture) issueAPIKey(t *testing.T, email, session string) string {
	t.Helper()

	var accountID string
	if err := f.pool.QueryRow(t.Context(), `
		SELECT a.id::text FROM account_users au
		JOIN accounts a ON a.id = au.account_id
		JOIN users u ON u.id = au.user_id
		WHERE u.email = $1 ORDER BY a.created_at, a.id LIMIT 1`, email).Scan(&accountID); err != nil {
		t.Fatalf("finding an account for %s: %v", email, err)
	}

	// The name is short and random rather than derived from the test name: `users`
	// caps an api key's name at 64 characters, and a name built from a long test name
	// is a 422 that reads like a fixture bug. Randomness is what makes it unique,
	// because "one live name per account" is a partial unique index.
	rec := sendWith(t, f.handler, http.MethodPost,
		"/v1/accounts/"+accountID+"/api-keys", session, "",
		`{"name":"audit-`+id.MustNew().String()[:8]+`","scopes":["accounts:read"]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("minting an api key = %d, want 201; body: %s", rec.Code, rec.Body)
	}

	var issued issuedAPIKeyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &issued); err != nil {
		t.Fatalf("the minting body is not JSON: %v", err)
	}
	if issued.Token == "" {
		t.Fatal("the 201 carried no token, so the introspection half of this test would prove nothing")
	}
	return issued.Token
}

// --- helpers ----------------------------------------------------------------

// mountedFamilyRoutes is every route under one of this family's prefixes, read out
// of chi with every conditional surface configured.
//
// THE OPTIONS LITERAL IS THE WHOLE OF THE WALK'S HONESTY: a registrar that returns
// early for a missing service leaves its routes out of the walk, and the census above
// would then be a census of a smaller service. That is not hypothetical in this
// package — `router_walk_test.go` records a check in this very directory passing
// green over three un-audited routes because a field was left out of a literal like
// this one. `TestEveryConditionalSurfaceIsVisibleToTheWalk` is what keeps the list
// honest.
func mountedFamilyRoutes() []string {
	var found []string

	r := chi.NewRouter()
	options{
		auth:         newFakeAuth(),
		tenancy:      newFakeTenancy(),
		apiKeys:      newFakeAPIKeys(),
		apiKeyCaller: newFakeAPIKeyCaller(users.User{}, apikeys.Key{}),
		mfa:          newFakeMFAManage(),
		introspector: newFakeIntrospector(),
		oidc:         newFakeOIDC(),
		oidcClients:  newFakeOIDCClients(),
		admin:        newFakeAdmin(),
		recovery:     newFakeRecovery(),
	}.registerRoutes(r)

	_ = chi.Walk(r, func(method string, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		clean := normalizeRoute(method, route)
		if isAuditFamilyRoute(clean) {
			found = append(found, clean)
		}
		return nil
	})

	sort.Strings(found)
	return found
}

// isAuditFamilyRoute says whether a "METHOD /path" key belongs to this file.
func isAuditFamilyRoute(route string) bool {
	_, path := splitRoute(route)
	for _, prefix := range auditFamilyPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// anonymousProbe sends a route the body this file's table gives it, with no
// credential at all.
//
// THE DEFAULT BODY IS `{}` AND IT IS ONLY EVER REACHED FOR A ROUTE WITH NO ROW —
// which is the case the walk is complaining about, and where a 400 from a missing
// body would be read as a refusal rather than as a route that answered a stranger.
func anonymousProbe(t *testing.T, f *auditFixture, method, pattern string) *httptest.ResponseRecorder {
	t.Helper()

	body := ""
	for _, row := range anonymousFamilyAudit() {
		if row.method == method && row.pattern == pattern {
			body = row.probe
			break
		}
	}
	return sendWith(t, f.handler, method, pattern, "", "", body)
}

// renderProblem marshals a problem document with its trace id already cleared, so
// two refusals can be compared byte for byte.
func renderProblem(t *testing.T, p Problem) string {
	t.Helper()
	p.TraceID = ""
	out, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("re-marshalling a problem document: %v", err)
	}
	return string(out)
}

// splitRoute is the inverse of normalizeRoute's key: "POST /v1/session" becomes
// ("POST", "/v1/session").
func splitRoute(route string) (string, string) {
	method, pattern, _ := strings.Cut(route, " ")
	return method, pattern
}

func contains(haystack []string, needle string) bool {
	for _, item := range haystack {
		if item == needle {
			return true
		}
	}
	return false
}

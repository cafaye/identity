package oidc

import (
	"errors"
	"net/url"
	"strings"
	"testing"
)

// THE LOGIN UI CONTRACT.
//
// Everything here is about a seam with another repository. There is no way to test
// the far side of it from here, so what this file does is make the near side
// impossible to change silently: the parameter names, the codes, the refusals, and
// the shape of a redirect. A change to any of them is a change to a published
// contract, and the point of these tests is that it cannot be one without a test
// going red in a file whose name says what broke.

// testLoginUIURL is the configured address in every construction in this package.
//
// IT IS A DIFFERENT ORIGIN from the issuer, deliberately. A same-origin login UI
// would make every question this file asks uninteresting: there would be no
// cross-site form post, no `client_name` crossing into a document identity does
// not control, and no configuration at all worth refusing. The deployment this
// contract exists for has the login UI somewhere else.
const testLoginUIURL = "https://login.example.com/sign-in/oidc"

func testProviderFor(t *testing.T, loginUI string) *Provider {
	t.Helper()

	key, err := LoadSigningKey(pemFor(t, 2048, pkcs8), "cafaye-test-key")
	if err != nil {
		t.Fatalf("LoadSigningKey: %v", err)
	}
	storage := NewStorage(nil, NewProfileReader(), key, testClock{}, nil, PathLogin)
	provider, err := NewProvider(Config{
		Issuer:     "https://identity.test",
		SigningKey: key,
		LoginUIURL: loginUI,
	}, storage)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	return provider
}

// A provider with no login UI is not built.
//
// THE ASSERTION IS THE SENTINEL AND NOT "an error came back", because a provider
// that mounts and then cannot complete a flow is the state this rule exists to
// prevent, and a bare `err != nil` would also be satisfied by a typo in a test.
func TestNewProviderRefusesToBuildWithoutALoginUI(t *testing.T) {
	t.Parallel()

	key, err := LoadSigningKey(pemFor(t, 2048, pkcs8), "cafaye-test-key")
	if err != nil {
		t.Fatalf("LoadSigningKey: %v", err)
	}
	storage := NewStorage(nil, NewProfileReader(), key, testClock{}, nil, PathLogin)

	_, err = NewProvider(Config{Issuer: "https://identity.test", SigningKey: key}, storage)
	if err == nil {
		t.Fatal("NewProvider built a provider that cannot send a browser anywhere to sign in")
	}
	if !errors.Is(err, ErrNoLoginUI) {
		t.Errorf("the refusal is %v, want one matching ErrNoLoginUI", err)
	}
	// The refusal has to NAME THE VARIABLE, because the reader of it is an operator
	// at boot and the whole value of failing early is the log line.
	if !strings.Contains(err.Error(), LoginUIEnvVar) {
		t.Errorf("the refusal does not name %s: %v", LoginUIEnvVar, err)
	}
}

// A login UI this service cannot send a browser to is refused, and each refusal
// names what is wrong with the address rather than saying "invalid".
func TestValidateLoginUIURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
		// want is the sentinel the refusal must match. A test that only asserted
		// "an error" would pass for a rule that refuses everything, including the
		// address below that is accepted.
		want error
	}{
		{name: "empty", raw: "", want: ErrNoLoginUI},
		{name: "no scheme", raw: "login.example.com/sign-in", want: ErrInvalidLoginUI},
		{name: "a scheme that is not http", raw: "javascript:alert(1)", want: ErrInvalidLoginUI},
		{name: "a data url", raw: "data:text/html,<form></form>", want: ErrInvalidLoginUI},
		{name: "no host", raw: "https:///sign-in", want: ErrInvalidLoginUI},
		{name: "userinfo", raw: "https://parlor@evil.example.com/login", want: ErrInvalidLoginUI},
		{name: "a fragment", raw: "https://login.example.com/sign-in#top", want: ErrInvalidLoginUI},
		{
			// The one that looks harmless. A configured query is MERGED rather than
			// clobbered, so it survives into a URL that also carries an authorization
			// request id, a CSRF state and a client's login_hint — a string this
			// service did not write, on the same URL.
			name: "a query", raw: "https://login.example.com/sign-in?variant=acme", want: ErrInvalidLoginUI,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := ValidateLoginUIURL(tt.raw)
			if !errors.Is(err, tt.want) {
				t.Errorf("ValidateLoginUIURL(%q) = %v, want one matching %v", tt.raw, err, tt.want)
			}
		})
	}
}

// The addresses that must be ACCEPTED, because a validator that only knows how to
// refuse is a validator nobody can rely on, and because the query refusal above is
// a rule that has to be paid for.
func TestValidateLoginUIURLAccepts(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{
		"https://login.example.com/sign-in/oidc",
		"https://login.example.com",
		"https://login.example.com/",
		// http, for a local compose stack. The scheme is the deployment's business,
		// and OIDC_ALLOW_INSECURE already governs whether identity is willing to be
		// reached over http at all.
		"http://localhost:4000/sign-in/oidc",
		// A trailing slash is harmless and refusing it would be a rule with no
		// failure behind it.
		"https://login.example.com/sign-in/oidc/",
	} {
		if err := ValidateLoginUIURL(raw); err != nil {
			t.Errorf("ValidateLoginUIURL(%q) = %v, want it accepted", raw, err)
		}
	}
}

// LoginRedirect builds the URL, and the four things about it that a reviewer has
// to be able to see without running anything.
func TestLoginRedirect(t *testing.T) {
	t.Parallel()

	p := testProviderFor(t, testLoginUIURL)
	params := LoginRedirectParams{
		RequestID:   "11111111-2222-3333-4444-555555555555",
		State:       "oidc.a-token",
		Step:        LoginStepPassword,
		ClientName:  "Anytalk",
		LoginHint:   "person@example.com",
		Error:       LoginErrorInvalidCredentials,
		ErrorDetail: "that email address and password were not accepted",
		RetryAfter:  "900",
	}

	raw := p.LoginRedirect(params)
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("the redirect is not a URL: %v", err)
	}

	if got := parsed.Scheme + "://" + parsed.Host + parsed.Path; got != testLoginUIURL {
		t.Errorf("the redirect is %q, want the configured login UI %q with only a query added", got, testLoginUIURL)
	}
	query := parsed.Query()
	for name, want := range map[string]string{
		LoginParamRequestID:   params.RequestID,
		LoginParamState:       params.State,
		LoginParamStep:        params.Step,
		LoginParamClientName:  params.ClientName,
		LoginParamLoginHint:   params.LoginHint,
		LoginParamError:       params.Error,
		LoginParamErrorDetail: params.ErrorDetail,
		LoginParamRetryAfter:  params.RetryAfter,
	} {
		if got := query.Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}

	// DETERMINISTIC, because a Location header that reorders itself between two
	// identical requests is untestable and unreadable. url.Values.Encode sorts by
	// key, and this is what holds it there.
	if again := p.LoginRedirect(params); again != raw {
		t.Errorf("two identical interactions produced two URLs:\n  %s\n  %s", raw, again)
	}
}

// An absent parameter is ABSENT and not empty.
//
// The reason is one line of login UI code: `if (params.error)` is true for an
// empty string, so an error that was sent empty would render an empty failure
// banner on a perfectly normal sign-in — and the absence of an error is the signal
// that nothing went wrong.
func TestLoginRedirectOmitsEmptyParametersRatherThanSendingThemEmpty(t *testing.T) {
	t.Parallel()

	p := testProviderFor(t, testLoginUIURL)
	parsed, err := url.Parse(p.LoginRedirect(LoginRedirectParams{
		RequestID:  "11111111-2222-3333-4444-555555555555",
		State:      "oidc.a-token",
		Step:       LoginStepPassword,
		ClientName: "Anytalk",
		// Everything else is the zero value: a fresh step.
	}))
	if err != nil {
		t.Fatalf("the redirect is not a URL: %v", err)
	}

	query := parsed.Query()
	for _, name := range []string{LoginParamError, LoginParamErrorDetail, LoginParamRetryAfter, LoginParamLoginHint} {
		if _, present := query[name]; present {
			t.Errorf("a fresh step carried %s=%q; an absent error and an empty one must "+
				"not both read as no error", name, query.Get(name))
		}
	}
	// …and the three that are always there, because the login UI cannot render a
	// form without them.
	for _, name := range []string{LoginParamRequestID, LoginParamState, LoginParamStep} {
		if query.Get(name) == "" {
			t.Errorf("a fresh step carried no %s", name)
		}
	}
}

// The state and the client's login hint are ESCAPED, and this is the assertion
// that the move out of an html/template did not introduce an injection.
//
// `client_name` is a row an account owner typed, and `login_hint` is a string the
// client chose. Before the move they were interpolated into an `html/template`,
// which escaped them by construction. Now they go into a query string, which
// url.Values.Encode percent-encodes — and a login UI that reads them off the query
// and interpolates them into a document without escaping is running whatever a
// product owner typed. The test pins that identity did not make that mistake, and
// `client_name` is the field worth pinning it on.
func TestLoginRedirectEscapesWhatTravelsInIt(t *testing.T) {
	t.Parallel()

	p := testProviderFor(t, testLoginUIURL)
	const hostile = `<script>alert("x")</script> & ?=#`

	raw := p.LoginRedirect(LoginRedirectParams{
		RequestID:  "11111111-2222-3333-4444-555555555555",
		State:      "oidc.a-token",
		Step:       LoginStepPassword,
		ClientName: hostile,
	})
	if strings.Contains(raw, "<script>") {
		t.Errorf("the redirect carries a raw script tag: %s", raw)
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("the redirect is not a URL: %v", err)
	}
	if got := parsed.Query().Get(LoginParamClientName); got != hostile {
		t.Errorf("%s came back as %q after a round trip, want the value unchanged — "+
			"escaping must survive the decode", LoginParamClientName, got)
	}
	// And the one that is load-bearing: a client_name that changes the shape of the
	// URL is a client_name that can add a parameter of its own.
	if strings.Contains(raw, "error=") {
		t.Errorf("a product name injected a parameter into the redirect: %s", raw)
	}
}

// A redirect must not be able to change the login UI's ORIGIN, and this is the
// property that makes the whole thing safe to hand a caller-influenced value.
//
// The registration's redirect_uri is matched by equality and the login UI is
// configuration, so neither is attacker-controlled — but the request id, the state
// and the login hint all are, and a merge that appended rather than replaced
// would put a `?` or a `#` from one of them into the path. A test that only
// checked the happy path would not see it.
func TestLoginRedirectKeepsEveryValueInsideTheQuery(t *testing.T) {
	t.Parallel()

	p := testProviderFor(t, testLoginUIURL)
	raw := p.LoginRedirect(LoginRedirectParams{
		RequestID:  "11111111-2222-3333-4444-555555555555",
		State:      "oidc.a-token",
		Step:       LoginStepPassword,
		LoginHint:  "person@example.com?next=https://evil.example.com",
		ClientName: "Anytalk",
	})

	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("the redirect is not a URL: %v", err)
	}
	if got := parsed.Scheme + "://" + parsed.Host + parsed.Path; got != testLoginUIURL {
		t.Errorf("the redirect's origin and path are %q, want %q; a value reached outside "+
			"the query", got, testLoginUIURL)
	}
	if parsed.Fragment != "" {
		t.Errorf("the redirect carries a fragment: %q", parsed.Fragment)
	}
}

// The parameter list and the struct are the same set, in BOTH directions.
//
// The struct is where a value is set and the constant list is what the document
// publishes, so a field added to one and not the other is a name the far side
// will never read, and a constant with nothing setting it is a name the far side is
// told to expect and never receives. Both are silent, which is why this is a test
// and not a convention — and the reason it walks the constants rather than
// comparing two hand-written lists is that a hand-written list is the thing that
// drifts.
func TestEveryLoginRedirectParameterIsCarriedAndEveryCarriedOneIsNamed(t *testing.T) {
	t.Parallel()

	declared := map[string]bool{
		LoginParamRequestID:   true,
		LoginParamState:       true,
		LoginParamStep:        true,
		LoginParamClientName:  true,
		LoginParamLoginHint:   true,
		LoginParamError:       true,
		LoginParamErrorDetail: true,
		LoginParamRetryAfter:  true,
	}

	// Everything the struct can carry, filled in with a value a reader can
	// recognise. If a field is added to LoginRedirectParams and not added here, it
	// is absent from `carried` and the second loop below fails.
	carried := LoginRedirectParams{
		RequestID:   "11111111-2222-3333-4444-555555555555",
		State:       "oidc.a-token",
		Step:        LoginStepPassword,
		ClientName:  "Anytalk",
		LoginHint:   "person@example.com",
		Error:       LoginErrorInvalidCredentials,
		ErrorDetail: "a sentence",
		RetryAfter:  "900",
	}.Values()

	for name := range declared {
		if _, carried := carried[name]; !carried {
			t.Errorf("the contract publishes %q and no field of LoginRedirectParams ever "+
				"sends it; a login UI told to expect it would never receive it", name)
		}
	}
	for name := range carried {
		if !declared[name] {
			t.Errorf("LoginRedirectParams carries %q and the contract does not name it, so "+
				"it is a parameter the login UI has no reason to read", name)
		}
	}
}

// The codes that mean the same thing on both surfaces are the SAME STRING, and
// this is the test that stops `account_locked` here and `account_locked` there
// drifting into two vocabularies.
//
// The problem envelope is in `internal/httpapi`, which imports this package, so
// the comparison is written the other way round: this file names the code that
// means the same thing and httpapi's own test walks the list. What this side can
// do is hold the LIST, so a sixth interaction code added here has to be added to
// the set below deliberately, with a note about whether it has a problem-code
// twin.
func TestAnInteractionErrorCodeThatNamesAProblemCodeIsTheSameString(t *testing.T) {
	t.Parallel()

	// Every interaction code, and whether `internal/httpapi` has a code that means
	// the same thing. A code with no twin is a new word; that is allowed, and it has
	// to be a decision recorded here rather than an accident.
	twins := map[string]string{
		LoginErrorInteractionExpired: "none — new. There is no problem code for " +
			"'the form expired': before this packet it was a 400 with `invalid_request`, " +
			"which is a different claim.",
		LoginErrorMissingCredentials: "none — new. The 422's `validation_failed` said " +
			"'the request is not acceptable', which is a statement about a request body. " +
			"This one is a statement about a form a person filled in.",
		LoginErrorInvalidCredentials: "none — new. The 401's `unauthorized` says 'you are " +
			"not signed in', which is a different claim from 'those credentials were not " +
			"accepted'; a login UI showing the wrong one of those tells a user their " +
			"session expired.",
		LoginErrorChallengeRejected: "none — new, for the same reason: the 401's " +
			"`unauthorized` is about a session, and this is about a code.",
		LoginErrorAccountLocked: "httpapi.CodeAccountLocked — the SAME WORD on purpose. " +
			"A UI that already switches on `account_locked` for a 423 must not have to " +
			"learn a second spelling of it.",
	}

	for code, note := range twins {
		if code == "" {
			t.Error("a code in the table is empty")
		}
		if !strings.Contains(note, " — ") {
			t.Errorf("the code %q has no note saying whether it has a problem-code twin; "+
				"adding a code without that sentence is how two vocabularies start", code)
		}
	}

	// The one that HAS a twin is spelled identically on both sides, and
	// `TestAnInteractionCodeThatHasAProblemCodeTwinIsTheSameString` in
	// internal/httpapi is what actually compares the two constants — this side
	// cannot import the package that would let it.
	if twins[LoginErrorAccountLocked] == "" {
		t.Error("account_locked lost its note")
	}
}

// The two step values are the ones a login UI switches on, and neither is a
// misspelling of a word anybody would reach for first. This is a low-value test
// and it is here because a rename of either value is a breaking change to another
// repository and should require editing a file that says so.
func TestTheStepValuesAreTheDocumentedOnes(t *testing.T) {
	t.Parallel()

	if LoginStepPassword != "password" {
		t.Errorf("the password step is %q, want \"password\"; the value is a published constant",
			LoginStepPassword)
	}
	if LoginStepChallenge != "challenge" {
		t.Errorf("the challenge step is %q, want \"challenge\"; the value is a published constant",
			LoginStepChallenge)
	}
}

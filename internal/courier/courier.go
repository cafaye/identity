// Package courier is identity's client for courier, the platform's mail service.
//
// # WHAT THIS PACKET IS, AND THE CONTRACT IT IS AGAINST
//
// courier answers `POST /v1/messages` behind its `:authenticated` and
// `:idempotent` pipelines, and that operation is the only door into its send
// path. This package speaks it. Everything below is a property of that document
// at courier master `f776b86`, and where this package and the document disagree
// the document is right and this package is the bug.
//
// # THE SENDING IS A TYPED, ATTRIBUTED SEND AND NOT A RENDERED ONE
//
// This is the single most important thing to know before reading anything else,
// because it decides the whole shape of the integration:
//
//	courier's request fields are a CLOSED list —
//	type, user_id, to, name, url, account_name, invited_by, role —
//	with `additionalProperties: false`.
//
// There is no `subject`, no `text`, no `html` and no `from`, and courier's own
// `CourierWeb.Messages` explains why: a caller that could choose the sender or
// the body would make courier a general-purpose relay wearing the platform's
// sending domain, which is a cost every other tenant pays. So courier RENDERS
// the mail from its own templates and the caller supplies FACTS.
//
// `RecoveryMailer` is where the translation from a `recovery.Message` into a
// courier request lives, and it is the only place in the repository that knows
// both vocabularies.
//
// # THE SERVICE CREDENTIAL, AND WHY IT IS A BEARER TOKEN
//
// courier's document declares `security: [bearerAuth: [messages:write]]` and
// says the issuer is identity. This package therefore presents
// `Authorization: Bearer <COURIER_TOKEN>` and nothing else — no cookie, no custom
// header, no second scheme — and it holds that value in a closure rather than in
// a struct field, for the reason `client/redact.go` gives and which is not
// repeated here because it is a property of Go's `fmt` rather than of this
// package: `%#v` prints an exported field by value and does not consult
// `String()`.
//
// The alternatives were weighed rather than skipped:
//
//   - **A shared secret on a header of our own.** courier's
//     `CourierWeb.Plugs.IngestToken` does exactly this, and its moduledoc gives
//     the reason it is right THERE: the callers are three services holding a
//     Sentry DSN and there is no identity service in that path to mint one. There
//     IS an identity in this path, and `IngestToken` is wired to a different
//     route — so a header courier's `:authenticated` pipeline does not read would
//     produce a request that is still a 401.
//   - **A user's session or scoped api key.** Both are a PERSON's credential, and
//     the `account_id` courier takes from the principal is the tenancy of the
//     mail. Attributing the platform's password resets to whichever user happened
//     to trigger one would put a stranger's recovery in somebody else's tenant.
//   - **A JWT identity mints for itself.** This is courier's declared contract and
//     the right end state, and it is not available today — see `RecoveryMailer`'s
//     section on the 401.
//
// # WHAT THIS PACKET DELIVERS AND WHAT IT REFUSES
//
// courier's `NotificationType` is `[welcome, password_reset, team_invitation]`.
// identity's `recovery` package renders four messages, and the mapping is drawn at
// "would courier's own template say the true thing to the person reading it",
// rather than at "which words are close enough":
//
//	password_reset            -> courier's password_reset       DELIVERED
//	verify_email              -> courier's welcome              DELIVERED
//	email_change (current)    -> no such courier message        REFUSED
//	email_change (new)        -> no such courier message        REFUSED
//
// `verify_email` maps to `welcome` because courier's own `welcome` template IS a
// registration's address confirmation — "Welcome aboard. Confirm your address and
// you are in." followed by the link whenever one is supplied — and `recovery` only
// ever sends that message to an account which has never proved an address.
// `RecoveryMailer` carries the argument in full, including the cost and the one
// sentence in courier's document that is wrong about its own template.
//
// The two refusals are refusals, not translations. Mapping the current-address
// half of an email change onto courier's `password_reset` would put "Somebody
// asked to reset the password on your account" into the one message a hijacked
// session cannot get past, and that message is the ONLY warning the owner of an
// account has that somebody is moving its address. A wrong-but-delivered security
// notice is worse than a loud failure.
//
// # WHAT THE RECORDED INTERACTIONS IN THIS PACKET ARE
//
// `recorded_test.go` replays byte-for-byte responses captured from a real courier
// at master `f776b86`. That file's header says how they were taken and — more
// importantly — what running that courier did and did not prove.
package courier

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// courier's paths. They are constants because they are courier's contract, and a
// path built from a template at a call site is a path that can be built wrong.
const (
	// messagesPath is the only door into courier's send path.
	messagesPath = "/v1/messages"

	// readyzPath is courier's infrastructure probe, and it is deliberately OUTSIDE
	// every pipeline: no auth, no accepts negotiation, no database. That is what
	// makes it the right answer to `recovery.Mailer.Ready`, whose contract is
	// "cheap, and sends nothing".
	readyzPath = "/readyz"
)

// The two bounds, and they are different numbers for a reason.
//
// `DefaultTimeout` bounds a SEND. A send is courier opening a database
// transaction, reading a preference, consulting a suppression list, dialling an
// SMTP relay and writing an outbox row, all inside one request, so this is
// genuinely the user's wait and not an internal hop. Five seconds is long enough
// for a TLS handshake and a relay queue and short enough that a browser is not
// left watching a spinner; the failure mode is a 503 the user can retry, and the
// retry is free because the request carries an `Idempotency-Key`.
//
// `DefaultProbeTimeout` bounds a READINESS PROBE, which is a few bytes from a
// process that is either up or not, and which runs on the anonymous request path
// before any credential is minted. It is short because a slow probe delays every
// password-reset request in the deployment, including the ones for addresses
// nobody registered.
const (
	DefaultTimeout      = 5 * time.Second
	DefaultProbeTimeout = 2 * time.Second
)

// maxResponseBytes bounds what this client will read from courier.
//
// courier's own responses are small and bounded by its schema, and this is here
// for the case where the thing answering is not courier: a proxy error page, a
// captive portal, a truncated connection. Reading without a bound is how a client
// becomes an unbounded memory consumer on somebody else's bad day.
const maxResponseBytes = 64 << 10

// The types courier will send, which are ALL of them, read from its document's
// `NotificationType` enum.
//
// The list is closed in Go for the reason `recovery.Purpose` is closed: a closed
// vocabulary is a code fact, and putting it only in the document would make the
// day courier adds a type a day this client answers `ErrInvalidRequest` for a
// request that is valid. The cost of the duplication is that it can go stale,
// which is why `TestEveryTypeThisClientSendsIsOneCourierAccepts` reads courier's
// `openapi.yaml` and fails when the two stop agreeing.
const (
	// TypeWelcome is courier's post-registration message, and it is the type
	// identity sends an address confirmation as. See `RecoveryMailer`'s section on
	// the mapping: courier's own `welcome` template IS a registration's address
	// confirmation, and it renders `url`.
	TypeWelcome = "welcome"

	// TypePasswordReset is the one template of courier's three that is about an
	// account that already exists rather than about joining it.
	TypePasswordReset = "password_reset"

	// TypeTeamInvitation is courier's account-invitation message. identity mounts
	// no invitation flow that sends mail, so nothing here builds a request for it;
	// the constant exists so the vocabulary is complete and the drift test has
	// something to compare against.
	TypeTeamInvitation = "team_invitation"
)

// StatusAccepted is the only `data.status` courier will ever send.
//
// It is named here rather than read as a free string because courier's document is
// emphatic that a 200 means the provider ACCEPTED the message and nothing more:
// there is no delivery receipt, and a client that recorded `delivered` would be
// asserting a fact about somebody else's inbox that courier cannot know. A second
// value appearing here would mean courier started claiming delivery, and it should
// be a test failure rather than a quiet success.
const StatusAccepted = "accepted"

// FieldPreferencesDisabled is the `errors[].code` courier answers when the
// recipient has turned this notification type off.
//
// IT IS NAMED AND NOT PARSED LOOSE, because this is the one refusal on courier's
// send path that is a fact about a RECIPIENT rather than about the deployment, and
// the whole of the concealment decision in `recovery` rests on telling the two
// apart. Anything else with a 422 is this client's own request being wrong, which
// is a different failure with a different answer.
const FieldPreferencesDisabled = "notification_preferences_disabled"

// FieldError is one entry of courier's `errors[]`, which its conventions reserve
// for a 422 and nothing else.
type FieldError struct {
	Field string `json:"field"`
	Code  string `json:"code"`
}

// MessageRequest is one `POST /v1/messages` body.
//
// IT IS STRUCTURALLY A SUBSET OF courier's vocabulary, and that is the point
// rather than an omission: `account_name`, `invited_by` and `role` exist for
// `team_invitation` alone, and a field this client cannot populate is a field
// whose value could only ever be empty. Sending `omitempty` placeholders for them
// would be a request courier has to be told to ignore, and the vocabulary is
// closed precisely so that nothing has to be ignored.
type MessageRequest struct {
	// Type is one of the `Type*` constants. Required.
	Type string `json:"type"`

	// UserID is the user this send is about, and the key courier reads that
	// recipient's notification preferences by. Required, and checked for shape:
	// courier holds no foreign key to identity's users, so there is nothing else to
	// check against.
	UserID string `json:"user_id"`

	// To is the recipient. Required. courier consults its suppression list on this
	// value, which is why a suppressed mailbox is the one refusal this client has
	// to think hardest about.
	To string `json:"to"`

	// Name is the recipient's display name, used in courier's greeting. Optional,
	// and omitted rather than sent empty.
	//
	// identity has no display name on a user today, so nothing sets it. The field
	// exists because courier's document declares it, and a client that could not
	// express it would have to change the day identity grows one.
	Name string `json:"name,omitempty"`

	// URL is the link the message carries. REQUIRED by `password_reset` and
	// `team_invitation` and unused by `welcome`, which is why its absence is
	// refused here rather than discovered as a 422 over the network: by the time
	// courier is called, a token has been minted and a row written.
	URL string `json:"url,omitempty"`

	// IdempotencyKey is the `Idempotency-Key` header.
	//
	// IT IS A UUID AND THAT IS courier's rule, not a preference: the key is scoped
	// to a unique index and "an unbounded string in a unique index is a cost every
	// write pays". The field is `json:"-"` because it is a header and the body is
	// the body; sending it twice would be a field courier does not have, and that
	// is a 422.
	//
	// Left empty, `SendMessage` generates one. `RecoveryMailer` always sets it,
	// derived from the recovery token, so a retry of one send is one send.
	IdempotencyKey string `json:"-"`
}

// MessageResult is the `data` object of a 200.
//
// Every field is required by courier's schema and every one is checked on the way
// in: a 200 whose body is missing `message_id` is not an accepted send, it is a
// response this client does not understand, and the two must not collapse into one.
// `TestSendMessageReadsCouriersContract` has a row for each.
type MessageResult struct {
	// MessageID is courier's id, and the one on the wire as `Message-ID`. A bounce
	// or a complaint quoting it ties back to this send, which is the entire reason
	// courier returns it.
	MessageID string `json:"message_id"`

	// EventID is the `courier.email.delivered` outbox row written in the same
	// transaction as the send, so a caller can correlate its send with the event
	// every subscriber on the bus sees.
	EventID string `json:"event_id"`

	// Type echoes what courier sent.
	Type string `json:"notification_type"`

	// UserID echoes the body.
	UserID string `json:"user_id"`

	// Status is always `accepted`.
	Status string `json:"status"`
}

// sentResponse is courier's 200 envelope. The data sits behind a `data` key
// because core's conventions put every successful body there, and a client that
// read the object at the top level would find a body with no fields in it.
type sentResponse struct {
	Data MessageResult `json:"data"`
}

// Client is a courier client.
//
// IT HAS NO CREDENTIAL FIELD, and that is the whole of the credential design: Go
// prints an exported struct field by value under `%#v` and does NOT consult
// `String()`, so a `token string` on this struct is a leak that no method on this
// package can intercept. The credential lives inside `authorize`'s closure and
// inside `scrub`'s closure, and there is no formatting verb in Go that prints a
// closure's environment.
type Client struct {
	// baseURL is courier's root, without a trailing slash. Not a secret and not a
	// credential: an operator has to be able to confirm which courier this process
	// is pointed at, and `String()` reports it.
	baseURL string

	// http is the transport, held as a value so a test can point it at an
	// `httptest.Server` and no test in this package reaches the network.
	http *http.Client

	// timeout and probeTimeout are read per call rather than baked into
	// http.Client, so one client can answer a send and a probe on different
	// bounds. They are applied as a context deadline, so a hung courier is bounded
	// even if the transport ignores the Client's own Timeout.
	timeout      time.Duration
	probeTimeout time.Duration

	// authorize attaches the credential. A func, for the reason above.
	authorize func(*http.Request) error

	// scrub says whether a string this package is about to print came out of
	// something that could contain the credential. Also a func, for the same
	// reason, and also all-or-nothing: it does not remove a substring, it refuses
	// the whole string.
	scrub func(string) bool

	// newKey mints an `Idempotency-Key` when the caller supplied none. A func so a
	// uuid is not a field a `%#v` would print — harmless in itself, but keeping
	// every callable a closure means the credential rule is one rule rather than
	// one rule plus an exception for the harmless case.
	newKey func() (string, error)
}

// Config is what New needs.
//
// Token is a construction-time value and is not retained: `New` moves it into
// closures and the `Config` may be garbage collected immediately. That is the
// difference between a credential held for a process's life and one held for a
// constructor call, and it is the reason `Config` is not `Client`.
type Config struct {
	// BaseURL is courier's root, e.g. `http://courier:4003`. Required.
	BaseURL string

	// Token is the service credential. Required: a client with none would send
	// every request as an anonymous caller, and courier's answer to that is a 401
	// on a mail egress — an open relay with a config file attached.
	Token string

	// Timeout bounds one send. Zero means DefaultTimeout.
	Timeout time.Duration

	// ProbeTimeout bounds one readiness probe. Zero means DefaultProbeTimeout.
	ProbeTimeout time.Duration

	// HTTPClient replaces the transport. nil means a client built from Timeout.
	//
	// The seam that makes this package testable without a network, and the reason
	// there is no test in it that dials anything.
	HTTPClient *http.Client
}

// Errors this package reports, matched with `errors.Is`.
//
// THEY ARE SENTINELS RATHER THAN A TYPE PER CASE because the question every caller
// of this package asks is a branch, not a match: retry, give up, tell the user, or
// hide it from the user. A type per branch would put the branch in a type switch
// and make the exhaustive answer a compiler-checked one only for the branches
// somebody already thought of.
var (
	// ErrNoBaseURL means Config.BaseURL was empty or not an http URL.
	ErrNoBaseURL = errors.New("courier: no usable base URL")

	// ErrNoToken means Config.Token was empty.
	//
	// IT IS REFUSED RATHER THAN DEFAULTED because the default is a client that
	// authenticates nobody, and courier's answer to that is a 401 on the one route
	// where an unauthenticated POST is an open relay.
	ErrNoToken = errors.New("courier: no service credential")

	// ErrInvalidRequest is a request this client refuses to put on the wire. It is
	// ALWAYS this client's bug rather than courier's answer.
	//
	// The cases are courier's own rules read from its document — an unknown type, a
	// `user_id` that is not a uuid, and a `password_reset` with no link — and each
	// is checked here so the failure arrives before a token has been mailed and
	// after nobody has been told anything.
	ErrInvalidRequest = errors.New("courier: the request is not one courier can accept")

	// ErrSuppressed means courier refused because the recipient's mailbox cannot
	// be written to: a hard bounce, or a spam complaint.
	//
	// IT IS NOT RETRYABLE, and it is the refusal on this path that is a fact about
	// a RECIPIENT rather than about the deployment. `recovery` conceals it from an
	// anonymous caller for that reason; see the package there.
	ErrSuppressed = errors.New("courier: the recipient's mailbox cannot receive mail")

	// ErrDeclined means courier refused because the recipient has turned this
	// notification type off.
	//
	// The same shape as `ErrSuppressed` and deliberately NOT the same sentinel: it
	// is visible through `GET /v1/notification_preferences/{user_id}` and
	// changeable through the `PUT` beside it, so it is a fact about a person
	// rather than about a mailbox, and an operator's response to a pile of them is
	// different. Both are per-recipient, which is the property that decides
	// whether a caller may be told.
	ErrDeclined = errors.New("courier: the recipient has declined this notification")

	// ErrRefused means courier answered 422 about the request itself, or answered
	// something this document does not describe.
	//
	// A 422 here is ALWAYS this client's bug, because the request was built from a
	// `recovery.Message` this package rendered and every field in it was checked
	// before the wire. A 422 from a send that passed `validate` means courier's
	// vocabulary grew a rule this client has not read, and that deserves a loud
	// failure rather than a shrug.
	ErrRefused = errors.New("courier: the request was refused")

	// ErrUnauthenticated means courier answered 401 or 403.
	//
	// IN PRACTICE THIS MEANS THE CREDENTIAL IS WRONG, and it is the one failure on
	// this path that is never the caller's fault and always the operator's. It is
	// not retryable: a token courier will not take will not be taken on the second
	// attempt, and a client that reported it as retryable would turn a
	// misconfiguration into a retry storm against the platform's mail egress.
	ErrUnauthenticated = errors.New("courier: the service credential was not accepted")

	// ErrUnavailable means courier answered 503, 502, 504 or 500: its provider
	// refused, its adapter cannot deliver, or courier itself failed.
	//
	// IT IS RETRYABLE, and that is courier's own promise rather than this package's
	// optimism: "nothing was sent and no row was written, so the retry is safe; and
	// a failed request RELEASES its Idempotency-Key rather than storing the
	// failure, so a retry is not locked out for 24 hours."
	ErrUnavailable = errors.New("courier: cannot deliver right now")

	// ErrMalformedResponse means courier answered 2xx with a body this client could
	// not read as an accepted send.
	//
	// IT IS ITS OWN SENTINEL AND NOT `ErrUnavailable` because the two demand
	// OPPOSITE behaviour. A 503 is a courier that told us it could not do the work,
	// and a retry is the answer. A malformed 200 is courier, or something in front
	// of it, answering 200 without having identified a send — and retrying it would
	// mail a second copy of a message the first attempt may already have sent.
	ErrMalformedResponse = errors.New("courier: the response was not one this client can read")

	// ErrTimeout means the send or the probe outran its bound.
	//
	// It wraps `context.DeadlineExceeded`, so a caller can tell "the user gave up"
	// from "courier is slow" — the difference between a 499 nobody reads and a
	// courier whose relay has stopped answering.
	ErrTimeout = errors.New("courier: the request outran its bound")
)

// New builds a Client.
//
// The two refusals are the two an anonymous client would otherwise be, and both
// are refusals because each has a plausible-looking wrong answer: no base URL
// would send somewhere arbitrary, and no credential would send as nobody.
func New(cfg Config) (*Client, error) {
	base, err := normaliseBaseURL(cfg.BaseURL)
	if err != nil {
		return nil, err
	}
	if cfg.Token == "" {
		return nil, ErrNoToken
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	probe := cfg.ProbeTimeout
	if probe <= 0 {
		probe = DefaultProbeTimeout
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{}
	}

	// The credential, twice, in closures: `authorize` puts it on the wire and
	// `scrub` recognises it in anything coming back. There is no third place it
	// exists in this package.
	token := cfg.Token
	credential := "Bearer " + token

	return &Client{
		baseURL:      base,
		http:         httpClient,
		timeout:      timeout,
		probeTimeout: probe,
		authorize: func(r *http.Request) error {
			// Header.Set and not Add: a repeated `Authorization` is ambiguous, and
			// courier's plug reads the first one it sees.
			r.Header.Set("Authorization", credential)
			return nil
		},
		scrub:  func(s string) bool { return strings.Contains(s, token) },
		newKey: newUUIDv4,
	}, nil
}

// String makes this client safe to print.
//
// `fmt` calls this for `%v`, `%+v`, `%s` and `%q`, which between them are
// effectively every way a value reaches a log line. It reports the two things a
// reader of a log needs — where requests go, and that this client holds a
// credential — and nothing else. `%#v` bypasses this method by design in Go; the
// closures above are what make that safe, and the two are load-bearing together
// rather than one being a convenience.
func (c *Client) String() string {
	return "courier.Client{base_url: " + c.baseURL + ", authenticated: " +
		strconv.FormatBool(c.HasCredential()) + "}"
}

// HasCredential reports whether this client can authenticate.
//
// It exists so `String` can say `authenticated: true` without consulting a field,
// and so a test can assert the client is not anonymous without reading its guts.
func (c *Client) HasCredential() bool { return c.authorize != nil }

// SendMessage asks courier to send one message, and reports what courier said.
//
// IT IS SYNCHRONOUS, and the decision is recorded rather than assumed. courier's
// own document gives the argument against a queue: a 202 "would answer before the
// suppression check ran, and a refusal that arrives after the response is a
// refusal the caller cannot act on". identity cannot tell a user their password
// reset is on its way and then find out an hour later that the mailbox was
// suppressed — and the alternative is not a wiring change here, because the outbox
// publisher is deliberately not started in this repository, so an asynchronous
// send would be a new subsystem rather than a decision about this one.
//
// THE COST IS LATENCY ON ONE REQUEST PATH, and it is named rather than absorbed:
// `POST /v1/password-resets` and `POST /v1/email-changes/current-address` now
// block on courier blocking on SMTP, bounded by `Config.Timeout`. Nothing else
// about those routes changes, and `Ready` — which runs on the same path — has its
// own, smaller bound.
func (c *Client) SendMessage(ctx context.Context, req MessageRequest) (MessageResult, error) {
	if err := validate(req); err != nil {
		return MessageResult{}, err
	}

	key := req.IdempotencyKey
	if key == "" {
		generated, err := c.newKey()
		if err != nil {
			return MessageResult{}, fmt.Errorf("courier: minting an idempotency key: %w", err)
		}
		key = generated
	}

	body, err := json.Marshal(req)
	if err != nil {
		return MessageResult{}, fmt.Errorf("courier: encoding the request: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	_, resp, raw, err := c.do(ctx, http.MethodPost, messagesPath, "send", key, body)
	if err != nil {
		return MessageResult{}, err
	}

	var sent sentResponse
	if err := json.Unmarshal(raw, &sent); err != nil {
		return MessageResult{}, fmt.Errorf("%w: courier answered %d with a body that is not a send result",
			ErrMalformedResponse, statusOf(resp))
	}
	if err := validateResult(sent.Data); err != nil {
		return MessageResult{}, err
	}
	return sent.Data, nil
}

// Ready reports whether courier is up. It is the implementation behind
// `recovery.Mailer.Ready`.
//
// IT PROBES `/readyz` AND NOTHING ELSE, for the reason the constant says: that
// route runs before auth, before routing and before the rest of the platform
// exists, it sends nothing, and it is the one courier operation whose cost does
// not grow with the platform's state.
//
// WHAT IT DOES NOT ESTABLISH is worth being exact about, because a probe that
// over-promises is worse than none. courier's `/readyz` says courier's database
// answers; it does NOT say courier can deliver, because courier's adapter check is
// scoped to production and a courier in any other environment answers ready with
// a silent adapter. A nil return means "courier is reachable and its database
// answers" and nothing more, and the send is where a misconfigured adapter is
// discovered. `RecoveryMailer` says so in the line it writes at boot, because an
// operator who reads "courier is ready" as "mail will be sent" has been told
// something this method cannot support.
func (c *Client) Ready(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, c.probeTimeout)
	defer cancel()

	_, resp, _, err := c.do(ctx, http.MethodGet, readyzPath, "probe", "", nil)
	if err != nil {
		return err
	}
	if statusOf(resp) != http.StatusOK {
		return &Error{
			Op:       "probe",
			Status:   statusOf(resp),
			Code:     codeUnreadable,
			sentinel: ErrUnavailable,
			retry:    true,
			cause:    errNotOK,
		}
	}
	return nil
}

// do performs one request and reads courier's answer.
//
// IT RETURNS FOUR THINGS AND THAT IS THE POINT: the parsed status, the response,
// the raw body, and an error. A single `(*Response, error)` pair cannot express
// "courier answered 503 and this client read the body" versus "the connection
// never happened", and a client that conflates them ends up retrying a refusal as
// though it were a network fault.
//
// It does NOT decide the outcome. Classification is `classify`'s job and parsing a
// 2xx is `SendMessage`'s, so that the table that decides what each status MEANS is
// one table and this function is only about getting the bytes.
func (c *Client) do(
	ctx context.Context, method, path, op, idempotencyKey string, body []byte,
) (MessageResult, *http.Response, []byte, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return MessageResult{}, nil, nil, fmt.Errorf("courier: building the request: %w", err)
	}
	if body != nil {
		// Set rather than rely on the default: courier's `:accepts` plug and its
		// body parser both branch on this, and a request with no content type is
		// parsed by neither.
		req.Header.Set("Content-Type", "application/json")
	}
	// On every request INCLUDING the probe, because a 406 is the answer a client
	// gets for asking for a media type courier cannot produce, and this client
	// knows how to ask for the right one.
	req.Header.Set("Accept", "application/json")
	if idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}
	if err := c.authorize(req); err != nil {
		return MessageResult{}, nil, nil, err
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return MessageResult{}, nil, nil, c.transportError(ctx, err)
	}
	defer resp.Body.Close()

	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))

	// A non-2xx is classified from whatever was read, INCLUDING nothing: a
	// connection that died after the status line is still a 503 courier wrote, and
	// reporting it as a transport failure would tell an operator to look at the
	// network rather than at courier's provider.
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		if readErr != nil && len(raw) == 0 {
			raw = nil
		}
		return MessageResult{}, resp, raw, classify(op, resp, raw)
	}

	if readErr != nil {
		return MessageResult{}, resp, nil, c.transportError(ctx, readErr)
	}
	return MessageResult{}, resp, raw, nil
}

// transportError normalises the failures that happen before a status exists.
//
// The three are kept apart because each says something different to an operator: a
// deadline that elapsed is courier being slow, a cancelled context is the caller
// giving up, and anything else is a connection that did not happen at all.
func (c *Client) transportError(ctx context.Context, err error) error {
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(ctx.Err(), context.DeadlineExceeded):
		return fmt.Errorf("%w: %w", ErrTimeout, context.DeadlineExceeded)
	case errors.Is(err, context.Canceled), errors.Is(ctx.Err(), context.Canceled):
		return fmt.Errorf("courier: the caller gave up: %w", context.Canceled)
	default:
		// The underlying error is a `*url.Error` whose message contains the request
		// URL. That URL is courier's address and carries no credential — the
		// credential is in a header, not the path — but the whole string still goes
		// through the scrubber, because "this one is safe" is the kind of judgement
		// that is right until somebody moves a token into a query string.
		return c.scrubbed(fmt.Errorf("courier: the request did not complete: %w", err))
	}
}

// scrubbed runs a string this package built past the credential check.
//
// All or nothing, and never a partial replacement: a scrubber that returns the
// rest is a scrubber whose safety depends on the completeness of a list nobody can
// check, and the honest failure mode of an incomplete list here is a token in
// somebody's log store.
func (c *Client) scrubbed(err error) error {
	if err == nil || !c.scrub(err.Error()) {
		return err
	}
	return errors.New("courier: [redacted: the string contained this client's credential]")
}

// validate refuses everything this client can know is wrong before the wire.
//
// The three checks are courier's own rules, read from its document, and each one
// is here rather than discovered as a 422 because by the time courier answers, a
// recovery token has been minted, its digest written, and the caller has been told
// a message is on its way.
func validate(req MessageRequest) error {
	if !IsType(req.Type) {
		return fmt.Errorf("%w: %q is not a type courier sends", ErrInvalidRequest, req.Type)
	}
	if req.To == "" {
		return fmt.Errorf("%w: no recipient", ErrInvalidRequest)
	}
	if !isUUID(req.UserID) {
		// Checked for shape and nothing else, exactly as courier checks it: courier
		// holds no foreign key to identity's users, so there is nothing else to
		// check against — and a value identity itself produced is a uuid by
		// construction, so a failure here is a bug rather than a bad address.
		return fmt.Errorf("%w: %q is not a user id courier can key a preference by",
			ErrInvalidRequest, req.UserID)
	}
	if req.Type == TypePasswordReset && req.URL == "" {
		// courier's `password_reset` template renders the link, so a reset mail
		// with no link is a mail nobody can use, and it is refused here rather than
		// delivered.
		return fmt.Errorf("%w: a %s needs the link it carries", ErrInvalidRequest, req.Type)
	}
	return nil
}

// IsType reports whether a type is one courier's document declares.
//
// Exported because `RecoveryMailer`'s mapping and its refusals both have to know
// the vocabulary, and because a second place in this package deciding it would be
// a second list.
func IsType(t string) bool {
	switch t {
	case TypeWelcome, TypePasswordReset, TypeTeamInvitation:
		return true
	default:
		return false
	}
}

// validateResult refuses a 200 this client cannot read as an accepted send.
//
// A reader that checks nothing here reports "sent" for a body with no message id
// in it, and a caller that believes a message was sent when courier did not
// identify it cannot tie a bounce back to anything.
func validateResult(got MessageResult) error {
	switch {
	case got.MessageID == "":
		return fmt.Errorf("%w: courier answered a send with no message id", ErrMalformedResponse)
	case got.EventID == "":
		return fmt.Errorf("%w: courier answered a send with no event id", ErrMalformedResponse)
	case got.Status == "":
		return fmt.Errorf("%w: courier answered a send with no status", ErrMalformedResponse)
	}
	return nil
}

// Error is courier's refusal, made printable without leaking anything courier said
// verbatim.
//
// courier's `detail` is prose written for whoever reads the response, and one of
// its refusals is a sentence explaining that somebody's mailbox hard-bounced. This
// package is a platform mail path whose errors end up in a log aggregator, so
// `detail` is not carried here at all: the trace id is, and that is precisely the
// handle courier's own document offers for finding the cause in its logs.
//
// It is ONE type with an unexported sentinel rather than a type per case, for the
// reason the sentinels above give: the caller branches, and `errors.Is` is the
// branch.
type Error struct {
	// Op is `send` or `probe`, so a reader of a log line can tell a failed delivery
	// from a failed readiness check without parsing prose.
	Op string

	// Status is the HTTP status courier answered, or 0 when no status was read.
	Status int

	// Code is courier's `code` — the contract its document tells clients to branch
	// on. `codeUnreadable` when the body was not a problem document.
	Code string

	// TraceID is courier's, and is the only handle a reader gets on what happened
	// inside courier.
	TraceID string

	// Fields is courier's `errors[]`, which core reserves for a 422.
	Fields []FieldError

	// retry records whether courier's own document says another attempt can help.
	// It is a field rather than a method so that `%#v` — which is what a
	// structured logger prints — carries the answer with it.
	retry bool

	// sentinel is what `errors.Is` matches, and cause is what `errors.Unwrap`
	// returns when there is one. Both unexported: there is no other way to set
	// them, so a courier error can only be built by a path that decided.
	sentinel error
	cause    error
}

// Error is the message a human reads, and it is assembled from a fixed vocabulary
// rather than from anything courier sent.
//
// The reason is the one `client/redact.go` gives and the one `transportError`
// applies: an `Error()` string is the single most likely thing in a process to end
// up in a log aggregator, and this service's mail path holds live reset tokens.
// `Code`, `TraceID` and the field names are courier's bounded enums.
func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString("courier: ")
	b.WriteString(e.Op)
	if e.Status != 0 {
		b.WriteString(" refused with ")
		b.WriteString(statusText(e.Status))
	}
	if e.Code != "" {
		b.WriteString(", code ")
		b.WriteString(e.Code)
	}
	if len(e.Fields) > 0 {
		b.WriteString(", fields ")
		b.WriteString(fieldsString(e.Fields))
	}
	if e.TraceID != "" {
		b.WriteString(", courier trace ")
		b.WriteString(e.TraceID)
	}
	if e.cause != nil {
		b.WriteString(": ")
		b.WriteString(e.cause.Error())
	}
	return b.String()
}

// Unwrap makes `errors.Is` work against the sentinel and the cause.
func (e *Error) Unwrap() error {
	if e.cause != nil {
		return e.cause
	}
	return e.sentinel
}

// Is reports whether this error matches one of this package's sentinels, so
// `errors.Is` reads the same against a courier error and against a bare one.
func (e *Error) Is(target error) bool { return target == e.sentinel }

// Retryable reports whether trying again can help.
//
// It is a function over the error and not a field a caller reads, so that the
// question has exactly one answer: courier's own promise that a 503 released its
// `Idempotency-Key` and wrote no row, that a 409 does not, and that a credential
// courier will not take will not be taken on a second attempt.
func Retryable(err error) bool {
	var refused *Error
	if errors.As(err, &refused) {
		return refused.retry
	}
	// A malformed 2xx is deliberately NOT retryable: this client cannot tell
	// whether the first attempt sent anything, and a second attempt is how a user
	// gets two reset mails for one request.
	return errors.Is(err, ErrTimeout)
}

// normaliseBaseURL validates and canonicalises courier's address.
//
// It strips a trailing slash because `baseURL + path` is how every request is
// built, and a base URL with a trailing slash produces a path with two slashes in
// it — which some routers answer and some redirect, and a redirect on a POST loses
// the body on some clients.
func normaliseBaseURL(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", ErrNoBaseURL
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("%w: %q is not a URL", ErrNoBaseURL, trimmed)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("%w: %q is not an http or https URL", ErrNoBaseURL, trimmed)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("%w: %q has no host", ErrNoBaseURL, trimmed)
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		// A base URL with a query string is a base URL somebody is about to
		// concatenate a path onto, and the result is a request whose query this
		// client did not write.
		return "", fmt.Errorf("%w: %q has a query or a fragment", ErrNoBaseURL, trimmed)
	}
	return strings.TrimRight(trimmed, "/"), nil
}

// statusOf reads a status, tolerating a nil response.
func statusOf(resp *http.Response) int {
	if resp == nil {
		return 0
	}
	return resp.StatusCode
}

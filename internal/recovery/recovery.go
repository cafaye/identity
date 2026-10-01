// Package recovery owns the three flows that a person can only finish by proving
// they can read an email inbox: resetting a password, changing the address on an
// account, and verifying that address.
//
// # WHY ONE PACKAGE
//
// Because they are one machine, not three features. Each of them mints a
// 256-bit random value, stores nothing but its SHA-256, mails it to an address,
// and spends it with a conditional UPDATE that makes a second presentation a
// refusal. That lifecycle — mint, store a digest, deliver, expire, single-use — is
// implemented once here, and the three flows are three different things done with
// a row of `recovery_tokens` plus a different set of writes at the end.
//
// Splitting them would give three packages each with its own token format, its own
// expiry arithmetic and its own answer to "is this token live", which is the same
// three-way drift this repository treats as a defect everywhere else.
//
// # WHAT THE THREE FLOWS SHARE, AND WHERE THEY DIVERGE
//
//	password_reset  request -> redeem -> new password, every session revoked
//	verify_email    request -> redeem -> email_verified_at set
//	email_change    request -> confirm the CURRENT address
//	                          -> a second token is minted and mailed to the NEW
//	                          -> confirm it -> the address moves, sessions revoked
//
// The email change is the only one with two sides, and the second side is minted
// ONLY after the first is confirmed. That is the whole of the hijack property: a
// stolen session can start an email change, and what it produces is a link in the
// victim's inbox and nowhere else. The attacker cannot advance the request, and
// the victim gets a message saying their address is being changed, which is the
// only warning they would otherwise get.
//
// # THE DELIVERY SEAM
//
// Nothing in this package talks to an SMTP server, an MTA, or courier's HTTP API.
// Every message goes through `Mailer`, one method, declared here at the consumer
// for the reason every other dependency in this repository is: the flows can be
// exercised against a recording double, and the delivery path is somebody else's
// problem to finish.
//
// The production implementation is `internal/courier`, which speaks courier's
// `POST /v1/messages`, and the seam is declared HERE so that this package gains no
// import of it, no knowledge of courier's type vocabulary, and no field on `Message`
// naming anything courier needs. `Message` grew exactly one field for that adapter
// and its type comment says why it is a fact about the recipient rather than a
// rendering decision.
//
// `Unavailable` is what main wires for a deployment that has not configured
// courier, and it is still here rather than deleted: absent `COURIER_TOKEN` is a
// SUPPORTED state, and the honest shape of it is a seam that FAILS. Every path
// that needs to send mail returns ErrNoMailer and the HTTP layer answers 503 with a
// sentence naming the problem. That is deliberately not a mailer that logs its
// messages — a reset token in an operator's log aggregator is a reset token
// anybody who can read the logs can redeem.
//
// The failure is checked BEFORE the token is minted, which is also what keeps the
// request endpoint from becoming an account-existence oracle: a deployment that
// cannot send mail stops a request for a registered address and a request for an
// unregistered one at the same place, before either has learned whether the account
// exists. `internal/courier`'s flow tests hold that property with a real Mailer and
// a real database, because a courier that is reachable but down must fail in the
// same place — an unconfigured deployment is not the only way to have no delivery
// path.
//
// # WHAT IS DELIBERATELY NOT HERE
//
//   - No rate limiter. `RequestWindow` is a per-address cooldown over a column
//     this table already has, and it bounds mail to one message per address per
//     window. It is not a rate limiter, it is not per-client, and a deployment
//     that needs one needs courier's, not a second one invented here.
//   - No sweeper for expired rows. `recovery_tokens_expires_at_idx` exists so the
//     job is one statement when somebody wants it; an expiry filter in the read
//     query is what makes an unswept row harmless in the meantime.
//   - No templates outside `Message`, and no message is ever logged, ever.
package recovery

import (
	"context"
	"errors"
	"time"

	"github.com/cafaye/identity/internal/platform/id"
	"github.com/cafaye/identity/internal/users"
)

// Purpose is what a row of `recovery_tokens` is for.
//
// IT IS A CLOSED SET IN GO AND A CHECK IN THE SCHEMA, for the reason 00011 gives
// for api_keys.scopes: a closed vocabulary is a code fact, and putting it in the
// schema would make adding a purpose a migration. The CHECK is a second opinion,
// and a row naming a purpose this build does not know about is refused on the way
// in — which is the fail-closed direction, since treating an unknown purpose as
// "and so anything goes" is the bug a later migration would otherwise introduce
// silently.
type Purpose string

const (
	// PurposePasswordReset is a token that changes a password.
	PurposePasswordReset Purpose = "password_reset"

	// PurposeVerifyEmail is a token that marks the account's own address proved.
	//
	// It verifies the address ON THE ROW, never an address the caller supplies.
	// A token that verified whatever address the request carried would be a
	// registration of somebody else's inbox.
	PurposeVerifyEmail Purpose = "verify_email"

	// PurposeEmailChange is a token that moves the account to a new address, in
	// two confirmed halves.
	//
	// It is the only purpose carrying a target, and the schema says so with a
	// CHECK rather than a convention.
	PurposeEmailChange Purpose = "email_change"
)

// TTLs. Three windows and three judgements, because the three tokens are worth
// different amounts to whoever holds them.
const (
	// PasswordResetTTL is thirty minutes.
	//
	// Long enough for an email that is delayed, mis-delivered or sitting in a
	// spam folder, and short enough that a link found in a mailbox years later is
	// not a live credential. Thirty is the middle of what the products this
	// service is measured against publish, and the thing it is protecting against
	// — a reset link sitting in a forwarded thread — is not really bounded by this
	// number at all.
	PasswordResetTTL = 30 * time.Minute

	// VerifyEmailTTL is twenty-four hours.
	//
	// MUCH LONGER THAN THE OTHER TWO, and deliberately: a verification is not a
	// credential, it is a fact about an address, and the token only ever sets a
	// boolean. Nothing is at risk while it waits, and a user who signs up on a
	// Monday and clicks the link on Tuesday morning must not find it dead. The
	// cost is a row that lives a day.
	VerifyEmailTTL = 24 * time.Hour

	// EmailChangeTTL is twenty-four hours for each half.
	//
	// Two hops and a person in the middle: somebody decides to move their address
	// and then has to find a link in one inbox and a second link in another. The
	// two halves share one expiry rather than each getting their own clock, so a
	// change cannot be kept alive indefinitely by confirming the first half over
	// and over.
	EmailChangeTTL = 24 * time.Hour

	// RequestWindow is the minimum time between two tokens of the same purpose
	// for the same account.
	//
	// THIS IS A COOLDOWN AND NOT A RATE LIMITER, and the difference is the whole
	// of what it buys. It stops the obvious abuse — an anonymous endpoint that
	// turns into a mail cannon pointed at one victim — because a request inside
	// the window mints nothing and sends nothing and answers exactly as a request
	// outside it does. It does nothing about a flood spread across a thousand
	// addresses, and it is not per-client: identity has no client identity to
	// count, and inventing one (an IP counter) would be a rate limiter built from
	// scratch, which is the thing this repository does not do without a cause on
	// record. Per-source throttling belongs to courier, which is in the path of
	// every message this service sends.
	//
	// A minute is short enough that a user who lost the first email presses the
	// button again almost immediately, and long enough that a double-tap does not
	// mail them twice.
	RequestWindow = time.Minute
)

// TTLFor is a purpose's window. It is a function rather than three exported
// constants read at the call site because the call sites are the use cases, and a
// use case that picked its own window would be a use case that could pick a
// different one on a different day.
func TTLFor(p Purpose) time.Duration {
	switch p {
	case PurposeVerifyEmail, PurposeEmailChange:
		return VerifyEmailTTL
	default:
		return PasswordResetTTL
	}
}

// Errors the flows return. A caller matches them with errors.Is; nothing here is
// compared by string.
var (
	// ErrTokenNotFound means no live token matched what was presented.
	//
	// IT COVERS FOUR CASES AND THE HTTP LAYER MUST NOT TELL THEM APART: a token
	// that never existed, one that has expired, one that has already been spent,
	// and one minted for a different purpose. That last one is the reason this is
	// a single error rather than a family: a password-reset token is an opaque
	// 256-bit value and the endpoint it is presented to is chosen by the caller,
	// so "that token belongs to another flow" is not a fact anybody outside this
	// service is entitled to.
	//
	// It maps to 404 rather than 401. The caller is not asking who they are; they
	// are presenting a link, and the honest answer to a link that does not work is
	// "there is no such link", which is also what a caller learns about every other
	// link they did not receive.
	ErrTokenNotFound = errors.New("no live recovery token matches that")

	// ErrNoMailer means this deployment cannot deliver a message.
	//
	// IT IS ITS OWN SENTINEL rather than a wrapped transport error, because the
	// HTTP layer's answer to it is not a 500: it is a 503 with a sentence naming
	// the deployment problem, for the reason `mfa.ErrNoVault` is. A user told
	// only "try later" retries forever, and an operator told `internal` goes
	// looking for a database problem that is not there.
	ErrNoMailer = errors.New("this deployment cannot send email")

	// ErrEmailTaken means the address an email change is moving to already has an
	// account. It is the one refusal on this surface a caller is entitled to: they
	// are authenticated as the person asking, and the alternative is a change that
	// fails at the last step, after two emails and two clicks.
	//
	// IT IS THE `users` SENTINEL RE-EXPORTED, NOT A SECOND RULE, and the alias is
	// deliberate. "One account per address" is `users`' property — it is the UNIQUE
	// index on users.email — so a distinct value here would be a second name for one
	// fact, and `errors.Is` between the two would be false, which is exactly the
	// kind of near-miss this repository keeps spending paragraphs on. The HTTP
	// layer matches this name; the rule belongs to the table that enforces it.
	ErrEmailTaken = users.ErrEmailTaken

	// ErrSameAddress means an email change was asked for the address already on the
	// row. It is refused rather than treated as a no-op because the request
	// described a move, and a "no-op" 202 would leave a caller believing an
	// address change had been requested and confirmed.
	ErrSameAddress = errors.New("that is already this account's address")

	// ErrAlreadyVerified means the account's address has already been proved. A
	// request for another verification link is refused rather than silently
	// ignored, because a client rendering "we have emailed you" on the strength of
	// a 202 it should never have been given is a client that tells a user to check
	// an inbox that is never going to receive anything.
	ErrAlreadyVerified = errors.New("this account's email address is already verified")
)

// Message is one email, and it is the whole of what leaves this process.
//
// IT IS A VALUE WITH NO TEMPLATE NAME, and that is the property worth reading: the
// subject and the body are already rendered by the time anything else sees this
// struct, so there is no code path where a delivery adapter chooses what the mail
// says and no code path where a body is built with a token in one branch and
// without it in another.
//
// A message carries no template identifier and no layout, deliberately. The moment
// this type grows a `Template` field, identity has taken courier's rendering
// decisions, and the two will disagree.
//
// # WHY THERE IS ONE FIELD THAT IS NOT PROSE, AND WHY IT IS NOT A `Template`
//
// `UserID`, and a reader will reasonably assume the rule above forbids it. The
// distinction is the difference between a RENDERING decision and a FACT about the
// recipient, and it is worth being exact about because both are fields on this
// struct.
//
// A `Template` field would be a rendering decision — "use layout 3", "use the HTML
// variant" — and identity would then be a second opinion about how a mail looks,
// disagreeing with the service that renders it. `UserID` is not that. It says WHICH
// ACCOUNT the message is about, and a platform mailer needs that for reasons with
// nothing to do with prose:
//
//   - courier reads that recipient's notification preferences by it, so a send
//     without one cannot be checked against a decline;
//   - it is what the `courier.email.delivered` event is attributed to, so a bounce
//     can be traced back to the account it concerned.
//
// Naming the account by ADDRESS would be worse than useless for both. An address
// changes — that is the entire point of the email-change flow two files over — and
// a preference table and a suppression list are keyed by an opaque id. Every body
// here names the address in prose because a PERSON reads it; none carries a uuid
// because a person has no use for one.
//
// So this is a fact every flow in this package already held. It was not on the
// struct because no implementation needed it, and adding it is the composition the
// delivery seam needed rather than a widening of the `Mailer` interface: `Send`
// still takes one argument and returns one error, and no implementation learns
// about courier.
type Message struct {
	// To is the normalised address the message goes to.
	To string
	// Subject and Body are the rendered text. Body is plain text on purpose: it is
	// the body a courier adapter can hand to any provider, and an HTML body is a
	// rendering decision courier's packet owns.
	Subject string
	Body    string

	// UserID is the account this message concerns, and it is never rendered.
	//
	// IT MAY BE THE ZERO VALUE, and that is not an error here: this package has no
	// provider to be unfriendly to, and a test double has no use for an id. An
	// implementation that requires one MUST refuse rather than guess — attributing a
	// message that contains a live credential to an account nobody chose is worse
	// than not sending it.
	UserID id.UUID
}

// Mailer hands one rendered message to the platform's mail service.
//
// ONE SEAM, TWO METHODS, and the second one is not padding. `Ready` exists because
// every request flow has to know whether a message CAN be delivered BEFORE it
// decides to mint a token, and the reason it has to know is the enumeration
// property: a deployment that cannot send mail has to refuse a reset request for a
// registered address and a reset request for an unregistered one at the same
// place, or "503" against "202" becomes an account-existence oracle. Asking the
// seam is honest about what it knows; a `mailer != Unavailable{}` type assertion
// in three flows is not.
//
// An implementation MUST NOT log a message, and the reason is the token in the
// body. Every message this package produces contains a live credential until it is
// spent, and an operator's log aggregator is searchable, retained, and usually
// readable by everybody who can read a deployment's metrics.
type Mailer interface {
	// Send delivers one rendered message.
	//
	// It takes a rendered `Message` rather than a template name and a set of
	// variables so that an implementation cannot get the content wrong in a way this
	// package cannot see: everything a caller could have written into a mail is
	// already a string here.
	Send(ctx context.Context, m Message) error

	// Ready reports whether Send could succeed right now, and why not if it could
	// not.
	//
	// IT MUST NOT SEND ANYTHING, and it must be cheap: it is called on the
	// anonymous request path before any credential is minted, so an implementation
	// that performed a real delivery here would mail an empty message on every
	// password-reset request anybody ever asked for.
	Ready(ctx context.Context) error
}

// Unavailable is the Mailer a deployment with no delivery path has.
//
// IT FAILS LOUDLY AND IT FAILS EVERY TIME, which is the whole of its design. The
// tempting alternative — a logger, or a nil check somewhere further up — produces
// a service that tells a user their password reset is on its way and drops the
// message on the floor, and a user who believes a reset was sent and was not is a
// user who does not ask a human for help.
//
// It is a struct rather than a nil Mailer so that no caller has to decide whether
// a nil is a supported configuration, and `main` cannot wire a process in which
// the flows are mounted and silent.
//
// # IT IS STILL REACHABLE, AND THAT IS THE REASON TO KEEP IT
//
// A courier-backed implementation exists, so the obvious question is why this one
// is not deleted. Because a deployment with no `COURIER_TOKEN` is a SUPPORTED
// state — a local stack, or one where mail has not been turned on — and the honest
// shape of "this deployment cannot send email" is a seam that refuses rather than a
// `nil` that panics, a logger that leaks the token, or a `courier.Client` built
// from an empty credential that would present nothing and get a 401 per send.
//
// `TestAMailerIsCouriersOrUnavailableAndNothingElse` in `cmd/identity` holds that
// these are the only two things `buildMailer` can return, so an "unavailable" a
// reader cannot reach is not hiding here.
type Unavailable struct{}

// Send returns ErrNoMailer.
func (Unavailable) Send(context.Context, Message) error { return ErrNoMailer }

// Ready returns ErrNoMailer.
func (Unavailable) Ready(context.Context) error { return ErrNoMailer }

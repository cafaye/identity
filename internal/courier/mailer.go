package courier

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/cafaye/identity/internal/recovery"
)

// # WHY A `recovery.Mailer` LIVES IN THE COURIER CLIENT RATHER THAN THE OTHER WAY
//
// ROUND
//
// It is not a preference. The `Mailer` interface is DECLARED IN `internal/recovery`,
// at the consumer, and every other rule in this repository is a consequence of that
// choice: `recovery` names what a message is (a recipient and some rendered text)
// and never names what delivers it. A `recovery.Mailer` implemented here rather
// than there is that rule applied to the mail path — `recovery` gains no import of
// courier, no knowledge of a `type` enum, and no field on `Message` for a URL.
//
// The whole adapter is below `NewRecoveryMailer` and it is small, which is the
// point: a translation table, a refusal, and a log line.

// ErrUnsupportedMessage means identity rendered a message courier has no type for.
//
// IT IS ITS OWN SENTINEL RATHER THAN A 422 COURIER ANSWERED, because the client
// refuses to send rather than to send and be told. TWO of `recovery`'s four
// messages have no courier equivalent:
//
//	email_change (current)  no courier template describes a change confirmation
//	email_change (new)      no courier template describes a change confirmation
//
// The refusal is the decision this packet is most careful about, and the reasoning
// belongs on the mapping below rather than here. What belongs HERE is the property
// that makes it safe: the failure happens before the wire, so no token is in a
// body courier will render, and the caller is told a deployment is missing a
// capability rather than that a mailbox refused.
//
// The alternative was weighing rather than skipping. Mapping
// `email_change_current` onto courier's `password_reset` would be one line and
// would put "Somebody asked to reset the password on your account" into the only
// message a hijacked session cannot get past — a message whose entire value is
// that it warns an account owner that somebody is moving their address. A
// wrong-but-delivered security notice is worse than a loud failure, and the
// failure mode here is a 503 an operator can read.
var ErrUnsupportedMessage = errors.New("courier: courier cannot send this message")

// recoveryKinds are the four messages `internal/recovery` renders, spelled the way
// this package needs to name them.
//
// THEY ARE DECLARED HERE RATHER THAN READ FROM `recovery` because
// `recovery.messageKind` is unexported, and un-exporting it is a decision
// `internal/recovery` makes for a good reason: a delivery adapter must not be able
// to switch on it and become a second place that knows what a message is. So
// `RecoveryMailer` matches on a field `recovery` does not have, and the mapping
// below is the ONLY place in the repository that knows both vocabularies.
//
// The test that holds the two in agreement is
// `TestEveryMessageRecoveryRendersIsAccountedFor`, and it reads
// `internal/recovery/message.go` and fails when the four bodies there are not the
// four subjects here.
const (
	kindPasswordReset = "Reset your cafaye password"
	kindVerifyEmail   = "Confirm your cafaye email address"
	kindChangeCurrent = "Confirm an email address change"
	kindChangeNew     = "Confirm your new cafaye email address"
)

// knownSubjects is every message `internal/recovery` renders, and the set is
// declared HERE rather than derived from `courierTypeFor` because the two answer
// different questions. `courierTypeFor` is "which of these can courier send"; this
// is "which of these exist", and the difference between the two is two refused
// messages that a reader needs to see enumerated rather than infer from an absent
// map entry.
//
// `TestEveryMessageRecoveryRendersIsAccountedFor` walks this set against
// `internal/recovery/message.go` in both directions, so a fifth message cannot be
// added to that package and left invisible here.
var knownSubjects = map[string]struct{}{
	kindPasswordReset: {},
	kindVerifyEmail:   {},
	kindChangeCurrent: {},
	kindChangeNew:     {},
}

// courierTypeFor is the whole of the translation: `recovery`'s message → courier's
// `NotificationType`.
//
// IT IS A MAP AND NOT A SWITCH, and the reason is that a switch would need a
// default branch and the default is the dangerous direction. A message kind that
// is not in this table is REFUSED, and a new body in `internal/recovery` — somebody
// adding a fifth message for a two-factor enrolment, say — cannot be delivered by
// accident through a fallback that guessed. `RecoveryMailer.Send` returns
// `ErrUnsupportedMessage` for it and the flow answers 503.
//
// # AND WHY `welcome` IS HONEST FOR `verify_email` AND NOT FOR ANYTHING ELSE
//
// courier's `NotificationType` is `[welcome, password_reset, team_invitation]`.
// There is no `email_verification`, and inventing one is a 422, so the question
// this table answers is which of courier's THREE messages an unverified account's
// address confirmation is.
//
// TWO of `recovery`'s four messages map and two are refused, and the line is not
// drawn at "which words are close enough" — it is drawn at "would courier's own
// template say the true thing to the person reading it".
//
// **`verify_email` → `welcome` IS TRUE.** courier's template reads, in full:
//
//	<%= @greeting %>
//
//	Welcome aboard. Confirm your address and you are in.
//	<%= if @url do %>
//	Confirm your email address: <%= @url %>
//	<% end %>
//
// That is a registration's address confirmation, and it renders `@url` — which
// is where the token goes. `recovery.RequestVerification` refuses with
// `ErrAlreadyVerified` for an account that has already proved its address, so
// this message only ever reaches an account that has never proved one, which is
// what the template's words describe. It is courier's own copy about courier's
// own event, not identity's prose forced through courier's mouth.
//
// **THE DOCUMENT IS WRONG ABOUT ONE THING, AND THE CODE IS RIGHT.** courier's
// `openapi.yaml` says `url` is "unused by `welcome`", and its
// `welcome.text.eex` renders `@url` when it is present. The document
// under-describes its own template; `Courier.Mailers.required/1` requires only
// `email` for a `welcome`, so sending one WITH a url is legal and the link
// appears. `TestAVerificationLinkReachesCouriersWelcomeTemplate` pins the
// request shape that relies on it, so a courier that changed the template would
// be a test failure here rather than a mail with no link in it.
//
// THE COST, STATED BECAUSE IT IS REAL: `welcome` is a shared notification type, so
// courier keys a user's PREFERENCE for it — a user who turned `welcome` off would
// also stop being able to confirm an address. `ErrDeclined` is the refusal that
// answers for it, and identity conceals it from an anonymous caller, so the
// observable effect is that address verification silently stops working for that
// one user. That is courier's vocabulary being narrower than identity's, and the
// fix is a fourth type in courier rather than a workaround here.
//
// **THE TWO `email_change` MESSAGES ARE NOT.** There is no courier message about
// an address change, and the two templates that exist both say something false
// about one: `password_reset` tells the owner somebody asked to reset their
// password, and `welcome` says "Welcome aboard" to an account owner being told
// that a hijacked session is moving their address. The current-address half is
// the ONLY warning the owner of an account has that somebody is moving its
// address — a wrong-but-delivered security notice is worse than a loud failure,
// and this is the loud one.
var courierTypeFor = map[string]string{
	kindPasswordReset: TypePasswordReset,
	kindVerifyEmail:   TypeWelcome,
}

// linkPurposeFor is the subject → purpose mapping, and it exists because THE LINK
// IS CONFIGURED PER PURPOSE RATHER THAN ONCE FOR EVERY MESSAGE.
//
// # THE SINGLE TEMPLATE WAS DEFENDED AT LENGTH AND WAS WRONG FOR HALF ITS USES
//
// `RecoveryMailer` held ONE `LinkTemplate` for all four of its messages, and the
// argument for it is sound FOR A RECOVERY LINK: a template with `{token}` beats a
// base URL plus a platform-chosen convention, and `ValidateLinkTemplate` refuses a
// template that cannot render a working link. That argument was then applied to a
// VERIFICATION link, which is not a recovery link.
//
// The result was a `welcome` mail whose button said
// `https://app.example.com/reset?token=…`, so a user who clicked "Confirm your
// email address" landed on the password-reset screen, where a verification token
// answers **404**. The token was fine — it redeemed at
// `POST /v1/email-verifications/confirm`, and identity-24 proved that end to end
// against a real courier. The mail was well-formed, passed every assertion in the
// repository, and sent the user somewhere useless, which is why it survived: every
// test was about the BYTES and the bytes were correct.
//
// So one template for two purposes is a template that must be wrong for one of them,
// and the wrongness survives review because a link template looks like a link
// template whatever it points at. The purpose is what says which screen it should
// be, and the purpose is what the configuration is keyed by now.
//
// # IT IS A SECOND TABLE AND NOT A COLUMN OF `courierTypeFor`, and the two are HELD
// IN STEP
//
// `courierTypeFor` answers "which of courier's three messages can express this" and
// `linkPurposeFor` answers "what is the token in it for". They are different
// questions with different answers over time — a courier type is courier's
// vocabulary, a purpose is `recovery`'s, and the two diverge the moment courier
// grows an `email_verification` type of its own — so merging them into one struct
// would make a change to either a change to both, and would have this package
// holding a vocabulary it does not own.
//
// Nothing in the type system joins them, which is why
// `TestEveryPurposeThisAdapterCanDeliverHasAVariableToConfigureItsLink` walks both
// sets against `internal/config`'s in both directions.
var linkPurposeFor = map[string]recovery.Purpose{
	kindPasswordReset: recovery.PurposePasswordReset,
	kindVerifyEmail:   recovery.PurposeVerifyEmail,
}

// RecoveryMailer is courier's implementation of `recovery.Mailer`.
//
// IT HAS NO CREDENTIAL FIELD, for the same reason `Client` has none: the
// credential is a closure inside the `Client`, and this struct holds the client
// rather than the token.
type RecoveryMailer struct {
	client *Client

	// linkTemplates renders the URL each message's purpose carries.
	//
	// IT IS CONFIGURED RATHER THAN DERIVED, and that is a real decision. courier's
	// `password_reset` template renders a link and its document REQUIRES `url` for
	// that type, so a reset mail has to have one — but this service does not know
	// where a product puts its reset screen, and inventing a path here would put
	// identity's guess into every reset link on the platform. So a deployment says
	// what its links look like and this renders them, one per purpose.
	//
	// IT IS A MAP AND NOT A FIELD, so a purpose cannot be handed a template written
	// for a different one. A single field is what let a verification mail inherit a
	// reset link in the first place, and no individual assignment in it was wrong —
	// the shape simply had nowhere to say otherwise.
	linkTemplates LinkTemplates

	// logger takes the refusals. IT MAY BE NIL, and a nil logger is a refusal
	// logged nowhere rather than a panic: `main` always passes one, and a test does
	// not have to.
	logger *slog.Logger

	// now is read for nothing but the log line's duration field, and it is a func
	// so a test can pin it. It is not a clock the adapter depends on for any
	// decision.
	now func() time.Time
}

// LinkTemplate is how a deployment says what a link looks like.
//
// IT IS A TEMPLATE WITH ONE PLACEHOLDER RATHER THAN A BASE URL, because a base URL
// is only half the answer: a product might want `…/reset?token=…`, a path segment,
// or a URL with the token somewhere else entirely, and a base-URL-plus-convention
// implementation picks a convention on the platform's behalf.
//
// The placeholder is `{token}` and it is REQUIRED, and "required" is checked at
// construction: a template with no placeholder produces a link that reaches a
// screen with no token on it, which is a mail a user can follow and cannot use.
// Failing at construction means the deployment is broken at boot rather than at a
// user's first password reset.
//
// IT SAYS WHAT A LINK LOOKS LIKE AND NOT WHAT A RECOVERY LINK LOOKS LIKE, because the
// second is narrower than the type is: a verification link is not a recovery link.
// The wording was one of the things that let a single template pass for a decision.
type LinkTemplate string

// LinkTemplates is a deployment's per-purpose link templates.
//
// THE KEY IS `recovery.Purpose` RATHER THAN courier's `NotificationType`, and rather
// than a subject, for one reason: it is the vocabulary that says what redeeming the
// token DOES, which is the thing that decides which screen the link belongs on.
// Keying it by a courier type would have made this package depend on the narrower of
// the two mappings above — the one where an address confirmation is a registration —
// and would have made the purpose a derived fact of a delivery decision.
type LinkTemplates map[recovery.Purpose]LinkTemplate

// TokenPlaceholder is what a link template must contain.
const TokenPlaceholder = "{token}"

// ValidateLinkTemplate refuses a template this package cannot render a working
// link from.
//
// THREE REFUSALS, and each is a link that does not work rather than a style
// opinion: a template with no `{token}` (a link with no credential on it), one
// that is not an absolute URL (courier's schema says `format: uri`, and a
// relative one cannot be rendered in a mail), and one with a query or a fragment
// in the template itself rather than in the substitution (the token would land
// somewhere the deployment did not intend).
//
// IT IS CALLED ONCE PER PURPOSE RATHER THAN ONCE PER MAILER, and `resolveLinkTemplates`
// is the only caller. The rule is a property of a template, so every template gets
// it — one template validated once used to mean four messages covered by accident
// of there being one of it, and a rule applied to one purpose and not the next is
// the same class of defect as the one this package exists to have fixed.
func ValidateLinkTemplate(raw string) (LinkTemplate, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", errors.New("courier: the link template is empty")
	}
	if !strings.Contains(trimmed, TokenPlaceholder) {
		return "", fmt.Errorf("courier: the link template has no %s in it, "+
			"so the link a user follows would carry no token", TokenPlaceholder)
	}
	// The placeholder is replaced by a uuid before courier sees the URL, so
	// validation is done against a stand-in that is the right SHAPE: a real uuid
	// rather than the literal `{token}`, which is not a valid character in a URI
	// and would make this check pass for a template courier rejects.
	probe := strings.ReplaceAll(trimmed, TokenPlaceholder,
		"6f5d4c3b-2a19-4e8f-9c07-1b2d3e4f5061")
	if err := checkAbsoluteHTTPURL(probe); err != nil {
		return "", fmt.Errorf("courier: the link template: %w", err)
	}
	return LinkTemplate(trimmed), nil
}

// errNoToken means a link was asked for with no credential in it.
//
// IT IS A SENTINEL rather than a formatted string so `recovery`'s side of the
// boundary can match it with `errors.Is` rather than reading a message, and it is
// wrapped in `ErrInvalidRequest` at every call site because that is the class the
// HTTP layer and the flows treat as "this is our bug, not the deployment's".
var errNoToken = errors.New("courier: refusing to render a link with no token")

// render substitutes a token into the template.
func (l LinkTemplate) render(token string) (string, error) {
	if token == "" {
		return "", errNoToken
	}
	if !strings.Contains(string(l), TokenPlaceholder) {
		// Unreachable through `NewRecoveryMailer`, which validates. Checked anyway
		// because the consequence of being wrong is a mail whose link does not
		// work, and the user has just been told it does.
		return "", errors.New("courier: the link template has no placeholder in it")
	}
	return strings.ReplaceAll(string(l), TokenPlaceholder, token), nil
}

// RecoveryMailerConfig is what NewRecoveryMailer needs.
type RecoveryMailerConfig struct {
	// Client is the courier client, and its credential comes with it. Required.
	Client *Client

	// LinkTemplates is what each purpose's link looks like.
	//
	// EVERY PURPOSE THIS ADAPTER CAN DELIVER MUST BE IN IT. There is no default and
	// no fallback, and the reason is the defect this shape replaced: a template for
	// one purpose serving another is a well-formed mail whose button leads to a 404,
	// and every test about the request still passes. So a purpose with no template
	// is a REFUSAL at construction, naming the purpose.
	//
	// The DEFAULT lives one layer up, in `internal/config`, because that is where
	// the backwards-compatibility question is: a deployment configured before the
	// per-purpose variables existed has one template, and `config` is what knows how
	// to apply it to every purpose without this package inventing a second answer to
	// "where does this link point".
	LinkTemplates map[recovery.Purpose]string

	// Logger takes the refusals. May be nil.
	Logger *slog.Logger
}

// NewRecoveryMailer builds courier's `recovery.Mailer`.
//
// IT VALIDATES EVERY LINK TEMPLATE HERE, at construction, for the reason
// `ValidateLinkTemplate` gives: a deployment with a template courier would reject
// is broken at boot rather than at a user's first password reset. That is the same
// rule `OIDC_SIGNING_KEY` follows, and the same rule the house rule "present but
// unparseable is a startup failure" exists to enforce.
//
// IT ALSO REFUSES A PURPOSE WITH NO TEMPLATE, and that is the rule this packet
// added. Every other validation here is about a link that is malformed; this one is
// about a link that is ABSENT, which is the state identity-24 found a verification
// mail reaching a user's screen in the wrong shape of answer.
func NewRecoveryMailer(cfg RecoveryMailerConfig) (*RecoveryMailer, error) {
	if cfg.Client == nil {
		return nil, errors.New("courier: no client to send with")
	}
	templates, err := resolveLinkTemplates(cfg.LinkTemplates)
	if err != nil {
		return nil, err
	}
	return &RecoveryMailer{
		client:        cfg.Client,
		linkTemplates: templates,
		logger:        cfg.Logger,
		now:           time.Now,
	}, nil
}

// resolveLinkTemplates validates one template per deliverable purpose, and refuses
// a configuration that names a purpose this adapter cannot deliver.
//
// # THREE REFUSALS, AND THE THIRD IS THE ONE THAT COULD HAVE BEEN A NO-OP
//
//	a purpose with no template   the deployment cannot say where that kind of link
//	                             goes. Substituting another purpose's template is
//	                             the defect, so there is no substitution.
//	a template that will not     delegated to `ValidateLinkTemplate`, once per
//	                             purpose, with the purpose named around it.
//	a purpose with no message    a template is a setting an operator changes and
//	                             nothing honours. It is refused rather than ignored
//	                             because a variable that is read by nothing is a
//	                             promise this service does not keep — the same rule
//	                             as a scope documented on a route that does not gate
//	                             it. `internal/config` must not be taught which
//	                             purposes are deliverable, so the check belongs
//	                             here, where that knowledge is.
func resolveLinkTemplates(raw map[recovery.Purpose]string) (LinkTemplates, error) {
	out := make(LinkTemplates, len(linkPurposeFor))
	for subject, purpose := range linkPurposeFor {
		value, present := raw[purpose]
		if !present {
			return nil, fmt.Errorf("courier: no link template for the %q message, so a %s "+
				"link has nowhere to point and the mail would carry a button that goes "+
				"nowhere. Set the %s variable to the screen that redeems one",
				subject, purpose, purpose)
		}
		template, err := ValidateLinkTemplate(value)
		if err != nil {
			return nil, fmt.Errorf("courier: the %s link template: %w", purpose, err)
		}
		out[purpose] = template
	}
	for purpose := range raw {
		if _, deliverable := out[purpose]; deliverable {
			continue
		}
		return nil, fmt.Errorf("courier: a link template was configured for the %q purpose, "+
			"which no message this adapter can deliver carries: courier has no template "+
			"for it, so the setting would be honoured nowhere", purpose)
	}
	return out, nil
}

// Send delivers one rendered message, and reports what courier said.
//
// IT IS THE WHOLE ADAPTER, and there are three things in it.
//
// # 1. THE KIND, FROM THE SUBJECT
//
// `courierTypeFor` above says why the subject is the key. What happens on a miss is
// the part that matters: `ErrUnsupportedMessage`, before the wire, so no token
// reaches courier for a message courier cannot render.
//
// # 2. THE LINK, AND WHICH TEMPLATE GETS IT
//
// courier's `password_reset` REQUIRES `url` and answers 422 without one — a
// recorded 422, in `recorded_test.go`. The token goes into the template configured
// for this message's PURPOSE and the result is what courier's own template renders.
//
// `linkPurposeFor` is the table that decides which template, and consulting it is
// the whole of what changed when a deployment could say where each kind of link goes.
// It is a lookup with a REFUSAL rather than a default, and the direction of that
// refusal is the point: a purpose with no template here means the constructor let a
// broken configuration through, and answering with another purpose's link — or with
// an empty one — would produce a mail that renders perfectly and sends the reader to
// a screen that cannot redeem what it is carrying.
//
// The token is in a URL rather than in prose, which is a real change from
// `recovery`'s own bodies ("Your reset code is: …") and it is courier's decision
// rather than this service's: courier's document has no field for a bare code. It
// also means the credential now lives in a URL, which is a wider blast radius than
// a body — referrers, proxies, browser history. That is a genuine cost and it is
// WHY the link is a configured template rather than something this package builds:
// the deployment that owns the screen owns where the credential travels.
//
// # 3. THE ERROR, AND WHICH ONES ARE ABOUT THE CALLER
//
// courier's 409 and its declined-preference 422 are facts about a RECIPIENT. They
// are returned as this package's sentinels and `recovery` decides what to tell the
// caller, because that decision is `recovery`'s: it knows whether the request was
// anonymous, and an anonymous caller must not learn that an address is
// undeliverable.
func (m *RecoveryMailer) Send(ctx context.Context, message recovery.Message) error {
	courierType, ok := courierTypeFor[message.Subject]
	if !ok {
		m.log("refusing a message courier has no type for",
			"subject", message.Subject,
			"reason", "courier's NotificationType is [welcome, password_reset, team_invitation]",
		)
		return fmt.Errorf("%w: %q", ErrUnsupportedMessage, message.Subject)
	}

	// The purpose, resolved alongside the courier type so a message that is
	// deliverable but has no purpose of its own is refused HERE rather than at the
	// render below, where the error would be about a template and would send an
	// operator looking in the wrong file. `linkPurposeFor` and `courierTypeFor` are
	// two closed sets and
	// `TestEveryRecoverableMessageReachesCourierHasALinkPurposeAndOneDoesNot` holds
	// them to the same keys.
	purpose, ok := linkPurposeFor[message.Subject]
	if !ok {
		m.log("refusing a message with no link purpose",
			"subject", message.Subject,
			"reason", "linkPurposeFor has no entry for a message courierTypeFor can send, "+
				"so there is no template to render the credential into",
		)
		return fmt.Errorf("%w: %q is deliverable but has no link purpose, so there is no "+
			"template to put the token in", ErrInvalidRequest, message.Subject)
	}

	if message.To == "" {
		// `recovery` refuses this itself; checked here because the alternative is a
		// request courier answers 422 for, and a message with no recipient is a
		// bug in the caller above rather than anything courier said.
		return errors.New("courier: refusing to send a message with no recipient")
	}

	token := tokenFromBody(message.Body)
	if token == "" {
		// Unreachable through `recovery`, which refuses to render a message with no
		// credential in it. Checked because the alternative is a link reaching a
		// real inbox with nothing in it.
		return fmt.Errorf("%w: %s has no token in it", ErrInvalidRequest, message.Subject)
	}

	// The account, and courier REQUIRES it — the request has no optional form,
	// because courier keys the recipient's preferences by it and attributes the
	// `courier.email.delivered` event to it.
	userID, err := userIDFrom(message)
	if err != nil {
		m.log("refusing a message identity cannot address",
			"subject", message.Subject,
			"reason", "the message named no account, and courier's request requires one",
		)
		return fmt.Errorf("%w: %s: %v", ErrUnsupportedMessage, message.Subject, err)
	}

	link, err := m.linkTemplates[purpose].render(token)
	if err != nil {
		return fmt.Errorf("%w: the %s link: %w", ErrInvalidRequest, purpose, err)
	}

	// The key is DERIVED from the send rather than minted per attempt, and the
	// three inputs are the ones that identify it: what is being sent, which account
	// it is about, and the credential it carries. A random key per call would be
	// the same header with none of the effect — a user who asks twice for one
	// reset link would be sent two, which is the thing courier's idempotency exists
	// to stop. See `idempotencyKeyFor`.
	key, err := idempotencyKeyFor(courierType, userID, token)
	if err != nil {
		return err
	}

	started := m.now()
	result, err := m.client.SendMessage(ctx, MessageRequest{
		Type:           courierType,
		UserID:         userID,
		To:             message.To,
		URL:            link,
		IdempotencyKey: key,
	})
	if err != nil {
		m.logSendFailure(message, courierType, started, err)
		return err
	}

	// The one thing worth saying out loud on a success. A 200 is courier accepting
	// the message for delivery, and the `message_id` is what a bounce or a
	// complaint will quote, so it is the one field an operator ever needs from a
	// send. It is logged and nothing else: the token is not, the recipient is not,
	// and the body is not.
	m.log("courier accepted a message for delivery",
		"type", courierType,
		"message_id", result.MessageID,
		"event_id", result.EventID,
		"status", result.Status,
		"duration", m.now().Sub(started),
	)
	return nil
}

// Ready reports whether courier is up, and is `recovery.Mailer.Ready`.
//
// The `ErrNoMailer` wrap is the whole of the translation: `recovery` answers its
// anonymous request paths with 503 when the seam cannot deliver, and its own
// `ErrNoMailer` is the sentinel the HTTP layer maps to that. A courier that is
// down and a deployment with no mailer are the same answer to a user, and they are
// the same answer to an operator at the level of a status line; the distinction
// that matters — a token was never minted — holds for both.
func (m *RecoveryMailer) Ready(ctx context.Context) error {
	if err := m.client.Ready(ctx); err != nil {
		return fmt.Errorf("%w: %w", recovery.ErrNoMailer, err)
	}
	return nil
}

// String makes this mailer safe to print, on the same terms as `Client`.
func (m *RecoveryMailer) String() string {
	return "courier.RecoveryMailer{" + m.client.String() + "}"
}

// logSendFailure writes one line per refused send.
//
// WHAT IS IN IT is the point: courier's status, courier's `code`, whether another
// attempt can help, and courier's trace id. What is NOT in it is the recipient, the
// body, the token, and the credential — and the absence is deliberate rather than
// incidental, because the temptation on a send failure is exactly to log "failed
// to send to kaka@example.com", and a log aggregator is the last place a reset
// recipient's address and the deployment's mail credential should meet.
func (m *RecoveryMailer) logSendFailure(message recovery.Message, courierType string, started time.Time, err error) {
	attrs := []any{
		"type", courierType,
		"duration", m.now().Sub(started),
		"retryable", Retryable(err),
	}
	var refused *Error
	if errors.As(err, &refused) {
		attrs = append(attrs,
			"status", refused.Status,
			"code", refused.Code,
			"trace_id", refused.TraceID,
		)
		if len(refused.Fields) > 0 {
			attrs = append(attrs, "fields", fieldsString(refused.Fields))
		}
	}
	// The subject is a constant with nothing variable in it, so it is safe and it
	// is the one thing that says WHICH flow failed, which is what somebody reading
	// a log at 3am needs.
	attrs = append(attrs, "subject", message.Subject, "error", err)
	m.log("courier did not accept a message", attrs...)
}

func (m *RecoveryMailer) log(msg string, attrs ...any) {
	if m.logger == nil {
		return
	}
	m.logger.Warn(msg, attrs...)
}

// # THE THREE EXTRACTIONS
//
// A `recovery.Message` is prose, and courier wants facts, so something has to read
// the prose. These three functions are where that happens, and they are the whole
// of the risk in this adapter — which is why they are the ONLY place a value is
// taken out of a rendered body, and why each is a named function with a test
// rather than an inline `strings.Index`.

// bodyMarker is the line `internal/recovery`'s bodies put the credential on.
//
// IT IS A MARKER AND NOT A REGEX BECAUSE THE BODY IS A CONSTANT TEMPLATE with one
// named substitution, and a pattern that could match more than one thing in a
// document that also contains an address and a date is a pattern that eventually
// extracts a date. `recovery`'s four bodies all indent the code by four spaces on
// its own line, which is the shape this reads.
//
// IF A BODY EVER STOPS MATCHING, the extraction returns "" and `render` refuses, so
// the failure is a 503 naming a missing token rather than a reset link with an
// empty query parameter reaching a real inbox.
const bodyMarker = "\n\n    "

// tokenFromBody reads the credential out of a rendered body.
func tokenFromBody(body string) string {
	_, after, found := strings.Cut(body, bodyMarker)
	if !found {
		return ""
	}
	token, _, _ := strings.Cut(after, "\n")
	return strings.TrimSpace(token)
}

// userIDFrom reads the account a message concerns.
//
// IT IS A FIELD READ AND NOT A PARSE, which is the whole reason the field is
// there: courier's `POST /v1/messages` REQUIRES `user_id` — there is no optional
// form — and it uses it for two things, keying the recipient's notification
// preferences and attributing the `courier.email.delivered` event. Reading it out
// of the body was the alternative and it is not available: none of `recovery`'s
// four templates has a slot for a uuid, and `strings.Index` over prose to find a
// credential-sized value is exactly the kind of parse that eventually finds a date.
//
// A ZERO VALUE IS REFUSED rather than defaulted. Attributing a message containing
// a live credential to an account nobody chose is worse than not sending it, and a
// `nil` there would become somebody's `user_id` in somebody else's outbox.
func userIDFrom(message recovery.Message) (string, error) {
	if message.UserID.IsZero() {
		return "", errors.New("recovery.Message carried no user id")
	}
	return message.UserID.String(), nil
}

// checkAbsoluteHTTPURL refuses a link courier's schema would not accept.
//
// IT IS NOT `normaliseBaseURL`, and the difference is the point: a BASE URL must
// have no query, because this package concatenates a path onto it. A LINK may have
// one — `https://app.example.com/reset?token=…` is the ordinary shape — and its
// query is where the credential goes. Reusing the base-URL check here refused every
// real reset link, which is the failure `TestTheLinkTemplateIsRefusedWhenItCannot
// MakeAWorkingLink` caught and why this function exists separately.
func checkAbsoluteHTTPURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: %q is not a URL", ErrNoBaseURL, raw)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("%w: %q is not an http or https URL", ErrNoBaseURL, raw)
	}
	if parsed.Host == "" {
		return fmt.Errorf("%w: %q has no host", ErrNoBaseURL, raw)
	}
	// A FRAGMENT is refused and a query is not, and the asymmetry is the rule rather
	// than an oversight. A fragment is not sent to a server, so a token in one
	// reaches a browser and never the screen that redeems it. A query is what
	// `?token=` is FOR.
	if parsed.Fragment != "" {
		return fmt.Errorf("%w: %q has a fragment; a mail client does not send one to a server",
			ErrNoBaseURL, raw)
	}
	if parsed.User != nil {
		// A userinfo section is a credential in a URL, and a link is a string that
		// gets quoted, logged and pasted.
		return fmt.Errorf("%w: %q has a userinfo section", ErrNoBaseURL, raw)
	}
	return nil
}

// compile-time proof that the seam `internal/recovery` declares is the one this
// package satisfies. A build-time assertion rather than a test, because a change to
// either signature should stop the build rather than a test run.
var _ recovery.Mailer = (*RecoveryMailer)(nil)

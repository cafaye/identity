package recovery

import (
	"fmt"
	"strings"
	"time"
)

// THE MESSAGES.
//
// Four of them, all in this file, rendered by one function. That is the whole of
// the rendering approach this package has, and it is worth saying why it is here
// rather than in the flows that use it:
//
//   - The bodies contain LIVE CREDENTIALS. A reset token, a verification token, an
//     email-change token. They are rendered in exactly one place, so there is one
//     place to point at when asking "where can a token end up", and the answer is
//     this file plus the Mailer.
//   - They are plain `strings.Replacer` substitutions over constant templates
//     rather than `text/template`. A template engine would buy looping, conditionals
//     and a layout language that four fixed messages do not need, and it would buy
//     them at the cost of a parse step that can fail, a `Must` that panics, and a
//     way for a mistyped field name to render as `<no value>` into a body a user is
//     about to trust with a credential. Two named substitutions into a constant is
//     the whole requirement.
//   - They are plain text. An HTML body is a rendering decision courier's packet
//     owns, and `Message` deliberately has no field for one.
//
// # THE TOKEN IS NEVER IN A SUBJECT LINE
//
// Subjects are the most widely logged part of a message: mail providers index
// them, notification daemons copy them into system logs, and a phone renders one
// on a lock screen. A body is the part somebody has to open, which is what a
// credential wants. Every subject below is a constant with nothing variable in
// it, and there is no code path that can put a token in one.

// messageKind is which of the four bodies to render.
//
// IT IS NOT A Purpose, and the two are kept apart on purpose. A row's `purpose`
// says what redeeming the token DOES, and an email change's two tokens both do
// the same thing — the second one is distinguished by which digest matched, not
// by what the row is for. The bodies, on the other hand, genuinely differ, so they
// are keyed by something that says "which message", and a fifth message that is
// not a fifth purpose cannot be added by accident.
type messageKind string

const (
	messageReset       messageKind = "password_reset"
	messageVerify      messageKind = "verify_email"
	messageChangeFirst messageKind = "email_change_current"
	messageChangeNew   messageKind = "email_change_new"
)

// The four bodies.
//
// `{{token}}` and `{{expiry}}` are the ONLY two substitutions, and they are named
// rather than positional so that adding a value to a body cannot repoint an
// existing one — the failure mode of every positional substitution, and the one
// that would put a deadline where a credential belongs.
const (
	passwordResetBody = `Somebody asked to reset the password for the account registered to ` +
		`{{email}}.

Your reset code is:

    {{token}}

Enter it where you sign in to choose a new password. It works once, and only
until {{expiry}}.

If this was not you, nothing has changed. Nobody can sign in with this code
without it, and it stops working as soon as it is used or when it expires.
`

	verifyEmailBody = `Confirm the address {{email}} for your cafaye account.

Your confirmation code is:

    {{token}}

Enter it where you sign in. It works once, and only until {{expiry}}.

This service does not call an address verified until somebody proves they can
read mail sent to it, which is what this code is for.
`

	// The current-address half is the one a hijacked session cannot get past, so
	// its body says what is waiting and what happens next. Silence would be the
	// comfortable answer and it is the wrong one: the only warning the owner of an
	// account has that somebody is moving its address is this message.
	emailChangeCurrentBody = `Somebody signed in to the cafaye account on {{email}} and asked to
change the address it uses.

If that was you, confirm it with this code:

    {{token}}

If it was not you, do nothing. The request cannot go any further without this
code, and nothing about the account has changed yet.

It works once, and only until {{expiry}}. Confirming it sends one more message,
to the NEW address — the change only completes when that one is confirmed too.
`

	emailChangeNewBody = `Somebody asked to move the cafaye account on {{email}} to this address.

Confirm it with this code:

    {{token}}

If you were expecting this, enter the code and the account's address becomes
{{target}}. If you were not expecting it, do nothing: a change needs this address
and the old one both confirmed, and the old one has already been.

It works once, and only until {{expiry}}.
`
)

// messageBodies is the subject and the body template per message kind.
//
// The subjects are constants with nothing variable in them, which is the property
// the section above is about. The lookup is a map rather than a switch so that a
// message kind with no body is an error rather than an empty mail: `messageFor`
// refuses rather than falling through, because a purpose that renders to nothing
// would be sent to a real inbox.
var messageBodies = map[messageKind]struct {
	Subject string
	Body    string
}{
	messageReset:       {Subject: "Reset your cafaye password", Body: passwordResetBody},
	messageVerify:      {Subject: "Confirm your cafaye email address", Body: verifyEmailBody},
	messageChangeFirst: {Subject: "Confirm an email address change", Body: emailChangeCurrentBody},
	messageChangeNew:   {Subject: "Confirm your new cafaye email address", Body: emailChangeNewBody},
}

// messageData is what a body is rendered against.
//
// It is a struct rather than a list of positional arguments for the reason the
// templates are named: two callers cannot pass them in the wrong order.
//
// To is here and not on `Message` because it is an INPUT to the render, not a
// property of the result: `Message.To` is what send() copies into. A field on both
// would be two answers to "where does this go", and the send path would have to
// pick one of them.
type messageData struct {
	To     string
	Email  string
	Target string
	Token  string
	Expiry time.Time
}

// messageFor renders the message for a kind.
//
// IT REFUSES AN UNKNOWN KIND rather than falling back, for the reason
// messageBodies says: a body this build does not have is not one anybody has
// read, and this is the last point at which that is still knowable.
func messageFor(kind messageKind, data messageData) (Message, error) {
	parts, ok := messageBodies[kind]
	if !ok {
		return Message{}, fmt.Errorf("recovery: %q is not a message this build can render", kind)
	}
	if data.Token == "" {
		// A body with an empty credential in it is the one rendering bug that
		// matters here, and it is checkable: every caller of this function holds a
		// freshly minted 256-bit token and has no path that produces "".
		return Message{}, fmt.Errorf("recovery: refusing to render the %s message with no token", kind)
	}

	body := strings.NewReplacer(
		"{{email}}", data.Email,
		"{{target}}", data.Target,
		"{{token}}", data.Token,
		// RFC 1123 in UTC, because the reader's clock zone is not this service's
		// and a deadline nobody can place is a deadline they will ignore.
		"{{expiry}}", data.Expiry.UTC().Format(time.RFC1123),
	).Replace(parts.Body)

	return Message{Subject: parts.Subject, Body: body}, nil
}

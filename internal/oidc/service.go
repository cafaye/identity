package oidc

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/cafaye/identity/internal/outbox"
	"github.com/cafaye/identity/internal/platform/clock"
	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/id"
)

// The client registration use cases: register a relying party, list them, read
// one, revoke one.
//
// Two writes and one fact. Registering writes a row and an event; revoking
// writes a row, an event, and a bulk revocation of every access token issued
// against that registration. All of it in one transaction, and the last one is
// the reason: a revoked client whose access tokens keep working for another
// fifteen minutes is a revoked client that is not revoked, and a consumer of
// `identity.oidc_client.revoked` would have no way to know that.
//
// The rules that are NOT here: who may call. That is RequireAccountRole's job in
// the HTTP layer, and it is the one place in this service where a minimum role
// is decided. What IS here is the scoping — every method takes the account id,
// and every statement is scoped by it, so a use case reached any other way is
// still scoped.

// UnitOfWork runs a function inside a transaction. db.TxRunner implements it;
// the interface is the seam that lets these rules be tested without Postgres.
type UnitOfWork interface {
	Do(ctx context.Context, fn func(ctx context.Context, q db.Querier) error) error
}

// ClientStore is the slice of Store the use cases need.
//
// It is declared here rather than taking *Store so a test can program a failure
// at the exact write that matters — a collision, a revocation of something
// already revoked — without standing up a database.
type ClientStore interface {
	CreateClient(ctx context.Context, q db.Querier, p CreateClientParams) (Client, error)
	ClientByRowID(ctx context.Context, q db.Querier, rowID id.UUID) (Client, error)
	ClientsForAccount(ctx context.Context, q db.Querier, accountID id.UUID) ([]Client, error)
	RevokeClient(ctx context.Context, q db.Querier, rowID, accountID, by id.UUID, at time.Time, reason string) (Client, error)
}

// EventAppender is the slice of outbox.Store these use cases need.
type EventAppender interface {
	Append(ctx context.Context, q db.Querier, e outbox.Envelope) error
}

// AccessTokenRevoker is the bulk revocation that makes a revocation real. It is
// the Storage's method rather than the Store's, because it is a property of the
// flow and not of the access-token table.
type AccessTokenRevoker interface {
	RevokeAccessTokensForClient(ctx context.Context, q db.Querier, clientRowID id.UUID, at time.Time) error
}

// Service is the client registration use cases.
type Service struct {
	uow    UnitOfWork
	store  ClientStore
	events EventAppender
	tokens AccessTokenRevoker
	clk    clock.Clock
	read   db.QuerierSource
}

// NewService wires the use cases.
func NewService(
	uow UnitOfWork,
	store ClientStore,
	events EventAppender,
	tokens AccessTokenRevoker,
	clk clock.Clock,
	read db.QuerierSource,
) *Service {
	return &Service{uow: uow, store: store, events: events, tokens: tokens, clk: clk, read: read}
}

// RegisterInput is a request to register a relying party.
//
// AccountID is the account that will own it and RegisteredBy is the caller, and
// neither is ever something the request body could have chosen: the account comes
// from the path and the actor from the session. That is the line between "register
// a client for the account I run" and "register a client for an account I do not",
// and no version of this body crosses it.
type RegisterInput struct {
	AccountID    id.UUID
	Name         string
	RedirectURIs []string
	GrantTypes   []string
	Scopes       []string
	RegisteredBy id.UUID
}

// RegisteredClient is a new registration and its one-time secret.
//
// Secret is here and nowhere else. It is returned in the 201, never stored, and
// there is no endpoint that re-reads it — a caller that loses it registers
// again. The same rule governs a session token, an invitation token and a
// password, and the reason is the same: a secret this service can produce again
// is a secret this service is storing.
type RegisteredClient struct {
	Client Client
	Secret string
}

// Register creates a registration and announces it.
//
// Validation happens before the transaction, so a bad request never takes a
// write lock, and the three validators run in the order the client reads: what
// it is called, where it may send a browser, and what it may ask for. The first
// error wins, and each one names its own field.
func (s *Service) Register(ctx context.Context, in RegisterInput) (RegisteredClient, error) {
	if in.AccountID.IsZero() || in.RegisteredBy.IsZero() {
		return RegisteredClient{}, ErrNotFound
	}

	name := strings.TrimSpace(in.Name)
	if err := validateName(name); err != nil {
		return RegisteredClient{}, err
	}
	redirectURIs, err := ValidateRedirectURIs(in.RedirectURIs)
	if err != nil {
		return RegisteredClient{}, err
	}
	grantTypes, err := ValidateGrantTypes(in.GrantTypes)
	if err != nil {
		return RegisteredClient{}, err
	}
	scopes, err := ValidateRegistrationScopes(in.Scopes)
	if err != nil {
		return RegisteredClient{}, err
	}

	clientID, secret, err := NewClientCredentials()
	if err != nil {
		return RegisteredClient{}, err
	}

	now := s.clk.Now()
	var out RegisteredClient

	err = s.uow.Do(ctx, func(ctx context.Context, q db.Querier) error {
		created, err := s.store.CreateClient(ctx, q, CreateClientParams{
			AccountID:    in.AccountID,
			ClientID:     clientID,
			Name:         name,
			SecretDigest: SecretDigest(secret),
			RedirectURIs: redirectURIs,
			GrantTypes:   grantTypes,
			Scopes:       scopes,
			CreatedBy:    in.RegisteredBy,
			CreatedAt:    now,
		})
		if err != nil {
			return err
		}

		event, err := outbox.NewOIDCClientCreated(now, created.ID, in.AccountID, created.ClientID,
			created.RedirectURIs, created.GrantTypes, created.Scopes, in.RegisteredBy)
		if err != nil {
			return err
		}
		if err := s.events.Append(ctx, q, event); err != nil {
			return err
		}

		out = RegisteredClient{Client: created, Secret: secret}
		return nil
	})
	if err != nil {
		return RegisteredClient{}, err
	}
	return out, nil
}

// List returns an account's registrations.
func (s *Service) List(ctx context.Context, accountID id.UUID) ([]Client, error) {
	if accountID.IsZero() {
		return nil, ErrNotFound
	}
	return s.store.ClientsForAccount(ctx, s.read.Queryer(), accountID)
}

// Get returns one registration, scoped to the account that owns it.
//
// Scoped rather than looked up by row id alone, so a caller holding a row id
// from another tenant gets ErrNotFound and not somebody else's client. The HTTP
// layer has already established that the caller owns the account; this is the
// same rule applied again at the query, because a use case reached any other way
// would otherwise not have it.
func (s *Service) Get(ctx context.Context, accountID, rowID id.UUID) (Client, error) {
	if accountID.IsZero() || rowID.IsZero() {
		return Client{}, ErrNotFound
	}
	client, err := s.store.ClientByRowID(ctx, s.read.Queryer(), rowID)
	if err != nil {
		return Client{}, err
	}
	if client.AccountID != accountID {
		// The same answer as a row that does not exist. core's conventions are
		// explicit: "404 is correct there, 403 is not allowed to leak existence".
		return Client{}, fmt.Errorf("%w: no client with that id in this account", ErrNotFound)
	}
	return client, nil
}

// RevokeInput is a request to stop honouring a registration.
type RevokeInput struct {
	AccountID id.UUID
	ClientID  id.UUID
	RevokedBy id.UUID
	// Reason is recorded on the row and is NOT in the event. See
	// outbox.NewOIDCClientRevoked.
	Reason string
}

// Revoke stops honouring a registration and announces it.
//
// Three writes in one transaction: the row, the bulk revocation of every access
// token issued against it, and the event. The middle one is the reason this is
// not a single UPDATE — a token is a signed JWT, so revoking the registration
// does not by itself stop one that has already been handed out, and the window
// between the two is fifteen minutes of a credential nobody has revoked.
func (s *Service) Revoke(ctx context.Context, in RevokeInput) (Client, error) {
	if in.AccountID.IsZero() || in.ClientID.IsZero() || in.RevokedBy.IsZero() {
		return Client{}, ErrNotFound
	}

	now := s.clk.Now()
	var out Client

	err := s.uow.Do(ctx, func(ctx context.Context, q db.Querier) error {
		// Read first so the event can name the account, and so a revocation of
		// something that is not there says so rather than announcing nothing.
		existing, err := s.store.ClientByRowID(ctx, q, in.ClientID)
		if err != nil {
			return err
		}
		if existing.AccountID != in.AccountID {
			return fmt.Errorf("%w: no client with that id in this account", ErrNotFound)
		}

		revoked, err := s.store.RevokeClient(ctx, q, in.ClientID, in.AccountID, in.RevokedBy, now, in.Reason)
		if err != nil {
			return err
		}

		if err := s.tokens.RevokeAccessTokensForClient(ctx, q, revoked.ID, now); err != nil {
			return err
		}

		event, err := outbox.NewOIDCClientRevoked(now, revoked.ID, in.AccountID, revoked.ClientID, in.RevokedBy)
		if err != nil {
			return err
		}
		if err := s.events.Append(ctx, q, event); err != nil {
			return err
		}

		out = revoked
		return nil
	})
	if err != nil {
		return Client{}, err
	}
	return out, nil
}

// validateName bounds and requires a registration's display name.
//
// Required because the login page renders it, and a login page that cannot name
// the application asking for a password is the setup for a credential-phishing
// page on this service's own domain. That is a security property, which is why
// it is a rule here and not a nicety in the OpenAPI document.
func validateName(name string) error {
	switch {
	case name == "":
		return fieldErr("name", CodeRequired)
	case len([]rune(name)) > MaxNameLength:
		return fieldErr("name", CodeTooMany)
	default:
		return nil
	}
}

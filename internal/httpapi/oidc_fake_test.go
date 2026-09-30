package httpapi

import (
	"context"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cafaye/identity/internal/oidc"
	"github.com/cafaye/identity/internal/outbox"
	"github.com/cafaye/identity/internal/platform/clock"
	"github.com/cafaye/identity/internal/platform/db"
	"github.com/cafaye/identity/internal/platform/id"
)

// The OIDC doubles, and one real builder.
//
// The authorization matrix runs the REAL registration use case over real SQL,
// because the interesting columns are "may a member add a client to this account"
// and "may the owner of another account add one to this one" — and a double
// would agree with whatever the handler did, which is the bug the matrix exists
// to find. What a double IS good for is the parts the matrix never drives: the
// login page, the discovery document and the key set, which exist only so the
// router can be walked.

// matrixOIDCClients builds the real registration use case over a pool, with the
// real storage adapter behind it.
//
// The adapter matters: the matrix's revoke row goes all the way through
// RevokeAccessTokensForClient, and a stub there would leave the most interesting
// half of a revocation untested by the very suite that says revocation is
// owner-only.
//
// It shares the pool with the rest of the fixture rather than opening a second
// one, and takes the same clock, so a registration written here is a
// registration the service could have written. The FAKE clock is fine here,
// unlike in the flow tests: nothing in the registration path compares a row's
// timestamp against the system clock.
func matrixOIDCClients(t *testing.T, pool *pgxpool.Pool, clk clock.Clock) *oidc.Service {
	t.Helper()

	store := oidc.NewStore(pool)
	storage := oidc.NewStorage(store, oidc.NewProfileReader(), generateTestKey(t), clk, db.Direct{Pool: pool}, oidc.PathLogin)

	return oidc.NewService(
		db.TxRunner{Pool: pool},
		store,
		outbox.NewStore(pool),
		storage,
		clk,
		db.Direct{Pool: pool},
	)
}

// fakeOIDCClients is the programmable stand-in, for the route-coverage walk.
//
// The walk builds a router with doubles for everything and reads the routes out
// of chi. It needs a non-nil OIDCClients so registerOIDCClientRoutes mounts the
// four routes at all, and it never calls them.
type fakeOIDCClients struct {
	registered  oidc.RegisteredClient
	registerErr error
	revokeErr   error
}

func newFakeOIDCClients() *fakeOIDCClients { return &fakeOIDCClients{} }

func (f *fakeOIDCClients) Register(context.Context, oidc.RegisterInput) (oidc.RegisteredClient, error) {
	return f.registered, f.registerErr
}

func (f *fakeOIDCClients) List(context.Context, id.UUID) ([]oidc.Client, error) {
	return []oidc.Client{}, nil
}

func (f *fakeOIDCClients) Get(context.Context, id.UUID, id.UUID) (oidc.Client, error) {
	return oidc.Client{}, nil
}

func (f *fakeOIDCClients) Revoke(context.Context, oidc.RevokeInput) (oidc.Client, error) {
	return oidc.Client{}, f.revokeErr
}

// fakeOIDC is the provider, as a double.
//
// It exists for two reasons and neither of them is convenience: the route walk
// needs a non-nil provider so the well-known routes mount, and the OIDC
// handlers' error mapping is worth testing against a provider that can fail in
// the specific ways a real one can.
type fakeOIDC struct {
	banner      oidc.LoginBanner
	bannerErr   error
	completeErr error
	jwksErr     error
	// requested records the request ids the login page was asked about, so a test
	// can prove the id in the path is the one that reached the use case.
	requested []string
}

func newFakeOIDC() *fakeOIDC { return &fakeOIDC{} }

func (f *fakeOIDC) Handler() http.Handler { return http.NotFoundHandler() }

func (f *fakeOIDC) Discovery(*http.Request) any {
	return map[string]any{"issuer": "https://identity.test"}
}

func (f *fakeOIDC) JWKS() ([]byte, error) {
	if f.jwksErr != nil {
		return nil, f.jwksErr
	}
	return []byte(`{"keys":[]}`), nil
}

func (f *fakeOIDC) LoginBanner(_ context.Context, requestID string) (oidc.LoginBanner, error) {
	f.requested = append(f.requested, requestID)
	if f.bannerErr != nil {
		return oidc.LoginBanner{}, f.bannerErr
	}
	banner := f.banner
	banner.RequestID = requestID
	return banner, nil
}

func (f *fakeOIDC) CompleteLogin(context.Context, string, id.UUID) error { return f.completeErr }

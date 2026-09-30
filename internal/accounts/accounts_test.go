package accounts

import (
	"errors"
	"strings"
	"testing"

	"github.com/cafaye/identity/internal/platform/id"
)

// These are the rules the whole tenancy surface rests on, and none of them needs
// a database: which role outranks which, what a slug may look like, and what a
// name may be. A change to any of them is a change to the authorization matrix,
// so they are pinned here rather than only implied by the HTTP tests.

func TestRoleIsOrdered(t *testing.T) {
	tests := []struct {
		name string
		have Role
		min  Role
		want bool
	}{
		{name: "an owner meets an admin minimum", have: RoleOwner, min: RoleAdmin, want: true},
		{name: "an admin meets an admin minimum", have: RoleAdmin, min: RoleAdmin, want: true},
		{name: "a member does not meet an admin minimum", have: RoleMember, min: RoleAdmin, want: false},
		{name: "an admin does not meet an owner minimum", have: RoleAdmin, min: RoleOwner, want: false},
		{name: "an owner meets an owner minimum", have: RoleOwner, min: RoleOwner, want: true},
		{name: "a member meets a member minimum", have: RoleMember, min: RoleMember, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.have.AtLeast(tt.min); got != tt.want {
				t.Errorf("%q.AtLeast(%q) = %v, want %v", tt.have, tt.min, got, tt.want)
			}
		})
	}
}

// The ordering is a total order, not a set. A role that does not compare against
// another one would make AtLeast answer a coin flip, and "the minimum role" is
// the single most load-bearing idea in the tenancy surface.
func TestEveryRoleComparesAgainstEveryOther(t *testing.T) {
	all := AllRoles()

	for _, have := range all {
		for _, min := range all {
			_ = have.AtLeast(min)
		}
	}

	if got, want := len(all), 3; got != want {
		t.Errorf("AllRoles() has %d roles, want %d (%v)", got, want, all)
	}
	// Ascending, so the zero value of the enum's ordinal is the weakest role and
	// an accidental numeric comparison cannot invert the hierarchy.
	if all[0] != RoleMember || all[1] != RoleAdmin || all[2] != RoleOwner {
		t.Errorf("AllRoles() = %v, want [member admin owner]", all)
	}
}

func TestParseRole(t *testing.T) {
	tests := []struct {
		in      string
		want    Role
		wantErr bool
	}{
		{in: "owner", want: RoleOwner},
		{in: "admin", want: RoleAdmin},
		{in: "member", want: RoleMember},
		{in: "", wantErr: true},
		{in: "Owner", wantErr: true},
		{in: "OWNER", wantErr: true},
		{in: " owner", wantErr: true},
		{in: "owner ", wantErr: true},
		{in: "owner;drop table users", wantErr: true},
		{in: "billing", wantErr: true},
		{in: "admin,owner", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := ParseRole(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseRole(%q) = %q, want an error", tt.in, got)
				}
				var fe *FieldError
				if !errors.As(err, &fe) {
					t.Fatalf("ParseRole(%q) error is %T, want *FieldError so the HTTP layer can render errors[]", tt.in, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseRole(%q): %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("ParseRole(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestSlugify(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "already a slug", in: "acme", want: "acme"},
		{name: "spaces become dashes", in: "Acme Corp", want: "acme-corp"},
		{name: "case is folded", in: "ACME", want: "acme"},
		{name: "runs of punctuation collapse", in: "Acme   ///  Corp", want: "acme-corp"},
		{name: "leading and trailing dashes are trimmed", in: "  --Acme--  ", want: "acme"},
		{name: "underscores become dashes", in: "acme_corp", want: "acme-corp"},
		{name: "digits are kept", in: "Acme 42", want: "acme-42"},
		{name: "an email local part", in: "kaka.r@example", want: "kaka-r-example"},
		{name: "non-ascii is dropped", in: "Acme 東京", want: "acme"},
		{name: "an over-long name is truncated on a dash", in: strings.Repeat("a", 200), want: strings.Repeat("a", MaxSlugLength)},
		{name: "truncation never leaves a trailing dash", in: strings.Repeat("ab-", 40), want: strings.Repeat("ab-", 20) + "ab"},
		{name: "nothing usable is empty", in: "東京", want: ""},
		{name: "empty is empty", in: "", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Slugify(tt.in); got != tt.want {
				t.Errorf("Slugify(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// A slug that does not match the migration's CHECK is a 500 at insert time, so
// this is the one that actually protects the database contract.
func TestSlugifyAlwaysProducesAStorableSlug(t *testing.T) {
	for _, in := range []string{"a", "A", "---", "東京", "  ", "MiXeD CaSe 42", strings.Repeat("x", 500)} {
		slug := Slugify(in)
		if slug == "" {
			continue // the caller turns this into a 422, tested in ValidateName
		}
		if len(slug) > MaxSlugLength {
			t.Errorf("Slugify(%q) is %d characters, over the %d limit", in, len(slug), MaxSlugLength)
		}
		if slug != strings.ToLower(slug) {
			t.Errorf("Slugify(%q) = %q, which is not lower case", in, slug)
		}
		if strings.HasPrefix(slug, "-") || strings.HasSuffix(slug, "-") {
			t.Errorf("Slugify(%q) = %q, which has a leading or trailing dash", in, slug)
		}
		if strings.Contains(slug, "--") {
			t.Errorf("Slugify(%q) = %q, which has a doubled dash", in, slug)
		}
		for _, r := range slug {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				t.Errorf("Slugify(%q) = %q, which contains %q", in, slug, r)
			}
		}
	}
}

func TestValidateName(t *testing.T) {
	tests := []struct {
		name      string
		in        string
		wantField string
		wantCode  string
		wantOK    bool
	}{
		{name: "a plain name", in: "Acme Corp", wantOK: true},
		{name: "a name with digits", in: "Acme 42", wantOK: true},
		{name: "a single character", in: "A", wantOK: true},
		{name: "a name at the limit", in: strings.Repeat("a", MaxNameLength), wantOK: true},
		{name: "surrounding space is trimmed, not rejected", in: "  Acme  ", wantOK: true},
		{name: "empty", in: "", wantField: "name", wantCode: CodeRequired},
		{name: "only space", in: "   ", wantField: "name", wantCode: CodeRequired},
		{name: "only punctuation, which slugifies to nothing", in: "東京", wantField: "name", wantCode: CodeInvalidFormat},
		{name: "over the limit", in: strings.Repeat("a", MaxNameLength+1), wantField: "name", wantCode: CodeTooLong},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateName(tt.in)
			if tt.wantOK {
				if err != nil {
					t.Fatalf("ValidateName(%q): %v", tt.in, err)
				}
				return
			}
			var fe *FieldError
			if !errors.As(err, &fe) {
				t.Fatalf("ValidateName(%q) error is %T, want *FieldError", tt.in, err)
			}
			if fe.Field != tt.wantField || fe.Code != tt.wantCode {
				t.Errorf("ValidateName(%q) = %s/%s, want %s/%s", tt.in, fe.Field, fe.Code, tt.wantField, tt.wantCode)
			}
		})
	}
}

// The personal account's slug is derived from a user id, and two people can
// share an email local part. If the suffix were not there, the second
// registration of "kaka@example.com" would be a 409 and the second human could
// not sign up at all.
func TestPersonalSlugIsUniquePerUser(t *testing.T) {
	first := id.MustNew()
	second := id.MustNew()

	a := PersonalSlug("kaka", first)
	b := PersonalSlug("kaka", second)

	if a == b {
		t.Fatalf("both users got the slug %q; the second registration would be a 409", a)
	}
	if a == "kaka" || b == "kaka" {
		t.Errorf("personal slug = %q / %q, want one derived from the user id", a, b)
	}
	for _, s := range []string{a, b} {
		if len(s) > MaxSlugLength {
			t.Errorf("PersonalSlug produced %q at %d characters, over the %d limit", s, len(s), MaxSlugLength)
		}
	}
	// Deterministic: a retried transaction re-derives the same slug, so a unique
	// violation means the slug really is taken and not that we rolled a die twice.
	if again := PersonalSlug("kaka", first); again != a {
		t.Errorf("PersonalSlug is not deterministic: %q then %q", a, again)
	}
	// An email local part with nothing sluggable still yields a storable slug.
	if got := PersonalSlug("東京", first); got == "" {
		t.Error("PersonalSlug(\"東京\") is empty, which the accounts table's CHECK would reject")
	}
}

// The personal account's name is the email's local part, per the packet. It is
// an email local part and not the whole address, so a display name never leaks
// the domain to anyone who can see the account list.
func TestPersonalNameIsTheEmailLocalPart(t *testing.T) {
	tests := []struct {
		email string
		want  string
	}{
		{email: "kaka@example.com", want: "kaka"},
		{email: "kaka.r+tag@example.co.uk", want: "kaka.r+tag"},
		{email: "kaka", want: "kaka"},
	}

	for _, tt := range tests {
		t.Run(tt.email, func(t *testing.T) {
			if got := PersonalName(tt.email); got != tt.want {
				t.Errorf("PersonalName(%q) = %q, want %q", tt.email, got, tt.want)
			}
		})
	}
}

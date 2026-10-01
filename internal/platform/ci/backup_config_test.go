package ci

// The cross-file contract between config/kamal-backup.yml and config/deploy.yml.
//
// # WHY THIS FILE IS HERE AT ALL
//
// Two committed files are one contract, and the failure mode is that BOTH files
// are valid and the PAIR is wrong. `config/kamal-backup.yml` names its
// credentials with `{ secret: NAME }`; `config/deploy.yml`'s `backup` accessory
// carries an `env.secret` list, and kamal-backup builds that accessory's
// environment from that list and from nothing else. So a secret named in the
// backup config and missing from the accessory is a pair that parses, reads
// correctly in review, and fails at deploy time.
//
// `kamal-backup validate` is what actually catches it — it is the right tool and
// the runbook quotes the real message — but that tool is not in this repository's
// gate. `bin/prime` is Go, and a check that only runs on a machine with kamal and
// the gem installed is a check that runs for whoever happens to have them and for
// nobody else. So the contract is asserted here, on every commit, by reading the
// two files.
//
// WHAT THIS IS NOT. This is not a replacement for the real binaries. It cannot
// know whether Kamal accepts the rendered config, whether the ERB resolves, or
// whether the image exists. It asserts ONE property — the two files name the same
// secrets — and it asserts it in the direction that fails loudly.
//
// # NO YAML DEPENDENCY, AND THE READER REFUSES RATHER THAN UNDER-READS
//
// go.mod has no YAML parser and adding one would put a library and its CVEs in
// this module's dependency list for the sake of two lists of strings. So this
// reads by indentation, the same trade `manifest_reader_test.go` and
// `internal/httpapi/openapi_reader_test.go` make.
//
// The rule that matters is refusal. A reader that finds nothing agrees with
// another reader that finds nothing, and this check's failure mode is a silent
// pass: an empty secret set on one side makes "every secret is declared"
// vacuously true. So every way this can come back with less than it should — no
// `app:`, an `accessory:` naming something absent from `accessories:`, a `secret:`
// with no value, a `backup:` block that yields no `env.secret` list, a line inside
// a list that is not a list item — is an error naming the line, and the caller
// turns that into a failed test rather than an empty set.
//
// The readers are pure functions of the document rather than helpers that fail
// the test themselves: a reader reporting through *testing.T cannot be tested
// for refusal at all, because the proof that it refused is a failed test, and a
// test that fails cannot also assert.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// backupConfig is what `config/kamal-backup.yml` asserts about itself.
type backupConfig struct {
	app       string
	accessory string
	secrets   []string
}

// accessoryConfig is what one accessory in `config/deploy.yml` carries.
type accessoryConfig struct {
	name    string
	secrets []string
}

func readRepoFile(t *testing.T, rel string) string {
	t.Helper()
	source, err := os.ReadFile(filepath.Join(repoRoot(t), rel))
	if err != nil {
		t.Fatalf("reading %s: %v", rel, err)
	}
	return string(source)
}

func readBackupConfig(t *testing.T) backupConfig {
	t.Helper()
	got, err := parseBackupConfig(readRepoFile(t, "config/kamal-backup.yml"))
	if err != nil {
		t.Fatalf("reading config/kamal-backup.yml: %v", err)
	}
	return got
}

func readAccessoryConfig(t *testing.T, name string) accessoryConfig {
	t.Helper()
	got, err := parseAccessory(readRepoFile(t, "config/deploy.yml"), name)
	if err != nil {
		t.Fatalf("reading config/deploy.yml: %v", err)
	}
	return got
}

// parseBackupConfig reads `app:`, `accessory:` and every `{ secret: NAME }`.
//
// The secret entries are read wherever they appear rather than under a known
// parent key, because the whole point is that the parent is not what matters:
// `restic.repository.secret` and `databases[].url.secret` are different parents
// with the same obligation, and a reader that understood only one of them would
// report the other's secrets as undeclared.
func parseBackupConfig(source string) (backupConfig, error) {
	var cfg backupConfig

	for i, line := range strings.Split(source, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || trimmed == "---" {
			continue
		}
		switch {
		case line == "app:" || strings.HasPrefix(line, "app:"):
			value := strings.TrimSpace(strings.TrimPrefix(trimmed, "app:"))
			if value == "" {
				return cfg, fmt.Errorf("line %d: `app:` with no value, so there is no name for the snapshot path", i+1)
			}
			if cfg.app != "" {
				return cfg, fmt.Errorf("line %d: a second `app:` (%q) after %q", i+1, value, cfg.app)
			}
			cfg.app = value
		case strings.HasPrefix(trimmed, "accessory:"):
			value := strings.TrimSpace(strings.TrimPrefix(trimmed, "accessory:"))
			if value == "" {
				return cfg, fmt.Errorf("line %d: `accessory:` with no value, so there is no container to run in", i+1)
			}
			cfg.accessory = value
		case strings.HasPrefix(trimmed, "secret:"):
			value := strings.TrimSpace(strings.TrimPrefix(trimmed, "secret:"))
			if value == "" {
				return cfg, fmt.Errorf("line %d: `secret:` with no value, so a credential is named by nothing", i+1)
			}
			cfg.secrets = append(cfg.secrets, value)
		}
	}

	if cfg.app == "" {
		return cfg, fmt.Errorf("no `app:` key, so nothing decides where snapshots are written")
	}
	if cfg.accessory == "" {
		return cfg, fmt.Errorf("no `accessory:` key, so no container is told to read this file")
	}
	if len(cfg.secrets) == 0 {
		return cfg, fmt.Errorf("no `secret:` entries, so \"every secret is declared by the accessory\" would hold vacuously")
	}
	return cfg, nil
}

// parseAccessory reads one named block out of `accessories:` and returns the
// entries of its `env.secret` list.
//
// The list is located by indentation rather than by a regexp over the whole
// document, because the deploy config has TWO accessories and a whole-document
// match would read the postgres accessory's `POSTGRES_PASSWORD` as the backup
// accessory's and report the backup's own secrets as undeclared — a false red
// that teaches a reviewer to ignore this file.
func parseAccessory(source, name string) (accessoryConfig, error) {
	lines := strings.Split(source, "\n")

	accessoriesAt := -1
	for i, line := range lines {
		if line == "accessories:" {
			if accessoriesAt >= 0 {
				return accessoryConfig{}, fmt.Errorf("a second top-level `accessories:` at line %d", i+1)
			}
			accessoriesAt = i
		}
	}
	if accessoriesAt < 0 {
		return accessoryConfig{}, fmt.Errorf("no top-level `accessories:`, so there is no accessory to read")
	}

	start, end := -1, len(lines)
	for i := accessoriesAt + 1; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		// An accessory is a key at two-space indentation. Shallower than that
		// has left the block, which is how the block's end is found at all.
		if !strings.HasPrefix(line, "  ") {
			end = i
			break
		}
		if line == "  "+name+":" {
			if start >= 0 {
				return accessoryConfig{}, fmt.Errorf("a second `  %s:` accessory at line %d", name, i+1)
			}
			start = i
		}
	}
	if start < 0 {
		return accessoryConfig{}, fmt.Errorf("no `%s` accessory under `accessories:`, so the backup config is mounted nowhere", name)
	}

	cfg := accessoryConfig{name: name}

	secretListAt := -1
	for i := start + 1; i < end; i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if line == "    env:" {
			for j := i + 1; j < end; j++ {
				if lines[j] == "      secret:" {
					secretListAt = j
					break
				}
				if !strings.HasPrefix(lines[j], "      ") {
					break
				}
			}
			break
		}
		if !strings.HasPrefix(line, "    ") {
			break
		}
	}
	if secretListAt < 0 {
		return cfg, fmt.Errorf("the `%s` accessory has no `env.secret` list, so it is built from nothing and every secret in it is missing", name)
	}

	for i := secretListAt + 1; i < end; i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if !strings.HasPrefix(line, "        - ") {
			if !strings.HasPrefix(line, "        ") {
				break
			}
			return cfg, fmt.Errorf("line %d is inside the `%s` env.secret list and is not a list item: %q", i+1, name, line)
		}
		value := strings.TrimSpace(strings.TrimPrefix(trimmed, "-"))
		if value == "" {
			return cfg, fmt.Errorf("line %d is an `env.secret` entry with no value", i+1)
		}
		cfg.secrets = append(cfg.secrets, value)
	}

	if len(cfg.secrets) == 0 {
		return cfg, fmt.Errorf("the `%s` accessory's `env.secret` list is empty, so an empty one is not evidence of agreement", name)
	}
	return cfg, nil
}

// TestEverySecretTheBackupConfigNamesIsDeclaredByItsAccessory is the contract.
//
// The direction matters. The backup config naming a secret the accessory does
// not declare is the deployment failure — `kamal-backup validate` reports
// "RESTIC_REPOSITORY or RESTIC_REPOSITORY_FILE is required" on a pair in which
// both files are internally consistent. The other direction is not a failure: an
// accessory may declare a secret the backup config does not use.
func TestEverySecretTheBackupConfigNamesIsDeclaredByItsAccessory(t *testing.T) {
	backup := readBackupConfig(t)
	accessory := readAccessoryConfig(t, backup.accessory)

	declared := make(map[string]bool, len(accessory.secrets))
	for _, name := range accessory.secrets {
		declared[name] = true
	}

	for _, want := range backup.secrets {
		if !declared[want] {
			t.Errorf("config/kamal-backup.yml names secret %s, and the %q accessory in config/deploy.yml does not declare it.\n"+
				"kamal-backup builds the accessory's environment from that accessory's env.secret list and from nothing else, so this pair deploys and then fails to validate with both files reading correctly in review.",
				want, backup.accessory)
		}
	}
}

// TestTheBackupAccessoryMountsTheBackupConfig is the other half of "reachable".
//
// A backup config nothing mounts is a specification. This asserts the `files:`
// entry by source path rather than by the accessory merely existing, because an
// accessory with no `files:` boots and schedules and never sees the file it is
// meant to be running.
func TestTheBackupAccessoryMountsTheBackupConfig(t *testing.T) {
	backup := readBackupConfig(t)
	if backup.accessory != "backup" {
		t.Fatalf("config/kamal-backup.yml says `accessory: %s`. This test reads the deploy config's `backup` accessory, so a rename here makes the assertions above vacuous rather than wrong — update both sides in one change.", backup.accessory)
	}
	if !strings.Contains(readRepoFile(t, "config/deploy.yml"), "config/kamal-backup.yml:/app/config/kamal-backup.yml:ro") {
		t.Error("config/deploy.yml does not mount config/kamal-backup.yml into the backup accessory at /app/config/kamal-backup.yml:ro.\n" +
			"An accessory that does not mount the file schedules backups against a config it cannot read.")
	}
}

// TestTheBackupConfigNamesThisService is the identity between the two files.
//
// `app:` is the label under databases/<app>/<name>/ and the restic tag, and
// restic tracks by path, so a mismatch does not fail loudly: snapshots are
// written under one name and looked for under another, which reads as "the
// backup is missing". Both files are rendered from the same KIT_SERVICE by the
// operator, and `app:` here is the one value this repository writes down
// literally, so it is the one place they can come to disagree.
func TestTheBackupConfigNamesThisService(t *testing.T) {
	backup := readBackupConfig(t)
	if want := "identity"; backup.app != want {
		t.Errorf("config/kamal-backup.yml says `app: %s`, want `app: %s`.\n"+
			"cafaye.yml's `name:` is %s and config/deploy.yml renders `service:` from the same KIT_SERVICE this file's app: is a copy of. A mismatch orphans every existing snapshot, because restic tracks by path.",
			backup.app, want, want)
	}
}

// TestTheScheduleIsStatedAndTheWindowInTheReadmeMatchesIt holds the number the
// README promises to the number the tool will use.
//
// The README says "up to 24 hours", and that sentence is only true while the
// schedule is `1d`. Someone shortening the schedule to catch up with a policy
// change leaves the README claiming a day of transactions are lost when it is
// an hour, which is a promise made to a customer in the wrong direction. The
// window is read out of the schedule rather than restated, so there is one
// number.
func TestTheScheduleIsStatedAndTheWindowInTheReadmeMatchesIt(t *testing.T) {
	const source = "config/kamal-backup.yml"
	raw := readRepoFile(t, source)

	var schedule string
	for i, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "schedule:") {
			schedule = strings.TrimSpace(strings.TrimPrefix(trimmed, "schedule:"))
			if schedule == "" {
				t.Fatalf("%s:%d: `schedule:` with no value", source, i+1)
			}
		}
	}
	if schedule == "" {
		t.Fatalf("%s carries no `schedule:` key, so the accessory takes no snapshots on its own", source)
	}

	// kamal-backup 0.5.2 reads the schedule as a number of SECONDS and the
	// template's `1d` is 86400 of them. Every spelling below is what a reader of
	// the README would have to translate, so the translation lives here once.
	wantWindow := map[string]string{
		"1d":  "24 hours",
		"12h": "12 hours",
		"6h":  "6 hours",
		"1h":  "1 hour",
	}[schedule]
	if wantWindow == "" {
		t.Fatalf("%s sets `schedule: %s`, which this test does not know how to turn into a data-loss window.\n"+
			"Add the spelling to the table with the real number from the gem's scheduler rather than letting README.md keep asserting a window nobody derived.", source, schedule)
	}

	readme := readRepoFile(t, "README.md")
	if !strings.Contains(readme, wantWindow) {
		t.Errorf("the schedule is `%s` (%s of committed transactions lost), and README.md does not say %q.\n"+
			"A README that states a window the configured schedule does not produce is a promise made to a customer in the wrong direction.",
			schedule, wantWindow, wantWindow)
	}
	// The stale-number case in the other direction: a shortened schedule that
	// leaves the old window in place is the failure worth catching, so the
	// window that is NO LONGER true must be gone.
	if schedule != "1d" && strings.Contains(readme, "up to 24 hours of committed transactions") {
		t.Errorf("the schedule is `%s`, so the data-loss window is no longer 24 hours, and README.md still says it is.", schedule)
	}
}

// The tests below are of the READERS, not of the two documents. Each is a shape
// a reader must refuse, because a reader exercised only against the real files
// has proven that it reads those files and nothing else — and a reader that
// under-reads turns every check above into a check that passes on nothing.

func TestTheBackupConfigReaderReadsTheRealShape(t *testing.T) {
	const document = `---
app: identity
accessory: backup
databases:
  - name: primary
    adapter: postgres
    url:
      secret: DATABASE_URL
    password:
      secret: DATABASE_PASSWORD
restic:
  repository:
    secret: RESTIC_REPOSITORY
backup:
  schedule: 1d
`

	got, err := parseBackupConfig(document)
	if err != nil {
		t.Fatalf("reading a well-formed document: %v\nIf the reader refuses this, the refusals below prove nothing about the real file.", err)
	}
	if got.app != "identity" {
		t.Errorf("app = %q, want %q", got.app, "identity")
	}
	if got.accessory != "backup" {
		t.Errorf("accessory = %q, want %q", got.accessory, "backup")
	}
	want := []string{"DATABASE_URL", "DATABASE_PASSWORD", "RESTIC_REPOSITORY"}
	if len(got.secrets) != len(want) {
		t.Fatalf("secrets = %v, want %v", got.secrets, want)
	}
	for i, name := range want {
		if got.secrets[i] != name {
			t.Errorf("secret %d = %q, want %q", i, got.secrets[i], name)
		}
	}
}

func TestTheBackupConfigReaderRefusesWhatItDidNotRead(t *testing.T) {
	const wellFormed = "app: identity\naccessory: backup\ndatabases:\n  - url:\n      secret: DATABASE_URL\n"

	for name, document := range map[string]string{
		"no app key":                     "accessory: backup\ndatabases:\n  - url:\n      secret: DATABASE_URL\n",
		"an app with no value":           "app:\naccessory: backup\nsecret: DATABASE_URL\n",
		"a second app":                   wellFormed + "app: courier\n",
		"no accessory key":               "app: identity\nsecret: DATABASE_URL\n",
		"an accessory with no value":     "app: identity\naccessory:\nsecret: DATABASE_URL\n",
		"no secret entries":              "app: identity\naccessory: backup\nbackup:\n  schedule: 1d\n",
		"a secret with no value":         "app: identity\naccessory: backup\ndatabases:\n  - url:\n      secret:\n",
		"nothing but comments":           "# app: identity\n# accessory: backup\n# secret: DATABASE_URL\n",
		"an empty document":              "",
		"the file is a comment about it": "---\n# TODO: copy kamal-backup.yml.erb here\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseBackupConfig(document); err == nil {
				t.Error("the reader returned a config for this document instead of refusing it.\n" +
					"A reader that under-reads is worse than no reader: the checks built on it go green, and they are green about a file nobody read.")
			}
		})
	}
}

func TestTheAccessoryReaderReadsTheRealShape(t *testing.T) {
	const document = `accessories:
  postgres:
    image: postgres:17-alpine
    env:
      secret:
        - POSTGRES_PASSWORD
  backup:
    image: ghcr.io/crmne/kamal-backup:0.5.2
    files:
      - config/kamal-backup.yml:/app/config/kamal-backup.yml:ro
    env:
      secret:
        - DATABASE_URL
        - RESTIC_REPOSITORY
    volumes:
      - identity_backup_state:/var/lib/kamal-backup
servers:
  web:
    - 198.51.100.7
`

	got, err := parseAccessory(document, "backup")
	if err != nil {
		t.Fatalf("reading a well-formed document: %v", err)
	}
	want := []string{"DATABASE_URL", "RESTIC_REPOSITORY"}
	if len(got.secrets) != len(want) {
		t.Fatalf("secrets = %v, want %v — and NOT postgres's POSTGRES_PASSWORD, which belongs to the other accessory", got.secrets, want)
	}
	for i, name := range want {
		if got.secrets[i] != name {
			t.Errorf("secret %d = %q, want %q", i, got.secrets[i], name)
		}
	}
}

func TestTheAccessoryReaderRefusesWhatItDidNotRead(t *testing.T) {
	const wellFormed = "accessories:\n  backup:\n    env:\n      secret:\n        - DATABASE_URL\n"

	for name, document := range map[string]string{
		"no accessories block":                   "service: identity\nservers:\n  web:\n    - 198.51.100.7\n",
		"no such accessory":                      "accessories:\n  postgres:\n    env:\n      secret:\n        - POSTGRES_PASSWORD\n",
		"an accessory with no env":               "accessories:\n  backup:\n    image: ghcr.io/crmne/kamal-backup:0.5.2\n",
		"an env with no secret list":             "accessories:\n  backup:\n    env:\n      clear:\n        - SOMETHING\n",
		"an empty secret list":                   "accessories:\n  backup:\n    env:\n      secret:\n        # none yet\n",
		"a second accessories":                   wellFormed + "accessories:\n  backup:\n    env:\n      secret:\n        - X\n",
		"a line in the list that is not an item": "accessories:\n  backup:\n    env:\n      secret:\n        - DATABASE_URL\n        RESTIC_REPOSITORY: yes\n",
		"a list entry with no value":             "accessories:\n  backup:\n    env:\n      secret:\n        - \n",
		"an empty document":                      "",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseAccessory(document, "backup"); err == nil {
				t.Error("the reader returned an accessory for this document instead of refusing it.\n" +
					"An accessory list that came back empty would make the secret comparison agree with itself.")
			}
		})
	}
}

// TestTheReadersAcceptWhatTheyUnderstand is the control for the two tables
// above. Without it, a reader that refused EVERYTHING would pass every case in
// them — which is why each table is paired with a positive case rather than
// trusted because the real files parse.
func TestTheReadersAcceptWhatTheyUnderstand(t *testing.T) {
	t.Run("the real backup config is not refused", func(t *testing.T) {
		readBackupConfig(t)
	})
	t.Run("the real accessory is not refused", func(t *testing.T) {
		readAccessoryConfig(t, "backup")
	})
}

// TestTheContractCheckFailsOnAnInjectedPair is the tripwire's own tripwire.
//
// The comparison above can be shown to hold on the committed files, and a
// comparison that has never fired is indistinguishable from one that cannot. So
// this removes one secret from the accessory's list — leaving both files valid
// and each internally consistent, which is the exact shape of the real defect —
// and asserts the reader finds the disagreement rather than reporting agreement.
func TestTheContractCheckFailsOnAnInjectedPair(t *testing.T) {
	const intact = "accessories:\n  backup:\n    env:\n      secret:\n        - DATABASE_URL\n        - RESTIC_REPOSITORY\n"

	broken := strings.Replace(intact, "        - RESTIC_REPOSITORY\n", "", 1)
	if broken == intact {
		t.Fatal("the injection did not change the document, so the negative below proves nothing")
	}

	if _, err := parseAccessory(intact, "backup"); err != nil {
		t.Fatalf("the intact pair is refused by the reader, so the negative below proves nothing: %v", err)
	}
	got, err := parseAccessory(broken, "backup")
	if err != nil {
		return // refusing the shorter list outright is also a correct outcome
	}
	declared := map[string]bool{}
	for _, name := range got.secrets {
		declared[name] = true
	}
	if declared["RESTIC_REPOSITORY"] {
		t.Error("the reader still reports RESTIC_REPOSITORY as declared after it was removed from the accessory.\n" +
			"This is the check going green without checking, which is the failure the whole file exists to prevent.")
	}
}

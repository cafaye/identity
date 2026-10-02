-- 00016_account_isolation.sql — the account boundary, enforced by Postgres.
--
-- WHAT THIS MIGRATION IS. The first one in this repository that makes the DATABASE
-- refuse a cross-account read rather than relying on every query remembering its own
-- `where account_id = ?`. Until now the account boundary was entirely in Go: five
-- tables carried `account_id`, every store method passed it, and the whole suite
-- stayed green if one of them stopped. That is one forgotten predicate per query, and
-- nothing but a careful reviewer stands between a typo and one customer reading
-- another's data.
--
-- THE CONTENT BELOW IS kit's `templates/database/tenancy/substrate.sql`, COPIED
-- VERBATIM. Not adapted, not trimmed, not reimplemented: the substrate is the fleet's
-- shared definition of the account boundary, and a service that edited its copy would
-- be a service whose boundary is its own private opinion. kit's README §"Adopting
-- this" step 1 says to copy it; this is that copy. Its own comments explain every
-- decision it makes — the two roles, why `FORCE ROW LEVEL SECURITY` is not optional,
-- why the identity call is wrapped in `(select …)`, and why `current_account_id()`
-- returns NULL rather than raising when no account has been set.
--
-- THE FIVE CALLS AT THE BOTTOM ARE THE WHOLE OF WHAT THIS MIGRATION DECIDES, and
-- `cafaye.protect_table` is the ONLY entry point FOR AN ORDINARILY SCOPED TABLE:
-- there is no `protect_table_lite`, and there is no way to ask it for a policy without
-- FORCE, because a template that offers the weaker version is a template the weaker
-- version gets chosen from.
--
-- There is exactly ONE second entry point, `cafaye.protect_credential_table(table,
-- digest_column)`, and ONE table uses it. It protects a table exactly as `protect_table`
-- does — it CALLS it, so there is no second copy of ENABLE/FORCE to drift — and then
-- adds a fifth `for select` policy whose qualifier is the digest the caller presented.
-- It exists because of a fact about THIS service's authentication, measured on this
-- cluster and written down at the foot of this header: the lookup that turns a presented
-- scoped token into a key has no account to predicate on, because the account is what
-- the lookup is FOR. `protect_table` alone made every scoped token read zero rows, and
-- `ByDigest` maps that to ErrNotFound, so the HTTP layer answered 401 for every valid
-- machine credential in the fleet. The mechanism, and the four answers it rejected (a
-- BYPASSRLS role, a SECURITY DEFINER function, dropping FORCE, leaving the table
-- unprotected), are kit's decision MD24 and the reasoning is in the substrate itself.
--
-- WHY THESE FIVE TABLES, and the method, stated rather than assumed. The list was
-- derived by grepping `account_id` across `migrations/` and then reading each
-- declaration, NOT copied from a document:
--
--   00006_account_users         the membership row. Its primary key is
--                                (account_id, user_id) — the account IS half the key.
--   00007_account_invitations    a pending invitation addressed into an account.
--   00009_oidc_clients          a client's credentials belong to one account.
--   00011_api_keys              a bearer credential. The most consequential row in
--                                the database: this is the token itself.
--   00012_account_audit_log     written once, never updated, but it says who did what
--                                in which account, so reading another account's audit
--                                trail is the disclosure this table exists to prevent.
--
-- The tables DELIBERATELY absent are worth naming, because "not in this migration" is
-- otherwise indistinguishable from "not thought about":
--
--   users, sessions, recovery_tokens, mfa_*      GLOBAL BY CONSTRUCTION. There is no
--       account to scope them by until a request is authenticated, and `users.email`
--       carries a global unique index (00002_users.sql) precisely because login has to
--       find a person before any account is known. Protecting these would be
--       protecting a table that has no account column.
--   connected_accounts          per-USER, not per-account: an external identity link
--       belongs to the person, and one person may hold links under several accounts.
--   accounts                    the account row itself. It is the thing every other
--       table's `account_id` points at, so there is nothing for a policy to filter.
--
-- THE ADOPTION COST, STATED HERE BECAUSE IT WILL SURPRISE SOMEONE. Once a table is
-- protected, the OWNER reads zero rows from it until it sets an identity — FORCE
-- removed the exemption that used to let it through. `protect_table` names the owner in
-- every policy, so the owner's reads are ACCOUNT-SCOPED rather than absent, which is
-- the only version of "the owner may read" that is not "the owner may read
-- everything". A migration that has to read or backfill one of these five tables sets
-- the identity first (`select cafaye.begin_account(…)`), and that is the WHOLE answer.
--
-- There was a second suggestion here and it was WRONG: "or goes through a SECURITY
-- DEFINER function". FORCE ROW LEVEL SECURITY applies to the DEFINER as well as to the
-- invoker, so a SECURITY DEFINER reader of a forced table reads zero rows too, and a
-- migration written to that advice fails SILENTLY rather than loudly. Measured on the
-- real cluster while kit decided MD24. The substrate's own README now says the identity
-- is the whole answer, and this header says it too rather than leaving the false version
-- where the next reader of this file finds it. `api_keys` has one further step: a
-- migration that reads it has no account to begin AS, so it opens the row with
-- `cafaye.begin_credential(<the digest it is looking for>)` — the resolution seam, and
-- the same transaction-local GUC as the account one.
--
-- NO MIGRATION AFTER THIS ONE NEEDS TO KNOW. `cafaye.protect_table` is idempotent —
-- it drops and recreates its policies and uses `create … if not exists` for the index
-- — so a re-run converges rather than failing on a duplicate name.

-- +goose Up

-- THE STATEMENTBEGIN/STATEMENTEND PAIR AROUND THE SUBSTRATE IS LOAD-BEARING, AND IT IS
-- THE ONE LINE IN THIS MIGRATION THAT IS NOT FROM kit.
--
-- goose splits a migration on every line that ends in a semicolon, and it has no
-- dollar-quote awareness whatsoever — not even for a TAGGED quote. The substrate below
-- is three plpgsql bodies delimited by `$caf$`, and every one of them contains lines
-- ending in `;`, so without the markers goose cuts each function in half at its first
-- `declare`. The failure, measured on this repository's own cluster before the markers
-- were added:
--
--     ERROR: unterminated dollar-quoted string at or near "$caf$"  (SQLSTATE 42601)
--
-- which reads like a quoting mistake in kit's SQL and is not one: the SQL is correct
-- and goose is the thing that cannot read it. `migrations/README.md` records this for
-- every other function body in this directory, and `00012_account_audit_log.sql:126`
-- wraps its trigger function for the same reason.
--
-- THE MARKERS COST THE SUBSTRATE NOTHING, and that is why this file edits kit's copy in
-- exactly one place. Inside StatementBegin/End goose hands the whole block to Postgres
-- as ONE statement over the simple protocol, and Postgres parses dollar quoting
-- correctly — so `$caf$` survives verbatim rather than being rewritten to `$$`. A
-- migration that had re-tagged the quotes would work and would also be a fork of the
-- shared substrate, which is the thing kit's README means by "a template that offers
-- one is a template the weaker one gets chosen from".

-- +goose StatementBegin

-- kit template — the ACCOUNT boundary inside one service's database.
--
--     psql "$MIGRATIONS_DATABASE_URL" -f substrate.sql
--
-- WHAT THIS IS. One schema, one GUC, one setter, one function that protects a
-- table, and one sweep that says whether the service is still isolated. Postgres
-- enforces the account boundary; the application does not have to remember to.
--
-- WHY IT EXISTS HERE AND NOT IN EACH SERVICE. Across the nine account-scoped
-- services there is not one `ROW LEVEL SECURITY`, not one `CREATE POLICY` and not
-- one non-owner login role. Tenancy is enforced entirely by hand-written
-- `WHERE account_id = ?` in six languages, which means it is one forgotten
-- predicate per query per service and the whole suite stays green. A boundary
-- that lives in application code is only as strong as the least recently
-- reviewed query. This is the same trade kit already makes with the database
-- itself, where the boundary is `REVOKE` and not good intentions.
--
-- THE TWO ROLES, AND WHY ONE OF THEM IS THE POINT.
--
--   <service>       the owner. LOGIN, owns the database and every table, runs
--                   migrations. This is the role kit's cluster already
--                   provisions and a service already uses, so adopting this
--                   changes nothing about how a service builds its schema.
--   <service>_app   the LOGIN the application uses. It owns nothing, so it
--                   cannot `ALTER TABLE ... DISABLE ROW LEVEL SECURITY`, drop a
--                   policy, or truncate around one. It is granted DML and
--                   nothing else.
--
-- FORCE ROW LEVEL SECURITY is still required, and it is required for the OWNER.
-- Postgres exempts a table's owner from its own policies; `FORCE` is what removes
-- that exemption. Without it a table whose policies are all in place still reads
-- as fully protected while the role that owns it reads every account's rows, and
-- nothing reports that: the policies are there, `relrowsecurity` is true, and
-- the owner walks straight past them. It is the one setting on this page that
-- Supabase's row-level-security guide does not document and that no lint in this
-- fleet checks for, which is why `templates/database/tenancy/isolation.sql`
-- asserts it by RUNNING the denials as the owner rather than by grepping for it.
--
-- THE CONSEQUENCE, STATED HERE BECAUSE IT WILL SURPRISE SOMEONE. Once a table is
-- protected, the OWNER reads zero rows from it too — no policy names the owner,
-- and FORCE removed the exemption that used to let it through. That is the
-- correct posture and it is also the adoption cost: a migration that has to read
-- or backfill rows either sets the identity (`set local role <service>_app` plus
-- `begin_account`) or goes through a `SECURITY DEFINER` function. A migration
-- that silently reads zero rows fails immediately, which is the good direction,
-- but it is a change to how a service writes backfills and it is worth knowing
-- before the first one runs rather than after.
--
-- THE `(select ...)` WRAPPING IS NOT STYLE.
--
--   using (      cafaye.current_account_id() = account_id )      -- per ROW
--   using ( (select cafaye.current_account_id()) = account_id )  -- per STATEMENT
--
-- Postgres evaluates a bare function call in a policy qualifier once per
-- candidate row and hoists an uncorrelated scalar subquery into an InitPlan that
-- runs once per statement. Measured on this kit, five rows, one call:
--
--     using (account_id = (select probe_id()))   ->  1 call
--     using (account_id = probe_id())            ->  5 calls
--
-- and `tests/tenancy_test.sh` re-measures it on every run, because a comment
-- saying so is not a measurement and this is the sort of difference that is
-- invisible until the table is large, which is the worst time to find it.
-- `protect_table` only ever writes the wrapped form. A hand-written policy that
-- writes the bare form is correct and slow, and nothing in a normal run will
-- ever notice.
--
-- WHAT IS NOT HERE. No JWT parsing, no token format, no session store, and no
-- `auth.uid()`. How a service turns the credential in its hand into an account
-- is that service's own business — identity issues opaque session tokens and
-- guard verifies JWKS bearer JWTs, and a template that picked one of those would
-- be wrong for the other. The seam is `cafaye.begin_account/1`, and a service
-- calls it once per request from whatever it already authenticates.
--
-- Idempotent, deliberately: this is a migration, migrations get re-run by
-- `down`/`up` and by `bin/dev down -v`, and `protect_table` drops and recreates
-- its policies so a re-run converges rather than failing on a duplicate name.

-- Its own schema, and not `public`, so `cafaye` is never part of a sweep over
-- the service's tables and never collides with a name the service chose.
create schema if not exists cafaye;

-- THE ONE SEAM.
--
--   returns NULL when no account has been set  ->  every policy reads zero rows
--   raises      when the value is not a uuid   ->  a plumbing bug, loudly
--
-- The NULL is the load-bearing half and it is deliberate. "No identity" and "an
-- identity that owns none of these rows" are indistinguishable by construction,
-- which is core's `docs/tenancy.md` D33 arriving from the other end: a policy that
-- raised on an absent identity would tell a caller its request was not
-- authenticated, and a caller can be made to believe that about somebody else's
-- request.
--
-- The raise is the other half, and it is not a contradiction. An ABSENT identity
-- is a legitimate state that must read as nothing. A MALFORMED one is a bug in
-- the service's own plumbing, and reading nothing would report it as a service
-- with no data, which is the worst possible way to find out.
create or replace function cafaye.current_account_id()
returns uuid
language plpgsql
stable
as $caf$
declare
  raw text;
begin
  -- `missing_ok = true` is what makes an unset GUC NULL rather than an error.
  -- A dotted custom GUC needs no CREATE to be read: Postgres treats the
  -- placeholder as set-to-empty, which is the second case below.
  raw := current_setting('cafaye.account_id', true);
  if raw is null or raw = '' then
    return null;
  end if;
  return raw::uuid;
exception
  when invalid_text_representation then
    raise exception 'cafaye.account_id is set to % which is not a uuid', raw
      using errcode = '22023',
            hint = 'cafaye.begin_account/1 takes a uuid. A request that reaches the '
                   'database with a malformed account has a bug in whatever '
                   'authenticated it, and this is the cheapest place to find it.';
end
$caf$;

-- SET THE IDENTITY, ONCE PER REQUEST, TRANSACTION-LOCAL.
--
-- `is_local = true` is the whole design. Every one of kit's six drivers holds a
-- POOL, and a session-level account variable on a pooled connection is the worst
-- shape this thing can take: the connection goes back to the pool still carrying
-- tenant A's identity, tenant B is handed it, and tenant B reads tenant A's rows.
-- Transaction-local cannot outlive the request, so a leak needs the caller to
-- forget to open a transaction, which is a different bug with a different
-- symptom.
--
-- A NULL argument CLEARS rather than failing, because "this worker has no
-- account" is a legitimate call and it goes through here rather than through a
-- raw `set_config`, so there is exactly one place in a service's codebase that
-- writes this GUC.
--
-- THE AUTOCOMMIT CONSEQUENCE, STATED RATHER THAN HIDDEN. Outside an explicit
-- transaction, `is_local = true` expires at the end of the statement that set it,
-- so a caller reaching the database in autocommit reads zero rows. That cannot
-- leak and it is loud rather than silent — a service that suddenly sees none of
-- its own data fails its first integration test — and `isolation.sql` runs every
-- case inside an explicit transaction for exactly this reason.
create or replace function cafaye.begin_account(p_account uuid)
returns void
language plpgsql
as $caf$
begin
  if p_account is null then
    perform set_config('cafaye.account_id', '', true);
    return;
  end if;
  perform set_config('cafaye.account_id', p_account::text, true);
end
$caf$;

-- ===========================================================================
-- CREDENTIAL RESOLUTION — the one query whose subject the boundary does not
-- know yet. Read this before changing anything below; MD24 is the decision and
-- its cost, and DECISIONS.md is where the alternatives are recorded as dead.
-- ===========================================================================
--
-- THE PROBLEM, IN ONE SENTENCE. A scoped token, an invitation token and a
-- client id all resolve by "find the row by an unguessable value and learn the
-- account from it", and the account is WHAT THE QUERY IS FOR — so a query with
-- no identity cannot be scoped by an identity it has not computed yet. Measured
-- by `identity` against its real protected `api_keys` table, as the OWNER:
--
--     no identity (the state a token request is in)      0 rows
--     identity = the credential's own account            1 row
--     identity = another tenant's identity               0 rows
--
-- The first line is the finding, and it is the quietest one available: the token
-- does not resolve, `ErrNoRows` becomes "not found", and the HTTP layer answers
-- 401. Every machine credential, refused as though it did not exist.
--
-- WHY NOT THE OTHER THREE ANSWERS. Each is measured or read rather than
-- assumed, and each is written down in `DECISIONS.md` (MD24):
--
--   * A `BYPASSRLS` role — Supabase's answer, and right for Supabase's
--     topology: `service_role` is `nologin noinherit bypassrls` granted only to
--     `authenticator`, and what bounds it is who may assume it plus its object
--     grants. kit has one per-request role and no separate service layer, so a
--     bypass role here is a bypass over the WHOLE DATABASE held by the role
--     every request already authenticates as.
--   * A `SECURITY DEFINER` function — does not work under FORCE. FORCE applies
--     to the definer, and only BYPASSRLS skips RLS; no service role has one.
--   * Dropping FORCE — MD23's measurement: 1 row with, 3 without, on the one
--     table holding every machine credential.
--
-- WHAT IS HERE INSTEAD. One extra `for select` policy, whose qualifier is the
-- value the CALLER PRESENTED, read from a transaction-local GUC:
--
--     using (token_digest = (select cafaye.current_credential_digest()))
--
-- The predicate is in the POLICY and not only in the caller's query, and that is
-- the whole design rather than a detail. RLS policies combine permissively, so a
-- policy that said merely "a credential session may select this table" would hand
-- the caller a table-wide SELECT and let it browse every key in the database
-- with the one query this mechanism exists to prevent. Because the policy
-- carries the same predicate the query carries, the honest semantics are:
--
--     A resolution session may read exactly the credential row whose digest it
--     presented, and nothing else in the database.
--
-- `select * from api_keys` inside one of these sessions returns THAT row, not
-- the table. `isolation.sql` asserts it as `credential/resolution-cannot-browse`
-- and asserts the other half — that the mechanism did not become a general
-- bypass — as `credential/resolution-does-not-open-another-table`.
--
-- WHAT IT CANNOT DO, all five, so nobody has to find them:
--
--   1. It cannot tell a secret from a label. It widens a read to the row whose
--      value you presented, and whether that value is unguessable is the
--      SERVICE's knowledge. `oidc_clients.client_id` is an identifier, not a
--      secret, and this is the wrong mechanism for it. The invariant that keeps
--      the mechanism from becoming a general bypass is exactly that one: you can
--      only widen a read to a row you could already name.
--   2. It cannot write. `for select`, so every write policy still demands an
--      account identity: a resolution session cannot mint a credential.
--   3. It does not open any other table. It is a policy on a named table, and
--      `account_users` still reads zero rows in a resolution session.
--   4. It is transaction-local, like `begin_account/1`, and that is not tidiness
--      — the six drivers hold pools, and a session-level digest survives the
--      pool and hands one resolution's credential to the next connection.
--   5. It is not audited at runtime. The GUC leaves nothing behind; what IS
--      auditable is the SCOPE, and `credential_tables()` below is the one query
--      that answers "which tables in this database can be read with no account".
--      A claim this file cannot honour would be a comment pretending to be a
--      control, so it is not made.
--
-- TWO SEAMS, NOT ONE. `begin_credential/1` is a second transaction-local GUC and
-- the cost of that is real and is why the substrate has no third. It is set in
-- exactly one function, so a service has exactly one place that writes it.

-- The digest the session is resolving. NULL when none is set, and the NULL is
-- load-bearing for the same reason `current_account_id()`'s is: with no digest
-- set, `token_digest = NULL` is never true, so a table carrying only a resolve
-- policy plus an account policy reads nothing at all rather than raising. A
-- credential table is still fully protected without a digest — this policy only
-- ever ADDS the one row whose digest is present.
create or replace function cafaye.current_credential_digest()
returns text
language plpgsql
stable
as $caf$
declare
  raw text;
begin
  -- `missing_ok = true` makes an unset GUC NULL rather than an error; the second
  -- case is Postgres treating an unregistered dotted placeholder as set-to-empty.
  raw := current_setting('cafaye.credential_digest', true);
  if raw is null or raw = '' then
    return null;
  end if;
  return raw;
end
$caf$;

-- OPEN THE RESOLUTION, ONCE, TRANSACTION-LOCAL. The twin of `begin_account/1`,
-- and a NULL argument clears rather than failing, for the same reason.
--
-- THE CALLER PASSES THE VALUE IT ALREADY COMPUTED. A service hashes the token it
-- was handed — that hash is how it was going to query the table anyway — and
-- hands the digest to Postgres as the statement that scopes the read. Postgres
-- does not learn the secret, does not learn how it was derived, and gains no
-- ability to compute one: it is given a string it will compare against a column.
create or replace function cafaye.begin_credential(p_digest text)
returns void
language plpgsql
as $caf$
begin
  if p_digest is null then
    perform set_config('cafaye.credential_digest', '', true);
    return;
  end if;
  perform set_config('cafaye.credential_digest', p_digest, true);
end
$caf$;

-- PROTECT ONE CREDENTIAL TABLE. The one call a credential table's migration
-- makes, and it is ONE call: it protects the table exactly as `protect_table`
-- does — same four policies, same ENABLE, same FORCE, same index on
-- `account_id` — and then adds the fifth. There is no `protect_credential_table`
-- that only adds the resolve policy to a table somebody forgot to protect,
-- because a substrate with two entry points for one table is a substrate where
-- the one nobody reads is the one that ships.
--
--   select cafaye.protect_credential_table('api_keys', 'token_digest');
--
-- The digest column is named in the migration and nowhere else, and naming it
-- IS the declaration: it is the column whose value a caller must already hold to
-- resolve a credential on this table, and the README says what makes a value
-- suitable (it has to be unguessable, or this mechanism is the wrong one).
create or replace function cafaye.protect_credential_table(
  p_table regclass,
  p_digest_column text,
  p_login_role text default null
)
returns void
language plpgsql
as $caf$
declare
  login_role text := coalesce(p_login_role, current_user || '_app');
  base text;
  qual text;
begin
  -- 0. THE COLUMN NAME IS A BARE IDENTIFIER. `%I` quotes it, so this is not
  --    about injection; it is about a typo becoming a policy nobody notices,
  --    which is the failure a database-boundary file exists to make loud.
  if p_digest_column is null
     or p_digest_column !~ '^[A-Za-z_][A-Za-z0-9_$]*$' then
    raise exception 'cafaye.protect_credential_table(%, %): the digest column must be one bare column name, and % is not one.', p_table, coalesce(p_digest_column, '<null>'), coalesce(p_digest_column, 'null')
      using errcode = 'undefined_column',
            hint = 'The second argument is the column a caller presents to resolve a credential on this table — `token_digest` for a hashed API key, `token` for a hashed invitation. It is a column of this table and nothing else.';
  end if;

  -- 1. AND IT EXISTS, before `protect_table` runs, so a misspelt column does not
  --    half-install a table.
  if not exists (
    select 1 from pg_attribute
    where attrelid = p_table and attname = p_digest_column and not attisdropped
  ) then
    raise exception 'cafaye.protect_credential_table(%, %): the table has no % column.', p_table, login_role, p_digest_column
      using errcode = 'undefined_column',
            hint = 'A credential table resolves by the column a caller presents. Name the one this table has; if it has none, this table is not resolved by an unguessable value and does not want this mechanism.';
  end if;

  -- 2. THE SAME PROTECTION AS EVERY OTHER ACCOUNT-SCOPED TABLE. This calls the
  --    other function rather than repeating it, so a fix to one is a fix to both
  --    and there is no second copy of ENABLE/FORCE to drift.
  perform cafaye.protect_table(p_table, p_login_role);

  base := (select c.relname from pg_class c where c.oid = p_table::regclass::oid);

  -- 3. THE INDEX ON THE DIGEST COLUMN, for the reason `protect_table` creates one
  --    on `account_id`: a policy is a filter on every candidate row, and this one
  --    filters on the column the resolution query is keyed by.
  execute format('create index if not exists %I on %s (%I)',
                 base || '_cafaye_' || p_digest_column || '_idx', p_table, p_digest_column);

  -- 4. ONE POLICY, FOR ONE COMMAND, FOR THE TWO NAMED ROLES, WITH THE PREDICATE
  --    THE CALLER'S OWN QUERY CARRIES.
  --
  --    `for select` and nothing else is what makes item 2 of "what it cannot do"
  --    true: there is no `insert`/`update`/`delete` counterpart, so a resolution
  --    session meets the ordinary account policies on the write side and a NULL
  --    identity there is `42501`.
  --
  --    The `(select ...)` wrapping is the same InitPlan discipline as every other
  --    policy in this file, for the same measured reason: `tests/tenancy_test.sh`
  --    measures 1 call wrapped against 5 bare on five rows, on every run.
  qual := format('%I = (select cafaye.current_credential_digest())', p_digest_column);

  --    DROP before CREATE, so a re-run converges and a corrected qualifier cannot
  --    survive one.
  execute format('drop policy if exists %I on %s', base || '_cafaye_resolve', p_table);
  execute format('create policy %I on %s for select to %I, %I using (%s)',
                 base || '_cafaye_resolve', p_table, current_user, login_role, qual);

  -- 5. USAGE on `cafaye`, for the same reason `protect_table` grants it: without
  --    it the login role cannot resolve `cafaye.begin_credential/1` and every
  --    resolution fails with `permission denied for schema cafaye`.
  if to_regnamespace('cafaye') is not null then
    execute format('grant usage on schema cafaye to %I', login_role);
  end if;
end
$caf$;

-- WHICH TABLES CAN BE READ WITHOUT AN ACCOUNT. The audit for item 5 above: one
-- query, and not a code search.
--
-- It reads the POLICIES rather than a list, for the reason the sweep reads
-- `pg_class`: a table this function could only know about because
-- `protect_credential_table` created it would be satisfied by a mechanism that
-- records nothing. The policy name and the rendered qualifier are both required,
-- so a hand-written policy that merely mentions the digest does not appear here
-- and a policy named like this one with a different qualifier does not either.
--
-- It answers the SCOPE question and only that one. It cannot answer "who
-- resolved what", and this file does not pretend otherwise: the digest is
-- transaction-local and gone by the time anything could look at it.
-- ONE CAPTURE GROUP, AROUND THE COLUMN AND NOTHING ELSE. `pg_get_expr` is a
-- pretty-printer, so the qualifier this file writes renders back as
-- `(token_digest = ( SELECT cafaye.current_credential_digest() AS …))` — its own
-- capitalisation, spacing and alias. A regexp written against the SQL executed
-- rather than against what the catalog prints matches nothing here, and an audit
-- query that returns an empty column forever looks exactly like an audit query
-- that found nothing.
create or replace function cafaye.credential_tables()
returns table (table_schema text, table_name text, digest_column text)
language sql
stable
as $caf$
  select n.nspname::text,
         c.relname::text,
         (regexp_match(
            lower(coalesce(pg_get_expr(p.polqual, p.polrelid), '')),
            '^ *\(?([a-z_][a-z0-9_$]*) = \( *select cafaye\.current_credential_digest\(\)'
          ))[1]::text
    from pg_policy p
    join pg_class c on c.oid = p.polrelid
    join pg_namespace n on n.oid = c.relnamespace
   where p.polname like '%!_cafaye!_resolve' escape '!'
     and p.polcmd = 'r'
     and lower(coalesce(pg_get_expr(p.polqual, p.polrelid), ''))
         like '%cafaye.current_credential_digest()%'
   order by n.nspname, c.relname
$caf$;

-- PROTECT ONE ACCOUNT-SCOPED TABLE. The only thing a migration calls.
--
--   select cafaye.protect_table('assets');                 -- the owner's role
--   select cafaye.protect_table('assets', 'darkroom_app'); -- explicit login role
--
-- Everything it does is required and everything it does is idempotent. There is
-- no `protect_table_lite`, and there is no way to ask it for a policy without
-- FORCE, because a template that offers the weaker version is a template the
-- weaker version gets chosen from.
create or replace function cafaye.protect_table(
  p_table regclass,
  p_login_role text default null
)
returns void
language plpgsql
as $caf$
declare
  login_role text := coalesce(p_login_role, current_user || '_app');
  qual text := 'account_id = (select cafaye.current_account_id())';
  base text;
begin
  -- 0. THE LOGIN ROLE HAS TO EXIST, and saying so by name is the difference
  --    between a diagnosable failure and a confusing one. Postgres reports a
  --    missing role in `create policy` as `role "courier_app" does not exist`,
  --    six lines into a function, with the table named by the context and the
  --    fix not. This is the check that turns that into one sentence.
  if not exists (select 1 from pg_roles where rolname = login_role and rolcanlogin) then
    raise exception 'cafaye.protect_table(%, %): % is not a LOGIN role on this cluster.', p_table, login_role, login_role
      using errcode = 'undefined_object',
            hint = 'kit''s cluster provisions <service> and <service>_app. Either the _app role has not been provisioned — this service was added to KIT_POSTGRES_DATABASES before it existed, and the init script only runs on a fresh volume — or pass the login role explicitly as the second argument.';
  end if;

  -- 1. THE COLUMN, OR STOP. A table with no `account_id` cannot be scoped by
  --    account, and protecting it anyway would create policies whose predicate
  --    cannot be evaluated — which Postgres resolves as "not true", i.e. a table
  --    nobody can read, which is a much harder failure to diagnose than this one.
  if not exists (
    select 1 from pg_attribute
    where attrelid = p_table and attname = 'account_id' and not attisdropped
  ) then
    raise exception 'cafaye.protect_table(%, %): the table has no account_id column, so there is nothing to scope it by.', p_table, login_role
      using errcode = 'undefined_column',
            hint = 'Either the column is spelled something else — write the policy yourself and name the fleet''s key — or this table is not account-scoped and should not be protected. A service holding no customer rows is core''s honest zero and needs none of this.';
  end if;

  base := (select c.relname from pg_class c where c.oid = p_table::regclass::oid);

  -- 2. THE INDEX, IN THE SAME FUNCTION, BECAUSE A POLICY IS A FILTER ON EVERY
  --    ROW AND AN UNINDEXED ONE IS A SEQUENTIAL SCAN. Postgres evaluates the
  --    policy against each candidate row, so an account-scoped table read
  --    through its primary key still has to filter on `account_id`, and without
  --    this index that is a full scan behind a primary-key lookup. Named
  --    deterministically so a re-run converges rather than making a second one.
  execute format('create index if not exists %I on %s (account_id)', base || '_cafaye_account_id_idx', p_table);

  -- 3. REVOKE FROM PUBLIC BEFORE ENABLING. A table's default privileges come
  --    from its owner and from whatever has been granted on it; PUBLIC is not
  --    among them unless somebody granted it. Revoking is one statement, and it
  --    means the answer to "who can read this" is not "whoever the last
  --    migration remembered".
  execute format('revoke all on table %s from public', p_table);

  -- 4. ENABLE, THEN FORCE. Two statements, and the second is the one that is in
  --    nobody's blog post.
  --
  --    Without FORCE a table's OWNER is exempt from its policies. Every service
  --    in this fleet runs its migrations as its own role, so without FORCE the
  --    role that owns the table reads every account's rows while the policies
  --    read as though they were in place. `pg_class.relforcerowsecurity` is the
  --    only catalog that says otherwise, and `isolation.sql` asserts it by
  --    running the denials AS THE OWNER — which is the only assertion that
  --    cannot be satisfied by a policy that exists.
  execute format('alter table %s enable row level security', p_table);
  execute format('alter table %s force row level security', p_table);

  -- 5. FOUR POLICIES, ONE PER COMMAND, ALL NAMED, FOR TWO NAMED ROLES.
  --
  --    Naming the roles with `to <owner>, <login>` rather than leaving it to PUBLIC
  --    is not tidiness: an unnamed policy is evaluated for every role including the
  --    ones that should never reach the table, and the role filter is what stops
  --    the evaluation early. It is also the first thing Supabase's guide tells you
  --    to do and the first thing everybody skips.
  --
  --    The OWNER is in the list, and that is not a convenience. FORCE removes the
  --    owner's exemption, so without an owner policy the owner reads NOTHING from
  --    a protected table — no rows, including its own — and a service that runs
  --    background work and migrations as that role discovers it by seeing empty
  --    result sets. Naming it means the owner's reads are ACCOUNT-SCOPED rather
  --    than absent: a migration sets an identity and reads exactly one account's
  --    rows, which is the same rule every other request obeys and the only version
  --    of "the owner may read" that is not "the owner may read everything".
  --
  --    One policy per command rather than one `for all` is what keeps a later
  --    grant additive — a policy added for one command cannot widen another. The
  --    `for all` shape with `using (true)` and `with check (...)` is the one that
  --    silently permits an INSERT nobody meant to permit, and it is the shape
  --    every "permissive RLS policy" lint is written to flag.
  --
  --    `insert` has no `using` — an INSERT has no existing row to filter — and
  --    its `with check` is what stops a row being created in somebody else's
  --    account, which is the write-side twin of the read denial.
  --
  --    DROP before CREATE so the function is re-runnable, and so a policy whose
  --    definition has been corrected here cannot survive a re-run.
  execute format('drop policy if exists %I on %s', base || '_cafaye_select', p_table);
  execute format('drop policy if exists %I on %s', base || '_cafaye_insert', p_table);
  execute format('drop policy if exists %I on %s', base || '_cafaye_update', p_table);
  execute format('drop policy if exists %I on %s', base || '_cafaye_delete', p_table);

  execute format('create policy %I on %s for select to %I, %I using (%s)', base || '_cafaye_select', p_table, current_user, login_role, qual);
  execute format('create policy %I on %s for insert to %I, %I with check (%s)', base || '_cafaye_insert', p_table, current_user, login_role, qual);
  execute format('create policy %I on %s for update to %I, %I using (%s) with check (%s)', base || '_cafaye_update', p_table, current_user, login_role, qual, qual);
  execute format('create policy %I on %s for delete to %I, %I using (%s)', base || '_cafaye_delete', p_table, current_user, login_role, qual);

  -- 6. AND THE LOGIN ROLE GETS DML AND NOTHING ELSE. No ownership, no DDL, no
  --    CREATE on the schema, no ability to change a policy. A grant that gives a
  --    login role more than it needs is a grant that has to be re-examined every
  --    time somebody adds a privilege, and this is the one place that list lives.
  --
  --    USAGE on `cafaye` is in the list and is not optional: without it the login
  --    role cannot resolve `cafaye.begin_account/1` at all, so the first thing a
  --    service does after adopting this is a `permission denied for schema
  --    cafaye` on every request.
  execute format('grant usage on schema public to %I', login_role);
  if to_regnamespace('cafaye') is not null then
    execute format('grant usage on schema cafaye to %I', login_role);
  end if;
  execute format('grant select, insert, update, delete on table %s to %I', p_table, login_role);
end
$caf$;

-- SWEEP: every account-scoped table in the schemas THIS SUBSTRATE OWNS,
-- protected or not.
--
-- Returns one row per table that is NOT, so a caller can report all of them
-- rather than the first. It returns rather than raising because a caller that
-- gets rows can print them, and a caller that gets an exception has to parse the
-- message. This is the query that answers "is this service isolated?".
--
-- THE COLUMN IS THE DEFINITION OF ACCOUNT-SCOPED, and it is a definition rather
-- than a list because a list is a thing to remember. A table that grows an
-- `account_id` column and no policies appears here on the next run, which is the
-- moment before it matters.
--
-- THE SCOPE IS THE SCHEMAS THE SUBSTRATE WAS APPLIED IN, and that is the whole
-- difference between this function and a scan of every table in the database.
-- The property being asserted is "every account-scoped table THE SERVICE
-- INSTALLED is protected", and its input is the set of tables the substrate was
-- applied to — a whole-database scan is one way to compute that set, and it is
-- the way that breaks every adopter.
--
-- MEASURED, on identity: its test helper builds a private fixture schema per
-- test by cloning tables with `LIKE … INCLUDING ALL`, and `LIKE` does not copy
-- row-level security. Each fixture therefore carries an `account_id` column and
-- no policies. A whole-database sweep named every one of them, so a correct
-- database produced a red proof — and the count moved with how many neighbouring
-- tests were mid-flight (5 on one run, 21 on the next), which is what says it
-- was a reach rather than a defect. A sweep that cannot stay green on a correct
-- database is a sweep nobody reads, and one that goes red for somebody else's
-- fixtures is a sweep an adopter has to work around, which is worse.
--
-- THE SCOPE IS DERIVED, NOT RECORDED, and the difference is the reason an
-- adopter needs no migration to get the fix. There is no registry table, because
-- a registry would have to be created by the NEW substrate and every database
-- that has applied the OLD one does not have it — so the fix would only arrive
-- with a migration, and the proofs it is meant to repair are the thing that
-- decides whether the migration is needed. Instead the scope is read back out of
-- what the substrate ALREADY wrote: `protect_table` names its policies
-- `<table>_cafaye_<command>` and creates an index beside them, so every schema
-- the substrate was applied in is discoverable from the catalog, with nothing
-- new to install and nothing to remember to update.
--
-- Extension-owned tables are excluded (`pg_depend.deptype = 'e'`): pgvector,
-- PostGIS and friends ship their own tables with their own grants, and reporting
-- a table this substrate cannot protect would train the reader to ignore the
-- sweep.
--
-- TEMPORARY TABLES ARE NOT EXCLUDED, and that is deliberate. A temp table with an
-- `account_id` column and no policies is genuinely unprotected, it is exactly
-- the shape a service's test fixture has, and `isolation.sql` plants one on
-- purpose as its sweep's control. It is safe to INCLUDE this file's own session's
-- temporary schema for the reason a fixture schema is not: temporary objects are
-- per-session, so no other session — not another test, not another service — can
-- put a table in scope by creating one. `pg_temp` is the alias; the real schema
-- is named `pg_temp_N`, which is why this is a prefix test and not an equality.
create or replace function cafaye.unprotected_tables()
returns table (table_schema text, table_name text, why text)
language sql
stable
as $caf$
  with scoped(nspname) as (
    -- (1) The substrate's own schema. It holds functions rather than rows, so
    --     this contributes nothing today; it is here so that a table added to
    --     `cafaye` later cannot be quietly unowned by the exclusion this query
    --     used to carry.
    select 'cafaye'::name
    -- (2) This session's temporary schema, where `isolation.sql` plants its
    --     control table. Per-session, so it can never carry another session's.
    union
    select n.nspname
      from pg_namespace n
     where n.nspname = 'pg_temp' or left(n.nspname, 8) = 'pg_temp_'
    -- (3) Every schema the substrate was applied IN, read back from the policies
    --     `protect_table` wrote. A schema qualifies when it holds at least one
    --     table this substrate protected, which is what makes the scope the
    --     service's own tables rather than a list somebody maintains: a new
    --     account-scoped table added NEXT MONTH to a schema already in scope is
    --     named on the next run, with nothing having been updated anywhere.
    union
    select n.nspname
      from pg_namespace n
      join pg_class c on c.relnamespace = n.oid
      join pg_policy p on p.polrelid = c.oid
     where c.relkind = 'r'
       and p.polname ~ '_cafaye_(select|insert|update|delete)$'
  )
  select n.nspname::text,
         c.relname::text,
         case
           when not c.relrowsecurity then 'row level security is not enabled'
           when not c.relforcerowsecurity then 'row level security is not FORCED, so the table owner bypasses it'
           when not exists (select 1 from pg_policy p where p.polrelid = c.oid) then 'row level security is enabled with no policy, so every row is hidden'
           else ''
         end
  from pg_class c
  join pg_namespace n on n.oid = c.relnamespace
  left join pg_depend d on d.objid = c.oid and d.deptype = 'e'
  where c.relkind = 'r'
    and d.objid is null
    and n.nspname in (select s.nspname from scoped s)
    and exists (
      select 1 from pg_attribute a
      where a.attrelid = c.oid and a.attname = 'account_id' and not a.attisdropped
    )
    and (
      not c.relrowsecurity
      or not c.relforcerowsecurity
      or not exists (select 1 from pg_policy p where p.polrelid = c.oid)
    )
  order by n.nspname, c.relname
$caf$;

-- ---------------------------------------------------------------------------
-- A login role that OWNS an account-scoped table can switch that table's
-- policies off, and no amount of FORCE stops it: FORCE is about the owner being
-- SUBJECT to policies, not about the owner being unable to REMOVE them. So the
-- second half of the design is a role that owns nothing, and that claim has
-- nothing to sweep — it is a fact about one role and one table, so it is asserted
-- about the role the application actually logs in as rather than generalised into
-- a query that would have to guess which role that is. `isolation.sql` asserts
-- it three ways, and the two that matter are the ones no catalog reports: the
-- login role is refused `ALTER TABLE ... DISABLE ROW LEVEL SECURITY`, and it is
-- refused `DROP POLICY`.
--
-- WHAT THIS FILE DOES NOT PROVE, because every item below is a way the boundary
-- can be right in the database and absent from the service.
--
--   * That the service SETS the identity. `begin_account/1` is one call in one
--     place, and nothing here can tell a service that never calls it from one
--     that calls it in every request. A service that forgets reads zero rows,
--     which is safe and extremely visible, so this is a diagnosis rather than a
--     leak.
--
--   * That the service's QUERIES still carry their own `where account_id = ?`.
--     They should. RLS is defence in depth, not a licence to delete the
--     predicate: the predicate is what makes the query indexable, and it is what
--     a mistake in the policy expression gets caught by. core's
--     `schemas/tenant-isolation.schema.json` still requires the predicate and this
--     file does not change that.
--
--   * That the login role is not a MEMBER of the owner role. The cluster grants
--     `<service>_app` TO `<service>` so a migration and `tests/isolation_test.sh`
--     can impersonate the weaker role; the reverse membership would undo the
--     entire design and is worth asserting in the services that adopt this.
--
--   * That a TABLE is account-scoped. The sweep defines that as "has an
--     `account_id` column", which is the fleet's own vocabulary (D7), and it
--     misses a service that spells it `tenant_id` and protects it by hand. A
--     service with no account-scoped tables at all is the honest zero, and
--     core's `tenancy.honest-zero` finding is what says so out loud.
--
--   * That a SCHEMA the substrate was never applied to holds no account-scoped
--     table. The sweep's scope is the schemas it protected, plus its own and
--     `pg_temp`, so customer rows kept in a schema no `protect_table` call ever
--     named are outside it. That is the trade, and it is a deliberate one: the
--     alternative reports every other session's test fixture, which is how a
--     correct database ends up with a red proof and how an adopter ends up
--     carrying a workaround for a bug that was upstream. A service whose account
--     tables span schemas the substrate has not met is a service that has not
--     protected them, and `protect_table` is one call per table.
-- ---------------------------------------------------------------------------
-- +goose StatementEnd

-- ---------------------------------------------------------------------------
-- IDENTITY'S ACCOUNT-SCOPED TABLES. The whole decision, five calls.
--
-- Each call does all of it for one table: the `account_id` index (a policy is a
-- filter on every row, and an unindexed one is a sequential scan behind a primary-key
-- lookup), `REVOKE … FROM PUBLIC`, `enable` AND `force` row level security, four
-- named policies — one per command, for the owner and for `identity_app`, never for
-- PUBLIC — and DML grants to `identity_app` and nothing else.
--
-- THE LOGIN ROLE IS `identity_app`, NOT `identity`. The default is
-- `current_user || '_app'` and this migration runs as `identity`, so it resolves to
-- `identity_app`, which kit's cluster provisions from `KIT_POSTGRES_DATABASES:
-- identity` alongside the owner. `identity_app` owns nothing, so it cannot
-- `ALTER TABLE … DISABLE ROW LEVEL SECURITY`, cannot drop a policy, and cannot
-- truncate around one. The application switching to that role is the NEXT packet and
-- is deliberately not in this one: it touches every query's behaviour.
--
-- NOT `cafaye.protect_table('accounts')`. The account table has no `account_id`, and
-- `protect_table` refuses that by name rather than creating policies whose predicate
-- cannot be evaluated — a table nobody can read is a much harder failure to diagnose
-- than one that says why.
--
-- `begin_account/1` is NOT CALLED HERE. It is transaction-local and expires at the end
-- of the statement that set it, so a migration calling it outside a transaction would
-- set an identity that is already gone. This migration only installs the boundary; the
-- application turns it on per request, in its own transaction, in the next packet.

-- WHO MAY BE A MEMBER OF AN ACCOUNT. The membership itself, its roles and its scopes
-- — this is the table an admin surface reads, and an admin reading another account's
-- membership is a disclosure of who works where.
select cafaye.protect_table('account_users');

-- AN INVITATION ADDRESSED INTO AN ACCOUNT. Its unique index is already the
-- account_id-leading partial index 00007 built for exactly this query.
--
-- `account_invitations.token_digest` is a secret in the same sense `api_keys.token_digest`
-- is — a 256-bit random value whose only stored form is a hash — so
-- `protect_credential_table('account_invitations', 'token_digest')` WOULD be the right
-- call here, and it is NOT made yet. The mechanism is one call in a migration and one
-- `cafaye.begin_credential` in the Go path, and taking the first without the second
-- breaks redemption the same way this migration just fixed api_keys: the lookup would
-- read zero rows and every invitation would be refused. They are ONE change and this
-- migration does not make half of it; the exact call and the exact call site are in
-- HANDOFF-identity-isolation.md.
select cafaye.protect_table('account_invitations');

-- THE SERVICE'S OWN CREDENTIAL FOR AN ACCOUNT. Read another account's and you hold a
-- bearer token for it, so this is the row whose isolation matters most — AND the one
-- table of the five that is resolved by a secret rather than by an account.
--
-- WHY THIS CALL IS NOT `protect_table`, which is the sentence this migration exists to
-- record. `apikeys.ByDigest` runs `SELECT … FROM api_keys k JOIN account_users au ON …
-- WHERE k.token_digest = $1`, with no `account_id` predicate and none it could carry:
-- the account is what the query is FOR, so a per-request identity cannot scope it. With
-- this table protected the ordinary way that query read ZERO rows for a request with no
-- identity — the state every scoped-token request is in — and ErrNotFound became 401.
-- Every machine credential in the fleet, refused as though it had never existed.
--
-- `protect_credential_table` adds one `for select` policy whose USING clause is
-- `token_digest = (select cafaye.current_credential_digest())`, so the POLICY carries
-- the same predicate the caller's own query carries. The honest semantics, which is
-- NARROWER than "reads nothing" and not one bit wider: a resolution session may read
-- exactly the row whose digest it presented, in either role, and cannot write at all —
-- there is no insert/update/delete counterpart, so a resolution session meets the
-- ordinary account policies on the write side and a NULL identity there is 42501.
--
-- `token_digest` is the correct second argument, and naming it IS the declaration: the
-- value a caller must already hold to resolve a row here is a 256-bit secret, hashed by
-- `Digest` before any query runs, and Postgres never sees the token. The mechanism cannot
-- tell a secret from a label, which is why the OTHER two lookups in this service do not
-- get this call — see `oidc_clients` below, where the presented value is a public
-- identifier and the mechanism is the wrong tool by construction.
select cafaye.protect_credential_table('api_keys', 'token_digest');

-- A CLIENT'S CREDENTIALS. `client_secret_hash` in somebody else's row is the same
-- disclosure as the row above.
--
-- DELIBERATELY `protect_table` AND NOT `protect_credential_table`, and the reason is the
-- mechanism's own first limitation rather than a preference. The OIDC lookup is by
-- `client_id`, which travels in the authorization URL and is therefore a PUBLIC
-- IDENTIFIER, and `protect_credential_table` widens a read to the row whose value the
-- caller presented — so on `client_id` it hands every anonymous requester one row of
-- another tenant's client. It cannot tell a secret from a label and this is a label. The
-- honest answers are (a) resolve on `client_secret` at the token endpoint, where the
-- value is genuinely unguessable, and (b) treat the authorization endpoint's `client_id`
-- lookup as a different problem this mechanism does not answer. Neither is this
-- migration's to guess at, and guessing would be applying the mechanism exactly where it
-- has been measured not to belong.
select cafaye.protect_table('oidc_clients');

-- THE AUDIT TRAIL. Immutable by trigger, so it is also the one table where a
-- cross-account read cannot be explained away by a recent write.
select cafaye.protect_table('account_audit_log');

-- +goose Down

-- UNDO THE BOUNDARY AND NOTHING ELSE. These five tables and their columns are what
-- 00006, 00007, 00009, 00011 and 00012 created; this migration changed nothing about
-- any of them, so it owns only the policies, the SIX indexes the substrate added, and
-- the schema it created.
--
-- `disable row level security` BEFORE `drop policy`, and the order is not tidiness: a
-- table with policies and no RLS enabled hides every row from everybody, so dropping
-- first would leave five tables unreadable in the window between the two statements.
-- `force` is dropped with `disable` in the same statement — they are two reloptions on
-- the same table and Postgres clears both when RLS is switched off.
--
-- THE GRANTS TO identity_app ARE NOT REVOKED, and that is deliberate rather than
-- forgotten. `protect_table` granted DML on these tables to a role that could not use
-- it before this migration, and a Down that took it away again would leave identity_app
-- holding DML on tables it must not be able to read — a weaker state than either side
-- of this migration. identity_app's usefulness comes from the policies, and it is
-- granted no ownership, so revoking the grant cannot widen anything either. If the
-- grant is genuinely unwanted, it is one statement and it belongs in the same commit
-- as a decision to remove the role, not here.
alter table account_users     disable row level security;
alter table account_invitations disable row level security;
alter table oidc_clients      disable row level security;
alter table api_keys          disable row level security;
alter table account_audit_log disable row level security;

drop policy if exists account_users_cafaye_select     on account_users;
drop policy if exists account_users_cafaye_insert     on account_users;
drop policy if exists account_users_cafaye_update     on account_users;
drop policy if exists account_users_cafaye_delete     on account_users;
drop policy if exists account_invitations_cafaye_select on account_invitations;
drop policy if exists account_invitations_cafaye_insert on account_invitations;
drop policy if exists account_invitations_cafaye_update on account_invitations;
drop policy if exists account_invitations_cafaye_delete on account_invitations;
drop policy if exists oidc_clients_cafaye_select      on oidc_clients;
drop policy if exists oidc_clients_cafaye_insert      on oidc_clients;
drop policy if exists oidc_clients_cafaye_update      on oidc_clients;
drop policy if exists oidc_clients_cafaye_delete      on oidc_clients;
drop policy if exists api_keys_cafaye_select          on api_keys;
drop policy if exists api_keys_cafaye_insert          on api_keys;
drop policy if exists api_keys_cafaye_update          on api_keys;
drop policy if exists api_keys_cafaye_delete          on api_keys;
-- The fifth one: the resolve policy `protect_credential_table` adds. It is named here
-- rather than left to the `cascade` because `cafaye.credential_tables()` READS THE
-- POLICIES, so a policy that outlived its table's RLS would keep answering "this table
-- can be read with no account" on a database where it no longer can — an audit query
-- that has gone stale is worse than no audit query.
drop policy if exists api_keys_cafaye_resolve         on api_keys;
drop policy if exists account_audit_log_cafaye_select on account_audit_log;
drop policy if exists account_audit_log_cafaye_insert on account_audit_log;
drop policy if exists account_audit_log_cafaye_update on account_audit_log;
drop policy if exists account_audit_log_cafaye_delete on account_audit_log;

-- The index protect_table created. `if exists` because a Down that assumes its own Up
-- ran is a Down that fails on a partially applied database, which is the one moment a
-- Down is actually wanted.
drop index if exists account_users_cafaye_account_id_idx;
drop index if exists account_invitations_cafaye_account_id_idx;
drop index if exists oidc_clients_cafaye_account_id_idx;
drop index if exists api_keys_cafaye_account_id_idx;
drop index if exists api_keys_cafaye_token_digest_idx;
drop index if exists account_audit_log_cafaye_account_id_idx;

-- `cascade` because the functions live in the schema and the schema is what is being
-- removed; naming them first and dropping the schema second would be two ways to fail
-- for the same result. Nothing outside this schema references any of them — the
-- functions are reached by name from a service that has not called them yet.
drop schema if exists cafaye cascade;

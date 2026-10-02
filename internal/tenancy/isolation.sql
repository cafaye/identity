-- kit template — the assertion set that proves an account boundary.
--
--     psql "$MIGRATIONS_DATABASE_URL" -f isolation.sql
--
-- ONE FILE, SIX LANGUAGES. This is the whole assertion set, and it is one file
-- because the assertions are about POSTGRES rather than about a language: the
-- denial a request meets is a denial Postgres returns. Each language's driver
-- (`templates/database/<lang>/tenancy_test.*`) runs this script and then asserts,
-- BY NAME, that every row below came back and that every verdict is `pass`. A
-- driver that stops naming them goes red, which is what makes six thin drivers
-- safe rather than six copies to keep in step.
--
-- THE SHAPE IS THREE DENIALS AND ONE ALLOWANCE, and it is three rather than one
-- because one proves nothing:
--
--   no identity                                   reads zero rows
--   ANOTHER tenant's VALID identity, on its rows  reads zero rows
--   its OWN identity                              reads its own rows, and not the other's
--
-- The first is satisfied by a table with no policy at all — which is the bug — and
-- the last is satisfied by a policy that permits everything. Only the three
-- together are the property, and each is run against BOTH roles: the login role
-- the application authenticates as, and the owner the service's migrations run as.
--
-- WHY THE OWNER IS IN THERE. Postgres exempts a table's OWNER from its own
-- policies unless `ALTER TABLE ... FORCE ROW LEVEL SECURITY` says otherwise, and
-- every service in this fleet runs its migrations as its own role — so the owner
-- IS the role that builds these tables, and the role a developer has open in
-- `psql`. Without FORCE every denial above passes for the login role and the
-- owner reads everything. Measured on this kit, a protected three-row table, read
-- as the owner with another tenant's identity:
--
--     with FORCE      1 row    (its own)
--     without FORCE   3 rows   (every tenant's)
--
-- `FORCE` is not in Supabase's row-level-security guide, no lint in this fleet
-- checks for it, and a table with policies, `relrowsecurity = true` and no FORCE
-- looks completely correct in review. That is why the owner half exists, and why
-- it is the half that cannot be satisfied by a policy which is merely present.
--
-- TWO CONTROLS, because a green answer from a check that cannot see its own
-- defect is worse than no answer at all:
--
--   `sweep/names-an-unprotected-table`      `cafaye.unprotected_tables()` really
--                                            does report a table with an
--                                            `account_id` column and no policies.
--                                            Without it, the sweep's empty result
--                                            is satisfied by a sweep that reports
--                                            nothing.
--   `policies/written-for-the-init-plan`    every policy qualifier is a subquery,
--                                            not a bare call. Measured on this
--                                            kit, five rows, one query: the
--                                            wrapped form calls once, the bare
--                                            form five times.
--
-- HOW TO RUN IT, AND WHAT IT LEAVES BEHIND.
--
--   Run it as a role that may `SET ROLE`: the owner. kit's cluster grants
--   `<service>_app` TO `<service>` for exactly this, and impersonating a strictly
--   weaker role cannot widen anything.
--
--   It opens a transaction and does NOT close it. Two things need one: the
--   identity is transaction-local (so a caller in autocommit reads zero rows and
--   every case would pass for the wrong reason), and `SET LOCAL ROLE` is refused
--   outside a transaction block. Every object it creates is TEMPORARY, so it
--   disappears with the session whether the session commits or rolls back — there
--   is nothing here that can outlive the connection, and no cleanup step to
--   forget. Roll back when you are done.
--
-- The output is one table. `verdict` is `pass` or `fail`; `expected` and `actual`
-- are text so a driver's comparison is a string equality in all six languages;
-- and `why` says what the assertion is FOR, so a red row is diagnosable from the
-- report alone rather than by opening this file.

begin;

-- ---------------------------------------------------------------------------
-- Preflight. A substrate that is not installed, or a service that has no login
-- role, is a loud failure here rather than a table of red rows that all say the
-- same thing for different reasons.
-- ---------------------------------------------------------------------------
do $preflight$
begin
  if to_regprocedure('cafaye.protect_table(regclass,text)') is null then
    raise exception 'the tenancy substrate is not installed in this database.'
      using errcode = 'undefined_function',
            hint = 'Apply templates/database/tenancy/substrate.sql first.';
  end if;
  if not exists (select 1 from pg_roles where rolname = current_user || '_app' and rolcanlogin) then
    raise exception 'this database has no %_app LOGIN role, so there is no login role to prove anything about.', current_user
      using errcode = 'undefined_object',
            hint = 'kit''s cluster provisions <service> and <service>_app. A service added to KIT_POSTGRES_DATABASES after the volume was created does not get one, because the init script only runs on a fresh volume: recreate the volume, or apply bin/dev db grant.';
  end if;
end
$preflight$;

-- ---------------------------------------------------------------------------
-- Three helpers, all in `pg_temp` so a run leaves nothing in the database.
-- ---------------------------------------------------------------------------

-- The comparison is text equality and nothing else. A tolerant comparison here
-- would make every driver inherit the tolerance, and there is no version of
-- "close enough" that means "another tenant's rows are still hidden".
--
-- `security definer`, owned by the invoking role, because half of these
-- assertions run AS the login role and the result table belongs to the session
-- that started the proof. A SECURITY INVOKER helper would be writing a table it
-- has no privilege on for most of this file's cases, and the failure would be
-- `permission denied for table cafaye_probe_result` rather than an assertion.
-- It is not a privilege escalation: a `pg_temp` function cannot outlive the
-- session, and its owner is the role that created it.
create or replace function pg_temp.cafaye_assert(
  p_assertion text, p_expected text, p_actual text, p_why text
) returns void
language plpgsql
security definer
as $fn$
declare
  seen text := coalesce(p_actual, '<null>');
begin
  insert into pg_temp.cafaye_probe_result (assertion, expected, actual, verdict, why)
  values (p_assertion, p_expected, seen,
          case when seen = p_expected then 'pass' else 'fail' end, p_why);
end
$fn$;
alter function pg_temp.cafaye_assert(text, text, text, text) owner to current_user;

-- For the three shapes that RAISE rather than return nothing. Everything else in
-- this file is an empty result, because core's D33 says a cross-tenant access
-- must be indistinguishable from nonexistence and a `403` is an enumeration
-- oracle. These three are not cross-tenant reads: one writes into another
-- account, and two switch the boundary off. All three are refused by a privilege
-- check, where an error is the correct answer and leaks nothing.
--
-- IT RETURNS THE SQLSTATE INSTEAD OF RECORDING, and that is load-bearing rather
-- than a style choice. It has to be called AS the login role — a SECURITY DEFINER
-- wrapper would run the statement as the owner, and the whole point of
-- `login-role/cannot-disable-row-level-security` is that the owner CAN do it. A
-- recorder built the obvious way therefore succeeds at disabling the boundary,
-- records "no error", and leaves the table unprotected for every assertion after
-- it. That is not hypothetical: it is what the first version of this file did,
-- and it reported three failures whose only common cause was its own harness.
--
-- So the caller sets the role (outside any exception block, see `cafaye_as`),
-- calls this, resets the role, and records the answer as the session role — which
-- is the one role with privilege on the result table.
create or replace function pg_temp.cafaye_observed(p_sql text)
returns text
language plpgsql
as $fn$
begin
  begin
    execute p_sql;
    return 'no error';
  exception
    when others then
      return sqlstate;
  end;
end
$fn$;

-- `SET LOCAL ROLE`, issued OUTSIDE every exception block below, and that is
-- load-bearing rather than tidy. Every `exception` clause opens a subtransaction,
-- and a role change made inside one is discarded when that subtransaction ends —
-- so a `set role` inside an exception handler is silently undone by the very
-- handler that caught the error, and every assertion after it runs as the wrong
-- role and passes for the wrong reason. This function has no exception block of
-- its own for that reason, and neither does anything that calls it.
create or replace function pg_temp.cafaye_as(p_role text)
returns void
language plpgsql
as $fn$
begin
  execute format('set local role %I', p_role);
end
$fn$;

-- The two tenants, as constants rather than generated, so every expected count
-- below is readable and a red row can be diagnosed by eye.
create or replace function pg_temp.cafaye_alpha() returns uuid
language sql immutable as $fn$ select '11111111-1111-1111-1111-111111111111'::uuid $fn$;

create or replace function pg_temp.cafaye_beta() returns uuid
language sql immutable as $fn$ select '22222222-2222-2222-2222-222222222222'::uuid $fn$;

create temp table pg_temp.cafaye_probe_result (
  assertion text primary key,
  expected text not null,
  actual text not null,
  verdict text not null,
  why text not null
) on commit drop;

-- ---------------------------------------------------------------------------
-- The fixture. TEMPORARY, so it cannot outlive the session, and created in
-- `pg_temp` so it never appears in the service's real schema. Two tables: one
-- protected, one deliberately not.
-- ---------------------------------------------------------------------------
create temp table cafaye_probe_things (
  id uuid primary key default gen_random_uuid(),
  account_id uuid not null,
  label text not null
) on commit drop;

insert into cafaye_probe_things (account_id, label) values
  (pg_temp.cafaye_alpha(), 'alpha-1'),
  (pg_temp.cafaye_alpha(), 'alpha-2'),
  (pg_temp.cafaye_beta(),  'beta-1');

-- The control table. An `account_id` column and NO policies: the state a service
-- reaches by adding a column to a new table and forgetting the substrate. It
-- exists for the sweep's positive control and for nothing else.
create temp table cafaye_probe_unprotected (
  id int primary key,
  account_id uuid not null
) on commit drop;

select cafaye.protect_table('pg_temp.cafaye_probe_things');

-- ===========================================================================
-- THE SPINE. Three denials and one allowance, per role.
-- ===========================================================================
do $spine$
declare
  r text;
begin
  foreach r in array array['login', 'owner'] loop
    -- `login` is the role the application authenticates as and owns nothing.
    -- `owner` is the role this script's migrations run as, which is the role
    -- FORCE is about. Both must be denied.
    if r = 'login' then
      perform pg_temp.cafaye_as(current_user || '_app');
    else
      perform pg_temp.cafaye_as(current_user);
    end if;

    -- (1) NO IDENTITY READS ZERO ROWS.
    perform cafaye.begin_account(null);
    perform pg_temp.cafaye_assert(
      r || '/no-identity-reads-no-rows', '0',
      (select count(*)::text from pg_temp.cafaye_probe_things),
      'a request with no account set must see nothing at all: not one tenant, not an error, and not a hint that the table has rows'
    );

    -- (2) ANOTHER TENANT'S VALID IDENTITY, ON THAT TENANT'S OWN ROWS, READS ZERO.
    perform cafaye.begin_account(pg_temp.cafaye_beta());
    perform pg_temp.cafaye_assert(
      r || '/another-tenants-rows-read-as-none', '0',
      (select count(*)::text from pg_temp.cafaye_probe_things where account_id = pg_temp.cafaye_alpha()),
      'a request carrying another tenant''s VALID identity must not read that tenant''s rows. This is the assertion an unenforced table fails, and the only one that does'
    );

    -- (3) ITS OWN IDENTITY READS ITS OWN ROWS. The allowance, and the half that
    -- stops the two above from being satisfied by a table nobody can read.
    perform cafaye.begin_account(pg_temp.cafaye_alpha());
    perform pg_temp.cafaye_assert(
      r || '/own-rows-are-visible', '2',
      (select count(*)::text from pg_temp.cafaye_probe_things where account_id = pg_temp.cafaye_alpha()),
      'a request carrying its own identity must read its own rows. Without this, "reads zero rows" is satisfied by a policy that denies everything'
    );

    -- (4) AND ONLY ITS OWN. The count of an UNQUALIFIED read, which is the shape
    -- a listing endpoint issues, and which stops assertion 3 from being satisfied
    -- by a policy that permits everything.
    perform pg_temp.cafaye_assert(
      r || '/own-identity-reads-only-its-own-rows', '2',
      (select count(*)::text from pg_temp.cafaye_probe_things),
      'an unqualified read as alpha must return alpha''s two rows and not beta''s third: this is what a listing endpoint issues'
    );

    -- (5) THE MIRROR OF 4, because one direction could be an accident: a policy
    -- mis-scoped so that alpha happens to see everything and beta happens to see
    -- nothing is still one broken direction.
    perform cafaye.begin_account(pg_temp.cafaye_beta());
    perform pg_temp.cafaye_assert(
      r || '/another-identity-reads-only-its-own-rows', '1',
      (select count(*)::text from pg_temp.cafaye_probe_things),
      'an unqualified read as beta must return beta''s single row: the other direction of assertion 4'
    );

    reset role;
  end loop;
end
$spine$;

-- ===========================================================================
-- THE WRITE SIDE. A `using` clause filters the row out and matches nothing; it
-- does not raise. "Matched zero rows" is only a proof once the row it targeted
-- is shown to be intact, so every denied write is paired with a read of that row.
-- Pairing them is the difference between an assertion and a typo.
--
-- The pairing read runs as ALPHA, not as the role that made the attempt. That is
-- not a detail: the attempt is made as beta, and beta cannot see alpha's rows at
-- all, so a read from beta returns NULL for a row that is present and correct.
-- Reading the row back as its owner is also the shape the claim has: "the denied
-- write changed nothing" is only observable by somebody who can see the row.
-- ===========================================================================
do $writes$
declare
  updated integer;
  deleted integer;
begin
  perform pg_temp.cafaye_as(current_user || '_app');
  perform cafaye.begin_account(pg_temp.cafaye_beta());

  update pg_temp.cafaye_probe_things set label = 'stolen'
    where account_id = pg_temp.cafaye_alpha();
  get diagnostics updated = row_count;
  perform pg_temp.cafaye_assert(
    'login/update-of-another-tenants-row-affects-no-rows', '0', updated::text,
    'an UPDATE aimed at another account''s rows must match nothing. It does not raise — that is the shape of a `using` denial — so the row count is the only thing that says it was refused'
  );

  delete from pg_temp.cafaye_probe_things where account_id = pg_temp.cafaye_alpha();
  get diagnostics deleted = row_count;
  perform pg_temp.cafaye_assert(
    'login/delete-of-another-tenants-row-affects-no-rows', '0', deleted::text,
    'a DELETE aimed at another account''s rows must match nothing'
  );

  reset role;
  perform cafaye.begin_account(pg_temp.cafaye_alpha());

  perform pg_temp.cafaye_assert(
    'login/denied-writes-left-the-other-tenants-rows-intact', 'alpha-1,alpha-2',
    (select string_agg(label, ',' order by label)::text
       from pg_temp.cafaye_probe_things where account_id = pg_temp.cafaye_alpha()),
    'both denied writes must have left the other account''s rows exactly as they were. Read back as alpha, because the role that made the attempt cannot see the rows it was aiming at'
  );

  -- ...and the attempter's own rows are still its own, which is what stops the
  -- pair above from being satisfied by a policy that refuses every write.
  perform cafaye.begin_account(pg_temp.cafaye_beta());
  perform pg_temp.cafaye_assert(
    'login/own-rows-survive-its-own-writes', 'beta-1',
    (select label::text from pg_temp.cafaye_probe_things where account_id = pg_temp.cafaye_beta()),
    'the denied writes must not have disturbed the caller''s own rows'
  );

  reset role;
end
$writes$;

-- ===========================================================================
-- THE ROLE HALF. A login role that OWNS an account-scoped table can switch that
-- table's policies off, and no amount of FORCE stops it: FORCE is about the owner
-- being SUBJECT to policies, not about the owner being unable to REMOVE them.
--
-- Nothing in the catalogs reports the second thing. `relforcerowsecurity` says
-- the owner is subject to the policies; it says nothing about whether the owner
-- can delete them. So the property is asserted by ATTEMPTING it, as the login
-- role, and reading the answer off the server.
--
-- The third case here is the only cross-tenant WRITE that raises rather than
-- matching nothing: an INSERT has no existing row to filter, so its policy
-- carries only `with check`, and a mismatch is a privilege failure. 42501 is
-- `insufficient_privilege`, which is the code Postgres uses for `with check`. It
-- leaks nothing — it says the INSERT was refused, not that the account exists.
-- ===========================================================================
do $role_half$
declare
  seen text;
begin
  perform pg_temp.cafaye_as(current_user || '_app');

  -- An INSERT naming ANOTHER account. This is the write-side twin of the read
  -- denial, and the only cross-tenant write in this file that can raise.
  seen := pg_temp.cafaye_observed(format(
    'insert into pg_temp.cafaye_probe_things (account_id, label) values (%L, %L)',
    pg_temp.cafaye_alpha()::text, 'intruder'));
  reset role;
  perform pg_temp.cafaye_assert(
    'login/insert-into-another-tenants-account-is-refused', '42501', seen,
    'an INSERT naming another account must be refused outright. There is no `using` on an INSERT, so `with check` is the whole boundary, and this is the only cross-tenant write that can raise rather than match nothing');

  perform pg_temp.cafaye_as(current_user || '_app');
  seen := pg_temp.cafaye_observed(
    'alter table pg_temp.cafaye_probe_things disable row level security');
  reset role;
  perform pg_temp.cafaye_assert(
    'login-role/cannot-disable-row-level-security', '42501', seen,
    'the login role must be REFUSED the ability to switch the boundary off. No catalog can report this, and it is the whole reason the login role owns nothing: a role that could disable RLS would need no privilege at all to become unbounded');

  perform pg_temp.cafaye_as(current_user || '_app');
  seen := pg_temp.cafaye_observed(
    'drop policy cafaye_probe_things_cafaye_select on pg_temp.cafaye_probe_things');
  reset role;
  perform pg_temp.cafaye_assert(
    'login-role/cannot-drop-a-policy', '42501', seen,
    'the login role must be REFUSED the ability to remove a policy. A role that could drop a policy needs no privilege at all to become unbounded, and there is no FORCE against it');
end
$role_half$;

select pg_temp.cafaye_assert(
  'login-role/is-not-the-table-owner', 'true',
  (select (pg_get_userbyid(c.relowner) <> current_user || '_app')::text
     from pg_class c where c.oid = 'pg_temp.cafaye_probe_things'::regclass),
  'the login role must not own the table. The two refusals above are the only thing standing between it and every account''s rows, and FORCE does not provide them'
);

-- ...and its positive counterpart, because "every insert is refused" is also a
-- state that passes a denial test. Run last, so the INSERT it makes is the one
-- row the count below is looking for.
do $insert_ok$
begin
  perform pg_temp.cafaye_as(current_user || '_app');
  perform cafaye.begin_account(pg_temp.cafaye_beta());
  insert into pg_temp.cafaye_probe_things (account_id, label)
  values (pg_temp.cafaye_beta(), 'beta-2');
  perform pg_temp.cafaye_assert(
    'login/insert-into-its-own-account-is-allowed', '1',
    (select count(*)::text from pg_temp.cafaye_probe_things where label = 'beta-2'),
    'an INSERT into the caller''s own account must succeed. Without this, the refusal above is satisfied by a policy that refuses every write, which is a state a service reaches by accident when a `with check` is written against the wrong column');
  reset role;
end
$insert_ok$;

-- ===========================================================================
-- THE POLICY SHAPE. Two properties no denial above can see, because both are
-- about how the policies are WRITTEN rather than about what they return.
-- ===========================================================================

-- Supabase's guide's first rule, and the one everybody skips: name the roles in
-- the policy. An unnamed policy is `TO PUBLIC`, which means it is evaluated for
-- every role on the cluster including the nine other services'.
select pg_temp.cafaye_assert(
  'policies/name-the-roles', '0',
  (select count(*)::text
     from pg_policy p
    where p.polrelid = 'pg_temp.cafaye_probe_things'::regclass
      and (p.polroles = '{0}'::oid[]
           or not (p.polroles @> ARRAY[
                 (select oid from pg_roles where rolname = current_user || '_app')::oid,
                 (select oid from pg_roles where rolname = current_user)::oid
               ]::oid[]))),
  'every policy must name the login role and the owner explicitly. A policy left at the default is TO PUBLIC, which evaluates it for every role on the cluster'
);

-- THE `(select ...)` WRAPPING, asserted structurally because it cannot be
-- asserted by a denial: a bare call and a wrapped call return exactly the same
-- rows. The measured difference is in how many times the function runs — 1 versus
-- 5 on five rows, re-measured on every run of tests/tenancy_test.sh.
--
-- The rendering is normalised the way Supabase's own permissive-policy lint
-- normalises it (strip spaces, newlines and tabs, lowercase) because `pg_get_expr`
-- is a pretty-printer and its output is not a stable string.
select pg_temp.cafaye_assert(
  'policies/written-for-the-init-plan', '0',
  (select count(*)::text
     from pg_policy p
    where p.polrelid = 'pg_temp.cafaye_probe_things'::regclass
      and strpos(
            replace(replace(replace(
              lower(coalesce(pg_get_expr(p.polqual, p.polrelid), '')
                     || coalesce(pg_get_expr(p.polwithcheck, p.polrelid), '')),
              ' ', ''), E'\n', ''), E'\t', ''),
            '(select') = 0),
  'every policy qualifier must wrap the identity call in (select …). A bare call is re-evaluated per candidate row and a subquery is hoisted into an InitPlan and evaluated once per statement: measured on this kit, one call against five on a five-row table'
);

-- ===========================================================================
-- THE SWEEP, AND ITS CONTROL.
-- ===========================================================================

-- The control. Without it, an empty sweep is satisfied by a sweep that reports
-- nothing, which is the same shape as an isolation test that only asserts "no
-- identity reads zero rows".
select pg_temp.cafaye_assert(
  'sweep/names-an-unprotected-table', '1',
  (select count(*)::text from cafaye.unprotected_tables()
    where table_name = 'cafaye_probe_unprotected'),
  'cafaye.unprotected_tables() must actually report a table with an account_id column and no policies. If it does not, the assertion below is satisfied by a sweep that reports nothing at all'
);

-- The sweep itself, over the whole database — every schema, not just this
-- fixture's. This is the assertion that keeps a service honest as it grows: a
-- table added next month with an account_id column and no policies is named here
-- on the next run.
select pg_temp.cafaye_assert(
  'sweep/every-account-scoped-table-is-protected', '1',
  (select count(*)::text from cafaye.unprotected_tables()),
  'every account-scoped table in this database must be enabled, FORCED and carrying policies. Exactly one is expected to be reported: the control table this file created on purpose'
);

select pg_temp.cafaye_assert(
  'sweep/the-only-finding-is-the-control', 'cafaye_probe_unprotected:row level security is not enabled',
  (select string_agg(table_name || ':' || why, ',')
     from cafaye.unprotected_tables()),
  'the sweep must name the control table and nothing else, with a reason. A sweep that reported a real table as well would mean this file''s own fixture was not protected'
);

-- ---------------------------------------------------------------------------
-- The result. `on commit drop` on the table above means a session that commits
-- takes it with it; this file leaves the transaction open so a caller can read
-- these rows first.
-- ---------------------------------------------------------------------------
select assertion, expected, actual, verdict, why
  from pg_temp.cafaye_probe_result
 order by assertion;
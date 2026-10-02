-- 00017_credential_audit_dependencies.sql — the credential audit stops reading a
-- spelling, because the spelling depends on who is reading.
--
-- WHAT THIS MIGRATION IS. `migrations/00016_account_isolation.sql` embeds a copy
-- of kit's `templates/database/tenancy/substrate.sql`, taken before
-- kit-rls-advisor-02 rewrote `credential_tables()`. The copy was never compared
-- against the template again, so it drifted, and it drifted into a query that is
-- wrong for the role an operator auditing credentials is logged in as.
--
-- MEASURED, on a scratch postgres:17, with both bodies installed side by side
-- against the same catalog in the same session (the harness is
-- `bin/credential-audit-drift`, and this is its output):
--
--   role      rows                     digest_column
--   identity  OLD (in 00016)           api_keys/token_digest
--   identity  NEW (here)               api_keys/token_digest
--   cafaye    OLD (in 00016)           (none)
--   cafaye    NEW (here)               api_keys/token_digest
--
-- THE MECHANISM, because "the regexp was too strict" is the wrong diagnosis and
-- would be fixed by loosening it. The old query recovered the column name by
-- pattern-matching the text `pg_get_expr(polqual, polrelid)` prints, and
-- `pg_get_expr` omits the schema of any name the READER could resolve — where the
-- reader is the session, `"$user"` is a `search_path` entry, and kit's cluster
-- admin role is `cafaye` (`KIT_POSTGRES_USER: ${KIT_POSTGRES_USER:-cafaye}` in
-- kit's `templates/compose/docker-compose.yml`). So ONE policy deparses two ways:
--
--   as identity  (token_digest = ( SELECT cafaye.current_credential_digest() AS ...))
--   as cafaye    (token_digest = ( SELECT current_credential_digest() AS ...))
--
-- and the old pattern requires the literal `cafaye.`, so it matches the first and
-- not the second.
--
-- WHY THAT IS WORTH A PACKET. As `cafaye` the old query returns ZERO ROWS, and
-- zero rows reads as "no table in this database can be resolved without an
-- account" — the answer an operator is most likely to believe, and the one this
-- query exists to make loud. The failure is also unfalsifiable from its own
-- output: an empty result set is indistinguishable from a correct one. That is
-- the whole thesis in one query — a check that cannot fail loudly is not a check.
--
-- WHY THIS IS A NEW FILE AND NOT AN EDIT TO 00016. 00016 has been applied in
-- deployed environments. Editing an applied migration changes the file the next
-- environment applies and not the one the deployed ones ran, which is how two
-- environments holding the same migration count diverge silently. This migration
-- installs the corrected function and touches nothing else: the substrate is
-- otherwise byte-identical to kit's, verified function by function.
--
-- WHY IT IS EXACTLY ONE FUNCTION. Compared against kit at
-- templates/database/tenancy/substrate.sql, all seven of the substrate's
-- functions hash equal except `credential_tables` — `current_account_id`,
-- `begin_account`, `current_credential_digest`, `begin_credential`,
-- `protect_table` and `protect_credential_table` are byte-identical. So this
-- replaces one function body rather than re-applying a whole template over a
-- database that already has one, and a re-apply would have had to be trusted to
-- be a no-op on everything it did not mean to touch.
--
-- WHAT DOES NOT CHANGE. The signature, the return columns, the volatility and
-- the `stable` marking are all unchanged, so no caller can tell. `CREATE OR
-- REPLACE` on the same signature keeps the existing OID, so any grant made on the
-- old function still applies and nothing has to be re-granted.

-- +goose Up
-- +goose StatementBegin
-- The body below is VERBATIM from kit's templates/database/tenancy/substrate.sql at
-- kit commit efa49e5, from `create or replace function` through its closing `$caf$;`
-- with nothing inserted between -- not even a comment, because a comment inside the
-- body is a byte difference and `internal/platform/ci/substrate_copy_test.go`
-- compares the two byte for byte. Kit's comment above that function is the argument
-- for it and is not duplicated here on purpose: one argument in one file is a fact,
-- and a second copy of it in this repository is the thing this migration exists to
-- stop.
create or replace function cafaye.credential_tables()
returns table (table_schema text, table_name text, digest_column text)
language sql
stable
as $caf$
  -- (1) The digest function, by OID. `pronargs = 0` is part of the identity and
  --     not decoration — see cost 3 above.
  with digest_fn as (
    select fn.oid
      from pg_proc fn
      join pg_namespace fns on fns.oid = fn.pronamespace
     where fns.nspname = 'cafaye'
       and fn.proname = 'current_credential_digest'
       and fn.pronargs = 0
  ),

  -- (2) The policies in the substrate's own naming that call it, with the columns
  --     of THEIR OWN table that the call sits beside. `cd.refobjid = pol.polrelid`
  --     is what keeps a qualifier that reads another table's column out: the
  --     audit is about what THIS table resolves by.
  resolve as (
    select pol.oid as policy_oid,
           pol.polrelid,
           att.attname as column_name
      from pg_policy pol
      join pg_depend fd
        on fd.classid = 'pg_policy'::regclass
       and fd.objid = pol.oid
       and fd.refclassid = 'pg_proc'::regclass
       and fd.deptype = 'n'
      join digest_fn df on df.oid = fd.refobjid
      left join pg_depend cd
        on cd.classid = 'pg_policy'::regclass
       and cd.objid = pol.oid
       and cd.refclassid = 'pg_class'::regclass
       and cd.refobjid = pol.polrelid
       and cd.refobjsubid > 0
      left join pg_attribute att
        on att.attrelid = pol.polrelid
       and att.attnum = cd.refobjsubid
       and not att.attisdropped
     where pol.polname like '%!_cafaye!_resolve' escape '!'
       and pol.polcmd = 'r'
  )

  -- (3) One row per policy. The column is reported only when the qualifier names
  --     exactly one of the table's own columns, and `'(unresolved)'` otherwise —
  --     cost 4 above. `min()` is never the answer; it is what a single-column
  --     qualifier reduces to.
  select n.nspname::text,
         c.relname::text,
         case when g.columns_named = 1 then g.column_name
              else '(unresolved)' end
    from (select policy_oid,
                 polrelid,
                 count(distinct column_name) as columns_named,
                 min(column_name)            as column_name
            from resolve
           group by policy_oid, polrelid) g
    join pg_class c on c.oid = g.polrelid
    join pg_namespace n on n.oid = c.relnamespace
   order by n.nspname, c.relname
$caf$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- The definition 00016 installed, restored byte for byte.
--
-- THIS IS A ROLLBACK TO A GREEN BOOT, NOT A ROLLBACK TO SAFETY. The body below
-- is the one this migration exists to remove, and it is wrong for the `cafaye`
-- role for the reason in this file's header. It is here because `goose down` has
-- to return the tree to the state the previous migration left it in, and dropping
-- the function instead would turn an audit that lies into one that errors at the
-- call site — a louder failure, but a different schema, and the migration
-- contract is a reversal rather than an improvement.
--
-- If you are reaching for this to fix something, the fix is a forward migration.
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
-- +goose StatementEnd
-- 00001_init.sql — the marker migration.
--
-- This file exists to establish the goose convention, not to create anything.
-- v0 of identity has no schema: the service boots, answers /healthz and
-- /readyz, and stops. The first real migration is the one that adds the users
-- table in a later packet, and it will be 00002_.
--
-- See README.md in this directory for how migrations run in dev and in prod.

-- +goose Up

-- +goose Down

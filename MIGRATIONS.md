# Database migrations

The backend uses additive, versioned migrations managed by `migrations.js` and recorded in `schema_migrations`, running against PostgreSQL (see `db.js`). The datastore was SQLite (`node:sqlite`) through migration 13; migrations from here on assume Postgres.

## Migration 1: tenant foundation

Applied September 7, 2026. It:

- Adds `organizations`, `schools`, `campuses`, and `memberships`.
- Adds nullable `school_id` and appropriate `campus_id` columns to existing school-owned tables.
- Creates a default organization, school, and campus.
- Assigns all existing records and users to that default tenant.
- Adds tenant lookup indexes.
- Does not remove tables, columns, or existing records.

The intentionally nullable tenant columns are a compatibility stage. They should become required only after all create/update paths and operational tables are tenant-aware and a validation query confirms that no null tenant values remain.

## Current constraint limitation

`student_number` is still globally unique across every school, stricter than necessary for multiple schools sharing one database. `school_years.name` had the same problem but was scoped to `(school_id, name)` in migration 2.

## SQLite → PostgreSQL (2026-09-14)

The backend originally ran on `node:sqlite`'s `DatabaseSync` (synchronous, file-based). It now runs on PostgreSQL via `pg`, both in production (Railway) and local dev — see `db.js` for the connection/query layer and `README`-level setup in `.env.example`. This was a fresh-start port: no SQLite data was migrated, since the local `data/school.db` only ever held seed/dev data. The old `database.js`, its `backend/data/`, and the pre-tenant-migration SQLite backup under `backend/backups/` (all git-ignored, local-only) were removed as part of the port.

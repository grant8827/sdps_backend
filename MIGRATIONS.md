# Database migrations

The backend uses additive, versioned migrations managed by `migrations.js` and recorded in `schema_migrations`.

## Migration 1: tenant foundation

Applied September 7, 2026. It:

- Adds `organizations`, `schools`, `campuses`, and `memberships`.
- Adds nullable `school_id` and appropriate `campus_id` columns to existing school-owned tables.
- Creates a default organization, school, and campus.
- Assigns all existing records and users to that default tenant.
- Adds tenant lookup indexes.
- Does not remove tables, columns, or existing records.

The intentionally nullable tenant columns are a compatibility stage. They should become required only after all create/update paths and operational tables are tenant-aware and a validation query confirms that no null tenant values remain.

## Rollback checkpoint

The pre-migration SQLite database, WAL, and shared-memory files are stored locally at:

`backend/backups/pre-tenant-2026-09-07/`

The backup directory is ignored by source control because it contains application data. Stop the backend before restoring SQLite files.

## Current constraint limitation

Some original uniqueness rules are still global, including student number and school-year name. They are stricter than necessary for multiple schools. Changing them requires rebuilding SQLite tables, so that work is deliberately deferred to a separately backed-up migration rather than performed destructively in this migration.

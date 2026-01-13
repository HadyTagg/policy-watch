# Migrations

Database migrations live in this directory. Policy Watch bootstraps the SQLite schema automatically on startup, and also applies any missing columns in code.

## Files

- `001_init.sql` - Base schema for users, config, categories, policies, policy versions, and email log tables.

## Usage

- Start the application to create or update the database automatically.
- To initialize a fresh database manually, run the SQL in `001_init.sql` against a new SQLite database.
- When upgrading older databases, the app will add any missing columns or supplemental tables on launch.

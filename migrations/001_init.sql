CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    role TEXT NOT NULL,
    created_at TEXT NOT NULL,
    disabled INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS categories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS policies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    slug TEXT NOT NULL,
    category TEXT NOT NULL,
    status TEXT NOT NULL,
    ratified INTEGER NOT NULL DEFAULT 0,
    ratified_at TEXT,
    ratified_by_user_id INTEGER,
    effective_date TEXT NOT NULL,
    review_due_date TEXT NOT NULL,
    review_frequency_months INTEGER,
    notes TEXT,
    current_version_id INTEGER,
    created_at TEXT NOT NULL,
    created_by_user_id INTEGER,
    FOREIGN KEY (ratified_by_user_id) REFERENCES users(id),
    FOREIGN KEY (created_by_user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS policy_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    policy_id INTEGER NOT NULL,
    version_number INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    created_by_user_id INTEGER,
    file_path TEXT NOT NULL,
    original_filename TEXT NOT NULL,
    file_size_bytes INTEGER NOT NULL,
    sha256_hash TEXT NOT NULL,
    ratified INTEGER NOT NULL DEFAULT 0,
    ratified_at TEXT,
    ratified_by_user_id INTEGER,
    status TEXT,
    effective_date TEXT,
    review_due_date TEXT,
    review_frequency_months INTEGER,
    notes TEXT,
    replacement_accepted INTEGER,
    owner TEXT,
    FOREIGN KEY (policy_id) REFERENCES policies(id),
    FOREIGN KEY (created_by_user_id) REFERENCES users(id),
    FOREIGN KEY (ratified_by_user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS policy_reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    policy_id INTEGER NOT NULL,
    policy_version_id INTEGER NOT NULL,
    reviewed_at TEXT NOT NULL,
    reviewed_by_user_id INTEGER,
    notes TEXT,
    no_change INTEGER NOT NULL DEFAULT 1,
    FOREIGN KEY (policy_id) REFERENCES policies(id),
    FOREIGN KEY (policy_version_id) REFERENCES policy_versions(id),
    FOREIGN KEY (reviewed_by_user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS policy_review_carryovers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_version_id INTEGER NOT NULL,
    replacement_version_id INTEGER NOT NULL,
    carried_at TEXT NOT NULL,
    FOREIGN KEY (source_version_id) REFERENCES policy_versions(id),
    FOREIGN KEY (replacement_version_id) REFERENCES policy_versions(id)
);

CREATE TABLE IF NOT EXISTS email_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sent_at TEXT NOT NULL,
    sender_windows_user TEXT NOT NULL,
    sender_mailbox TEXT,
    recipient_name TEXT NOT NULL,
    recipient_email TEXT NOT NULL,
    policy_id INTEGER NOT NULL,
    policy_title TEXT NOT NULL,
    policy_version_id INTEGER NOT NULL,
    version_number INTEGER NOT NULL,
    email_subject TEXT NOT NULL,
    email_part_index INTEGER NOT NULL,
    email_part_total INTEGER NOT NULL,
    total_attachment_bytes_for_part INTEGER NOT NULL,
    outlook_entry_id TEXT,
    status TEXT NOT NULL,
    error_text TEXT,
    prev_row_hash TEXT NOT NULL,
    row_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_state (
    singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
    latest_row_hash TEXT NOT NULL
);

CREATE TRIGGER IF NOT EXISTS email_log_no_update
BEFORE UPDATE ON email_log
BEGIN
    SELECT RAISE(ABORT, 'email_log is append-only');
END;

CREATE TRIGGER IF NOT EXISTS email_log_no_delete
BEFORE DELETE ON email_log
BEGIN
    SELECT RAISE(ABORT, 'email_log is append-only');
END;

-- Accepted feedback. Rows past retention become tombstones (deleted = 1, content cleared)
-- so the read feed can tell clients to drop them, then are purged later.
CREATE TABLE feedback (
  id TEXT PRIMARY KEY,
  cursor INTEGER NOT NULL UNIQUE,
  submission_id TEXT NOT NULL UNIQUE,
  digest TEXT NOT NULL,
  received_at TEXT NOT NULL,
  received_ms INTEGER NOT NULL,
  ip_hash TEXT,
  deleted INTEGER NOT NULL DEFAULT 0,
  schema_version INTEGER,
  install_id TEXT,
  source TEXT,
  category TEXT,
  message TEXT,
  scope TEXT,
  screen TEXT,
  session_ref TEXT,
  lattice_version TEXT,
  provider TEXT,
  model TEXT,
  classification_state TEXT NOT NULL DEFAULT 'pending',
  off_topic INTEGER,
  abusive INTEGER,
  classification_reason TEXT,
  classifier_version TEXT,
  classify_attempts INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX feedback_install_time ON feedback (install_id, received_ms);
CREATE INDEX feedback_ip_time ON feedback (ip_hash, received_ms);
CREATE INDEX feedback_time ON feedback (received_ms);
CREATE INDEX feedback_state ON feedback (classification_state, received_ms);

-- Install keys, issued once per install after a Turnstile pass. Only the SHA-256 is stored.
-- Revoke with: UPDATE install_keys SET revoked_at = datetime('now') WHERE install_id = '...';
CREATE TABLE install_keys (
  key_hash TEXT PRIMARY KEY,
  install_id TEXT NOT NULL,
  ticket_id TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  created_ms INTEGER NOT NULL,
  revoked_at TEXT,
  last_used_ms INTEGER
);
CREATE INDEX install_keys_install ON install_keys (install_id);

-- Monotonic change cursor for the read feed.
CREATE TABLE seq (name TEXT PRIMARY KEY, value INTEGER NOT NULL);
INSERT INTO seq (name, value) VALUES ('cursor', 0);

-- Short-lived abuse counters (attempts per IP per minute, key creations per IP per day,
-- daily classifier retry budget).
CREATE TABLE counters (key TEXT PRIMARY KEY, count INTEGER NOT NULL, expires_ms INTEGER NOT NULL);
CREATE INDEX counters_expiry ON counters (expires_ms);

-- Advanced Exam Tracker - Cloudflare D1 schema
-- IMPORTANT: This replaces the old users table if it was only a test table.
-- Run in D1 -> userdb -> Studio -> Console/SQL.

DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS topic_progress;
DROP TABLE IF EXISTS exam_settings;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE sessions (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_sessions_user ON sessions(user_id);
CREATE INDEX idx_sessions_expiry ON sessions(expires_at);

CREATE TABLE topic_progress (
  user_id TEXT NOT NULL,
  topic_id INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'NotStarted'
    CHECK(status IN ('NotStarted','InProgress','NeedsReview','Mastered')),
  last_reviewed TEXT,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (user_id, topic_id),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE exam_settings (
  user_id TEXT PRIMARY KEY,
  exam_date TEXT,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

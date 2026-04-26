CREATE TABLE IF NOT EXISTS bot_files (
  id BIGSERIAL PRIMARY KEY,
  file_unique_id TEXT NOT NULL,
  file_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  file_name TEXT NOT NULL,
  mime_type TEXT,
  file_size BIGINT,
  title TEXT,
  uploader_id BIGINT NOT NULL,
  uploader_name TEXT,
  download_count BIGINT NOT NULL DEFAULT 0,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (file_unique_id, kind)
);

CREATE INDEX IF NOT EXISTS bot_files_active_created_idx
  ON bot_files (is_active, created_at DESC);

CREATE INDEX IF NOT EXISTS bot_files_search_idx
  ON bot_files USING GIN (
    to_tsvector('simple', coalesce(title, '') || ' ' || coalesce(file_name, '') || ' ' || coalesce(mime_type, ''))
  );

CREATE TABLE IF NOT EXISTS bot_users (
  telegram_id BIGINT PRIMARY KEY,
  username TEXT,
  first_name TEXT,
  last_name TEXT,
  is_authorized BOOLEAN NOT NULL DEFAULT FALSE,
  authorized_at TIMESTAMPTZ,
  authorized_by_password_id BIGINT,
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS bot_settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_by BIGINT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS bot_user_passwords (
  id BIGSERIAL PRIMARY KEY,
  password_hash TEXT NOT NULL,
  salt TEXT NOT NULL,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_by BIGINT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_used_at TIMESTAMPTZ,
  use_count BIGINT NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS bot_user_passwords_active_idx
  ON bot_user_passwords (is_active, created_at DESC);

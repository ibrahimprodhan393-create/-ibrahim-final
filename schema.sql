CREATE TABLE IF NOT EXISTS bot_files (
  id BIGSERIAL PRIMARY KEY,
  file_unique_id TEXT NOT NULL,
  file_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  file_name TEXT NOT NULL,
  mime_type TEXT,
  file_size BIGINT,
  title TEXT,
  description TEXT,
  uploader_id BIGINT NOT NULL,
  uploader_name TEXT,
  download_count BIGINT NOT NULL DEFAULT 0,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (file_unique_id, kind)
);

ALTER TABLE bot_files
  ADD COLUMN IF NOT EXISTS description TEXT;

CREATE INDEX IF NOT EXISTS bot_files_active_created_idx
  ON bot_files (is_active, created_at DESC);

CREATE INDEX IF NOT EXISTS bot_files_search_idx
  ON bot_files USING GIN (
    to_tsvector('simple', coalesce(title, '') || ' ' || coalesce(description, '') || ' ' || coalesce(file_name, '') || ' ' || coalesce(mime_type, ''))
  );

CREATE TABLE IF NOT EXISTS bot_links (
  id BIGSERIAL PRIMARY KEY,
  title TEXT NOT NULL,
  url TEXT NOT NULL,
  description TEXT,
  uploader_id BIGINT NOT NULL,
  uploader_name TEXT,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE bot_links
  ADD COLUMN IF NOT EXISTS description TEXT;

CREATE INDEX IF NOT EXISTS bot_links_active_created_idx
  ON bot_links (is_active, created_at DESC);

CREATE INDEX IF NOT EXISTS bot_links_search_idx
  ON bot_links USING GIN (
    to_tsvector('simple', coalesce(title, '') || ' ' || coalesce(description, '') || ' ' || coalesce(url, ''))
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

ALTER TABLE bot_users
  ADD COLUMN IF NOT EXISTS is_authorized BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE bot_users
  ADD COLUMN IF NOT EXISTS authorized_at TIMESTAMPTZ;

ALTER TABLE bot_users
  ADD COLUMN IF NOT EXISTS authorized_by_password_id BIGINT;

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
  password_preview TEXT,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_by BIGINT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  deactivated_by BIGINT,
  deactivated_at TIMESTAMPTZ,
  last_used_at TIMESTAMPTZ,
  use_count BIGINT NOT NULL DEFAULT 0
);

ALTER TABLE bot_user_passwords
  ADD COLUMN IF NOT EXISTS password_preview TEXT;

ALTER TABLE bot_user_passwords
  ADD COLUMN IF NOT EXISTS deactivated_by BIGINT;

ALTER TABLE bot_user_passwords
  ADD COLUMN IF NOT EXISTS deactivated_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS bot_user_passwords_active_idx
  ON bot_user_passwords (is_active, created_at DESC);

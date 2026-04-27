CREATE TABLE IF NOT EXISTS bot_sections (
  id BIGSERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  sort_order INTEGER NOT NULL DEFAULT 1,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_by BIGINT,
  updated_by BIGINT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS bot_sections_active_order_idx
  ON bot_sections (is_active, sort_order, id);

CREATE INDEX IF NOT EXISTS bot_sections_name_idx
  ON bot_sections ((lower(name)));

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
  section_no INTEGER NOT NULL DEFAULT 1,
  section_id BIGINT,
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

ALTER TABLE bot_files
  ADD COLUMN IF NOT EXISTS section_no INTEGER NOT NULL DEFAULT 1;

ALTER TABLE bot_files
  ADD COLUMN IF NOT EXISTS section_id BIGINT;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'bot_files_section_id_fkey'
  ) THEN
    ALTER TABLE bot_files
      ADD CONSTRAINT bot_files_section_id_fkey
      FOREIGN KEY (section_id) REFERENCES bot_sections(id);
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS bot_files_active_created_idx
  ON bot_files (is_active, created_at DESC);

CREATE INDEX IF NOT EXISTS bot_files_search_idx
  ON bot_files USING GIN (
    to_tsvector('simple', coalesce(title, '') || ' ' || coalesce(description, '') || ' ' || coalesce(file_name, '') || ' ' || coalesce(mime_type, ''))
  );

INSERT INTO bot_sections (name, sort_order, created_by, updated_by)
SELECT 'General', 1, 0, 0
WHERE NOT EXISTS (
  SELECT 1 FROM bot_sections WHERE is_active = TRUE
);

UPDATE bot_files AS f
SET section_id = s.id
FROM bot_sections AS s
WHERE f.section_id IS NULL
  AND s.is_active = TRUE
  AND s.sort_order = GREATEST(1, COALESCE(f.section_no, 1));

UPDATE bot_files AS f
SET section_id = (
  SELECT id
  FROM bot_sections
  WHERE is_active = TRUE
  ORDER BY sort_order ASC, id ASC
  LIMIT 1
)
WHERE f.section_id IS NULL;

UPDATE bot_files AS f
SET section_no = s.sort_order
FROM bot_sections AS s
WHERE f.section_id = s.id;

CREATE TABLE IF NOT EXISTS bot_links (
  id BIGSERIAL PRIMARY KEY,
  title TEXT NOT NULL,
  url TEXT NOT NULL,
  description TEXT,
  uploader_id BIGINT NOT NULL,
  uploader_name TEXT,
  download_count BIGINT NOT NULL DEFAULT 0,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE bot_links
  ADD COLUMN IF NOT EXISTS description TEXT;

ALTER TABLE bot_links
  ADD COLUMN IF NOT EXISTS download_count BIGINT NOT NULL DEFAULT 0;

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

CREATE TABLE IF NOT EXISTS bot_user_file_downloads (
  telegram_id BIGINT NOT NULL,
  file_id BIGINT NOT NULL,
  download_count BIGINT NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_download_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (telegram_id, file_id),
  FOREIGN KEY (telegram_id) REFERENCES bot_users(telegram_id) ON DELETE CASCADE,
  FOREIGN KEY (file_id) REFERENCES bot_files(id) ON DELETE CASCADE
);

ALTER TABLE bot_user_file_downloads
  ADD COLUMN IF NOT EXISTS download_count BIGINT NOT NULL DEFAULT 0;

ALTER TABLE bot_user_file_downloads
  ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

ALTER TABLE bot_user_file_downloads
  ADD COLUMN IF NOT EXISTS last_download_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

CREATE INDEX IF NOT EXISTS bot_user_file_downloads_telegram_idx
  ON bot_user_file_downloads (telegram_id, last_download_at DESC);

CREATE INDEX IF NOT EXISTS bot_user_file_downloads_file_idx
  ON bot_user_file_downloads (file_id);

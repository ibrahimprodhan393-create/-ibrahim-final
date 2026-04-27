# Telegram Neon File Bot

Python/FastAPI Telegram bot for admin-only file uploads and user downloads. The bot stores only Telegram `file_id` metadata in Neon Postgres. Files are not downloaded to Render.

## Tech Stack

- Python 3.12
- FastAPI
- Uvicorn
- Neon PostgreSQL
- Telegram Bot API
- Render Web Service

## Important File Size Note

This bot is designed for large files by reusing Telegram `file_id`.

Admin sends a file to the bot. The bot saves the file metadata and `file_id` in Neon. Users press the download button, and the bot sends the same Telegram file again.

On Render, do not store uploaded files on disk. Render Free has an ephemeral filesystem, and Telegram Bot API also has direct upload/download limits. This project avoids those issues by storing metadata only.

Official Telegram Bot API docs: https://core.telegram.org/bots/api

## Features

- Admin-only direct Telegram file upload
- Admin-only browser download link add/remove
- File and link description support during upload/add
- Admin can edit existing direct-file description later
- User direct Telegram file download
- User browser download link buttons
- Separate Direct Download and Browser Download sections
- English inline button UI with matching emojis
- English bot messages
- File/link list, search, file details, download count for direct files
- Support button with admin-managed Telegram contact
- User login with admin-created passwords
- Passwords are stored as salted hashes, not plaintext
- Admin password preview list (masked) inside Admin Panel
- Admin bot user list with Telegram ID and last seen
- Admin can remove/disable a user password later
- Neon Postgres metadata storage
- Render Free deploy support
- `/id` command to find Telegram user ID
- `/healthz` endpoint for uptime monitor
- `/monitor/{MONITOR_SECRET}` runtime monitor endpoint

## Project Files

```text
app/
  __init__.py
  main.py

db/
  schema.sql

main.py
requirements.txt
runtime.txt
.python-version
render.yaml
.env.example
.gitignore
GITHUB_UPLOAD_FILES.md
DEPLOY_TROUBLESHOOTING.md
README.md
```

## Render Settings

Deploy as a Render Web Service, not a Worker.

```text
Runtime: Python
Build Command: pip install -r requirements.txt
Start Command: uvicorn main:app --host 0.0.0.0 --port $PORT
Plan: Free
Health Check Path: /healthz
```

Telegram webhooks need a public HTTPS URL, so Render Background Worker is not suitable for this bot.

The root `main.py` is the main app file. If your GitHub upload does not include `app/main.py`, the bot will still run from `main.py`.

## Environment Variables

Add these in Render:

```text
BOT_TOKEN=your_botfather_token
DATABASE_URL=your_neon_connection_string
ADMIN_IDS=your_telegram_user_id
WEBHOOK_SECRET=your_random_secret
WEBHOOK_BASE_URL=https://your-render-service.onrender.com
MONITOR_SECRET=your_monitor_secret
PYTHON_VERSION=3.12.8
DB_POOL_SIZE=2
PAGE_SIZE=5
USER_PASSWORD_MIN_LENGTH=6
PROTECT_CONTENT=false
DROP_PENDING_UPDATES=false
```

Optional:

```text
TELEGRAM_API_ROOT=https://api.telegram.org
SKIP_WEBHOOK_SETUP=false
```

`WEBHOOK_SECRET` and `MONITOR_SECRET` are made by you. Use letters, numbers, underscore, or dash. Do not use your bot token as these secrets.

## Neon Database Setup

You do not upload bot code to Neon. Neon only stores database tables.

The bot creates tables automatically when it starts. If you want to create tables manually:

1. Open Neon dashboard.
2. Go to SQL Editor.
3. Open `db/schema.sql`.
4. Paste the SQL and click Run.
5. Copy the Neon connection string to Render as `DATABASE_URL`.

Use the pooled connection string if Neon shows one. It usually contains `-pooler` in the host name.

## Free Neon + Free Render Notes

- `render.yaml` uses `plan: free`.
- `DB_POOL_SIZE=2` keeps Neon connections low.
- Neon Free is enough because only metadata is stored.
- Render Free can sleep after idle time, so the first request after sleep may be delayed.

For better free uptime, create a monitor on UptimeRobot or cron-job.org:

```text
https://your-service.onrender.com/healthz
```

Set the interval to 5 or 10 minutes. This helps keep the service awake, but it is not a guaranteed 24/7 SLA. For guaranteed always-on, use a paid Render instance.

Detailed monitor endpoint:

```text
https://your-service.onrender.com/monitor/your_monitor_secret
```

It shows uptime seconds, update counters, and last error info.

## Local Run

```bash
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 3000
```

For local development without setting Telegram webhook:

```bash
SKIP_WEBHOOK_SETUP=true uvicorn main:app --host 0.0.0.0 --port 3000
```

## Admin Flow

1. Open the bot.
2. Press `🛠 Admin Panel`.
3. Press `📤 Upload Direct File`.
4. Send a document, video, audio, or photo with optional caption:

```text
Title
Title | Description
```

5. The bot saves the metadata in Neon.

To add a browser download link:

1. Press `🛠 Admin Panel`.
2. Press `🌐 Add Browser Link`.
3. Send the link in one of these formats:

```text
Title | https://example.com/file.zip
Title | https://example.com/file.zip | Description
https://example.com/file.zip
```

The link will appear under `🌐 Browser Download`, and users can open it with a browser download button.

To edit description of an existing uploaded direct file:

1. Press `📥 Direct Files`.
2. Open a file.
3. Press `✏️ Edit Details`.
4. Send one of these:

```text
Title | Description
| Description only
Description only
clear
```

To set the support contact:

1. Press `🛠 Admin Panel`.
2. Press `🛠 Set Support ID`.
3. Send the support Telegram ID, username, or t.me link.

Examples:

```text
@yourusername
123456789
https://t.me/yourusername
```

To create a user login password:

1. Press `🛠 Admin Panel`.
2. Press `🔑 Create User Password`.
3. Send the password users should login with.

The bot stores only a secure hash in Neon. It does not store the plain password.

To view created password previews:

1. Press `🛠 Admin Panel`.
2. Press `🔍 Password List`.

This list shows masked previews only (for security), status, and usage count.

To remove a user login password:

1. Press `🛠 Admin Panel`.
2. Press `🗑 Remove User Password`.
3. Send the password you want to remove.

The password will be disabled, and users logged in with that password will be logged out.

To see all users who used the bot:

1. Press `🛠 Admin Panel`.
2. Press `👥 Bot Users`.

The list shows user name/username, Telegram ID, access status, and last seen time.

## User Flow

1. Press `🔐 Login`.
2. Send the user password.
3. Press `📥 Direct Download` to get Telegram files, or `🌐 Browser Download` to open saved links.
4. Pick a direct file and press `📥 Direct Download`, or pick a browser link and press `🌐 Browser Download`.

Users cannot upload files.

## UI Preview

User main menu:

```text
Welcome.

Please login with your user password to access downloads.

[ 🔐 Login ]
[ 💬 Support ]
```

Logged-in user menu:

```text
Welcome.

Choose Direct Download for Telegram files or Browser Download for external links.

[ 📥 Direct Download ]
[ 🌐 Browser Download ]
[ 🔎 Search ]
[ 🚪 Logout ]
[ 💬 Support ]
```

Admin main menu:

```text
Welcome.

Choose Direct Download for Telegram files or Browser Download for external links.

[ 📥 Direct Download ]
[ 🌐 Browser Download ]
[ 🔎 Search ]
[ 🛠 Admin Panel ]
[ 💬 Support ]
```

Admin panel:

```text
🛠 Admin Panel

📤 Upload Direct File adds Telegram files.
🌐 Add Browser Link adds external download links.
✏️ Open any file and press Edit Details to update description later.
🔑 Create User Password adds a login password.
🔍 Password List shows created password previews.
🗑 Remove User Password disables a login password.
👥 Bot Users shows everyone who used the bot.
📥 Direct Files shows Telegram files.
🌐 Browser Links shows external links.
🛠 Set Support ID updates the support contact.

[ 📤 Upload Direct File ] [ 🌐 Add Browser Link ]
[ 📥 Direct Files ] [ 🌐 Browser Links ]
[ 🔑 Create User Password ] [ 🔍 Password List ]
[ 🗑 Remove User Password ] [ 👥 Bot Users ]
[ 🛠 Set Support ID ]
[ 🏠 Main Menu ]
```

Support:

```text
Support

For help, contact the admin:
@yourusername

[ 💬 Contact Admin ]
[ 🏠 Main Menu ]
```

Direct file details:

```text
📥 Movie.zip

File name: Movie.zip
Size: 2.1 GB
Type: document
Downloads: 12
Uploaded: 2026-04-27

[ 📥 Direct Download ]
[ ✏️ Edit Details ]
[ 🗑 Remove Direct File ]
[ 📥 Direct Files ] [ 🏠 Main Menu ]
```

Browser link details:

```text
🌐 Movie Download Link

Link: https://example.com/movie.zip
Added: 2026-04-27

[ 🌐 Browser Download ]
[ 🌐 Browser Links ] [ 🏠 Main Menu ]
```

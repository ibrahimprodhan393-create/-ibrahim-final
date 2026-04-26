# Deploy Troubleshooting

If Render shows `Failed`, open your Render service, go to `Logs`, and check the first red error.

Most common fixes:

## 1. Wrong Service Type

Use:

```text
New > Web Service
Runtime: Python
```

Do not use Worker. Telegram webhook needs a public HTTPS URL.

## 2. Wrong Commands

Use:

```text
Build Command: pip install -r requirements.txt
Start Command: uvicorn main:app --host 0.0.0.0 --port $PORT
```

## 3. Missing Environment Variables

Required:

```text
BOT_TOKEN
DATABASE_URL
ADMIN_IDS
WEBHOOK_SECRET
WEBHOOK_BASE_URL
```

Also add:

```text
PYTHON_VERSION=3.12.8
DB_POOL_SIZE=2
PAGE_SIZE=5
USER_PASSWORD_MIN_LENGTH=6
PROTECT_CONTENT=false
DROP_PENDING_UPDATES=false
```

## 4. Bad WEBHOOK_SECRET

Use only letters, numbers, underscore, or dash. No spaces.

Good:

```text
my_bot_secret_12345
```

Bad:

```text
my bot secret
abc/123
```

## 5. DATABASE_URL Issue

Use the Neon connection string. Pooled URL is recommended.

Make sure the URL starts with:

```text
postgresql://
```

If Neon adds `channel_binding=require`, this project removes it before connecting with `asyncpg` and keeps `sslmode=require`.

## 6. WEBHOOK_BASE_URL Issue

Use your Render service URL only:

```text
https://your-service.onrender.com
```

Do not add `/webhook/...` manually.

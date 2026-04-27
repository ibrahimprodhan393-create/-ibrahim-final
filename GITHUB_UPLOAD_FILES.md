# GitHub Upload Checklist

Upload these files and folders to GitHub for the final Python version:

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
README.md
DEPLOY_TROUBLESHOOTING.md
.env.example
.gitignore
GITHUB_UPLOAD_FILES.md
```

Optional backup folders/files:

```text
src/
  server.js

package.json
```

Do not upload these:

```text
.env
node_modules/
__pycache__/
.venv/
venv/
*.zip
npm-debug.log*
yarn-debug.log*
yarn-error.log*
```

After uploading to GitHub, deploy the repository on Render as a Python web service.

Render settings:

```text
Runtime: Python
Build Command: pip install -r requirements.txt
Start Command: uvicorn main:app --host 0.0.0.0 --port $PORT
Plan: Free
```

Render environment variables:

```text
BOT_TOKEN=your_botfather_token
DATABASE_URL=your_neon_connection_string
ADMIN_IDS=your_telegram_user_id
WEBHOOK_SECRET=your_random_secret
WEBHOOK_BASE_URL=https://your-service.onrender.com
MONITOR_SECRET=your_monitor_secret
PYTHON_VERSION=3.12.8
DB_POOL_SIZE=2
PAGE_SIZE=5
PROTECT_CONTENT=false
DROP_PENDING_UPDATES=false
```

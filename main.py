import asyncio
import hashlib
import html
import hmac
import os
import re
import secrets
from datetime import datetime
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import asyncpg
import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, Header, HTTPException, Request

load_dotenv()


def parse_admin_ids(value: str | None) -> set[str]:
    return {item.strip() for item in (value or "").split(",") if item.strip()}


def normalize_database_url(value: str) -> str:
    if not value:
        return value

    parsed = urlsplit(value)
    params = [(key, val) for key, val in parse_qsl(parsed.query, keep_blank_values=True) if key != "channel_binding"]

    if parsed.hostname and parsed.hostname.endswith(".neon.tech") and not any(key == "sslmode" for key, _ in params):
        params.append(("sslmode", "require"))

    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(params), parsed.fragment))


def positive_int(value: str | None, fallback: int) -> int:
    try:
        parsed = int(value or "")
    except ValueError:
        return fallback
    return parsed if parsed > 0 else fallback


BOT_TOKEN = os.getenv("BOT_TOKEN", "")
DATABASE_URL = os.getenv("DATABASE_URL", "")
DATABASE_DSN = normalize_database_url(DATABASE_URL)
ADMIN_IDS = parse_admin_ids(os.getenv("ADMIN_IDS"))
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "")
WEBHOOK_BASE_URL = os.getenv("WEBHOOK_BASE_URL") or (
    f"https://{os.getenv('RENDER_EXTERNAL_HOSTNAME')}" if os.getenv("RENDER_EXTERNAL_HOSTNAME") else ""
)
TELEGRAM_API_ROOT = os.getenv("TELEGRAM_API_ROOT", "https://api.telegram.org").rstrip("/")
PAGE_SIZE = positive_int(os.getenv("PAGE_SIZE"), 5)
DB_POOL_SIZE = positive_int(os.getenv("DB_POOL_SIZE"), 2)
PROTECT_CONTENT = os.getenv("PROTECT_CONTENT") == "true"
DROP_PENDING_UPDATES = os.getenv("DROP_PENDING_UPDATES") == "true"
SKIP_WEBHOOK_SETUP = os.getenv("SKIP_WEBHOOK_SETUP") == "true"
USER_PASSWORD_MIN_LENGTH = positive_int(os.getenv("USER_PASSWORD_MIN_LENGTH"), 6)

if not BOT_TOKEN:
    raise RuntimeError("BOT_TOKEN is required")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is required")
if not WEBHOOK_SECRET:
    raise RuntimeError("WEBHOOK_SECRET is required")
if not re.fullmatch(r"[A-Za-z0-9_-]{8,256}", WEBHOOK_SECRET):
    raise RuntimeError("WEBHOOK_SECRET must be 8-256 chars and use only letters, numbers, underscore, or dash")
if not SKIP_WEBHOOK_SETUP and not WEBHOOK_BASE_URL:
    raise RuntimeError("WEBHOOK_BASE_URL is required unless SKIP_WEBHOOK_SETUP=true")
if not ADMIN_IDS:
    print("Warning: ADMIN_IDS is empty. Nobody can upload files.")

app = FastAPI()
db_pool: asyncpg.Pool | None = None
http_client: httpx.AsyncClient | None = None
user_states: dict[int, str] = {}


@app.on_event("startup")
async def startup() -> None:
    global db_pool, http_client
    db_pool = await asyncpg.create_pool(
        DATABASE_DSN,
        min_size=0,
        max_size=DB_POOL_SIZE,
        command_timeout=30,
    )
    http_client = httpx.AsyncClient(timeout=30)
    await migrate()
    if not SKIP_WEBHOOK_SETUP:
        await set_webhook()


@app.on_event("shutdown")
async def shutdown() -> None:
    if http_client:
        await http_client.aclose()
    if db_pool:
        await db_pool.close()


@app.get("/healthz")
async def healthz() -> dict[str, bool]:
    return {"ok": True}


@app.post("/webhook/{secret}")
async def webhook(
    secret: str,
    request: Request,
    x_telegram_bot_api_secret_token: str | None = Header(default=None),
) -> dict[str, bool]:
    if secret != WEBHOOK_SECRET or x_telegram_bot_api_secret_token != WEBHOOK_SECRET:
        raise HTTPException(status_code=403, detail="invalid webhook secret")

    update = await request.json()
    asyncio.create_task(process_update(update))
    return {"ok": True}


async def process_update(update: dict[str, Any]) -> None:
    try:
        if "message" in update:
            await handle_message(update["message"])
        if "callback_query" in update:
            await handle_callback(update["callback_query"])
    except Exception as exc:
        print(f"Failed to process update: {exc}")


async def handle_message(message: dict[str, Any]) -> None:
    chat_id = message["chat"]["id"]
    user = message.get("from", {})
    text = (message.get("text") or "").strip()

    if text.startswith("/"):
        await handle_command(message, text)
        return

    state = user_states.get(user.get("id"))
    if state == "support_contact":
        await handle_support_contact_update(chat_id, user, text)
        return

    if state == "new_user_password":
        await handle_new_user_password(chat_id, user, text)
        return

    if state == "login_password":
        await handle_login_attempt(chat_id, user, text)
        return

    media = media_from_message(message)
    if media:
        await handle_media_upload(message, media)
        return

    if state == "search":
        user_states.pop(user.get("id"), None)
        await send_search_results(chat_id, text)
        return

    await send_main_menu(chat_id, user)


async def handle_command(message: dict[str, Any], text: str) -> None:
    chat_id = message["chat"]["id"]
    user = message.get("from", {})
    command = text.split()[0].split("@")[0].lower()

    if command == "/start":
        await upsert_user(user)
        await send_main_menu(chat_id, user)
        return

    if command in {"/help", "/support"}:
        await send_support(chat_id, is_admin(user.get("id")))
        return

    if command == "/login":
        if is_admin(user.get("id")):
            await send_message(chat_id, "Admins do not need to login.", reply_markup=admin_panel_keyboard())
            return
        user_states[user["id"]] = "login_password"
        await send_message(chat_id, login_prompt_text(), reply_markup=cancel_keyboard())
        return

    if command == "/logout":
        await set_user_authorized(user.get("id"), False)
        user_states.pop(user.get("id"), None)
        await send_message(chat_id, "You have been logged out.", reply_markup=main_menu_keyboard(False, False))
        return

    if command == "/id":
        await send_message(chat_id, f"Your Telegram user ID:\n<code>{e(user.get('id'))}</code>")
        return

    if command == "/admin":
        if not is_admin(user.get("id")):
            await send_message(chat_id, "This section is only for admins.")
            return
        await send_message(chat_id, admin_panel_text(), reply_markup=admin_panel_keyboard())
        return

    await send_main_menu(chat_id, user)


async def handle_media_upload(message: dict[str, Any], media: dict[str, Any]) -> None:
    chat_id = message["chat"]["id"]
    user = message.get("from", {})
    user_states.pop(user.get("id"), None)

    if not is_admin(user.get("id")):
        await send_message(
            chat_id,
            "Only admins can upload files. You can download files from the buttons.",
            reply_markup=main_menu_keyboard(False, False),
        )
        return

    saved = await save_file(
        {
            "file_unique_id": media["file_unique_id"],
            "file_id": media["file_id"],
            "kind": media["kind"],
            "file_name": media["file_name"],
            "mime_type": media.get("mime_type"),
            "file_size": media.get("file_size"),
            "title": clean_title(message.get("caption") or media["file_name"]),
            "uploader_id": user["id"],
            "uploader_name": display_name(user),
        }
    )

    await send_message(
        chat_id,
        "\n".join(
            [
                "File saved successfully.",
                "",
                f"<b>{e(saved['title'] or saved['file_name'])}</b>",
                f"Size: {e(format_bytes(saved['file_size']))}",
                f"Type: {e(saved['kind'])}",
            ]
        ),
        reply_markup=file_saved_keyboard(saved["id"]),
    )


async def handle_callback(query: dict[str, Any]) -> None:
    user = query.get("from", {})
    message = query.get("message") or {}
    chat_id = (message.get("chat") or {}).get("id")
    message_id = message.get("message_id")
    data = query.get("data") or ""
    action, _, raw_value = data.partition(":")

    if not chat_id or not message_id:
        await answer_callback(query["id"])
        return

    if action not in {"search", "upload", "setsupport", "createpass", "login"}:
        user_states.pop(user.get("id"), None)

    if action == "menu":
        await answer_callback(query["id"])
        await show_main_menu(chat_id, message_id, user)
    elif action == "support":
        await answer_callback(query["id"])
        await show_support(chat_id, message_id, is_admin(user.get("id")))
    elif action == "list":
        if not await user_has_access(user.get("id")):
            await deny_locked_callback(query["id"], chat_id, message_id)
            return
        await answer_callback(query["id"])
        await show_file_list(chat_id, message_id, safe_int(raw_value), user)
    elif action == "file":
        if not await user_has_access(user.get("id")):
            await deny_locked_callback(query["id"], chat_id, message_id)
            return
        await answer_callback(query["id"])
        await show_file_detail(chat_id, message_id, safe_int(raw_value), user)
    elif action == "get":
        if not await user_has_access(user.get("id")):
            await deny_locked_callback(query["id"], chat_id, message_id)
            return
        await answer_callback(query["id"], "Sending file...")
        await send_stored_file(chat_id, safe_int(raw_value))
    elif action == "search":
        if not await user_has_access(user.get("id")):
            await deny_locked_callback(query["id"], chat_id, message_id)
            return
        user_states[user["id"]] = "search"
        await answer_callback(query["id"])
        await edit_message(chat_id, message_id, "Send the file name or keyword you want to search for.", cancel_keyboard())
    elif action == "login":
        if is_admin(user.get("id")):
            await answer_callback(query["id"], "Admins do not need to login.")
            await edit_message(chat_id, message_id, admin_panel_text(), admin_panel_keyboard())
            return
        user_states[user["id"]] = "login_password"
        await answer_callback(query["id"])
        await edit_message(chat_id, message_id, login_prompt_text(), cancel_keyboard())
    elif action == "logout":
        await set_user_authorized(user.get("id"), False)
        await answer_callback(query["id"], "Logged out.")
        await edit_message(chat_id, message_id, main_menu_text(user, False), main_menu_keyboard(False, False))
    elif action == "admin":
        if not is_admin(user.get("id")):
            await answer_callback(query["id"], "Admins only.", True)
            return
        await answer_callback(query["id"])
        await edit_message(chat_id, message_id, admin_panel_text(), admin_panel_keyboard())
    elif action == "upload":
        if not is_admin(user.get("id")):
            await answer_callback(query["id"], "Admins only.", True)
            return
        user_states[user["id"]] = "upload"
        await answer_callback(query["id"])
        await edit_message(chat_id, message_id, upload_instructions(), back_keyboard("admin"))
    elif action == "setsupport":
        if not is_admin(user.get("id")):
            await answer_callback(query["id"], "Admins only.", True)
            return
        user_states[user["id"]] = "support_contact"
        await answer_callback(query["id"])
        await edit_message(
            chat_id,
            message_id,
            "Send the support Telegram ID or username.\n\nExamples:\n@yourusername\n123456789\nhttps://t.me/yourusername",
            back_keyboard("admin"),
        )
    elif action == "createpass":
        if not is_admin(user.get("id")):
            await answer_callback(query["id"], "Admins only.", True)
            return
        user_states[user["id"]] = "new_user_password"
        await answer_callback(query["id"])
        await edit_message(
            chat_id,
            message_id,
            f"Send the new user login password.\n\nMinimum length: {USER_PASSWORD_MIN_LENGTH} characters.\nThe bot stores only a secure hash, not the plain password.",
            back_keyboard("admin"),
        )
    elif action == "del":
        if not is_admin(user.get("id")):
            await answer_callback(query["id"], "Admins only.", True)
            return
        await answer_callback(query["id"])
        await edit_message(chat_id, message_id, "Do you want to remove this file from the list?", delete_confirm_keyboard(safe_int(raw_value)))
    elif action == "delok":
        if not is_admin(user.get("id")):
            await answer_callback(query["id"], "Admins only.", True)
            return
        await mark_file_inactive(safe_int(raw_value))
        await answer_callback(query["id"], "File removed.")
        await show_file_list(chat_id, message_id, 0, user)
    else:
        await answer_callback(query["id"])


async def send_main_menu(chat_id: int, user: dict[str, Any]) -> None:
    admin = is_admin(user.get("id"))
    authorized = admin or await is_user_authorized(user.get("id"))
    await send_message(chat_id, main_menu_text(user, authorized), reply_markup=main_menu_keyboard(admin, authorized))


async def show_main_menu(chat_id: int, message_id: int, user: dict[str, Any]) -> None:
    admin = is_admin(user.get("id"))
    authorized = admin or await is_user_authorized(user.get("id"))
    await edit_message(chat_id, message_id, main_menu_text(user, authorized), main_menu_keyboard(admin, authorized))


def main_menu_text(user: dict[str, Any], authorized: bool = True) -> str:
    name = f", {e(user.get('first_name'))}" if user.get("first_name") else ""
    if not authorized:
        return f"Welcome{name}.\n\nPlease login with your user password to access files."
    return f"Welcome{name}.\n\nBrowse files, search by keyword, then press Download."


def login_prompt_text() -> str:
    return "Please send your user password to login."


async def deny_locked_callback(callback_query_id: str, chat_id: int, message_id: int) -> None:
    await answer_callback(callback_query_id, "Please login first.", True)
    await edit_message(chat_id, message_id, login_prompt_text(), login_keyboard())


async def handle_login_attempt(chat_id: int, user: dict[str, Any], password: str) -> None:
    if is_admin(user.get("id")):
        user_states.pop(user.get("id"), None)
        await send_message(chat_id, "Admins do not need to login.", reply_markup=admin_panel_keyboard())
        return

    password = password.strip()
    if not password:
        await send_message(chat_id, login_prompt_text(), reply_markup=login_keyboard())
        return

    password_id = await verify_user_password(password)
    if not password_id:
        await send_message(chat_id, "Invalid password. Please try again.", reply_markup=login_keyboard())
        return

    user_states.pop(user.get("id"), None)
    await upsert_user(user)
    await set_user_authorized(user.get("id"), True, password_id)
    await mark_password_used(password_id)
    await send_message(chat_id, "Login successful. You can now access files.", reply_markup=main_menu_keyboard(False, True))


async def handle_new_user_password(chat_id: int, user: dict[str, Any], password: str) -> None:
    if not is_admin(user.get("id")):
        user_states.pop(user.get("id"), None)
        await send_message(chat_id, "Admins only.", reply_markup=main_menu_keyboard(False, False))
        return

    password = password.strip()
    if len(password) < USER_PASSWORD_MIN_LENGTH:
        await send_message(
            chat_id,
            f"Password is too short. Send at least {USER_PASSWORD_MIN_LENGTH} characters.",
            reply_markup=back_keyboard("admin"),
        )
        return

    user_states.pop(user.get("id"), None)
    await create_user_password(password, user.get("id"))
    await send_message(
        chat_id,
        "User password created successfully.\n\nShare this password with users privately. The plain password is not stored in Neon.",
        reply_markup=admin_panel_keyboard(),
    )


async def send_support(chat_id: int, admin: bool) -> None:
    contact = await get_support_contact()
    await send_message(chat_id, support_text(contact, admin), reply_markup=support_keyboard(contact))


async def show_support(chat_id: int, message_id: int, admin: bool) -> None:
    contact = await get_support_contact()
    await edit_message(chat_id, message_id, support_text(contact, admin), support_keyboard(contact))


async def handle_support_contact_update(chat_id: int, user: dict[str, Any], text: str) -> None:
    if not is_admin(user.get("id")):
        user_states.pop(user.get("id"), None)
        await send_message(chat_id, "Admins only.", reply_markup=main_menu_keyboard(False, False))
        return

    contact = clean_support_contact(text)
    if not contact:
        await send_message(
            chat_id,
            "Please send a valid Telegram ID, username, or t.me link.\n\nExamples:\n@yourusername\n123456789\nhttps://t.me/yourusername",
            reply_markup=back_keyboard("admin"),
        )
        return

    user_states.pop(user.get("id"), None)
    await set_support_contact(contact, user.get("id"))
    await send_message(
        chat_id,
        f"Support contact updated:\n<code>{e(contact)}</code>",
        reply_markup=admin_panel_keyboard(),
    )


def support_text(contact: str | None, admin: bool) -> str:
    if contact:
        lines = [
            "<b>Support</b>",
            "",
            "For help, contact the admin:",
            f"<code>{e(contact)}</code>",
        ]
    else:
        lines = [
            "<b>Support</b>",
            "",
            "Support contact has not been set yet.",
        ]

    if admin:
        lines += ["", "Admin can update this from Admin Panel > Set Support ID."]

    return "\n".join(lines)


def admin_panel_text() -> str:
    return "Admin Panel\n\nPress Upload File to add a new file.\nPress Create User Password to add a login password.\nPress File List to view saved files.\nPress Set Support ID to update the support contact."


def upload_instructions() -> str:
    return (
        "<b>Upload File</b>\n\n"
        "Send a document, video, audio, or photo in this chat.\n"
        "If you add a caption, it will be saved as the file title.\n\n"
        "The bot will not download the file to Render. It only stores the Telegram file_id in Neon."
    )


async def show_file_list(chat_id: int, message_id: int, page: int, user: dict[str, Any]) -> None:
    page = max(0, page)
    files, total = await list_files(page, PAGE_SIZE)
    total_pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)

    if page >= total_pages:
        await show_file_list(chat_id, message_id, total_pages - 1, user)
        return

    if not files:
        await edit_message(chat_id, message_id, "No files have been uploaded yet.", back_keyboard())
        return

    lines = [f"<b>File List</b>", f"Page {page + 1}/{total_pages}", ""]
    for index, file in enumerate(files, start=page * PAGE_SIZE + 1):
        lines.append(f"{index}. {e(file['title'] or file['file_name'])} ({e(format_bytes(file['file_size']))})")
    await edit_message(chat_id, message_id, "\n".join(lines), file_list_keyboard(files, page, total_pages))


async def show_file_detail(chat_id: int, message_id: int, file_id: int, user: dict[str, Any]) -> None:
    file = await get_file(file_id)
    if not file:
        await edit_message(chat_id, message_id, "File not found.", back_keyboard())
        return

    lines = [
        f"<b>{e(file['title'] or file['file_name'])}</b>",
        "",
        f"File name: {e(file['file_name'])}",
        f"Size: {e(format_bytes(file['file_size']))}",
        f"Type: {e(file['kind'])}",
        f"Downloads: {e(file['download_count'])}",
        f"Uploaded: {e(format_date(file['created_at']))}",
    ]
    await edit_message(chat_id, message_id, "\n".join(lines), file_detail_keyboard(file["id"], is_admin(user.get("id"))))


async def send_search_results(chat_id: int, keyword: str) -> None:
    keyword = keyword.strip()
    if not keyword:
        await send_message(chat_id, "Send a keyword to search.", reply_markup=main_menu_keyboard(False, True))
        return

    files = await search_files(keyword, 8)
    if not files:
        await send_message(chat_id, f"No files found for \"{e(keyword)}\".", reply_markup=main_menu_keyboard(False, True))
        return

    await send_message(chat_id, f"<b>Search Results</b>\n{e(keyword)}", reply_markup=search_results_keyboard(files))


async def send_stored_file(chat_id: int, file_id: int) -> None:
    file = await get_file(file_id)
    if not file:
        await send_message(chat_id, "File not found.", reply_markup=main_menu_keyboard(False, True))
        return

    common = {
        "chat_id": chat_id,
        "caption": f"{file['title'] or file['file_name']}\nSize: {format_bytes(file['file_size'])}",
        "protect_content": PROTECT_CONTENT,
        "reply_markup": {"inline_keyboard": [[{"text": "Main Menu", "callback_data": "menu"}]]},
    }
    method, field = {
        "video": ("sendVideo", "video"),
        "audio": ("sendAudio", "audio"),
        "photo": ("sendPhoto", "photo"),
    }.get(file["kind"], ("sendDocument", "document"))
    await telegram(method, {**common, field: file["file_id"]})
    await increment_download_count(file_id)


def main_menu_keyboard(admin: bool, authorized: bool) -> dict[str, Any]:
    if admin or authorized:
        keyboard = [
            [{"text": "Browse Files", "callback_data": "list:0"}, {"text": "Search", "callback_data": "search"}],
        ]
    else:
        keyboard = [[{"text": "Login", "callback_data": "login"}]]

    if admin:
        keyboard.append([{"text": "Admin Panel", "callback_data": "admin"}])
    elif authorized:
        keyboard.append([{"text": "Logout", "callback_data": "logout"}])

    keyboard.append([{"text": "Support", "callback_data": "support"}])
    return {"inline_keyboard": keyboard}


def admin_panel_keyboard() -> dict[str, Any]:
    return {
        "inline_keyboard": [
            [{"text": "Upload File", "callback_data": "upload"}],
            [{"text": "Create User Password", "callback_data": "createpass"}],
            [{"text": "Set Support ID", "callback_data": "setsupport"}],
            [{"text": "File List", "callback_data": "list:0"}],
            [{"text": "Main Menu", "callback_data": "menu"}],
        ]
    }


def file_saved_keyboard(file_id: int) -> dict[str, Any]:
    return {"inline_keyboard": [[{"text": "View File", "callback_data": f"file:{file_id}"}], [{"text": "Admin Panel", "callback_data": "admin"}]]}


def file_list_keyboard(files: list[asyncpg.Record], page: int, total_pages: int) -> dict[str, Any]:
    rows = [[{"text": trim_button(file["title"] or file["file_name"]), "callback_data": f"file:{file['id']}"}] for file in files]
    nav = []
    if page > 0:
        nav.append({"text": "Previous", "callback_data": f"list:{page - 1}"})
    if page + 1 < total_pages:
        nav.append({"text": "Next", "callback_data": f"list:{page + 1}"})
    if nav:
        rows.append(nav)
    rows.append([{"text": "Search", "callback_data": "search"}, {"text": "Main Menu", "callback_data": "menu"}])
    return {"inline_keyboard": rows}


def file_detail_keyboard(file_id: int, admin: bool) -> dict[str, Any]:
    rows = [
        [{"text": "Download", "callback_data": f"get:{file_id}"}],
        [{"text": "File List", "callback_data": "list:0"}, {"text": "Main Menu", "callback_data": "menu"}],
    ]
    if admin:
        rows.insert(1, [{"text": "Remove From List", "callback_data": f"del:{file_id}"}])
    return {"inline_keyboard": rows}


def search_results_keyboard(files: list[asyncpg.Record]) -> dict[str, Any]:
    rows = [[{"text": trim_button(file["title"] or file["file_name"]), "callback_data": f"file:{file['id']}"}] for file in files]
    rows.append([{"text": "Search Again", "callback_data": "search"}, {"text": "Main Menu", "callback_data": "menu"}])
    return {"inline_keyboard": rows}


def support_keyboard(contact: str | None) -> dict[str, Any]:
    rows = []
    url = support_contact_url(contact)
    if url:
        rows.append([{"text": "Contact Admin", "url": url}])
    rows.append([{"text": "Main Menu", "callback_data": "menu"}])
    return {"inline_keyboard": rows}


def login_keyboard() -> dict[str, Any]:
    return {
        "inline_keyboard": [
            [{"text": "Login", "callback_data": "login"}],
            [{"text": "Support", "callback_data": "support"}],
        ]
    }


def delete_confirm_keyboard(file_id: int) -> dict[str, Any]:
    return {"inline_keyboard": [[{"text": "Yes, Delete", "callback_data": f"delok:{file_id}"}], [{"text": "Cancel", "callback_data": f"file:{file_id}"}]]}


def back_keyboard(target: str = "menu") -> dict[str, Any]:
    text = "Admin Panel" if target == "admin" else "Main Menu"
    return {"inline_keyboard": [[{"text": text, "callback_data": target}]]}


def cancel_keyboard() -> dict[str, Any]:
    return {"inline_keyboard": [[{"text": "Cancel", "callback_data": "menu"}]]}


async def migrate() -> None:
    assert db_pool
    async with db_pool.acquire() as conn:
        await conn.execute(
            """
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
              is_active BOOLEAN NOT NULL DEFAULT TRUE,
              created_by BIGINT,
              created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
              last_used_at TIMESTAMPTZ,
              use_count BIGINT NOT NULL DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS bot_user_passwords_active_idx
              ON bot_user_passwords (is_active, created_at DESC);
            """
        )


async def upsert_user(user: dict[str, Any]) -> None:
    if not user.get("id"):
        return
    assert db_pool
    async with db_pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO bot_users (telegram_id, username, first_name, last_name)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (telegram_id)
            DO UPDATE SET
              username = EXCLUDED.username,
              first_name = EXCLUDED.first_name,
              last_name = EXCLUDED.last_name,
              last_seen_at = NOW()
            """,
            user.get("id"),
            user.get("username"),
            user.get("first_name"),
            user.get("last_name"),
        )


async def is_user_authorized(user_id: Any) -> bool:
    if not user_id:
        return False
    assert db_pool
    async with db_pool.acquire() as conn:
        authorized = await conn.fetchval("SELECT is_authorized FROM bot_users WHERE telegram_id = $1", safe_int(user_id))
    return bool(authorized)


async def user_has_access(user_id: Any) -> bool:
    return is_admin(user_id) or await is_user_authorized(user_id)


async def set_user_authorized(user_id: Any, authorized: bool, password_id: int | None = None) -> None:
    if not user_id:
        return
    assert db_pool
    async with db_pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO bot_users (telegram_id, is_authorized, authorized_at, authorized_by_password_id)
            VALUES ($1, $2, CASE WHEN $2 THEN NOW() ELSE NULL END, $3)
            ON CONFLICT (telegram_id)
            DO UPDATE SET
              is_authorized = EXCLUDED.is_authorized,
              authorized_at = EXCLUDED.authorized_at,
              authorized_by_password_id = EXCLUDED.authorized_by_password_id,
              last_seen_at = NOW()
            """,
            safe_int(user_id),
            authorized,
            password_id,
        )


async def create_user_password(password: str, admin_id: Any) -> None:
    salt, password_hash = hash_password(password)
    assert db_pool
    async with db_pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO bot_user_passwords (password_hash, salt, created_by)
            VALUES ($1, $2, $3)
            """,
            password_hash,
            salt,
            safe_int(admin_id),
        )


async def verify_user_password(password: str) -> int | None:
    assert db_pool
    async with db_pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT id, password_hash, salt
            FROM bot_user_passwords
            WHERE is_active = TRUE
            ORDER BY created_at DESC
            """
        )

    for row in rows:
        if verify_password(password, row["salt"], row["password_hash"]):
            return int(row["id"])

    return None


async def mark_password_used(password_id: int) -> None:
    assert db_pool
    async with db_pool.acquire() as conn:
        await conn.execute(
            """
            UPDATE bot_user_passwords
            SET last_used_at = NOW(), use_count = use_count + 1
            WHERE id = $1
            """,
            password_id,
        )


async def save_file(file: dict[str, Any]) -> asyncpg.Record:
    assert db_pool
    async with db_pool.acquire() as conn:
        return await conn.fetchrow(
            """
            INSERT INTO bot_files (
              file_unique_id, file_id, kind, file_name, mime_type, file_size,
              title, uploader_id, uploader_name
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            ON CONFLICT (file_unique_id, kind)
            DO UPDATE SET
              file_id = EXCLUDED.file_id,
              file_name = EXCLUDED.file_name,
              mime_type = EXCLUDED.mime_type,
              file_size = EXCLUDED.file_size,
              title = EXCLUDED.title,
              uploader_id = EXCLUDED.uploader_id,
              uploader_name = EXCLUDED.uploader_name,
              is_active = TRUE,
              updated_at = NOW()
            RETURNING *
            """,
            file["file_unique_id"],
            file["file_id"],
            file["kind"],
            file["file_name"],
            file.get("mime_type"),
            file.get("file_size"),
            file["title"],
            file["uploader_id"],
            file["uploader_name"],
        )


async def list_files(page: int, page_size: int) -> tuple[list[asyncpg.Record], int]:
    assert db_pool
    async with db_pool.acquire() as conn:
        files = await conn.fetch(
            """
            SELECT *
            FROM bot_files
            WHERE is_active = TRUE
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
            """,
            page_size,
            page * page_size,
        )
        total = await conn.fetchval("SELECT COUNT(*) FROM bot_files WHERE is_active = TRUE")
    return list(files), int(total or 0)


async def search_files(keyword: str, limit: int) -> list[asyncpg.Record]:
    assert db_pool
    async with db_pool.acquire() as conn:
        return list(
            await conn.fetch(
                """
                SELECT *
                FROM bot_files
                WHERE is_active = TRUE
                  AND (
                    title ILIKE $1
                    OR file_name ILIKE $1
                    OR mime_type ILIKE $1
                    OR to_tsvector('simple', coalesce(title, '') || ' ' || coalesce(file_name, '') || ' ' || coalesce(mime_type, ''))
                       @@ plainto_tsquery('simple', $2)
                  )
                ORDER BY created_at DESC
                LIMIT $3
                """,
                f"%{keyword}%",
                keyword,
                limit,
            )
        )


async def get_file(file_id: int) -> asyncpg.Record | None:
    if file_id <= 0:
        return None
    assert db_pool
    async with db_pool.acquire() as conn:
        return await conn.fetchrow("SELECT * FROM bot_files WHERE id = $1 AND is_active = TRUE", file_id)


async def increment_download_count(file_id: int) -> None:
    assert db_pool
    async with db_pool.acquire() as conn:
        await conn.execute("UPDATE bot_files SET download_count = download_count + 1 WHERE id = $1", file_id)


async def mark_file_inactive(file_id: int) -> None:
    assert db_pool
    async with db_pool.acquire() as conn:
        await conn.execute("UPDATE bot_files SET is_active = FALSE, updated_at = NOW() WHERE id = $1", file_id)


async def get_support_contact() -> str | None:
    assert db_pool
    async with db_pool.acquire() as conn:
        contact = await conn.fetchval("SELECT value FROM bot_settings WHERE key = 'support_contact'")

    if contact:
        return str(contact)

    return sorted(ADMIN_IDS)[0] if ADMIN_IDS else None


async def set_support_contact(contact: str, admin_id: Any) -> None:
    assert db_pool
    async with db_pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO bot_settings (key, value, updated_by, updated_at)
            VALUES ('support_contact', $1, $2, NOW())
            ON CONFLICT (key)
            DO UPDATE SET
              value = EXCLUDED.value,
              updated_by = EXCLUDED.updated_by,
              updated_at = NOW()
            """,
            contact,
            safe_int(admin_id),
        )


def media_from_message(message: dict[str, Any]) -> dict[str, Any] | None:
    if document := message.get("document"):
        return {
            "kind": "document",
            "file_id": document["file_id"],
            "file_unique_id": document["file_unique_id"],
            "file_name": document.get("file_name") or f"document-{message['message_id']}",
            "mime_type": document.get("mime_type"),
            "file_size": document.get("file_size"),
        }
    if video := message.get("video"):
        return {
            "kind": "video",
            "file_id": video["file_id"],
            "file_unique_id": video["file_unique_id"],
            "file_name": video.get("file_name") or f"video-{message['message_id']}.mp4",
            "mime_type": video.get("mime_type") or "video/mp4",
            "file_size": video.get("file_size"),
        }
    if audio := message.get("audio"):
        return {
            "kind": "audio",
            "file_id": audio["file_id"],
            "file_unique_id": audio["file_unique_id"],
            "file_name": audio.get("file_name") or audio.get("title") or f"audio-{message['message_id']}",
            "mime_type": audio.get("mime_type"),
            "file_size": audio.get("file_size"),
        }
    if photos := message.get("photo"):
        photo = sorted(photos, key=lambda item: item.get("file_size") or 0, reverse=True)[0]
        return {
            "kind": "photo",
            "file_id": photo["file_id"],
            "file_unique_id": photo["file_unique_id"],
            "file_name": f"photo-{message['message_id']}.jpg",
            "mime_type": "image/jpeg",
            "file_size": photo.get("file_size"),
        }
    return None


async def set_webhook() -> None:
    webhook_url = f"{WEBHOOK_BASE_URL.rstrip('/')}/webhook/{WEBHOOK_SECRET}"
    await telegram(
        "setWebhook",
        {
            "url": webhook_url,
            "secret_token": WEBHOOK_SECRET,
            "allowed_updates": ["message", "callback_query"],
            "drop_pending_updates": DROP_PENDING_UPDATES,
        },
    )
    print(f"Webhook set to {webhook_url}")


async def telegram(method: str, payload: dict[str, Any]) -> Any:
    assert http_client
    response = await http_client.post(f"{TELEGRAM_API_ROOT}/bot{BOT_TOKEN}/{method}", json=payload)
    body = response.json()
    if not response.is_success or not body.get("ok"):
        raise RuntimeError(f"Telegram {method} failed: {body.get('description') or response.text}")
    return body.get("result")


async def send_message(chat_id: int, text: str, **extra: Any) -> Any:
    return await telegram(
        "sendMessage",
        {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
            **extra,
        },
    )


async def edit_message(chat_id: int, message_id: int, text: str, reply_markup: dict[str, Any]) -> Any:
    try:
        return await telegram(
            "editMessageText",
            {
                "chat_id": chat_id,
                "message_id": message_id,
                "text": text,
                "parse_mode": "HTML",
                "disable_web_page_preview": True,
                "reply_markup": reply_markup,
            },
        )
    except RuntimeError as exc:
        msg = str(exc)
        if "message is not modified" in msg:
            return None
        if "there is no text in the message to edit" in msg or "message can't be edited" in msg:
            return await send_message(chat_id, text, reply_markup=reply_markup)
        raise


async def answer_callback(callback_query_id: str, text: str | None = None, show_alert: bool = False) -> Any:
    payload: dict[str, Any] = {"callback_query_id": callback_query_id, "show_alert": show_alert}
    if text:
        payload["text"] = text
    return await telegram("answerCallbackQuery", payload)


def is_admin(user_id: Any) -> bool:
    return str(user_id) in ADMIN_IDS


def hash_password(password: str) -> tuple[str, str]:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), 200_000)
    return salt, digest.hex()


def verify_password(password: str, salt: str, expected_hash: str) -> bool:
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), 200_000).hex()
    return hmac.compare_digest(digest, expected_hash)


def clean_title(value: str) -> str:
    return " ".join(str(value or "").strip().split())[:255]


def clean_support_contact(value: str) -> str:
    contact = " ".join(str(value or "").strip().split())
    if not contact or len(contact) > 128:
        return ""

    if re.fullmatch(r"[A-Za-z0-9_]{5,32}", contact):
        return f"@{contact}"

    if re.fullmatch(r"@[A-Za-z0-9_]{5,32}", contact):
        return contact

    if re.fullmatch(r"\d{4,20}", contact):
        return contact

    if support_contact_url(contact):
        return contact

    return ""


def support_contact_url(contact: str | None) -> str | None:
    if not contact:
        return None

    value = contact.strip()
    username = ""

    if re.fullmatch(r"@[A-Za-z0-9_]{5,32}", value):
        username = value[1:]
    elif re.fullmatch(r"[A-Za-z0-9_]{5,32}", value):
        username = value
    else:
        match = re.fullmatch(r"(?:https?://)?t\.me/([A-Za-z0-9_]{5,32})/?", value)
        if match:
            username = match.group(1)

    return f"https://t.me/{username}" if username else None


def trim_button(value: str) -> str:
    text = str(value or "Untitled").strip()
    return f"{text[:45]}..." if len(text) > 48 else text


def display_name(user: dict[str, Any]) -> str:
    return " ".join(item for item in [user.get("first_name"), user.get("last_name")] if item) or user.get("username") or str(user.get("id"))


def format_bytes(value: Any) -> str:
    try:
        size = float(value or 0)
    except ValueError:
        return "unknown"
    if size <= 0:
        return "unknown"
    units = ["B", "KB", "MB", "GB", "TB"]
    unit = 0
    while size >= 1024 and unit < len(units) - 1:
        size /= 1024
        unit += 1
    return f"{size:.0f} {units[unit]}" if size >= 10 or unit == 0 else f"{size:.1f} {units[unit]}"


def format_date(value: Any) -> str:
    if isinstance(value, datetime):
        return value.date().isoformat()
    return "unknown"


def safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def e(value: Any) -> str:
    return html.escape(str(value or ""), quote=True)

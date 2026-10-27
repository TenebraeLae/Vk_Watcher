#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""VK-наблюдатель: Telegram-бот, следящий за открытыми профилями VK.

Зависимость: requests. Python 3.9+.
Секреты берутся из переменных окружения VK_TOKEN, TG_TOKEN, TG_CHAT
или из файла .env рядом со скриптом.
Запуск: python vk_watcher.py
"""

import html
import logging
import os
import re
import sqlite3
import stat
import threading
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

import requests


# ============================ СЕКРЕТЫ И КОНФИГУРАЦИЯ ============================
def load_dotenv(path: str) -> None:
    """Подгружает KEY=VALUE из .env в os.environ (уже заданные переменные не трогает).

    На POSIX предупреждает, если файл доступен группе/остальным пользователям.
    """
    if not os.path.isfile(path):
        return
    try:
        if os.name == "posix" and os.stat(path).st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            print(f"ВНИМАНИЕ: {path} доступен другим пользователям. Выполните: chmod 600 {path}")
    except OSError:
        pass
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip().removeprefix("export ").strip() if hasattr(str, "removeprefix") \
                else re.sub(r"^export\s+", "", key.strip())
            value = value.strip().strip('"').strip("'")
            os.environ.setdefault(key, value)


def parse_chat_id(raw: str) -> int:
    """Преобразует TG_CHAT в число; при неверном значении возвращает 0."""
    try:
        return int(raw.strip())
    except (ValueError, AttributeError):
        return 0


load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

CONFIG = {
    "vk_token": os.environ.get("VK_TOKEN", "").strip(),     # токен VK
    "tg_token": os.environ.get("TG_TOKEN", "").strip(),     # токен бота от @BotFather
    "tg_chat": parse_chat_id(os.environ.get("TG_CHAT", "")),  # chat_id владельца
    "online_period": 300,        # опрос онлайна, сек
    "friends_period": 86400,     # опрос друзей, сек
    "likes_period": 86400,       # опрос лайков, сек
    "posts_depth": 20,           # сколько последних постов проверять
    "log_keep_days": 30,         # сколько дней хранить online_log
    "db_path": "vk_watcher.db",
}

VK_API_URL = "https://api.vk.com/method/"
VK_API_VERSION = "5.199"
VK_MIN_INTERVAL = 0.4          # пауза между запросами к VK (≤ 3 запросов/сек)
VK_RETRY_CODES = {6, 9}        # «слишком много запросов» — повторяем с паузой
VK_ACCESS_CODES = {15, 18, 30, 203}  # закрытый/удалённый профиль, нет доступа
TG_MAX_LEN = 4000              # лимит Telegram 4096, оставляем запас
HTTP_TIMEOUT = 20
DAY = 86400

PLATFORMS = {
    1: "мобильное приложение", 2: "iPhone", 3: "iPad", 4: "Android",
    5: "Windows Phone", 6: "Windows", 7: "веб-версия",
}


# ============================ ЛОГИРОВАНИЕ БЕЗ УТЕЧКИ ТОКЕНОВ ============================
_TOKEN_PATTERNS = [
    re.compile(r"bot\d+:[A-Za-z0-9_-]+"),         # токен бота в URL Telegram
    re.compile(r"access_token=[^&\s'\"]+"),        # токен VK в параметрах
]


def redact(text: str) -> str:
    """Маскирует токены в произвольном тексте (логи, сообщения об ошибках)."""
    for secret in (CONFIG["vk_token"], CONFIG["tg_token"]):
        if len(secret) >= 8:
            text = text.replace(secret, "***")
    for pattern in _TOKEN_PATTERNS:
        text = pattern.sub("***", text)
    return text


class RedactingFormatter(logging.Formatter):
    """Форматтер, который маскирует токены в сообщении и в traceback."""

    def format(self, record: logging.LogRecord) -> str:
        return redact(super().format(record))


_handler = logging.StreamHandler()
_handler.setFormatter(RedactingFormatter("%(asctime)s [%(threadName)s] %(levelname)s: %(message)s"))
logging.basicConfig(level=logging.INFO, handlers=[_handler])
logging.getLogger("urllib3").setLevel(logging.WARNING)
log = logging.getLogger("vk_watcher")


# ============================ ИСКЛЮЧЕНИЯ ============================
class VkError(Exception):
    """Ошибка, возвращённая VK API (поле error в ответе)."""

    def __init__(self, message: str, code: Optional[int] = None):
        super().__init__(message)
        self.code = code


class TgError(Exception):
    """Ошибка, возвращённая Telegram Bot API."""


# ============================ БАЗА ДАННЫХ ============================
DB_LOCK = threading.Lock()   # один лок на каждую транзакцию и на состояние диалога
_conn = sqlite3.connect(CONFIG["db_path"], check_same_thread=False)
_conn.execute("PRAGMA journal_mode=WAL")
try:                          # база содержит чужие данные — закрываем от других пользователей
    os.chmod(CONFIG["db_path"], 0o600)
except OSError:
    pass

SCHEMA = """
CREATE TABLE IF NOT EXISTS subscribers(
    target_id INTEGER PRIMARY KEY, label TEXT NOT NULL, added_ts INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS online_log(
    ts INTEGER NOT NULL, target_id INTEGER NOT NULL, online INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS idx_online_log ON online_log(target_id, ts);
CREATE TABLE IF NOT EXISTS friend_map(
    target_id INTEGER NOT NULL, friend_id INTEGER NOT NULL,
    PRIMARY KEY(target_id, friend_id));
CREATE TABLE IF NOT EXISTS post_seen(
    target_id INTEGER NOT NULL, post_id INTEGER NOT NULL, seen_ts INTEGER NOT NULL,
    PRIMARY KEY(target_id, post_id));
CREATE TABLE IF NOT EXISTS like_map(
    post_id TEXT NOT NULL, liker_id INTEGER NOT NULL,
    PRIMARY KEY(post_id, liker_id));
"""
with DB_LOCK, _conn:
    _conn.executescript(SCHEMA)


def db_query(sql: str, params: Sequence[Any] = ()) -> List[tuple]:
    """Выполняет SELECT под глобальным локом и возвращает все строки."""
    with DB_LOCK:
        return _conn.execute(sql, params).fetchall()


def db_write(statements: Sequence[Tuple[str, Sequence[Any]]]) -> None:
    """Выполняет несколько изменяющих запросов одной транзакцией под локом."""
    with DB_LOCK, _conn:
        for sql, params in statements:
            _conn.execute(sql, params)


def db_write_many(sql: str, rows: Sequence[Sequence[Any]]) -> None:
    """Массовая вставка/удаление (executemany) одной транзакцией под локом."""
    if rows:
        with DB_LOCK, _conn:
            _conn.executemany(sql, rows)


def get_subscribers() -> List[Tuple[int, str]]:
    """Возвращает список подписок [(target_id, label)] по алфавиту."""
    return db_query("SELECT target_id, label FROM subscribers ORDER BY label COLLATE NOCASE")


def get_label(target_id: int) -> Optional[str]:
    """Возвращает имя подписки или None, если подписки нет."""
    rows = db_query("SELECT label FROM subscribers WHERE target_id=?", (target_id,))
    return rows[0][0] if rows else None


def cleanup_online_log() -> None:
    """Удаляет записи online_log старше log_keep_days.

    Последняя запись каждого человека сохраняется, чтобы не потерять текущее состояние.
    """
    cutoff = int(time.time()) - int(CONFIG["log_keep_days"]) * DAY
    db_write([("DELETE FROM online_log WHERE ts < ? AND rowid NOT IN "
               "(SELECT MAX(rowid) FROM online_log GROUP BY target_id)", (cutoff,))])


# ============================ БЛОКИРОВКИ ПРОВЕРОК ============================
# Периодический опрос и «нулевой снимок» новой подписки не должны пересекаться,
# иначе возможны дубликаты уведомлений.
_target_locks: Dict[Tuple[str, int], threading.Lock] = {}
_target_locks_guard = threading.Lock()
ONLINE_LOCK = threading.Lock()
_warned: Set[Tuple[str, int]] = set()   # о каких закрытых профилях уже писали в лог


def target_lock(kind: str, target_id: int) -> threading.Lock:
    """Возвращает отдельный лок для пары (вид проверки, цель)."""
    with _target_locks_guard:
        return _target_locks.setdefault((kind, target_id), threading.Lock())


def warn_access_once(kind: str, target_id: int, exc: Exception) -> None:
    """Пишет в лог о недоступности данных (закрытый профиль) только один раз."""
    key = (kind, target_id)
    if key not in _warned:
        _warned.add(key)
        log.warning("%s для %s недоступны (профиль закрыт/удалён?): %s", kind, target_id, exc)


# ============================ СОСТОЯНИЕ ДИАЛОГА ============================
_dialog: Dict[str, Any] = {"state": None, "prompt_msg": None}
STATE_AWAIT_TARGET = "await_target"   # шаг 1: ждём id/ссылку
STATE_CONFIRM = "confirm"             # шаг 2: ждём нажатия кнопки


def set_dialog(state: Optional[str], prompt_msg: Optional[int] = None) -> None:
    """Устанавливает состояние диалога и id сообщения-подсказки."""
    with DB_LOCK:
        _dialog["state"] = state
        _dialog["prompt_msg"] = prompt_msg


def get_dialog() -> Tuple[Optional[str], Optional[int]]:
    """Возвращает (состояние, id сообщения-подсказки)."""
    with DB_LOCK:
        return _dialog["state"], _dialog["prompt_msg"]


# ============================ VK API ============================
_vk_rate_lock = threading.Lock()
_vk_last_call = 0.0


def vk_call(method: str, **params: Any) -> Any:
    """Вызывает метод VK API с общим троттлингом (≤ 3 запросов/сек).

    Токен передаётся в теле POST-запроса, а не в URL, поэтому он не попадает
    в тексты исключений requests. Ошибки 6/9 (лимиты) повторяются с паузой.
    При наличии error в ответе бросает VkError.
    """
    global _vk_last_call
    params.update(access_token=CONFIG["vk_token"], v=VK_API_VERSION)
    for attempt in range(3):
        with _vk_rate_lock:
            wait = _vk_last_call + VK_MIN_INTERVAL - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            _vk_last_call = time.monotonic()
        resp = requests.post(VK_API_URL + method, data=params, timeout=HTTP_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        if "error" in data:
            err = data["error"]
            code = err.get("error_code")
            if code in VK_RETRY_CODES and attempt < 2:
                time.sleep(1.5 * (attempt + 1))
                continue
            raise VkError(f"{method}: [{code}] {err.get('error_msg')}", code)
        return data["response"]
    raise VkError(f"{method}: превышено число попыток")


def get_users(ids: Sequence[int], fields: str = "", chunk: int = 100) -> List[dict]:
    """users.get для списка id пачками по chunk штук."""
    result: List[dict] = []
    ids = list(ids)
    for i in range(0, len(ids), chunk):
        part = ids[i:i + chunk]
        params: Dict[str, Any] = {"user_ids": ",".join(map(str, part))}
        if fields:
            params["fields"] = fields
        result.extend(vk_call("users.get", **params))
    return result


def full_name(user: dict) -> str:
    """Имя и фамилия пользователя из объекта VK."""
    return f"{user.get('first_name', '')} {user.get('last_name', '')}".strip() or "Без имени"


def profile_url(user_id: int) -> str:
    """Ссылка на профиль по числовому id."""
    return f"https://vk.com/id{user_id}"


def person_html(user_id: int, names: Dict[int, str]) -> str:
    """Строка «Имя (vk.com/idN)» с экранированием для HTML-режима Telegram."""
    name = html.escape(names.get(user_id, f"id{user_id}"))
    return f"{name} (vk.com/id{user_id})"


def parse_target_input(text: str) -> Tuple[Optional[str], Any]:
    """Разбирает ввод пользователя.

    Возвращает ("id", int), ("name", str) или (None, текст_ошибки).
    """
    raw = text.strip().lstrip("@")
    if not raw:
        return None, "Пустой ввод. Отправьте id, ссылку или короткое имя."
    path = re.sub(r"^(?:https?://)?(?:www\.|m\.)?vk\.(?:com|ru)/", "", raw, flags=re.I)
    path = re.split(r"[/?#]", path, maxsplit=1)[0]
    if re.fullmatch(r"-\d+", path) or re.fullmatch(r"(?:club|public|event)\d+", path, re.I):
        return None, "Это сообщество, а не пользователь. Отправьте профиль человека."
    if re.fullmatch(r"\d+", path):
        return "id", int(path)
    m = re.fullmatch(r"id(\d+)", path, re.I)
    if m:
        return "id", int(m.group(1))
    if re.fullmatch(r"[A-Za-z0-9_.]{2,64}", path):
        return "name", path
    return None, "Не удалось распознать id или ссылку. Попробуйте ещё раз."


def resolve_user(text: str) -> Tuple[Optional[dict], str]:
    """Находит пользователя VK по вводу. Возвращает (user, ошибка)."""
    kind, value = parse_target_input(text)
    if kind is None:
        return None, value
    if kind == "name":
        resolved = vk_call("utils.resolveScreenName", screen_name=value)
        if not isinstance(resolved, dict) or not resolved:
            return None, "Такого имени не существует."
        if resolved.get("type") != "user":
            return None, "Это не пользователь (группа или другой объект)."
        user_id = int(resolved["object_id"])
    else:
        user_id = value
    users = get_users([user_id], fields="screen_name,online,last_seen,city,status")
    if not users:
        return None, "Пользователь не найден."
    user = users[0]
    if user.get("deactivated"):
        return None, "Профиль удалён или заблокирован."
    return user, ""


# ============================ TELEGRAM API ============================
def tg_call(method: str, http_timeout: int = HTTP_TIMEOUT, **params: Any) -> Any:
    """Вызов Bot API. При ok=false бросает TgError; один повтор при 429.

    http_timeout — таймаут HTTP-запроса (для getUpdates он больше long-poll timeout).
    """
    url = f"https://api.telegram.org/bot{CONFIG['tg_token']}/{method}"
    for attempt in range(2):
        resp = requests.post(url, json=params, timeout=http_timeout)
        try:
            data = resp.json()
        except ValueError:
            resp.raise_for_status()
            raise
        if data.get("ok"):
            return data["result"]
        retry_after = (data.get("parameters") or {}).get("retry_after")
        if data.get("error_code") == 429 and retry_after and attempt == 0:
            time.sleep(int(retry_after) + 1)
            continue
        raise TgError(data.get("description", "unknown error"))
    raise TgError("Telegram: слишком много запросов")


def split_text(text: str, limit: int = TG_MAX_LEN) -> List[str]:
    """Режет текст на куски ≤ limit, по возможности по границам строк.

    Теги HTML не рвутся: разметка в уведомлениях целиком помещается в одну строку.
    """
    chunks, current = [], ""
    for line in text.split("\n"):
        while len(line) > limit:                 # слишком длинная строка — режем жёстко
            if current:
                chunks.append(current)
                current = ""
            chunks.append(line[:limit])
            line = line[limit:]
        candidate = f"{current}\n{line}" if current else line
        if len(candidate) > limit:
            chunks.append(current)
            current = line
        else:
            current = candidate
    if current or not chunks:
        chunks.append(current)
    return chunks


def send_message(chat_id: int, text: str, keyboard: Optional[dict] = None) -> Optional[int]:
    """Отправляет сообщение (HTML), длинное режет. Клавиатура — на последнем куске.

    Возвращает message_id последнего куска.
    """
    parts = split_text(text)
    message_id = None
    for i, part in enumerate(parts):
        params: Dict[str, Any] = {
            "chat_id": chat_id, "text": part, "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }
        if keyboard and i == len(parts) - 1:
            params["reply_markup"] = keyboard
        message_id = tg_call("sendMessage", **params)["message_id"]
    return message_id


def edit_message(chat_id: int, message_id: int, text: str, keyboard: Optional[dict] = None) -> None:
    """editMessageText; «message is not modified» игнорируется молча."""
    params: Dict[str, Any] = {
        "chat_id": chat_id, "message_id": message_id, "text": text[:TG_MAX_LEN],
        "parse_mode": "HTML", "disable_web_page_preview": True,
    }
    if keyboard:
        params["reply_markup"] = keyboard
    try:
        tg_call("editMessageText", **params)
    except TgError as exc:
        if "message is not modified" in str(exc):
            return
        raise


def show(chat_id: int, message_id: Optional[int], text: str, keyboard: Optional[dict] = None) -> Optional[int]:
    """Обновляет экран через edit; если править нечего/нельзя — шлёт новое сообщение."""
    if message_id:
        try:
            edit_message(chat_id, message_id, text, keyboard)
            return message_id
        except TgError as exc:
            log.warning("editMessageText не удался (%s), отправляю новое сообщение", exc)
    return send_message(chat_id, text, keyboard)


def answer_callback(callback_id: str) -> None:
    """answerCallbackQuery без текста (убирает «часики» на кнопке)."""
    try:
        tg_call("answerCallbackQuery", callback_query_id=callback_id)
    except Exception as exc:  # устаревший callback — не критично
        log.warning("answerCallbackQuery: %s", exc)


def notify(text: str) -> None:
    """Уведомление владельцу."""
    send_message(int(CONFIG["tg_chat"]), text)


# ============================ КЛАВИАТУРЫ И ЭКРАНЫ ============================
def btn(text: str, data: str) -> dict:
    """Inline-кнопка с компактным callback_data."""
    return {"text": text, "callback_data": data}


def kb(*rows: List[dict]) -> dict:
    """Собирает inline-клавиатуру из рядов кнопок."""
    return {"inline_keyboard": [list(r) for r in rows]}


MENU_BTN_ROW = [btn("⬅️ Назад", "back")]


def main_menu() -> Tuple[str, dict]:
    """Текст и клавиатура главного меню."""
    text = "👁 <b>VK-наблюдатель</b>\nСлежу за открытыми профилями VK. Выберите действие:"
    return text, kb(
        [btn("➕ Подписаться", "sub_start")],
        [btn("📋 Мои подписки", "list")],
        [btn("❓ Как это работает", "help")],
    )


HELP_TEXT = (
    "❓ <b>Как это работает</b>\n\n"
    "Нажмите «Подписаться» и отправьте id, ссылку или короткое имя профиля VK.\n\n"
    "Я слежу за:\n"
    "🟢 онлайном — уведомляю, когда человек зашёл или вышел (проверка каждые "
    f"{CONFIG['online_period'] // 60} мин);\n"
    "👥 друзьями — новые и удалённые (раз в сутки);\n"
    "❤️ лайками на последних постах (раз в сутки).\n\n"
    "Первая проверка ничего не присылает — она лишь запоминает текущее состояние. "
    "У закрытых профилей друзья и посты недоступны, отслеживается только онлайн."
)


# ============================ ОБРАБОТЧИКИ TELEGRAM ============================
def screen_menu(chat_id: int, message_id: Optional[int]) -> None:
    """Показывает главное меню и сбрасывает диалог."""
    set_dialog(None)
    text, keyboard = main_menu()
    show(chat_id, message_id, text, keyboard)


def screen_list(chat_id: int, message_id: int) -> None:
    """Список подписок: по кнопке на человека."""
    subs = get_subscribers()
    if not subs:
        show(chat_id, message_id, "📋 Подписок пока нет.",
             kb([btn("➕ Подписаться", "sub_start")], MENU_BTN_ROW))
        return
    rows = [[btn(f"👤 {label}"[:60], f"user:{tid}")] for tid, label in subs]
    rows.append(MENU_BTN_ROW)
    show(chat_id, message_id, f"📋 <b>Мои подписки</b> ({len(subs)}):", kb(*rows))


def screen_user(chat_id: int, message_id: int, target_id: int) -> None:
    """Карточка человека."""
    label = get_label(target_id)
    if label is None:
        screen_list(chat_id, message_id)
        return
    text = f"👤 <b>{html.escape(label)}</b>\n{profile_url(target_id)}"
    show(chat_id, message_id, text, kb(
        [btn("📍 Статус сейчас", f"check:{target_id}")],
        [btn("🗑 Отписаться", f"unsub:{target_id}")],
        [btn("⬅️ Назад", "list")],
    ))


def format_status(user: dict) -> str:
    """Текст «статус сейчас» по объекту users.get."""
    seen = user.get("last_seen") or {}
    platform = PLATFORMS.get(seen.get("platform"), "")
    if user.get("online"):
        state = "🟢 онлайн" + (f" ({platform})" if platform else "")
    else:
        state = "⚫ офлайн"
    last = (datetime.fromtimestamp(seen["time"]).strftime("%d.%m.%Y %H:%M")
            if seen.get("time") else "скрыто / неизвестно")
    city = (user.get("city") or {}).get("title") or "не указан"
    status = user.get("status") or "—"
    closed = ("\n🔒 Профиль закрыт, данные могут быть неполными."
              if user.get("is_closed") and not user.get("can_access_closed") else "")
    return (
        f"📍 <b>{html.escape(full_name(user))}</b>\n"
        f"Сейчас: {state}\n"
        f"Последний визит: {last}\n"
        f"Город: {html.escape(city)}\n"
        f"Статус: {html.escape(status)}{closed}"
    )


def screen_check(chat_id: int, message_id: int, target_id: int) -> None:
    """Мгновенный статус человека через users.get."""
    users = get_users([target_id], fields="online,last_seen,city,status,is_closed,can_access_closed")
    text = format_status(users[0]) if users else "Пользователь не найден."
    show(chat_id, message_id, text, kb(
        [btn("🔄 Обновить", f"check:{target_id}")],
        [btn("⬅️ Назад", f"user:{target_id}")],
    ))


def screen_unsub_ask(chat_id: int, message_id: int, target_id: int) -> None:
    """Запрос подтверждения отписки."""
    label = html.escape(get_label(target_id) or str(target_id))
    show(chat_id, message_id, f"Точно отписаться от <b>{label}</b>?", kb(
        [btn("✅ Да", f"unsub_yes:{target_id}"), btn("❌ Нет", f"user:{target_id}")]))


def do_unsubscribe(chat_id: int, message_id: int, target_id: int) -> None:
    """Удаляет подписку и все связанные данные одной транзакцией."""
    prefix = f"{target_id}_"
    db_write([
        ("DELETE FROM subscribers WHERE target_id=?", (target_id,)),
        ("DELETE FROM online_log WHERE target_id=?", (target_id,)),
        ("DELETE FROM friend_map WHERE target_id=?", (target_id,)),
        ("DELETE FROM post_seen WHERE target_id=?", (target_id,)),
        ("DELETE FROM like_map WHERE substr(post_id, 1, ?) = ?", (len(prefix), prefix)),
    ])
    show(chat_id, message_id, "🗑 Подписка удалена.",
         kb([btn("📋 Мои подписки", "list")], MENU_BTN_ROW))


def baseline_in_background(target_id: int) -> None:
    """Сразу снимает «нулевое» состояние новой подписки (без уведомлений)."""
    def worker() -> None:
        for name, task in (("онлайн", lambda: check_online([target_id])),
                           ("друзья", lambda: check_friends_for(target_id)),
                           ("лайки", lambda: check_likes_for(target_id))):
            try:
                task()
            except Exception as exc:
                log.error("Первичный снимок (%s) для %s не удался: %s", name, target_id, exc)
    threading.Thread(target=worker, name=f"baseline-{target_id}", daemon=True).start()


def do_subscribe(chat_id: int, message_id: int, target_id: int) -> None:
    """Шаг 2: подтверждение — записывает подписку в БД."""
    set_dialog(None)
    existing = get_label(target_id)
    if existing is not None:
        show(chat_id, message_id, f"👀 Уже слежу за <b>{html.escape(existing)}</b>.",
             kb(MENU_BTN_ROW))
        return
    users = get_users([target_id])
    if not users or users[0].get("deactivated"):
        show(chat_id, message_id, "Профиль больше недоступен.", kb(MENU_BTN_ROW))
        return
    name = full_name(users[0])
    db_write([("INSERT OR IGNORE INTO subscribers(target_id, label, added_ts) VALUES(?,?,?)",
               (target_id, name, int(time.time())))])
    baseline_in_background(target_id)
    show(chat_id, message_id,
         f"✅ Подписка оформлена: <b>{html.escape(name)}</b>\n"
         "Текущее состояние запоминаю, уведомления пойдут при изменениях.",
         kb([btn("📋 Мои подписки", "list")], MENU_BTN_ROW))


def handle_target_input(chat_id: int, text: str, prompt_msg: Optional[int]) -> None:
    """Шаг 1 диалога: проверяет присланный профиль и показывает шаг 2."""
    cancel_row = [btn("❌ Отмена", "menu")]
    user, error = resolve_user(text)
    if user is None:
        show(chat_id, prompt_msg, f"⚠️ {html.escape(error)}\n\nОтправьте id, ссылку vk.com/… "
             "или короткое имя ещё раз.", kb(cancel_row))
        return
    target_id = int(user["id"])
    existing = get_label(target_id)
    if existing is not None:
        set_dialog(None)
        show(chat_id, prompt_msg, f"👀 Уже слежу за <b>{html.escape(existing)}</b>.",
             kb(MENU_BTN_ROW))
        return
    set_dialog(STATE_CONFIRM, prompt_msg)
    closed = ("\n🔒 Профиль закрыт — друзья и посты могут быть недоступны."
              if user.get("is_closed") and not user.get("can_access_closed") else "")
    show(chat_id, prompt_msg,
         f"Найден профиль:\n<b>{html.escape(full_name(user))}</b>\n{profile_url(target_id)}{closed}\n\n"
         "Подписаться?",
         kb([btn("✅ Подписаться", f"sub_confirm:{target_id}"), btn("❌ Отмена", "menu")]))


def handle_message(msg: dict) -> None:
    """Обработка обычного сообщения владельца."""
    chat_id = msg["chat"]["id"]
    text = (msg.get("text") or "").strip()
    if text.split("@")[0] == "/start":
        screen_menu(chat_id, None)
        return
    state, prompt_msg = get_dialog()
    if state == STATE_AWAIT_TARGET and text:
        handle_target_input(chat_id, text, prompt_msg)
        return
    menu_text, menu_kb = main_menu()
    send_message(chat_id, "Не совсем понял 🙂 Давайте воспользуемся меню:\n\n" + menu_text, menu_kb)


def handle_callback(cb: dict) -> None:
    """Обработка нажатия inline-кнопки."""
    answer_callback(cb["id"])
    msg = cb.get("message")
    if not msg:          # слишком старое сообщение: Telegram не передаёт его содержимое
        return
    chat_id, message_id = msg["chat"]["id"], msg["message_id"]
    action, _, arg = (cb.get("data") or "").partition(":")
    target_id = int(arg) if arg.lstrip("-").isdigit() else None

    if action in ("menu", "back"):
        screen_menu(chat_id, message_id)
    elif action == "help":
        show(chat_id, message_id, HELP_TEXT, kb(MENU_BTN_ROW))
    elif action == "sub_start":
        set_dialog(STATE_AWAIT_TARGET, message_id)
        show(chat_id, message_id,
             "➕ <b>Новая подписка</b>\nОтправьте id, ссылку vk.com/… или короткое имя профиля.",
             kb([btn("❌ Отмена", "menu")]))
    elif action == "list":
        set_dialog(None)
        screen_list(chat_id, message_id)
    elif target_id is not None and action == "sub_confirm":
        do_subscribe(chat_id, message_id, target_id)
    elif target_id is not None and action == "user":
        screen_user(chat_id, message_id, target_id)
    elif target_id is not None and action == "check":
        screen_check(chat_id, message_id, target_id)
    elif target_id is not None and action == "unsub":
        screen_unsub_ask(chat_id, message_id, target_id)
    elif target_id is not None and action == "unsub_yes":
        do_unsubscribe(chat_id, message_id, target_id)
    else:
        screen_menu(chat_id, message_id)


def process_update(update: dict) -> None:
    """Проверяет владельца, маршрутизирует апдейт и ловит ошибки обработчиков."""
    owner = int(CONFIG["tg_chat"])
    cb = update.get("callback_query")
    msg = update.get("message")
    if cb:
        if cb.get("from", {}).get("id") != owner or cb.get("message", {}).get("chat", {}).get("id") != owner:
            return
    elif msg:
        if msg.get("from", {}).get("id") != owner or msg.get("chat", {}).get("id") != owner:
            return
    else:
        return
    try:
        handle_callback(cb) if cb else handle_message(msg)
    except Exception as exc:
        log.exception("Ошибка в обработчике")
        try:
            # redact: текст исключения requests может содержать URL с токеном
            text = f"⚠️ Произошла ошибка:\n<code>{html.escape(redact(str(exc)))[:500]}</code>"
            message_id = (cb.get("message") or {}).get("message_id") if cb else None
            if message_id:
                show(owner, message_id, text, kb(MENU_BTN_ROW))
            else:
                send_message(owner, text, kb(MENU_BTN_ROW))
        except Exception:
            log.exception("Не удалось показать сообщение об ошибке")


# ============================ МОНИТОРИНГ: ОНЛАЙН ============================
def check_online(target_ids: Optional[Sequence[int]] = None) -> None:
    """Опрашивает онлайн подписок, логирует состояние и уведомляет о смене.

    ids отправляются одной пачкой (users.get принимает до 1000, берём по 100).
    Первая проверка человека (нет записей в логе) уведомления не шлёт.
    """
    if target_ids is None:
        target_ids = [tid for tid, _ in get_subscribers()]
    if not target_ids:
        return
    with ONLINE_LOCK:
        labels = dict(get_subscribers())
        for user in get_users(target_ids, fields="online,last_seen"):
            tid = int(user["id"])
            if tid not in labels or user.get("deactivated"):
                continue
            now_online = 1 if user.get("online") else 0
            prev = db_query("SELECT online FROM online_log WHERE target_id=? "
                            "ORDER BY ts DESC, rowid DESC LIMIT 1", (tid,))
            seen = user.get("last_seen") or {}
            if prev and prev[0][0] != now_online:
                platform_id = seen.get("platform")
                platform = PLATFORMS.get(platform_id, f"платформа {platform_id}" if platform_id else "неизвестно")
                # при выходе реальное время — last_seen.time, при входе — текущее
                event_ts = seen["time"] if (not now_online and seen.get("time")) else int(time.time())
                when = datetime.fromtimestamp(event_ts).strftime("%d.%m.%Y %H:%M")
                action = "🟢 зашёл в сеть" if now_online else "⚫ вышел из сети"
                notify(f"<b>{html.escape(labels[tid])}</b> {action}\n"
                       f"🕒 {when}\n📱 Платформа: {html.escape(platform)}")
            db_write([("INSERT INTO online_log(ts, target_id, online) VALUES(?,?,?)",
                       (int(time.time()), tid, now_online))])


_last_cleanup = 0.0


def online_task() -> None:
    """Задача онлайн-потока: опрос + раз в сутки очистка старого лога."""
    global _last_cleanup
    check_online()
    if time.time() - _last_cleanup > DAY:
        cleanup_online_log()
        _last_cleanup = time.time()


# ============================ МОНИТОРИНГ: ДРУЗЬЯ ============================
# Строка с friend_id=0 / post_id=0 — маркер «первый снимок уже сделан»
# (чтобы пустой список друзей/постов не считался «первым запуском» вечно).
BASELINE_MARK = 0


def check_friends_for(target_id: int) -> None:
    """Сравнивает список друзей цели с сохранённым и уведомляет об изменениях."""
    with target_lock("friends", target_id):
        label = get_label(target_id)
        if label is None:
            return
        try:
            current = set(vk_call("friends.get", user_id=target_id, count=10000)["items"])
        except VkError as exc:
            if exc.code in VK_ACCESS_CODES:
                warn_access_once("friends", target_id, exc)
                return
            raise
        _warned.discard(("friends", target_id))
        stored = {r[0] for r in db_query("SELECT friend_id FROM friend_map WHERE target_id=?", (target_id,))}
        has_baseline = BASELINE_MARK in stored
        stored.discard(BASELINE_MARK)

        added, removed = current - stored, stored - current
        if has_baseline and (added or removed):
            lines = [f"👥 <b>{html.escape(label)}</b>: изменения в друзьях"]
            if added:
                names = {int(u["id"]): full_name(u) for u in get_users(sorted(added), chunk=20)}
                lines += ["➕ " + person_html(fid, names) for fid in sorted(added)]
            if removed:
                lines.append("➖ Удалены (имена недоступны): " +
                             ", ".join(f"vk.com/id{fid}" for fid in sorted(removed)))
            notify("\n".join(lines))

        if get_label(target_id) is None:     # отписались, пока шла проверка
            return
        db_write_many("DELETE FROM friend_map WHERE target_id=? AND friend_id=?",
                      [(target_id, fid) for fid in removed])
        db_write_many("INSERT OR IGNORE INTO friend_map(target_id, friend_id) VALUES(?,?)",
                      [(target_id, fid) for fid in added | {BASELINE_MARK}])


# ============================ МОНИТОРИНГ: ЛАЙКИ ============================
def check_likes_for(target_id: int) -> None:
    """Проверяет лайки на последних постах цели.

    Первый проход по цели только запоминает посты и лайки (без уведомлений).
    like_map.post_id хранится как «<owner>_<post>», т.к. id постов у разных людей совпадают.
    Если лайкнувших больше 1000 (список усечён), снятые лайки не вычисляются,
    чтобы не получить ложные «новые лайки» при следующей проверке.
    """
    with target_lock("likes", target_id):
        label = get_label(target_id)
        if label is None:
            return
        safe_label = html.escape(label)
        try:
            posts = vk_call("wall.get", owner_id=target_id, count=CONFIG["posts_depth"])["items"]
        except VkError as exc:
            if exc.code in VK_ACCESS_CODES:
                warn_access_once("posts", target_id, exc)
                return
            raise
        _warned.discard(("posts", target_id))
        seen_posts = {r[0] for r in db_query("SELECT post_id FROM post_seen WHERE target_id=?", (target_id,))}
        has_baseline = BASELINE_MARK in seen_posts

        for post in posts:
            if get_label(target_id) is None:     # отписались, пока шла проверка
                return
            post_id = int(post["id"])
            key = f"{target_id}_{post_id}"
            url = f"https://vk.com/wall{key}"
            try:
                resp = vk_call("likes.getList", type="post", owner_id=target_id, item_id=post_id,
                               filter="likes", extended=0, count=1000)
            except VkError as exc:
                log.warning("likes.getList %s: %s", key, exc)
                continue
            likers_list = [int(x) for x in resp["items"]]
            likers = set(likers_list)
            truncated = int(resp.get("count", 0)) > len(likers_list)
            stored = {r[0] for r in db_query("SELECT liker_id FROM like_map WHERE post_id=?", (key,))}

            if post_id not in seen_posts:
                if has_baseline:
                    head = likers_list[:10]
                    names = {int(u["id"]): full_name(u) for u in get_users([x for x in head if x > 0], chunk=20)}
                    lines = [f"❤️ <b>{safe_label}</b>: новый пост: {resp.get('count', len(likers))} лайков", url]
                    lines += [person_html(uid, names) for uid in head]
                    notify("\n".join(lines))
                db_write([("INSERT OR IGNORE INTO post_seen(target_id, post_id, seen_ts) VALUES(?,?,?)",
                           (target_id, post_id, int(time.time())))])
            else:
                new_likers = [x for x in likers_list if x not in stored]
                if new_likers:
                    shown = new_likers[:50]
                    names = {int(u["id"]): full_name(u) for u in get_users([x for x in shown if x > 0], chunk=20)}
                    lines = [f"❤️ <b>{safe_label}</b>: новые лайки на посте", url]
                    lines += [person_html(uid, names) for uid in shown]
                    if len(new_likers) > len(shown):
                        lines.append(f"…и ещё {len(new_likers) - len(shown)}")
                    notify("\n".join(lines))

            if not truncated:
                db_write_many("DELETE FROM like_map WHERE post_id=? AND liker_id=?",
                              [(key, uid) for uid in stored - likers])
            db_write_many("INSERT OR IGNORE INTO like_map(post_id, liker_id) VALUES(?,?)",
                          [(key, uid) for uid in likers - stored])

        if not has_baseline and get_label(target_id) is not None:
            db_write([("INSERT OR IGNORE INTO post_seen(target_id, post_id, seen_ts) VALUES(?,?,?)",
                       (target_id, BASELINE_MARK, int(time.time())))])


# ============================ ФОНОВЫЕ ПОТОКИ ============================
def check_all_friends() -> None:
    """Проход по всем подпискам: друзья. Ошибка одной цели не прерывает остальных."""
    for tid, label in get_subscribers():
        try:
            check_friends_for(tid)
        except Exception as exc:
            log.error("friends для %s (%s): %s", tid, label, exc)


def check_all_likes() -> None:
    """Проход по всем подпискам: лайки. Ошибка одной цели не прерывает остальных."""
    for tid, label in get_subscribers():
        try:
            check_likes_for(tid)
        except Exception as exc:
            log.error("likes для %s (%s): %s", tid, label, exc)


def run_periodic(task, period: int) -> None:
    """Бесконечный цикл: выполнить task, при ошибке залогировать, спать period сек."""
    while True:
        try:
            task()
        except Exception as exc:
            log.error("Ошибка в фоновой задаче %s: %s", task.__name__, exc)
        time.sleep(period)


def start_background_threads() -> None:
    """Запускает три демона: онлайн, друзья, лайки."""
    jobs = [
        ("online", online_task, CONFIG["online_period"]),
        ("friends", check_all_friends, CONFIG["friends_period"]),
        ("likes", check_all_likes, CONFIG["likes_period"]),
    ]
    for name, task, period in jobs:
        threading.Thread(target=run_periodic, args=(task, period), name=name, daemon=True).start()


# ============================ ГЛАВНЫЙ ЦИКЛ ============================
def poll_telegram() -> None:
    """Long polling getUpdates: обрабатывает message и callback_query."""
    offset = 0
    while True:
        try:
            updates = tg_call("getUpdates", http_timeout=45, offset=offset, timeout=30,
                              allowed_updates=["message", "callback_query"])
        except Exception as exc:
            log.error("getUpdates: %s", exc)
            time.sleep(3)
            continue
        for update in updates:
            offset = update["update_id"] + 1
            process_update(update)


def check_config() -> None:
    """Проверяет, что секреты заданы; иначе завершает работу с понятным сообщением."""
    missing = [name for name, ok in (
        ("VK_TOKEN", bool(CONFIG["vk_token"])),
        ("TG_TOKEN", bool(CONFIG["tg_token"])),
        ("TG_CHAT (число)", bool(CONFIG["tg_chat"])),
    ) if not ok]
    if missing:
        raise SystemExit("Не заданы: " + ", ".join(missing) +
                         ". Укажите их в переменных окружения или в файле .env.")


def main() -> None:
    """Точка входа: проверка конфигурации, фоновые потоки, поллер."""
    check_config()
    try:   # активный webhook блокирует getUpdates (ошибка 409)
        tg_call("deleteWebhook")
    except Exception as exc:
        log.error("deleteWebhook: %s", exc)
    start_background_threads()
    log.info("Бот запущен")
    try:
        poll_telegram()
    except KeyboardInterrupt:
        log.info("Остановлено пользователем")


if __name__ == "__main__":
    main()
import json
import sqlite3
from pathlib import Path
from datetime import datetime, timezone

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "backend" / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "vulenser.db"


def get_connection():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def init_database():
    with get_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user','admin')),
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                original_requirement TEXT NOT NULL,
                result_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        connection.commit()


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def create_user(name: str, email: str, password_hash: str, role: str = "user"):
    with get_connection() as connection:
        cursor = connection.execute(
            "INSERT INTO users (name,email,password_hash,role,is_active,created_at) VALUES (?,?,?,?,1,?)",
            (name.strip(), email.strip().lower(), password_hash, role, utc_now())
        )
        connection.commit()
        return get_user_by_id(cursor.lastrowid)


def get_user_by_email(email: str):
    with get_connection() as connection:
        row = connection.execute("SELECT * FROM users WHERE email = ? COLLATE NOCASE", (email.strip(),)).fetchone()
        return dict(row) if row else None


def get_user_by_id(user_id: int):
    with get_connection() as connection:
        row = connection.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return dict(row) if row else None


def public_user(user):
    return {key: user[key] for key in ("id", "name", "email", "role", "is_active", "created_at")}


def save_analysis(user_id: int, original_requirement: str, result: dict):
    with get_connection() as connection:
        cursor = connection.execute(
            "INSERT INTO analyses (user_id,original_requirement,result_json,created_at) VALUES (?,?,?,?)",
            (user_id, original_requirement, json.dumps(result, ensure_ascii=False), utc_now())
        )
        connection.commit()
        return cursor.lastrowid


def get_user_analyses(user_id: int):
    with get_connection() as connection:
        rows = connection.execute(
            "SELECT id, original_requirement, result_json, created_at FROM analyses WHERE user_id = ? ORDER BY id DESC",
            (user_id,)
        ).fetchall()
        output = []
        for row in rows:
            item = dict(row)
            result = json.loads(item.pop("result_json"))
            output.append({**result, "id": item["id"], "original_requirement": item["original_requirement"], "created_at": item["created_at"]})
        return output


def clear_user_analyses(user_id: int):
    with get_connection() as connection:
        connection.execute("DELETE FROM analyses WHERE user_id = ?", (user_id,))
        connection.commit()

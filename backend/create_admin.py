import re
from getpass import getpass

from database import init_database, get_connection, get_user_by_email, create_user
from auth_service import hash_password


def valid_password(password: str) -> bool:
    return (
        len(password) >= 8
        and re.search(r"[A-Z]", password)
        and re.search(r"[a-z]", password)
        and re.search(r"[0-9]", password)
        and re.search(r"[^A-Za-z0-9\s]", password)
    )


def main():
    init_database()
    with get_connection() as connection:
        existing_admin = connection.execute(
            "SELECT COUNT(*) FROM users WHERE role='admin'"
        ).fetchone()[0]

    if existing_admin:
        raise SystemExit("The main administrator account already exists. Only one admin is allowed.")

    print("Create the main SDLC VuLenseR administrator")
    name = input("Admin name: ").strip()
    email = input("Admin email: ").strip().lower()
    password = getpass("Admin password: ")
    confirm = getpass("Confirm password: ")

    if len(name) < 2:
        raise SystemExit("Name must contain at least 2 characters.")
    if not valid_password(password):
        raise SystemExit("Password must be 8+ characters and include uppercase, lowercase, number and special symbol.")
    if password != confirm:
        raise SystemExit("Passwords do not match.")
    if get_user_by_email(email):
        raise SystemExit("An account with this email already exists.")

    user = create_user(name, email, hash_password(password), "admin")
    print(f"Main administrator created successfully: {user['email']}")


if __name__ == "__main__":
    main()

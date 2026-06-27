import os
import secrets
import string
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from .models import User

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def get_user_by_username(db: Session, username: str) -> User | None:
    return db.query(User).filter(User.username == username).first()


def authenticate_user(db: Session, username: str, password: str) -> User | None:
    user = get_user_by_username(db, username)
    if not user or not verify_password(password, user.hashed_password):
        return None
    return user


def generate_password(length: int = 20) -> str:
    """Cryptographically secure random password (letters + digits, no ambiguity)."""
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def create_default_user(db: Session) -> None:
    if db.query(User).first():
        return
    username = os.getenv("ADMIN_USERNAME", "admin")
    password = os.getenv("ADMIN_PASSWORD")  # optional override
    generated = password is None or password == ""
    if generated:
        password = generate_password()

    db.add(User(username=username, hashed_password=hash_password(password)))
    db.commit()

    if generated:
        bar = "=" * 64
        print(
            f"\n{bar}\n"
            f"  TrueVector — access credentials generated on deploy\n"
            f"{bar}\n"
            f"  Username:   {username}\n"
            f"  Password:   {password}\n"
            f"{bar}\n"
            f"  Save it NOW: it will not be shown again.\n"
            f"  To set your own, define ADMIN_PASSWORD in the environment.\n"
            f"{bar}\n",
            flush=True,
        )
    else:
        print(f"[init] Admin user created from ADMIN_PASSWORD: {username}", flush=True)

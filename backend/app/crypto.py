from __future__ import annotations

import base64
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .config import get_settings
from .models import EncryptedSecret


def ensure_master_key(path: Path | None = None) -> None:
    target = path or get_settings().master_key_path
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.exists():
        target.write_bytes(os.urandom(32))
        target.chmod(0o600)
    if len(target.read_bytes()) != 32:
        raise RuntimeError("Ungültiger Master-Key")


def _key() -> bytes:
    value = get_settings().master_key_path.read_bytes()
    if len(value) != 32:
        raise RuntimeError("Ungültiger Master-Key")
    return value


def encrypt_value(value: str, associated_data: str) -> str:
    nonce = os.urandom(12)
    ciphertext = AESGCM(_key()).encrypt(nonce, value.encode(), associated_data.encode())
    return base64.urlsafe_b64encode(nonce + ciphertext).decode()


def decrypt_value(value: str, associated_data: str) -> str:
    raw = base64.urlsafe_b64decode(value.encode())
    return AESGCM(_key()).decrypt(raw[:12], raw[12:], associated_data.encode()).decode()


def set_repository_secret(db: Session, repository_id: str, name: str, value: str | None) -> None:
    row = db.scalar(
        select(EncryptedSecret).where(
            EncryptedSecret.repository_id == repository_id,
            EncryptedSecret.name == name,
        )
    )
    if value is None:
        if row:
            db.delete(row)
        return
    aad = f"repository:{repository_id}:{name}"
    ciphertext = encrypt_value(value, aad)
    if row:
        row.ciphertext = ciphertext
    else:
        db.add(
            EncryptedSecret(
                repository_id=repository_id,
                name=name,
                ciphertext=ciphertext,
            )
        )


def get_repository_secrets(db: Session, repository_id: str) -> dict[str, str]:
    rows = db.scalars(
        select(EncryptedSecret).where(EncryptedSecret.repository_id == repository_id)
    ).all()
    return {
        row.name: decrypt_value(
            row.ciphertext,
            f"repository:{repository_id}:{row.name}",
        )
        for row in rows
    }


def delete_repository_secrets(db: Session, repository_id: str) -> None:
    db.execute(delete(EncryptedSecret).where(EncryptedSecret.repository_id == repository_id))


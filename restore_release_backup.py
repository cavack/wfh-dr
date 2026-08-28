#!/usr/bin/env python3
"""Standalone restore verifier for WaterfallHunter encrypted DR release assets."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sqlite3
import zlib
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BUFFER_BYTES = 4 * 1024 * 1024


class RestoreError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(BUFFER_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()

def load_key() -> bytes:
    raw = os.environ.get("WFH_DR_AES256_KEY_B64", "")
    try:
        key = base64.b64decode(raw, validate=True)
    except ValueError as error:
        raise RestoreError("RESTORE_KEY_INVALID") from error
    if len(key) != 32:
        raise RestoreError("RESTORE_KEY_INVALID")
    return key


def load_manifest(path: Path) -> dict:
    if path.is_symlink() or not path.is_file():
        raise RestoreError("MANIFEST_INVALID")
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RestoreError("MANIFEST_INVALID") from error
    if (
        not isinstance(manifest, dict)
        or manifest.get("contract_version") != "wfh_encrypted_backup_bundle_v1"
        or manifest.get("algorithm") != "AES-256-GCM"
        or manifest.get("compression") != "zlib"
        or not isinstance(manifest.get("chunks"), list)
        or not manifest["chunks"]
    ):
        raise RestoreError("MANIFEST_INVALID")
    return manifest

def restore(manifest_path: Path, bundle_dir: Path, output: Path, key: bytes) -> None:
    manifest = load_manifest(manifest_path)
    if output.exists() or output.is_symlink():
        raise RestoreError("OUTPUT_EXISTS")
    try:
        nonce = base64.b64decode(manifest["nonce_b64"], validate=True)
        tag = base64.b64decode(manifest["tag_b64"], validate=True)
    except (KeyError, ValueError) as error:
        raise RestoreError("CRYPTO_METADATA_INVALID") from error
    if len(nonce) != 12 or len(tag) != 16:
        raise RestoreError("CRYPTO_METADATA_INVALID")

    decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
    decompressor = zlib.decompressobj()
    plaintext_hash = hashlib.sha256()
    ciphertext_hash = hashlib.sha256()
    plaintext_size = 0
    partial = output.with_name(f".{output.name}.partial")
    fd = os.open(partial, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(fd, "wb") as target:
            for expected_index, item in enumerate(manifest["chunks"]):
                if not isinstance(item, dict) or item.get("index") != expected_index:
                    raise RestoreError("CHUNK_ORDER_INVALID")
                name = item.get("name")
                if not isinstance(name, str) or Path(name).name != name:
                    raise RestoreError("CHUNK_NAME_INVALID")
                path = bundle_dir / name
                if path.is_symlink() or not path.is_file():
                    raise RestoreError("CHUNK_MISSING")
                if (
                    path.stat().st_size != item.get("size_bytes")
                    or sha256_file(path) != item.get("sha256")
                ):
                    raise RestoreError("CHUNK_DIGEST_MISMATCH")
                with path.open("rb") as source:
                    for block in iter(lambda: source.read(BUFFER_BYTES), b""):
                        ciphertext_hash.update(block)
                        decrypted = decryptor.update(block)
                        if decrypted:
                            plain = decompressor.decompress(decrypted)
                            if plain:
                                target.write(plain)
                                plaintext_hash.update(plain)
                                plaintext_size += len(plain)
            try:
                final = decryptor.finalize()
            except InvalidTag as error:
                raise RestoreError("AUTHENTICATION_FAILED") from error
            if final:
                plain = decompressor.decompress(final)
                if plain:
                    target.write(plain)
                    plaintext_hash.update(plain)
                    plaintext_size += len(plain)
            tail = decompressor.flush()
            if tail:
                target.write(tail)
                plaintext_hash.update(tail)
                plaintext_size += len(tail)
            target.flush()
            os.fsync(target.fileno())

        if ciphertext_hash.hexdigest() != manifest.get("ciphertext_sha256"):
            raise RestoreError("CIPHERTEXT_DIGEST_MISMATCH")
        if plaintext_hash.hexdigest() != manifest.get("plaintext_sha256"):
            raise RestoreError("PLAINTEXT_DIGEST_MISMATCH")
        if plaintext_size != manifest.get("plaintext_size_bytes"):
            raise RestoreError("PLAINTEXT_SIZE_MISMATCH")
        os.link(partial, output)
        partial.unlink()
    except BaseException:
        partial.unlink(missing_ok=True)
        raise


def audit_database(path: Path) -> dict:
    with sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True) as connection:
        integrity = [row[0] for row in connection.execute("PRAGMA integrity_check")]
        foreign_keys = connection.execute("PRAGMA foreign_key_check").fetchall()
        user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
    if integrity != ["ok"]:
        raise RestoreError("SQLITE_INTEGRITY_FAILED")
    if foreign_keys:
        raise RestoreError("SQLITE_FOREIGN_KEY_FAILED")
    return {
        "status": "RESTORE_VERIFIED",
        "file_sha256": sha256_file(path),
        "file_size_bytes": path.stat().st_size,
        "integrity_check": "ok",
        "foreign_key_violation_count": 0,
        "user_version": user_version,
    }

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--bundle-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        restore(
            args.manifest.resolve(),
            args.bundle_dir.resolve(),
            args.output.resolve(),
            load_key(),
        )
        report = audit_database(args.output.resolve())
    except (RestoreError, OSError, sqlite3.Error) as error:
        print(json.dumps({"ok": False, "reason": str(error)}, sort_keys=True))
        return 2
    print(json.dumps({"ok": True, **report}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

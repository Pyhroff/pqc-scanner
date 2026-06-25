"""
Uses only quantum-safe cryptographic primitives.
pqc-scan MUST produce ZERO quantum-broken and ZERO classically-broken findings here.

Why this is safe:
  AES-256  — Grover's algorithm halves the security level (256 → 128 bits), still acceptable.
  SHA-256  — Grover's provides only a quadratic speedup; 256-bit → 128-bit effective, still secure.
  SHA-3-256 — same reasoning as SHA-256.
  HMAC-SHA-256 — symmetric MAC, Grover-safe at 256-bit key.
"""
import hashlib
import hmac
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def encrypt_aes256(plaintext: bytes) -> tuple[bytes, bytes, bytes]:
    key = os.urandom(32)   # 256-bit key — quantum-safe
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    enc = cipher.encryptor()
    ciphertext = enc.update(plaintext) + enc.finalize()
    return key, iv, ciphertext


def hash_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_sha3_256(data: bytes) -> str:
    return hashlib.sha3_256(data).hexdigest()


def mac_sha256(key: bytes, message: bytes) -> bytes:
    return hmac.new(key, message, hashlib.sha256).digest()

#!/usr/bin/env python3
"""
Chiffrement hybride RSA-OAEP (4096 bits) + AES-256-GCM
─────────────────────────────────────────────────────────
Flux :
  Chiffrement  → génère clé AES aléatoire → chiffre données (AES-GCM)
                → chiffre clé AES avec RSA public → sauvegarde bundle JSON
  Déchiffrement → déchiffre clé AES avec RSA privé → déchiffre données (AES-GCM)

Format du bundle chiffré (JSON) :
{
  "version":       "1.0",
  "algorithm":     "RSA-OAEP-SHA256+AES-256-GCM",
  "encrypted_key": "<base64>",   ← clé AES chiffrée par RSA
  "nonce":         "<base64>",   ← nonce GCM 96 bits
  "ciphertext":    "<base64>"    ← données + tag GCM
}
"""

import os
import json
import base64
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend


# ── Génération de clés ─────────────────────────────────────────────────────

def generate_key_pair(bits: int = 4096):
    """Génère une paire RSA. bits=4096 recommandé pour usage long terme."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits,
        backend=default_backend()
    )
    return private_key, private_key.public_key()


def save_private_key(private_key, path: Path, password: str | None = None):
    """
    Sauvegarde la clé privée en PEM.
    Si password fourni : chiffrée AES-256-CBC (conseillé fortement).
    """
    enc_algo = (
        serialization.BestAvailableEncryption(password.encode())
        if password else serialization.NoEncryption()
    )
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc_algo
    )
    Path(path).write_bytes(pem)
    os.chmod(path, 0o600)  # lecture uniquement par le propriétaire


def save_public_key(public_key, path: Path):
    """Sauvegarde la clé publique en PEM."""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    Path(path).write_bytes(pem)


# ── Chargement de clés ─────────────────────────────────────────────────────

def load_public_key(path: Path):
    return serialization.load_pem_public_key(
        Path(path).read_bytes(),
        backend=default_backend()
    )


def load_private_key(path: Path, password: str | None = None):
    pw = password.encode() if password else None
    return serialization.load_pem_private_key(
        Path(path).read_bytes(),
        password=pw,
        backend=default_backend()
    )


# ── Chiffrement ────────────────────────────────────────────────────────────

def encrypt_data(plaintext: str, public_key) -> dict:
    """
    Chiffre une chaîne UTF-8 avec chiffrement hybride.
    Retourne un dict JSON-sérialisable.
    """
    # 1. Clé AES-256 + nonce GCM aléatoires
    aes_key = AESGCM.generate_key(bit_length=256)
    nonce   = os.urandom(12)  # 96 bits standard GCM

    # 2. Chiffrement AES-256-GCM (inclut le tag d'authentification)
    aesgcm     = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)

    # 3. Chiffrement RSA-OAEP-SHA256 de la clé AES
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return {
        "version":       "1.0",
        "algorithm":     "RSA-OAEP-SHA256+AES-256-GCM",
        "encrypted_key": base64.b64encode(encrypted_key).decode("ascii"),
        "nonce":         base64.b64encode(nonce).decode("ascii"),
        "ciphertext":    base64.b64encode(ciphertext).decode("ascii"),
    }


# ── Déchiffrement ──────────────────────────────────────────────────────────

def decrypt_data(bundle: dict, private_key) -> str:
    """
    Déchiffre un bundle produit par encrypt_data().
    Retourne le JSON original en clair.
    """
    encrypted_key = base64.b64decode(bundle["encrypted_key"])
    nonce         = base64.b64decode(bundle["nonce"])
    ciphertext    = base64.b64decode(bundle["ciphertext"])

    # 1. Déchiffrement RSA → récupère la clé AES
    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # 2. Déchiffrement AES-GCM (vérifie aussi l'authenticité)
    aesgcm    = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    return plaintext.decode("utf-8")


def decrypt_file(enc_path: Path, private_key) -> dict:
    """Déchiffre un fichier .enc et retourne le dict Python."""
    bundle = json.loads(Path(enc_path).read_text(encoding="utf-8"))
    return json.loads(decrypt_data(bundle, private_key))

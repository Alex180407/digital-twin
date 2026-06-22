#!/usr/bin/env python3
"""
decrypt.py — Outil de déchiffrement OFFLINE pour Digital Twin ZK v3
═══════════════════════════════════════════════════════════════════════
Architecture Zero-Knowledge :
  - Le chiffrement est fait dans le navigateur (Web Crypto API)
  - Le serveur n'a jamais vu les données en clair
  - Ce script est le SEUL moyen de déchiffrer (nécessite la clé privée)

Format bundle v3 (client-side) :
{
  "version": "3.0",
  "algorithm": "client-RSA-OAEP-SHA256+AES-256-GCM",
  "saved_at": "...",
  "entry_type": "...",
  "encrypted_data": "<base64>",      ← AES-256-GCM(JSON)
  "iv": "<base64>",                  ← IV 96 bits
  "encrypted_aes_key": "<base64>"    ← RSA-OAEP(clé AES)
}

Usage :
  # Déchiffrer un fichier et l'afficher
  python3 decrypt.py --key private.pem --file data/reasoning/rsn_20250115_001.enc

  # Déchiffrer tout un dossier
  python3 decrypt.py --key private.pem --dir data/ --output ./clair/

  # Export complet structuré
  python3 decrypt.py --key private.pem --dir data/ --all --output ./export/

  # Mode interactif (ls + cat)
  python3 decrypt.py --key private.pem --interactive
"""

import argparse
import base64
import getpass
import json
import sys
from pathlib import Path
from datetime import datetime

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend


# ── Chargement de la clé privée ────────────────────────────────────────────

def load_key(path: str, password: str | None = None):
    p = Path(path)
    if not p.exists():
        print(f"❌ Clé privée introuvable : {p}")
        sys.exit(1)
    if password is None:
        password = getpass.getpass(f"  Mot de passe pour {p.name} : ")
    try:
        return serialization.load_pem_private_key(
            p.read_bytes(),
            password=password.encode() if password else None,
            backend=default_backend()
        )
    except Exception as e:
        print(f"❌ Erreur chargement clé : {e}")
        sys.exit(1)


# ── Déchiffrement d'un bundle ──────────────────────────────────────────────

def decrypt_bundle(bundle: dict, private_key) -> dict:
    """
    Déchiffre un bundle v3 (client-side ZK) ou v1 (ancien server-side).
    Retourne le dict Python original.
    """
    version = bundle.get("version", "1.0")

    if version in ("3.0", "2.0") and "encrypted_data" in bundle:
        # Format v3/v2 : chiffrement client (Web Crypto API)
        enc_aes_key = base64.b64decode(bundle["encrypted_aes_key"])
        iv          = base64.b64decode(bundle["iv"])
        enc_data    = base64.b64decode(bundle["encrypted_data"])

        # 1. Déchiffrement RSA-OAEP → clé AES brute
        aes_key = private_key.decrypt(
            enc_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        # 2. Déchiffrement AES-256-GCM (vérifie aussi l'authenticité)
        aesgcm    = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(iv, enc_data, None)
        return json.loads(plaintext.decode("utf-8"))

    elif "encrypted_key" in bundle and "nonce" in bundle:
        # Format v1 (ancien server-side, compatibilité)
        enc_key    = base64.b64decode(bundle["encrypted_key"])
        nonce      = base64.b64decode(bundle["nonce"])
        ciphertext = base64.b64decode(bundle["ciphertext"])

        aes_key = private_key.decrypt(
            enc_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        aesgcm    = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return json.loads(plaintext.decode("utf-8"))

    else:
        raise ValueError(f"Format de bundle inconnu (version={version})")


def decrypt_file(path: Path, private_key) -> dict | None:
    try:
        bundle = json.loads(path.read_text(encoding="utf-8"))
        return decrypt_bundle(bundle, private_key)
    except Exception as e:
        print(f"  ⚠  {path.name} : {e}")
        return None


# ── Export ─────────────────────────────────────────────────────────────────

def decrypt_dir(data_dir: Path, private_key, output_dir: Path, verbose=True) -> dict:
    files  = sorted(data_dir.rglob("*.enc"))
    ok = fail = 0
    results = {}

    for f in files:
        rel  = f.relative_to(data_dir)
        data = decrypt_file(f, private_key)
        if data is not None:
            out = output_dir / rel.with_suffix(".json")
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
            results[str(rel)] = data
            ok += 1
            if verbose: print(f"  ✅ {rel}")
        else:
            fail += 1

    print(f"\n  Déchiffrés : {ok} | Échecs : {fail}")
    return results


def export_all(data_dir: Path, private_key, output_dir: Path):
    print("\nExport complet Zero-Knowledge...\n")
    cats = {
        "daily": data_dir/"daily", "events": data_dir/"events",
        "reasoning": data_dir/"reasoning", "beliefs": data_dir/"beliefs",
        "knowledge": data_dir/"knowledge", "projects": data_dir/"projects",
        "relationships": data_dir/"relationships", "predictions": data_dir/"predictions",
        "snapshots": data_dir/"snapshots",
    }
    master = {}
    for cat, p in cats.items():
        if not p.exists(): continue
        print(f"  [{cat}]")
        master[cat] = decrypt_dir(p, private_key, output_dir/cat, verbose=True)

    out = output_dir/"full_export.json"
    out.write_text(json.dumps(master, ensure_ascii=False, indent=2), encoding="utf-8")
    total = sum(len(v) for v in master.values())
    print(f"\n  📦 Export → {out}")
    print(f"  Total : {total} entrées déchiffrées")


# ── Exporter au format JSONL pour fine-tuning ──────────────────────────────

def export_reasoning_jsonl(data_dir: Path, private_key, output_dir: Path):
    """
    Exporte les raisonnements complétés en JSONL pour fine-tuning IA.
    Seuls les raisonnements avec suivi.resultat_effectif sont inclus.
    """
    files  = sorted((data_dir/"reasoning").rglob("rsn_*.enc"))
    output = []
    for f in files:
        data = decrypt_file(f, private_key)
        if not data: continue
        suivi = data.get("suivi") or {}
        if not suivi.get("resultat_effectif"): continue
        entry = {
            "id": data.get("reasoning_id",""),
            "date": data.get("date",""),
            "domaine": data.get("domaine",""),
            "input": {
                "probleme":  data.get("probleme",""),
                "objectif":  data.get("objectif",""),
                "contexte":  data.get("contexte",""),
                "contraintes": data.get("contraintes",[]),
                "options":   [
                    {"id": o.get("id",""), "desc": o.get("description",""),
                     "avantages": o.get("avantages",[]),
                     "inconvenients": o.get("inconvenients",[])}
                    for o in (data.get("options") or [])
                ]
            },
            "output": {
                "option_choisie": data.get("option_choisie",""),
                "justification":  data.get("justification",""),
                "confiance":      data.get("confiance_avant",0),
                "heuristiques":   data.get("heuristiques_appliquees",[]),
            },
            "resultat_reel": {
                "resultat":   suivi.get("resultat_effectif",""),
                "qualite":    suivi.get("qualite_du_raisonnement",0),
                "lecon":      suivi.get("lecon",""),
            }
        }
        output.append(entry)

    if not output:
        print("  Aucun raisonnement complété trouvé (suivi.resultat_effectif vide).")
        return

    out = output_dir / f"fine_tuning_reasoning_{datetime.now().strftime('%Y%m%d')}.jsonl"
    output_dir.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        for item in output:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")
    print(f"  ✅ {len(output)} raisonnements → {out}")


# ── Brier Score (calibration prédictions) ─────────────────────────────────

def calibration_stats(data_dir: Path, private_key):
    files = sorted((data_dir/"predictions").rglob("*.enc"))
    preds = []
    for f in files:
        d = decrypt_file(f, private_key)
        if not d or not d.get("resolu"): continue
        p_est  = float(d.get("probabilite", 0))
        result = d.get("resultat","")
        p_real = 1.0 if result=="vrai" else (0.0 if result=="faux" else None)
        if p_real is None: continue
        preds.append({"p_est": p_est, "p_real": p_real,
                      "brier": (p_est-p_real)**2,
                      "enonce": d.get("enonce","")[:60]})

    if not preds:
        print("  Aucune prédiction résolue trouvée.")
        return

    avg = sum(p["brier"] for p in preds)/len(preds)
    print(f"\n  Prédictions analysées : {len(preds)}")
    print(f"  Brier Score moyen     : {avg:.4f}")
    print(f"  Interprétation        : {'Excellent (<0.10)' if avg<.10 else 'Bon (<0.15)' if avg<.15 else 'Acceptable (<0.20)' if avg<.20 else 'À améliorer'}")
    print(f"\n  Détail :")
    for p in sorted(preds, key=lambda x: x["brier"], reverse=True)[:10]:
        print(f"    {p['brier']:.3f}  p={p['p_est']:.2f}→{p['p_real']:.0f}  {p['enonce']}")


# ── Mode interactif ────────────────────────────────────────────────────────

def interactive(private_key):
    print("\n╔════════════════════════════════════════════╗")
    print("║  Digital Twin ZK — Mode interactif         ║")
    print("╚════════════════════════════════════════════╝")
    print("  Commandes : ls [dossier] | cat <fichier.enc> | exit\n")
    data_dir = Path(input("  Dossier data : ").strip() or "./data")

    while True:
        try: cmd = input("\n  > ").strip()
        except (EOFError, KeyboardInterrupt): print("\n  Bye."); break
        if cmd in ("exit","quit","q"): break

        elif cmd.startswith("ls"):
            parts = cmd.split(maxsplit=1)
            d = Path(parts[1]) if len(parts)>1 else data_dir
            if d.exists():
                for f in sorted(d.iterdir()):
                    icon = "📁" if f.is_dir() else "🔒"
                    size = f"  ({f.stat().st_size//1024}KB)" if f.is_file() else ""
                    print(f"    {icon} {f.name}{size}")
            else: print(f"  Dossier introuvable : {d}")

        elif cmd.startswith("cat"):
            parts = cmd.split(maxsplit=1)
            if len(parts)<2: print("  Usage : cat <fichier.enc>"); continue
            p = Path(parts[1])
            if not p.exists(): p = data_dir/parts[1]
            data = decrypt_file(p, private_key)
            if data: print(json.dumps(data, ensure_ascii=False, indent=2))

        else: print("  Commandes : ls [dossier] | cat <fichier.enc> | exit")


# ── Main ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Déchiffrement offline Digital Twin ZK"
    )
    parser.add_argument("--key",         required=True, help="Chemin vers private.pem")
    parser.add_argument("--password",    default=None,  help="Mot de passe (sinon prompt)")
    parser.add_argument("--file",        default=None,  help="Fichier .enc à déchiffrer")
    parser.add_argument("--dir",         default=None,  help="Dossier source")
    parser.add_argument("--output",      default="./decrypted", help="Dossier de sortie")
    parser.add_argument("--all",         action="store_true", help="Export structuré complet")
    parser.add_argument("--reasoning",   action="store_true", help="Export JSONL fine-tuning")
    parser.add_argument("--calibration", action="store_true", help="Stats Brier Score")
    parser.add_argument("--interactive", action="store_true", help="Mode interactif")
    parser.add_argument("--print",       action="store_true", help="Affiche en console")
    args = parser.parse_args()

    private_key = load_key(args.key, args.password)
    output_dir  = Path(args.output)

    print(f"\n  ✅ Clé privée chargée — architecture Zero-Knowledge\n")

    if args.interactive:
        interactive(private_key)

    elif args.file:
        data = decrypt_file(Path(args.file), private_key)
        if data:
            output_dir.mkdir(parents=True, exist_ok=True)
            out = output_dir / Path(args.file).with_suffix(".json").name
            out.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
            print(f"  ✅ → {out}")
            if args.print: print(json.dumps(data, ensure_ascii=False, indent=2))

    elif args.dir:
        d = Path(args.dir)
        if args.calibration:
            calibration_stats(d, private_key)
        elif args.reasoning:
            export_reasoning_jsonl(d, private_key, output_dir)
        elif args.all:
            export_all(d, private_key, output_dir)
        else:
            decrypt_dir(d, private_key, output_dir)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()


# ══════════════════════════════════════════════════════════════════════════════
# DÉCHIFFREMENT v4.1 — RSA-4096 + ECDH-P384 + AES-256-GCM × 2
# ══════════════════════════════════════════════════════════════════════════════

def load_ec_key(path: str, password: str | None = None):
    """Charge la clé privée ECDH-P384."""
    p = Path(path)
    if not p.exists():
        return None
    try:
        return serialization.load_pem_private_key(
            p.read_bytes(),
            password=password.encode() if password else None,
            backend=default_backend()
        )
    except Exception as e:
        print(f"  ⚠ Clé EC non chargée : {e}")
        return None


def decrypt_ecdh_key(enc_key_data: dict, ec_private_key) -> bytes:
    """Déchiffre une clé AES wrappée par ECDH éphémère + HKDF + AES-GCM."""
    from cryptography.hazmat.primitives.asymmetric.ec import (
        ECDH, SECP384R1, EllipticCurvePublicNumbers
    )
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    # Clé publique éphémère (format raw = 04 || X[48] || Y[48])
    raw = base64.b64decode(enc_key_data["eph_pub"])
    x = int.from_bytes(raw[1:49],  "big")
    y = int.from_bytes(raw[49:97], "big")
    eph_pub = EllipticCurvePublicNumbers(x, y, SECP384R1()).public_key(default_backend())

    # Secret partagé ECDH
    shared = ec_private_key.exchange(ECDH(), eph_pub)

    # HKDF → clé de wrapping AES-256
    hkdf = HKDF(
        algorithm=hashes.SHA384(), length=32,
        salt=b"\x00" * 48,
        info=b"dt-ecdh-wrap-v1",
        backend=default_backend()
    )
    wrap_key = hkdf.derive(shared)

    # AES-GCM dé-wrapping
    wiv     = base64.b64decode(enc_key_data["iv"])
    wrapped = base64.b64decode(enc_key_data["ct"])
    return AESGCM(wrap_key).decrypt(wiv, wrapped, None)


def decrypt_v41(bundle: dict, rsa_key, ec_key=None) -> dict:
    """
    Déchiffre un bundle v4.1 (double AES + hybride RSA+ECDH).
    Compatible avec v4.1 même si la clé EC est absente
    (fallback sur RSA seul).
    """
    def get_aes_key(rsa_field: str, ec_field: str) -> bytes:
        if rsa_key and bundle.get(rsa_field):
            return rsa_key.decrypt(
                base64.b64decode(bundle[rsa_field]),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(), label=None
                )
            )
        if ec_key and bundle.get(ec_field):
            return decrypt_ecdh_key(bundle[ec_field], ec_key)
        raise ValueError(f"Impossible de déchiffrer {rsa_field} — clé privée absente")

    raw1 = get_aes_key("k1_rsa", "k1_ec")
    raw2 = get_aes_key("k2_rsa", "k2_ec")

    # Décryptage couche externe (AES key 2)
    iv2 = base64.b64decode(bundle["iv2"])
    ct  = base64.b64decode(bundle["ct"])
    ct1 = AESGCM(raw2).decrypt(iv2, ct, None)

    # Décryptage couche interne (AES key 1)
    iv1 = base64.b64decode(bundle["iv1"])
    return json.loads(AESGCM(raw1).decrypt(iv1, ct1, None).decode("utf-8"))


# Patcher decrypt_bundle pour gérer v4.1
_orig_decrypt_bundle = decrypt_bundle

def decrypt_bundle(bundle: dict, private_key, private_ec_key=None) -> dict:
    version = bundle.get("version", "3.0")
    if version == "4.1":
        return decrypt_v41(bundle, private_key, private_ec_key)
    return _orig_decrypt_bundle(bundle, private_key)

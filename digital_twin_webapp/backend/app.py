#!/usr/bin/env python3
"""
Digital Twin — Backend Zero-Knowledge v4
Architecture Event-Sourcing (Append-Only Log)
- Le serveur est aveugle (ZK : ne voit jamais les données en clair)
- Chaque bundle = un événement immuable
- _id et _target_id sont NON chiffrés pour permettre la réconciliation offline
"""

from fastapi import FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import json, os, logging
from datetime import datetime
from pathlib import Path

DATA_DIR        = Path(os.environ.get("DATA_DIR",        "./data"))
PUBLIC_KEY_PATH = Path(os.environ.get("PUBLIC_KEY_PATH", "./keys/public.pem"))
PORT            = int(os.environ.get("PORT", 8000))

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

app = FastAPI(title="Digital Twin ZK v4", version="4.0", docs_url=None, redoc_url=None)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

def _seq(directory: Path, prefix: str) -> int:
    directory.mkdir(parents=True, exist_ok=True)
    return len(list(directory.glob(f"{prefix}*.enc"))) + 1

def _filepath(entry_type: str, hint: dict) -> Path:
    """
    Chemin de stockage basé sur le type et les hints organisationnels.
    Le contenu est dans le blob chiffré — ce fichier est purement indexable.
    """
    now     = datetime.now()
    Y, M, D = now.strftime("%Y"), now.strftime("%m"), now.strftime("%d")
    compact = now.strftime("%Y%m%d")
    stamp   = now.strftime("%Y%m%d_%H%M%S")

    # Nettoyage des hints (caractères dangereux)
    def safe(s, maxlen=40):
        import re
        return re.sub(r'[^a-zA-Z0-9_\-]', '_', str(s or ''))[:maxlen]

    match entry_type:
        # ── Standalone (un par période) ──────────────────────────────────
        case "daily":
            return DATA_DIR / "daily" / Y / M / f"{D}.enc"
        case "weekly_review":
            week = now.strftime("%Y-W%V")
            return DATA_DIR / "weekly" / f"{week}.enc"
        case "monthly_snapshot":
            m = safe(hint.get("mois") or now.strftime("%Y-%m"), 7)
            return DATA_DIR / "snapshots" / f"{m}.enc"

        # ── Événements standalone (séquentiels) ──────────────────────────
        case "event":
            n = _seq(DATA_DIR / "events" / Y, f"evt_{compact}_")
            return DATA_DIR / "events" / Y / f"evt_{compact}_{n:03d}.enc"

        # ── GENESIS — Création d'entités ──────────────────────────────────
        case "project":
            eid = safe(hint.get("_id") or f"proj_{compact}")
            return DATA_DIR / "projects" / eid / f"__genesis_{stamp}.enc"
        case "person":
            eid = safe(hint.get("_id") or f"p_unknown_{compact}")
            return DATA_DIR / "persons" / eid / f"__genesis_{stamp}.enc"
        case "reasoning":
            eid = safe(hint.get("_id") or f"rsn_{compact}")
            return DATA_DIR / "reasoning" / f"{eid}__genesis_{stamp}.enc"
        case "prediction":
            eid = safe(hint.get("_id") or f"pred_{compact}")
            return DATA_DIR / "predictions" / f"{eid}__genesis_{stamp}.enc"
        case "knowledge_node":
            eid = safe(hint.get("_id") or "kn_UNKNOWN")
            return DATA_DIR / "knowledge" / f"{eid}__genesis_{stamp}.enc"
        case "belief":
            eid = safe(hint.get("_id") or f"belief_{compact}")
            return DATA_DIR / "beliefs" / f"{eid}__genesis_{stamp}.enc"

        # ── DELTA — Enrichissement d'entités ─────────────────────────────
        case "project_log" | "project_update":
            tid = safe(hint.get("_target_id") or "unknown")
            return DATA_DIR / "projects" / tid / f"delta_{stamp}.enc"
        case "relationship_update":
            tid = safe(hint.get("_target_id") or "unknown")
            return DATA_DIR / "persons" / tid / f"delta_{stamp}.enc"
        case "reasoning_followup":
            tid = safe(hint.get("_target_id") or "unknown")
            return DATA_DIR / "reasoning" / f"{tid}__delta_{stamp}.enc"
        case "prediction_resolution":
            tid = safe(hint.get("_target_id") or "unknown")
            return DATA_DIR / "predictions" / f"{tid}__delta_{stamp}.enc"
        case "knowledge_update":
            tid = safe(hint.get("_target_id") or "unknown")
            return DATA_DIR / "knowledge" / f"{tid}__delta_{stamp}.enc"
        case "belief_update":
            tid = safe(hint.get("_target_id") or f"belief_{compact}")
            return DATA_DIR / "beliefs" / f"{tid}__delta_{stamp}.enc"

        case _:
            return DATA_DIR / "misc" / f"{entry_type}_{stamp}.enc"

VALID = {
    "daily", "weekly_review", "monthly_snapshot", "event",
    "project", "person", "reasoning", "prediction", "knowledge_node", "belief",
    "project_log", "project_update", "relationship_update",
    "reasoning_followup", "prediction_resolution", "knowledge_update", "belief_update",
}

# ── Routes ─────────────────────────────────────────────────────────────────

@app.get("/api/health")
def health():
    return {
        "status": "ok", "version": "4.0",
        "architecture": "zero-knowledge + event-sourcing",
        "key_ready": PUBLIC_KEY_PATH.exists(),
        "time": datetime.now().isoformat()
    }

@app.get("/api/pubkey")
def pubkey():
    if not PUBLIC_KEY_PATH.exists():
        raise HTTPException(503, "Clé publique absente — lance generate_keys.sh")
    return {"pem": PUBLIC_KEY_PATH.read_text(encoding="utf-8")}



@app.get("/api/pubkeys")
def pubkeys():
    """
    Sert les deux clés publiques (RSA + ECDH) au navigateur.
    Le chiffrement hybride RSA-4096 + ECDH-P384 + AES-256-GCM×2
    se fait entièrement dans le navigateur (Zero-Knowledge).
    """
    if not PUBLIC_KEY_PATH.exists():
        raise HTTPException(503, "Clé RSA absente — lance generate_keys.sh")
    result = {"rsa_pem": PUBLIC_KEY_PATH.read_text(encoding="utf-8")}
    ec_path = PUBLIC_KEY_PATH.parent / "public_ec.pem"
    if ec_path.exists():
        result["ec_pem"] = ec_path.read_text(encoding="utf-8")
    return result

@app.get("/api/meta/stats")
def stats():
    def c(p):
        return len(list((DATA_DIR/p).rglob("*.enc"))) if (DATA_DIR/p).exists() else 0
    def d(p):
        return len([x for x in (DATA_DIR/p).iterdir()
                    if x.is_dir()]) if (DATA_DIR/p).exists() else 0
    return {
        "daily":          c("daily"),
        "events":         c("events"),
        "reasoning":      c("reasoning"),
        "beliefs":        c("beliefs"),
        "knowledge":      c("knowledge"),
        "predictions":    c("predictions"),
        "projects":       d("projects"),
        "persons":        d("persons"),
        "snapshots":      c("snapshots"),
        "weekly":         c("weekly"),
    }

@app.get("/api/meta/event_log")
def event_log(limit: int = 50):
    """
    Retourne le journal des événements (métadonnées non chiffrées uniquement).
    Utile pour visualiser l'activité sans déchiffrer.
    """
    bundles = []
    for f in sorted(DATA_DIR.rglob("*.enc"), key=lambda x: x.stat().st_mtime, reverse=True)[:limit]:
        try:
            b = json.loads(f.read_text(encoding="utf-8"))
            bundles.append({
                "file":        str(f.relative_to(DATA_DIR)),
                "entry_type":  b.get("entry_type"),
                "event_class": b.get("event_class"),
                "_id":         b.get("_id"),
                "_target_id":  b.get("_target_id"),
                "saved_at":    b.get("saved_at"),
            })
        except Exception:
            pass
    return {"events": bundles, "total": len(bundles)}

@app.post("/api/save/{entry_type}")
async def save(entry_type: str, request: Request):
    """
    Reçoit un blob déjà chiffré par le navigateur.
    Le serveur ne peut pas lire le contenu — il classe et stocke aveuglément.
    """
    if entry_type not in VALID:
        raise HTTPException(400, f"Type inconnu : {entry_type}")
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(400, "JSON invalide")

    if not {"encrypted_data", "iv", "encrypted_aes_key"}.issubset(payload):
        raise HTTPException(400, "Payload non chiffré côté client")

    hint        = payload.get("_hint") or {}
    entity_id   = hint.get("_id")    or None
    target_id   = hint.get("_target_id") or None
    event_class = "delta" if target_id else "genesis"

    bundle = {
        "version":     "4.0",
        "algorithm":   "client-RSA-OAEP-SHA256+AES-256-GCM",
        "saved_at":    datetime.now().isoformat(),
        "entry_type":  entry_type,
        "event_class": event_class,
        "_id":         entity_id,   # NON chiffré — pour réconciliation offline
        "_target_id":  target_id,   # NON chiffré — clé étrangère vers l'entité parente
        # Blob illisible pour le serveur :
        "encrypted_data":    payload["encrypted_data"],
        "iv":                payload["iv"],
        "encrypted_aes_key": payload["encrypted_aes_key"],
    }

    fp = _filepath(entry_type, hint)
    fp.parent.mkdir(parents=True, exist_ok=True)
    fp.write_text(json.dumps(bundle, ensure_ascii=False, indent=2), encoding="utf-8")

    log.info(f"{'DELTA' if target_id else 'GENESIS'} {entry_type} {entity_id or ''} -> {fp.relative_to(DATA_DIR)}")
    return {"success": True, "file": str(fp.relative_to(DATA_DIR)), "_id": entity_id}

app.mount("/", StaticFiles(directory="./static", html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=PORT)


@app.get("/api/meta/registry")
def registry():
    """
    Phase 4 — Nexus de synchronisation cross-device.
    Scanne les noms de fichiers et métadonnées NON chiffrées.
    Retourne les IDs par catégorie. Zéro contenu sensible exposé.
    """
    reg = {
        "projects":    [],
        "persons":     [],
        "concepts":    [],
        "reasonings":  [],
        "predictions": [],
        "beliefs":     [],
    }

    # Dossiers → ID = nom du sous-dossier
    for cat, folder in [("projects","projects"), ("persons","persons")]:
        d = DATA_DIR / folder
        if d.exists():
            for item in sorted(d.iterdir()):
                if item.is_dir() and not item.name.startswith('.'):
                    if item.name not in reg[cat]:
                        reg[cat].append(item.name)

    # Fichiers genesis → ID stocké en clair dans le bundle
    for cat, folder in [
        ("reasonings","reasoning"), ("predictions","predictions"),
        ("beliefs","beliefs"),      ("concepts","knowledge"),
    ]:
        d = DATA_DIR / folder
        if not d.exists():
            continue
        for enc_file in sorted(d.rglob("*genesis*.enc")):
            try:
                bundle = json.loads(enc_file.read_text(encoding="utf-8"))
                eid = bundle.get("_id")
                if eid and eid not in reg[cat]:
                    reg[cat].append(eid)
            except Exception:
                pass

    total = sum(len(v) for v in reg.values())
    return {"registry": reg, "total": total, "timestamp": datetime.now().isoformat()}

# 🧬 Digital Twin — Zero-Knowledge Cognitive Journal

> **⚠️ Déclaration de co-ingénierie (IA / Humain)**
> Le code source, l'architecture cryptographique et cette documentation ont été co-conçus avec l'assistance d'une intelligence artificielle. L'ensemble du système a été rigoureusement audité au niveau des sockets réseaux, testé en environnement de production (Proxmox/LXC), et validé par un opérateur humain pour garantir une étanchéité absolue des données et l'absence de failles logiques.

**Digital Twin** n'est pas un simple journal. C'est une machine à états (State Machine) qui modélise la cognition, les raisonnements et les croyances via une architecture **Event Sourcing**. Conçu avec une approche **Zero-Knowledge (ZK)** stricte, le serveur agit comme un coffre-fort aveugle. Les données sont chiffrées de bout en bout dans la RAM du navigateur et ne peuvent être déchiffrées qu'hors-ligne, sur une ligne d'univers de confiance.

---

## 🏗 Philosophie & Architecture Data (Event Sourcing)

Le paradigme de base repose sur l'immuabilité. Le serveur ne met jamais à jour une base de données relationnelle : il se contente d'empiler des événements chiffrés (*Append-Only Log*).

Chaque donnée ingérée appartient à l'une de ces deux classes :
* **S0 (Genesis) :** La création d'une entité racine. Exemple : La déclaration d'une nouvelle croyance (`belief`), d'un projet, ou d'une prédiction. Cela génère un `_id` unique (ex: `kn_ZFS` pour un concept technique).
* **Δ (Delta) :** La modification d'un état. Exemple : Le suivi d'un raisonnement (`reasoning_followup`) ou l'évolution d'une relation. Le Delta référence l'entité mère via un `_target_id`. 

Le calcul de l'état final se fait **à la lecture (offline)** en rejouant chronologiquement les Deltas par-dessus le Genesis.

---

## 🔐 Matrice Cryptographique (v4.1)

Le système utilise un chiffrement asymétrique hybride multicouche exécuté nativement via la *Web Crypto API* du navigateur.

**Algorithmes engagés :** `RSA-4096` + `ECDH-P384` + `AES-256-GCM ×2`

### Flux Zero-Knowledge Détaillé

```text
[ NAVIGATEUR (Client) ]                                       [ SERVEUR (Blind LXC) ]
                                                              
1. INIT       ──(GET /api/pubkeys)─────────────────────────►  Renvoie RSA & EC PubKeys
2. SESSION    Génération de 2 clés AES-256 jetables
3. PAYLOAD    Chiffrement JSON → AES-GCM(Clé 1) → AES-GCM(Clé 2)
4. WRAPPING   Clé 1 chiffrée via RSA-OAEP-SHA256
              Clé 2 wrappée via ECDH éphémère (P-384) + HKDF
5. COMMIT     Transmission du Bundle ZK ──(POST HTTP)──────►  Contrôle des métadonnées
                                                              Écriture du fichier `.enc`
```

### Le modèle de menace

L'architecture isole l'information vitale des couches de transport et d'hébergement.

| Vecteur d'attaque | Donnée exposée | Mitigation structurelle |
| :--- | :--- | :--- |
| **Interception Réseau (MITM)** | Endpoint, Horodatage | Payload illisible (AES-256). L'isolation via Tailscale empêche l'accès au port. |
| **Compromission Root LXC** | ID concept, Type d'event | Les fichiers `.enc` sont verrouillés. Impossible de forger de nouvelles clés privées. |
| **Vol Physique du Serveur** | Base complète (chiffrée) | Utilité nulle sans le `private.pem` stocké sur support hors-ligne (Air-Gapped). |

---

## 🚀 Déploiement Infrastructure (Proxmox & Réseau)

### 1. Préparation du Container (LXC)
Créez un container sous **Ubuntu 22.04** ou **Debian 12** :
* **Ressources :** 1-2 vCPU, 512 MB RAM, 10 GB Disk.
* **Privilèges :** Désactivez "Unprivileged container" si des montages spécifiques (ZFS/NFS) sont prévus.

### 2. Installation du Core Backend
Connectez-vous en `root` sur le LXC :

```bash
apt-get update && apt-get install -y git

# Clonage du répertoire
git clone [https://github.com/ton-repo/digital-twin](https://github.com/ton-repo/digital-twin) /opt/digital-twin
cd /opt/digital-twin

# Exécution du script d'automatisation (Python 3.11, Venv, systemd)
bash scripts/setup_lxc.sh
```

### 3. Génération de la Paire Asymétrique
Le système nécessite des clés pour verrouiller la matrice :

```bash
sudo -u digitaltwin bash /opt/digital-twin/scripts/generate_keys.sh
```

🚨 **Isolation (Air-Gap) :**
La clé privée générée (`keys/private.pem` et `keys/private_ec.pem`) ne doit **jamais** rester sur le nœud d'exécution.
1. Exfiltrez les clés privées vers un support physique (Clé USB, Bitwarden local).
2. Détruisez les originaux sur le serveur : `shred -u /opt/digital-twin/keys/private*.pem`
3. Seule la clé publique (`public.pem`) doit survivre sur l'hôte.

### 4. Routage Réseau & Reverse Proxy (Caddy)
Par défaut, Uvicorn écoute sur `0.0.0.0:8000`. Si votre Reverse Proxy (Caddy/Nginx) se trouve sur une VM/LXC distincte dans le même VLAN :

**Configuration Caddyfile (Exemple avec Tailscale/Cloudflare) :**
```caddyfile
journal.ton-domaine.com {
    tls {
        dns cloudflare {env.CLOUDFLARE_API_TOKEN}
    }
    reverse_proxy 192.168.1.50:8000  # Remplacer par l'IP du LXC Digital Twin
    
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
    }
}
```
*Si Caddy et le backend tournent dans le même environnement local, modifiez `/etc/systemd/system/digital-twin.service` pour binder sur `--host 127.0.0.1`.*

---

## 🧠 Cycle de Vie & Utilisation

Accédez à l'IHM via votre navigateur.

### Formulaires Principaux
* **⭐ Daily State :** Instantané des métriques physiologiques (Sommeil, Énergie) et cognitives (Humeur, Focus). À exécuter quotidiennement.
* **🧩 Raisonnement (Decision Log) :** Formalisation d'une problématique, des options et des heuristiques avant de trancher. (Évite les biais rétrospectifs).
* **🎯 Prédiction :** Établir une probabilité sur un événement futur. S'évalue a posteriori (Brier Score).
* **📚 Connaissance :** Modélisation d'un concept (ex: `kn_LINUX_KERNEL`).

*Raccourci UI : Utilisez `Ctrl+K` pour ouvrir la palette de commandes et naviguer instantanément entre les interfaces d'ingestion.*

---

## 🔓 Rétro-Ingénierie & Extraction (Offline)

Le serveur ne propose **aucune** route de lecture. L'analyse des données (le "Reading Steiner") se fait sur votre machine locale de confiance, en déchiffrant les blobs bruts.

### Installation de la suite de déchiffrement
```bash
pip install cryptography
```

### Rapatriement de la DB
```bash
scp -r root@192.168.1.50:/opt/digital-twin/data ~/dt_data_backup/
```

### Exploitation via CLI
Le script `decrypt.py` gère la traduction ZK -> Clair.

```bash
# 1. Lire une divergence spécifique
python3 scripts/decrypt.py --key ~/private.pem --file ~/dt_data/reasoning/rsn_xxx.enc --print

# 2. Reconstruire la réalité absolue (Export complet)
python3 scripts/decrypt.py --key ~/private.pem --dir ~/dt_data/ --all --output ~/dt_clair/

# 3. Mode IA Fine-Tuning (Exporte les raisonnements en format JSONL)
python3 scripts/decrypt.py --key ~/private.pem --dir ~/dt_data/ --reasoning --output ~/exports/

# 4. Calibration (Calcule la précision mathématique de tes prédictions)
python3 scripts/decrypt.py --key ~/private.pem --dir ~/dt_data/ --calibration

# 5. Mode shell interactif
python3 scripts/decrypt.py --key ~/private.pem --interactive
```

---

## ⚙️ Administration Avancée

**Surveillance du démon**
```bash
systemctl status digital-twin
journalctl -u digital-twin -f
```

**Métadonnées (API Non chiffrée)**
Permet de visualiser le volume d'events sans compromettre le contenu :
```bash
curl -s [http://127.0.0.1:8000/api/meta/stats](http://127.0.0.1:8000/api/meta/stats) | python3 -m json.tool
curl -s [http://127.0.0.1:8000/api/meta/event_log](http://127.0.0.1:8000/api/meta/event_log)
```

---

## 🛡 Disaster Recovery Plan (DRP)

**Scénario 1 : Compromission de la clé privée**
Si votre coffre-fort offline est percé, le chiffrement asymétrique est vaincu.
1. Coupez le backend : `systemctl stop digital-twin`
2. Déchiffrez toute la base actuelle sur une machine saine.
3. Regénérez une nouvelle paire asymétrique via `generate_keys.sh`.
4. (Note : L'historique chiffré avec l'ancienne clé publique ne sera mathématiquement plus lisible avec la nouvelle. Les archives doivent être gérées offline).

**Scénario 2 : Crash matériel du Proxmox**
La base de données n'est constituée que de fichiers plats (`.enc`). Une simple tâche Cron copiant `/opt/digital-twin/data` vers un bucket S3, un NAS ZFS ou un cloud public suffit. Les données étant intrinsèquement chiffrées, la destination du backup n'a pas besoin d'être "Zero Trust".
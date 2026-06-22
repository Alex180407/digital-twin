#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
#  setup_lxc.sh — Installation de Digital Twin sur Ubuntu 22.04 LXC
#
#  À exécuter EN ROOT dans le container LXC :
#    bash setup_lxc.sh
#
#  Ce script :
#   1. Met à jour le système
#   2. Installe Python 3.11 + pip
#   3. Installe les dépendances Python
#   4. Configure le service systemd
#   5. Configure le pare-feu (ufw)
#   6. Lance le service
# ═══════════════════════════════════════════════════════════════════════════

set -euo pipefail
BOLD="\033[1m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
RED="\033[0;31m"
NC="\033[0m"

APP_DIR="/opt/digital-twin"
APP_USER="digitaltwin"
PORT=8000

log()   { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[✗]${NC} $*"; exit 1; }
title() { echo -e "\n${BOLD}$*${NC}"; }

# ── Vérifications ──────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && error "Lance ce script en root (sudo bash setup_lxc.sh)"

title "╔══════════════════════════════════════════════════════════╗"
echo  "║           DIGITAL TWIN — Installation LXC                ║"
echo  "╚══════════════════════════════════════════════════════════╝"
echo ""

# ── 1. Mise à jour système ─────────────────────────────────────────────────
title "1. Mise à jour du système"
apt-get update -qq
apt-get upgrade -y -qq
log "Système à jour"

# ── 2. Dépendances système ─────────────────────────────────────────────────
title "2. Installation de Python 3.11 et outils"
apt-get install -y -qq \
    python3.11 python3.11-venv python3-pip \
    git curl wget ufw \
    software-properties-common
log "Python 3.11 installé"

# ── 3. Utilisateur dédié ──────────────────────────────────────────────────
title "3. Création de l'utilisateur système"
if ! id "$APP_USER" &>/dev/null; then
    useradd -r -s /bin/bash -d "$APP_DIR" "$APP_USER"
    log "Utilisateur $APP_USER créé"
else
    warn "Utilisateur $APP_USER déjà existant"
fi

# ── 4. Dossiers ───────────────────────────────────────────────────────────
title "4. Création de la structure des dossiers"
mkdir -p "$APP_DIR"/{backend,static,scripts,keys,data,systemd}
mkdir -p "$APP_DIR"/data/{
    daily/states,
    daily/weekly_reviews,
    events,
    reasoning,
    beliefs/updates,
    knowledge/nodes,
    projects,
    relationships/{persons,updates},
    predictions/{active,resolved},
    snapshots,
    simulation/context_snapshots,
    misc
}

chown -R "$APP_USER:$APP_USER" "$APP_DIR"
chmod 750 "$APP_DIR"
chmod 700 "$APP_DIR/keys"
chmod 700 "$APP_DIR/data"
log "Dossiers créés dans $APP_DIR"

# ── 5. Copie des fichiers de l'app ─────────────────────────────────────────
title "5. Copie des fichiers de l'application"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_ROOT="$(dirname "$SCRIPT_DIR")"

cp "$APP_ROOT/backend/"*.py "$APP_DIR/backend/"
cp "$APP_ROOT/backend/requirements.txt" "$APP_DIR/backend/"
cp -r "$APP_ROOT/static/"* "$APP_DIR/static/"
cp "$APP_ROOT/scripts/"*.sh "$APP_DIR/scripts/"
cp "$APP_ROOT/scripts/"*.py "$APP_DIR/scripts/"
chmod +x "$APP_DIR/scripts/"*.sh

log "Fichiers copiés"

# ── 6. Environnement virtuel Python ───────────────────────────────────────
title "6. Installation des dépendances Python"
python3.11 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install --upgrade pip -q
"$APP_DIR/venv/bin/pip" install -r "$APP_DIR/backend/requirements.txt" -q
chown -R "$APP_USER:$APP_USER" "$APP_DIR/venv"
log "Dépendances installées"

# ── 7. Service systemd ────────────────────────────────────────────────────
title "7. Configuration du service systemd"
cat > /etc/systemd/system/digital-twin.service <<EOF
[Unit]
Description=Digital Twin — Serveur API
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=$APP_USER
Group=$APP_USER
WorkingDirectory=$APP_DIR/backend
ExecStart=$APP_DIR/venv/bin/python3 -m uvicorn app:app \\
    --host 0.0.0.0 \\
    --port $PORT \\
    --log-level info \\
    --access-log
Restart=on-failure
RestartSec=5

# Variables d'environnement
Environment="DATA_DIR=$APP_DIR/data"
Environment="PUBLIC_KEY_PATH=$APP_DIR/keys/public.pem"
Environment="PORT=$PORT"

# Sécurité
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=$APP_DIR/data $APP_DIR/keys

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable digital-twin.service
log "Service systemd configuré"

# ── 8. Pare-feu ───────────────────────────────────────────────────────────
title "8. Configuration du pare-feu (ufw)"
ufw --force reset >/dev/null 2>&1
ufw default deny incoming >/dev/null 2>&1
ufw default allow outgoing >/dev/null 2>&1
ufw allow ssh >/dev/null 2>&1
ufw allow "$PORT/tcp" >/dev/null 2>&1
ufw --force enable >/dev/null 2>&1
log "Pare-feu configuré (ports 22 et $PORT ouverts)"

# ── 9. Génération des clés ────────────────────────────────────────────────
title "9. Génération des clés RSA"
echo ""
warn "Tu vas maintenant générer les clés RSA-4096."
warn "IMPORTANT : après génération, copie private.pem hors du serveur !"
echo ""
read -p "  Générer les clés maintenant ? [O/n] : " GENKEYS
GENKEYS=${GENKEYS:-O}

if [[ "$GENKEYS" =~ ^[Oo]$ ]]; then
    sudo -u "$APP_USER" bash "$APP_DIR/scripts/generate_keys.sh"
else
    warn "Génération des clés ignorée. Lance manuellement :"
    warn "  sudo -u $APP_USER bash $APP_DIR/scripts/generate_keys.sh"
fi

# ── 10. Démarrage ─────────────────────────────────────────────────────────
title "10. Démarrage du service"
if [[ -f "$APP_DIR/keys/public.pem" ]]; then
    systemctl start digital-twin.service
    sleep 2
    if systemctl is-active --quiet digital-twin.service; then
        log "Service démarré avec succès !"
    else
        error "Le service n'a pas démarré. Vérifie : journalctl -u digital-twin -n 50"
    fi
else
    warn "Clé publique absente — service non démarré."
    warn "Génère d'abord les clés puis : systemctl start digital-twin"
fi

# ── Récapitulatif ─────────────────────────────────────────────────────────
IP=$(hostname -I | awk '{print $1}')
echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║  ✅ Installation terminée !                              ║"
echo "╠══════════════════════════════════════════════════════════╣"
echo "║                                                          ║"
echo "║  Interface web : http://$IP:$PORT                        ║"
echo "║  API health    : http://$IP:$PORT/api/health             ║"
echo "║  Données       : $APP_DIR/data/                          ║"
echo "║  Logs          : journalctl -u digital-twin -f           ║"
echo "║                                                          ║"
echo "║  Commandes utiles :                                      ║"
echo "║    systemctl status digital-twin                         ║"
echo "║    systemctl restart digital-twin                        ║"
echo "║    journalctl -u digital-twin -n 100                     ║"
echo "║                                                          ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
warn "⚠  Si tu as généré les clés, PENSE À COPIER private.pem OFFLINE !"
echo ""

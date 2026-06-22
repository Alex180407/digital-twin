#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
#  generate_keys.sh — Génère la paire de clés RSA-4096 pour Digital Twin
#
#  Usage : bash generate_keys.sh [--bits 4096]
#  Produit :
#    keys/public.pem    → à laisser sur le serveur
#    keys/private.pem   → À GARDER HORS LIGNE (clé USB, coffre, Bitwarden…)
# ═══════════════════════════════════════════════════════════════════════════

set -euo pipefail

BITS=${1:-4096}
KEYS_DIR="$(dirname "$0")/../keys"
PRIVATE_KEY="$KEYS_DIR/private.pem"
PUBLIC_KEY="$KEYS_DIR/public.pem"

mkdir -p "$KEYS_DIR"
chmod 700 "$KEYS_DIR"

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║         DIGITAL TWIN — Génération des clés RSA           ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "⚠  La clé privée va être générée ici TEMPORAIREMENT."
echo "   Tu DOIS la copier sur un support hors-ligne et la supprimer du serveur."
echo ""

# Mot de passe pour protéger la clé privée
echo -n "   Mot de passe pour protéger la clé privée : "
read -s PASSPHRASE
echo ""
echo -n "   Confirmer le mot de passe : "
read -s PASSPHRASE2
echo ""

if [ "$PASSPHRASE" != "$PASSPHRASE2" ]; then
  echo "❌ Les mots de passe ne correspondent pas. Abandon."
  exit 1
fi

if [ ${#PASSPHRASE} -lt 12 ]; then
  echo "❌ Mot de passe trop court (minimum 12 caractères). Abandon."
  exit 1
fi

echo ""
echo "   Génération RSA-$BITS en cours (peut prendre 10-30 secondes)..."

# Génération via Python (utilise la même lib que l'app)
python3 - <<EOF
import sys
sys.path.insert(0, '$(realpath "$(dirname "$0")/../backend")')
from crypto_utils import generate_key_pair, save_private_key, save_public_key
from pathlib import Path

private_key, public_key = generate_key_pair(bits=$BITS)

save_private_key(private_key, Path('$PRIVATE_KEY'), password='$PASSPHRASE')
save_public_key(public_key,   Path('$PUBLIC_KEY'))
print("   Clés générées avec succès.")
EOF

chmod 600 "$PRIVATE_KEY"
chmod 644 "$PUBLIC_KEY"

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║  ✅ Clés générées                                        ║"
echo "╠══════════════════════════════════════════════════════════╣"
echo "║                                                          ║"
echo "║  Clé publique  : keys/public.pem                        ║"
echo "║  Clé privée    : keys/private.pem  ← COPIER ET EFFACER  ║"
echo "║                                                          ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "  ⚠  ÉTAPES OBLIGATOIRES :"
echo ""
echo "  1. Copie keys/private.pem sur une clé USB sécurisée :"
echo "       cp keys/private.pem /media/usb_cle/dt_private_$(date +%Y%m%d).pem"
echo ""
echo "  2. Supprime la clé privée du serveur :"
echo "       shred -u keys/private.pem"
echo ""
echo "  3. Vérifie que seule keys/public.pem reste sur le serveur."
echo ""
echo "  La clé publique est la seule chose nécessaire pour que l'app fonctionne."
echo "  La clé privée n'est nécessaire QUE pour déchiffrer (offline)."
echo ""

echo ""
echo "=== Génération de la paire ECDH-P384 (couche hybride) ==="
openssl genpkey -algorithm EC \
    -pkeyopt ec_paramgen_curve:P-384 \
    -aes-256-cbc \
    -pass pass:"$PASSPHRASE" \
    -out "$KEYS_DIR/private_ec.pem" 2>/dev/null

openssl pkey \
    -in "$KEYS_DIR/private_ec.pem" \
    -passin pass:"$PASSPHRASE" \
    -pubout \
    -out "$KEYS_DIR/public_ec.pem" 2>/dev/null

if [ -f "$KEYS_DIR/public_ec.pem" ]; then
    echo "  ✓ Paire ECDH-P384 générée"
    echo "    private_ec.pem (à copier sur votre machine + supprimer du serveur)"
    echo "    public_ec.pem  (reste sur le serveur)"
else
    echo "  ⚠ ECDH-P384 non disponible — chiffrement RSA seul actif"
fi

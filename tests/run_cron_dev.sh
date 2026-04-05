#!/bin/bash
# Script pour simuler le cron WCS en environnement Linux (WSL, Serveur, etc.)
# S'exécute en boucle toutes les 60 secondes.

WCS_MANAGE=~/envs/publik-env-py3/bin/wcs-manage
DOMAIN=wcs.dev.publik.love

while true; do
    clear
    echo "======================================================================"
    echo "[ $(date '+%Y-%m-%d %H:%M:%S') ] Lancement du cron WCS pour $DOMAIN"
    echo "======================================================================"
    echo ""

    if [ -f "$WCS_MANAGE" ]; then
        "$WCS_MANAGE" cron -d $DOMAIN
    else
        echo "[ERREUR] Le script wcs-manage est introuvable à l'emplacement suivant :"
        echo "$WCS_MANAGE"
        echo ""
        echo "Veuillez vérifier le chemin de votre environnement virtuel."
        exit 1
    fi

    echo ""
    echo "======================================================================"
    echo "Prochain lancement dans 60 secondes... (Ctrl+C pour arrêter)"
    echo "======================================================================"
    sleep 60
done

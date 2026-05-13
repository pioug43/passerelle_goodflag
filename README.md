# passerelle-goodflag

Connecteur [Passerelle](https://doc-publik.entrouvert.com/dev/developpement-d-un-connecteur/) pour la signature électronique [Goodflag](https://sgs-demo-test01.sunnystamp.com/wm-docs/api.html).

Permet à Publik (W.C.S.) de piloter un circuit de signature : création de workflow, upload de documents, démarrage, suivi du statut, récupération des documents signés.

## Installation

```bash
# Dans le virtualenv Publik
pip install -e .

# Déclarer l'app dans les settings Passerelle
cat > /etc/passerelle/settings.d/goodflag.py <<'EOF'
INSTALLED_APPS += ('passerelle_goodflag',)
TENANT_APPS += ('passerelle_goodflag',)
EOF

# Migrations + redémarrage
passerelle-manage migrate_schemas
systemctl restart passerelle
```

## Configuration

Dans l'admin Passerelle → **Signature électronique** → **Ajouter un connecteur Goodflag** :

| Champ | Obligatoire | Description |
|-------|:-----------:|-------------|
| `base_url` | oui | URL de base API Goodflag (ex: `https://signature.example.com/api`) |
| `access_token` | oui | Bearer token (format: `act_xxx.yyy`) |
| `user_id` | oui | Utilisateur propriétaire des workflows (format: `usr_xxx`) |
| `default_consent_page_id` | recommandé | Page de consentement par défaut (format: `cop_xxx`) |
| `default_signature_profile_id` | recommandé | Profil de signature par défaut (format: `sip_xxx`) |
| `default_layout_id` | | Layout pour les métadonnées (format: `lay_xxx`) |
| `webhook_secret` | | Token de validation passé en query string par Goodflag (`?token=...`) |
| `timeout` | | Timeout HTTP en secondes (défaut: 30) |
| `verify_ssl` | | Vérification SSL (défaut: activé) |

Dans l'onglet **Sécurité** : ajouter le rôle de service W.C.S. en `can_access`. Le webhook (`/webhook`) est en permission `open`.

## Endpoints

URLs : `{passerelle_url}passerelle-goodflag/{slug}/{endpoint}`

| Endpoint | Méthode | Description |
|----------|---------|-------------|
| `create-workflow` | POST | Crée un workflow (statut `draft`), sans document |
| `submit-workflow` | POST | Crée + uploade + démarre en un seul appel |
| `upload-document` | POST | Upload un document (PDF/DOCX/Images) |
| `start-workflow` | POST | Démarre le workflow (envoie les invitations) |
| `stop-workflow` | POST | Arrête un workflow en cours |
| `get-workflow` | GET | Détail complet d'un workflow |
| `sync-status` | GET | Statut normalisé (draft/started/finished/refused/error) |
| `create-invite` | POST | URL d'invitation pour un destinataire |
| `download-signed-documents` | GET | Documents signés (PDF ou ZIP, streaming) |
| `download-evidence` | GET | Certificat de preuve |
| `retrieve-by-external-ref` | GET | Recherche workflows par référence Publik (via API Goodflag) |
| `webhook` | POST | Notifications Goodflag (permission `open`) |

La plupart des endpoints acceptent `external_ref` à la place de `workflow_id` : la résolution est faite via l'API de recherche Goodflag (`data1`-`data16` ou nom du workflow).

## Formats de destinataires (create-workflow / submit-workflow)

Trois formats supportés, mutuellement exclusifs avec `steps` (format natif Goodflag) :

**Signataire unique (form-encoded W.C.S.) :**

```
name=Signature {{ form_number }}
recipient_email={{ form_var_email_signataire }}
recipient_firstname={{ form_var_prenom_signataire }}
recipient_lastname={{ form_var_nom_signataire }}
recipient_phone={{ form_var_telephone_portable }}
```

**Multi-signataires indexé :**

```
recipients_0_email=alice@example.com
recipients_0_firstname=Alice
recipients_1_email=bob@example.com
recipients_1_firstname=Bob
```

**JSON `recipients` ou `steps`** : pour les cas multi-étapes (approbation + signature). Voir l'API Goodflag pour le format `steps`.

## Mapping des statuts

| Statut Goodflag | Statut normalisé | `is_final` | Action W.C.S. |
|-----------------|------------------|:----------:|---------------|
| `draft` | `draft` | non | Attendre |
| `started` | `started` | non | Attendre |
| `finished` | `finished` | oui | Télécharger le document signé |
| `stopped` | `refused` | oui | Notifier le demandeur |
| autre | `error` | oui | Alerter l'administrateur |

## Webhook

Configurer Goodflag pour envoyer un webhook vers :

```
https://passerelle.example.com/passerelle-goodflag/{slug}/webhook?token=<webhook_secret>
```

Sécurité : Goodflag ne signe pas ses webhooks (pas de HMAC). Le connecteur valide soit par le token URL (si `webhook_secret` configuré), soit par re-validation auprès de l'API `webhookEvents` Goodflag.

## Métadonnées

Goodflag accepte uniquement les champs `data1` à `data16`. Toute autre clé dans `metadata` provoque une erreur de validation. Prérequis : configurer le mapping côté tenant Goodflag et renseigner `default_layout_id`.

## Upload de documents

Sources supportées pour `upload-document` et `submit-workflow` :

1. **JSON imbriqué** `file = {"filename": ..., "content_type": ..., "content": "<base64>"}`
2. **Multipart Django** champ `file`
3. **Base64 direct** champ `file_base64` + `filename`
4. **URL Publik** champ `file_url` — HTTPS uniquement, récupéré via la session signée Passerelle (`self.requests`), avec protection SSRF (rejet des IP privées/loopback).

Types MIME acceptés : `application/pdf`, DOCX, JPEG, PNG, WebP. Taille max : 50 Mo.

## Tests

```bash
pip install pytest pytest-django responses
pytest tests/ -v
```

## Structure

```
passerelle_goodflag/
├── exceptions.py    # GoodflagError, GoodflagAuthError, GoodflagValidationError
├── client.py        # Client HTTP isolé (testable sans Django)
├── models.py        # GoodflagResource + endpoints Passerelle
└── migrations/
tests/
├── conftest.py
├── test_client.py
└── test_connector.py
```

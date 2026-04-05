# passerelle-goodflag

Connecteur [Passerelle](https://doc-publik.entrouvert.com/dev/developpement-d-un-connecteur/) pour la signature électronique [Goodflag](https://sgs-demo-test01.sunnystamp.com/wm-docs/api.html).

Permet à Publik (W.C.S.) de piloter un circuit de signature électronique : création de workflow, upload de documents, démarrage, suivi du statut et récupération des documents signés.

## Installation

### Environnement local (publik-devinst)

Prérequis : environnement [publik-devinst](https://dev.entrouvert.org/projects/publik-devinst/wiki/Installation_d%27un_environnement_de_d%C3%A9veloppement_local) installé et fonctionnel.

```bash
# Cloner le connecteur dans les sources Publik
cd ~/src
git clone <url-du-depot> passerelle_goodflag
cd passerelle_goodflag

# Installer dans le virtualenv Publik (mode développement)
~/envs/publik-env-py3/bin/pip install -e . --no-build-isolation

# Déclarer l'app dans les settings Passerelle
mkdir -p ~/.config/publik/settings/passerelle/settings.d
cat > ~/.config/publik/settings/passerelle/settings.d/goodflag.py << 'EOF'
INSTALLED_APPS += ('passerelle_goodflag',)
TENANT_APPS += ('passerelle_goodflag',)
EOF

# Redémarrer Passerelle
sudo supervisorctl restart django:passerelle

# Générer et appliquer les migrations
~/envs/publik-env-py3/bin/passerelle-manage makemigrations passerelle_goodflag
~/envs/publik-env-py3/bin/passerelle-manage migrate_schemas
```

> **Erreur `InvalidBasesError`** au `migrate_schemas` ? Supprimer les migrations existantes et les régénérer :
> ```bash
> rm passerelle_goodflag/migrations/0001_initial.py
> ~/envs/publik-env-py3/bin/passerelle-manage makemigrations passerelle_goodflag
> ~/envs/publik-env-py3/bin/passerelle-manage migrate_schemas
> ```

### Mise à jour du connecteur

```bash
cd ~/src/passerelle_goodflag
git pull
~/envs/publik-env-py3/bin/pip install -e . --no-build-isolation
~/envs/publik-env-py3/bin/passerelle-manage makemigrations passerelle_goodflag
~/envs/publik-env-py3/bin/passerelle-manage migrate_schemas
sudo supervisorctl restart django:passerelle
```

> Si seul le code Python a changé (sans modification de modèles), `makemigrations` retourne "No changes detected" — redémarrer Passerelle suffit.

### Production

```bash
pip install passerelle-goodflag
echo "INSTALLED_APPS += ('passerelle_goodflag',)" >> /etc/passerelle/settings.d/goodflag.py
echo "TENANT_APPS += ('passerelle_goodflag',)" >> /etc/passerelle/settings.d/goodflag.py
passerelle-manage makemigrations passerelle_goodflag
passerelle-manage migrate_schemas
systemctl restart passerelle
```

## Configuration

Dans l'admin Passerelle (`/manage/`) → **Signature électronique** → **Ajouter un connecteur Goodflag** :

| Champ | Obligatoire | Description |
|-------|:-----------:|-------------|
| `base_url` | oui | URL de base API Goodflag (ex: `https://signature.example.com/api`) |
| `access_token` | oui | Bearer token (format: `act_xxx.yyy`) |
| `user_id` | oui | Identifiant utilisateur propriétaire des workflows (format: `usr_xxx`) |
| `default_consent_page_id` | recommandé | Page de consentement par défaut (format: `cop_xxx`) |
| `default_signature_profile_id` | recommandé | Profil de signature par défaut (format: `sip_xxx`) |
| `default_layout_id` | | Layout pour les métadonnées (format: `lay_xxx`) |
| `webhook_secret` | | Token de validation URL webhook |
| `publik_callback_url` | | URL W.C.S. à notifier automatiquement sur événement webhook Goodflag |
| `tenant_id` | | Identifiant du tenant Goodflag (format: `ten_xxx`) |
| `timeout` | | Timeout HTTP en secondes (défaut: 30) |
| `verify_ssl` | | Vérification SSL (défaut: activé) |
| `debug_mode` | | Journalisation détaillée des appels API |
| `sandbox_mode` | | Indicateur environnement de test |
| `retention_days` | | Durée de conservation des traces en jours (défaut: 90) |
| `status_cache_ttl` | | Durée de cache du statut en secondes (défaut: 120, 0 = désactivé) |

### Permissions

Dans la page du connecteur → onglet **Sécurité** :
- Ajouter le rôle de service W.C.S. en `can_access`
- Le webhook (`/webhook`) est en permission `open` (pas de droits à ouvrir)

### Vérification

Après configuration, le connecteur est automatiquement surveillé par Passerelle (tâche `check_status` toutes les 5 minutes). Vous pouvez vérifier les logs pour confirmer le bon fonctionnement initial.

## Endpoints

Les URLs suivent le schéma : `{passerelle_url}passerelle-goodflag/{slug}/{endpoint}`

Exemple local : `https://passerelle.dev.publik.love/passerelle-goodflag/goodflag/create-workflow`

### Circuit de signature

| Endpoint | Méthode | Description |
|----------|---------|-------------|
| `create-workflow` | POST | Crée un workflow de signature (statut `draft`). Supporte 1 à N signataires. |
| `upload-document` | POST | Upload un document (PDF/DOCX/Images) — corps binaire brut, validation avancée |
| `upload-documents` | POST | Upload plusieurs documents en une seule requête (multipart) |
| `start-workflow` | POST | Démarre le workflow (envoie les invitations email) |
| `sync-status` | GET | Retourne le statut normalisé pour W.C.S. (avec cache configurable) |
| `download-signed-documents` | GET | Télécharge les documents signés (PDF ou ZIP) — streaming |
| `download-evidence` | GET | Télécharge le certificat de preuve — streaming, fallback `external_ref` |

### Gestion du workflow

| Endpoint | Méthode | Description |
|----------|---------|-------------|
| `get-workflow` | GET | Récupère le détail complet d'un workflow |
| `stop-workflow` | POST/GET | Arrête un workflow en cours (statut `stopped`) |
| `archive-workflow` | POST/GET | Archive un workflow terminé |
| `create-invite` | POST | Génère une URL d'invitation pour un destinataire |
| `resend-invite` | POST | Ré-envoie l'invitation par email à un signataire |
| `get-viewer-url` | POST/GET | Génère une URL de viewer pour un document |
| `retrieve-by-external-ref` | GET | Retrouve un workflow par référence Publik |
| `list-workflows` | GET | Liste et recherche les workflows (filtres statut, texte, pagination) |

### Supervision

| Endpoint | Méthode | Description |
|----------|---------|-------------|
| `webhook` | POST | Reçoit les notifications Goodflag (permission `open`) + callback Publik |

## Utilisation depuis W.C.S.

### Enchaînement standard

```
[Dépôt formulaire]
      ↓
[create-workflow]               ← POST name, recipient_email, recipient_firstname, recipient_lastname, external_ref
      ↓
[upload-document]               ← POST workflow_id, file_url, filename
      ↓
[start-workflow]                ← POST workflow_id
      ↓
[sync-status]                   ← GET  workflow_id   (polling toutes les 5 min)
      ↓ (status=finished)
[download-signed-documents]     ← GET  workflow_id
```

### Formats de requête

Le connecteur accepte deux formats de données :

- **JSON** (`Content-Type: application/json`) : pour les appels directs (curl, scripts)
- **Form-encoded** (`application/x-www-form-urlencoded`) : format natif des appels webservice W.C.S.

Pour `create-workflow`, le connecteur accepte **trois formats de destinataires** :

**Format signataire unique (form-encoded W.C.S.) :**

| Paramètre | Description |
|-----------|-------------|
| `name` | Nom du workflow (obligatoire) |
| `recipient_email` | Email du signataire |
| `recipient_firstname` | Prénom du signataire |
| `recipient_lastname` | Nom du signataire |
| `recipient_phone` | Téléphone du signataire (SMS 2FA) |
| `external_ref` | Référence externe Publik (ex: `{{ form_number }}`) |

**Format multi-signataires indexé (form-encoded W.C.S.) :**

```
recipients_0_email=alice@example.com
recipients_0_firstname=Alice
recipients_0_lastname=Martin
recipients_1_email=bob@example.com
recipients_1_firstname=Bob
recipients_1_lastname=Dupont
```

Les index commencent à 0 et sont consécutifs. Chaque signataire peut aussi avoir `recipients_N_phone`, `recipients_N_consent_page_id`, `recipients_N_signature_profile_id`.

**Format JSON avancé :**

En JSON, on peut aussi envoyer `recipients` (liste) ou `steps` (format natif Goodflag) pour les cas multi-signataires ou multi-étapes (approbation + signature).

### Envoi direct du document (Recommandé)

Si le serveur Passerelle ne peut pas accéder aux documents via une URL (pare-feu, authentification), vous pouvez envoyer le contenu du document directement dans la requête `upload-document`.

**Format JSON imbriqué (Publik) :**
```json
{
  "external_ref": "{{ form_number }}",
  "file": {
    "filename": "convention.pdf",
    "content_type": "application/pdf",
    "content": "JVBERi0xL...(base64)..."
  }
}
```

**Format Multipart (Standard) :**
Envoyer le fichier dans le champ `file` d'une requête `multipart/form-data`. Le `filename` sera extrait automatiquement du fichier si absent des paramètres.

### Fallback par `external_ref`

Les endpoints `upload-document`, `start-workflow`, `sync-status` et `download-signed-documents` acceptent `external_ref` (numéro de demande Publik) en remplacement de `workflow_id`. Si `workflow_id` est absent ou vide, le connecteur retrouve automatiquement le workflow depuis la trace locale via `external_ref`.

**Toujours passer `external_ref={{ form_number }}` en plus de `workflow_id`** dans les appels webservice W.C.S. pour garantir la robustesse (le fichier d'import XML fourni le fait déjà).

### Mapping des statuts

| Statut Goodflag | Statut normalisé | `is_final` | Action W.C.S. |
|-----------------|------------------|:----------:|---------------|
| `draft` | `draft` | non | Attendre |
| `started` | `started` | non | Attendre |
| `finished` + timestamp présent | `finished` | oui | Télécharger le document signé, continuer |
| `finished` sans timestamp | `started` | non | Attendre (guard anti-transition prématurée) |
| `stopped` | `refused` | oui | Notifier le demandeur |
| autre | `error` | oui | Alerter l'administrateur |

> **Guard anti-transition prématurée** : si l'API Goodflag retourne `workflowStatus: finished` mais sans timestamp `finished` (comportement observé en environnement de test), `sync-status` reclasse le statut en `started` et journalise un avertissement. Ceci évite que W.C.S. passe prématurément à l'étape "Récupération du document signé".

### Polling dans W.C.S.

W.C.S. exécute les éléments d'un statut immédiatement à l'entrée dans ce statut, puis reste bloqué jusqu'à un déclenchement externe. Pour le statut `attente-signature`, un mécanisme de relance est donc nécessaire.

**Option 1 — Cron Passerelle (recommandé)**

Configurer un déclencheur cron dans W.C.S. sur le statut `attente-signature` pour rappeler `sync-status` régulièrement :

```
Toutes les 5 minutes → rappeler le statut si la condition n'est pas satisfaite
```

En environnement local :
```bash
~/envs/publik-env-py3/bin/passerelle-manage tenant_command cron -d passerelle.dev.publik.love hourly
```

**Option 2 — Webhook Goodflag + callback WCS (recommandé)**

Configurer Goodflag pour envoyer un webhook sur `workflowFinished` et `workflowStopped`. Le connecteur reçoit la notification sur `/webhook`, met à jour la trace locale, puis notifie WCS via un callback automatique (POST sur le trigger URL du workflow WCS).

Pour activer le callback automatique, configurer le champ **`publik_callback_url`** sur le connecteur Passerelle avec l'URL du trigger WCS.

Le connecteur utilise `self.requests` (session Passerelle avec signature d'URL) pour que WCS accepte l'appel. Le callback est déclenché par le webhook Goodflag et par le polling `hourly()` quand il détecte un changement vers un état final.

**Pattern WCS recommandé (backoffice fields)**

Les réponses webservice WCS sont stockées dans des champs backoffice persistants via `set-backoffice-fields`, puis utilisées dans les conditions de saut via `form_var_` :

```
form_var_goodflag_status == "finished"
```

| Variable WCS | Source | Rôle |
|---|---|---|
| `form_var_goodflag_workflow_id` | `goodflag_create_response_data_workflow_id` | ID du workflow Goodflag |
| `form_var_goodflag_status` | `goodflag_status_response_data_status` | Statut normalisé (finished, refused...) |

> **Important** : les variables de réponse webservice WCS utilisent le préfixe `_response_` (ex: `goodflag_status_response_data_status`). Les stocker dans des champs backoffice (`form_var_`) garantit leur persistance entre les sauts de statut.

### Fichiers d'import W.C.S.

Le dossier `docs/` contient des fichiers XML importables directement dans Publik :

| Fichier | Contenu |
|---------|---------|
| `exemple_formulaire_signature.xml` | Formulaire : fichier PDF + email/nom/prénom signataire |
| `exemple_workflow_signature.xml` | Workflow : création, upload, démarrage, polling, récupération |

Procédure : voir [docs/guide_integration_publik.md](docs/guide_integration_publik.md) section 11.

## Webhook

### Configuration Goodflag

Créer un webhook pointant vers :
```
https://passerelle.example.com/passerelle-goodflag/{slug}/webhook?token=<secret>
```

Événements recommandés : `workflowFinished`, `workflowStopped`, `recipientFinished`, `recipientRefused`.

### Sécurité

Goodflag ne signe pas ses webhooks (pas de HMAC). Le connecteur compense par :

1. **Token secret** dans l'URL du webhook (`webhook_secret`)
2. **Re-validation** de chaque événement via `GET /api/webhookEvents/{id}`
3. **Anti-rejeu** par `event_id` unique en base de données

## Fonctionnalités Passerelle intégrées

### Suivi de disponibilité (`check_status`)

Passerelle appelle `check_status()` toutes les 5 minutes pour vérifier la
disponibilité de l'API Goodflag. Le résultat est visible dans le tableau
de bord du connecteur. Si l'API ne répond pas, le connecteur est marqué
comme indisponible.

### Synchronisation automatique (`hourly`)

La tâche planifiée `hourly()` synchronise automatiquement les statuts des
workflows actifs (`draft` ou `started`) sans nécessiter d'appel explicite
depuis W.C.S. Cela permet de détecter les changements de statut même si
le webhook ou le polling W.C.S. ne fonctionne pas.

### Purge automatique (`daily`)

Une tâche quotidienne purge les anciennes traces de workflows, événements
webhook et traces de documents de plus de 90 jours pour éviter
l'encombrement de la base de données.

> En environnement local, les tâches planifiées ne sont pas exécutées
> automatiquement. Pour les déclencher manuellement :
> ```bash
> ~/envs/publik-env-py3/bin/passerelle-manage tenant_command cron -d passerelle.dev.publik.love hourly
> ~/envs/publik-env-py3/bin/passerelle-manage tenant_command cron -d passerelle.dev.publik.love availability
> ```

### Journalisation

Le connecteur utilise la journalisation intégrée de Passerelle (visible dans
l'onglet **Journaux** du connecteur). Activer `debug_mode` pour une trace
détaillée de chaque appel API (contenu des requêtes et réponses).

## Métadonnées Goodflag

Les métadonnées Goodflag utilisent les champs `data1` à `data16`. Avant de
les utiliser :

1. Configurer le mapping au niveau du tenant (`PUT /api/tenants/{tenantId}/dataMapping`)
2. Créer un layout qui référence les métadonnées
3. Renseigner `default_layout_id` dans la configuration du connecteur

Exemple de mapping :

| Champ | Utilisation |
|-------|-------------|
| `data1` | Référence demande Publik (`{{ form_number }}`) |
| `data2` | Service émetteur |
| `data3` | Identifiant usager |

## Tests

```bash
source ~/envs/publik-env-py3/bin/activate
pip install pytest pytest-django responses
cd ~/src/passerelle_goodflag
pytest tests/ -v
pytest tests/ --cov=passerelle_goodflag --cov-report=term-missing
```

## Structure du projet

```
passerelle-goodflag/
├── setup.py                   # Installation + entry_points passerelle.connectors
├── MANIFEST.in
├── passerelle_goodflag/
│   ├── __init__.py
│   ├── exceptions.py          # GoodflagError, GoodflagAuthError, GoodflagValidationError, ...
│   ├── client.py              # Client HTTP isolé (testable sans Django)
│   ├── models.py              # GoodflagResource (endpoints) + modèles de persistance
│   └── migrations/            # Générées localement par makemigrations
├── tests/
│   ├── conftest.py            # Fixtures : connector, factory, mocks API
│   ├── test_client.py         # Tests unitaires du client HTTP
│   └── test_connector.py      # Tests d'intégration des endpoints Passerelle
└── docs/
    ├── guide_integration_publik.md      # Guide complet W.C.S. + exemples d'import
    ├── guide_developpeur.md             # Développement, extension, conventions
    ├── guide_exploitation.md            # Administration, supervision, troubleshooting
    ├── api_goodflag.md                  # Référence API Goodflag v1.19.4
    ├── integration_goodflag.md          # Guide d'intégration officiel Goodflag
    ├── dev_publik.md                    # Liens documentation officielle Publik/W.C.S.
    ├── exemple_formulaire_signature.xml # Formulaire W.C.S. importable
    └── exemple_workflow_signature.xml   # Workflow W.C.S. importable
```

### Architecture

| Module | Responsabilité |
|--------|---------------|
| `client.py` | Appels HTTP vers l'API Goodflag, authentification Bearer, gestion erreurs, **retry automatique** (3 tentatives sur erreurs 5xx), mapping statuts |
| `models.py` | Endpoints Passerelle (`@endpoint`), parsing des requêtes (JSON + form-encoded), persistance locale, webhook, `check_status`, `hourly` |
| `exceptions.py` | Hiérarchie d'exceptions métier (`GoodflagError` → `Auth`, `NotFound`, `Validation`, `Timeout`, `Upload`) |

### Modèles de persistance

| Modèle | Rôle |
|--------|------|
| `GoodflagWorkflowTrace` | Corrélation workflow Goodflag / demande Publik, suivi du statut |
| `GoodflagWebhookEvent` | Journal des webhooks reçus, idempotence par `event_id` |
| `GoodflagDocumentTrace` | Métadonnées des documents uploadés |

## Hypothèses API

Le connecteur a été développé sur la base de la documentation API Goodflag
Workflow Manager v1.19.4 :

| Endpoint API Goodflag | Méthode client |
|---|---|
| `GET /api/version` | `test_connection()` |
| `POST /api/users/{userId}/workflows` | `create_workflow()` |
| `POST /api/workflows/{id}/parts` (corps binaire brut) | `upload_document()` |
| `POST /api/workflows/{id}/parts` (multipart) | `upload_documents()` (multi-fichiers) |
| `PATCH /api/workflows/{id}` | `start_workflow()`, `stop_workflow()`, `archive_workflow()` |
| `GET /api/workflows/{id}` | `get_workflow()` |
| `POST /api/workflows/{id}/invite` | `create_invite()` |
| `GET /api/workflows/{id}/downloadDocuments` | `download_documents()` |
| `GET /api/workflows/{id}/downloadEvidenceCertificate` | `download_evidence_certificate()` |
| `GET /api/webhookEvents/{id}` | `get_webhook_event()` |
| `GET /api/workflows` | `search_workflows()` |

## Sécurité

- Le token API n'est jamais journalisé (masquage dans `_sanitize_for_log`)
- SSL activé par défaut (`verify_ssl=True`)
- Webhooks validés par token URL + re-validation API + anti-rejeu
- Upload limité à 50 Mo, types MIME contrôlés (PDF, DOCX, JPEG, PNG, WebP)
- Permissions Passerelle `can_access` sur tous les endpoints (sauf webhook : `open`)

## Prérequis

- Passerelle (fourni par publik-devinst ou paquet Debian)
- Python 3.8+
- Un compte Goodflag avec :
  - Access token API (format: `act_xxx.yyy`)
  - Identifiant utilisateur (format: `usr_xxx`)
  - Page de consentement (format: `cop_xxx`)
  - Profil de signature (format: `sip_xxx`)


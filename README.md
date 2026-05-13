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
| `timeout` | | Timeout HTTP en secondes (défaut: 30) |
| `verify_ssl` | | Vérification SSL (défaut: activé) |

Dans l'onglet **Sécurité** : ajouter le rôle de service W.C.S. en `can_access`.

## Endpoints

URLs : `{passerelle_url}passerelle-goodflag/{slug}/{endpoint}`

| Endpoint | Méthode | Description |
|----------|---------|-------------|
| `create-workflow` | POST | Crée un workflow (statut `draft`), sans document |
| `submit-workflow` | POST | Crée + uploade + démarre en un seul appel |
| `upload-document` | POST | Upload un document (PDF/DOCX/Images) |
| `start-workflow` | POST | Démarre le workflow (envoie les invitations) |
| `stop-workflow` | POST | Arrête un workflow en cours |
| `resend-invite` | POST | Renvoie une invitation email à un destinataire |
| `sync-status` | GET | Statut normalisé (draft/started/finished/refused/error) |
| `list-workflows` | GET | Liste/recherche les workflows (pagination + texte) |
| `get-workflow` | GET | Détail complet d'un workflow |
| `get-viewer-url` | GET, POST | URL de visualisation d'un document |
| `download-signed-documents` | GET | Documents signés (PDF ou ZIP, streaming) |

La plupart des endpoints acceptent `external_ref` à la place de `workflow_id` : la résolution est faite via l'API de recherche Goodflag (`data1`-`data16` ou nom du workflow).

### Référence par endpoint

Tous les endpoints renvoient `{"data": {…}}` en cas de succès (sauf `download-signed-documents` qui renvoie un flux binaire). Erreurs : HTTP 4xx/5xx avec `{"err": 1, "err_desc": "…"}`.

#### `POST create-workflow`

Crée un workflow vide en `draft`. Pas de document, pas d'envoi d'invitation.

| Param | Obligatoire | Description |
|---|:---:|---|
| `name` | oui | Nom du workflow (ex: `Signature {{ form_number }}`) |
| `recipient_email` / `_firstname` / `_lastname` / `_phone` | * | Signataire unique (form-encoded) |
| `recipients_N_email` / `_firstname` / `_lastname` / `_phone` | * | Multi-signataires indexés (N=0,1,2…) |
| `recipients` | * | JSON, alternative aux deux formats ci-dessus |
| `steps` | * | JSON natif Goodflag (multi-étapes), exclusif avec `recipients` |
| `metadata` | non | Dict `{"data1": …, …, "data16": …}` (cf. § Métadonnées) |
| `workflow_mode` | non | `FULL` (défaut) ou `LIGHT` |
| `layout_id` | non | Surcharge `default_layout_id` |

\* l'un des quatre formats de destinataires est requis.

Réponse :
```json
{"data": {"workflow_id": "wfl_xxx", "status": "draft"}}
```

#### `POST submit-workflow`

Pipeline complet en un appel : `create-workflow` + `upload-document` + `start-workflow`.

Mêmes params que `create-workflow` + ceux d'`upload-document` (`file`/`file_base64`/`file_url`/multipart).

Réponse :
```json
{"data": {"workflow_id": "wfl_xxx", "status": "started", "document_id": "doc_xxx"}}
```

#### `POST upload-document`

Upload un document dans un workflow `draft` existant.

| Param | Obligatoire | Description |
|---|:---:|---|
| `workflow_id` ou `external_ref` | oui | Cible du workflow |
| `file` (dict JSON) | * | `{"filename":…, "content_type":…, "content": "<base64>"}` |
| `file_base64` + `filename` | * | Base64 direct |
| `file_url` | * | URL HTTPS Publik, récupérée côté Passerelle (cf. § Upload) |
| `file` (multipart) | * | Upload multipart standard |
| `signature_profile_id` | non | Surcharge `default_signature_profile_id` |

\* une des quatre sources est requise.

Réponse : `{"data": {"workflow_id": "wfl_xxx", "document_id": "doc_xxx", "filename": "…", "documents": […], "parts": […]}}`

#### `POST start-workflow`

Bascule le workflow en `started` et envoie les invitations email.

| Param | Obligatoire | Description |
|---|:---:|---|
| `workflow_id` ou `external_ref` | oui | Cible du workflow |

Réponse : `{"data": {"workflow_id": "wfl_xxx", "status": "started"}}`

#### `POST stop-workflow`

Arrête un workflow en cours (passage à `stopped` côté Goodflag, qui sera vu comme `refused` côté Publik).

| Param | Obligatoire | Description |
|---|:---:|---|
| `workflow_id` ou `external_ref` | oui | Cible du workflow |

Réponse : `{"data": {"workflow_id": "wfl_xxx", "status": "stopped"}}`

#### `POST resend-invite`

Renvoie une invitation email à un destinataire (relance).

| Param | Obligatoire | Description |
|---|:---:|---|
| `workflow_id` ou `external_ref` | oui | Cible du workflow |
| `recipient_email` | oui | Email du destinataire à relancer |

Réponse : `{"data": {"invite_url": "https://…", "workflow_id": "wfl_xxx", "recipient_email": "…"}}`

#### `GET sync-status`

Statut normalisé pour polling W.C.S. (le format préféré pour les workflows de signature).

| Param | Obligatoire | Description |
|---|:---:|---|
| `workflow_id` ou `external_ref` | oui | Cible du workflow |

Réponse :
```json
{"data": {
  "workflow_id": "wfl_xxx",
  "raw_status": "started",
  "status": "started",
  "progress": 50,
  "is_final": false
}}
```

Cf. § Mapping des statuts.

#### `GET list-workflows`

Liste et recherche les workflows (utile pour supervision ou diagnostic).

| Param | Obligatoire | Description |
|---|:---:|---|
| `text` | non | Recherche texte (sur nom et métadonnées) |
| `page` | non | Index 0-based (défaut: 0) |
| `per_page` | non | Items par page (défaut: 50, max: 100) |

Réponse :
```json
{"data": {
  "total": 42, "page": 0, "per_page": 50,
  "items": [
    {"workflow_id": "wfl_xxx", "name": "…", "status": "started",
     "progress": 50, "created": "…", "updated": "…"}
  ]
}}
```

#### `GET get-workflow`

Détail complet d'un workflow (statut brut Goodflag + steps + métadonnées).

| Param | Obligatoire | Description |
|---|:---:|---|
| `workflow_id` ou `external_ref` | oui | Cible du workflow |

Réponse : `{"data": {"workflow_id": "wfl_xxx", "status": "started", "normalized_status": "started", "name": "…", "progress": 50, "steps": […], "raw": {…}}}`

#### `GET / POST get-viewer-url`

URL de visualisation d'un document (ouverture dans le navigateur, hors signature).

| Param | Obligatoire | Description |
|---|:---:|---|
| `document_id` | oui | ID Goodflag du document |
| `redirect_url` | non | URL de retour après fermeture |
| `expired` | non | Date d'expiration de l'URL (ISO 8601) |

Réponse : `{"data": {"viewer_url": "https://…", "expired": "…", "document_id": "doc_xxx"}}`

#### `GET download-signed-documents`

Télécharge les documents signés d'un workflow terminé. Retourne le flux binaire (PDF unique, ou ZIP si plusieurs documents) avec `Content-Disposition: attachment; filename="…"`.

| Param | Obligatoire | Description |
|---|:---:|---|
| `workflow_id` ou `external_ref` | oui | Cible du workflow (doit être `finished`) |

Réponse : flux binaire (pas de wrapper `data`). Côté W.C.S., utiliser un champ « Téléchargement de fichier » pointant vers cet endpoint.

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
└── test_connector.py
```

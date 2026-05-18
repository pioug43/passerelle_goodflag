# passerelle-goodflag

Connecteur [Passerelle](https://doc-publik.entrouvert.com/dev/developpement-d-un-connecteur/) pour la signature électronique [Goodflag](https://sgs-demo-test01.sunnystamp.com/wm-docs/api.html).

Permet à Publik (W.C.S.) de piloter un circuit de signature : création de workflow, upload de documents (PDF, DOCX, images), démarrage, suivi du statut et récupération des documents signés.

**v2.1** — 803 lignes (-78% vs v1.4). Utilise les patterns natifs Passerelle (`self.requests`, `APIError`, `cache_duration`, `parameters`).

## Installation

### Docker (Publik-Docker)

```bash
# Installer dans le conteneur Passerelle
docker exec publik-passerelle-1 pip install --no-deps \
  git+https://github.com/pioug43/passerelle_goodflag.git@claude/review-connector-code-G3VsD

# Ajouter à TENANT_APPS (auto-découvert via entry_points pour INSTALLED_APPS)
docker exec publik-passerelle-1 sh -c 'cat > /etc/passerelle/settings.d/goodflag.py <<EOF
TENANT_APPS += ("passerelle_goodflag",)
EOF'

# Appliquer les migrations
docker exec publik-passerelle-1 sudo -u passerelle \
  passerelle-manage migrate_schemas -d passerelle.mon-tenant.example.com

# Redémarrer
docker restart publik-passerelle-1
```

### Production classique

```bash
pip install passerelle-goodflag
echo "TENANT_APPS += ('passerelle_goodflag',)" >> /etc/passerelle/settings.d/goodflag.py
passerelle-manage migrate_schemas
systemctl restart passerelle
```

## Configuration

Dans l'admin Passerelle (`/manage/`) → **Connecteurs métiers** → **Ajouter un connecteur Goodflag** :

| Champ | Obligatoire | Description | Exemple |
|-------|:-----------:|-------------|---------|
| `base_url` | oui | URL de base API Goodflag | `https://gofast.test02.goodflag.com/api` |
| `access_token` | oui | Bearer token (masqué dans l'admin) | `act_xxx.yyy` |
| `user_id` | oui | Utilisateur propriétaire des workflows | `usr_xxx` |
| `default_consent_page_id` | recommandé | Page de consentement par défaut | `cop_xxx` |
| `default_signature_profile_id` | recommandé | Profil de signature (OTP SMS) | `sip_xxx` |
| `default_layout_id` | optionnel | Layout pour les métadonnées | `lay_xxx` |
| `timeout` | optionnel | Timeout HTTP en secondes (défaut: 30) | `30` |
| `verify_ssl` | optionnel | Vérification SSL (défaut: activé) | `true` |

Dans l'onglet **Sécurité** : ajouter les services Publik (`Démarches`, `Connexion`) avec le droit `can_access`.

## Exemples concrets

### Test rapide avec curl

```bash
# Vérifier la disponibilité
curl -s https://passerelle.example.com/passerelle-goodflag/signature/up
# → {"err": 0}

# Créer + uploader + démarrer un workflow en un seul appel
curl -s -X POST \
  https://passerelle.example.com/passerelle-goodflag/signature/submit-workflow \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Convention de stage 2026-001",
    "recipient_email": "signataire@example.com",
    "recipient_firstname": "Jean",
    "recipient_lastname": "Dupont",
    "recipient_phone": "+33612345678",
    "file_url": "https://formulaires.example.com/demande/42/download?f=2",
    "content_type": "application/pdf"
  }'
# → {"data": {"workflow_id": "wfl_xxx", "status": "started", "document_id": "doc_xxx"}}

# Vérifier le statut (polling depuis WCS)
curl -s "https://passerelle.example.com/passerelle-goodflag/signature/sync-status?workflow_id=wfl_xxx"
# → {"data": {"workflow_id": "wfl_xxx", "status": "started", "progress": 0, "is_final": false}}

# Après signature terminée
curl -s "https://passerelle.example.com/passerelle-goodflag/signature/sync-status?workflow_id=wfl_xxx"
# → {"data": {"workflow_id": "wfl_xxx", "status": "finished", "progress": 100, "is_final": true}}

# Télécharger le document signé
curl -sOJ "https://passerelle.example.com/passerelle-goodflag/signature/download-signed-documents?workflow_id=wfl_xxx"
```

### Upload d'un fichier DOCX (Word)

```bash
# Via file_url (le plus courant depuis WCS)
curl -s -X POST .../submit-workflow \
  -d '{"name": "Contrat", "recipient_email": "...",
       "file_url": "https://formulaires.example.com/demande/42/download?f=2",
       "content_type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document"}'

# Via base64
curl -s -X POST .../upload-document \
  -d '{"workflow_id": "wfl_xxx",
       "file_base64": "'$(base64 -w0 document.docx)'",
       "filename": "contrat.docx",
       "content_type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document"}'

# Via multipart
curl -s -X POST .../upload-document \
  -F "workflow_id=wfl_xxx" \
  -F "file=@document.docx;type=application/vnd.openxmlformats-officedocument.wordprocessingml.document"
```

Les fichiers DOCX sont automatiquement convertis en PDF côté Goodflag (`convertToPdf=true`). Le profil de signature (`sip_xxx`) est appliqué au document converti.

### Intégration dans un workflow WCS

Le dossier `exemple/` contient un formulaire et un workflow WCS prêts à l'emploi :

```bash
# Importer dans WCS
wcs-manage shell -d formulaires.example.com -c "
from wcs.workflows import Workflow
from wcs.formdef import FormDef
with open('exemple/exemple_workflow_signature.xml', 'rb') as f:
    w = Workflow.import_from_xml(f); w.store()
with open('exemple/exemple_formulaire_signature.xml', 'rb') as f:
    fd = FormDef.import_from_xml(f); fd.store()
print(f'Workflow {w.name} (id={w.id})')
print(f'Form {fd.name} (id={fd.id})')
"
```

**Important** : dans le workflow, les URLs des webservice_call utilisent `{{ passerelle_url }}passerelle-goodflag/<slug>/`. Vérifiez que le `<slug>` correspond à celui de votre connecteur dans Passerelle (visible sur la page du connecteur).

#### Architecture du workflow d'exemple

```
Nouveau
  └─ jump → Création workflow Goodflag
              └─ webservice_call POST submit-workflow
                  ├─ (succès) → En attente de signature
                  │               └─ webservice_call GET sync-status (polling timeout 15min)
                  │                   ├─ status=finished → Récupération document signé
                  │                   │                      └─ webservice_call GET download-signed-documents
                  │                   │                          └─ Terminé ✓
                  │                   ├─ status=refused → Signature refusée ✗
                  │                   └─ (non final) → reboucle via timeout
                  └─ (erreur) → Erreur technique ✗
```

#### Paramètres WCS du webservice_call `submit-workflow`

```
URL : {{ passerelle_url }}passerelle-goodflag/signature/submit-workflow
Méthode : POST
Paramètres POST :
  name              = {{ form_var_objet_document }}
  recipient_email   = {{ form_var_email_signataire }}
  recipient_firstname = {{ form_var_prenom_signataire }}
  recipient_lastname  = {{ form_var_nom_signataire }}
  recipient_phone   = {{ form_var_telephone_portable }}
  file_url          = {{ form_var_document_pdf_url }}
  content_type      = application/pdf
  external_ref      = {{ form_number }}
Nom de variable : goodflag_submit
```

#### Paramètres WCS du webservice_call `sync-status`

```
URL : {{ passerelle_url }}passerelle-goodflag/signature/sync-status?workflow_id={{ form_var_goodflag_workflow_id }}&external_ref={{ form_number }}
Méthode : GET
Nom de variable : goodflag_status
```

#### Données de traitement (backoffice fields)

| Champ | Type | Expression |
|-------|------|------------|
| Identifiant workflow Goodflag | Texte | `{{ form_var_goodflag_workflow_id }}` |
| Statut signature Goodflag | Texte | `{{ form_var_goodflag_status }}` |

### Multi-signataires (format indexé)

```bash
curl -s -X POST .../submit-workflow \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Convention tripartite",
    "recipients_0_email": "etudiant@example.com",
    "recipients_0_firstname": "Alice",
    "recipients_0_lastname": "Martin",
    "recipients_0_phone": "+33611111111",
    "recipients_1_email": "tuteur@example.com",
    "recipients_1_firstname": "Bob",
    "recipients_1_lastname": "Dupont",
    "recipients_1_phone": "+33622222222",
    "file_url": "https://formulaires.example.com/convention/1/download?f=2"
  }'
```

### Multi-étapes : valideur + signataires avec consent/profil spécifiques

Cas d'usage : un responsable **valide** le document, puis deux signataires le **signent** avec authentification OTP SMS. Chaque étape a sa propre page de consentement et son profil de signature.

```bash
curl -s -X POST .../submit-workflow \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Convention recherche Labo-Industriel 2026",
    "steps": [
      {
        "stepType": "approval",
        "recipients": [
          {
            "email": "directeur.labo@example.com",
            "firstName": "Marie",
            "lastName": "Curie",
            "consentPageId": "cop_ApprobationLabo"
          }
        ],
        "maxInvites": 3
      },
      {
        "stepType": "signature",
        "recipients": [
          {
            "email": "chercheur@example.com",
            "firstName": "Pierre",
            "lastName": "Martin",
            "phoneNumber": "+33611111111",
            "consentPageId": "cop_SignatureOTPSMS"
          },
          {
            "email": "responsable@industriel.com",
            "firstName": "Jean",
            "lastName": "Dupont",
            "phoneNumber": "+33622222222",
            "consentPageId": "cop_SignatureOTPSMS"
          }
        ],
        "maxInvites": 5
      }
    ],
    "signature_profile_id": "sip_ProfilOTPSMS",
    "layout_id": "lay_MetadataDefault",
    "metadata": {
      "data1": "{{ form_number }}",
      "data2": "Convention recherche",
      "data3": "Laboratoire CITI"
    },
    "file_url": "https://formulaires.example.com/convention/1/download?f=2",
    "content_type": "application/pdf"
  }'
```

**Explication du circuit :**

1. **Étape 1 — Approbation** (`stepType: approval`) :  
   Le directeur de labo reçoit un email, visualise le document et approuve (pas de signature électronique, juste une validation). La page de consentement `cop_ApprobationLabo` affiche les conditions d'approbation spécifiques.

2. **Étape 2 — Signature** (`stepType: signature`) :  
   Une fois l'approbation donnée, les deux signataires reçoivent simultanément une invitation. Chacun signe avec OTP SMS (code envoyé sur leur téléphone). La page `cop_SignatureOTPSMS` affiche les mentions légales de signature électronique.

**Paramètres spécifiques :**

| Paramètre | Niveau | Description |
|-----------|--------|-------------|
| `consentPageId` | par destinataire | Page de consentement (texte affiché avant signature/approbation). Surcharge `default_consent_page_id` du connecteur. |
| `signature_profile_id` | par document | Profil de signature (type d'authentification : OTP SMS, certificat...). Surcharge `default_signature_profile_id` du connecteur. |
| `layout_id` | par workflow | Layout pour les métadonnées (`data1`-`data16`). Surcharge `default_layout_id`. |
| `maxInvites` | par étape | Nombre max de relances automatiques par destinataire. |

### Même exemple en format WCS (webservice_call POST)

Pour intégrer dans un workflow WCS sans JSON natif, utiliser les paramètres indexés :

```
URL : {{ passerelle_url }}passerelle-goodflag/signature/create-workflow
Méthode : POST
Paramètres POST :
  name = Convention recherche {{ form_number }}

  # Étape 1 : valideur (utiliser le format steps JSON dans le body)
  # → Pour les workflows multi-étapes, passer le JSON complet via le champ
  #   "steps" dans le body de la requête WCS (type: JSON)

  # Alternative simple : 2 signataires sans étape d'approbation
  recipients_0_email     = {{ form_var_email_chercheur }}
  recipients_0_firstname = {{ form_var_prenom_chercheur }}
  recipients_0_lastname  = {{ form_var_nom_chercheur }}
  recipients_0_phone     = {{ form_var_tel_chercheur }}
  recipients_0_consent_page_id = cop_SignatureOTPSMS
  recipients_1_email     = {{ form_var_email_industriel }}
  recipients_1_firstname = {{ form_var_prenom_industriel }}
  recipients_1_lastname  = {{ form_var_nom_industriel }}
  recipients_1_phone     = {{ form_var_tel_industriel }}
  recipients_1_consent_page_id = cop_SignatureOTPSMS
  signature_profile_id   = sip_ProfilOTPSMS
  external_ref           = {{ form_number }}
```

> **Note** : le format indexé (`recipients_N_consent_page_id`) permet de surcharger la page de consentement **par destinataire** directement depuis les paramètres WCS, sans passer par le JSON `steps`.

### Recherche et supervision

```bash
# Lister les workflows récents
curl -s ".../list-workflows?per_page=10"

# Rechercher par texte (nom ou métadonnées)
curl -s ".../list-workflows?text=Convention%20stage"

# Détail complet
curl -s ".../get-workflow?workflow_id=wfl_xxx"

# URL de visualisation (sans signature)
curl -s ".../get-viewer-url?document_id=doc_xxx"
```

## Endpoints

| Endpoint | Méthode | Cache | Description |
|----------|---------|:-----:|-------------|
| `up` | GET | — | Test disponibilité |
| `create-workflow` | POST | — | Crée un workflow (statut `draft`) |
| `submit-workflow` | POST | — | Crée + uploade + démarre en un appel |
| `upload-document` | POST | — | Upload PDF/DOCX/image |
| `start-workflow` | POST | — | Démarre (envoie invitations) |
| `stop-workflow` | POST | — | Arrête un workflow |
| `resend-invite` | POST | — | Relance une invitation email |
| `sync-status` | GET | 10s | Statut normalisé pour polling WCS |
| `list-workflows` | GET | 15s | Liste/recherche avec pagination |
| `get-workflow` | GET | — | Détail complet |
| `get-viewer-url` | GET/POST | — | URL de visualisation document |
| `download-signed-documents` | GET | — | Téléchargement documents signés |

## Mapping des statuts

| Statut Goodflag | Statut normalisé | `is_final` | Action WCS |
|-----------------|------------------|:----------:|------------|
| `draft` | `draft` | non | Attendre |
| `started` | `started` | non | Polling via `sync-status` |
| `finished` | `finished` | oui | Télécharger le document signé |
| `archived` | `finished` | oui | Idem (variante post-archivage) |
| `stopped` | `refused` | oui | Notifier le demandeur |
| autre | `error` | oui | Alerter l'administrateur |

## Upload de documents

Sources supportées pour `upload-document` et `submit-workflow` :

| Source | Paramètre | Usage typique |
|--------|-----------|---------------|
| URL Publik | `file_url` | WCS `{{ form_var_document_url }}` — recommandé |
| JSON imbriqué | `file = {"filename":…, "content_type":…, "content":"<b64>"}` | Intégration API |
| Multipart | champ `file` | Test/debug |
| Base64 direct | `file_base64` + `filename` | Compatibilité |

**Types MIME** : `application/pdf`, DOCX, JPEG, PNG, WebP. Taille max : 50 Mo.  
**SSRF** : `file_url` requiert HTTPS, les IP privées/loopback/link-local sont bloquées.  
**DOCX** : validé (signature ZIP + `word/document.xml`), converti en PDF côté Goodflag.

## Architecture v2.1

```
passerelle_goodflag/
├── models.py        # GoodflagResource + 12 endpoints (571 lignes)
├── client.py        # GoodflagClient sur self.requests Passerelle (226 lignes)
├── exceptions.py    # Alias APIError (rétrocompatibilité)
└── migrations/
exemple/
├── exemple_formulaire_signature.xml   # Formulaire WCS prêt à importer
├── exemple_workflow_signature.xml     # Workflow WCS avec circuit complet
└── test_pdf.pdf                       # PDF de test
tests/
└── test_connector.py
```

### Différences v2.1 vs v1.4

| Aspect | v1.4 (3 663 lignes) | v2.1 (803 lignes) |
|--------|---------------------|-------------------|
| HTTP | `requests.Session()` custom | `self.requests` Passerelle (pooling, retry, logging, cache) |
| Erreurs | `GoodflagError` → 500 + traceback | `APIError` → `{"err": 1, "err_desc": "…"}` + bon HTTP status |
| Logs | `logging.getLogger(__name__)` | `self.logger` → visible dans admin Passerelle |
| Cache | aucun | 10s sur `sync-status`, 15s sur `list-workflows` |
| Doc API | aucune | `parameters={}` sur tous les endpoints |
| Token | affiché en clair | masqué via `PasswordInput` |
| Modèles DB | 5 tables (traces locales) | 2 tables (resource + users) |
| Fichiers | 10 fichiers Python | 3 fichiers Python |

## Tests

```bash
pip install pytest pytest-django responses
pytest tests/ -v
```

## Licence

AGPLv3+

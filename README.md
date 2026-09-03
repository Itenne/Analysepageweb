# SASE Web Filtering Validation Tool

Outil de diagnostic **Web local portable**. Il démarre une page sur `http://127.0.0.1:8080` dans le navigateur du poste et teste les URL depuis ce même poste, donc via son chemin réseau, proxy et SASE habituels. Il ne modifie ni les routes, ni le DNS, ni le proxy système, ni la validation TLS ; il ne fournit aucun mécanisme de contournement.

## Architecture

- `app/web.py` : serveur Flask local uniquement et orchestration asynchrone des tests.
- `app/templates/` et `app/static/` : interface Web locale sans dépendance JavaScript externe.
- `app/security.py`, `parsers.py`, `dns_checker.py`, `http_client.py` : validation SSRF, import, DNS et requête HTTP(S).
- `classifier.py` + `config/signatures.json` : moteur configurable de détection SASE/proxy et de restriction IP.
- `public_ip.py`, `exporters.py` : observation de l’IP publique et rapports CSV/HTML.

Les résultats sont des modèles sérialisables : une comparaison de rapports avant/après pourra réutiliser URL, URL finale, code HTTP et classification.

## Installation et lancement

Prérequis : Python 3.10+ et accès aux dépendances Python.

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m app.main
```

Le navigateur par défaut s’ouvre sur `http://127.0.0.1:8080`. Le serveur écoute **exclusivement** sur `127.0.0.1`, jamais sur le réseau local. Aucun droit administrateur n’est nécessaire.

## Utilisation

1. Chargez un fichier `.txt` (une URL par ligne) ou `.csv` (colonne `url`, séparateur `;` ou `,`), ou ajoutez une URL manuellement.
2. Cliquez sur **Detect Public IP**. Deux services d’observation sont interrogés avec le proxy système normal ; deux réponses identiques donnent une confiance `HIGH`.
3. Choisissez le nombre de connexions simultanées (5 par défaut, maximum 20), puis cliquez sur **Test All**. La progression est actualisée sans bloquer la page ; **Stop** annule les tâches non commencées.
4. Cliquez sur une ligne pour afficher le DNS, IP distante, redirections, headers pertinents, classification et indicateurs.
5. Téléchargez les rapports **CSV** ou **HTML**.

Les importations sont limitées à 1 Mo. Les URL HTTP(S) sont validées et les destinations locales, privées, loopback, link-local et réservées sont refusées. Le User-Agent est explicite (`SASE-Web-Validation-Tool/0.1.0`) ; les certificats TLS restent vérifiés. La réponse analysée est limitée à 64 KiB et l’outil ne conserve pas le corps intégral des pages, cookies, tokens ou credentials.

## Détection et limites

Un simple `403` est classé `HTTP_403`, pas comme un blocage. `ACCESS_DENIED` exige un code de refus et des signaux corroborants (au moins deux signatures, ou une signature et un header proxy/SASE). `IP_RESTRICTION` est prioritaire lorsqu’un indicateur IP configurable est présent. Les signatures peuvent être ajoutées dans `config/signatures.json`, notamment pour d’autres langues.

> Une classification `ACCESS_DENIED` ou `IP_RESTRICTION` est une indication basée sur les éléments observés par l’outil ; elle ne constitue pas une preuve définitive de la cause du blocage.

Le comportement dépend des réponses visibles au poste : une application peut masquer sa cause de refus, un proxy peut masquer l’IP distante, et les services de détection d’IP publique peuvent être bloqués. L’outil ne fait ni scan de ports, ni fuzzing, ni brute force, ni authentification, ni tunnel, ni VPN/Tor.

## Exécutable Windows portable

Créez l’exécutable sous Windows :

```powershell
pip install pyinstaller
pyinstaller --noconfirm --onefile --add-data "app/templates;app/templates" --add-data "app/static;app/static" --add-data "config;config" --name SASEWebValidator app\main.py
```

Testez l’exécutable produit dans `dist\SASEWebValidator.exe` avec un compte utilisateur standard. Pour une distribution réellement autonome, incluez les dépendances installées par PyInstaller et vérifiez le chargement des signatures après packaging.

## Tests

```bash
python -m unittest discover -s tests -v
```

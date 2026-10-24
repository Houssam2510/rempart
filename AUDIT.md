# Audit de Rempart — 24 octobre 2026

Audit sceptique de la branche `feat/bench-learning-v2` (commit `72eb339`). L'audit a tourné dans un clone séparé, avec un venv neuf, un `REMPART_HOME` jetable et des outils tiers installés à part. Ce fichier est le seul écrit dans le dépôt.

Conventions :
- « **exécuté** » : résultat obtenu en lançant la commande indiquée ;
- « **lecture de code** » : constat fait en lisant le code, sans exécution ;
- « **non vérifié** » : rien n'a été exécuté pour le prouver.

## Résumé

**Verdict.** L'ingénierie est sérieuse, la reproductibilité excellente et l'ambition réelle. Mais la précision mesurée sur du code jamais vu est très loin des chiffres mis en avant : sur les 24 résultats critiques ou high les mieux classés de 5 dépôts réels, **1 seul est un vrai positif** (4 %, ou 21 % en comptant les cas discutables). Le 99,4 OWASP et le 100 % du bench sont exacts, mais ils mesurent du code que l'outil a servi à régler.

**3 forces réelles**
1. Tout se reproduit à l'identique : 160 tests, bench, OWASP 99,4, démo.
2. L'installation se fait en une commande, en 2 s pour le cœur, et la sortie a de vraies bonnes surprises. Exemples : `shell=True` interne classé MEDIUM là où Semgrep dit ERROR, deux `dangerouslySetInnerHTML` sur commerce là où Semgrep n'en voit qu'un, une clé Stripe de test correctement classée LOW.
3. Les choix défensifs de base sont justes : action GitHub sans injection, agent confiné aux fichiers scannés, noms de preuves assainis, secrets masqués dans les résultats.

**3 faiblesses qui comptent**
1. **Précision hors corpus de 4 à 21 %**. Le haut de la liste est faux : chaînes CRITICAL bâties sur la configuration de développement, `str.replace` pris pour un accès fichier, typosquat sur `psycopg`.
2. **Trois failles de sécurité de l'outil, prouvées par exécution** :
   - empoisonnement de l'apprentissage par un dépôt tiers ;
   - fail-open (« grade A » quand le scanner plante) ;
   - l'assistant MCP peut fermer des résultats.
3. **Robustesse** : le moteur Python plante sur django ; sur les gros dépôts il relie des méthodes par leur seul nom (12 CRITICAL SQLi dans le code de Django lui-même, tous faux) ; les alias d'import (`from os import system`) passent inaperçus.

---

## 1. Affirmations du README

| Affirmation | Statut | Commande | Résultat |
|---|---|---|---|
| 160 tests | **Confirmé** | `python -m unittest discover -s tests -t .` (venv avec `[all]`) | `Ran 160 tests … OK`, 0 skipped, 12,8 s |
| 316 règles | **Confirmé, à nuancer** | `rempart rules` + comptage par domaine | 316 au total, dont **68 actives seulement contre un compte cloud ou un site en direct**, 11 pour les images et 7 règles techniques (`*-CHECK-SKIPPED`, `CTX-*`). **230 servent à un scan de dépôt.** Le domaine « dependencies » n'a que 3 règles (une seule, `DEP-VULNERABLE`, porte tous les CVE). |
| 16 domaines | **Confirmé** | `models.DOMAINS` et `Counter(rule.domain)` | 16 déclarés, 16 avec des règles |
| 13 scanners | **Partiellement vrai** | `ALL_SCANNERS` | 10 scanners de dépôt, plus images, cloud et web en commandes séparées |
| OWASP Benchmark Python 99,4 | **Confirmé, mais conditionnel** | `python bench/owasp_python.py <clone BenchmarkPython f129148>` | 99,4 sur les 1 230 cas, 2,4 s. **En comptant les résultats INFO, le score tombe à 87,7** (`codeinj` 60,6, `deserialization` 66,7, `xxe` 0) : le script exclut INFO, niveau où le moteur rétrograde les cas douteux. Le moteur a été réglé sur ce benchmark (14,2 → 99,4, CHANGELOG 0.3.0). |
| Bench 100 % / 97,8 % | **Confirmé, mais ce n'est pas une mesure de généralisation** | `rempart bench -v` (depuis le paquet installé, le corpus est bien empaqueté) | 90 TP, 0 FP, 2 FN, 0 piège déclenché sur 73. Le corpus a servi à corriger 11 défauts : il prouve qu'ils restent corrigés, rien de plus (le README le dit). |
| 9/9 sur cspm-lite (+ 2 chemins) | **Non vérifiable** dans cet audit | le « 9/9 » porte sur un audit AWS **en direct** ; aucun compte AWS utilisé | En **statique** sur `lab/*.tf` : **5 des 9** failles plantées trouvées (BPA désactivé, policy `Principal *`, AdministratorAccess, `Action *`, ports 22/3306). Ratées en statique : chiffrement S3, versioning, condition TLS, flow logs. 2 chaînes trouvées (1 *linked*, 1 *co-occurrence*). |
| « six chemins, dont cinq prouvés » (légende de la démo) | **Faux** | `rempart scan examples/vulnerable-app --offline -f json` | 6 chaînes, **4** *linked* et 2 *correlated* |
| 45 formats de jetons · 24 vérificateurs live · 12 lockfiles | **Confirmé** | introspection de `secrets._COMPILED`, `verify.checker`, `lockfiles.PARSERS` | 45 · 24 identifiants de règles (23 fournisseurs, Stripe compté deux fois) · 12 |
| Précision 8 % → 80 % sur 10 dépôts privés | **Non vérifiable** (dépôts privés) | — | **Contredit par la section 3** : 4 à 21 % sur 5 dépôts publics jamais vus |
| Agent : 9 dépôts d'évaluation, accord mesuré | **Non vérifié** | `rempart agent-eval` demande une clé API, non utilisée | — |
| 28 contrôles AWS « validés contre les modèles de service » | **Partiellement vrai** (lecture de code) | tests `botocore.Stubber` | La forme des appels est validée, pas leur comportement sur un vrai compte |

## 2. Sur-ajustement

| Constat | Où | Effet mesuré |
|---|---|---|
| `escape_for_html`, une fonction **propre à BenchmarkPython** (`helpers/utils.py:42`, présente dans les 1 230 fichiers), est codée en dur comme nettoyeur XSS | [pyflow.py:120](src/rempart/pyflow.py#L120), [pyflow.py:504](src/rempart/pyflow.py#L504) | **Ablation exécutée** (retrait dans un clone) : 99,4 → **99,3**, un piège XSS de plus. Le moteur la retrouve presque seul ; le nom codé en dur est un indice, pas la source du score. |
| Suivi **en mémoire** de `configparser` (`section`, `set`, `get`) pour propager le taint | [pyflow.py:449-486](src/rempart/pyflow.py#L449-L486) | C'est l'idiome de « blanchiment » du benchmark (118 fichiers sur 1 230). Dans une vraie application, `configparser` lit un fichier : fonctionnalité à faible valeur hors benchmark. Non ablaté. |
| Repliement de constantes et de comparaisons arithmétiques (`(7*42) - num > 200`) | [pyflow.py:270-325](src/rempart/pyflow.py#L270-L325) | Utile en général, mais calibré sur 148 fichiers du benchmark qui utilisent exactement ce motif. Non ablaté. |
| Exclusion des résultats **INFO** dans le script de score | [bench/owasp_python.py](bench/owasp_python.py) (`f.severity >= Severity.LOW`) | 99,4 → 87,7 avec INFO compté (exécuté). À déclarer. |
| Noms du corpus interne (`clean_html`, `only_digits`, `reqeusts`…) dans les sources | `grep` exécuté | **Aucun** en dehors de la doc et du texte d'aide de l'interface. Le réglage sur le corpus est structurel et documenté (11 correctifs dans le CHANGELOG). |

## 3. Test sur du code jamais vu

`rempart scan <dépôt> --offline --no-history -f json`. Les clones superficiels datent du 24/10/2026. Chacun des résultats critiques ou high (10 au maximum, par risque décroissant) a été étiqueté à la main en lisant le code.

| Dépôt | Fichiers | Temps | CRIT / HIGH / MED / LOW | Étiquetés | VP | FP | Discutable | Précision stricte / large |
|---|---|---|---|---|---|---|---|---|
| miguelgrinberg/microblog (Flask) | 73 | 0,4 s | 0 / 2 / 3 / 4 | 2 | 0 | 1 | 1 | **0 % / 50 %** |
| django/djangoproject.com (Django) | 676 | 5,8 s | 1 / 10 / 25 / 25 | 10 | 0 | 8 | 2 | **0 % / 20 %** |
| vercel/commerce (Next.js) | 78 | 0,3 s | 0 / 0 / 0 / 2 | 0 | — | — | — | n/a (les 2 LOW sont justes, voir plus bas) |
| terraform-aws-modules/terraform-aws-eks | 185 | 2,0 s | 0 / 3 / 23 / 16 | 3 | 0 | 3 | 0 | **0 %** |
| GoogleCloudPlatform/microservices-demo (K8s, GHA, Go, Python) | 364 | 2,3 s | 2 / 7 / 62 / 119 | 9 | 1 | 7 | 1 | **11 % / 22 %** |
| **Total** | | | | **24** | **1** | **19** | **4** | **4 % / 21 %** |

### Détail des étiquettes

**microblog**
- `CODE-OPEN-REDIRECT` `app/auth/routes.py:29` — **discutable**. La garde `urlsplit(next_page).netloc != ''` est présente et non reconnue ; le contournement par antislash reste théorique.
- `CODE-SSRF` `app/main/routes.py:160` — **FP**. L'hôte est constant (`api.cognitive.microsofttranslator.com`) ; seuls les paramètres de langue viennent de la requête.

**djangoproject.com**
- `CHAIN-DEBUG-CONSOLE-EXPOSED` (CRITICAL) — **FP**. Elle relie `DEBUG=True` de `settings/dev.py` au `runserver 0.0.0.0` d'un compose qui utilise `settings.docker`. De plus, Django n'a pas la console Werkzeug annoncée.
- `CHAIN-XSS-SESSION-THEFT` — **FP**. `mark_safe(highlight(...))` sur la documentation, et la chaîne affirme des « jetons en localStorage » inexistants : le maillon est un cookie de la configuration de développement.
- `CODE-PATH-TRAVERSAL` `docs/views.py:35` — **FP**. `path.replace(version, …)` est une méthode de chaîne, pas un accès fichier.
- `CODE-OPEN-REDIRECT` ×3 (`:35`, `:132`, `:172`) — **FP**. Chemin de la requête sur le même hôte, `reverse()` plus une chaîne de requête, et un objet modèle.
- `CODE-EVAL` `static/js/lib/require.js:36` — **FP**. Bibliothèque tierce minifiée et embarquée.
- `COMPOSE-SECRET-LITERAL` `SECRET_KEY=foo` — **discutable** (compose de développement).
- `DATA-SQL-LITERAL-PASSWORD` `'secret'` dans le SQL d'initialisation local — **FP**.
- `CODE-DEBUG-ENABLED` `settings/dev.py` — **discutable**. C'est vrai, mais c'est le rôle d'un fichier de développement.

**terraform-aws-eks**
- `TF-EC2-IMDSV1` `examples/eks-hybrid-nodes/remote.tf:97` — **FP**. IMDS y est **désactivé** (`http_endpoint = "disabled"`).
- `TF-EC2-IMDSV1` ×2 (modules de groupes de nœuds) — **FP**. Le défaut de la variable est `http_tokens = "required"`, que l'outil ne lit pas à travers les blocs `dynamic`. Checkov fait la même erreur.

**microservices-demo**
- `CHAIN-CI-UNTRUSTED-TO-RELEASE` (CRITICAL) `make-release.yaml:53` — **FP** comme chaîne. Le déclencheur est `workflow_dispatch`, réservé aux personnes ayant les droits d'écriture.
- `CODE-SQL-INJECTION` `catalog_loader.go:132` — **FP**. Le nom de table vient de `os.Getenv`.
- `K8S-SECRET-IN-ENV` ×2 — **FP**. Les valeurs sont des gabarits (`GOOGLE_API_KEY_VAL`) ou un *nom* de secret.
- `GHA-OIDC-UNTRUSTED` `cleanup.yaml` — **discutable**. `pull_request_target`, mais le code de la PR n'est pas exécuté.
- `GHA-OIDC-UNTRUSTED` `deploy-pr.yaml:34` — **VP**. `workflow_run`, avec récupération de `head_sha` et `allow-unsafe-pr-checkout: true`, un jeton OIDC GCP, et un artefact du fork écrit dans `GITHUB_ENV`.
- `DATA-TLS-DISABLED` `catalog_loader.go:110` — **FP**. `sslmode=disable` est le schéma documenté avec le connecteur AlloyDB, qui chiffre lui-même la connexion.
- `SUPPLY-TYPOSQUAT` `psycopg`, `psycopg-binary` — **FP**. C'est psycopg 3, un paquet légitime.

**Ce qui aggrave le constat.** Sur microservices-demo, le vrai scénario d'attaque (`deploy-pr.yaml`) n'est **pas** assemblé en chaîne : il reste en HIGH et MEDIUM. La seule chaîne CRITICAL pointe vers le mauvais workflow.

**Ce qui est bon.**
- commerce : les 2 LOW sont pertinents (JSON-LD injecté sans échapper `<`, et un `dangerouslySetInnerHTML`) ; Semgrep n'en trouve qu'un.
- djangoproject : `shell=True` dans `update_docs.py` est classé MEDIUM, à juste titre (le chemin vient de la configuration interne) ; Semgrep le met en ERROR.
- Pour mémoire, la clé Stripe de test est vue par Rempart, Gitleaks et Trivy.

### Gros dépôt (django/django, 7 089 fichiers)

- **Exécuté** : le scan se termine en 50,5 s, mais **le scanner de code plante** (`TypeError: cannot use 'list' as a set element`, [pyflow.py:209](src/rempart/pyflow.py#L209)). La console affiche ensuite « Posture score 100/100, grade A » et le code de sortie est 0 (voir la faille n°2).
- Avec ce bug corrigé dans un clone d'ablation : 85 s et 684 résultats, dont **12 CRITICAL `CODE-SQL-INJECTION` dans le code de Django**. Exemple : `aflush() passes request data to clear() passes request data to .execute()`. Tous sont faux : les résumés interprocéduraux résolvent les méthodes par leur **nom court** (`clear`, `exists`, `list`).

### Lacunes de détection simples (exécuté)

Sur 8 styles d'injection Python courants, Rempart en rate 2 :
- `from os import system` puis `system("ping " + request.args["h"])` : **raté** ;
- `import subprocess as sp` puis `sp.run(cmd, shell=True)` : **raté**.

`os.system` direct, `from subprocess import check_output`, `cursor.execute`, `.objects.raw`, un paramètre FastAPI et `str.format` passent.

### Comparaison avec d'autres outils (exécuté, mêmes dépôts)

| Outil | Constat |
|---|---|
| Semgrep 1.182 `p/default` | Même redirection discutable sur microblog, même `run-shell-injection` sur `make-release.yaml`, rate aussi `deploy-pr.yaml`. **Plus bruyant** : 419 résultats sur djangoproject, dont 384 INFO de gabarits. Trouve un `missing-user-entrypoint` par Dockerfile, que Rempart signale aussi (`DOCKER-RUNS-AS-ROOT`). |
| Checkov 3.3.30 | Même FP IMDS sur EKS. Volume nettement plus grand : 139 échecs sur EKS, 382 sur microservices-demo. 94 s sur EKS. |
| Trivy 0.76.1 (misconfig + secrets) | 107 et 369 erreurs de configuration ; trouve la même clé Stripe. |
| Gitleaks 8.24.2 | Une seule fuite au total (la clé Stripe de test), également vue par Rempart. |

**Lecture honnête.** Sur ces dépôts, Rempart n'est pas plus bruyant que les autres en volume ; il l'est souvent moins. Mais son **haut de liste**, ce qu'un humain lit en premier, se trompe plus souvent : chaînes CRITICAL fausses, faux typosquat. Je n'ai trouvé **aucun cas où Rempart détecte un vrai problème critique que les autres ratent** sur ces 5 dépôts.

## 4. Failles de sécurité de l'outil, par gravité

| # | Gravité | Faille | Preuve |
|---|---|---|---|
| 1 | **Haute** | **Empoisonnement de l'apprentissage par un dépôt tiers.** Les `rempart:ignore` de n'importe quel dépôt scanné comptent comme preuve de faux positif, et la calibration est **globale à toute la machine**. | **Exécuté** : un dépôt avec 12 `rempart:ignore[CODE-SQL-INJECTION]`, scanné une seule fois, fait passer une vraie injection SQL d'**un autre projet** de CRITICAL (confiance 0,90) à **HIGH (0,14)**, « severity lowered ». `--fail-on critical` laisserait passer. Les verdicts de l'agent (poids 0,5) sur un dépôt hostile suivent le même mécanisme (non exécuté). |
| 2 | **Haute** | **Fail-open** : quand un scanner plante, le scan affiche « grade A », retourne 0 et la CI passe. | **Exécuté** sur django (`--only code`) : `scanner error: code: TypeError…`, puis « Posture score 100/100 grade A », exit 0. |
| 3 | **Haute** | **Un assistant MCP peut fermer des résultats.** `rempart_triage` enregistre les verdicts avec la source `human`, alors que le README promet que l'IA ne ferme jamais rien. | **Exécuté** : verdict MCP stocké en `('fp', 'human')` ; le scan CLI suivant avec `--fail-on high` sort en 0. |
| 4 | Moyenne | **Contournement de la barrière CI par la PR elle-même.** Le scan lit `.rempart.toml` et `.rempart/knowledge.toml` depuis le code de la PR. | **Exécuté** : `disable = ["CODE-CMD-INJECTION"]` donne exit 1 → 0. Déclarer sa propre fonction comme nettoyeur dans `knowledge.toml` donne exit 1 → 0. |
| 5 | Moyenne | **L'agent envoie le contenu brut des fichiers**, secrets compris, à l'API Anthropic : `read_file` ne masque rien. | Lecture de code ([agent.py:217-223](src/rempart/agent.py#L217-L223)). Les `.env` ignorés par git sont exclus, pas les fichiers de configuration commités. |
| 6 | Moyenne | **Les sorties de l'agent sont influençables par le dépôt.** Des tests de preuve « à lancer soi-même » et des correctifs appliqués par `--apply`, y compris sur `.github/workflows` ou `package.json`, peuvent être orientés par une injection de prompt. | Lecture de code ([agent.py:437-466](src/rempart/agent.py#L437-L466)). La défense repose uniquement sur le prompt. Non exécuté. |
| 7 | Moyenne / basse | **Vérification live des secrets** : endpoints officiels en lecture seule (bon point), mais rien n'empêche de l'utiliser sur le dépôt d'autrui, ce qui pose un risque légal. STS déclenche les canarytokens et GuardDuty. Les jetons Telegram et Mapbox passent dans l'URL. | Lecture de code ([verify.py:135-160](src/rempart/verify.py#L135-L160)). |
| 8 | Basse | **MCP** : `rempart_web_audit` accepte n'importe quelle URL (sondage du réseau interne par un assistant manipulé) ; `rempart_scan` accepte n'importe quel répertoire. | Lecture de code ([mcp_server.py](src/rempart/mcp_server.py)). |
| 9 | Basse | `search_code` compile une regex fournie par le modèle, d'où un risque de ReDoS (blocage). | Lecture de code. |

**Ce qui tient.**
- `action.yml` passe toutes les entrées par `env:`, sans aucune interpolation `${{ }}` dans les scripts.
- L'agent est confiné aux fichiers découverts, avec vérification `is_relative_to`.
- Les noms de fichiers de preuve sont assainis (`[\w.\-]{1,80}`).
- Les valeurs de secrets sont masquées dans les résultats.

**Auto-scan** (`rempart scan . --offline`, exécuté) : 0 CRITICAL ou HIGH ; 15 MEDIUM, dont 5 `CODE-SQL-INJECTION` dans `history.py` (**FP** : f-strings construites sur des constantes du module) ; `pypa/gh-action-pypi-publish@release/v1` non épinglé dans le workflow de release ; 75 `QUAL-COMPLEXITY`.

## 5. Qualité d'ingénierie

- **Taille** : 11 667 lignes de Python dans `src`, 2 929 dans les tests. Les modules les plus lourds sont `tui.py` (1 114), `pyflow.py` (1 013), `scanners/code.py` (1 008) et `cli.py` (696). 141 lignes dépassent 180 caractères.
- **Modules les plus fragiles** :
  - `pyflow.py` : plantage sur django, résolution par nom court ;
  - `scanners/code.py` : 67 règles ligne par ligne par regex pour JS, Go, Java, PHP, Ruby et C# ;
  - `correlate.py` : chaînes assemblées sur des fichiers de développement, avec un récit factuellement faux (« localStorage »).
- **Gestion d'erreurs** : un scanner qui plante ne casse pas le scan, mais ne casse pas non plus la CI (faille n°2). Les `except Exception` de pyflow sont des replis de repliement de constantes : acceptables.
- **Tests** : 160 tests qui passent. Mais les tests cloud valident la forme des appels (Stubber, fixtures), pas un compte réel, et l'agent est testé contre un transport HTTP simulé. Aucun test ne couvre un dépôt réel de taille moyenne, ce qui explique que le plantage sur django ait échappé.
- **Performance** : de 0,3 à 5,8 s sur les dépôts moyens. 85 s pour 7 089 fichiers (avec le correctif), contre 18 s pour Semgrep sur djangoproject et 5,8 s pour Rempart.
- **Installation depuis zéro** : `pip install ./rempart` en 1,9 s, `[all]` en 8,7 s. Les 160 tests passent sans saut ; le bench fonctionne depuis le paquet installé.
- **Historique** : 13 des 15 commits datent des 8 et 9 octobre 2026, avec un seul auteur. Un jury demandera comment ce code a été produit et qui peut le maintenir.

## 6. Regard produit

**Les 10 premières minutes d'un CTO.** Sur microservices-demo : 191 résultats. Le premier CRITICAL accuse le mauvais workflow, les HIGH suivants sont des gabarits Kubernetes et des typosquats inexistants. Sur djangoproject.com : le premier CRITICAL porte sur `settings/dev.py`. **Il perd confiance avant d'atteindre le seul vrai problème.** En revanche, sur un projet réellement exposé comme StudyLumina, la vue « à corriger d'abord » (mettre `next` à jour, utilisé par le code) est directement actionnable. La valeur existe, mais elle est noyée par le bruit des règles de code et de chaîne.

**Ce qui est unique** (positionnement par rapport aux concurrents, non vérifié en exécution) :
- des chaînes d'attaque qui croisent code, IaC, Kubernetes et CI dans un même scan local et open source ;
- l'apprentissage par la raison (`--because`) ;
- le rejeu (`learn --eval`).

Des concepts proches existent dans des produits commerciaux (graphe d'attaque cloud chez Wiz, tri automatique chez Aikido, atteignabilité chez Snyk et Endor), mais pas à cette échelle locale et gratuite.

**Ce qui fait doublon avec du gratuit** (non vérifié en exécution, sauf mention) :
- secrets : Gitleaks, TruffleHog et sa vérification sur des centaines de fournisseurs ;
- dépendances : osv-scanner, Trivy, Grype ;
- images : Trivy, Grype ;
- IaC et Kubernetes : Checkov, Trivy, KICS, kubescape. Dans cet audit, Checkov et Trivy produisent bien plus de contrôles, **exécuté** ;
- cloud en direct : Prowler, dont l'ordre de grandeur est de plusieurs centaines de contrôles contre 28 + 13 + 9 ici ;
- web passif : Mozilla Observatory ;
- qualité et performance : linters.

**À couper ou geler pour se concentrer** :
- l'audit cloud en direct, les images, l'audit web, et les domaines qualité et performance ;
- la promotion des chaînes de portée « dépôt » (*correlated*) en CRITICAL : ne garder CRITICAL que pour les chaînes *linked*, et exclure les fichiers de développement.

**À garder et rendre irréprochable** : les chaînes *linked*, la CI/CD, le flux de données Python et l'apprentissage, une fois les failles 1 à 4 corrigées.

## 7. Les 5 questions les plus dures, et ce que l'audit permet d'y répondre

1. **« Quelle est votre précision sur du code que vous n'avez jamais vu ? »**
   Réponse honnête aujourd'hui : 1 vrai positif sur 24 en critique et high, sur 5 dépôts publics, soit 4 % en strict et 21 % en large. Le 99,4 OWASP et le 100 % du bench sont des mesures de réglage. Il faut montrer un jeu tenu à l'écart du réglage, avec le protocole de cet audit.
2. **« Votre outil de sécurité peut-il être retourné contre l'utilisateur ? »**
   Oui, trois fois, preuves à l'appui : empoisonnement de l'apprentissage (CRITICAL → HIGH par un dépôt tiers), fermeture de résultats par un assistant MCP, contournement de la CI par le `.rempart.toml` de la PR. Il faut arriver au jury avec ces trois failles déjà corrigées et testées.
3. **« Que se passe-t-il quand l'outil plante ? »**
   Aujourd'hui, il affiche « grade A » et la CI passe (django). Un outil de sécurité doit échouer fermé.
4. **« En quoi êtes-vous meilleur que Semgrep + Trivy + Gitleaks, gratuits ? »**
   Sur ces 5 dépôts, je n'ai trouvé aucun vrai problème critique trouvé par Rempart seul. L'avantage défendable est le croisement code ↔ infrastructure (*linked*) et l'apprentissage. Ni l'un ni l'autre n'a été démontré sur du code réel jamais vu : la seule chaîne CRITICAL observée était fausse, et le vrai scénario de `deploy-pr.yaml` n'a pas été assemblé.
5. **« Ce code a été écrit en deux jours par une seule personne : qui le maintient, et comment savez-vous qu'il est juste ? »**
   Les tests (160), le bench avec barrière CI et la reproductibilité sont de vraies réponses. Mais l'audit montre qu'ils n'ont pas attrapé un plantage sur un dépôt réel courant ni des alias d'import élémentaires. Il faut ajouter un jeu de dépôts réels en CI, comme celui de cet audit.

---

*Données brutes de l'audit (JSON des scans, sorties Semgrep, Checkov, Trivy et Gitleaks, clones) :*
`/tmp/claude-1000/-home-ahn-rempart/738fb44e-d134-4212-aafd-6856f947290b/scratchpad/audit/`

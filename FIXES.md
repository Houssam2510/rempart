# Corrections de l'audit (AUDIT.md)

Branche `fix/audit-2026-10`, créée depuis `feat/bench-learning-v2` (`72eb339`). Une phase à la fois, chacune validée avant la suivante.

Conventions : « **exécuté** » = chiffre obtenu en lançant la commande indiquée ; « **non vérifié** » = rien n'a été exécuté pour le prouver.

## Phase 0 — mesure de départ (avant tout correctif)

### Outils de mesure ajoutés

| Élément | Rôle |
|---|---|
| `bench/realworld/repos.json` | Les 5 dépôts de l'audit épinglés au commit exact, plus `django/django` en « stress » (temps et plantages seulement, sans étiquettes) |
| `bench/realworld/labels.json` | Les 26 étiquettes de l'audit (24 du top 10 critique/high + 2 LOW de commerce, hors métrique). Chacune a été vérifiée contre la sortie JSON de l'audit : aucune ne manque. |
| `bench/realworld.py` | Clone avec cache, scan du code de la branche (`python -m rempart scan --offline --no-history -f json`) dans un `REMPART_HOME` jetable, comparaison aux étiquettes, précision stricte et large du top 10, temps, plantages. Un résultat du top 10 sans étiquette est affiché `UNLABELLED` et rend la précision provisoire : aucune étiquette n'est jamais déduite. |
| `bench/holdout/repos.json` | 5 dépôts de contrôle épinglés le 24/10/2026 par `git ls-remote` uniquement, **sans clonage ni lecture du code** : CTFd (Flask), full-stack-fastapi-template (FastAPI), node-express-boilerplate (Express), cloudposse/terraform-aws-rds (Terraform), podinfo (Kubernetes, Helm, GitHub Actions). Scannés une seule fois, en phase 5. |
| `tests/test_realworld.py` | Logique de score (top 10, étiquettes, lignes déplacées, manifestes épinglés, absence d'étiquettes holdout) |

### Mesure de départ — exécuté sur `70fae95` (= `72eb339` + AUDIT.md)

| Mesure | Commande | Résultat |
|---|---|---|
| Suite de tests | `PYTHONPATH=src python -m unittest discover -s tests -t .` (venv avec `[all]`) | **164 tests OK**, 0 skipped (160 + 4 de `test_realworld.py`) |
| Bench interne | `rempart bench -v` | 90 TP / 0 FP / 2 FN · précision **100 %** · rappel **97,8 %** · 0/73 pièges |
| OWASP Benchmark Python (`f129148`), sans INFO | `python bench/owasp_python.py <bp>` | **99,4** |
| OWASP Benchmark Python, INFO compté | même script, seuil `>= Severity.INFO` (copie hors dépôt) | **87,7** |
| Bench réel | `python bench/realworld.py --stress -v` | voir ci-dessous |

#### Bench réel (top 10 critique/high, étiquettes de l'audit)

| Dépôt | Temps | CRIT/HIGH/MED/LOW | Top | VP | FP | Discutable | Non étiqueté | Stricte | Large |
|---|---|---|---|---|---|---|---|---|---|
| microblog | 0,4 s | 0/2/3/4 | 2 | 0 | 1 | 1 | 0 | 0 % | 50 % |
| djangoproject.com | 5,8 s | 1/10/25/25 | 10 | 0 | 8 | 2 | 0 | 0 % | 20 % |
| commerce | 0,3 s | 0/0/0/2 | 0 | — | — | — | — | n/a | n/a |
| terraform-aws-eks | 2,1 s | 0/3/23/16 | 3 | 0 | 3 | 0 | 0 | 0 % | 0 % |
| microservices-demo | 2,3 s | 2/7/62/119 | 9 | 1 | 7 | 1 | 0 | 11 % | 22 % |
| **Total** | | | **24** | **1** | **19** | **4** | **0** | **4 %** | **21 %** |
| django (stress) | 50,2 s | 2/31/171/123 | — | — | — | — | — | — | — |

Plantages : **1** (django : `code: TypeError: cannot use 'list' as a set element`).

Scénarios d'attaque F1 à F4 : reproduits dans l'audit (section 4, exécutés sur `72eb339`) ; chacun deviendra un test en phase 1.

## Phase 1 — sécurité de l'outil

Chaque test a été écrit et vu en échec avant le correctif (exécuté), puis vu passer après. Tous sont dans `tests/test_audit_fixes.py`.

| Id | Statut | Commit | Test | Reste incomplet |
|---|---|---|---|---|
| F1 | corrigé | `de111f3` | `F1LearningIsolationTest` (5 tests, dont le scénario exact de l'audit : la SQLi de B reste CRITICAL 0,90 après le scan du dépôt A aux 12 ignores) | Un **fork** partage le commit racine, donc l'identité de projet : ses `rempart:ignore` comptent pour le projet d'origine, mais plafonnés à 1,0 par règle. Les bases existantes sont migrées à la première utilisation (`History.for_root`). |
| F2 | corrigé | `6739e6e` | `F2FailClosedTest` (6) | Un scanner qui dépasse le délai est abandonné, pas tué (thread démon) : il peut continuer à consommer du CPU jusqu'à la fin du processus. Nouveau domaine `scan` : il y a désormais 17 domaines (README à corriger en phase 3). |
| F3 | corrigé | `b665538` | `F3AssistantCannotCloseTest` (4) | Ce commit corrige aussi une régression introduite par F1 dans `tool_triage` (`Path` importé localement). |
| F4 | corrigé | `6744132` | `F4ConfigFromBaseTest` (5) | Les `rempart:ignore` ajoutés par la PR s'appliquent toujours (comme `nosemgrep`) ; c'est documenté dans SECURITY.md, sans signalement automatique. |
| F5 | corrigé | `3af5eed` | `F5AgentNeverSeesSecretsTest` (4) | Le masquage repose sur les détecteurs de Rempart : un secret dans un format inconnu et non affecté à un nom évocateur passe. |
| F6 | corrigé | `27d62f4` | `F6AgentOutputsTest` (4) | Le contrôle des preuves est statique : un code Python obfusqué (`getattr` dynamique, chaînes construites) peut l'éviter. Les fichiers compose ne sont pas protégés. Non vérifié contre une vraie injection de prompt (aucun appel API). |
| F7 | corrigé | `2534199` | `F7LiveVerificationTest` (2) | Telegram et Mapbox gardent le jeton dans l'URL : leurs API n'acceptent rien d'autre (documenté). L'usage reste déclaratif : rien n'empêche techniquement de vérifier les clés d'un dépôt tiers. |
| F8 | corrigé | `61c6430` | `F8McpBoundariesTest` (4) | Les images tirées d'un registre via MCP ne sont pas soumises au filtre « public seulement » (un registre interne reste joignable). `test_mcp.py` accorde explicitement sa racine temporaire. |
| F9 | corrigé | `a4db1e4` | `F9SearchCannotHangTest` (4) | La recherche littérale reste en processus : elle est linéaire, sans risque ReDoS. `test_agent.py` passe `regex=True` pour l'appel qu'il vérifie. |
| SELF | corrigé | `59eadba`, `b097448` | `SelfScanPinnedActionsTest` | Les 5 actions de `release.yml` sont épinglées, pas seulement celle de PyPI. AUDIT.md, FIXES.md et `bench/realworld|holdout` sont exclus du dogfooding : `DATA-TLS-DISABLED` s'y déclenchait sur de la prose (à traiter dans R4). |
| R1 – R7 | voir phase 2 | | | |

### Mesures après la phase 1 — exécuté sur `b097448`

| Mesure | Avant (P0) | Après P1 |
|---|---|---|
| Tests | 164 OK | **203 OK**, 0 sautés |
| Bench interne | 100 % / 97,8 % | 100 % / 97,8 % (`--check bench/baseline.json` : aucune régression) |
| OWASP sans INFO / avec INFO | 99,4 / 87,7 | 99,4 / 87,7 |
| Bench réel strict / large | 4 % / 21 % | 4 % / 21 % (inchangé : la phase 1 ne touche pas la détection) |
| django | plantage masqué, « grade A », exit 0 | plantage visible : `SCANNER-ERROR` HIGH, score « incomplet », **exit 3** |
| Dogfooding (`scan . --fail-on high`) | exit 0 | exit 0 (après exclusion des documents d'audit) |

### Tests existants modifiés (rien n'est supprimé ni affaibli)

- `tests/test_tui.py` : l'historique est recherché par `project_identity(root)` au lieu du chemin brut (F1 change le format de l'identifiant). L'assertion est inchangée.
- `tests/test_mcp.py` : le serveur reçoit explicitement le dossier temporaire scanné comme racine (F8). Les assertions sont inchangées.
- `tests/test_agent.py` : l'appel direct `search_code(r"^OPS", "*.py")` passe `regex=True`, puisque la recherche est littérale par défaut depuis F9. L'assertion est inchangée.

## Phase 2 — robustesse et précision

Même méthode : chaque test a été écrit et vu en échec avant le correctif, puis vu passer. Tous sont dans `tests/test_audit_fixes.py`. Aucun correctif ne nomme un fichier, un dépôt ou une fonction des dépôts de l'audit.

| Id | Statut | Commits | Tests | Reste incomplet |
|---|---|---|---|---|
| R1 | corrigé | `2081f59` | `R1NoCrashTest` (moteur exécuté sur toute la bibliothèque standard ; fonctions qui renvoient des conteneurs constants différents) | — |
| R2 | corrigé | `cd66dbb`, `cce66de`, `5f2af1e`, `2ed7941` | `R2SafeResolutionTest` (5) | Python seulement : les appels JavaScript restent liés comme avant. Une fonction du projet dont le nom est celui d'un échappeur connu (`escape_html`…) est crue sur son nom, même si elle n'échappe rien. `cce66de` et `5f2af1e` corrigent deux régressions introduites par `cd66dbb` et trouvées par les mesures de fin de phase (voir plus bas) ; `2ed7941` corrige le coût en temps de `5f2af1e`. |
| R3 | corrigé | `109e54e` | `R3ImportAliasesTest` (2) | Python seulement. `importlib.import_module` / `__import__` dynamiques ne sont pas suivis. |
| R4 | corrigé | `4d99163` | `R4FileKindsTest` (5) | Heuristique sur les chemins (`filekind.py` en donne la liste) : un fichier de développement nommé autrement est traité comme du code livré. |
| R5 | corrigé | `5d73e96` | `R5ChainsTest` (5) | Un « lien » reste une co-occurrence dans un même workflow ou une route reliée par le graphe, pas une preuve d'exploitation. |
| R6 | corrigé | `825b2b4`, `2fc0217`, `86a81fd`, `b2cebe3`, `2243c1a`, `a07836c`, `2b8c75d`, `c40c1f9`, `31d2c39` | `R6FalsePositivesTest` (10) | Les listes de paquets populaires (`src/rempart/data/`) datent de leur téléchargement : `scripts/update_popular.py` les régénère. Une route Flask qui renvoie une **liste** est encore signalée XSS (Flask ≥ 2.2 la sérialise en JSON) ; un dict ne l'est pas. Un `csrf_exempt` sur un webhook dont la signature est vérifiée reste signalé (FP étiqueté dans le bench réel). |
| R7 | corrigé | `58f830d` | `R7TerraformValuesTest` (4) | Cas simples seulement : valeurs par défaut, `terraform.tfvars` / `*.auto.tfvars` du même dossier, locals littéraux, `[ref]`, `ref.attr`, `lookup()`, `"${…}"`. Les entrées passées à un module enfant (`module "x" { … }`) ne sont pas propagées ; un `for_each` à plusieurs éléments n'est pas résolu. Une valeur non résolue est plafonnée à MEDIUM / 0,5 avec « Value not resolved » ; un CIDR non résolu ne produit rien (comme avant). |

### Régressions trouvées en fin de phase, et corrigées

- **OWASP, invisible dans le score** : après `cd66dbb`, `helpers.utils.escape_for_html(...)` était résolu vers le code du projet, qui échappe caractère par caractère, ce que le moteur ne sait pas prouver. Le score par catégorie baissait à peine (99,4 → 99,3 ; 87,7 → 87,5), mais un diff cas par cas montrait **256 nouveaux `CODE-XSS-SINK` HIGH** dans d'autres catégories. Corrigé par `cce66de` : les noms d'échappeurs passent avant la résolution (`NEUTRALIZERS` et les méthodes de chaîne restent après : `Repo().find` n'est pas `str.find`). Le diff ne garde ensuite qu'un changement : 19 pièges xpathi perdent un `CODE-PATH-TRAVERSAL` faux (le fichier ouvert est un chemin constant ; `bar.replace(...)` n'est plus pris pour une opération de fichier, R6).
- **Bench réel** : une méthode héritée d'une classe de base du projet (`User.to_collection_dict`, définie sur un mixin) n'était plus résolue de façon certaine ; le dict renvoyé devenait du texte souillé, d'où 3 `CODE-XSS-SINK` HIGH faux dans microblog. Corrigé par `5f2af1e` (recherche dans les bases, dans l'ordre, comme Python), puis `2ed7941` pour le temps (django 251 s → 109 s, mêmes résultats).

### Mesures après la phase 2 — exécuté sur `2ed7941`

| Mesure | Après P1 | Après P2 |
|---|---|---|
| Tests | 203 OK | **236 OK**, 0 sautés |
| Bench interne (précision / rappel) | 100 % / 97,8 % | 100 % / **98,9 %** (iac 87,5 % → 100 % : R7 trouve le cas qui dépendait d'une variable). `--check bench/baseline.json` : aucune régression. |
| OWASP sans INFO / avec INFO | 99,4 / 87,7 | 99,4 / 87,7 |
| Bench réel strict / large | 4 % / 21 % (24 étiquetés) | **50 % / 75 %** (8 étiquetés) |
| django (stress) | plantage, exit 3 | **0 plantage**, 109 s, 2/34/304/135 |
| Dogfooding (`scan . --fail-on high`) | exit 0 | exit 0 |

Les 50 s de django en phase 0 ne sont pas comparables : le scanner de code y plantait avant d'avoir fini.

#### Bench réel par dépôt (top 10 critique/high)

| Dépôt | Temps | CRIT/HIGH/MED/LOW | Top | VP | FP | Discutable | Stricte | Large |
|---|---|---|---|---|---|---|---|---|
| microblog | 0,6 s | 0/0/3/4 (avant 0/2/3/4) | 0 (avant 2) | — | — | — | n/a | n/a |
| djangoproject.com | 7,8 s | 0/1/22/28 (avant 1/10/25/25) | 1 (avant 10) | 0 | 1 | 0 | 0 % | 0 % |
| commerce | 0,3 s | 0/0/0/2 | 0 | — | — | — | n/a | n/a |
| terraform-aws-eks | 2,1 s | 0/0/17/14 (avant 0/3/23/16) | 0 (avant 3) | — | — | — | n/a | n/a |
| microservices-demo | 2,5 s | 2/5/60/122 (avant 2/7/62/119) | 7 (avant 9) | 4 | 1 | 2 | 57 % | 86 % |
| **Total** | | | **8** (avant 24) | **4** | **2** | **2** | **50 %** | **75 %** |

**À lire avec prudence** : ces cinq dépôts sont l'ensemble de réglage. Les correctifs ont été écrits en connaissant leurs faux positifs (règles générales, mais choisies en les regardant). Le chiffre honnête sera celui des dépôts holdout en phase 5. Le top 10 ne contient plus que 8 résultats : la précision porte sur moins d'éléments, et rien ici ne mesure le rappel sur ces dépôts.

**6 étiquettes ajoutées** dans `bench/realworld/labels.json` (champ `labelled_in`), en lisant le code, pour les résultats du top 10 qui n'en avaient pas. Ce sont les seules étiquettes qui ne viennent pas de l'audit :

- djangoproject.com `CODE-CSRF-DISABLED` `fundraising/views.py:281` : **fp** (webhook Stripe, signature vérifiée par `construct_event`) ;
- microservices-demo `deploy-pr.yaml:44` `GHA-PWN-REQUEST` : **tp**, et `CHAIN-CI-UNTRUSTED-TO-RELEASE` : **tp** (le code de la PR est construit dans le job qui obtient les identifiants cloud OIDC ; l'environnement `gke-staging` exige peut-être une approbation, ce que le dépôt ne montre pas) ;
- `GHA-ENV-INJECTION` `:65` : **tp** (le contenu de l'artefact de la PR est écrit dans `$GITHUB_ENV` sans validation), `:104` : **discutable** (dérivé de la même valeur), `:151` : **fp** (adresse attribuée par le load balancer).

### Tests existants modifiés (rien n'est supprimé ni affaibli)

- `tests/test_tui.py` (R5) : deux tests supposaient que la chaîne était la première action. Une chaîne seulement corrélée est désormais au plus HIGH, donc une découverte CRITICAL peut passer devant. Les tests cherchent l'action de la chaîne et vérifient qu'aucune action de sévérité inférieure ou égale ne la précède.
- `tests/test_agent.py` (R6) : la table `OPS` était un littéral, que le moteur résout maintenant (l'`eval` n'y voit que des constantes). Elle est construite par `dict(...)`, pour garder la prémisse du test (un `eval` que l'analyse statique ne peut pas trancher). Les assertions sont inchangées.

## Phase 3 — honnêteté des mesures et du README

| Point demandé | Statut | Commit | Test / preuve | Reste incomplet |
|---|---|---|---|---|
| `bench/owasp_python.py` affiche les deux scores | fait | `7129344` | `tests/test_owasp_script.py` (vu en échec avant) ; exécuté : 99,4 (alertes) / 87,7 (INFO compté) | — |
| Job CI nightly qui échoue en cas de régression | fait | `64fc3ce` | `RegressionCheckTest` (3, vus en échec avant) ; `--check bench/realworld/baseline.json` exécuté localement : aucune régression | **Non vérifié sur GitHub** : rien n'a été poussé, le workflow n'a jamais tourné sur un runner. Il échoue aussi sur un résultat non étiqueté du top 10, par choix : la précision n'est pas fiable tant qu'il n'est pas lu. |
| Légende de la démo (4 linked, 2 correlated) | fait | `f119c8b` | scan exécuté : 4 chaînes avec route (CRITICAL), 2 sans (HIGH) | L'ancienne capture ne correspondait plus à la sortie (R5 : chaîne debug HIGH, compteurs 16/19/17/10/1). Elle est redessinée à partir d'un vrai scan par `scripts/render_demo.py` (Pillow, hors dépendances de Rempart). |
| « 10 scanners de dépôt + images, cloud et web » | fait | `f119c8b` | `ALL_SCANNERS` : 10 | — |
| Répartition des règles | fait | `f119c8b` | introspection de `load_all_rules()` : **319** = 233 dépôt + 68 en direct (AWS 29, GCP/Azure 22, web 17) + 11 images + 7 techniques | 319 et non 316 : `GHA-ENV-INJECTION` (R5) et les 2 règles du domaine `scan` (F2) sont nouvelles ; 17 domaines. |
| « 8 % → 80 % » | retiré | `f119c8b` | — | Le README dit pourquoi il a été retiré (dépôts privés, contredit par la mesure publique). Il reste dans `CHANGELOG.md` (historique, non modifié). |
| cspm-lite « 9/9 en live, 5/9 en statique » | fait | `f119c8b` | statique **exécuté** sur `cspm-lite@64266df` `lab/` : 5/9 + 2 chaînes | Le 9/9 en direct est **non vérifié** (aucun compte AWS) ; le README le dit. |
| Promesse MCP exacte | fait | `f119c8b` | relu contre `mcp_server.py` et les tests F3/F8 | Ajouté : `rempart_image_scan` peut tirer une image de n'importe quel registre joignable, y compris interne. |
| Section Limites | réécrite | `f119c8b` | — | Elle commence par la précision faible sur code jamais vu. |
| Tableau « Précision sur code jamais vu » | fait | `f119c8b` | `bench/realworld.py --stress -v` exécuté | La colonne « après » porte sur l'ensemble de réglage : le README le dit. Le holdout est en phase 5. |

Correctif trouvé en refaisant la capture : la narration des chaînes écrivait « oS command built from dynamic input » (R5 met la première lettre du titre en minuscule). Corrigé avec test (`059cff6`, `R5ChainsTest.test_a_title_starting_with_an_acronym_keeps_it`).

### Mesures après la phase 3 — exécuté sur `f119c8b`

| Mesure | Après P2 | Après P3 |
|---|---|---|
| Tests | 236 OK | **241 OK** |
| Bench interne | 100 % / 98,9 % | 100 % / 98,9 % (`--check` : aucune régression) |
| OWASP sans INFO / avec INFO | 99,4 / 87,7 | 99,4 / 87,7 (le script imprime maintenant les deux) |
| Bench réel strict / large | 50 % / 75 % | 50 % / 75 % (`--check bench/realworld/baseline.json` : aucune régression) |
| django | 0 plantage, 109 s | 0 plantage, 109 s |
| Dogfooding | exit 0 | exit 0 |

## Phase 4 — concentration

| Point demandé | Statut | Commit | Test | Reste incomplet |
|---|---|---|---|---|
| Cloud live, images, web, qualité/performance en « expérimental », désactivés par défaut, activables par option | fait | `49a6881` | `P4ExperimentalTest` (4, vus en échec avant) : profil par défaut sans qualité/performance, `--experimental` les active et les marque, aide des options et commandes, même profil pour la TUI et le MCP | Le cloud live, les images et le web demandaient déjà une option ou une commande : ils sont désormais **marqués** (aide, avis sur stderr, `"experimental": true`), pas désactivés davantage. Qualité/performance sont coupées par **domaine**, car le scanner data produit aussi des `PERF-*`. |
| Profil par défaut centré sur code, dépendances, secrets, IaC, Kubernetes, CI/CD, chaînes linked, apprentissage | fait, avec une interprétation | `49a6881` | idem | Data, IA, conteneurs (Dockerfile) et supply chain restent actifs : la consigne nomme quatre parties expérimentales, pas celles-là. Les chaînes *correlated* restent visibles, plafonnées à HIGH (R5). |
| Signalé dans le README | fait | `8607b92` | — | Marque 🧪 et paragraphe « Experimental », ligne dans les Limites, capture redessinée (`scripts/render_demo.py`), section dans `docs/ARCHITECTURE.md`. |
| Ne rien supprimer | respecté | — | `run_scan()` garde tout par défaut : `rempart bench` et les tests mesurent toujours ces domaines | — |

### Mesures après la phase 4 — exécuté sur `8607b92`

| Mesure | Après P3 | Après P4 |
|---|---|---|
| Tests | 241 OK | **245 OK** |
| Bench interne | 100 % / 98,9 % | 100 % / 98,9 % (aucune régression) |
| OWASP sans INFO / avec INFO | 99,4 / 87,7 | 99,4 / 87,7 |
| Bench réel strict / large | 50 % / 75 % | 50 % / 75 % (`--check` : aucune régression ; même top 10) |
| django | 0 plantage, 109 s, 2/34/304/135 | 0 plantage, 107 s, **2/3/142/76** (31 des 34 HIGH venaient de qualité/performance) |
| Dogfooding | exit 0 | exit 0 |

Volume par dépôt (CRIT/HIGH/MED/LOW), avant → après P4 : microblog 0/0/3/4 → 0/0/2/2 ; djangoproject.com 0/1/22/28 → 0/1/16/16 ; terraform-aws-eks 0/0/17/14 → 0/0/17/12 ; microservices-demo 2/5/60/122 → 2/5/57/113.

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
| R1 – R7 | à faire (phase 2) | | | |

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

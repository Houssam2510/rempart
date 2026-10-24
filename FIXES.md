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

## Suivi par identifiant

| Id | Statut | Commit | Test | Reste incomplet |
|---|---|---|---|---|
| F1 – F9 | à faire (phase 1) | | | |
| R1 – R7 | à faire (phase 2) | | | |

# Guide d'utilisation et de progression

Ce guide sert à utiliser Rempart au quotidien sur tes propres projets, à le faire progresser, et à le présenter en entrevue.

## 1. Usage quotidien

```bash
pipx install git+https://github.com/Houssam2510/rempart   # une seule fois
cd ~/mon-projet
rempart scan .                 # scan complet, avec recherche des CVE en ligne
rempart scan . -v              # avec le correctif et les référentiels de chaque résultat
rempart scan . -f html -o rapport.html
rempart web https://mon-site.com
```

Avant chaque mise en production, `rempart scan . --fail-on high` donne un code de sortie à 1 dès qu'un résultat HIGH ou CRITICAL apparaît.

Au-delà du dépôt :

```bash
rempart scan . --aws --image monorg/api:latest   # code + compte AWS réel + image, corrélés ensemble
rempart image python:3.12-slim                   # image d'un registre, sans Docker
rempart cloud aws --profile prod                 # audit AWS en lecture seule (politique SecurityAudit)
rempart k8s --context prod                       # cluster Kubernetes via kubectl
rempart scan . --verify-secrets                  # une clé fuitée est-elle encore active ? (tes dépôts seulement)
rempart cloud gcp --project mon-projet           # Google Cloud via gcloud, lecture seule
rempart cloud azure                              # Azure via az, lecture seule
```

Au quotidien sur une branche :

```bash
rempart scan . --baseline origin/main            # seulement ce que la branche ajoute
rempart scan . --git-history                     # secrets supprimés des fichiers mais restés dans l'historique
rempart scan . --prod-only                       # ignorer les dépendances de build et de test
rempart watch .                                  # re-scan à chaque modification, n'affiche que la différence
```

## 1b. L'agent IA

```bash
export ANTHROPIC_API_KEY=...
rempart agent .            # l'agent IA relit le code derrière chaque résultat important
rempart agent . --apply    # applique aussi les correctifs proposés (vérifie avec git diff)
```

Pour chaque résultat, l'agent lit le code, suit la donnée et rend un verdict : confirmé, faux positif ou incertain. Il cite les lignes qui le justifient et propose un correctif minimal sous forme de patch. Il ne peut que lire les fichiers du dépôt scanné : il ne peut ni exécuter de code, ni accéder au réseau, ni écrire. Ses verdicts comptent à moitié dans l'apprentissage et ne ferment jamais un résultat : seul toi peux le faire. Attention, il envoie des extraits de ton code à l'API Anthropic.

Rempart est aussi un serveur MCP. Ajoute-le dans `.mcp.json` pour que ton assistant de code IA (Cursor, VS Code…) l'utilise pendant qu'ils écrivent du code :

```json
{ "mcpServers": { "rempart": { "command": "rempart", "args": ["mcp"] } } }
```

## 2. Comment il apprend

Chaque résultat porte un identifiant court. Quand tu as vérifié un résultat, tu donnes ton verdict :

```bash
rempart triage 7d9771c7fb --fp --note "regex bornée"   # faux positif
rempart triage 697ff3c2a7 --tp                         # vrai problème
rempart triage a3750d61ca --accept --note "risque accepté, documenté"
```

Trois effets :

1. Dans ce projet, un faux positif ou un risque accepté disparaît des scans suivants.
2. Pour tous tes projets, la précision de la règle est recalculée. Une règle qui se trompe souvent voit sa confiance baisser, puis sa sévérité descendre d'un cran après 5 faux positifs.
3. `rempart history` montre la tendance du score, les nouveaux résultats et ceux corrigés, ainsi que le temps moyen de correction.

`rempart learn` affiche ce que l'outil a appris, règle par règle. Plus tu tries, plus il devient précis sur ta façon de coder.

## 3. Le faire progresser

La boucle qui a servi à construire la v0.1 est la bonne :

1. Scanner un vrai dépôt.
2. Vérifier chaque résultat à la main.
3. Pour chaque faux positif, comprendre *pourquoi* la règle s'est trompée, la corriger et ajouter un test qui reproduit le cas.
4. Pour chaque faille réelle que l'outil a ratée, écrire la règle et son test.

Pistes classées par valeur (détails dans `docs/ROADMAP.md`) :

Livré en 0.3 : graphe de ressources, `--baseline`, secrets dans l'historique, flux entre fonctions (Python, tout le dépôt ; JS, dans un fichier), corpus d'évaluation de l'agent, GCP et Azure, RPM/Go/JAR.

- **Flux JS/TS entre modules** : suivre les imports comme on le fait déjà en Python.
- **Lier le cloud observé au dépôt** : rattacher un groupe de sécurité ou une instance réelle à la ressource Terraform et à l'image qui l'ont créée.
- **Chemins d'attaque confirmés par l'agent** : lui demander de prouver ou de casser chaque maillon, avec un test de preuve.
- **Politique de « cooldown »** sur les paquets publiés il y a moins de N jours : la seule défense contre les vers qui publient avec une provenance SLSA valide.
- **Mesurer l'agent avec une vraie clé** : `rempart agent-eval`, puis publier le score par modèle.

## 4. Le présenter en entrevue

**En une phrase :** « J'ai construit un scanner de sécurité qui raisonne en chemins d'attaque. Il couvre le code, les dépendances, les images, le compte AWS réel, Kubernetes, les données, le CI/CD et les agents IA. Un agent IA vérifie chaque résultat en lisant le code, et l'outil apprend de mes verdicts. »

Points à mettre en avant :

- **Les chemins d'attaque.** Une SSRF et IMDSv1 sont deux résultats « élevés ». Ensemble, ils forment le chemin de la brèche Capital One de 2019, et Rempart le signale comme un seul scénario critique.
- **La vérification.** Chaque résultat dit comment il a été établi : motif, flux de données, dépendance importée, observation en direct, clé vérifiée active, revue par l'IA.
- **L'agent IA sûr par construction.** Il n'a que des outils de lecture, traite le contenu du dépôt comme non fiable et ne supprime jamais un résultat.

- **La priorisation par l'exploitation réelle.** Un CVSS de 9,8 jamais exploité passe après une faille listée au KEV. C'est la logique de la directive BOD 22-01 de la CISA.
- **La précision mesurée.** 99,4 sur l'OWASP Benchmark Python (1 230 cas étiquetés), et une précision passée de 8 % à 80 % sur dix vrais dépôts étiquetés à la main, sans perdre une seule vraie faille. Chaque faux positif est devenu un test de non-régression.
- **Les chemins prouvés.** Un chemin d'attaque n'est « lié » que si l'infrastructure relie ses maillons, et Rempart affiche la route (`aws_iam_policy.ci → … → aws_instance.worker`). Sinon il est signalé comme simple coïncidence, un cran plus bas.
- **La couverture actuelle.** Le projet suit l'OWASP Top 10:2025, le CWE Top 25 de 2025 et le Top 10 agentique de 2026, avec des incidents récents comme React2Shell, Shai-Hulud, TanStack et tj-actions.
- **L'honnêteté sur les limites.** Le README dit ce que l'analyse statique ne voit pas : la logique métier, l'IDOR, la mémoire. Un recruteur sécurité respecte ça plus qu'une promesse de « tout détecter ».
- **Le volet données.** Il couvre Supabase RLS, les règles Firebase, MongoDB exposé et les données personnelles, avec un renvoi à la Loi 25 du Québec, un atout pour un poste au Canada.

Questions probables et pistes de réponse :

- *« Pourquoi pas Semgrep ou CodeQL ? »* CodeQL va plus loin sur le flux de données JS entre modules. Rempart couvre en plus les images, le cloud en direct, l'IaC, les données, le CI/CD et les agents, les relie en chemins d'attaque, priorise par l'exploitation et apprend. Les deux sont complémentaires.
- *« Comment tu empêches l'agent d'être manipulé par du code malveillant ? »* Il n'a aucun outil d'écriture, d'exécution ou de réseau, il ne lit que les fichiers du scan, le contenu du dépôt est déclaré non fiable dans ses consignes, et ses verdicts ne peuvent pas fermer un résultat.
- *« Comment gères-tu les faux positifs ? »* Il y a quatre niveaux : un puits **et** une source non fiable sur la même ligne, des motifs de désinfection (`unless`), une confiance a priori par règle, puis le recalibrage bayésien à partir des verdicts.
- *« Comment le passerais-tu à l'échelle ? »* Le mode baseline et le commentaire de PR existent déjà ; ensuite un cache partagé de la veille sur les menaces et une calibration exportée par équipe.

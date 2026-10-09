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

- **Mode `--baseline`** : ne montrer que ce qu'une branche ajoute. Indispensable pour l'utiliser en PR.
- **Secrets dans l'historique git** : les secrets supprimés restent récupérables.
- **Suivi de flux (taint) intra-fichier en JS/TS** : c'est la limite principale actuelle.
- **Politique de « cooldown »** sur les paquets publiés il y a moins de N jours : la seule défense contre les vers qui publient avec une provenance SLSA valide.
- **Fusion avec cspm-lite et triage** : un seul score pour le code, le compte AWS et les images.

## 4. Le présenter en entrevue

**En une phrase :** « J'ai construit un scanner de sécurité qui couvre le code, les dépendances, le cloud, les bases de données, les pipelines CI/CD et les agents IA en une seule passe. Il classe les CVE selon l'exploitation réelle avec CISA KEV et EPSS, et il apprend de mes verdicts pour réduire ses faux positifs. »

Points à mettre en avant :

- **La priorisation par l'exploitation réelle.** Un CVSS de 9,8 jamais exploité passe après une faille listée au KEV. C'est la logique de la directive BOD 22-01 de la CISA.
- **La précision mesurée.** L'outil a été testé sur de vrais dépôts. Chaque faux positif est devenu un test de non-régression, par exemple le cookie de langue, le JSON-LD déjà échappé ou les regex bornées.
- **La couverture actuelle.** Le projet suit l'OWASP Top 10:2025, le CWE Top 25 de 2025 et le Top 10 agentique de 2026, avec des incidents récents comme React2Shell, Shai-Hulud, TanStack et tj-actions.
- **L'honnêteté sur les limites.** Le README dit ce que l'analyse statique ne voit pas : la logique métier, l'IDOR, la mémoire. Un recruteur sécurité respecte ça plus qu'une promesse de « tout détecter ».
- **Le volet données.** Il couvre Supabase RLS, les règles Firebase, MongoDB exposé et les données personnelles, avec un renvoi à la Loi 25 du Québec, un atout pour un poste au Canada.

Questions probables et pistes de réponse :

- *« Pourquoi pas Semgrep ou CodeQL ? »* Ils vont plus loin sur le code. Rempart couvre en plus l'IaC, les données, le CI/CD et les agents, priorise par l'exploitation et apprend, sans aucune configuration. Les deux sont complémentaires.
- *« Comment gères-tu les faux positifs ? »* Il y a quatre niveaux : un puits **et** une source non fiable sur la même ligne, des motifs de désinfection (`unless`), une confiance a priori par règle, puis le recalibrage bayésien à partir des verdicts.
- *« Comment le passerais-tu à l'échelle ? »* Mode baseline pour les PR, cache partagé de la veille sur les menaces, calibration exportée par équipe.

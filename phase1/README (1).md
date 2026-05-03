# MicroSecScore — Phase 1 : Topologie & Graphe G0

Système intelligent de corrélation d'attaques pour architectures microservices.
Phase 1 : construction du graphe de connaissances statique G0.

---

## Description générale

La Phase 1 parse l'architecture d'une application microservices (Docker Compose ou Kubernetes),
construit le graphe G0 des communications autorisées, calcule les scores de vulnérabilité
CVE par service, et produit un score global de sécurité du système.

---

## Structure du projet

```
MicroSecScore/
├── phase1/                         # Code source Phase 1
│   ├── phase1_topology.py          # Point d'entrée principal
│   ├── config/
│   │   └── settings.py             # Paramètres globaux
│   ├── utils/
│   │   └── logger.py               # Logger centralisé
│   ├── parsers/
│   │   ├── __init__.py             # Initialisation du module
│   │   ├── detector.py             # Détection automatique de l'environnement
│   │   ├── docker_parser.py        # Parser Docker Compose
│   │   └── kubernetes_parser.py    # Parser Kubernetes
│   ├── graph/
│   │   ├── __init__.py             # Initialisation du module
│   │   ├── builder.py              # Construction de G0 avec NetworkX
│   │   ├── scorer.py               # Calcul criticité et score global
│   │   └── exporter.py             # Export graph_G0.json et CSV
│   ├── cve/
│   │   ├── __init__.py             # Initialisation du module
│   │   ├── cve_client.py           # Client API OSV.dev avec fallback NVD
│   │   └── cve_scorer.py           # Formule de calcul Score_CVE
│   ├── neo4j/
│   │   ├── __init__.py             # Initialisation du module
│   │   ├── connector.py            # Connexion à Neo4j
│   │   └── sync.py                 # Synchronisation NetworkX vers Neo4j
│   ├── watcher/
│   │   ├── __init__.py             # Initialisation du module
│   │   └── k8s_watcher.py          # Surveillance temps réel Kubernetes
│   └── visualizer/
│       ├── __init__.py             # Initialisation du module
│       └── graph_viz.py            # Visualisation de G0 (matplotlib / pyvis)
├── data/
│   ├── input/
│   │   ├── docker-compose.yml      # Architecture cible Sock Shop
│   │   └── k8s/                    # Manifestes Kubernetes (optionnel)
│   └── output/
│       ├── graph_G0.json           # Graphe G0 exporté
│       └── security_scores.csv     # Scores CVE par service
├── tests/
│   ├── test_docker_parser.py       # Tests unitaires du parser Docker
│   ├── test_cve_scorer.py          # Tests unitaires du calcul CVE
│   └── test_graph_builder.py       # Tests unitaires de la construction G0
├── logs/
│   └── phase1.log                  # Journal d'exécution
├── requirements.txt                # Dépendances Python
└── README.md                       # Ce fichier
```

---

## Rôle détaillé de chaque fichier

### `phase1_topology.py`
Point d'entrée unique du système. Orchestre l'exécution dans l'ordre suivant :
détection de l'environnement, parsing de l'architecture, construction de G0,
calcul des scores CVE, synchronisation Neo4j, export des fichiers de sortie.
Affiche le résultat final dans le terminal.

### `config/settings.py`
Centralise tous les paramètres du projet : URI Neo4j, coefficients CVE
(CRITICAL=10, HIGH=7, MEDIUM=4, LOW=1), seuils des niveaux de sécurité
(SAIN=90-100, STABLE=70-89, DÉGRADÉ=50-69, CRITIQUE=0-49),
chemins des dossiers input et output.

### `utils/logger.py`
Logger centralisé utilisé par tous les modules. Écrit simultanément
dans le terminal et dans logs/phase1.log. Remplace tous les print()
par des messages horodatés avec niveau de gravité (INFO, WARNING, ERROR).

### `parsers/detector.py`
Détecte automatiquement l'environnement sans intervention manuelle.
Vérifie la présence du fichier docker-compose.yml pour Docker,
ou teste la disponibilité de kubectl pour Kubernetes.
Retourne une constante ENV_DOCKER ou ENV_KUBERNETES.

### `parsers/docker_parser.py`
Lit le fichier docker-compose.yml via PyYAML et extrait pour chaque service :
le nom, l'image Docker, les ports exposés vers l'extérieur,
les dépendances (depends_on), les réseaux (networks),
et les accès privilégiés (privileged, docker.sock).

### `parsers/kubernetes_parser.py`
Interroge l'API Kubernetes via le client Python pour extraire
les Deployments, Services et NetworkPolicies du cluster.
Fournit une photo statique de l'architecture au moment du lancement.

### `graph/builder.py`
Construit le graphe G0 = (N, E, A) avec NetworkX (nx.DiGraph).
Chaque noeud représente un microservice avec ses attributs de sécurité.
Chaque arête orientée représente une communication autorisée entre deux services.
Ajoute le noeud spécial Outside relié aux services exposant des ports.

### `graph/scorer.py`
Calcule la criticité de chaque noeud selon le nombre de connexions
entrantes et sortantes dans G0. Applique la formule de moyenne pondérée
pour produire le score global du système.
Détermine le niveau : SAIN, STABLE, DÉGRADÉ ou CRITIQUE.

### `graph/exporter.py`
Exporte le graphe G0 au format JSON (graph_G0.json) avec horodatage.
Génère le fichier security_scores.csv contenant pour chaque service
son score CVE, sa criticité et son niveau de sécurité.

### `cve/cve_client.py`
Interroge l'API OSV.dev pour récupérer les CVE associées à chaque image Docker.
En cas d'échec ou de timeout, bascule automatiquement sur l'API NVD NIST.
Retourne pour chaque image le nombre de CVE par niveau de gravité.

### `cve/cve_scorer.py`
Applique la formule de calcul du score CVE :
Score = 100 - (CRITICAL×10 + HIGH×7 + MEDIUM×4 + LOW×1).
Plafonne le résultat entre 0 et 100.
Enrichit chaque noeud de G0 avec son score calculé.

### `neo4j/connector.py`
Ouvre et gère la connexion à la base de données Neo4j
via le driver officiel Python (bolt://localhost:7687).
Fournit une méthode de test de connexion et de fermeture propre.

### `neo4j/sync.py`
Prend le graphe G0 construit par NetworkX et le pousse dans Neo4j.
Crée les noeuds Service avec leurs attributs (score_cve, criticité).
Crée les relations DEPENDS_ON et PEUT_ATTAQUER entre les noeuds.
Permet aux phases 3 et 4 d'interroger G0 via Cypher.

### `watcher/k8s_watcher.py`
Utilise le Watch API de Kubernetes pour écouter en temps réel
les événements de type Pod et Service (ADDED, MODIFIED, DELETED).
Met à jour G0 automatiquement à chaque changement détecté.
Sauvegarde graph_G0.json à chaque mise à jour avec horodatage.

### `visualizer/graph_viz.py`
Génère une représentation visuelle de G0.
Utilise matplotlib pour un rendu statique ou pyvis pour un rendu interactif HTML.
Code couleur : rouge pour les services CRITIQUE, orange pour DÉGRADÉ,
jaune pour STABLE, vert pour SAIN.

---

## Installation

```bash
pip install -r requirements.txt
```

## Lancement

```bash
python phase1_topology.py
```

## Sortie attendue

```
→ Environnement détecté : Docker Compose
→ Services parsés : 13 noeuds, 11 arêtes
→ G0 sauvegardé : data/output/graph_G0.json
→ Scores CVE calculés : data/output/security_scores.csv
→ Score global : 59.7/100 → État DÉGRADÉ
```

---

## Stack technique

| Besoin             | Librairie         |
|--------------------|-------------------|
| Graphe             | networkx          |
| Parser YAML        | pyyaml            |
| Client Kubernetes  | kubernetes        |
| CVE lookup         | requests          |
| Visualisation      | matplotlib, pyvis |
| Export données     | pandas            |
| Base graphe        | neo4j-driver      |

---

## Auteur

DJOUYAGUENG SADE CEDRIC — Master II RSD — Université de Dschang — 2025-2026

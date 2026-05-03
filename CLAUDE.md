# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**MicroSecScore** is a multi-phase intelligent attack correlation system for microservices architectures, developed as a Master II RSD thesis project (Université de Dschang). The target environment is the **Sock Shop** demo application (13 microservices).

## Commands

### Phase 1 — Construction du graphe G0

```bash
# Détection automatique (Docker ou Kubernetes)
python phase1/phase1_topology.py

# Forcer un environnement spécifique
python phase1/phase1_topology.py --env docker
python phase1/phase1_topology.py --env kubernetes

# Sans Neo4j ni visualisation (rapide)
python phase1/phase1_topology.py --no-neo4j --no-viz

# Scores CVE simulés (pas d'appels API externes)
python phase1/phase1_topology.py --simulation

# Test d'intégration rapide (scores simulés)
python phase1/test_rapide.py

# Constructeur standalone (scores hardcodés, sans API)
python build_g0.py
```

### Phase 2 — Collecte d'événements runtime

```bash
# Démarrer Kafka avant la phase 2
docker compose -f phase2/kafka/docker-compose-kafka.yml up -d

# Pipeline complet
python phase2/phase2_runtime.py

# Tester la connectivité Kafka uniquement
python phase2/phase2_runtime.py --test-kafka

# Injecter un scénario APT complet
python phase2/phase2_runtime.py --inject-attack

# Durée fixe en secondes
python phase2/phase2_runtime.py --duration 60
```

### Démarrer l'application Sock Shop (cible)

```bash
docker compose up -d          # Démarre les 13 services
docker compose down           # Arrête tout
```

### Installation des dépendances

```bash
pip install networkx pyyaml kubernetes requests pandas neo4j matplotlib pyvis
pip install -r phase2/requirements_phase2.txt
```

## Architecture

### Vue d'ensemble des phases

```
Phase 1 : YAML/K8s API → Parser → G0 (NetworkX DiGraph) → CVE scoring → Export/Neo4j/Viz
Phase 2 : Docker logs + Prometheus + Falco sim → Kafka → Normalizer → events_collected.jsonl
Phase 3 : (non implémentée) Corrélation CEP sur événements
Phase 4 : (non implémentée) Remédiation automatique
```

### Phase 1 — Graphe de connaissance G0

Le graphe G0 représente la topologie statique de sécurité :
- **Nœuds** = microservices + nœud "Outside" (attaquant potentiel)
- **Arêtes DEPENDS_ON** = communications autorisées (issues de `depends_on`)
- **Arêtes PEUT_ATTAQUER** = depuis Outside vers les services exposés publiquement
- **Attributs par nœud** : `image`, `score_cve` (0-100), `criticite` (0-5), `niveau` (SAIN/STABLE/DÉGRADÉ/CRITIQUE)

Pipeline Phase 1 (`phase1/phase1_topology.py`) en 8 étapes :
1. `parsers/detector.py` → détecte l'environnement
2. `parsers/docker_parser.py` ou `parsers/kubernetes_parser.py` → descripteurs de services
3. `graph/builder.py` → construit G0 (nx.DiGraph)
4. `graph/scorer.py` → calcule la criticité (basée sur la centralité de degré)
5. `cve/cve_client.py` + `cve/cve_scorer.py` → enrichit les nœuds (OSV.dev → NVD en fallback)
6. `neo4j_db/sync.py` → synchronise G0 vers Neo4j
7. `graph/exporter.py` → génère `data/output/graph_G0.json` + `security_scores.csv`
8. `visualizer/graph_viz.py` → PNG (matplotlib) + HTML interactif (pyvis)

### Phase 2 — Collecte runtime

Pipeline Phase 2 (`phase2/phase2_runtime.py`) :
- 3 **collecteurs en parallèle** (threads) qui publient sur Kafka :
  - `collectors/docker_log_collector.py` → topic `logs-applicatifs`
  - `collectors/prometheus_collector.py` → topic `metriques-systeme` (scrape cAdvisor)
  - `collectors/falco_generator.py` → topic `alertes-securite` (simulation Falco)
- 1 **normaliseur** (`normalizer/event_normalizer.py`) → consomme les 3 topics, produit `events_collected.jsonl`

### Fichiers de configuration clés

| Fichier | Contenu |
|---|---|
| `phase1/config/settings.py` | Neo4j URL/credentials, poids CVE (CRITICAL=10, HIGH=7, MEDIUM=4, LOW=1), seuils de score, chemins fichiers |
| `phase2/config/phase2_settings.py` | Bootstrap Kafka (`localhost:9092`), intervalles de collecte, seuils d'alerte Prometheus, probabilités des événements Falco simulés |

### Formats de sortie

- **`data/output/graph_G0.json`** : format node-link NetworkX (`directed: true`, nœuds avec attributs de sécurité)
- **`data/output/security_scores.csv`** : classement par service (`service, image, score_cve, criticite, niveau, ports, privileged`)
- **`phase2/data/output/events_collected.jsonl`** : un événement JSON par ligne (`event_id` UUID, `timestamp_utc`, `source`, `event_type`, `service`, `severity`, `fields`)

## Points d'attention

- **Credentials Neo4j hardcodés** dans `phase1/config/settings.py` (`neo4j/microsec123`) — à externaliser via variable d'environnement avant tout déploiement
- Le fallback CVE est `OSV.dev → NVD NIST → score par défaut 100` ; en cas d'échec API, le pipeline continue sans erreur fatale
- La détection Falco est **simulée** (pas d'eBPF réel) — les probabilités d'événements sont configurables dans `phase2_settings.py`
- Kafka doit être démarré avant `phase2_runtime.py` ; utiliser `--test-kafka` pour vérifier la connectivité
- `build_g0.py` et `phase1/test_rapide.py` utilisent des scores CVE hardcodés, utiles pour tester sans accès réseau
